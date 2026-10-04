// src/api/state.rs
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

use crate::common::CommandResponse;
use crate::database::DbPool;
use crate::server::listeners::ListenerManager;

#[derive(Debug, Clone)]
pub struct StoredResult {
    pub response: CommandResponse,
    pub inserted_at: Instant,
    pub sequence: u64,
}

pub type SharedResults  = Arc<Mutex<HashMap<(u32, u64), StoredResult>>>;
pub type SharedListenerManager = Arc<tokio::sync::Mutex<ListenerManager>>;

pub const RESULT_TTL: Duration = Duration::from_secs(60 * 60);
pub const MAX_RESULTS_PER_SESSION: usize = 100;

fn sweep_map_expired(map: &mut HashMap<(u32, u64), StoredResult>, ttl: Duration) -> usize {
    let before = map.len();
    map.retain(|_, entry| entry.inserted_at.elapsed() <= ttl);
    before - map.len()
}

fn enforce_session_cap(map: &mut HashMap<(u32, u64), StoredResult>, session_id: u32) {
    let mut session_entries: Vec<((u32, u64), u64)> = map
        .iter()
        .filter(|((sid, _), _)| *sid == session_id)
        .map(|(key, entry)| (*key, entry.sequence))
        .collect();
    if session_entries.len() <= MAX_RESULTS_PER_SESSION {
        return;
    }

    session_entries.sort_by_key(|(_, sequence)| *sequence);
    let excess = session_entries.len() - MAX_RESULTS_PER_SESSION;
    for (key, _) in session_entries.into_iter().take(excess) {
        map.remove(&key);
    }
}

pub fn insert_result(
    results: &SharedResults,
    session_id: u32,
    request_id: u64,
    response: CommandResponse,
) {
    let mut map = results.lock().unwrap_or_else(|e| e.into_inner());
    let sequence = map.values().map(|entry| entry.sequence).max().unwrap_or(0) + 1;
    map.insert((session_id, request_id), StoredResult {
        response,
        inserted_at: Instant::now(),
        sequence,
    });
    sweep_map_expired(&mut map, RESULT_TTL);
    enforce_session_cap(&mut map, session_id);
}

pub fn sweep_expired_results(results: &SharedResults, ttl: Duration) -> usize {
    let mut map = results.lock().unwrap_or_else(|e| e.into_inner());
    sweep_map_expired(&mut map, ttl)
}

pub fn spawn_results_retention(results: SharedResults) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let removed = sweep_expired_results(&results, RESULT_TTL);
            if removed > 0 {
                tracing::debug!(removed, "Expired completed command results removed");
            }
        }
    });
}
pub type SharedBuildJobs = Arc<Mutex<HashMap<String, BuildJob>>>;
/// Registry of publicly hosted build artifacts (randomized /dl/<token>/<name>
/// links), keyed by token. Persisted to dist/payload_links.json.
pub type SharedPayloadLinks = Arc<Mutex<HashMap<String, crate::api::routes::payloads::HostedPayload>>>;

// ── Build job types ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum BuildStatus {
    Running,
    Success,
    Failed,
}

#[derive(Debug, Clone)]
pub struct BuildJob {
    pub id: String,
    pub status: BuildStatus,
    /// Captured stdout/stderr lines in order.
    pub log: Vec<String>,
    /// Filesystem path to the compiled artifact (set on success).
    pub artifact_path: Option<String>,
    /// Internal build id the builder generated and embedded into the agent
    /// (harvested from its "[*] Build ID:" log line). This - not the API
    /// queue job id - is the <build_id> in dist/staged_<build_id>.payload
    /// and the /stage/<build_id> download path.
    pub build_id: Option<String>,
    pub started_at: String,
    pub finished_at: Option<String>,
    /// Operator who triggered the build.
    pub operator: String,
}

// ── Proxy / rportfwd handle types ─────────────────────────────────────

pub struct ProxyHandle {
    pub session_id: u32,
    pub tunnel_port: u16,
    pub socks_port: u16,
    pub stop_tx: oneshot::Sender<()>,
}

/// Server-side state for an active reverse port forward.
pub struct RportfwdServerHandle {
    pub session_id: u32,
    pub bind_port: u16,
    pub tunnel_port: u16,
    pub target_host: String,
    pub target_port: u16,
    pub stop_tx: oneshot::Sender<()>,
}

pub type SharedProxies   = Arc<Mutex<HashMap<u32, ProxyHandle>>>;
pub type SharedRportfwds = Arc<Mutex<HashMap<(u32, u16), RportfwdServerHandle>>>;
pub type LoginLimiter    = Arc<Mutex<HashMap<String, (u32, std::time::Instant)>>>;

// ── Shared API context ─────────────────────────────────────────────────

#[derive(Clone)]
pub struct ApiContext {
    pub sessions:      crate::common::SharedSessions,
    pub db:            DbPool,
    pub results:       SharedResults,
    pub proxies:       SharedProxies,
    pub rportfwds:     SharedRportfwds,
    pub listener_mgr:  SharedListenerManager,
    pub login_limiter: LoginLimiter,
    /// In-memory registry of build jobs started via the web UI.
    pub build_jobs:    SharedBuildJobs,
    /// Publicly hosted build artifacts (unguessable /dl/ links).
    pub payload_links: SharedPayloadLinks,
    /// Per-IP rate limiter for the public /dl/ download endpoint.
    pub dl_limiter:    LoginLimiter,
}