// src/api/state.rs
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use tokio::sync::oneshot;
use rhai::AST;

use crate::common::CommandResponse;
use crate::database::DbPool;
use crate::server::listeners::ListenerManager;

pub type SharedResults  = Arc<Mutex<HashMap<(u32, u64), CommandResponse>>>;
pub type SharedScripts  = Arc<Mutex<HashMap<String, AST>>>;
pub type SharedListenerManager = Arc<tokio::sync::Mutex<ListenerManager>>;
pub type SharedBuildJobs = Arc<Mutex<HashMap<String, BuildJob>>>;

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
    pub scripts:       SharedScripts,
    pub listener_mgr:  SharedListenerManager,
    pub login_limiter: LoginLimiter,
    /// In-memory registry of build jobs started via the web UI.
    pub build_jobs:    SharedBuildJobs,
}
