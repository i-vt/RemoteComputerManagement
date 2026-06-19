// src/api/routes/topology.rs
//
// GET /api/topology/plan?target=<ip>
//   Returns route candidates across all connected sessions that can reach
//   the target IP or CIDR. Completely passive — no probes sent, no new
//   network traffic generated. Analysis is over data agents already reported
//   at registration.
//
// GET /api/topology/snapshot
//   Full cross-session topology view: all candidates, shared networks, and
//   overlapping-CIDR conflicts.
//
// Routes to register in src/api/mod.rs:
//   .route("/api/topology/plan",     get(topology::plan))
//   .route("/api/topology/snapshot", get(topology::snapshot))

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::api::state::ApiContext;
use crate::topology::{RouteCandidate, RouteConflict, SessionSnapshot, SharedNetwork, TopologyManager};

// ── Request / Response types ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct PlanQuery {
    /// Target IP ("10.0.0.5") or CIDR ("10.0.0.0/24").
    target: String,
}

#[derive(Serialize)]
pub struct CandidateDto {
    pub session_id: u32,
    pub hostname: String,
    pub cidr: String,
    pub interface: String,
    pub source_addr: String,
    pub score: u16,
}

#[derive(Serialize)]
pub struct SharedNetworkDto {
    pub cidr: String,
    pub sessions: Vec<u32>,
}

#[derive(Serialize)]
pub struct ConflictDto {
    pub cidr_a: String,
    pub cidr_b: String,
    pub session_a: u32,
    pub session_b: u32,
}

#[derive(Serialize)]
pub struct PlanResponse {
    pub target: String,
    /// Ranked candidates, highest score first.
    pub candidates: Vec<CandidateDto>,
    /// Human-readable render of the plan (same as server console output).
    pub rendered: String,
}

#[derive(Serialize)]
pub struct SnapshotResponse {
    pub session_count: usize,
    pub candidates: Vec<CandidateDto>,
    pub shared_networks: Vec<SharedNetworkDto>,
    pub conflicts: Vec<ConflictDto>,
}

// ── Conversions ────────────────────────────────────────────────────────────

impl From<RouteCandidate> for CandidateDto {
    fn from(c: RouteCandidate) -> Self {
        Self {
            session_id: c.session_id,
            hostname: c.hostname,
            cidr: c.cidr,
            interface: c.interface,
            source_addr: c.source_addr,
            score: c.score,
        }
    }
}

impl From<SharedNetwork> for SharedNetworkDto {
    fn from(n: SharedNetwork) -> Self {
        Self {
            cidr: n.cidr,
            sessions: n.sessions,
        }
    }
}

impl From<RouteConflict> for ConflictDto {
    fn from(c: RouteConflict) -> Self {
        Self {
            cidr_a: c.cidr_a,
            cidr_b: c.cidr_b,
            session_a: c.session_a,
            session_b: c.session_b,
        }
    }
}

// ── Handlers ───────────────────────────────────────────────────────────────

/// GET /api/topology/plan?target=<ip_or_cidr>
///
/// Returns ranked sessions that can reach the target.
/// 200 with empty candidates vec when target is unreachable from any session.
/// 400 when target is not a valid IP or CIDR.
pub async fn plan(
    State(state): State<Arc<ApiContext>>,
    Query(params): Query<PlanQuery>,
) -> impl IntoResponse {
    let target = params.target.trim().to_string();

    // Basic validation — TopologyManager::plan returns empty for invalid IPs,
    // but we want a 400 here instead of a silent empty 200.
    if target.is_empty()
        || target
            .split('/')
            .next()
            .and_then(|s| s.parse::<std::net::IpAddr>().ok())
            .is_none()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "target must be a valid IPv4 address or CIDR"})),
        )
            .into_response();
    }

    let sessions = collect_snapshots(&state);
    let candidates: Vec<CandidateDto> = TopologyManager::plan(&sessions, &target)
        .into_iter()
        .map(Into::into)
        .collect();

    let rendered = TopologyManager::render_plan(&target, {
        // Re-collect as RouteCandidate slice to pass to render_plan
        // We already consumed candidates above; re-run plan for the render.
        &TopologyManager::plan(&sessions, &target)
    });

    Json(PlanResponse {
        target,
        candidates,
        rendered,
    })
    .into_response()
}

/// GET /api/topology/snapshot
///
/// Full cross-session topology view: all non-loopback routes, shared
/// networks, and overlapping-CIDR conflicts.
pub async fn snapshot(State(state): State<Arc<ApiContext>>) -> Json<SnapshotResponse> {
    let sessions = collect_snapshots(&state);
    let session_count = sessions.len();
    let snap = TopologyManager::build_snapshot(&sessions);

    Json(SnapshotResponse {
        session_count,
        candidates: snap.candidates.into_iter().map(Into::into).collect(),
        shared_networks: snap.shared_networks.into_iter().map(Into::into).collect(),
        conflicts: snap.conflicts.into_iter().map(Into::into).collect(),
    })
}

// ── Private helpers ────────────────────────────────────────────────────────

fn collect_snapshots(state: &ApiContext) -> Vec<SessionSnapshot> {
    state
        .sessions
        .iter()
        .map(|entry| SessionSnapshot {
            session_id: *entry.key(),
            hostname: entry.value().hostname.clone(),
            interfaces: entry.value().interfaces.clone(),
        })
        .collect()
}
