// src/api/routes/iocs.rs
//
// CRUD routes for the IOC (artifact) tracker.
// DB helpers live in database.rs; this file just exposes them over HTTP.
//
// Routes (all protected by X-API-KEY middleware):
//   GET    /api/iocs                — all IOCs, active first
//   GET    /api/hosts/:id/iocs      — IOCs for one session
//   POST   /api/hosts/:id/iocs      — record a new artifact
//   POST   /api/iocs/:id/clean      — stamp cleaned_at (idempotent)
//   DELETE /api/iocs/:id            — hard-delete a record

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json, Extension,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::api::state::ApiContext;
use crate::api::middleware::OperatorInfo;
use crate::database;

// ── helpers ───────────────────────────────────────────────────────────────────

macro_rules! db {
    ($state:expr) => {
        match $state.db.get() {
            Ok(c)  => c,
            Err(_) => return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error":"db pool exhausted"}))
            ).into_response(),
        }
    };
}

// ── DTO ───────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct IocDto {
    id:          i64,
    session_id:  i64,
    ioc_type:    String,
    path:        String,
    detail:      Option<String>,
    cleanup_cmd: Option<String>,
    operator:    String,
    created_at:  String,
    cleaned_at:  Option<String>,
}

#[derive(Deserialize)]
pub struct AddIocBody {
    pub ioc_type:    String,
    pub path:        String,
    pub detail:      Option<String>,
    pub cleanup_cmd: Option<String>,
}

// ── handlers ──────────────────────────────────────────────────────────────────

/// GET /api/iocs
pub async fn list_all(State(state): State<Arc<ApiContext>>) -> Response {
    let conn = db!(state);
    let rows = database::list_all_iocs(&conn)
        .into_iter()
        .map(|r| IocDto {
            id: r.id, session_id: r.session_id, ioc_type: r.ioc_type,
            path: r.path, detail: r.detail, cleanup_cmd: r.cleanup_cmd,
            operator: r.operator, created_at: r.created_at, cleaned_at: r.cleaned_at,
        })
        .collect::<Vec<_>>();
    (StatusCode::OK, Json(rows)).into_response()
}

/// GET /api/hosts/:id/iocs
pub async fn list_for_session(
    Path(session_id): Path<u32>,
    State(state): State<Arc<ApiContext>>,
) -> Response {
    let conn = db!(state);
    let rows = database::list_iocs_for_session(&conn, session_id)
        .into_iter()
        .map(|r| IocDto {
            id: r.id, session_id: r.session_id, ioc_type: r.ioc_type,
            path: r.path, detail: r.detail, cleanup_cmd: r.cleanup_cmd,
            operator: r.operator, created_at: r.created_at, cleaned_at: r.cleaned_at,
        })
        .collect::<Vec<_>>();
    (StatusCode::OK, Json(rows)).into_response()
}

/// POST /api/hosts/:id/iocs
pub async fn add(
    Path(session_id): Path<u32>,
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    Json(body): Json<AddIocBody>,
) -> Response {
    let conn = db!(state);
    match database::add_ioc(
        &conn, session_id, &body.ioc_type, &body.path,
        body.detail.as_deref(), body.cleanup_cmd.as_deref(), &operator.username,
    ) {
        Ok(id)  => (StatusCode::CREATED, Json(serde_json::json!({"id": id}))).into_response(),
        Err(e)  => (StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

/// POST /api/iocs/:id/clean
pub async fn mark_clean(
    Path(ioc_id): Path<i64>,
    State(state): State<Arc<ApiContext>>,
) -> Response {
    let conn = db!(state);
    match database::mark_ioc_cleaned(&conn, ioc_id) {
        Ok(_)  => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR,
                   Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

/// DELETE /api/iocs/:id
pub async fn delete(
    Path(ioc_id): Path<i64>,
    State(state): State<Arc<ApiContext>>,
) -> Response {
    let conn = db!(state);
    match database::delete_ioc(&conn, ioc_id) {
        Ok(_)  => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR,
                   Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}
