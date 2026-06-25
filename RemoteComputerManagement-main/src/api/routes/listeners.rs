// src/api/routes/listeners.rs
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json, Extension,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::api::state::ApiContext;
use crate::api::middleware::OperatorInfo;
use crate::database;

#[derive(Deserialize)]
pub struct CreateListenerRequest {
    pub name: String,
    pub port: u16,
    #[serde(default = "default_transport")]
    pub transport: String,
    pub profile_json: Option<String>,
}

fn default_transport() -> String { "tls".into() }

/// GET /api/listeners — list all listeners (DB + runtime status)
pub async fn list(
    State(state): State<Arc<ApiContext>>,
    Extension(_operator): Extension<OperatorInfo>,
) -> Response {
    let db_listeners = {
        let conn = match state.db.get() {
            Ok(c) => c,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "DB error"}))).into_response(),
        };
        database::list_listeners(&conn)
    };

    let active = state.listener_mgr.lock().await.list_active();
    let active_ids: std::collections::HashSet<i64> = active.iter().map(|a| a.id).collect();

    let result: Vec<serde_json::Value> = db_listeners.iter().map(|l| {
        serde_json::json!({
            "id": l.id,
            "name": l.name,
            "port": l.port,
            "transport": l.transport,
            "auto_start": l.auto_start,
            "running": active_ids.contains(&l.id),
            "created_at": l.created_at,
        })
    }).collect();

    (StatusCode::OK, Json(serde_json::json!(result))).into_response()
}

/// POST /api/listeners — create and start a new listener (admin only)
pub async fn create(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    Json(payload): Json<CreateListenerRequest>,
) -> Response {
    if !operator.is_admin() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Admin only"}))).into_response();
    }

    if payload.port == 0 || payload.port == 8080 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Port 0 and 8080 (API) are reserved"}))).into_response();
    }

    // Block privileged ports — binding these requires root and is usually
    // a configuration mistake. Operators who genuinely need port 443 can
    // use iptables REDIRECT or a reverse proxy.
    if payload.port < 1024 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Privileged ports (< 1024) are not allowed. Use a reverse proxy or iptables redirect."}))).into_response();
    }

    // Reject duplicate: another listener already running on this port
    {
        let mgr = state.listener_mgr.lock().await;
        let active = mgr.list_active();
        if active.iter().any(|l| l.port == payload.port && l.running) {
            return (StatusCode::CONFLICT, Json(serde_json::json!({"error": format!("Port {} is already in use by another listener", payload.port)}))).into_response();
        }
    }

    let result = {
        let mut mgr = state.listener_mgr.lock().await;
        mgr.create_and_start(
            &payload.name,
            payload.port,
            &payload.transport,
            payload.profile_json.as_deref(),
        ).await
    };

    match result {
        Ok(lc) => {
            if let Ok(conn) = state.db.get() {
                database::audit_log(&conn, operator.id, &operator.username, "create_listener",
                    None, Some(&format!("name={} port={}", lc.name, lc.port)));
            }
            (StatusCode::CREATED, Json(serde_json::json!(lc))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
    }
}

/// POST /api/listeners/:id/start — start a stopped listener
pub async fn start(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Response {
    if !operator.can_execute() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Insufficient permissions"}))).into_response();
    }

    let lc = {
        let conn = match state.db.get() {
            Ok(c) => c,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "DB error"}))).into_response(),
        };
        database::get_listener(&conn, id)
    };

    match lc {
        Some(l) => {
            let result = state.listener_mgr.lock().await.start_listener(&l).await;
            match result {
                Ok(msg) => (StatusCode::OK, Json(serde_json::json!({"status": msg}))).into_response(),
                Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
            }
        }
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Listener not found"}))).into_response(),
    }
}

/// POST /api/listeners/:id/stop — stop a running listener
pub async fn stop(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Response {
    if !operator.can_execute() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Insufficient permissions"}))).into_response();
    }

    let result = state.listener_mgr.lock().await.stop_listener(id);
    match result {
        Ok(msg) => {
            if let Ok(conn) = state.db.get() {
                database::audit_log(&conn, operator.id, &operator.username, "stop_listener", None, Some(&format!("id={}", id)));
            }
            (StatusCode::OK, Json(serde_json::json!({"status": msg}))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
    }
}

/// DELETE /api/listeners/:id — stop and delete a listener (admin only)
pub async fn delete(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Response {
    if !operator.is_admin() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Admin only"}))).into_response();
    }

    let result = state.listener_mgr.lock().await.remove(id);
    match result {
        Ok(msg) => {
            if let Ok(conn) = state.db.get() {
                database::audit_log(&conn, operator.id, &operator.username, "delete_listener", None, Some(&format!("id={}", id)));
            }
            (StatusCode::OK, Json(serde_json::json!({"status": msg}))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
    }
}
