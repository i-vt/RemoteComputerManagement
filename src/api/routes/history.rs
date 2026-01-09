use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;
use crate::api::state::ApiContext;
use crate::api::models::UnifiedHistoryDto;
use crate::database;

pub async fn get_history(
    State(state): State<Arc<ApiContext>>,
    Path(id): Path<u32>,
) -> Response {
    let db = state.db.clone();
    let history_result = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        database::get_session_full_history(&conn, id, 50) 
    }).await.unwrap();

    match history_result {
        Ok(logs) => {
            let dtos: Vec<UnifiedHistoryDto> = logs.into_iter().map(|l| UnifiedHistoryDto {
                session_id: l.session_id,
                request_id: l.request_id,
                command: l.command,
                output: l.output,
                error: l.error,
                timestamp: l.timestamp,
            }).collect();
            (StatusCode::OK, Json(dtos)).into_response()
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

pub async fn get_global_history(State(state): State<Arc<ApiContext>>) -> Response {
    let db = state.db.clone();
    let history_result = tokio::task::spawn_blocking(move || {
        let conn = db.lock().unwrap();
        database::get_global_full_history(&conn, 100)
    }).await.unwrap();

    match history_result {
        Ok(logs) => {
            let dtos: Vec<UnifiedHistoryDto> = logs.into_iter().map(|l| UnifiedHistoryDto {
                session_id: l.session_id,
                request_id: l.request_id,
                command: l.command,
                output: l.output,
                error: l.error,
                timestamp: l.timestamp,
            }).collect();
            (StatusCode::OK, Json(dtos)).into_response()
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}
