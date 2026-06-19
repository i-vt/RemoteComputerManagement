// src/api/routes/tasks.rs
//
// Task queue endpoints for hibernating agents.
//
// Hibernating agents don't hold persistent connections — they check in on a
// jitter-bounded interval, claim whatever is queued, execute, and disconnect.
// These endpoints let operators enqueue commands ahead of the next check-in.
//
// Routes to register in src/api/mod.rs:
//   .route("/api/hosts/:id/queue",          post(tasks::queue_task))
//   .route("/api/hosts/:id/tasks",          get(tasks::list_tasks))
//   .route("/api/hosts/:id/tasks/:task_id", get(tasks::get_task))
//   .route("/api/hosts/:id/tasks/:task_id", delete(tasks::cancel_task))

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::api::middleware::OperatorInfo;
use crate::api::state::ApiContext;
use crate::database::{self, QueuedTask};

// ── Request / Response types ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct QueueRequest {
    pub command: String,
}

#[derive(Serialize)]
pub struct QueueResponse {
    pub task_id: String,
    pub session_id: u32,
    pub command: String,
    pub status: String,
}

#[derive(Serialize)]
pub struct TasksResponse {
    pub session_id: u32,
    pub tasks: Vec<QueuedTaskDto>,
    pub total: usize,
}

#[derive(Serialize)]
pub struct QueuedTaskDto {
    pub task_id: String,
    pub command: String,
    pub status: String,
    pub created_at: i64,
    pub claimed_at: Option<i64>,
    pub result: Option<String>,
    pub error: Option<String>,
    pub finished_at: Option<i64>,
}

impl From<QueuedTask> for QueuedTaskDto {
    fn from(t: QueuedTask) -> Self {
        Self {
            task_id: t.task_id,
            command: t.command,
            status: t.status,
            created_at: t.created_at,
            claimed_at: t.claimed_at,
            result: t.result,
            error: t.error,
            finished_at: t.finished_at,
        }
    }
}

// ── Handlers ───────────────────────────────────────────────────────────────

/// POST /api/hosts/:id/queue
/// Body: { "command": "shell id" }
///
/// Enqueue a command for a hibernating agent's next check-in.
/// The session doesn't need to be connected — tasks persist in the DB until
/// the agent connects and claims them.
///
/// Returns 201 Created with the task_id on success.
/// Returns 403 for viewer-role operators.
/// Returns 404 if the session_id has no DB record.
pub async fn queue_task(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    Path(session_id): Path<u32>,
    Json(req): Json<QueueRequest>,
) -> impl IntoResponse {
    if operator.is_viewer() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Viewers cannot queue tasks"})),
        )
            .into_response();
    }

    if req.command.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "command must not be empty"})),
        )
            .into_response();
    }

    let conn = match state.db.get() {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "database unavailable"})),
            )
                .into_response()
        }
    };

    // Audit log
    database::audit_log(
        &conn,
        operator.id,
        &operator.username,
        "queue_task",
        Some(session_id),
        Some(&req.command),
    );

    match database::queue_task(&conn, session_id as i64, &req.command) {
        Ok(task_id) => (
            StatusCode::CREATED,
            Json(QueueResponse {
                task_id,
                session_id,
                command: req.command,
                status: "pending".to_string(),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// GET /api/hosts/:id/tasks
///
/// List all tasks for a session (last 100, newest first).
/// Works for both hibernating and persistent sessions.
/// Returns 200 with an empty `tasks` array when no tasks exist.
pub async fn list_tasks(
    State(state): State<Arc<ApiContext>>,
    Path(session_id): Path<u32>,
) -> impl IntoResponse {
    let conn = match state.db.get() {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "database unavailable"})),
            )
                .into_response()
        }
    };

    let tasks: Vec<QueuedTaskDto> = database::list_tasks(&conn, session_id as i64)
        .into_iter()
        .map(Into::into)
        .collect();

    let total = tasks.len();
    Json(TasksResponse {
        session_id,
        tasks,
        total,
    })
    .into_response()
}

/// GET /api/hosts/:id/tasks/:task_id
///
/// Fetch a single task by its UUID.
pub async fn get_task(
    State(state): State<Arc<ApiContext>>,
    Path((session_id, task_id)): Path<(u32, String)>,
) -> impl IntoResponse {
    let conn = match state.db.get() {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "database unavailable"})),
            )
                .into_response()
        }
    };

    let tasks = database::list_tasks(&conn, session_id as i64);
    match tasks.into_iter().find(|t| t.task_id == task_id) {
        Some(t) => Json(QueuedTaskDto::from(t)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "task not found"})),
        )
            .into_response(),
    }
}

/// DELETE /api/hosts/:id/tasks/:task_id
///
/// Cancel a pending task. Only works on tasks with status = 'pending'.
/// Has no effect on running, completed, or failed tasks.
pub async fn cancel_task(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    Path((session_id, task_id)): Path<(u32, String)>,
) -> impl IntoResponse {
    if operator.is_viewer() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Viewers cannot cancel tasks"})),
        )
            .into_response();
    }

    let conn = match state.db.get() {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "database unavailable"})),
            )
                .into_response()
        }
    };

    // Only cancel if still pending — don't interrupt an in-flight batch
    let affected = conn
        .execute(
            "UPDATE queued_tasks SET status = 'cancelled'
              WHERE task_id = ?1 AND session_id = ?2 AND status = 'pending'",
            rusqlite::params![task_id, session_id as i64],
        )
        .unwrap_or(0);

    if affected == 0 {
        return (
            StatusCode::CONFLICT,
            Json(
                serde_json::json!({"error": "task not found or already claimed/completed"}),
            ),
        )
            .into_response();
    }

    database::audit_log(
        &conn,
        operator.id,
        &operator.username,
        "cancel_task",
        Some(session_id),
        Some(&task_id),
    );

    (StatusCode::NO_CONTENT, ()).into_response()
}
