// src/api/routes/extensions.rs
//
// CRUD for `.rhai` script files in two directories:
//
//   extensions (agent-side, pushed via ext:load):
//     GET    /api/extensions           → list names
//     GET    /api/extensions/:name     → read content
//     PUT    /api/extensions/:name     → create / overwrite
//     DELETE /api/extensions/:name     → delete
//
//   modules (server-side Rhai, run on session connect or via /api/hosts/:id/modules/:name):
//     GET    /api/modules/:name        → read content   (list is still /api/modules in modules.rs)
//     PUT    /api/modules/:name        → create / overwrite
//     DELETE /api/modules/:name        → delete

use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;

use crate::api::middleware::OperatorInfo;

const EXT_DIR: &str = "./extensions";
const MOD_DIR: &str = "./modules";

/// Reject names with path-traversal characters.
fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains("..")
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
}

fn list_rhai_in(dir: &str) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(dir) else { return vec![]; };
    let mut names: Vec<String> = rd
        .filter_map(|e| {
            let e = e.ok()?;
            if !e.file_type().ok()?.is_file() { return None; }
            let raw = e.file_name().into_string().ok()?;
            raw.ends_with(".rhai")
                .then(|| raw.trim_end_matches(".rhai").to_string())
        })
        .collect();
    names.sort();
    names
}

// ─────────────────────────────────────────────────────────────────────────────
// Extensions  (/api/extensions[/:name])
// ─────────────────────────────────────────────────────────────────────────────

pub async fn list_extensions() -> impl IntoResponse {
    let names = tokio::task::spawn_blocking(|| list_rhai_in(EXT_DIR))
        .await.unwrap_or_default();
    Json(serde_json::json!({ "extensions": names }))
}

pub async fn get_extension(Path(name): Path<String>) -> Response {
    get_script(EXT_DIR, &name).await
}

#[derive(Deserialize)]
pub struct ScriptBody { pub content: String }

pub async fn put_extension(
    Extension(op): Extension<OperatorInfo>,
    Path(name): Path<String>,
    Json(body): Json<ScriptBody>,
) -> Response {
    write_script(op, EXT_DIR, &name, body.content).await
}

pub async fn delete_extension(
    Extension(op): Extension<OperatorInfo>,
    Path(name): Path<String>,
) -> Response {
    delete_script(op, EXT_DIR, &name).await
}

// ─────────────────────────────────────────────────────────────────────────────
// Modules  (/api/modules/:name)
// ─────────────────────────────────────────────────────────────────────────────

// Note: GET /api/modules (list) lives in modules.rs; we only add per-file CRUD.

pub async fn get_module(Path(name): Path<String>) -> Response {
    get_script(MOD_DIR, &name).await
}

pub async fn put_module(
    Extension(op): Extension<OperatorInfo>,
    Path(name): Path<String>,
    Json(body): Json<ScriptBody>,
) -> Response {
    write_script(op, MOD_DIR, &name, body.content).await
}

pub async fn delete_module(
    Extension(op): Extension<OperatorInfo>,
    Path(name): Path<String>,
) -> Response {
    delete_script(op, MOD_DIR, &name).await
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

async fn get_script(dir: &str, name: &str) -> Response {
    if !safe_name(name) {
        return (StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error":"invalid name"}))).into_response();
    }
    let path = format!("{}/{}.rhai", dir, name);
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => Json(serde_json::json!({ "name": name, "content": content })).into_response(),
        Err(_)      => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn write_script(op: OperatorInfo, dir: &str, name: &str, content: String) -> Response {
    if !op.can_execute() {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !safe_name(name) {
        return (StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error":"invalid name"}))).into_response();
    }
    let _ = tokio::fs::create_dir_all(dir).await;
    let path = format!("{}/{}.rhai", dir, name);
    match tokio::fs::write(&path, content.as_bytes()).await {
        Ok(_)  => (StatusCode::OK,
                   Json(serde_json::json!({"saved": name}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR,
                   Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

async fn delete_script(op: OperatorInfo, dir: &str, name: &str) -> Response {
    if !op.can_execute() {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !safe_name(name) {
        return (StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error":"invalid name"}))).into_response();
    }
    let path = format!("{}/{}.rhai", dir, name);
    match tokio::fs::remove_file(&path).await {
        Ok(_)  => StatusCode::NO_CONTENT.into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests — safe_name validator
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod unit {
    use super::safe_name;

    #[test]
    fn accepts_plain_names() {
        for name in ["auto_persist", "recon", "a", "A-Z_09", "my-script-v2"] {
            assert!(safe_name(name), "expected safe: {}", name);
        }
    }

    #[test]
    fn rejects_empty() {
        assert!(!safe_name(""));
    }

    #[test]
    fn rejects_dot_dot() {
        for bad in ["..", "../etc/passwd", "foo/../bar", "..\\windows"] {
            assert!(!safe_name(bad), "expected unsafe: {}", bad);
        }
    }

    #[test]
    fn rejects_slashes() {
        assert!(!safe_name("sub/script"));
        assert!(!safe_name("sub\\script"));
    }

    #[test]
    fn rejects_null_byte() {
        assert!(!safe_name("foo\0bar"));
    }
}
