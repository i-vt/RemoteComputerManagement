// src/api/routes/rcm.rs
//
// Operator-facing RCM package management (SPEC §5):
//
// GET /api/rcm/packages
//   Enumerate the packages under downloads/*. A package root is a directory
//   containing `.rcmtarget` OR any of fingerprint.RCM.xml / downloads/ /
//   downloads.metadata/. Returns
//   [{"name","sealed":bool,"generations":n,"size_bytes":n}].
//
// POST /api/rcm/seal body {"name":"<RootFolder>"}
//   Seal the package (Sec 17.2 manifest + PACKAGE custody event).
//   -> {"manifest":"<manifest file name>","generation":n};
//   404 if the package is unknown, 500 with a message on seal errors.
//
// POST /api/rcm/verify body {"name":"<RootFolder>"}
//   Verify the latest manifest generation (REQ-17.2.4).
//   -> {"mismatches":[...]}  (empty = OK); 404 unknown, 500 on error.
//
// All routes are registered behind the API auth middleware (never public).

use axum::{
    extract::State,
    response::{IntoResponse, Response},
    http::StatusCode,
    Json,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::api::state::ApiContext;
use crate::rcm::PackageManager;

// ── helpers ───────────────────────────────────────────────────────────────────

/// Recursive size of `path` in bytes; symlinks are never followed.
fn dir_size(path: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack: Vec<PathBuf> = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for e in entries.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                stack.push(e.path());
            } else if ft.is_file() {
                total += e.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }
    }
    total
}

/// Count manifest generations present at a package root
/// (manifest.RCM.xml + manifest.RCM.<n>.xml).
fn manifest_generations(root: &Path) -> u64 {
    let mut n = 0u64;
    if let Ok(entries) = std::fs::read_dir(root) {
        for e in entries.flatten() {
            let name = e.file_name().into_string().unwrap_or_default();
            if name == "manifest.RCM.xml"
                || (name.starts_with("manifest.RCM.") && name.ends_with(".xml"))
            {
                n += 1;
            }
        }
    }
    n
}

/// Parse the generation number out of a manifest file name.
fn manifest_generation(fname: &str) -> u64 {
    if fname == "manifest.RCM.xml" {
        0
    } else {
        fname
            .trim_start_matches("manifest.RCM.")
            .trim_end_matches(".xml")
            .parse::<u64>()
            .unwrap_or(0)
    }
}

#[derive(serde::Deserialize)]
pub struct PackageRequest {
    name: String,
}

/// Open a package by root folder name, mapping failures to HTTP status:
/// 404 when there is no such directory, 500 otherwise.
///
/// Routed through the shared registry (NOT a fresh
/// PackageManager::open_by_root_name): every caller must share ONE Arc per
/// on-disk package so seal/verify take the same write lock as in-flight
/// stores from the session path - a private manager here would race them.
fn open_package(name: &str) -> Result<Arc<PackageManager>, Response> {
    // Base matches rcm::registry()'s base; see the note there on why it is
    // not yet read from config.rcm.storage_base.
    let base = Path::new(crate::config::config().rcm.storage_base.as_str());
    let root = base.join(name);
    let exists = root
        .symlink_metadata()
        .map(|m| m.is_dir() && !m.file_type().is_symlink())
        .unwrap_or(false);
    match crate::rcm::registry().by_root_name(name) {
        Ok(pkg) => Ok(pkg),
        Err(e) => Err(if !exists {
            (StatusCode::NOT_FOUND, format!("unknown package: {}", name)).into_response()
        } else {
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }),
    }
}

// ── handlers ──────────────────────────────────────────────────────────────────

/// GET /api/rcm/packages
pub async fn list_packages(State(_state): State<Arc<ApiContext>>) -> impl IntoResponse {
    let packages = tokio::task::spawn_blocking(|| {
        let mut out: Vec<serde_json::Value> = Vec::new();
        let base = Path::new(crate::config::config().rcm.storage_base.as_str());
        if let Ok(entries) = std::fs::read_dir(base) {
            for e in entries.flatten() {
                let Ok(ft) = e.file_type() else { continue };
                if ft.is_symlink() || !ft.is_dir() {
                    continue;
                }
                let root = e.path();
                let is_package = root.join(".rcmtarget").exists()
                    || root.join("fingerprint.RCM.xml").exists()
                    || root.join("downloads").is_dir()
                    || root.join("downloads.metadata").is_dir();
                if !is_package {
                    continue;
                }
                let name = e.file_name().into_string().unwrap_or_default();
                out.push(serde_json::json!({
                    "name": name,
                    "sealed": root.join("manifest.RCM.xml").exists(),
                    "generations": manifest_generations(&root),
                    "size_bytes": dir_size(&root),
                }));
            }
        }
        out.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        out
    })
    .await
    .unwrap_or_default();

    Json(packages)
}

/// POST /api/rcm/seal
pub async fn seal_package(Json(body): Json<PackageRequest>) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let pkg = open_package(&body.name)?;
        pkg.seal()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())
    })
    .await;

    match result {
        Ok(Ok(path)) => {
            let fname = path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let generation = manifest_generation(&fname);
            (
                StatusCode::OK,
                Json(serde_json::json!({ "manifest": fname, "generation": generation })),
            )
                .into_response()
        }
        Ok(Err(resp)) => resp,
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// POST /api/rcm/verify
pub async fn verify_package(Json(body): Json<PackageRequest>) -> Response {
    let result = tokio::task::spawn_blocking(move || {
        let pkg = open_package(&body.name)?;
        pkg.verify()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())
    })
    .await;

    match result {
        Ok(Ok(mismatches)) => {
            (StatusCode::OK, Json(serde_json::json!({ "mismatches": mismatches })))
                .into_response()
        }
        Ok(Err(resp)) => resp,
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
