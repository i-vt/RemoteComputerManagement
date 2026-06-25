// src/api/routes/downloads.rs
//
// GET /api/hosts/:id/screenshots
//   Lists screenshot folders saved by the server for a given session.
//   Returns them newest-first so the panel can pick up the latest capture.
//
// GET /api/downloads/*path
//   Serves any file under the server-side `downloads/` directory.
//   Path traversal is blocked by rejecting `..` components.
//   Requires X-API-KEY auth (applied by the router's middleware layer).

use axum::{
    extract::{Path, State},
    response::{IntoResponse, Response},
    http::{StatusCode, header},
    Json,
};
use std::{path::PathBuf, sync::Arc};
use crate::api::state::ApiContext;

// ── Screenshot folder listing ─────────────────────────────────────────────────

pub async fn list_screenshots(
    Path(session_id): Path<u32>,
    State(_state): State<Arc<ApiContext>>,
) -> impl IntoResponse {
    let downloads = PathBuf::from("downloads");
    // Convention: {timestamp}_{session_id}_screenshot  (matches file_transfer naming)
    let suffix = format!("_{}_screenshot", session_id);

    let mut folders: Vec<String> = tokio::task::spawn_blocking(move || {
        let Ok(entries) = std::fs::read_dir(&downloads) else {
            return vec![];
        };
        entries
            .filter_map(|e| {
                let name = e.ok()?.file_name().into_string().ok()?;
                if name.ends_with(&suffix) {
                    Some(name)
                } else {
                    None
                }
            })
            .collect()
    })
    .await
    .unwrap_or_default();

    // Newest-first (folder names embed a timestamp so lexicographic sort works)
    folders.sort_by(|a, b| b.cmp(a));

    Json(serde_json::json!({ "folders": folders }))
}

// ── File serving ──────────────────────────────────────────────────────────────

pub async fn serve_download(Path(path): Path<String>) -> Response {
    // Block path traversal: reject any component that is or contains ".."
    let safe: PathBuf = path
        .split('/')
        .filter(|seg| !seg.is_empty() && *seg != ".." && !seg.contains(".."))
        .collect();

    if safe.components().count() == 0 {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let full = PathBuf::from("downloads").join(&safe);

    match tokio::fs::read(&full).await {
        Ok(bytes) => {
            // Guess MIME type from extension; fall back to octet-stream
            let mime = match full.extension().and_then(|e| e.to_str()).unwrap_or("") {
                "png"  => "image/png",
                "jpg" | "jpeg" => "image/jpeg",
                "json" => "application/json",
                "txt"  => "text/plain",
                _      => "application/octet-stream",
            };
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, mime)],
                bytes,
            ).into_response()
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

// ── Loot directory listing ────────────────────────────────────────────────────

#[derive(serde::Serialize)]
pub struct LootEntry {
    pub name: String,
    pub path: String,      // relative to downloads/
    pub is_dir: bool,
    pub size: u64,
    pub modified: u64,     // Unix timestamp
    pub children: Option<Vec<LootEntry>>,
}

/// Walk one level of `downloads/<subpath>` and return the entries.
/// If subpath is empty, lists the root of downloads/.
/// Directories are returned with children = None (client requests them on expand).
fn list_dir(rel: &str) -> Vec<LootEntry> {
    let base = std::path::Path::new("downloads");
    let target = if rel.is_empty() { base.to_path_buf() } else {
        // block traversal
        let safe: std::path::PathBuf = rel.split('/').filter(|s| !s.is_empty() && !s.contains("..")).collect();
        base.join(safe)
    };

    let Ok(dir) = std::fs::read_dir(&target) else { return vec![]; };

    let mut entries: Vec<LootEntry> = dir
        .filter_map(|e| {
            let e = e.ok()?;
            let meta = e.metadata().ok()?;
            let name = e.file_name().into_string().ok()?;
            let modified = meta
                .modified().ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let rel_path = if rel.is_empty() {
                name.clone()
            } else {
                format!("{}/{}", rel, &name)
            };
            Some(LootEntry {
                name,
                path: rel_path,
                is_dir: meta.is_dir(),
                size: if meta.is_file() { meta.len() } else { 0 },
                modified,
                children: None,
            })
        })
        .collect();

    entries.sort_by(|a, b| {
        match (a.is_dir, b.is_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => b.modified.cmp(&a.modified),  // newest first
        }
    });
    entries
}

/// GET /api/loot?path=<optional_subpath>
pub async fn list_loot(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let subpath = params.get("path").map(|s| s.as_str()).unwrap_or("");
    let entries = tokio::task::spawn_blocking({
        let subpath = subpath.to_string();
        move || list_dir(&subpath)
    }).await.unwrap_or_default();

    Json(serde_json::json!({ "path": subpath, "entries": entries }))
}

/// GET /api/loot/zip?path=<folder_path>
/// Recursively zips everything under downloads/<path> and returns it as
/// a single application/zip download.  Useful for pulling an entire
/// session's loot folder in one click from the panel.
pub async fn zip_loot(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    use std::io::Write as _;

    let subpath = match params.get("path") {
        Some(p) if !p.is_empty() => p.clone(),
        _ => return (StatusCode::BAD_REQUEST, "path required").into_response(),
    };

    let safe: PathBuf = subpath
        .split('/')
        .filter(|s| !s.is_empty() && !s.contains(".."))
        .collect();
    if safe.components().count() == 0 {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let full      = PathBuf::from("downloads").join(&safe);
    let zip_name  = format!(
        "{}.zip",
        safe.file_name().and_then(|n| n.to_str()).unwrap_or("loot")
    );

    if !full.is_dir() {
        return (StatusCode::NOT_FOUND, "Not a directory").into_response();
    }

    let result = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, String> {
        use std::io::{BufReader, Write as _};

        // Strip from the parent so the folder name becomes the zip root.
        let base_path: std::path::PathBuf = full
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| full.clone());

        let cursor  = std::io::Cursor::new(Vec::new());
        let mut zip = zip::ZipWriter::new(cursor);

        let file_opts = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        let dir_opts  = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);

        // Explicit stack traversal — avoids recursion stack-overflow on deep
        // trees and streams each file directly into the zip via io::copy so
        // we never buffer all file bytes in RAM at once.
        let mut stack: Vec<std::path::PathBuf> = vec![full.clone()];

        while let Some(current_dir) = stack.pop() {
            let entries = match std::fs::read_dir(&current_dir) {
                Ok(e)  => e,
                Err(_) => continue,
            };

            for entry in entries.flatten() {
                let path = entry.path();

                let rel = match path.strip_prefix(&base_path) {
                    Ok(r)  => r.to_string_lossy().replace('\\', "/"),
                    Err(_) => continue,
                };

                if path.is_dir() {
                    let dir_name = if rel.ends_with('/') {
                        rel.to_string()
                    } else {
                        format!("{}/", rel)
                    };
                    zip.add_directory(&dir_name, dir_opts)
                        .map_err(|e| e.to_string())?;
                    stack.push(path);

                } else if path.is_file() {
                    zip.start_file(&rel, file_opts)
                        .map_err(|e| e.to_string())?;

                    let file = match std::fs::File::open(&path) {
                        Ok(f)  => f,
                        Err(_) => continue,
                    };
                    let mut reader = BufReader::new(file);
                    std::io::copy(&mut reader, &mut zip)
                        .map_err(|e| e.to_string())?;
                }
            }
        }

        let finished = zip.finish().map_err(|e| e.to_string())?;
        Ok(finished.into_inner())
    })
    .await;

    match result {
        Ok(Ok(bytes)) => {
            use axum::http::{HeaderMap, HeaderValue};
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE,
                HeaderValue::from_static("application/zip"));
            headers.insert(header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&format!("attachment; filename=\"{}\"", zip_name))
                    .unwrap_or_else(|_| HeaderValue::from_static("attachment")));
            (StatusCode::OK, headers, bytes).into_response()
        }
        _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// DELETE /api/loot?path=<file_or_dir>
/// Removes a single file or an empty directory from downloads/.
pub async fn delete_loot(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let subpath = match params.get("path") {
        Some(p) if !p.is_empty() => p.clone(),
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    let safe: std::path::PathBuf = subpath.split('/').filter(|s| !s.is_empty() && !s.contains("..")).collect();
    let full = std::path::PathBuf::from("downloads").join(safe);

    let result = tokio::task::spawn_blocking(move || {
        if full.is_dir() { std::fs::remove_dir_all(&full) } else { std::fs::remove_file(&full) }
    }).await;

    match result {
        Ok(Ok(_)) => StatusCode::NO_CONTENT.into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}
