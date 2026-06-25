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
    body::StreamBody,
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

    // ── Streaming zip via channel ─────────────────────────────────────────────
    //
    // The zip bytes are produced in a spawn_blocking thread by
    // streaming_zip::write_zip_directory and forwarded through a bounded
    // mpsc channel to the Axum response body.  Because we never buffer the
    // whole archive, RAM usage is constant regardless of folder size — a 1 TB
    // folder uses the same ~64 KB copy buffer as a 1 KB folder.
    //
    // No temp file is needed: the previous approach wrote a tempfile first
    // (limiting the archive size to available temp-disk space) then streamed
    // it back.  The streaming approach has no such limit.

    let base_path = full.parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| full.clone());

    // Bounded channel: 32 × 64 KB ≈ 2 MB in flight at a time.
    // The writer blocks (backpressure) if the HTTP layer can't keep up.
    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);

    tokio::task::spawn_blocking(move || {
        /// Write impl that batches output into 64 KB chunks and sends them
        /// through the channel.  Implements backpressure via blocking_send.
        struct ChanWriter {
            tx:  tokio::sync::mpsc::Sender<Vec<u8>>,
            buf: Vec<u8>,
        }
        impl std::io::Write for ChanWriter {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                self.buf.extend_from_slice(data);
                while self.buf.len() >= 65_536 {
                    let chunk: Vec<u8> = self.buf.drain(..65_536).collect();
                    self.tx.blocking_send(chunk).map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::BrokenPipe, "client gone")
                    })?;
                }
                Ok(data.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                if !self.buf.is_empty() {
                    let tail = std::mem::take(&mut self.buf);
                    self.tx.blocking_send(tail).map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::BrokenPipe, "client gone")
                    })?;
                }
                Ok(())
            }
        }
        impl Drop for ChanWriter {
            fn drop(&mut self) {
                use std::io::Write as _;
                let _ = self.flush();
            }
        }

        let mut w = ChanWriter { tx, buf: Vec::with_capacity(65_536) };
        // Errors (e.g. file disappeared mid-zip, client disconnected) are
        // logged at debug level; the channel close signals EOF to the client.
        if let Err(e) = crate::streaming_zip::write_zip_directory(&mut w, &base_path, &full) {
            tracing::debug!(err = %e, "zip_loot: streaming zip aborted");
        }
    });

    // Convert the channel receiver into an async stream for StreamBody.
    let stream = futures::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|chunk| (Ok::<Vec<u8>, std::io::Error>(chunk), rx))
    });
    let body = StreamBody::new(stream);

    use axum::http::{HeaderMap, HeaderValue};
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"));
    headers.insert(header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{}\"", zip_name))
            .unwrap_or_else(|_| HeaderValue::from_static("attachment")));
    // Content-Length is intentionally omitted: the streaming zip computes CRC
    // and sizes on the fly, so the total length is not known before writing.

    (StatusCode::OK, headers, body).into_response()
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
