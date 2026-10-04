// src/api/routes/listeners.rs
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json, Extension,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::api::state::ApiContext;
use crate::api::middleware::OperatorInfo;
use crate::database;
use crate::config::config;
use std::collections::BTreeSet;
use std::net::Ipv4Addr;

#[derive(Deserialize)]
pub struct CreateListenerRequest {
    pub name: String,
    pub port: u16,
    #[serde(default = "default_transport")]
    pub transport: String,
    pub profile_json: Option<String>,
}

fn default_transport() -> String { "tls".into() }

/// Directory holding the built-in traffic profiles, relative to the server
/// working directory (same convention as certs/ and downloads/).
const TRAFFIC_PROFILES_DIR: &str = "traffic_profiles";

/// Largest profile file served to the panel; shipped profiles are a few KB.
const MAX_PROFILE_BYTES: u64 = 256 * 1024;

/// Read `dir` and return the traffic profiles it contains as
/// [{name, content}]. Only regular .json files under the size cap are
/// returned; symlinks and subdirectories are skipped. Split from the
/// handler so the listing logic can be tested against a tempdir.
fn list_traffic_profiles(dir: &std::path::Path) -> Result<Vec<serde_json::Value>, String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot read {}: {}", dir.display(), e))?;
    let mut profiles = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
        if !meta.is_file() || meta.len() > MAX_PROFILE_BYTES {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Some(name) = path.file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string()) else { continue };
        if let Ok(content) = std::fs::read_to_string(&path) {
            profiles.push(serde_json::json!({ "name": name, "content": content }));
        }
    }
    profiles.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(profiles)
}

/// GET /api/listeners/profiles - list the built-in traffic profiles
/// (operator role or higher). Returns [{name, content}] so the panel no
/// longer ships static copies of traffic_profiles/.
///
/// This is a read-only directory listing: it takes no filename parameter,
/// so there is no path-traversal surface. Only regular .json files under
/// the size cap are returned; symlinks and subdirectories are skipped.
pub async fn profiles(
    Extension(operator): Extension<OperatorInfo>,
) -> Response {
    if !operator.can_execute() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Insufficient permissions"}))).into_response();
    }

    match tokio::task::spawn_blocking(|| list_traffic_profiles(std::path::Path::new(TRAFFIC_PROFILES_DIR))).await {
        Ok(Ok(list)) => (StatusCode::OK, Json(serde_json::json!(list))).into_response(),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

/// Parse IPv4 SAN entries from `openssl x509 -text` output.
#[doc(hidden)]
pub fn parse_ipv4_sans_from_openssl_text(text: &str) -> Vec<Ipv4Addr> {
    text.split("IP Address:")
        .skip(1)
        .filter_map(|part| part.split([',', '\n', '\r']).next()?.trim().parse().ok())
        .collect()
}

/// Merge certificate SANs, host interface addresses, and a concrete API bind
/// address. Interface and bind wildcards/loopbacks are not useful C2 hints.
#[doc(hidden)]
pub fn collect_c2_hints(
    openssl_text: &str,
    interface_addresses: &[String],
    api_bind_addr: &str,
) -> Vec<String> {
    let mut hints = BTreeSet::new();
    hints.extend(parse_ipv4_sans_from_openssl_text(openssl_text));
    for address in interface_addresses {
        let candidate = address.split('/').next().unwrap_or(address);
        if let Ok(ip) = candidate.parse::<Ipv4Addr>() {
            if !ip.is_loopback() && !ip.is_unspecified() {
                hints.insert(ip);
            }
        }
    }
    if let Ok(ip) = api_bind_addr.parse::<Ipv4Addr>() {
        if !ip.is_loopback() && !ip.is_unspecified() {
            hints.insert(ip);
        }
    }
    hints.into_iter().map(|ip| ip.to_string()).collect()
}

fn current_c2_hints() -> Vec<String> {
    let cert_text = std::process::Command::new("openssl")
        .args(["x509", "-in", "certs/server.crt", "-noout", "-text"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default();
    let interface_addresses: Vec<String> = crate::utils::get_network_interfaces()
        .into_iter()
        .flat_map(|interface| interface.addresses)
        .collect();
    collect_c2_hints(&cert_text, &interface_addresses, &config().server.api_bind_addr)
}

/// GET /api/server/c2-hints - candidate C2 addresses for the builder.
pub async fn c2_hints(
    Extension(operator): Extension<OperatorInfo>,
) -> Response {
    if !operator.can_execute() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Insufficient permissions"}))).into_response();
    }
    match tokio::task::spawn_blocking(current_c2_hints).await {
        Ok(ips) => Json(serde_json::json!({ "ips": ips })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

/// GET /api/listeners - list all listeners (DB + runtime status)
pub async fn list(
    State(state): State<Arc<ApiContext>>,
    Extension(_operator): Extension<OperatorInfo>,
) -> Response {
    let db_listeners = {
        let conn = match state.db.get() {
            Ok(c) => c,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "DB error"}))).into_response(),
        };
        database::list_listeners(&conn)
    };

    let active = state.listener_mgr.lock().await.list_active();
    let active_ids: std::collections::HashSet<i64> = active.iter().map(|a| a.id).collect();

    let result: Vec<serde_json::Value> = db_listeners.iter().map(|l| {
        serde_json::json!({
            "id": l.id,
            "name": l.name,
            "port": l.port,
            "transport": l.transport,
            "auto_start": l.auto_start,
            "running": active_ids.contains(&l.id),
            "created_at": l.created_at,
        })
    }).collect();

    (StatusCode::OK, Json(serde_json::json!(result))).into_response()
}

/// POST /api/listeners - create and start a new listener (admin only)
pub async fn create(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    Json(payload): Json<CreateListenerRequest>,
) -> Response {
    if !operator.is_admin() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Admin only"}))).into_response();
    }

    // Port 0 is invalid and the operator API port must stay free for the
    // panel/REST service. The guard reads the configured port instead of
    // assuming the 8080 default.
    let api_port = crate::config::config().server.api_port;
    if payload.port == 0 || payload.port == api_port {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("Port 0 and {} (API) are reserved", api_port)}))).into_response();
    }

    // Reject transports the server cannot bind. Anything unknown would
    // silently fall through to a TLS listener downstream. https is served
    // natively (the server terminates TLS for HTTP listeners itself).
    match payload.transport.as_str() {
        "tls" | "tcp_plain" | "http" | "https" => {}
        other => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("Unknown transport '{}': expected tls, tcp_plain, http, or https", other)}))).into_response();
        }
    }

    // Block privileged ports - binding these requires root and is usually
    // a configuration mistake. Operators who genuinely need port 443 can
    // use iptables REDIRECT or a reverse proxy.
    if payload.port < 1024 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Privileged ports (< 1024) are not allowed. Use a reverse proxy or iptables redirect."}))).into_response();
    }

    // Reject duplicate: another listener already running on this port
    {
        let mgr = state.listener_mgr.lock().await;
        let active = mgr.list_active();
        if active.iter().any(|l| l.port == payload.port && l.running) {
            return (StatusCode::CONFLICT, Json(serde_json::json!({"error": format!("Port {} is already in use by another listener", payload.port)}))).into_response();
        }
    }

    let result = {
        let mut mgr = state.listener_mgr.lock().await;
        mgr.create_and_start(
            &payload.name,
            payload.port,
            &payload.transport,
            payload.profile_json.as_deref(),
        ).await
    };

    match result {
        Ok(lc) => {
            if let Ok(conn) = state.db.get() {
                database::audit_log(&conn, operator.id, &operator.username, "create_listener",
                    None, Some(&format!("name={} port={}", lc.name, lc.port)));
            }
            (StatusCode::CREATED, Json(serde_json::json!(lc))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
    }
}

/// POST /api/listeners/:id/start - start a stopped listener
pub async fn start(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Response {
    if !operator.can_execute() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Insufficient permissions"}))).into_response();
    }

    let lc = {
        let conn = match state.db.get() {
            Ok(c) => c,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "DB error"}))).into_response(),
        };
        database::get_listener(&conn, id)
    };

    match lc {
        Some(l) => {
            let result = state.listener_mgr.lock().await.start_listener(&l).await;
            match result {
                Ok(msg) => (StatusCode::OK, Json(serde_json::json!({"status": msg}))).into_response(),
                Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
            }
        }
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Listener not found"}))).into_response(),
    }
}

/// POST /api/listeners/:id/stop - stop a running listener
pub async fn stop(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Response {
    if !operator.can_execute() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Insufficient permissions"}))).into_response();
    }

    let result = state.listener_mgr.lock().await.stop_listener(id);
    match result {
        Ok(msg) => {
            if let Ok(conn) = state.db.get() {
                database::audit_log(&conn, operator.id, &operator.username, "stop_listener", None, Some(&format!("id={}", id)));
            }
            (StatusCode::OK, Json(serde_json::json!({"status": msg}))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
    }
}

/// DELETE /api/listeners/:id - stop and delete a listener (admin only)
pub async fn delete(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Response {
    if !operator.is_admin() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Admin only"}))).into_response();
    }

    let result = state.listener_mgr.lock().await.remove(id);
    match result {
        Ok(msg) => {
            if let Ok(conn) = state.db.get() {
                database::audit_log(&conn, operator.id, &operator.username, "delete_listener", None, Some(&format!("id={}", id)));
            }
            (StatusCode::OK, Json(serde_json::json!({"status": msg}))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
    }
}
#[cfg(test)]
mod tests {
    use super::list_traffic_profiles;

    #[test]
    fn lists_json_profiles_sorted() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("b_profile.json"), "{\"b\":1}").unwrap();
        std::fs::write(dir.path().join("a_profile.json"), "{\"a\":1}").unwrap();
        // Non-JSON files and subdirectories are not profiles.
        std::fs::write(dir.path().join("notes.txt"), "hi").unwrap();
        std::fs::create_dir(dir.path().join("nested")).unwrap();

        let list = list_traffic_profiles(dir.path()).expect("listing works");
        let names: Vec<&str> = list.iter().filter_map(|p| p["name"].as_str()).collect();
        assert_eq!(names, vec!["a_profile.json", "b_profile.json"]);
        assert_eq!(list[0]["content"].as_str().unwrap(), "{\"a\":1}");
    }

    #[cfg(unix)]
    #[test]
    fn skips_symlinks() {
        let dir = tempfile::TempDir::new().unwrap();
        let outside = tempfile::TempDir::new().unwrap();
        std::fs::write(outside.path().join("secret.json"), "{}").unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret.json"),
            dir.path().join("linked.json"),
        ).unwrap();

        let list = list_traffic_profiles(dir.path()).expect("listing works");
        assert!(list.is_empty(), "symlinked profiles must be skipped");
    }

    #[test]
    fn missing_dir_is_an_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let missing = dir.path().join("no-such-dir");
        assert!(list_traffic_profiles(&missing).is_err());
    }
}
