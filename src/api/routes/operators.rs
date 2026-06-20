// src/api/routes/operators.rs
use axum::{
    extract::{State, ConnectInfo},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json, Extension,
};
use serde::Deserialize;
use std::sync::Arc;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use uuid::Uuid;
use sha2::Digest;
use subtle::ConstantTimeEq;

use crate::api::state::ApiContext;
use crate::api::middleware::OperatorInfo;
use crate::database;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct CreateOperatorRequest {
    pub username: String,
    pub password: String,
    pub role: String,
}

/// Hash a password with argon2id using a random salt.
/// Returns the PHC-formatted hash string (includes salt + params).
pub fn hash_password(password: &str) -> Result<String, String> {
    use argon2::{Argon2, password_hash::{SaltString, PasswordHasher, rand_core::OsRng}};
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2.hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("Hash error: {}", e))
}

/// Verify a password against an argon2 PHC hash string.
/// Falls back to SHA-256 comparison for legacy hashes (migration support).
fn verify_password(password: &str, stored_hash: &str) -> bool {
    // Try argon2 verification first (new format: starts with $argon2)
    if stored_hash.starts_with("$argon2") {
        use argon2::{Argon2, password_hash::{PasswordHash, PasswordVerifier}};
        if let Ok(parsed) = PasswordHash::new(stored_hash) {
            return Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok();
        }
        return false;
    }
    // Legacy SHA-256 fallback (constant-time comparison)
    let legacy_hash = format!("{:x}", sha2::Sha256::digest(password.as_bytes()));
    let a = legacy_hash.as_bytes();
    let b = stored_hash.as_bytes();
    if a.len() != b.len() { return false; }
    a.ct_eq(b).into()
}

/// POST /api/auth/login — authenticate with username/password, get API key
pub async fn login(
    State(state): State<Arc<ApiContext>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(payload): Json<LoginRequest>,
) -> Response {
    // Use the real TCP peer address for rate limiting, not spoofable
    // X-Forwarded-For headers. If the API sits behind a trusted reverse
    // proxy, swap this for the proxy-set header at the middleware level.
    let client_ip = peer.ip().to_string();
    let rate_key = format!("{}:{}", payload.username, client_ip);

    // Rate limiting: check recent failures for this username+IP
    {
        let mut limiter = state.login_limiter.lock()
            .unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();

        // Periodic cleanup: purge expired entries to prevent unbounded growth
        if limiter.len() > 100 {
            limiter.retain(|_, (_, last)| now.duration_since(*last).as_secs() < 120);
        }

        if let Some((count, last_attempt)) = limiter.get(&rate_key) {
            if *count >= 5 && now.duration_since(*last_attempt).as_secs() < 60 {
                return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!(
                    {"error": "Too many login attempts. Try again later."}
                ))).into_response();
            }
            // Reset counter after cooldown
            if now.duration_since(*last_attempt).as_secs() >= 60 {
                limiter.remove(&rate_key);
            }
        }
    }

    let conn = match state.db.get() {
        Ok(c) => c,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "DB error"}))).into_response(),
    };

    match database::get_operator_by_username(&conn, &payload.username) {
        Some(op) if verify_password(&payload.password, &op.password_hash) => {
            // Clear rate limit on success
            {
                let mut limiter = state.login_limiter.lock()
                    .unwrap_or_else(|e| e.into_inner());
                limiter.remove(&rate_key);
            }
            // Upgrade legacy hash to argon2 on successful login
            if !op.password_hash.starts_with("$argon2") {
                if let Ok(new_hash) = hash_password(&payload.password) {
                    if let Ok(conn) = state.db.get() {
                        database::update_operator_password(&conn, op.id, &new_hash);
                    }
                }
            }
            database::update_operator_login(&conn, op.id);
            database::audit_log(&conn, op.id, &op.username, "login", None, None);

            // Regenerate the API key so the browser receives a raw key.
            // The DB only stores HMAC(raw_key); returning the stored value
            // would give the browser a hash, and middleware would hash it
            // again on every request → permanent 401.
            let fresh_key = database::regenerate_api_key(&conn, op.id)
                .unwrap_or_default();

            (StatusCode::OK, Json(serde_json::json!({
                "api_key": fresh_key,
                "username": op.username,
                "role": op.role,
            }))).into_response()
        }
        _ => {
            // Record failed attempt for rate limiting
            {
                let mut limiter = state.login_limiter.lock()
                    .unwrap_or_else(|e| e.into_inner());
                let entry = limiter.entry(rate_key).or_insert((0, std::time::Instant::now()));
                entry.0 += 1;
                entry.1 = std::time::Instant::now();
            }
            (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Invalid credentials"}))).into_response()
        }
    }
}

/// GET /api/operators — list all operators (admin only)
pub async fn list(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
) -> Response {
    if !operator.is_admin() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Admin only"}))).into_response();
    }

    let conn = match state.db.get() {
        Ok(c) => c,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "DB error"}))).into_response(),
    };

    let ops = database::list_operators(&conn);
    // Strip password hashes from response
    let safe: Vec<serde_json::Value> = ops.iter().map(|o| serde_json::json!({
        "id": o.id,
        "username": o.username,
        "role": o.role,
        "created_at": o.created_at,
        "last_login": o.last_login,
    })).collect();

    (StatusCode::OK, Json(serde_json::json!(safe))).into_response()
}

/// POST /api/operators — create a new operator (admin only)
pub async fn create(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    Json(payload): Json<CreateOperatorRequest>,
) -> Response {
    if !operator.is_admin() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Admin only"}))).into_response();
    }

    if !["admin", "operator", "viewer"].contains(&payload.role.as_str()) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Role must be admin, operator, or viewer"}))).into_response();
    }

    let conn = match state.db.get() {
        Ok(c) => c,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "DB error"}))).into_response(),
    };

    let hash = match hash_password(&payload.password) {
        Ok(h) => h,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e}))).into_response(),
    };
    let api_key = Uuid::new_v4().to_string();

    match database::create_operator(&conn, &payload.username, &hash, &payload.role, &api_key) {
        Ok(id) => {
            database::audit_log(&conn, operator.id, &operator.username, "create_operator",
                None, Some(&format!("username={} role={}", payload.username, payload.role)));
            (StatusCode::CREATED, Json(serde_json::json!({
                "id": id,
                "username": payload.username,
                "role": payload.role,
                "api_key": api_key,
            }))).into_response()
        }
        Err(e) => (StatusCode::CONFLICT, Json(serde_json::json!({"error": format!("{}", e)}))).into_response(),
    }
}

/// DELETE /api/operators/:id — delete an operator (admin only)
pub async fn delete(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Response {
    if !operator.is_admin() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Admin only"}))).into_response();
    }

    if id == operator.id {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Cannot delete yourself"}))).into_response();
    }

    let conn = match state.db.get() {
        Ok(c) => c,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "DB error"}))).into_response(),
    };

    if database::delete_operator(&conn, id) {
        database::audit_log(&conn, operator.id, &operator.username, "delete_operator", None, Some(&format!("id={}", id)));
        (StatusCode::OK, Json(serde_json::json!({"status": "deleted"}))).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Operator not found"}))).into_response()
    }
}

/// GET /api/audit — get audit log (admin/operator)
pub async fn audit_log_handler(
    State(state): State<Arc<ApiContext>>,
    Extension(_operator): Extension<OperatorInfo>,
) -> Response {
    let conn = match state.db.get() {
        Ok(c) => c,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "DB error"}))).into_response(),
    };

    let log = database::get_audit_log(&conn, 200);
    (StatusCode::OK, Json(serde_json::json!(log))).into_response()
}

/// GET /api/auth/me — get current operator info
pub async fn whoami(
    Extension(operator): Extension<OperatorInfo>,
) -> Response {
    (StatusCode::OK, Json(serde_json::json!({
        "id": operator.id,
        "username": operator.username,
        "role": operator.role,
    }))).into_response()
}

// ── Webhook Configuration ──────────────────────────────────────────────

#[derive(Deserialize)]
pub struct WebhookRequest {
    pub url: String,
}

/// GET /api/config/webhook — get current webhook URL
pub async fn get_webhook(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
) -> Response {
    if !operator.is_admin() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Admin only"}))).into_response();
    }
    let url = state.db.get().ok()
        .and_then(|conn| database::get_webhook_url(&conn))
        .unwrap_or_default();
    (StatusCode::OK, Json(serde_json::json!({"webhook_url": url}))).into_response()
}

// ── Webhook URL Validation ─────────────────────────────────────────────

/// Validate a webhook URL for SSRF safety. Returns Ok(()) if the URL is
/// safe, or Err(message) with a human-readable rejection reason.
/// Extracted as a standalone function for testability (#10).
fn validate_webhook_url(raw_url: &str) -> Result<(), String> {
    if raw_url.is_empty() { return Ok(()); } // empty = clear webhook

    let url_lower = raw_url.to_lowercase();
    if !url_lower.starts_with("https://") && !url_lower.starts_with("http://") {
        return Err("URL must start with http:// or https://".into());
    }

    let parsed = url::Url::parse(raw_url)
        .map_err(|_| "Invalid URL".to_string())?;

    let host_str = parsed.host_str()
        .ok_or_else(|| "URL has no host".to_string())?
        .to_string();

    // Block well-known internal hostnames and literal loopback IPs
    let host_lower = host_str.to_lowercase();
    if host_lower == "localhost" || host_lower == "127.0.0.1" || host_lower == "[::1]"
        || host_lower.ends_with(".internal")
        || host_lower.ends_with(".local") || host_lower.contains("metadata.google")
        || host_lower.ends_with(".corp") || host_lower.ends_with(".lan") {
        return Err("Internal/private URLs are not allowed".into());
    }

    // Resolve and check every IP. Unlike the previous version, resolution
    // failure is now a hard block — an unresolvable host could resolve to
    // a private IP later (DNS rebinding / delayed provisioning).
    // In test mode (RCM_TEST_MODE=1), skip IP resolution so Docker-internal
    // service names (which resolve to private 172.x IPs) are allowed.
    if std::env::var("RCM_TEST_MODE").unwrap_or_default() != "1" {
    let port = parsed.port().unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });
    let resolve_target = format!("{}:{}", host_str, port);
    let addrs: Vec<std::net::SocketAddr> = resolve_target.to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed for '{}': {}", host_str, e))?
        .collect();

    if addrs.is_empty() {
        return Err(format!("DNS returned no addresses for '{}'", host_str));
    }

    for addr in &addrs {
        let ip = addr.ip();
        if ip.is_loopback() || ip.is_unspecified() || is_private_ip(&ip) {
            return Err(format!("URL resolves to a private/internal IP address ({})", ip));
        }
    }
    }

    Ok(())
}

/// POST /api/config/webhook — set webhook URL (Slack/Discord/custom)
pub async fn set_webhook(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    Json(payload): Json<WebhookRequest>,
) -> Response {
    if !operator.is_admin() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Admin only"}))).into_response();
    }

    if let Err(reason) = validate_webhook_url(&payload.url) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": reason}))).into_response();
    }

    if let Ok(conn) = state.db.get() {
        database::set_webhook_url(&conn, &payload.url);
        database::audit_log(&conn, operator.id, &operator.username, "set_webhook", None, Some(&payload.url));
    }
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"}))).into_response()
}

// ── Auto-Recon Configuration ───────────────────────────────────────────

#[derive(Deserialize)]
pub struct AddReconRequest {
    pub command: String,
}

/// GET /api/config/recon — list auto-recon commands
pub async fn list_recon(
    State(state): State<Arc<ApiContext>>,
    Extension(_operator): Extension<OperatorInfo>,
) -> Response {
    let conn = match state.db.get() {
        Ok(c) => c,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "DB error"}))).into_response(),
    };
    let entries = database::list_auto_recon(&conn);
    (StatusCode::OK, Json(serde_json::json!(entries))).into_response()
}

/// POST /api/config/recon — add an auto-recon command

fn normalise_recon_cmd(raw: &str) -> String {
    let raw = raw.trim();
    // Prefixes handled natively by the agent's command dispatcher
    const BUILTINS: &[&str] = &[
        "shell ", "!", "file:", "fs:", "jobs:", "bg ",
        "evasion:", "inmem:", "ext:", "proc:", "migrate:",
        "keylogger:", "proxy:", "pivot:", "rportfwd:",
        "sleep ", "beacon:", "sys:", "exit", "fallback:",
    ];
    if BUILTINS.iter().any(|p| raw.starts_with(p)) {
        raw.to_string()
    } else {
        format!("shell {}", raw)
    }
}

pub async fn add_recon(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    Json(payload): Json<AddReconRequest>,
) -> Response {
    if !operator.can_execute() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Insufficient permissions"}))).into_response();
    }
    let conn = match state.db.get() {
        Ok(c) => c,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "DB error"}))).into_response(),
    };
    let cmd = normalise_recon_cmd(&payload.command);
    match database::add_auto_recon(&conn, &cmd) {
        Ok(id) => {
            database::audit_log(&conn, operator.id, &operator.username, "add_recon", None, Some(&cmd));
            (StatusCode::CREATED, Json(serde_json::json!({"id": id, "command": cmd}))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("{}", e)}))).into_response(),
    }
}

/// DELETE /api/config/recon/:id — remove an auto-recon command
pub async fn remove_recon(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Response {
    if !operator.can_execute() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Insufficient permissions"}))).into_response();
    }
    let conn = match state.db.get() {
        Ok(c) => c,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "DB error"}))).into_response(),
    };
    if database::remove_auto_recon(&conn, id) {
        database::audit_log(&conn, operator.id, &operator.username, "remove_recon", None, Some(&format!("id={}", id)));
        (StatusCode::OK, Json(serde_json::json!({"status": "removed"}))).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Not found"}))).into_response()
    }
}

// ── SSRF Helpers ───────────────────────────────────────────────────────

/// Check if an IP address is in a private/reserved range.
/// Covers RFC1918, link-local, loopback, CGNAT, and IPv6 equivalents.
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 10.0.0.0/8
            octets[0] == 10
            // 172.16.0.0/12
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            // 192.168.0.0/16
            || (octets[0] == 192 && octets[1] == 168)
            // 169.254.0.0/16 (link-local / cloud metadata)
            || (octets[0] == 169 && octets[1] == 254)
            // 100.64.0.0/10 (CGNAT)
            || (octets[0] == 100 && (64..=127).contains(&octets[1]))
            // 127.0.0.0/8
            || octets[0] == 127
            // 0.0.0.0
            || octets == [0, 0, 0, 0]
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
            || v6.is_unspecified()
            // IPv4-mapped addresses: check the embedded v4
            || v6.to_ipv4_mapped().map(|v4| is_private_ip(&IpAddr::V4(v4))).unwrap_or(false)
            // fe80::/10 link-local
            || (v6.segments()[0] & 0xffc0) == 0xfe80
            // fc00::/7 unique local
            || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}
