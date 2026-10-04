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

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Deserialize)]
pub struct AdminPasswordRequest {
    pub password: String,
}

/// Minimum password length, matching the rule the panel enforces when an
/// operator is created.
const MIN_PASSWORD_LEN: usize = 8;

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

/// Max failed attempts per (username, IP) inside the lockout window.
const MAX_ATTEMPTS_PER_USER_IP: u32 = 5;
/// Max failed attempts per IP across all usernames inside the window.
/// Stops password spraying that rotates usernames from one address.
const MAX_ATTEMPTS_PER_IP: u32 = 20;
/// Lockout window in seconds for both limiter buckets.
const LOCKOUT_WINDOW_SECS: u64 = 60;

/// Returns true when the bucket for `key` is over `max` inside the window.
/// Otherwise records one attempt and returns false. Expired buckets are
/// reset on contact. Caller must hold the limiter lock, which makes the
/// check-and-record atomic across concurrent requests.
fn limiter_check_and_record(
    limiter: &mut std::collections::HashMap<String, (u32, std::time::Instant)>,
    key: &str,
    max: u32,
    now: std::time::Instant,
) -> bool {
    if let Some((count, last)) = limiter.get(key) {
        if now.duration_since(*last).as_secs() >= LOCKOUT_WINDOW_SECS {
            limiter.remove(key);
        } else if *count >= max {
            return true;
        }
    }
    let entry = limiter.entry(key.to_string()).or_insert((0, now));
    entry.0 += 1;
    entry.1 = now;
    false
}

/// POST /api/auth/login - authenticate with username/password, get API key
pub async fn login(
    State(state): State<Arc<ApiContext>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(payload): Json<LoginRequest>,
) -> Response {
    // Use the real TCP peer address for rate limiting, not spoofable
    // X-Forwarded-For headers. If the API sits behind a trusted reverse
    // proxy, swap this for the proxy-set header at the middleware level.
    let client_ip = peer.ip().to_string();
    // Two buckets in the same map, distinguished by prefix: the per
    // (username, IP) bucket throttles targeted brute force, the per-IP
    // bucket throttles sprays that rotate usernames from one address.
    let rate_key = format!("u:{}:{}", payload.username, client_ip);
    let ip_key = format!("i:{}", client_ip);

    // Check both buckets and record this attempt in one lock scope so the
    // check cannot race the increment across concurrent requests.
    {
        let mut limiter = state.login_limiter.lock()
            .unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();

        // Periodic cleanup: purge expired entries to prevent unbounded growth
        if limiter.len() > 100 {
            limiter.retain(|_, (_, last)| now.duration_since(*last).as_secs() < 120);
        }

        if limiter_check_and_record(&mut limiter, &ip_key, MAX_ATTEMPTS_PER_IP, now)
            || limiter_check_and_record(&mut limiter, &rate_key, MAX_ATTEMPTS_PER_USER_IP, now)
        {
            return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!(
                {"error": "Too many login attempts. Try again later."}
            ))).into_response();
        }
    }

    let conn = match state.db.get() {
        Ok(c) => c,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "DB error"}))).into_response(),
    };

    match database::get_operator_by_username(&conn, &payload.username) {
        Some(op) if verify_password(&payload.password, &op.password_hash) => {
            // Successful login clears both limiter buckets.
            {
                let mut limiter = state.login_limiter.lock()
                    .unwrap_or_else(|e| e.into_inner());
                limiter.remove(&rate_key);
                limiter.remove(&ip_key);
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

            // Per-session key: every login mints a new row in
            // operator_sessions, so a concurrent panel session or an
            // automation of the same operator keeps working. The legacy
            // primary key on the operator row is left untouched.
            let fresh_key = database::create_operator_session(&conn, op.id)
                .unwrap_or_default();

            (StatusCode::OK, Json(serde_json::json!({
                "api_key": fresh_key,
                "username": op.username,
                "role": op.role,
            }))).into_response()
        }
        _ => {
            // The attempt was already recorded up-front, before the
            // password check, so there is nothing to do here.
            (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Invalid credentials"}))).into_response()
        }
    }
}

/// POST /api/auth/logout - invalidate the calling session's key only.
/// Other sessions of the same operator (and every other operator) keep
/// working.
pub async fn logout(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    headers: axum::http::HeaderMap,
) -> Response {
    let raw_key = headers
        .get("X-API-KEY")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let conn = match state.db.get() {
        Ok(c) => c,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "DB error"}))).into_response(),
    };

    let key_hash = database::hash_api_key(raw_key);
    if database::delete_operator_session_by_hash(&conn, &key_hash) {
        database::audit_log(&conn, operator.id, &operator.username, "logout", None, None);
        return (StatusCode::OK, Json(serde_json::json!({"status": "logged out"}))).into_response();
    }

    // Legacy primary key (issued at operator creation, before per-session
    // keys): rotating it invalidates exactly this key material and nothing
    // else.
    if database::get_operator_by_key(&conn, raw_key).map(|o| o.id) == Some(operator.id) {
        let _ = database::regenerate_api_key(&conn, operator.id);
        database::audit_log(&conn, operator.id, &operator.username, "logout", None, Some("legacy primary key rotated"));
    }

    (StatusCode::OK, Json(serde_json::json!({"status": "logged out"}))).into_response()
}

/// POST /api/auth/change_password - self-service password change. Requires
/// the current password and revokes the operator's OTHER sessions; the
/// calling session stays valid. Rate-limited like login.
pub async fn change_password(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<ChangePasswordRequest>,
) -> Response {
    let client_ip = peer.ip().to_string();
    // Brute-forcing the current password is throttled with the same buckets
    // login uses: per (username, IP) and per IP.
    let rate_key = format!("u:{}:{}", operator.username, client_ip);
    let ip_key = format!("i:{}", client_ip);
    {
        let mut limiter = state.login_limiter.lock()
            .unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        if limiter.len() > 100 {
            limiter.retain(|_, (_, last)| now.duration_since(*last).as_secs() < 120);
        }
        if limiter_check_and_record(&mut limiter, &ip_key, MAX_ATTEMPTS_PER_IP, now)
            || limiter_check_and_record(&mut limiter, &rate_key, MAX_ATTEMPTS_PER_USER_IP, now)
        {
            return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!(
                {"error": "Too many attempts. Try again later."}
            ))).into_response();
        }
    }

    if payload.new_password.len() < MIN_PASSWORD_LEN {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Password must be at least 8 characters"}))).into_response();
    }

    let conn = match state.db.get() {
        Ok(c) => c,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "DB error"}))).into_response(),
    };

    let Some(op) = database::get_operator_by_username(&conn, &operator.username) else {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Operator not found"}))).into_response();
    };

    if !verify_password(&payload.current_password, &op.password_hash) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Current password is incorrect"}))).into_response();
    }

    let hash = match hash_password(&payload.new_password) {
        Ok(h) => h,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e}))).into_response(),
    };
    database::update_operator_password(&conn, op.id, &hash);

    // Revoke the operator's other sessions; the caller's own key survives.
    let raw_key = headers
        .get("X-API-KEY")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let revoked = database::delete_other_operator_sessions(&conn, op.id, &database::hash_api_key(raw_key));

    {
        let mut limiter = state.login_limiter.lock()
            .unwrap_or_else(|e| e.into_inner());
        limiter.remove(&rate_key);
        limiter.remove(&ip_key);
    }

    database::audit_log(&conn, operator.id, &operator.username, "change_password",
        None, Some(&format!("sessions_revoked={}", revoked)));

    (StatusCode::OK, Json(serde_json::json!({
        "status": "password updated",
        "sessions_revoked": revoked,
    }))).into_response()
}

/// POST /api/operators/:name/password - admin resets an operator's password.
/// Kills every active key of the target (all sessions plus the legacy
/// primary key). Rate-limited like login.
pub async fn admin_reset_password(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    axum::extract::Path(name): axum::extract::Path<String>,
    Json(payload): Json<AdminPasswordRequest>,
) -> Response {
    if !operator.is_admin() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Admin only"}))).into_response();
    }

    let client_ip = peer.ip().to_string();
    let rate_key = format!("u:{}:{}", name, client_ip);
    let ip_key = format!("i:{}", client_ip);
    {
        let mut limiter = state.login_limiter.lock()
            .unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        if limiter.len() > 100 {
            limiter.retain(|_, (_, last)| now.duration_since(*last).as_secs() < 120);
        }
        if limiter_check_and_record(&mut limiter, &ip_key, MAX_ATTEMPTS_PER_IP, now)
            || limiter_check_and_record(&mut limiter, &rate_key, MAX_ATTEMPTS_PER_USER_IP, now)
        {
            return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!(
                {"error": "Too many attempts. Try again later."}
            ))).into_response();
        }
    }

    if payload.password.len() < MIN_PASSWORD_LEN {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Password must be at least 8 characters"}))).into_response();
    }

    let conn = match state.db.get() {
        Ok(c) => c,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "DB error"}))).into_response(),
    };

    let Some(target) = database::get_operator_by_username(&conn, &name) else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Operator not found"}))).into_response();
    };

    let hash = match hash_password(&payload.password) {
        Ok(h) => h,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e}))).into_response(),
    };
    database::update_operator_password(&conn, target.id, &hash);

    // Full lockout: every session key plus the legacy primary key.
    let killed = database::delete_operator_sessions(&conn, target.id);
    let _ = database::regenerate_api_key(&conn, target.id);

    {
        let mut limiter = state.login_limiter.lock()
            .unwrap_or_else(|e| e.into_inner());
        limiter.remove(&rate_key);
        limiter.remove(&ip_key);
    }

    database::audit_log(&conn, operator.id, &operator.username, "reset_password",
        None, Some(&format!("target={} keys_killed={}", name, killed + 1)));

    (StatusCode::OK, Json(serde_json::json!({
        "status": "password reset",
        "keys_killed": killed + 1,
    }))).into_response()
}

/// POST /api/operators/:name/revoke - admin kills all active keys of an
/// operator (sessions plus the legacy primary key) without touching the
/// password. Incident response for a leaked key.
pub async fn revoke_keys(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Response {
    if !operator.is_admin() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Admin only"}))).into_response();
    }

    let conn = match state.db.get() {
        Ok(c) => c,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "DB error"}))).into_response(),
    };

    let Some(target) = database::get_operator_by_username(&conn, &name) else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Operator not found"}))).into_response();
    };

    if target.id == operator.id {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Cannot revoke your own keys; use logout"}))).into_response();
    }

    let killed = database::delete_operator_sessions(&conn, target.id);
    let _ = database::regenerate_api_key(&conn, target.id);

    database::audit_log(&conn, operator.id, &operator.username, "revoke_keys",
        None, Some(&format!("target={} keys_killed={}", name, killed + 1)));

    (StatusCode::OK, Json(serde_json::json!({
        "status": "revoked",
        "keys_killed": killed + 1,
    }))).into_response()
}

/// GET /api/operators - list all operators (admin only)
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

/// POST /api/operators - create a new operator (admin only)
pub async fn create(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    Json(payload): Json<CreateOperatorRequest>,
) -> Response {
    if !operator.is_admin() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Admin only"}))).into_response();
    }

    if payload.password.len() < MIN_PASSWORD_LEN {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Password must be at least 8 characters"}))).into_response();
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

/// DELETE /api/operators/:name - delete an operator (admin only).
/// The path wildcard accepts a numeric id for backward compatibility or a
/// username; it shares the :name segment with the revoke/password routes.
pub async fn delete(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Response {
    if !operator.is_admin() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Admin only"}))).into_response();
    }

    let conn = match state.db.get() {
        Ok(c) => c,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "DB error"}))).into_response(),
    };

    let target = match name.parse::<i64>() {
        Ok(id) => database::list_operators(&conn).into_iter().find(|o| o.id == id),
        Err(_) => database::get_operator_by_username(&conn, &name),
    };
    let Some(target) = target else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Operator not found"}))).into_response();
    };

    if target.id == operator.id {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Cannot delete yourself"}))).into_response();
    }

    if database::delete_operator(&conn, target.id) {
        database::audit_log(&conn, operator.id, &operator.username, "delete_operator",
            None, Some(&format!("id={} name={}", target.id, target.username)));
        (StatusCode::OK, Json(serde_json::json!({"status": "deleted"}))).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Operator not found"}))).into_response()
    }
}

/// GET /api/audit - get audit log (admin/operator)
pub async fn audit_log_handler(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
) -> Response {
    // The audit trail exposes operator actions and usernames; viewers are
    // excluded even though the route sits behind the auth middleware.
    if !operator.can_execute() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Insufficient permissions"}))).into_response();
    }

    let conn = match state.db.get() {
        Ok(c) => c,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "DB error"}))).into_response(),
    };

    let log = database::get_audit_log(&conn, 200);
    (StatusCode::OK, Json(serde_json::json!(log))).into_response()
}

/// GET /api/auth/me - get current operator info
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

/// GET /api/config/webhook - get current webhook URL
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
    // failure is now a hard block - an unresolvable host could resolve to
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

/// POST /api/config/webhook - set webhook URL (Slack/Discord/custom)
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

/// GET /api/config/recon - list auto-recon commands
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

/// POST /api/config/recon - add an auto-recon command

fn normalise_recon_cmd(raw: &str) -> String {
    let raw = raw.trim();
    // Prefixes handled natively by the agent's command dispatcher
    const BUILTINS: &[&str] = &[
        "shell ", "!", "file:", "fs:", "jobs:", "bg ",
        "evasion:", "inmem:", "ext:", "proc:", "migrate:",
        "keylogger:", "proxy:", "pivot:", "rportfwd:",
        "sleep ", "beacon:", "sys:", "exit", "fallback:",
        "module:",  // server-side Rhai module invocation
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

/// DELETE /api/config/recon/:id - remove an auto-recon command
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
#[cfg(test)]
mod tests {
    use super::{
        limiter_check_and_record, LOCKOUT_WINDOW_SECS, MAX_ATTEMPTS_PER_IP,
        MAX_ATTEMPTS_PER_USER_IP,
    };
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    #[test]
    fn per_user_bucket_locks_out_at_threshold() {
        let mut m = HashMap::new();
        let now = Instant::now();
        for i in 0..MAX_ATTEMPTS_PER_USER_IP {
            assert!(
                !limiter_check_and_record(&mut m, "u:bob:10.0.0.1", MAX_ATTEMPTS_PER_USER_IP, now),
                "attempt {} should be allowed", i
            );
        }
        assert!(limiter_check_and_record(&mut m, "u:bob:10.0.0.1", MAX_ATTEMPTS_PER_USER_IP, now));
        // A different username from the same IP has its own bucket.
        assert!(!limiter_check_and_record(&mut m, "u:alice:10.0.0.1", MAX_ATTEMPTS_PER_USER_IP, now));
    }

    #[test]
    fn per_ip_bucket_stops_username_spray() {
        let mut m = HashMap::new();
        let now = Instant::now();
        for i in 0..MAX_ATTEMPTS_PER_IP {
            assert!(
                !limiter_check_and_record(&mut m, "i:10.0.0.9", MAX_ATTEMPTS_PER_IP, now),
                "attempt {} should be allowed", i
            );
        }
        assert!(limiter_check_and_record(&mut m, "i:10.0.0.9", MAX_ATTEMPTS_PER_IP, now));
    }

    #[test]
    fn expired_window_resets_bucket() {
        let mut m = HashMap::new();
        let t0 = Instant::now();
        for _ in 0..MAX_ATTEMPTS_PER_USER_IP {
            limiter_check_and_record(&mut m, "u:bob:10.0.0.1", MAX_ATTEMPTS_PER_USER_IP, t0);
        }
        let later = t0 + Duration::from_secs(LOCKOUT_WINDOW_SECS + 1);
        assert!(!limiter_check_and_record(&mut m, "u:bob:10.0.0.1", MAX_ATTEMPTS_PER_USER_IP, later));
    }
}
