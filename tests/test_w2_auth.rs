// tests/test_w2_auth.rs
//
// Wave-2 auth lifecycle tests :
// - login issues per-session keys; concurrent sessions survive
// - logout invalidates only the calling key
// - change_password requires the current password and is rate-limited
// - admin revoke/reset kill all of a target operator's keys
//
// Handlers are exercised directly against a temp SQLite database and a
// real ApiContext, mirroring the middleware's key-resolution order
// (session table first, legacy primary key as fallback).

use rcm::api::middleware::OperatorInfo;
use rcm::api::routes::operators;
use rcm::api::state::ApiContext;
use rcm::database;
use rcm::server::listeners::ListenerManager;

use axum::{
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    Extension, Json,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

// ── Scaffolding ─────────────────────────────────────────────────────────────

fn temp_db() -> database::DbPool {
    let path = format!("/tmp/rcm_w2auth_{}.db", uuid::Uuid::new_v4());
    let manager = r2d2_sqlite::SqliteConnectionManager::file(&path)
        .with_init(|c| c.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;"
        ));
    let pool = r2d2::Pool::builder().max_size(2).build(manager).unwrap();
    let conn = pool.get().unwrap();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS operators (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'operator',
            api_key TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL, last_login TEXT
         );
         CREATE TABLE IF NOT EXISTS operator_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, operator_id INTEGER NOT NULL,
            key_hash TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL,
            FOREIGN KEY(operator_id) REFERENCES operators(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, operator_id INTEGER,
            operator_name TEXT, action TEXT NOT NULL, target_session INTEGER,
            details TEXT, timestamp TEXT NOT NULL
         );"
    ).unwrap();
    drop(conn);
    pool
}

fn test_ctx() -> Arc<ApiContext> {
    let pool = temp_db();
    let sessions: rcm::common::SharedSessions = Arc::new(dashmap::DashMap::new());
    let results = Arc::new(Mutex::new(HashMap::new()));
    let mgr = ListenerManager::new(
        pool.clone(), sessions.clone(), results.clone(), vec![], vec![], vec![],
    );
    Arc::new(ApiContext {
        sessions,
        db: pool,
        results,
        proxies: Arc::new(Mutex::new(HashMap::new())),
        rportfwds: Arc::new(Mutex::new(HashMap::new())),
        listener_mgr: Arc::new(tokio::sync::Mutex::new(mgr)),
        login_limiter: Arc::new(Mutex::new(HashMap::new())),
        build_jobs: Arc::new(Mutex::new(HashMap::new())),
        payload_links: Arc::new(Mutex::new(HashMap::new())),
        dl_limiter: Arc::new(Mutex::new(HashMap::new())),
    })
}

fn op_info(id: i64, username: &str, role: &str) -> OperatorInfo {
    OperatorInfo { id, username: username.to_string(), role: role.to_string() }
}

fn peer(a: u8) -> ConnectInfo<SocketAddr> {
    ConnectInfo(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, a)), 9000))
}

fn key_header(raw: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("X-API-KEY", HeaderValue::from_str(raw).unwrap());
    h
}

/// Seed the bootstrap admin directly (mirrors first-run provisioning).
/// Returns the admin identity and the raw legacy primary key.
fn seed_admin(ctx: &Arc<ApiContext>, password: &str) -> (OperatorInfo, String) {
    let conn = ctx.db.get().unwrap();
    let hash = operators::hash_password(password).unwrap();
    let legacy_key = format!("legacy-{}", uuid::Uuid::new_v4());
    let id = database::create_operator(&conn, "root", &hash, "admin", &legacy_key).unwrap();
    (op_info(id, "root", "admin"), legacy_key)
}

/// Create an operator through the real handler; returns the raw legacy key.
async fn create_operator(
    ctx: &Arc<ApiContext>, admin: &OperatorInfo, username: &str, password: &str, role: &str,
) -> String {
    let resp = operators::create(
        State(ctx.clone()),
        Extension(admin.clone()),
        Json(operators::CreateOperatorRequest {
            username: username.to_string(),
            password: password.to_string(),
            role: role.to_string(),
        }),
    ).await;
    assert_eq!(resp.status(), StatusCode::CREATED, "create operator {}", username);
    let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    v["api_key"].as_str().expect("api_key in create response").to_string()
}

/// Log in through the real handler; returns (status, raw session key).
async fn login(ctx: &Arc<ApiContext>, username: &str, password: &str, ip: u8) -> (StatusCode, String) {
    let resp = operators::login(
        State(ctx.clone()),
        peer(ip),
        Json(operators::LoginRequest {
            username: username.to_string(),
            password: password.to_string(),
        }),
    ).await;
    let status = resp.status();
    let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    (status, v["api_key"].as_str().unwrap_or("").to_string())
}

/// Mirror of the middleware's two-tier key resolution.
fn key_works(ctx: &Arc<ApiContext>, raw_key: &str) -> bool {
    let conn = ctx.db.get().unwrap();
    database::get_operator_by_session_key(&conn, raw_key)
        .or_else(|| database::get_operator_by_key(&conn, raw_key))
        .is_some()
}

// ── : session keys ───────────────────────────────────────────────────────

#[tokio::test]
async fn concurrent_sessions_survive_login() {
    let ctx = test_ctx();
    let (_admin, legacy) = seed_admin(&ctx, "admin-pw-123");

    let (s1, k1) = login(&ctx, "root", "admin-pw-123", 1).await;
    let (s2, k2) = login(&ctx, "root", "admin-pw-123", 2).await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(s2, StatusCode::OK);
    assert_ne!(k1, k2, "each login mints its own key");

 // The second login must not kick the first session out.
    assert!(key_works(&ctx, &k1));
    assert!(key_works(&ctx, &k2));
 // The legacy primary key is untouched by logins.
    assert!(key_works(&ctx, &legacy));
}

#[tokio::test]
async fn logout_invalidates_only_the_caller() {
    let ctx = test_ctx();
    let (admin, legacy) = seed_admin(&ctx, "admin-pw-123");

    let (_, k1) = login(&ctx, "root", "admin-pw-123", 1).await;
    let (_, k2) = login(&ctx, "root", "admin-pw-123", 2).await;
    let _bob_legacy = create_operator(&ctx, &admin, "bob", "bob-pass-123", "operator").await;
    let (_, kb) = login(&ctx, "bob", "bob-pass-123", 3).await;

 // Logging out k1 kills only k1.
    let resp = operators::logout(
        State(ctx.clone()), Extension(admin.clone()), key_header(&k1),
    ).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!key_works(&ctx, &k1), "logged-out session key must be dead");
    assert!(key_works(&ctx, &k2), "same operator's other session survives");
    assert!(key_works(&ctx, &kb), "other operators are unaffected");
    assert!(key_works(&ctx, &legacy), "legacy primary key survives");

 // Logging out with the legacy primary key rotates only that key.
    let resp = operators::logout(
        State(ctx.clone()), Extension(admin.clone()), key_header(&legacy),
    ).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!key_works(&ctx, &legacy), "legacy key rotated on logout");
    assert!(key_works(&ctx, &k2), "session keys survive legacy logout");
}

#[tokio::test]
async fn admin_revoke_kills_all_target_keys() {
    let ctx = test_ctx();
    let (admin, _) = seed_admin(&ctx, "admin-pw-123");
    let bob_legacy = create_operator(&ctx, &admin, "bob", "bob-pass-123", "operator").await;
    let (_, kb) = login(&ctx, "bob", "bob-pass-123", 3).await;
    assert!(key_works(&ctx, &kb));

 // Non-admins cannot revoke.
    let resp = operators::revoke_keys(
        State(ctx.clone()), Extension(op_info(99, "mallory", "operator")), Path("bob".to_string()),
    ).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

 // Self-revoke is refused (logout is the self-service path).
    let resp = operators::revoke_keys(
        State(ctx.clone()), Extension(admin.clone()), Path("root".to_string()),
    ).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

 // Unknown operator 404s.
    let resp = operators::revoke_keys(
        State(ctx.clone()), Extension(admin.clone()), Path("nobody".to_string()),
    ).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

 // Admin revoke kills the session keys AND the legacy primary key.
    let resp = operators::revoke_keys(
        State(ctx.clone()), Extension(admin.clone()), Path("bob".to_string()),
    ).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!key_works(&ctx, &kb), "session key revoked");
    assert!(!key_works(&ctx, &bob_legacy), "legacy key revoked");

 // The account itself is untouched: bob can still log in.
    let (s, _) = login(&ctx, "bob", "bob-pass-123", 3).await;
    assert_eq!(s, StatusCode::OK);
}

// ── : password change / reset ────────────────────────────────────────────

#[tokio::test]
async fn change_password_rejects_wrong_current() {
    let ctx = test_ctx();
    let (admin, _) = seed_admin(&ctx, "admin-pw-123");
    let (_, k1) = login(&ctx, "root", "admin-pw-123", 1).await;

    let resp = operators::change_password(
        State(ctx.clone()),
        Extension(admin.clone()),
        peer(1),
        key_header(&k1),
        Json(operators::ChangePasswordRequest {
            current_password: "wrong-pass-000".to_string(),
            new_password: "new-password-1".to_string(),
        }),
    ).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
 // A failed attempt must not disturb the session.
    assert!(key_works(&ctx, &k1));

 // Too-short new password is rejected before touching anything.
    let resp = operators::change_password(
        State(ctx.clone()),
        Extension(admin.clone()),
        peer(2),
        key_header(&k1),
        Json(operators::ChangePasswordRequest {
            current_password: "admin-pw-123".to_string(),
            new_password: "short".to_string(),
        }),
    ).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

 // Correct current password works.
    let resp = operators::change_password(
        State(ctx.clone()),
        Extension(admin.clone()),
        peer(3),
        key_header(&k1),
        Json(operators::ChangePasswordRequest {
            current_password: "admin-pw-123".to_string(),
            new_password: "new-password-1".to_string(),
        }),
    ).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let (s_old, _) = login(&ctx, "root", "admin-pw-123", 4).await;
    assert_eq!(s_old, StatusCode::UNAUTHORIZED, "old password must be dead");
    let (s_new, _) = login(&ctx, "root", "new-password-1", 4).await;
    assert_eq!(s_new, StatusCode::OK, "new password must work");
}

#[tokio::test]
async fn change_password_revokes_other_sessions_keeps_caller() {
    let ctx = test_ctx();
    let (admin, _) = seed_admin(&ctx, "admin-pw-123");
    let (_, k1) = login(&ctx, "root", "admin-pw-123", 1).await;
    let (_, k2) = login(&ctx, "root", "admin-pw-123", 2).await;

    let resp = operators::change_password(
        State(ctx.clone()),
        Extension(admin.clone()),
        peer(1),
        key_header(&k1),
        Json(operators::ChangePasswordRequest {
            current_password: "admin-pw-123".to_string(),
            new_password: "new-password-1".to_string(),
        }),
    ).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(key_works(&ctx, &k1), "the calling session stays valid");
    assert!(!key_works(&ctx, &k2), "the operator's other sessions are revoked");
}

#[tokio::test]
async fn change_password_is_rate_limited() {
    let ctx = test_ctx();
    let (admin, _) = seed_admin(&ctx, "admin-pw-123");
    let (_, k1) = login(&ctx, "root", "admin-pw-123", 7).await;

 // Five wrong-current attempts pass the limiter (and fail the check)...
    for i in 0..5 {
        let resp = operators::change_password(
            State(ctx.clone()),
            Extension(admin.clone()),
            peer(7),
            key_header(&k1),
            Json(operators::ChangePasswordRequest {
                current_password: format!("wrong-pass-{}", i),
                new_password: "new-password-1".to_string(),
            }),
        ).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "attempt {}", i);
    }
 // ...and the sixth is throttled.
    let resp = operators::change_password(
        State(ctx.clone()),
        Extension(admin.clone()),
        peer(7),
        key_header(&k1),
        Json(operators::ChangePasswordRequest {
            current_password: "wrong-pass-6".to_string(),
            new_password: "new-password-1".to_string(),
        }),
    ).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn admin_reset_password_locks_out_target() {
    let ctx = test_ctx();
    let (admin, _) = seed_admin(&ctx, "admin-pw-123");
    let bob_legacy = create_operator(&ctx, &admin, "bob", "bob-pass-123", "operator").await;
    let (_, kb) = login(&ctx, "bob", "bob-pass-123", 3).await;

 // Non-admin reset is refused.
    let resp = operators::admin_reset_password(
        State(ctx.clone()),
        Extension(op_info(99, "mallory", "operator")),
        peer(8),
        Path("bob".to_string()),
        Json(operators::AdminPasswordRequest { password: "reset-pw-123".to_string() }),
    ).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

 // Short password is refused.
    let resp = operators::admin_reset_password(
        State(ctx.clone()),
        Extension(admin.clone()),
        peer(8),
        Path("bob".to_string()),
        Json(operators::AdminPasswordRequest { password: "short".to_string() }),
    ).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

 // Admin reset kills every active key of the target.
    let resp = operators::admin_reset_password(
        State(ctx.clone()),
        Extension(admin.clone()),
        peer(8),
        Path("bob".to_string()),
        Json(operators::AdminPasswordRequest { password: "reset-pw-123".to_string() }),
    ).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!key_works(&ctx, &kb), "target sessions are killed");
    assert!(!key_works(&ctx, &bob_legacy), "target legacy key is killed");

    let (s_old, _) = login(&ctx, "bob", "bob-pass-123", 3).await;
    assert_eq!(s_old, StatusCode::UNAUTHORIZED);
    let (s_new, _) = login(&ctx, "bob", "reset-pw-123", 3).await;
    assert_eq!(s_new, StatusCode::OK);
}

// ── Middleware-level: empty / missing / valid keys ───────────────────────────

/// Router with /api/auth/me behind the real auth middleware, mirroring the
/// production wiring in api::mod.
fn me_app(ctx: &Arc<ApiContext>) -> axum::Router {
    axum::Router::new()
        .route("/api/auth/me", axum::routing::get(operators::whoami))
        .route_layer(axum::middleware::from_fn_with_state(
            ctx.clone(),
            rcm::api::middleware::auth,
        ))
}

#[tokio::test]
async fn middleware_rejects_empty_and_missing_keys() {
    use tower::ServiceExt;
    let ctx = test_ctx();
    let _ = seed_admin(&ctx, "admin-pw-123");
    let app = me_app(&ctx);

 // Missing X-API-KEY header -> 401 before any table lookup.
    let resp = app.clone().oneshot(
        axum::http::Request::builder()
            .uri("/api/auth/me")
            .body(axum::body::Body::empty())
            .unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

 // Empty X-API-KEY value -> 401; must never resolve to an operator row.
    let resp = app.clone().oneshot(
        axum::http::Request::builder()
            .uri("/api/auth/me")
            .header("X-API-KEY", "")
            .body(axum::body::Body::empty())
            .unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

 // Whitespace is not a key either: it fails both table lookups.
    let resp = app.clone().oneshot(
        axum::http::Request::builder()
            .uri("/api/auth/me")
            .header("X-API-KEY", " ")
            .body(axum::body::Body::empty())
            .unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn middleware_accepts_session_and_legacy_keys() {
    use tower::ServiceExt;
    let ctx = test_ctx();
    let (_admin, legacy) = seed_admin(&ctx, "admin-pw-123");
    let (_, session_key) = login(&ctx, "root", "admin-pw-123", 5).await;
    let app = me_app(&ctx);

 // Both key tiers must pass the middleware and resolve to admin.
    for raw in [session_key, legacy] {
        let resp = app.clone().oneshot(
            axum::http::Request::builder()
                .uri("/api/auth/me")
                .header("X-API-KEY", raw)
                .body(axum::body::Body::empty())
                .unwrap(),
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["username"].as_str().unwrap(), "root");
        assert_eq!(v["role"].as_str().unwrap(), "admin");
    }
}
