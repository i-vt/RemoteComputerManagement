// src/api/middleware.rs
use axum::{
    extract::State,
    http::{StatusCode, HeaderMap, Method, Request},
    response::IntoResponse,
    middleware,
};
use std::sync::Arc;
use crate::api::state::ApiContext;
use crate::database;

/// Operator identity injected into request extensions after auth.
#[derive(Clone, Debug)]
pub struct OperatorInfo {
    pub id: i64,
    pub username: String,
    pub role: String,
}

impl OperatorInfo {
    pub fn is_admin(&self) -> bool { self.role == "admin" }
    pub fn is_viewer(&self) -> bool { self.role == "viewer" }
    pub fn can_execute(&self) -> bool { self.role == "admin" || self.role == "operator" }
}

/// Numeric rank of a role string; unknown roles rank below viewer.
/// Hierarchy: viewer (0) < operator (1) < admin (2).
pub fn role_rank(role: &str) -> u8 {
    match role {
        "admin" => 2,
        "operator" => 1,
        "viewer" => 0,
        _ => 0,
    }
}

/// Returns true when `role` meets or exceeds the minimum role `min`
/// ("viewer" | "operator" | "admin"). Kept as a pure function so the RBAC
/// matrix can be tested without standing up the HTTP stack.
pub fn role_at_least(role: &str, min: &str) -> bool {
    role_rank(role) >= role_rank(min)
}

/// Authentication middleware. Resolves the operator from the X-API-KEY header
/// and injects OperatorInfo into request extensions. Returns 401 if the key
/// is missing or invalid.
///
/// Two key tiers are accepted: per-session keys minted at login (the
/// operator_sessions table) and the legacy primary key stored on the
/// operator row (issued at creation, before session keys existed). Session
/// keys are checked first so a revoked session fails immediately.
pub async fn auth(
    State(state): State<Arc<ApiContext>>,
    headers: HeaderMap,
    mut request: Request<axum::body::Body>,
    next: middleware::Next<axum::body::Body>,
) -> Result<impl IntoResponse, StatusCode> {
    if request.method() == Method::OPTIONS {
        return Ok(next.run(request).await);
    }

    // Allow unauthenticated access to /api/auth/login
    if request.uri().path() == "/api/auth/login" {
        return Ok(next.run(request).await);
    }

    let header_key = headers
        .get("X-API-KEY")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // The X-API-KEY header is the only accepted credential carrier. The
    // former ?key=<api_key> query fallback for download URLs leaked keys
    // into browser history, screenshots, and logs; clients must send the
    // header on every request.
    let api_key: &str = header_key;

    if api_key.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let operator = {
        let conn = state.db.get().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        database::get_operator_by_session_key(&conn, api_key)
            .or_else(|| database::get_operator_by_key(&conn, api_key))
    };

    match operator {
        Some(op) => {
            let info = OperatorInfo {
                id: op.id,
                username: op.username,
                role: op.role,
            };
            request.extensions_mut().insert(info);
            Ok(next.run(request).await)
        }
        None => Err(StatusCode::UNAUTHORIZED),
    }
}

/// Helper: extract operator info from request extensions in route handlers.
pub fn get_operator(extensions: &axum::http::Extensions) -> Option<OperatorInfo> {
    extensions.get::<OperatorInfo>().cloned()
}
#[cfg(test)]
mod tests {
    use super::{role_at_least, role_rank};

    #[test]
    fn role_rank_orders_hierarchy() {
        assert!(role_rank("admin") > role_rank("operator"));
        assert!(role_rank("operator") > role_rank("viewer"));
    }

    #[test]
    fn unknown_roles_rank_as_viewer() {
        assert_eq!(role_rank("superuser"), 0);
        assert_eq!(role_rank(""), role_rank("viewer"));
    }

    #[test]
    fn role_at_least_matrix() {
        assert!(role_at_least("admin", "admin"));
        assert!(role_at_least("admin", "operator"));
        assert!(role_at_least("operator", "operator"));
        assert!(role_at_least("operator", "viewer"));
        assert!(role_at_least("viewer", "viewer"));
        assert!(!role_at_least("viewer", "operator"));
        assert!(!role_at_least("operator", "admin"));
        assert!(!role_at_least("unknown", "operator"));
    }
}
