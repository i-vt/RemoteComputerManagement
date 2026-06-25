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

/// Authentication middleware. Resolves the operator from the X-API-KEY header
/// and injects OperatorInfo into request extensions. Returns 401 if the key
/// is missing or invalid.
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

    // Streaming download endpoints use a plain <a href>, which cannot send
    // custom headers.  Accept ?key=<api_key> as a fallback so the browser
    // streams directly to disk without fetch→blob memory buffering.
    let download_paths = ["/api/loot/zip", "/api/builder/jobs/"];
    let is_download_path = download_paths
        .iter()
        .any(|p| request.uri().path().starts_with(p));

    let query_key_buf: String;
    let api_key: &str = if !header_key.is_empty() {
        header_key
    } else if is_download_path {
        query_key_buf = request.uri().query()
            .unwrap_or("")
            .split('&')
            .find_map(|pair| {
                let mut kv = pair.splitn(2, '=');
                let k = kv.next()?;
                if k == "key" { kv.next().map(|v| v.to_owned()) } else { None }
            })
            .unwrap_or_default();
        &query_key_buf
    } else {
        ""
    };

    if api_key.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let operator = {
        let conn = state.db.get().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        database::get_operator_by_key(&conn, api_key)
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
