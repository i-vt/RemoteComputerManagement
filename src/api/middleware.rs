use axum::{
    extract::State,
    http::{StatusCode, HeaderMap, Method},
    response::IntoResponse,
    middleware,
};
use std::sync::Arc;
use crate::api::state::ApiContext;

pub async fn auth(
    State(state): State<Arc<ApiContext>>,
    headers: HeaderMap,
    request: axum::http::Request<axum::body::Body>,
    next: middleware::Next<axum::body::Body>,
) -> Result<impl IntoResponse, StatusCode> {
    if request.method() == Method::OPTIONS { 
        return Ok(next.run(request).await); 
    }

    match headers.get("X-API-KEY") {
        Some(key) if key == &state.api_key => Ok(next.run(request).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}
