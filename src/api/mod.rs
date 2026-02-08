// src/api/mod.rs
pub mod state;
pub mod models;
pub mod middleware;
pub mod routes;

use axum::{
    routing::{get, post},
    Router, middleware as axum_middleware,
};
use tower_http::cors::CorsLayer;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::net::SocketAddr;

use crate::common::SharedSessions;
use crate::database::DbPool; 

pub use state::{ApiContext, SharedResults, SharedProxies, SharedScripts};
use crate::api::routes::{hosts, proxies, modules, history};

pub use state::SharedResults as ResultsType;
pub use state::SharedProxies as ProxiesType;

pub async fn start_api_server(
    sessions: SharedSessions, 
    db: DbPool, 
    results: SharedResults, 
    proxies: SharedProxies,
    api_key: String, 
    port: u16
) {
    let scripts: SharedScripts = Arc::new(Mutex::new(HashMap::new()));
    let shared_state = Arc::new(ApiContext { sessions, db, results, proxies, scripts, api_key });

    let cors = CorsLayer::permissive();

    let app = Router::new()
        .route("/api/hosts", get(hosts::list_hosts))
        .route("/api/hosts/:id/command", post(hosts::send_command))
        .route("/api/hosts/:id/output/:req_id", get(hosts::get_output))
        .route("/api/hosts/:id/history", get(history::get_history)) 
        .route("/api/history", get(history::get_global_history))
        // [NEW] File Browser
        .route("/api/hosts/:id/files/browse", get(hosts::browse_files))
        
        .route("/api/broadcast", post(hosts::broadcast))
        .route("/api/broadcast/module", post(modules::broadcast_module))
        .route("/api/proxies", get(proxies::list_proxies))
        .route("/api/hosts/:id/proxy", post(proxies::start_proxy).delete(proxies::stop_proxy))
        .route("/api/hosts/:id/proxy/check", post(proxies::check_proxy_ip))
        .route("/api/hosts/:id/modules/:module_name", post(modules::execute_module))
        .route("/api/modules", get(modules::list_modules))
        .route("/api/hosts/:id/extensions/:filename", post(modules::deploy_extension))

        .route_layer(axum_middleware::from_fn_with_state(shared_state.clone(), middleware::auth))
        .layer(cors)
        .with_state(shared_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    eprintln!("[+] API Server listening on http://{}", addr);

    let server = axum::Server::bind(&addr)
        .serve(app.into_make_service());

    if let Err(e) = server.await {
        eprintln!("[-] API Server Error: {}", e);
    }
}
