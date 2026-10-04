use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_util::compat::{TokioAsyncReadCompatExt, FuturesAsyncReadCompatExt};
use futures::prelude::*;
use std::sync::MutexGuard;
use std::collections::HashMap;
use std::thread;

use crate::api::SharedProxies;
use crate::api::state::ProxyHandle;
use crate::api::routes::proxies::{new_tunnel_token, tunnel_token_matches};
use crate::common::{SessionCommandSender, try_send_session_command};

// The menu and the REST API share one proxy registry: the SharedProxies map
// owned by server::run and exposed through ApiContext.proxies. Menu-started
// proxies therefore show up in /api/proxies and the panel, API-started
// proxies show up in `proxy list`, and either side can stop any entry
// through the same teardown path.

fn lock_map(map: &SharedProxies) -> MutexGuard<'_, HashMap<u32, ProxyHandle>> {
    map.lock().unwrap_or_else(|e| e.into_inner())
}

/// Removes the session's proxy registry entry when dropped. It lives for the
/// whole proxy runtime, so runtime failures, tunnel death and manual stops
/// from either side all release the entry and a later start cannot wedge on
/// a stale one.
struct ProxyMapEntry {
    map: SharedProxies,
    session_id: u32,
}

impl Drop for ProxyMapEntry {
    fn drop(&mut self) {
        lock_map(&self.map).remove(&self.session_id);
    }
}

/// Register a proxy handle for a session, refusing to replace a live entry.
/// Check and insert happen under one lock, so a concurrent start from the
/// other side (API vs menu) loses honestly instead of silently taking over
/// the session's slot. Returns false when any proxy already exists.
pub fn try_register_proxy(proxies: &SharedProxies, handle: ProxyHandle) -> bool {
    let mut map = lock_map(proxies);
    if map.contains_key(&handle.session_id) {
        return false;
    }
    map.insert(handle.session_id, handle);
    true
}

/// Remove and return the session's proxy handle, if any. The caller owns
/// teardown: signal stop_tx and tell the agent to shut its end down.
pub fn take_proxy_handle(proxies: &SharedProxies, session_id: u32) -> Option<ProxyHandle> {
    lock_map(proxies).remove(&session_id)
}

/// Snapshot of active proxies as (session_id, tunnel_port, socks_port),
/// sorted by session id for stable display.
pub fn proxy_entries(proxies: &SharedProxies) -> Vec<(u32, u16, u16)> {
    let map = lock_map(proxies);
    let mut entries: Vec<(u32, u16, u16)> = map
        .values()
        .map(|h| (h.session_id, h.tunnel_port, h.socks_port))
        .collect();
    entries.sort_by_key(|e| e.0);
    entries
}

/// Build the `proxy:start <port> <token>` command the agent expects. The
/// token is presented by the agent right after it connects to the tunnel
/// port, before yamux starts, so an ephemeral port bound on 0.0.0.0 cannot
/// be claimed by whoever connects first.
pub fn build_proxy_start_command(tunnel_port: u16, tunnel_token: &str) -> String {
    format!("proxy:start {} {}", tunnel_port, tunnel_token)
}

pub fn start(
    session_id: u32,
    proxies: SharedProxies,
    session_tx: SessionCommandSender,
) {
    // Fail fast before doing any work; the authoritative conflict check is
    // try_register_proxy below, after the ports exist.
    if lock_map(&proxies).contains_key(&session_id) {
        eprintln!("[-] Proxy already running for session {}.", session_id);
        return;
    }

    // Bind before registering so the shared map only ever holds handles with
    // live ports, matching what the API route publishes. The runtime moves
    // into the proxy thread together with the listeners it created.
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build() {
        Ok(rt) => rt,
        Err(e) => { eprintln!("[-] Failed to build proxy runtime: {}", e); return; }
    };

    let bound: Result<(TcpListener, TcpListener, u16, u16), String> = rt.block_on(async {
        let tunnel_listener = TcpListener::bind("0.0.0.0:0").await
            .map_err(|e| format!("Tunnel Bind Fail: {}", e))?;
        let socks_listener = TcpListener::bind("127.0.0.1:0").await
            .map_err(|e| format!("SOCKS Bind Fail: {}", e))?;
        let tunnel_port = tunnel_listener.local_addr()
            .map_err(|e| format!("Tunnel addr failed: {}", e))?.port();
        let socks_port = socks_listener.local_addr()
            .map_err(|e| format!("SOCKS addr failed: {}", e))?.port();
        Ok((tunnel_listener, socks_listener, tunnel_port, socks_port))
    });

    let (tunnel_listener, socks_listener, tunnel_port, socks_port) = match bound {
        Ok(b) => b,
        Err(e) => { eprintln!("[-] {}", e); return; }
    };

    let (tx, rx) = oneshot::channel();
    let handle = ProxyHandle { session_id, tunnel_port, socks_port, stop_tx: tx };
    if !try_register_proxy(&proxies, handle) {
        // Lost a race with a start from the other side; our listeners and
        // runtime drop here, releasing both ports.
        eprintln!("[-] Proxy already running for session {} (concurrent start).", session_id);
        return;
    }

    eprintln!("\n[+] Proxy Initialized for Session {}", session_id);
    eprintln!("[i] Tunnel Listening on 0.0.0.0:{}", tunnel_port);
    eprintln!("[i] SOCKS5 Listening on 127.0.0.1:{}", socks_port);

    // Spawn a dedicated runtime thread for this proxy to avoid blocking the menu
    thread::spawn(move || {
        run_proxy_runtime(
            session_id, rx, proxies, session_tx, rt,
            tunnel_listener, socks_listener, tunnel_port,
        );
    });
}

/// Stop the session's proxy through the same teardown path the API stop
/// route uses: remove the registry entry, signal the runtime to shut down,
/// then tell the agent to close its end.
pub fn stop(
    session_id: u32,
    proxies: &SharedProxies,
    session_tx: SessionCommandSender,
) {
    if let Some(handle) = take_proxy_handle(proxies, session_id) {
        let _ = handle.stop_tx.send(());
        let _ = try_send_session_command(session_id, &session_tx, "proxy:stop".to_string(), None);
        eprintln!("[+] Proxy stopped for session {}.", session_id);
    } else {
        eprintln!("[-] No active proxy found for session {}.", session_id);
    }
}

/// Show every active proxy in the shared registry, regardless of which side
/// started it, marking the one bound to the session being interacted with.
pub fn list(proxies: &SharedProxies, current_session_id: u32) {
    let entries = proxy_entries(proxies);
    if entries.is_empty() {
        eprintln!("No active proxies.");
        return;
    }
    eprintln!("Session | Tunnel Port | SOCKS5 Port");
    eprintln!("--------|-------------|------------");
    for (sid, tunnel_port, socks_port) in entries {
        let marker = if sid == current_session_id { "  <- this session" } else { "" };
        eprintln!("{:<7} | {:<11} | {}{}", sid, tunnel_port, socks_port, marker);
    }
}

#[allow(clippy::too_many_arguments)]
fn run_proxy_runtime(
    session_id: u32,
    mut stop_signal: oneshot::Receiver<()>,
    proxies: SharedProxies,
    session_tx: SessionCommandSender,
    rt: tokio::runtime::Runtime,
    tunnel_listener: TcpListener,
    socks_listener: TcpListener,
    tunnel_port: u16,
) {
    // Created before any fallible step so every exit path drops it and
    // releases the proxy registry entry.
    let _map_entry = ProxyMapEntry { map: proxies, session_id };

    rt.block_on(async move {
        // Tell client to connect to us. The per-tunnel token travels inside
        // the proxy:start command; the agent presents it right after the TCP
        // connect, before yamux starts.
        let tunnel_token = new_tunnel_token();
        if !try_send_session_command(
            session_id,
            &session_tx,
            build_proxy_start_command(tunnel_port, &tunnel_token),
            None,
        ) {
            eprintln!("[-] Session command queue full or closed; proxy start rejected");
            return;
        }
        eprintln!("[Proxy] Waiting for Client connection...");

        // Only the peer that proves the token is the agent; wrong or slow
        // peers are dropped and the loop keeps listening.
        let (stream, addr) = loop {
            let (mut s, peer) = tokio::select! {
                res = tunnel_listener.accept() => match res {
                    Ok(r) => r,
                    Err(_) => return,
                },
                _ = &mut stop_signal => {
                    eprintln!("[Proxy] Stopped before client connection.");
                    return;
                }
            };
            if tunnel_token_matches(&mut s, &tunnel_token).await {
                break (s, peer);
            }
            eprintln!("[Proxy] Dropped unauthenticated tunnel peer {}.", peer);
        };

        eprintln!("[Proxy] Client {} connected via Tunnel.", addr);

        let stream = Box::pin(TokioAsyncReadCompatExt::compat(stream));
        let connection = yamux::Connection::new(stream, yamux::Config::default(), yamux::Mode::Server);
        let control = connection.control();

        // Drive the yamux runner in its own dedicated task. yamux must be
        // polled continuously; parking it in a select! arm starves it of
        // ACKs and window updates, and any single runner event (including
        // routine control frames) would fire that arm and break the accept
        // loop, silently killing the tunnel.
        let (dead_tx, mut dead_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let runner = yamux::into_stream(connection);
            tokio::pin!(runner);
            // Processes all control frames, ACKs, window updates and
            // keepalives. Returns when the underlying TCP connection closes.
            while runner.next().await.is_some() {}
            // Signal the accept loop that the tunnel is gone.
            let _ = dead_tx.send(());
        });

        loop {
            tokio::select! {
                // Tunnel died - clean up.
                _ = &mut dead_rx => {
                    eprintln!("[Proxy] Tunnel closed for Session {}.", session_id);
                    break;
                }
                // New SOCKS connection from the operator's tool.
                res = socks_listener.accept() => {
                    if let Ok((user_socket, _)) = res {
                        let mut ctrl = control.clone();
                        tokio::spawn(async move {
                            match ctrl.open_stream().await {
                                Ok(tunnel_stream) => {
                                    let (mut ri, mut wi) = tokio::io::split(user_socket);
                                    let (mut ro, mut wo) = tokio::io::split(FuturesAsyncReadCompatExt::compat(tunnel_stream));
                                    let _ = tokio::try_join!(
                                        tokio::io::copy(&mut ri, &mut wo),
                                        tokio::io::copy(&mut ro, &mut wi)
                                    );
                                }
                                Err(e) => {
                                    eprintln!("[Proxy] open_stream failed: {} - tunnel may have closed", e);
                                }
                            }
                        });
                    }
                }
                // Manual stop from the operator, from either side.
                _ = &mut stop_signal => {
                    eprintln!("[Proxy] Shutdown signal received for Session {}.", session_id);
                    break;
                }
            }
        }
    });
}
