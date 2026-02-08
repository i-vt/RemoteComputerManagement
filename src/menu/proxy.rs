use tokio::net::TcpListener;
use tokio::sync::{oneshot, mpsc};
use tokio_util::compat::{TokioAsyncReadCompatExt, FuturesAsyncReadCompatExt};
use futures::prelude::*;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::thread;

// Map SessionID -> StopSignalSender
pub type ProxyMap = Arc<Mutex<HashMap<u32, oneshot::Sender<()>>>>;

pub fn start(
    session_id: u32, 
    proxy_map: ProxyMap, 
    session_tx: mpsc::UnboundedSender<(String, Option<oneshot::Sender<u64>>)>
) {
    let (tx, rx) = oneshot::channel();
    
    {
        let mut map = proxy_map.lock().unwrap();
        if map.contains_key(&session_id) {
            eprintln!("[-] Proxy already running for session {}.", session_id);
            return;
        }
        map.insert(session_id, tx);
    }

    // Spawn a dedicated runtime thread for this proxy to avoid blocking the menu
    thread::spawn(move || {
        run_proxy_runtime(session_id, rx, proxy_map, session_tx);
    });
}

pub fn stop(
    session_id: u32,
    proxy_map: ProxyMap,
    session_tx: mpsc::UnboundedSender<(String, Option<oneshot::Sender<u64>>)>
) {
    let mut map = proxy_map.lock().unwrap();
    if let Some(tx) = map.remove(&session_id) {
        let _ = tx.send(());
        let _ = session_tx.send(("proxy:stop".to_string(), None));
        eprintln!("[+] Proxy stopped for session {}.", session_id);
    } else {
        eprintln!("[-] No active proxy found for session {}.", session_id);
    }
}

fn run_proxy_runtime(
    session_id: u32,
    mut stop_signal: oneshot::Receiver<()>,
    proxy_map: ProxyMap,
    session_tx: mpsc::UnboundedSender<(String, Option<oneshot::Sender<u64>>)>
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to build proxy runtime");

    rt.block_on(async move {
        let tunnel_listener = match TcpListener::bind("0.0.0.0:0").await {
            Ok(l) => l,
            Err(e) => { eprintln!("[-] Tunnel Bind Fail: {}", e); return; }
        };
        let socks_listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) => { eprintln!("[-] SOCKS Bind Fail: {}", e); return; }
        };

        let tunnel_port = tunnel_listener.local_addr().unwrap().port();
        let socks_port = socks_listener.local_addr().unwrap().port();

        eprintln!("\n[+] Proxy Initialized for Session {}", session_id);
        eprintln!("[i] Tunnel Listening on 0.0.0.0:{}", tunnel_port);
        eprintln!("[i] SOCKS5 Listening on 127.0.0.1:{}", socks_port);

        // Tell client to connect to us
        let _ = session_tx.send((format!("proxy:start {}", tunnel_port), None));
        eprintln!("[Proxy] Waiting for Client connection...");

        let (stream, addr) = tokio::select! {
            res = tunnel_listener.accept() => match res {
                Ok(r) => r,
                Err(_) => return,
            },
            _ = &mut stop_signal => {
                eprintln!("[Proxy] Stopped before client connection.");
                return;
            }
        };

        eprintln!("[Proxy] Client {} connected via Tunnel.", addr);

        let stream = Box::pin(TokioAsyncReadCompatExt::compat(stream));
        let connection = yamux::Connection::new(stream, yamux::Config::default(), yamux::Mode::Server);
        let control = connection.control();
        let runner = yamux::into_stream(connection);
        tokio::pin!(runner);

        loop {
            tokio::select! {
                _ = runner.next() => break,
                res = socks_listener.accept() => {
                    if let Ok((user_socket, _)) = res {
                        let mut ctrl = control.clone();
                        tokio::spawn(async move {
                            if let Ok(tunnel_stream) = ctrl.open_stream().await {
                                let (mut ri, mut wi) = tokio::io::split(user_socket);
                                let (mut ro, mut wo) = tokio::io::split(FuturesAsyncReadCompatExt::compat(tunnel_stream));
                                let _ = tokio::try_join!(
                                    tokio::io::copy(&mut ri, &mut wo),
                                    tokio::io::copy(&mut ro, &mut wi)
                                );
                            }
                        });
                    }
                }
                _ = &mut stop_signal => {
                    eprintln!("[Proxy] Shutdown signal received for Session {}.", session_id);
                    break;
                }
            }
        }
        
        // Clean up map when loop exits
        let mut map = proxy_map.lock().unwrap();
        map.remove(&session_id);
    });
}
