// src/server/mod.rs
pub mod session;
pub mod logging;
pub mod listeners;
pub mod http_listener;

use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use dashmap::DashMap;
use uuid::Uuid;
use tracing::{info, error};

use crate::{database, menu, api};
use crate::common::SharedSessions;
use crate::server::listeners::ListenerManager;

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let db_pool = database::init()?;

    let (cert, key, ca) = {
        let conn = db_pool.get()?;
        database::load_or_import_certs(&conn)?
    };

    let sessions: SharedSessions = Arc::new(DashMap::new());
    let results_store: api::SharedResults = Arc::new(Mutex::new(HashMap::new()));
    let proxy_store: api::SharedProxies = Arc::new(Mutex::new(HashMap::new()));

    // ── Bootstrap default admin operator on first run ──────────────────
    let _admin_key = {
        let conn = db_pool.get()?;
        if database::operator_count(&conn) == 0 {
            // Generate a 24-character password from the full alphanumeric set.
            // UUID hex gives only 4 bits/char (64 bits for 16 chars). A 24-char
            // alphanumeric password gives ~143 bits of entropy (log2(62^24)),
            // making brute-force infeasible even if the database is dumped.
            let password: String = {
                use rand::Rng;
                // Use OsRng directly for guaranteed OS-level CSPRNG entropy.
                // thread_rng() is generally secure but not strictly guaranteed
                // to be a CSPRNG in all configurations/platforms.
                let mut rng = rand::rngs::OsRng;
                const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                (0..24).map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char).collect()
            };
            let api_key = Uuid::new_v4().to_string();
            let hash = crate::api::routes::operators::hash_password(&password)
                .expect("FATAL: argon2 password hashing failed — cannot create admin account");
            database::create_operator(&conn, "admin", &hash, "admin", &api_key)?;
            println!("========================================");
            println!("[*] First run — default admin created:");
            println!("[*]   Username:  admin");
            println!("[*]   Password:  {}", password);
            println!("[*]   API Key:   {}", api_key);
            println!("========================================");
            api_key
        } else {
            let ops = database::list_operators(&conn);
            let admin = ops.iter().find(|o| o.role == "admin").unwrap_or(&ops[0]);
            admin.api_key.clone()
        }
    };

    // ── Start Listener Manager ─────────────────────────────────────────
    let listener_mgr = Arc::new(tokio::sync::Mutex::new(ListenerManager::new(
        db_pool.clone(),
        sessions.clone(),
        results_store.clone(),
        cert.clone(),
        key.clone(),
        ca.clone(),
    )));

    // Ensure at least one default listener exists
    {
        let conn = db_pool.get()?;
        let existing = database::list_listeners(&conn);
        if existing.is_empty() {
            database::create_listener(&conn, "default", 4443, "tls", None)?;
            println!("[*] Created default TLS listener on port 4443");
        }
    }

    // Auto-start all listeners flagged for it
    {
        let mut mgr = listener_mgr.lock().await;
        mgr.start_auto().await;
    }

    // ── Start API Server ───────────────────────────────────────────────
    let api_port = 8080;
    println!("[*] API Endpoint:   http://127.0.0.1:{}", api_port);
    println!("========================================");

    info!("C2 Server started");

    let s_api = sessions.clone();
    let db_api = db_pool.clone();
    let res_api = results_store.clone();
    let prox_api = proxy_store.clone();
    let lm_api = listener_mgr.clone();

    tokio::spawn(async move {
        api::start_api_server(s_api, db_api, res_api, prox_api, lm_api, api_port).await;
    });

    // ── Periodic Log Cleanup ──────────────────────────────────────────
    logging::spawn_periodic_cleanup();

    // ── Interactive CLI Menu ───────────────────────────────────────────
    let s_cli = sessions.clone();
    std::thread::spawn(move || {
        if let Err(e) = menu::run(s_cli) { error!("Menu Error: {:?}", e); }
    });

    // ── Graceful shutdown on SIGTERM/SIGINT ────────────────────────────
    let db_shutdown = db_pool.clone();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received CTRL+C, shutting down...");
        }
        _ = async {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                let mut sigterm = signal(SignalKind::terminate()).expect("Failed to bind SIGTERM");
                sigterm.recv().await;
            }
            #[cfg(not(unix))]
            {
                // On non-Unix, just wait forever (ctrl_c branch will fire)
                std::future::pending::<()>().await;
            }
        } => {
            info!("Received SIGTERM, shutting down...");
        }
    }

    // Cleanup: checkpoint WAL and close DB cleanly
    info!("Running shutdown cleanup...");
    if let Ok(conn) = db_shutdown.get() {
        if let Err(e) = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);") {
            error!("WAL checkpoint failed: {}", e);
        } else {
            info!("WAL checkpoint complete");
        }
    }
    info!("Server stopped.");
    Ok(())
}
