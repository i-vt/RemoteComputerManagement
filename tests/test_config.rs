// ./tests/test_config.rs
// Integration tests for the typed configuration core (src/config.rs).
//
// Env-var note: RCM_CONFIG is process-global, so exactly one test touches it
// and no other test in this binary depends on the ambient environment.

use rcm::config::{
    self, AgentConfig, Config, CryptoConfig, ServerConfig, TransferConfig,
};
use std::io::Write as _;
use std::path::Path;
use std::sync::Mutex;

// Serializes the two tests that mutate the process-global RCM_CONFIG.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn tmp_file(contents: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().expect("create temp file");
    f.write_all(contents.as_bytes()).expect("write temp file");
    f
}

#[test]
fn defaults_are_sane() {
    let c = Config::default();
    // Server
    assert_eq!(c.server.api_port, 8080);
    assert_eq!(c.server.default_listener_port, 4443);
    assert_eq!(c.server.max_queued_commands, 256);
    assert_eq!(c.server.http_prune_interval_secs, 300);
    assert_eq!(c.server.http_prune_idle_secs, 3600);
    assert_eq!(c.server.http_body_limit_bytes, 50 * 1024 * 1024);
    assert_eq!(c.server.registration_hmac_window_secs, 300);
    assert_eq!(c.server.seen_hmac_prune_threshold, 1000);
    assert_eq!(c.server.max_poison_recoveries, 3);
    assert_eq!(c.server.max_virtual_sessions, 64);
    // Transfer limits are ordered sanely.
    assert!(c.transfer.max_file_size_bytes > c.transfer.small_file_threshold_bytes);
    assert!(c.transfer.max_chunk_b64_bytes as u64 > c.transfer.download_chunk_size_bytes);
    assert!(c.transfer.zip_chunk_bytes > 0 && c.transfer.zip_channel_chunks > 0);
    // Agent jitter bounds are ordered.
    assert!(c.agent.jitter_min_pct <= c.agent.jitter_max_pct);
    assert!(c.agent.backoff_cap_secs > 0);
    // Logging retention target is below the trigger.
    assert!(c.logging.target_size_bytes < c.logging.max_size_bytes);
    // FFI pins.
    assert_eq!(c.ffi_windows.image_nt_signature, 0x4550);
    assert_eq!(c.ffi_windows.process_all_access, 0x001F_0FFF);
    assert_eq!(c.ffi_windows.se_debug_name, "SeDebugPrivilege");
    // Crypto.
    assert_eq!(c.crypto.fingerprint_hash, "md5");
    assert!(c.crypto.file_hash_algorithms.iter().any(|a| a == "sha256"));
}

#[test]
fn partial_toml_overlay_keeps_unspecified_defaults() {
    let f = tmp_file(
        "[server]\napi_port = 9090\n\n[transfer]\nchunk_sleep_ms = 7\n",
    );
    let c = config::load_from_file(f.path()).expect("partial overlay loads");
    // Overridden keys win.
    assert_eq!(c.server.api_port, 9090);
    assert_eq!(c.transfer.chunk_sleep_ms, 7);
    // Everything else keeps defaults, including untouched sections.
    assert_eq!(c.server.default_listener_port, 4443);
    assert_eq!(c.server.max_virtual_sessions, 64);
    assert_eq!(c.transfer.max_file_size_bytes, 500 * 1024 * 1024);
    assert_eq!(c.agent, AgentConfig::default());
    assert_eq!(c.crypto, CryptoConfig::default());
}

#[test]
fn full_toml_overlay_wins_everywhere() {
    let full = r#"
[server]
api_port = 1
default_listener_port = 2
max_queued_commands = 3
http_prune_interval_secs = 4
http_prune_idle_secs = 5
http_body_limit_bytes = 6
listener_max_sessions = 7
session_command_channel = 8
audit_operator_password_len = 9
registration_hmac_window_secs = 10
seen_hmac_prune_threshold = 11
max_poison_recoveries = 12
max_virtual_sessions = 13

[transfer]
max_file_size_bytes = 14
max_total_file_size_bytes = 15
max_chunk_b64_bytes = 16
small_file_threshold_bytes = 17
download_chunk_size_bytes = 18
recursive_chunk_size_bytes = 19
chunk_sleep_ms = 20
files_per_yield = 21
zip_channel_chunks = 22
zip_chunk_bytes = 23

[rcm]
storage_base = "a"
tool_name = "b"
spec_version = "c"
meta_cache_cap = 24
chunk_slots = 25
stale_slot_ttl_secs = 26
log_rotate_bytes = 27
screenshot_default_ext = "d"
fallback_toolspecific = "e"

[logging]
log_dir = "f"
max_size_bytes = 28
target_size_bytes = 29
cleanup_interval_secs = 30

[agent]
default_sleep_secs = 31
jitter_min_pct = 32
jitter_max_pct = 33
default_task_batch_size = 34
backoff_cap_secs = 35
connect_timeout_secs = 36
request_timeout_secs = 37

[evasion]
heap_block_size = 38
sleep_obfuscation = "g"

[ffi_windows]
image_nt_signature = 39
image_directory_entry_import = 40
mem_commit = 41
mem_reserve = 42
mem_release = 43
page_execute_readwrite = 44
page_readwrite = 45
page_execute_read = 46
page_noaccess = 47
process_all_access = 48
create_suspended = 49
infinite = 50
wait_timeout = 51
wait_object_0 = 52
token_query = 53
se_debug_name = "h"

[crypto]
fingerprint_hash = "i"
file_hash_algorithms = ["j", "k"]
"#;
    let f = tmp_file(full);
    let c = config::load_from_file(f.path()).expect("full overlay loads");
    assert_eq!(c.server.api_port, 1);
    assert_eq!(c.server.default_listener_port, 2);
    assert_eq!(c.server.max_queued_commands, 3);
    assert_eq!(c.server.http_prune_interval_secs, 4);
    assert_eq!(c.server.http_prune_idle_secs, 5);
    assert_eq!(c.server.http_body_limit_bytes, 6);
    assert_eq!(c.server.listener_max_sessions, 7);
    assert_eq!(c.server.session_command_channel, 8);
    assert_eq!(c.server.audit_operator_password_len, 9);
    assert_eq!(c.server.registration_hmac_window_secs, 10);
    assert_eq!(c.server.seen_hmac_prune_threshold, 11);
    assert_eq!(c.server.max_poison_recoveries, 12);
    assert_eq!(c.server.max_virtual_sessions, 13);
    assert_eq!(c.transfer.max_file_size_bytes, 14);
    assert_eq!(c.transfer.max_total_file_size_bytes, 15);
    assert_eq!(c.transfer.max_chunk_b64_bytes, 16);
    assert_eq!(c.transfer.small_file_threshold_bytes, 17);
    assert_eq!(c.transfer.download_chunk_size_bytes, 18);
    assert_eq!(c.transfer.recursive_chunk_size_bytes, 19);
    assert_eq!(c.transfer.chunk_sleep_ms, 20);
    assert_eq!(c.transfer.files_per_yield, 21);
    assert_eq!(c.transfer.zip_channel_chunks, 22);
    assert_eq!(c.transfer.zip_chunk_bytes, 23);
    assert_eq!(c.rcm.storage_base, "a");
    assert_eq!(c.rcm.tool_name, "b");
    assert_eq!(c.rcm.spec_version, "c");
    assert_eq!(c.rcm.meta_cache_cap, 24);
    assert_eq!(c.rcm.chunk_slots, 25);
    assert_eq!(c.rcm.stale_slot_ttl_secs, 26);
    assert_eq!(c.rcm.log_rotate_bytes, 27);
    assert_eq!(c.rcm.screenshot_default_ext, "d");
    assert_eq!(c.rcm.fallback_toolspecific, "e");
    assert_eq!(c.logging.log_dir, "f");
    assert_eq!(c.logging.max_size_bytes, 28);
    assert_eq!(c.logging.target_size_bytes, 29);
    assert_eq!(c.logging.cleanup_interval_secs, 30);
    assert_eq!(c.agent.default_sleep_secs, 31);
    assert_eq!(c.agent.jitter_min_pct, 32);
    assert_eq!(c.agent.jitter_max_pct, 33);
    assert_eq!(c.agent.default_task_batch_size, 34);
    assert_eq!(c.agent.backoff_cap_secs, 35);
    assert_eq!(c.agent.connect_timeout_secs, 36);
    assert_eq!(c.agent.request_timeout_secs, 37);
    assert_eq!(c.evasion.heap_block_size, 38);
    assert_eq!(c.evasion.sleep_obfuscation, "g");
    assert_eq!(c.ffi_windows.image_nt_signature, 39);
    assert_eq!(c.ffi_windows.image_directory_entry_import, 40);
    assert_eq!(c.ffi_windows.mem_commit, 41);
    assert_eq!(c.ffi_windows.mem_reserve, 42);
    assert_eq!(c.ffi_windows.mem_release, 43);
    assert_eq!(c.ffi_windows.page_execute_readwrite, 44);
    assert_eq!(c.ffi_windows.page_readwrite, 45);
    assert_eq!(c.ffi_windows.page_execute_read, 46);
    assert_eq!(c.ffi_windows.page_noaccess, 47);
    assert_eq!(c.ffi_windows.process_all_access, 48);
    assert_eq!(c.ffi_windows.create_suspended, 49);
    assert_eq!(c.ffi_windows.infinite, 50);
    assert_eq!(c.ffi_windows.wait_timeout, 51);
    assert_eq!(c.ffi_windows.wait_object_0, 52);
    assert_eq!(c.ffi_windows.token_query, 53);
    assert_eq!(c.ffi_windows.se_debug_name, "h");
    assert_eq!(c.crypto.fingerprint_hash, "i");
    assert_eq!(c.crypto.file_hash_algorithms, vec!["j".to_string(), "k".to_string()]);
}

#[test]
fn malformed_toml_is_err_for_load_and_default_for_load_or_default() {
    // load_from_file surfaces a descriptive error.
    let bad = tmp_file("[server\napi_port = ");
    let err = config::load_from_file(bad.path()).expect_err("malformed TOML must fail");
    assert!(err.contains("failed to parse config file"), "got: {}", err);

    // The same file via RCM_CONFIG: load() errs, load_or_default() falls back.
    let _guard = ENV_LOCK.lock().unwrap();
    std::env::set_var(config::ENV_CONFIG, bad.path());
    let err = config::load().expect_err("load must propagate the parse error");
    assert!(err.contains("failed to parse config file"), "got: {}", err);
    let fell_back = config::load_or_default();
    std::env::remove_var(config::ENV_CONFIG);
    assert_eq!(fell_back, Config::default());
}

#[test]
fn rcm_config_env_var_is_honored() {
    let f = tmp_file("[server]\napi_port = 1234\n[rcm]\ntool_name = \"envtool\"\n");
    let _guard = ENV_LOCK.lock().unwrap();
    std::env::set_var(config::ENV_CONFIG, f.path());
    let c = config::load().expect("load via RCM_CONFIG");
    std::env::remove_var(config::ENV_CONFIG);
    assert_eq!(c.server.api_port, 1234);
    assert_eq!(c.rcm.tool_name, "envtool");
    // Unspecified sections still come from defaults.
    assert_eq!(c.transfer, TransferConfig::default());
}

#[test]
fn template_roundtrips_to_default() {
    let rendered = config::template_toml();
    let parsed: Config = toml::from_str(&rendered).expect("template parses");
    assert_eq!(parsed, Config::default());
    // Every key line carries an inline comment.
    for line in rendered.lines() {
        let t = line.trim();
        if !t.is_empty() && !t.starts_with('#') && !t.starts_with('[') {
            assert!(t.contains('#'), "key line missing comment: {}", t);
        }
    }
}

#[test]
fn write_template_writes_parseable_file() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("config.example.toml");
    config::write_template(&path).expect("write template");
    let c = config::load_from_file(&path).expect("written template parses");
    assert_eq!(c, Config::default());
}

#[test]
fn example_file_in_repo_matches_template() {
    // config.example.toml at the repo root is generated by template_toml().
    // Trimmed build contexts (e.g. Docker stages that copy only selected
    // files) may not include it: skip there instead of failing, the pin
    // still applies wherever the full source tree is present.
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config.example.toml");
    if !path.exists() {
        eprintln!(
            "skipping: {} not present in this build context",
            path.display()
        );
        return;
    }
    let on_disk = std::fs::read_to_string(&path).expect("config.example.toml readable");
    assert_eq!(on_disk, config::template_toml());
    let parsed = config::load_from_file(&path).expect("example file parses");
    assert_eq!(parsed, Config::default());
}

#[test]
fn global_accessor_returns_same_instance_twice() {
    let a = config::config() as *const Config;
    let b = config::config() as *const Config;
    assert_eq!(a, b);
    // And it always yields a fully-populated config.
    assert!(config::config().server.max_queued_commands > 0);
    let _ = ServerConfig::default(); // section type is publicly constructible
}
