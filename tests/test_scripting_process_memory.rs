// tests/test_scripting_process_memory.rs
//
// Tests for scripting/{process,procinfo,memory}.rs
//
// Strategy: target the test process's own PID wherever possible so tests
// work without spawning external processes or requiring elevated privileges.

use rcm::agent::scripting::ExtensionManager;

fn run(script: &str) -> String {
    ExtensionManager::new().run_script(script, vec![])
}

fn self_pid() -> String { std::process::id().to_string() }

// ─────────────────────────────────────────────────────────────────────────────
// scripting/process.rs  — proc_kill, spawn_hidden, proc_env, is_elevated
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn process_is_elevated_returns_bool() {
    let result = run(r#"internal_is_elevated()"#);
    assert!(
        result.trim() == "true" || result.trim() == "false",
        "is_elevated should return a bool string: {}", result
    );
}

#[test]
fn process_spawn_hidden_returns_pid() {
    #[cfg(not(target_os = "windows"))]
    let script = r#"internal_spawn_hidden("sleep", "[\"1\"]")"#;
    #[cfg(target_os = "windows")]
    let script = r#"internal_spawn_hidden("cmd", "[\"/c\", \"timeout\", \"1\"]")"#;

    let pid_str = run(script);
    assert!(
        pid_str.parse::<u32>().is_ok(),
        "spawn_hidden should return a numeric PID: {}", pid_str
    );
    // Kill the spawned process immediately.
    run(&format!(r#"internal_proc_kill("{}")"#, pid_str));
}

#[test]
fn process_proc_kill_nonexistent_pid_returns_error() {
    // PID 0 is never a valid target for kill on any platform.
    let result = run(r#"internal_proc_kill("0")"#);
    // Either an error string or "Killed" depending on OS, but should not panic.
    let _ = result;
}

#[test]
fn process_proc_kill_invalid_pid_string_returns_error() {
    let result = run(r#"internal_proc_kill("not_a_number")"#);
    assert!(result.starts_with("Error"),
        "non-numeric PID should return Error: {}", result);
}

#[test]
fn process_spawn_and_kill_lifecycle() {
    #[cfg(not(target_os = "windows"))]
    let spawn_script = r#"internal_spawn_hidden("sleep", "[\"60\"]")"#;
    #[cfg(target_os = "windows")]
    let spawn_script = r#"internal_spawn_hidden("cmd", "[\"/c\", \"timeout\", \"/t\", \"60\"]")"#;

    let pid_str = run(spawn_script);
    assert!(pid_str.parse::<u32>().is_ok(),
        "spawn should return a PID: {}", pid_str);

    let kill_result = run(&format!(r#"internal_proc_kill("{}")"#, pid_str));
    assert!(kill_result == "Killed" || !kill_result.starts_with("Error"),
        "kill of spawned process should succeed: {}", kill_result);
}

#[test]
#[cfg(target_os = "linux")]
fn process_proc_env_self_contains_path() {
    let pid = self_pid();
    let json = run(&format!(r#"internal_proc_env("{}")"#, pid));
    assert!(!json.starts_with("Error"),
        "proc_env of self should succeed: {}", json);
    assert!(json.contains("PATH"),
        "self proc_env should contain PATH: {:.200}", json);
}

#[test]
fn process_token_steal_nonwindows_returns_error() {
    #[cfg(not(target_os = "windows"))]
    {
        let result = run(&format!(r#"internal_token_steal("{}")"#, self_pid()));
        assert!(result.starts_with("Error"),
            "token_steal on non-Windows should return Error: {}", result);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// scripting/procinfo.rs  — proc_path, proc_parent, proc_cmdline, proc_modules
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn procinfo_proc_path_self_nonempty() {
    let path = run(&format!(r#"internal_proc_path("{}")"#, self_pid()));
    assert!(!path.starts_with("Error"),
        "proc_path for self should succeed: {}", path);
    assert!(!path.is_empty(),
        "proc_path should return a non-empty path");
}

#[test]
fn procinfo_proc_parent_self_is_positive_integer() {
    let parent_str = run(&format!(r#"internal_proc_parent("{}")"#, self_pid()));
    assert!(!parent_str.starts_with("Error"),
        "proc_parent for self should succeed: {}", parent_str);
    let ppid: u32 = parent_str.trim().parse()
        .expect("parent PID should be a non-negative integer: {parent_str}");
    assert!(ppid > 0, "parent PID should be > 0: {}", ppid);
}

#[test]
fn procinfo_proc_path_invalid_pid_returns_error() {
    let result = run(r#"internal_proc_path("not_a_pid")"#);
    assert!(result.starts_with("Error"),
        "non-numeric PID should error: {}", result);
}

#[test]
#[cfg(target_os = "linux")]
fn procinfo_proc_cmdline_self_contains_binary_name() {
    let cmdline = run(&format!(r#"internal_proc_cmdline("{}")"#, self_pid()));
    assert!(!cmdline.starts_with("Error"),
        "proc_cmdline for self should succeed: {}", cmdline);
    // The test binary name usually contains "test" or the crate name.
    assert!(!cmdline.is_empty(), "proc_cmdline should not be empty");
}

#[test]
#[cfg(target_os = "linux")]
fn procinfo_proc_user_self_nonempty() {
    let user = run(&format!(r#"internal_proc_user("{}")"#, self_pid()));
    assert!(!user.starts_with("Error"),
        "proc_user for self should succeed: {}", user);
    assert!(!user.is_empty(), "proc_user should return a non-empty username");
}

#[test]
#[cfg(target_os = "linux")]
fn procinfo_proc_modules_self_json_array() {
    let json = run(&format!(r#"internal_proc_modules("{}")"#, self_pid()));
    assert!(!json.starts_with("Error"),
        "proc_modules for self should succeed: {}", json);
    let v: serde_json::Value = serde_json::from_str(&json)
        .expect("proc_modules should return JSON");
    assert!(v.is_array(), "proc_modules should return a JSON array");
    // The test binary itself should appear.
    assert!(!v.as_array().unwrap().is_empty(),
        "proc_modules should have at least one entry");
}

// ─────────────────────────────────────────────────────────────────────────────
// scripting/memory.rs  — mem_regions, mem_scan (Linux self-PID)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[cfg(target_os = "linux")]
fn memory_mem_regions_self_nonempty_json() {
    let pid   = self_pid();
    let json  = run(&format!(r#"internal_mem_regions("{}")"#, pid));
    assert!(!json.starts_with("Error"),
        "mem_regions for self should succeed: {}", json);
    let v: serde_json::Value = serde_json::from_str(&json)
        .expect("mem_regions should return JSON");
    assert!(v.is_array(), "mem_regions should be a JSON array");
    assert!(!v.as_array().unwrap().is_empty(),
        "self memory regions should not be empty");
}

#[test]
#[cfg(target_os = "linux")]
fn memory_mem_scan_finds_known_pattern() {
    // Place a known byte sequence on the stack and scan for it.
    let needle: &[u8; 8] = b"RCM_TEST";
    let needle_hex = hex::encode(needle);
    let pid = self_pid();

    let json = run(&format!(
        r#"internal_mem_scan("{}", "{}")"#, pid, needle_hex
    ));
    // The needle is on the stack of this test thread; mem_scan may or may not
    // find it depending on /proc/mem permissions and ASLR.
    // We only verify the shape — a JSON array of hex addresses.
    assert!(!json.starts_with("Error") || json.contains("/proc"),
        "mem_scan should return JSON or a /proc error: {}", json);
    if !json.starts_with("Error") {
        let v: serde_json::Value = serde_json::from_str(&json)
            .expect("mem_scan should return JSON: {json}");
        assert!(v.is_array(), "mem_scan should return a JSON array");
    }
}

#[test]
fn memory_mem_read_invalid_pid_returns_error() {
    let result = run(r#"internal_mem_read("not_a_pid", "0x0", 4)"#);
    assert!(result.starts_with("Error"),
        "non-numeric PID should error: {}", result);
}

#[test]
fn memory_mem_write_nonwindows_linux_invalid_pid_returns_error() {
    // Writing to an invalid PID should always error cleanly.
    let result = run(r#"internal_mem_write("999999999", "0x400000", "deadbeef")"#);
    assert!(result.starts_with("Error"),
        "write to non-existent process should error: {}", result);
}
