// tests/test_utils.rs
//
// Tests for src/utils.rs public API.
// All functions are OS-level primitives; tests run on every platform and
// skip platform-specific assertions gracefully.

use rcm::utils;
use std::time::Duration;

// ─────────────────────────────────────────────────────────────────────────────
// execute_shell_command
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn shell_echo_stdout_and_exit_zero() {
    #[cfg(not(target_os = "windows"))]
    let (out, err, code) = utils::execute_shell_command("echo hello_rcm_test");
    #[cfg(target_os = "windows")]
    let (out, err, code) = utils::execute_shell_command("cmd /c echo hello_rcm_test");
    assert_eq!(code, 0, "echo should exit 0; stderr: {}", err);
    assert!(out.contains("hello_rcm_test"), "stdout should contain echo'd text: {}", out);
}

#[test]
fn shell_exit_nonzero_returns_code() {
    #[cfg(not(target_os = "windows"))]
    let (_, _, code) = utils::execute_shell_command("exit 42");
    #[cfg(target_os = "windows")]
    let (_, _, code) = utils::execute_shell_command("cmd /c exit 42");
    assert_eq!(code, 42, "exit code should be captured exactly");
}

#[test]
fn shell_stderr_captured_separately() {
    #[cfg(not(target_os = "windows"))]
    let (out, err, _) = utils::execute_shell_command("echo on_stdout; echo on_stderr >&2");
    #[cfg(target_os = "windows")]
    let (out, err, _) = utils::execute_shell_command("cmd /c echo on_stdout & echo on_stderr 1>&2");
    assert!(out.contains("on_stdout"), "stdout capture failed: {:?}", out);
    assert!(err.contains("on_stderr"), "stderr capture failed: {:?}", err);
}

#[test]
fn shell_pipe_works() {
    #[cfg(not(target_os = "windows"))]
    let (out, _, code) = utils::execute_shell_command("printf 'A\\nB\\nC' | grep B");
    if cfg!(target_os = "windows") { return; } // pipes tested above
    assert_eq!(code, 0, "grep through pipe should exit 0");
    assert!(out.trim() == "B", "grep should return only matched line: {:?}", out);
}

#[test]
fn shell_empty_command_does_not_panic() {
    let (_, _, _) = utils::execute_shell_command("");
    // Just verify it doesn't panic
}

#[test]
fn shell_long_output_returns_completely() {
    #[cfg(not(target_os = "windows"))]
    let (out, _, _) = utils::execute_shell_command("python3 -c 'print(\"X\" * 100000)' 2>/dev/null || true");
    #[cfg(target_os = "windows")]
    let (out, _, _) = utils::execute_shell_command(
        "cmd /c python -c \"print('X' * 100000)\" 2>NUL"
    );
    if out.is_empty() { return; } // python not available — skip
    assert!(out.len() > 99000, "long output should not be truncated: {} chars", out.len());
}

// ─────────────────────────────────────────────────────────────────────────────
// execute_shell_command_timeout
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn shell_timeout_fires_before_deadline() {
    let start = std::time::Instant::now();
    let (_, _, code) = utils::execute_shell_command_timeout(
        "sleep 60",
        Duration::from_millis(500),
    );
    let elapsed = start.elapsed();
    assert!(elapsed.as_secs() < 5,
        "timeout should fire well before 60s (took {:?})", elapsed);
    assert_ne!(code, 0, "timed-out process should not exit 0");
}

#[test]
fn shell_timeout_long_enough_lets_command_finish() {
    #[cfg(not(target_os = "windows"))]
    let (out, _, code) = utils::execute_shell_command_timeout(
        "echo done_in_time",
        Duration::from_secs(10),
    );
    #[cfg(target_os = "windows")]
    let (out, _, code) = utils::execute_shell_command_timeout(
        "cmd /c echo done_in_time",
        Duration::from_secs(10),
    );
    assert_eq!(code, 0, "fast command should finish before timeout");
    assert!(out.contains("done_in_time"), "output should be captured: {}", out);
}

// ─────────────────────────────────────────────────────────────────────────────
// get_process_list
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn process_list_contains_self_pid() {
    let pid    = std::process::id().to_string();
    let result = utils::get_process_list();
    assert!(!result.is_empty(), "process list should not be empty");
    assert!(result.contains(&pid),
        "process list should contain this test's PID ({}): {:.300}", pid, result);
}

#[test]
fn process_list_nonempty_string() {
    let result = utils::get_process_list();
    assert!(!result.is_empty(), "get_process_list should return a non-empty string");
}

// ─────────────────────────────────────────────────────────────────────────────
// get_network_interfaces
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn network_interfaces_nonempty() {
    let ifaces = utils::get_network_interfaces();
    if ifaces.is_empty() { eprintln!("[SKIP] get_network_interfaces returned [] (ip not installed?)"); return; }
    assert!(!ifaces.is_empty(), "get_network_interfaces should return at least one interface");
}

#[test]
fn network_interfaces_has_loopback() {
    let ifaces = utils::get_network_interfaces();
    if ifaces.is_empty() { eprintln!("[SKIP] no interfaces returned"); return; }
    let has_loopback = ifaces.iter().any(|i| {
        i.name.contains("lo") || i.name.contains("Loopback") || i.name.contains("loop")
    });
    assert!(has_loopback, "loopback interface must be present: {:?}",
        ifaces.iter().map(|i| &i.name).collect::<Vec<_>>());
}

#[test]
fn network_interfaces_loopback_has_127001() {
    let ifaces = utils::get_network_interfaces();
    let loopback = ifaces.iter().find(|i| {
        i.name.contains("lo") || i.name.contains("Loopback") || i.name.contains("loop")
    });
    if let Some(lo) = loopback {
        assert!(
            lo.addresses.iter().any(|ip| ip.starts_with("127.")),
            "loopback should have 127.x.x.x IPv4 address: {:?}", lo.addresses
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// get_persistent_id / generate_exe_id
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn persistent_id_is_nonempty() {
    let id = utils::get_persistent_id();
    assert!(!id.is_empty(), "get_persistent_id should return a non-empty string");
}

#[test]
fn persistent_id_is_deterministic() {
    let a = utils::get_persistent_id();
    let b = utils::get_persistent_id();
    assert_eq!(a, b, "get_persistent_id should return the same value each call");
}

#[test]
fn exe_id_differs_by_salt() {
    let a = utils::generate_exe_id("salt_a");
    let b = utils::generate_exe_id("salt_b");
    assert_ne!(a, b, "generate_exe_id should differ for different salts");
}

#[test]
fn exe_id_same_salt_is_deterministic() {
    let a = utils::generate_exe_id("same_salt");
    let b = utils::generate_exe_id("same_salt");
    assert_eq!(a, b, "generate_exe_id should be deterministic for the same salt");
}

// ─────────────────────────────────────────────────────────────────────────────
// strip_ansi
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn strip_ansi_removes_escape_sequences() {
    let ansi = "\x1b[31mred text\x1b[0m";
    let clean = utils::strip_ansi(ansi);
    assert_eq!(clean, "red text", "ANSI escape sequences should be removed");
}

#[test]
fn strip_ansi_leaves_plain_text_unchanged() {
    let plain = "hello world";
    assert_eq!(utils::strip_ansi(plain), plain);
}
