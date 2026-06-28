// tests/test_scripting_network_dns.rs
//
// Tests for scripting/{network,dns,evasion}.rs
//
// Network tests that require external connectivity are skip-guarded.
// All TCP/UDP tests use loopback (127.0.0.1) so they work offline.

use rcm::agent::scripting::ExtensionManager;
use std::{
    net::{TcpListener, UdpSocket},
    thread,
    time::Duration,
};

fn run(script: &str) -> String {
    ExtensionManager::new().run_script(script, vec![])
}

// ─────────────────────────────────────────────────────────────────────────────
// scripting/dns.rs
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn dns_resolve_localhost_gives_loopback() {
    let result = run(r#"internal_dns_resolve("localhost")"#);
    assert!(
        result == "127.0.0.1" || result == "::1",
        "localhost should resolve to a loopback address: {}", result
    );
}

#[test]
fn dns_resolve_all_localhost_is_array() {
    let json = run(r#"internal_dns_resolve_all("localhost")"#);
    assert!(!json.starts_with("Error"), "resolve_all should not error: {}", json);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.is_array(), "resolve_all should return JSON array");
    assert!(
        !v.as_array().unwrap().is_empty(),
        "localhost should resolve to at least one address"
    );
}

#[test]
fn dns_resolve_nonexistent_domain_returns_error() {
    let result = run(r#"internal_dns_resolve("this.hostname.definitely.does.not.exist.invalid")"#);
    assert!(result.starts_with("Error"),
        "non-existent domain should return Error: {}", result);
}

#[test]
fn dns_txt_without_network_returns_error_or_empty() {
    // This makes a real DoH request. If there's no network, we get an error — that's acceptable.
    // If network is available, the shape must be a JSON array.
    let result = run(r#"internal_dns_txt("example.com")"#);
    if result.starts_with("Error") { return; } // no network — skip
    let v: serde_json::Value = serde_json::from_str(&result)
        .expect("dns_txt should return JSON when network is available");
    assert!(v.is_array(), "dns_txt should return a JSON array: {}", result);
}

// ─────────────────────────────────────────────────────────────────────────────
// scripting/network.rs  — tcp_connect (loopback, no external network)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn tcp_connect_to_listening_socket_returns_open() {
    // Bind a real listener on a random port, then probe it.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port     = listener.local_addr().unwrap().port();
    // Keep listener alive for the duration of the test.
    thread::spawn(move || { let _ = listener.accept(); });

    let result = run(&format!(
        r#"internal_tcp_connect("127.0.0.1", {}, 1000)"#, port
    ));
    assert_eq!(result, "open", "active listener should return 'open': {}", result);
}

#[test]
fn tcp_connect_no_listener_returns_closed_or_error() {
    // Use a port where nothing is listening (we just bound + unbound to get a port number).
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener); // release immediately
    thread::sleep(Duration::from_millis(50)); // let OS reclaim port

    let result = run(&format!(
        r#"internal_tcp_connect("127.0.0.1", {}, 300)"#, port
    ));
    assert!(
        result == "closed" || result.starts_with("Error"),
        "no listener should return 'closed' or Error: {}", result
    );
}

#[test]
fn tcp_connect_timeout_is_respected() {
    // 192.0.2.0/24 is TEST-NET-1 (RFC 5737) — packets go nowhere, so the connect times out.
    let start  = std::time::Instant::now();
    let result = run(r#"internal_tcp_connect("192.0.2.1", 9999, 300)"#);
    let elapsed = start.elapsed().as_millis();
    // Should return within ~1 second even though the timeout is 300ms.
    assert!(elapsed < 5000,
        "tcp_connect should not block forever (took {}ms): {}", elapsed, result);
}

// ─────────────────────────────────────────────────────────────────────────────
// scripting/network.rs  — udp_send / udp_recv (loopback round-trip)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn udp_send_recv_round_trip() {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = sock.local_addr().unwrap().port();
    let data_hex = "deadbeef";

    // Start a receiver thread.
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    thread::spawn(move || {
        let mut buf = [0u8; 64];
        if let Ok((n, _)) = sock.recv_from(&mut buf) {
            tx.send(hex::encode(&buf[..n])).ok();
        }
    });

    let send_result = run(&format!(
        r#"internal_udp_send("127.0.0.1", {}, "{}")"#, port, data_hex
    ));
    assert!(send_result.starts_with("Sent"),
        "udp_send should report success: {}", send_result);

    let received = rx.recv_timeout(Duration::from_secs(3)).unwrap_or_default();
    assert_eq!(received, data_hex, "received data should match sent data");
}

#[test]
fn udp_recv_times_out_with_no_sender() {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = sock.local_addr().unwrap().port();
    drop(sock); // Release the port so recv_from binds a fresh one.

    let start  = std::time::Instant::now();
    let result = run(&format!(r#"internal_udp_recv({}, 200)"#, port));
    let elapsed = start.elapsed().as_millis();
    assert!(elapsed < 3000, "udp_recv timeout should fire quickly: took {}ms", elapsed);
    // Result is either an error (bind failed on released port) or the timeout string.
    let _ = result; // any non-panic outcome is acceptable
}

// ─────────────────────────────────────────────────────────────────────────────
// scripting/network.rs  — http_get (external, skip if offline)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn http_get_external_url_contains_expected_json_field() {
    let result = run(r#"internal_http_get("https://httpbin.org/get")"#);
    if result.starts_with("Error") || result.starts_with("Request") {
        eprintln!("[SKIP] No network or httpbin unavailable: {}", result);
        return;
    }
    assert!(result.contains("\"url\""),
        "httpbin /get response should contain url field: {:.200}", result);
}

#[test]
fn http_post_sends_body() {
    let result = run(r#"internal_http_post("https://httpbin.org/post", "hello_body", "text/plain")"#);
    if result.starts_with("Error") || result.starts_with("Request") {
        eprintln!("[SKIP] No network: {}", result);
        return;
    }
    assert!(result.contains("hello_body"),
        "httpbin /post should echo body: {:.300}", result);
}

#[test]
fn http_get_invalid_url_returns_error() {
    let result = run(r#"internal_http_get("not-a-url")"#);
    assert!(result.starts_with("Error") || result.starts_with("Request"),
        "invalid URL should return an error: {}", result);
}

// ─────────────────────────────────────────────────────────────────────────────
// scripting/network.rs  — exec_detach
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn exec_detach_returns_numeric_pid() {
    #[cfg(not(target_os = "windows"))]
    let script = r#"internal_exec_detach("true")"#;
    #[cfg(target_os = "windows")]
    let script = r#"internal_exec_detach("cmd /c exit 0")"#;

    let result = run(script);
    // "Detached" (Linux) or a PID string (Windows) are both valid.
    assert!(
        result.trim() == "Detached" || result.parse::<u32>().is_ok(),
        "exec_detach should return 'Detached' or a PID: {}", result
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// scripting/evasion.rs  — mutex create / exists / release
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn evasion_mutex_create_first_call_true() {
    let name = format!("rcm_test_mutex_{}", uuid::Uuid::new_v4());
    let script_create = format!(r#"internal_mutex_create("{}")"#, name);
    let script_release = format!(r#"internal_mutex_release("{}")"#, name);

    let first = run(&script_create);
    assert_eq!(first.trim(), "true",
        "first create should return true (newly created): {}", first);
    run(&script_release); // cleanup
}

#[test]
fn evasion_mutex_exists_true_after_create() {
    let name = format!("rcm_test_mutex_{}", uuid::Uuid::new_v4());
    run(&format!(r#"internal_mutex_create("{}")"#, name));
    let exists = run(&format!(r#"internal_mutex_exists("{}")"#, name));
    assert_eq!(exists.trim(), "true",
        "mutex should exist after creation: {}", exists);
    run(&format!(r#"internal_mutex_release("{}")"#, name));
}

#[test]
fn evasion_mutex_release_removes_mutex() {
    let name = format!("rcm_test_mutex_{}", uuid::Uuid::new_v4());
    run(&format!(r#"internal_mutex_create("{}")"#, name));
    let release = run(&format!(r#"internal_mutex_release("{}")"#, name));
    assert!(release.contains("Released"), "release should confirm: {}", release);
    let exists = run(&format!(r#"internal_mutex_exists("{}")"#, name));
    assert_eq!(exists.trim(), "false",
        "mutex should not exist after release: {}", exists);
}

#[test]
fn evasion_mutex_second_create_returns_false() {
    // Two separate engines both try to create the same mutex.
    // The first wins; the second sees it already exists.
    let name = format!("rcm_test_mutex_{}", uuid::Uuid::new_v4());
    let mut em1 = ExtensionManager::new();
    let mut em2 = ExtensionManager::new();
    let first  = em1.run_script(&format!(r#"internal_mutex_create("{}")"#, name), vec![]);
    let second = em2.run_script(&format!(r#"internal_mutex_create("{}")"#, name), vec![]);
    assert_eq!(first.trim(), "true", "first engine should win: {}", first);
    assert_eq!(second.trim(), "false", "second engine should find it exists: {}", second);
    em1.run_script(&format!(r#"internal_mutex_release("{}")"#, name), vec![]);
}

#[test]
fn evasion_timing_check_returns_bool() {
    // Don't assert the value (could be a sandbox or slow CI). Just verify no panic.
    let result = run(r#"internal_timing_check()"#);
    assert!(
        result.trim() == "true" || result.trim() == "false",
        "timing_check should return a bool string: {}", result
    );
}

#[test]
fn evasion_av_detect_returns_json_array() {
    let json = run(r#"internal_av_detect()"#);
    let v: serde_json::Value = serde_json::from_str(&json)
        .expect("av_detect should return JSON: {json}");
    assert!(v.is_array(), "av_detect should return a JSON array");
}

#[test]
fn evasion_vm_detect_returns_bool() {
    let result = run(r#"internal_vm_detect()"#);
    assert!(
        result.trim() == "true" || result.trim() == "false",
        "vm_detect should return a bool string: {}", result
    );
}

#[test]
fn evasion_debugger_detect_false_in_ci() {
    let result = run(r#"internal_debugger_detect()"#);
    assert!(
        result.trim() == "true" || result.trim() == "false",
        "debugger_detect should return a bool string: {}", result
    );
    // In standard CI there is no debugger.
    if std::env::var("CI").is_ok() {
        assert_eq!(result.trim(), "false",
            "no debugger should be attached in CI: {}", result);
    }
}
