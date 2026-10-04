// tests/test_w2_agent.rs - Wave 2 agent behavior tests
//
// Covers: (quoted ext:load args), (result Outbox bounds),
// (pivot listener ids, list/stop), (Rhai engine limits).
// (sleep clamp) is covered by the in-file tests in
// src/agent/handlers/config.rs: DispatchResult is pub(crate), so
// handle_sleep cannot be asserted from an integration test.

use rcm::agent::handlers::execution::split_shell_args;
use rcm::agent::http_transport::{Outbox, OUTBOX_MAX_ENTRIES, OUTBOX_MAX_ATTEMPTS};
use rcm::agent::pivot::PivotManager;
use rcm::common::CommandResponse;

fn resp(id: u64, out: &str) -> CommandResponse {
    CommandResponse { request_id: id, output: out.to_string(), error: String::new(), exit_code: 0 }
}

// ── : quoted argument parsing ───────────────────────────────────────

#[test]
fn split_shell_args_plain() {
    assert_eq!(split_shell_args("ext:load QkJD arg2"), vec!["ext:load", "QkJD", "arg2"]);
}

#[test]
fn split_shell_args_quoted_segments() {
    let v = split_shell_args("ext:load QkJD \"arg one\" arg2");
    assert_eq!(v, vec!["ext:load", "QkJD", "arg one", "arg2"]);
}

#[test]
fn split_shell_args_escaped_quote_inside_quotes() {
    let v = split_shell_args("cmd \"say \\\"hi\\\" now\" tail");
    assert_eq!(v, vec!["cmd", "say \"hi\" now", "tail"]);
}

#[test]
fn split_shell_args_multiple_spaces_and_empty_quotes() {
    let v = split_shell_args("a    b   \"\"");
    assert_eq!(v, vec!["a", "b"]);
}

// ── : Outbox bounds and attempt budget ─────────────────────────

#[test]
fn outbox_drop_oldest_on_entry_bound() {
    let mut o = Outbox::new();
    for i in 0..(OUTBOX_MAX_ENTRIES as u64 + 5) {
        o.push(resp(i, "x"), false);
    }
    assert_eq!(o.len(), OUTBOX_MAX_ENTRIES);
 // Oldest (id 0..5) were evicted; front is id 5.
    assert_eq!(o.front().unwrap().request_id, 5);
}

#[test]
fn outbox_drop_oldest_on_byte_bound() {
    let mut o = Outbox::new();
    let big = "A".repeat(600_000); // ~600 KB per entry, 1 MiB bound
    for i in 0..4 {
        o.push(resp(i, &big), false);
    }
    assert!(o.len() < 4, "byte bound must evict older entries");
    assert!(o.len() >= 1);
}

#[test]
fn outbox_attempt_budget_drops_poison_entry() {
    let mut o = Outbox::new();
    o.push(resp(1, "a"), false);
    o.push(resp(2, "b"), false);
    for _ in 0..OUTBOX_MAX_ATTEMPTS {
        o.note_send_failure(false);
    }
 // First entry exhausted its budget and was dropped; second is now front.
    assert_eq!(o.len(), 1);
    assert_eq!(o.front().unwrap().request_id, 2);
}

#[test]
fn outbox_pop_tracks_bytes() {
    let mut o = Outbox::new();
    o.push(resp(1, &"B".repeat(700_000)), false);
    o.push(resp(2, &"B".repeat(700_000)), false);
 // First push must have been evicted by the byte bound already.
    assert_eq!(o.len(), 1);
    o.pop();
    assert_eq!(o.len(), 0);
 // And the queue accepts new entries after draining.
    o.push(resp(3, "small"), false);
    assert_eq!(o.len(), 1);
}

// ── : pivot listener ids, list, stop ───────────────────────────

#[tokio::test]
async fn pivot_listener_lifecycle() {
    let (tx, _rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let mgr = PivotManager::new(tx);

    assert!(mgr.list_listeners().is_empty());

    let msg = mgr.start_agent_listener(0).await.expect("bind ephemeral");
    assert!(msg.contains("listener id"), "reply should carry the listener id: {}", msg);

    let listed = mgr.list_listeners();
    assert_eq!(listed.len(), 1);
    let (id, desc, links) = &listed[0];
    assert!(desc.starts_with("tcp:"), "desc was: {}", desc);
    assert_eq!(*links, 0);

    mgr.stop_listener(*id).await.expect("stop must succeed");
    assert!(mgr.list_listeners().is_empty());

 // Unknown ids fail honestly.
    assert!(mgr.stop_listener(9999).await.is_err());
}

#[tokio::test]
async fn pivot_link_ids_are_monotonic_across_listeners() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let mgr = PivotManager::new(tx);

    // Probe-then-bind races with parallel tests grabbing the same
    // ephemeral port (the bind is eager, so the loser gets EADDRINUSE);
    // retry until each listener's bind actually lands.
    async fn start_free(mgr: &PivotManager) -> u16 {
        for _ in 0..16 {
            let p = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
            if mgr.start_agent_listener(p).await.is_ok() {
                return p;
            }
        }
        panic!("no free ephemeral port after retries");
    }
    let p1 = start_free(&mgr).await;
    let p2 = start_free(&mgr).await;

 // Connect one downstream to each listener; the init frames carry the
 // allocated link ids, which must be distinct across both listeners.
    let _c1 = tokio::net::TcpStream::connect(("127.0.0.1", p1)).await.unwrap();
    let _c2 = tokio::net::TcpStream::connect(("127.0.0.1", p2)).await.unwrap();

    let mut ids = Vec::new();
    for _ in 0..2 {
        let data = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await.expect("init frame expected").expect("channel open");
        let v: serde_json::Value = serde_json::from_slice(&data).unwrap();
        ids.push(v.as_array().unwrap()[0].as_u64().unwrap() as u32);
    }
    assert_ne!(ids[0], ids[1], "link ids from different listeners collided");
}

// ── : Rhai engine limits ────────────────────────────────────────────

#[test]
fn script_runs_normally_under_limits() {
    let mut mgr = rcm::agent::scripting::ExtensionManager::new();
    let out = mgr.run_script(r#""he" + "llo""#, vec![]);
    assert_eq!(out, "hello");
}

#[test]
fn runaway_script_is_aborted_not_wedged() {
    let mut mgr = rcm::agent::scripting::ExtensionManager::new();
    let start = std::time::Instant::now();
    let out = mgr.run_script("for i in 0..1_000_000_000 { let x = i * 2; }", vec![]);
    assert!(out.contains("Aborted") || out.contains("Exception"),
        "runaway script must surface as a script error, got: {}", out);
    assert!(start.elapsed() < std::time::Duration::from_secs(120),
        "the engine limits must bound runtime well under the old hang");

 // The subsystem survives: another script still runs afterwards.
    let out2 = mgr.run_script(r#""alive""#, vec![]);
    assert_eq!(out2, "alive");
}

// ── Wave 3 additions : Outbox FIFO/edge cases ───────────────────

#[test]
fn outbox_fifo_order_and_empty_guards() {
    use rcm::agent::http_transport::Outbox;
    let mut ob = Outbox::new();
 // Empty-queue operations must be no-ops, not panics.
    assert!(ob.front().is_none());
    ob.pop();
    ob.note_send_failure(false);

    for i in 1..=4u64 {
        ob.push(resp(i, &format!("r{}", i)), false);
    }
 // front() is stable across peeks; pop() advances in FIFO order.
    for expected in 1..=4u64 {
        assert_eq!(ob.front().unwrap().request_id, expected);
        assert_eq!(ob.front().unwrap().request_id, expected, "front must not advance");
        ob.pop();
    }
    assert!(ob.front().is_none(), "drained queue must be empty");
}

#[test]
fn outbox_attempt_budget_keeps_entry_until_ten_failures() {
    use rcm::agent::http_transport::Outbox;
    let mut ob = Outbox::new();
    ob.push(resp(1, "sticky"), false);
 // Nine failures: still queued.
    for _ in 0..9 {
        ob.note_send_failure(false);
        assert_eq!(ob.front().unwrap().request_id, 1, "entry must survive 9 failures");
    }
 // The tenth failure drops it.
    ob.note_send_failure(false);
    assert!(ob.front().is_none(), "entry must be dropped at the attempt budget");
 // A failure on an empty queue afterwards is still a no-op.
    ob.note_send_failure(false);
}
