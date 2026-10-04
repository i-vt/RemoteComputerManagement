// tests/test_pivot.rs - Pivot listener error honesty
//
// start_agent_listener / start_named_pipe_listener return Result so the
// handlers can put failures on the error channel with a non-zero exit
// code; before, bind failures and the non-Windows SMB stub came back as
// success-looking strings with exit 0.

use rcm::agent::pivot::PivotManager;
use tokio::sync::mpsc;

#[cfg(not(target_os = "windows"))]
#[tokio::test]
async fn smb_listener_is_err_on_non_windows() {
    let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
    let mgr = PivotManager::new(tx);
    let res = mgr.start_named_pipe_listener("rcm_test_pipe".into()).await;
    assert!(res.is_err(), "named pipes are Windows-only; must return Err");
}

#[tokio::test]
async fn tcp_listener_bind_failure_is_err() {
    let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
    let mgr = PivotManager::new(tx);

 // Occupy a port so the pivot listener's own bind must fail.
    let blocker = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = blocker.local_addr().unwrap().port();

    let res = mgr.start_agent_listener(port).await;
    assert!(res.is_err(), "binding an in-use port must return Err");
    drop(blocker);
}

#[tokio::test]
async fn tcp_listener_start_reports_ok() {
    let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
    let mgr = PivotManager::new(tx);

 // Port 0 lets the OS pick a free ephemeral port.
    let res = mgr.start_agent_listener(0).await;
    assert!(res.is_ok(), "free port should start: {:?}", res.err());
}

// ── Wave 3 additions : frame codec + link-id allocator ─────────

use rcm::common::PivotFrame;
use tokio::io::AsyncReadExt;
use tokio::time::{timeout, Duration};

const WAIT: Duration = Duration::from_secs(10);

fn frame(id: u32) -> PivotFrame {
    PivotFrame {
        stream_id: id,
        destination: 7,
        source: id,
        data: b"\xde\xad\xbe\xef".to_vec(),
        metadata: "tcp:127.0.0.1:9000".into(),
    }
}

#[test]
fn pivot_frame_serde_roundtrip() {
    let f = frame(42);
    let bytes = serde_json::to_vec(&f).unwrap();
    let back: PivotFrame = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(back.stream_id, 42);
    assert_eq!(back.destination, 7);
    assert_eq!(back.source, 42);
    assert_eq!(back.data, b"\xde\xad\xbe\xef");
    assert_eq!(back.metadata, "tcp:127.0.0.1:9000");
}

#[test]
fn pivot_frame_decode_rejects_garbage() {
 // Not JSON at all.
    assert!(serde_json::from_slice::<PivotFrame>(b"not a frame").is_err());
 // Truncated sequence (missing fields).
    assert!(serde_json::from_slice::<PivotFrame>(b"[1, 2]").is_err());
 // Wrong field types (stream_id as string).
    assert!(serde_json::from_slice::<PivotFrame>(
        br#"["abc", 1, 1, [], ""]"#
    )
    .is_err());
}

/// Find a currently-free TCP port by binding then releasing. Small race
/// window, standard practice for listener tests.
// Probe-then-bind races with parallel tests grabbing the same ephemeral
// port (the bind is eager, so the loser gets EADDRINUSE); retry until the
// listener's bind actually lands.
async fn start_free_listener(mgr: &PivotManager) -> u16 {
    for _ in 0..16 {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        if mgr.start_agent_listener(port).await.is_ok() {
            return port;
        }
    }
    panic!("no free ephemeral port after retries");
}

#[tokio::test]
async fn init_frames_carry_peer_metadata_and_monotonic_link_ids() {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(16);
    let mgr = PivotManager::new(tx);

    let port = start_free_listener(&mgr).await;

 // Two sequential TCP connections get sequential link ids.
    let mut c1 = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let b1 = timeout(WAIT, rx.recv()).await.unwrap().unwrap();
    let f1: PivotFrame = serde_json::from_slice(&b1).unwrap();
    assert_eq!(f1.stream_id, 5000, "first link id starts at 5000");
    assert_eq!(f1.source, 5000);
    assert_eq!(f1.destination, 0, "init frames target the server");
    assert!(f1.data.is_empty());
    assert!(f1.metadata.starts_with("127.0.0.1:"), "peer addr in metadata: {}", f1.metadata);

    let mut c2 = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let b2 = timeout(WAIT, rx.recv()).await.unwrap().unwrap();
    let f2: PivotFrame = serde_json::from_slice(&b2).unwrap();
    assert_eq!(f2.stream_id, 5001, "allocator is monotonic within a listener");

 // Bytes written by the client arrive upstream as data frames on the
 // same link id.
    use tokio::io::AsyncWriteExt;
    c1.write_all(b"abc").await.unwrap();
    let b3 = timeout(WAIT, rx.recv()).await.unwrap().unwrap();
    let f3: PivotFrame = serde_json::from_slice(&b3).unwrap();
    assert_eq!(f3.stream_id, 5000);
    assert_eq!(f3.data, b"abc");

 // A second listener keeps counting where the first left off: the
 // allocator is manager-global, not per-listener.
    let port2 = start_free_listener(&mgr).await;
    let mut c3 = tokio::net::TcpStream::connect(("127.0.0.1", port2)).await.unwrap();
    let b4 = timeout(WAIT, rx.recv()).await.unwrap().unwrap();
    let f4: PivotFrame = serde_json::from_slice(&b4).unwrap();
    assert_eq!(f4.stream_id, 5002, "allocator is monotonic across listeners");

    drop((c1, c2, c3));
}

#[tokio::test]
async fn downstream_frame_to_unknown_destination_is_tolerated() {
    let (tx, _rx) = mpsc::channel::<Vec<u8>>(8);
    let mgr = PivotManager::new(tx);
 // No links registered: this must be a silent no-op, not a panic.
    mgr.handle_downstream_frame(frame(999_999));
    mgr.handle_downstream_frame(PivotFrame {
        stream_id: 1, destination: 0, source: 1, data: vec![], metadata: String::new(),
    });
}
