use rcm::common::{
    session_command_channel, try_send_session_command, CommandResponse, MalleableProfile,
    PivotFrame, Session, SessionTransport, TransformStep,
};
use rcm::database::{self, DbPool};
use rcm::server::http_listener::HttpC2State;
use rcm::server::session::parse_pivot_close_frame;
use rcm::traffic::DataMolder;

use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

fn temp_db() -> DbPool {
    let path = format!("/tmp/rcm_w2_{}.db", uuid::Uuid::new_v4());
    let manager = r2d2_sqlite::SqliteConnectionManager::file(&path)
        .with_init(|c| c.execute_batch("PRAGMA busy_timeout = 5000;"));
    let pool = r2d2::Pool::builder().max_size(2).build(manager).unwrap();
    pool.get().unwrap().execute_batch(
        "CREATE TABLE session_id_seq (id INTEGER PRIMARY KEY CHECK (id = 1), next_id INTEGER NOT NULL DEFAULT 1);
         INSERT INTO session_id_seq (id,next_id) VALUES (1,1);
         CREATE TABLE sessions (
            id INTEGER PRIMARY KEY, session_uuid TEXT, exe_id TEXT, computer_id TEXT,
            hostname TEXT, os TEXT, ip_address TEXT, build_id TEXT, connected_at TEXT,
            is_active INTEGER DEFAULT 0, profile TEXT DEFAULT 'default'
         );
         CREATE TABLE command_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER, request_id INTEGER,
            command TEXT, timestamp TEXT
         );
         CREATE TABLE queued_tasks (
            task_id TEXT PRIMARY KEY, session_id INTEGER NOT NULL, command TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL,
            claimed_at INTEGER, result TEXT, error TEXT, finished_at INTEGER
         );"
    ).unwrap();
    pool
}

fn response() -> CommandResponse {
    CommandResponse { request_id: 1, output: "ok".into(), error: String::new(), exit_code: 0 }
}

fn http_session(id: u32) -> Session {
    let (tx, _rx) = session_command_channel(2);
    Session {
        id,
        transport: SessionTransport::Http,
        computer_id: "machine-a".into(),
        addr: "127.0.0.1:4444".parse().unwrap(),
        hostname: "host-a".into(),
        os: "linux".into(),
        tx,
        signing_key: ed25519_dalek::SigningKey::from_bytes(&[id as u8; 32]),
        parent_id: None,
        last_seen: Arc::new(std::sync::atomic::AtomicI64::new(0)),
        interfaces: Vec::new(),
        hibernation_mode: false,
    }
}

#[test]
fn hibernation_claim_complete_and_fail_lifecycle() {
    let pool = temp_db();
    let conn = pool.get().unwrap();
    let first = database::queue_task(&conn, 7, "whoami").unwrap();
    let second = database::queue_task(&conn, 7, "id").unwrap();

    let claimed = database::poll_and_claim_tasks(&conn, 7, 1);
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].task_id, first);

    database::requeue_task(&conn, &first);
    let reclaimed = database::poll_and_claim_tasks(&conn, 7, 1);
    assert_eq!(reclaimed.len(), 1);
    assert_eq!(reclaimed[0].task_id, first);
    database::complete_task(&conn, &first, "done");

    let status: String = conn.query_row(
        "SELECT status FROM queued_tasks WHERE task_id = ?1", [first], |row| row.get(0)
    ).unwrap();
    assert_eq!(status, "completed");

    let claimed = database::poll_and_claim_tasks(&conn, 7, 10);
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].task_id, second);
    conn.execute("UPDATE queued_tasks SET claimed_at = 0 WHERE task_id = ?1", [&second]).unwrap();
    assert_eq!(database::fail_stale_running_tasks(&conn, 3600), 1);
    database::fail_task(&conn, &second, "agent error");
    let status: String = conn.query_row(
        "SELECT status FROM queued_tasks WHERE task_id = ?1", [second], |row| row.get(0)
    ).unwrap();
    assert_eq!(status, "failed");

    database::log_command(&conn, 7, 42, "whoami");
    assert_eq!(database::max_command_request_id(&conn, 7), 42);
}

#[test]
fn bounded_session_channel_rejects_when_full_and_recovers() {
    let (tx, mut rx) = session_command_channel(1);
    assert!(try_send_session_command(3, &tx, "one".into(), None));
    assert!(!try_send_session_command(3, &tx, "two".into(), None));
    let (command, _) = rx.try_recv().unwrap();
    assert_eq!(command, "one");
    assert!(try_send_session_command(3, &tx, "three".into(), None));
}

#[test]
fn command_history_redacts_extension_and_module_arguments() {
    assert_eq!(
        database::redact_command_for_history("ext:load secret key=abc123"),
        "ext:load <args redacted>"
    );
    assert_eq!(
        database::redact_command_for_history("module:recon secret key=abc123"),
        "module:recon <args redacted>"
    );
    assert_eq!(
        database::redact_command_for_history("module:recon"),
        "module:recon"
    );
    assert_eq!(database::redact_command_for_history("whoami"), "whoami");
}

#[test]
fn pivot_close_frame_parser_matches_agent_wire_contract() {
    let close = PivotFrame {
        stream_id: 5001,
        destination: 0,
        source: 5001,
        data: Vec::new(),
        metadata: "CLOSE".into(),
    };
    assert_eq!(parse_pivot_close_frame(&close), Some(5001));

    let data_close = PivotFrame { data: b"x".to_vec(), ..close.clone() };
    assert_eq!(parse_pivot_close_frame(&data_close), None);
    let reverse_close = PivotFrame { destination: 5001, ..close };
    assert_eq!(parse_pivot_close_frame(&reverse_close), None);
}

#[tokio::test]
async fn profile_wrapped_challenge_response_decodes_with_active_profile() {
    let mut profile = MalleableProfile::default();
    profile.format_http = true;
    profile.http_post.data_transform = vec![TransformStep::Base64];
    let (mut agent, mut server) = tokio::io::duplex(8192);
    let challenge = b"challenge-response".to_vec();

    DataMolder::send(&mut agent, &challenge, &profile).await.unwrap();
    let decoded = DataMolder::recv(&mut server, &profile).await.unwrap();
    assert_eq!(decoded, challenge);
}

#[test]
fn http_reregistration_reuses_session_id_and_preserves_history() {
    let pool = temp_db();
    let conn = pool.get().unwrap();
    let original = database::register_session(
        &conn, "exe", "machine-a", "host-a", "linux", "10.0.0.2", "build", "default"
    ).unwrap();
    database::log_command(&conn, original, 4, "whoami");

    let candidates = database::find_machine_session_ids(&conn, "machine-a", "host-a");
    assert_eq!(candidates, vec![original]);
    database::reregister_session(
        &conn, original, "exe2", "machine-a", "host-a", "linux", "10.0.0.3", "build2", "default"
    ).unwrap();

    let history: i64 = conn.query_row(
        "SELECT COUNT(*) FROM command_history WHERE session_id = ?1", [original], |row| row.get(0)
    ).unwrap();
    let exe: String = conn.query_row(
        "SELECT exe_id FROM sessions WHERE id = ?1", [original], |row| row.get(0)
    ).unwrap();
    assert_eq!(history, 1);
    assert_eq!(exe, "exe2");
}

#[test]
fn http_reregistration_evicts_stale_http_token_but_not_tls() {
    let sessions = Arc::new(DashMap::new());
    let state = Arc::new(HttpC2State::new(
        sessions.clone(),
        temp_db(),
        Arc::new(Mutex::new(HashMap::new())),
    ));
    sessions.insert(5, http_session(5));
    let mut tls = http_session(6);
    tls.transport = SessionTransport::Tls;
    sessions.insert(6, tls);
    sessions.insert(7, http_session(7));
    state.inner.lock().unwrap().token_map.insert("old".into(), 5);
    state.inner.lock().unwrap().token_map.insert("tls-token".into(), 6);

    assert_eq!(state.evict_reregistration_candidates(&[5, 6, 7]), Some(5));
    assert!(!sessions.contains_key(&5));
    assert!(sessions.contains_key(&6));
    assert!(sessions.contains_key(&7));
    let inner = state.inner.lock().unwrap();
    assert!(!inner.token_map.contains_key("old"));
    assert!(inner.token_map.contains_key("tls-token"));
}
