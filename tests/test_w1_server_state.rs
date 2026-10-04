use rcm::api::state::{
    insert_result, sweep_expired_results, StoredResult, MAX_RESULTS_PER_SESSION,
};
use rcm::api::SharedResults;
use rcm::common::{CommandResponse, Session, SessionTransport, SharedSessions};
use rcm::database::DbPool;
use rcm::server::http_listener::{self, HttpC2State};

use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn temp_db() -> DbPool {
    let path = format!("/tmp/rcm_w1_state_{}.db", uuid::Uuid::new_v4());
    let manager = r2d2_sqlite::SqliteConnectionManager::file(&path)
        .with_init(|c| c.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = 5000;"
        ));
    let pool = r2d2::Pool::builder().max_size(2).build(manager).unwrap();
    pool.get().unwrap().execute_batch(
        "CREATE TABLE sessions (
            id INTEGER PRIMARY KEY,
            session_uuid TEXT,
            exe_id TEXT,
            computer_id TEXT,
            hostname TEXT,
            os TEXT,
            ip_address TEXT,
            build_id TEXT,
            connected_at TEXT,
            is_active INTEGER DEFAULT 0,
            profile TEXT DEFAULT 'default'
         );
         CREATE TABLE command_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            request_id INTEGER,
            command TEXT,
            timestamp TEXT,
            FOREIGN KEY(session_id) REFERENCES sessions(id)
         );
         CREATE TABLE listeners (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            port INTEGER NOT NULL,
            transport TEXT NOT NULL DEFAULT 'tls',
            profile_json TEXT,
            auto_start INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
         );"
    ).unwrap();
    pool
}

fn results() -> SharedResults {
    Arc::new(Mutex::new(HashMap::new()))
}

fn response(request_id: u64) -> CommandResponse {
    CommandResponse {
        request_id,
        output: "ok".to_string(),
        error: String::new(),
        exit_code: 0,
    }
}

fn session(id: u32, transport: SessionTransport, last_seen: i64) -> Session {
    let (tx, _rx) = rcm::common::session_command_channel(2);
    Session {
        id,
        transport,
        computer_id: format!("computer-{}", id),
        addr: "127.0.0.1:4444".parse().unwrap(),
        hostname: format!("host-{}", id),
        os: "linux".to_string(),
        tx,
        signing_key: ed25519_dalek::SigningKey::from_bytes(&[id as u8; 32]),
        parent_id: None,
        last_seen: Arc::new(std::sync::atomic::AtomicI64::new(last_seen)),
        interfaces: Vec::new(),
        hibernation_mode: false,
    }
}

#[test]
fn shared_results_enforce_per_session_cap() {
    let results = results();
    for request_id in 0..(MAX_RESULTS_PER_SESSION + 2) as u64 {
        insert_result(&results, 7, request_id, response(request_id));
    }

    let map = results.lock().unwrap();
    assert_eq!(map.len(), MAX_RESULTS_PER_SESSION);
    assert!(!map.contains_key(&(7, 0)));
    assert!(!map.contains_key(&(7, 1)));
    assert!(map.contains_key(&(7, (MAX_RESULTS_PER_SESSION + 1) as u64)));
}

#[test]
fn shared_results_ttl_sweep_removes_old_entries() {
    let results = results();
    results.lock().unwrap().insert((7, 1), StoredResult {
        response: response(1),
        inserted_at: Instant::now() - Duration::from_secs(120),
        sequence: 1,
    });
    insert_result(&results, 7, 2, response(2));

    assert_eq!(sweep_expired_results(&results, Duration::from_secs(60)), 1);
    let map = results.lock().unwrap();
    assert!(!map.contains_key(&(7, 1)));
    assert!(map.contains_key(&(7, 2)));
}

#[test]
fn http_prune_removes_only_stale_http_sessions() {
    let pool = temp_db();
    let sessions: SharedSessions = Arc::new(DashMap::new());
    let state = Arc::new(HttpC2State::new(sessions.clone(), pool, results()));
    let old = chrono::Utc::now().timestamp() - 3600;
    sessions.insert(1, session(1, SessionTransport::Http, old));
    sessions.insert(2, session(2, SessionTransport::Tls, old));
    sessions.insert(3, session(3, SessionTransport::Http, old));

    {
        let mut inner = state.inner.lock().unwrap();
        inner.token_map.insert("http-token".to_string(), 1);
        inner.signing_keys.insert(1, ed25519_dalek::SigningKey::from_bytes(&[1; 32]));
        inner.counters.insert(1, 0);
        inner.cmd_queues.insert(1, Default::default());
    }

    state.prune_stale_sessions(60);
    assert!(!sessions.contains_key(&1));
    assert!(sessions.contains_key(&2));
    assert!(sessions.contains_key(&3), "another listener's HTTP session must survive");
    let inner = state.inner.lock().unwrap();
    assert!(!inner.token_map.contains_key("http-token"));
    assert!(!inner.signing_keys.contains_key(&1));
}

#[test]
fn http_listener_bind_failure_is_returned_before_spawn() {
    let blocker = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = blocker.local_addr().unwrap().port();
    let sessions: SharedSessions = Arc::new(DashMap::new());
    let state = Arc::new(HttpC2State::new(sessions, temp_db(), results()));

    assert!(http_listener::start(state, port, false, &[], &[]).is_err());
}

#[tokio::test]
async fn listener_manager_propagates_http_bind_failure_and_rolls_back_row() {
    let blocker = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = blocker.local_addr().unwrap().port();
    let pool = temp_db();
    let sessions: SharedSessions = Arc::new(DashMap::new());
    let mut manager = rcm::server::listeners::ListenerManager::new(
        pool.clone(),
        sessions,
        results(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );

    let err = manager.create_and_start("blocked", port, "http", None).await.unwrap_err();
    assert!(err.contains("bind failed"), "unexpected error: {}", err);
    let rows: i64 = pool.get().unwrap().query_row(
        "SELECT COUNT(*) FROM listeners",
        [],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(rows, 0);
}

#[tokio::test]
async fn http_queue_command_logs_joinable_request_id() {
    let pool = temp_db();
    {
        let conn = pool.get().unwrap();
        conn.execute(
            "INSERT INTO sessions (id, exe_id, computer_id, hostname, os, ip_address, build_id, connected_at)
             VALUES (9, 'exe', 'computer', 'host', 'linux', '127.0.0.1', 'build', 'now')",
            [],
        ).unwrap();
    }

    let sessions: SharedSessions = Arc::new(DashMap::new());
    let state = Arc::new(HttpC2State::new(sessions, pool.clone(), results()));
    state.inner.lock().unwrap().signing_keys.insert(
        9,
        ed25519_dalek::SigningKey::from_bytes(&[9; 32]),
    );

    assert_eq!(state.queue_command(9, "whoami".to_string()), 1);
    assert_eq!(state.queue_command(9, "id".to_string()), 2);

    let mut rows = Vec::new();
    for _ in 0..50 {
        rows = {
            let conn = pool.get().unwrap();
            let mut stmt = conn.prepare(
                "SELECT request_id, command FROM command_history WHERE session_id = 9 ORDER BY request_id"
            ).unwrap();
            stmt.query_map([], |row| Ok((row.get::<_, u64>(0)?, row.get::<_, String>(1)?)))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        };
        if rows.len() == 2 { break; }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert_eq!(rows, vec![(1, "whoami".to_string()), (2, "id".to_string())]);
}
