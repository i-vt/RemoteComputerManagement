// tests/test_database.rs — Database CRUD integration tests
// Uses a temporary SQLite file per test for isolation.

use rcm::database;

fn temp_db() -> database::DbPool {
    let path = format!("/tmp/rcm_test_{}.db", uuid::Uuid::new_v4());
    let manager = r2d2_sqlite::SqliteConnectionManager::file(&path)
        .with_init(|c| c.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = 5000;"
        ));
    let pool = r2d2::Pool::builder().max_size(2).build(manager).unwrap();

    // Initialise schema inline (database_schema.sql is not shipped to tests/)
    let conn = pool.get().unwrap();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS operators (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'operator',
            api_key TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL, last_login TEXT
         );
         CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, operator_id INTEGER,
            operator_name TEXT, action TEXT NOT NULL, target_session INTEGER,
            details TEXT, timestamp TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS auto_recon (
            id INTEGER PRIMARY KEY AUTOINCREMENT, command TEXT NOT NULL,
            sort_order INTEGER NOT NULL DEFAULT 0
         );
         CREATE TABLE IF NOT EXISTS session_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER NOT NULL,
            tag TEXT, note TEXT NOT NULL, operator TEXT NOT NULL, timestamp TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS listeners (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
            port INTEGER NOT NULL, transport TEXT NOT NULL DEFAULT 'tls',
            profile_json TEXT, auto_start INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS session_id_seq (
            id INTEGER PRIMARY KEY CHECK (id = 1), next_id INTEGER NOT NULL DEFAULT 1
         );
         INSERT OR IGNORE INTO session_id_seq (id, next_id) VALUES (1, 1);
         CREATE TABLE IF NOT EXISTS server_config (key TEXT PRIMARY KEY, value BLOB);
         CREATE TABLE IF NOT EXISTS queued_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER NOT NULL,
            command TEXT NOT NULL, queued_at TEXT NOT NULL, claimed_at TEXT,
            completed_at TEXT, output TEXT, error TEXT
         );"
    ).unwrap();

    pool
}

#[test]
fn test_operator_crud() {
    let pool = temp_db();
    let conn = pool.get().unwrap();

    let id = database::create_operator(&conn, "alice", "hash123", "admin", "key-alice").unwrap();
    assert!(id > 0);

    let op = database::get_operator_by_key(&conn, "key-alice").unwrap();
    assert_eq!(op.username, "alice");
    assert_eq!(op.role, "admin");

    // api_key is stored as a hash, so don't compare the raw value.
    // Verify round-trip: the plain-text key still resolves to this operator.
    let op2 = database::get_operator_by_username(&conn, "alice").unwrap();
    assert_eq!(op2.username, "alice");
    assert!(database::get_operator_by_key(&conn, "key-alice").is_some(),
        "hashed api_key should still be findable by the plain-text key");

    let _ = database::create_operator(&conn, "bob", "hash456", "operator", "key-bob").unwrap();
    let ops = database::list_operators(&conn);
    assert_eq!(ops.len(), 2);

    assert_eq!(database::operator_count(&conn), 2);

    assert!(database::delete_operator(&conn, id));
    assert_eq!(database::operator_count(&conn), 1);

    assert!(database::get_operator_by_key(&conn, "nonexistent").is_none());
}

#[test]
fn test_audit_log() {
    let pool = temp_db();
    let conn = pool.get().unwrap();

    database::audit_log(&conn, 1, "admin", "login", None, None);
    database::audit_log(&conn, 1, "admin", "command", Some(5), Some("whoami"));
    database::audit_log(&conn, 2, "bob", "command", Some(3), Some("ipconfig"));

    let log = database::get_audit_log(&conn, 10);
    assert_eq!(log.len(), 3);
    assert_eq!(log[0].operator_name, "bob");
    assert_eq!(log[0].action, "command");
    assert_eq!(log[0].target_session, Some(3));
}

#[test]
fn test_auto_recon() {
    let pool = temp_db();
    let conn = pool.get().unwrap();

    database::add_auto_recon(&conn, "whoami").unwrap();
    database::add_auto_recon(&conn, "hostname").unwrap();
    database::add_auto_recon(&conn, "ipconfig /all").unwrap();

    let commands = database::get_auto_recon(&conn);
    assert_eq!(commands.len(), 3);
    assert_eq!(commands[0], "whoami");
    assert_eq!(commands[2], "ipconfig /all");

    let entries = database::list_auto_recon(&conn);
    assert_eq!(entries.len(), 3);

    database::remove_auto_recon(&conn, entries[1].id);
    let remaining = database::get_auto_recon(&conn);
    assert_eq!(remaining.len(), 2);
    assert_eq!(remaining[0], "whoami");
    assert_eq!(remaining[1], "ipconfig /all");
}

#[test]
fn test_session_notes() {
    let pool = temp_db();
    let conn = pool.get().unwrap();

    database::add_session_note(&conn, 1, Some("da"), "Domain Admin on DC01", "alice").unwrap();
    database::add_session_note(&conn, 1, Some("creds"), "Has CORP\\svc_sql password", "bob").unwrap();
    database::add_session_note(&conn, 1, None, "Initial foothold, don't burn", "alice").unwrap();
    database::add_session_note(&conn, 2, Some("da"), "Also DA", "alice").unwrap();

    let notes = database::get_session_notes(&conn, 1);
    assert_eq!(notes.len(), 3);

    let tags = database::get_session_tags(&conn, 1);
    assert_eq!(tags.len(), 2);
    assert!(tags.contains(&"da".to_string()));
    assert!(tags.contains(&"creds".to_string()));

    // delete_session_note now requires session_id + note_id
    let note_id = notes[0].id;
    assert!(database::delete_session_note(&conn, 1, note_id));
    assert_eq!(database::get_session_notes(&conn, 1).len(), 2);

    assert_eq!(database::get_session_notes(&conn, 2).len(), 1);
}

#[test]
fn test_listeners() {
    let pool = temp_db();
    let conn = pool.get().unwrap();

    let id1 = database::create_listener(&conn, "https_main", 443, "https", None).unwrap();
    let id2 = database::create_listener(&conn, "tls_backup", 4443, "tls", Some("{\"name\":\"test\"}")).unwrap();

    let listeners = database::list_listeners(&conn);
    assert_eq!(listeners.len(), 2);
    assert_eq!(listeners[0].name, "https_main");
    assert_eq!(listeners[0].port, 443);
    assert!(listeners[0].auto_start);

    let l = database::get_listener(&conn, id2).unwrap();
    assert_eq!(l.transport, "tls");
    assert!(l.profile_json.is_some());

    assert!(database::delete_listener(&conn, id1));
    assert_eq!(database::list_listeners(&conn).len(), 1);
}

#[test]
fn test_session_id_allocation() {
    let pool = temp_db();
    let conn = pool.get().unwrap();

    let id1 = database::allocate_session_id(&conn).unwrap();
    let id2 = database::allocate_session_id(&conn).unwrap();
    let id3 = database::allocate_session_id(&conn).unwrap();

    assert_eq!(id2, id1 + 1);
    assert_eq!(id3, id2 + 1);
}

#[test]
fn test_webhook_config() {
    let pool = temp_db();
    let conn = pool.get().unwrap();

    assert!(database::get_webhook_url(&conn).is_none());

    database::set_webhook_url(&conn, "https://hooks.slack.com/test");
    assert_eq!(database::get_webhook_url(&conn).unwrap(), "https://hooks.slack.com/test");

    database::set_webhook_url(&conn, "");
    assert!(database::get_webhook_url(&conn).is_none());
}
