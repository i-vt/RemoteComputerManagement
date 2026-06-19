// src/database.rs
use rusqlite::{Connection, params, OptionalExtension};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use chrono::Utc;
use tracing::{warn, error, info};

pub type DbPool = Pool<SqliteConnectionManager>;

pub struct FullLogEntry {
    pub session_id: u32,
    pub request_id: u64,
    pub command: String,
    pub output: Option<String>,
    pub error: Option<String>,
    pub timestamp: String,
}

pub fn init() -> Result<DbPool, Box<dyn std::error::Error>> {
    let manager = SqliteConnectionManager::file("c2_audit.db")
        .with_init(|c| c.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;
             PRAGMA foreign_keys = ON;"
        ));

    let pool = Pool::builder().max_size(15).build(manager)?;
    let conn = pool.get()?;
    
    // Create Tables
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

         CREATE TABLE IF NOT EXISTS server_config (
            key TEXT PRIMARY KEY,
            value BLOB
         );

         CREATE TABLE IF NOT EXISTS build_keys (
            build_id TEXT PRIMARY KEY,
            private_key BLOB,
            profile TEXT DEFAULT 'default',
            profile_data TEXT,
            challenge_key BLOB
         );

         CREATE TABLE IF NOT EXISTS client_outputs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            request_id INTEGER,
            output TEXT,
            error TEXT,
            timestamp TEXT,
            FOREIGN KEY(session_id) REFERENCES sessions(id)
         );

         CREATE TABLE IF NOT EXISTS command_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            request_id INTEGER,
            command TEXT,
            timestamp TEXT,
            FOREIGN KEY(session_id) REFERENCES sessions(id)
         );

         CREATE INDEX IF NOT EXISTS idx_outputs_req ON client_outputs(request_id);
         CREATE INDEX IF NOT EXISTS idx_cmd_req ON command_history(request_id);
         CREATE INDEX IF NOT EXISTS idx_outputs_timestamp ON client_outputs(timestamp);
         
         CREATE TABLE IF NOT EXISTS session_id_seq (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            next_id INTEGER NOT NULL DEFAULT 1
         );
         INSERT OR IGNORE INTO session_id_seq (id, next_id) VALUES (1, 1);

         CREATE TABLE IF NOT EXISTS operators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'operator',
            api_key TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            last_login TEXT
         );

         CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            operator_id INTEGER,
            operator_name TEXT,
            action TEXT NOT NULL,
            target_session INTEGER,
            details TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY(operator_id) REFERENCES operators(id)
         );
         CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp);

         CREATE TABLE IF NOT EXISTS listeners (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            port INTEGER NOT NULL,
            transport TEXT NOT NULL DEFAULT 'tls',
            profile_json TEXT,
            auto_start INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
         );

         CREATE TABLE IF NOT EXISTS auto_recon (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            command TEXT NOT NULL,
            sort_order INTEGER NOT NULL DEFAULT 0
         );

         CREATE TABLE IF NOT EXISTS session_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            tag TEXT,
            note TEXT NOT NULL,
            operator TEXT NOT NULL,
            timestamp TEXT NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_notes_session ON session_notes(session_id);
         CREATE TABLE IF NOT EXISTS queued_tasks (
            task_id     TEXT PRIMARY KEY,
            session_id  INTEGER NOT NULL,
            command     TEXT NOT NULL,
            status      TEXT NOT NULL DEFAULT 'pending',
            created_at  INTEGER NOT NULL,
            claimed_at  INTEGER,
            result      TEXT,
            error       TEXT,
            finished_at INTEGER
         );
         CREATE INDEX IF NOT EXISTS idx_tasks_session ON queued_tasks(session_id);
         CREATE INDEX IF NOT EXISTS idx_tasks_status  ON queued_tasks(status);"
    )?;

    // Migration for existing DBs
    let count: i32 = conn.query_row(
        "SELECT count(*) FROM pragma_table_info('build_keys') WHERE name='profile_data'", 
        [], 
        |r| r.get(0)
    ).unwrap_or(0);

    if count == 0 {
        if let Err(e) = conn.execute("ALTER TABLE build_keys ADD COLUMN profile_data TEXT", []) {
            warn!("Migration profile_data column: {}", e);
        }
    }

    // Migration: add challenge_key column for handshake authentication
    let ck_count: i32 = conn.query_row(
        "SELECT count(*) FROM pragma_table_info('build_keys') WHERE name='challenge_key'",
        [], |r| r.get(0)
    ).unwrap_or(0);
    if ck_count == 0 {
        if let Err(e) = conn.execute("ALTER TABLE build_keys ADD COLUMN challenge_key BLOB", []) {
            warn!("Migration challenge_key column: {}", e);
        }
    }


    // Migration: add queued_tasks table for hibernation mode
    let task_count: i32 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='queued_tasks'",
        [], |r| r.get(0)
    ).unwrap_or(0);
    if task_count == 0 {
        if let Err(e) = conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS queued_tasks (
                task_id TEXT PRIMARY KEY, session_id INTEGER NOT NULL,
                command TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
                created_at INTEGER NOT NULL, claimed_at INTEGER,
                result TEXT, error TEXT, finished_at INTEGER
             );
             CREATE INDEX IF NOT EXISTS idx_tasks_session ON queued_tasks(session_id);
             CREATE INDEX IF NOT EXISTS idx_tasks_status  ON queued_tasks(status);"
        ) {
            warn!("Migration queued_tasks: {}", e);
        }
    }

    Ok(pool)
}

/// Atomically allocate a session ID that persists across server restarts.
pub fn allocate_session_id(conn: &Connection) -> Result<u32, rusqlite::Error> {
    conn.execute("UPDATE session_id_seq SET next_id = next_id + 1 WHERE id = 1", [])?;
    let id: u32 = conn.query_row(
        "SELECT next_id - 1 FROM session_id_seq WHERE id = 1", [], |r| r.get(0)
    )?;
    Ok(id)
}

// ... (load_or_import_certs remains same) ...
pub fn load_or_import_certs(conn: &Connection) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let cert_blob: Option<Vec<u8>> = conn.query_row(
        "SELECT value FROM server_config WHERE key='server_cert'", [], |row| row.get(0)
    ).optional()?;

    if let Some(c) = cert_blob {
        let k: Vec<u8> = conn.query_row("SELECT value FROM server_config WHERE key='server_key'", [], |row| row.get(0))?;
        let ca: Vec<u8> = conn.query_row("SELECT value FROM server_config WHERE key='ca_cert'", [], |row| row.get(0))?;
        Ok((c, k, ca))
    } else {
        info!("Importing TLS certificates from certs/ directory...");
        let c = std::fs::read("certs/server.crt")?;
        let k = std::fs::read("certs/server.key.der")?;
        let ca = std::fs::read("certs/ca.crt")?;
        
        conn.execute("INSERT OR REPLACE INTO server_config (key, value) VALUES (?1, ?2)", params!["server_cert", &c])?;
        conn.execute("INSERT OR REPLACE INTO server_config (key, value) VALUES (?1, ?2)", params!["server_key", &k])?;
        conn.execute("INSERT OR REPLACE INTO server_config (key, value) VALUES (?1, ?2)", params!["ca_cert", &ca])?;
        Ok((c, k, ca))
    }
}

// [UPDATED] Return profile_data (JSON) as the 3rd element
pub fn get_build_info(conn: &Connection, build_id: &str) -> Option<(Vec<u8>, String, Option<String>, Option<Vec<u8>>)> {
    conn.query_row(
        "SELECT private_key, profile, profile_data, challenge_key FROM build_keys WHERE build_id = ?", 
        [build_id], 
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
    ).optional().unwrap_or(None)
}

pub fn log_new_session(
    conn: &Connection, 
    exe_id: &str, 
    computer_id: &str, 
    hostname: &str, 
    os: &str, 
    ip: &str, 
    build_id: &str,
    profile: &str
) {
    if let Err(e) = conn.execute(
        "INSERT INTO sessions (exe_id, computer_id, hostname, os, ip_address, build_id, connected_at, is_active, profile) 
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8)",
        params![exe_id, computer_id, hostname, os, ip, build_id, Utc::now().to_rfc3339(), profile]
    ) {
        error!("Failed to log new session for {}: {}", hostname, e);
    }
}

// ... (Rest of functions: set_session_active, is_session_active, get_session_profile, log_command, save_client_output, enforce_storage_limit, get_global_full_history, get_session_full_history remain EXACTLY as they were) ...

pub fn set_session_active(conn: &Connection, session_id: u32, active: bool) {
    let val = if active { 1 } else { 0 };
    if let Err(e) = conn.execute("UPDATE sessions SET is_active = ?1 WHERE id = ?2", params![val, session_id]) {
        error!("Failed to set session {} active={}: {}", session_id, active, e);
    }
}

pub fn is_session_active(conn: &Connection, session_id: u32) -> bool {
    conn.query_row("SELECT is_active FROM sessions WHERE id = ?1", params![session_id], |r| r.get::<_, i32>(0))
        .map(|v| v == 1)
        .unwrap_or(false)
}

pub fn get_session_profile(conn: &Connection, session_id: u32) -> String {
    conn.query_row("SELECT profile FROM sessions WHERE id = ?1", params![session_id], |r| r.get(0))
        .unwrap_or("default".to_string())
}

pub fn log_command(conn: &Connection, session_id: u32, request_id: u64, command: &str) {
    if let Err(e) = conn.execute(
        "INSERT INTO command_history (session_id, request_id, command, timestamp) VALUES (?1, ?2, ?3, ?4)",
        params![session_id, request_id as i64, command, Utc::now().to_rfc3339()]
    ) {
        error!("Failed to log command for session {}: {}", session_id, e);
    }
}

const MAX_STORAGE_BYTES: usize = 150 * 1024 * 1024; 
const MAX_CHAR_LIMIT: usize = 3000;

pub fn save_client_output(conn: &Connection, session_id: u32, request_id: u64, output: &str, error: &str) {
    let safe_output: String = output.chars().take(MAX_CHAR_LIMIT).collect();
    let safe_error: String = error.chars().take(MAX_CHAR_LIMIT).collect();

    let res = conn.execute(
        "INSERT INTO client_outputs (session_id, request_id, output, error, timestamp) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![session_id, request_id as i64, safe_output, safe_error, Utc::now().to_rfc3339()]
    );

    if let Err(e) = res { error!("DB insert failed for session {} req {}: {}", session_id, request_id, e); return; }
    if let Err(e) = enforce_storage_limit(conn) { warn!("DB cleanup failed: {}", e); }
}

fn enforce_storage_limit(conn: &Connection) -> Result<(), rusqlite::Error> {
    let current_size: i64 = conn.query_row(
        "SELECT COALESCE(SUM(LENGTH(output) + LENGTH(error)), 0) FROM client_outputs", [], |row| row.get(0)
    )?;

    if (current_size as usize) > MAX_STORAGE_BYTES {
        let target = MAX_STORAGE_BYTES.saturating_sub(1024 * 1024); // free at least 1MB below limit
        let mut attempts = 0;
        loop {
            let count = conn.execute(
                "DELETE FROM client_outputs WHERE id IN (SELECT id FROM client_outputs ORDER BY timestamp ASC LIMIT 50)", []
            )?;
            if count == 0 { break; }
            attempts += 1;
            if attempts > 100 { break; }
            // Re-check actual size after each batch
            let remaining: i64 = conn.query_row(
                "SELECT COALESCE(SUM(LENGTH(output) + LENGTH(error)), 0) FROM client_outputs", [], |row| row.get(0)
            )?;
            if (remaining as usize) <= target { break; }
        }
    }
    Ok(())
}

pub fn get_global_full_history(conn: &Connection, limit: usize) -> Result<Vec<FullLogEntry>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT ch.session_id, ch.request_id, ch.command, co.output, co.error, ch.timestamp 
         FROM command_history ch
         LEFT JOIN client_outputs co ON ch.session_id = co.session_id AND ch.request_id = co.request_id
         ORDER BY ch.timestamp DESC LIMIT ?1"
    )?;

    let rows = stmt.query_map([limit as i64], |row| {
        Ok(FullLogEntry {
            session_id: row.get(0)?,
            request_id: row.get::<_, i64>(1)? as u64,
            command: row.get(2)?,
            output: row.get(3)?,
            error: row.get(4)?,
            timestamp: row.get(5)?,
        })
    })?;

    let mut history = Vec::new();
    for row in rows { history.push(row?); }
    Ok(history)
}

pub fn get_session_full_history(conn: &Connection, session_id: u32, limit: usize) -> Result<Vec<FullLogEntry>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT ch.session_id, ch.request_id, ch.command, co.output, co.error, ch.timestamp 
         FROM command_history ch
         LEFT JOIN client_outputs co ON ch.session_id = co.session_id AND ch.request_id = co.request_id
         WHERE ch.session_id = ?1 ORDER BY ch.timestamp DESC LIMIT ?2"
    )?;

    let rows = stmt.query_map(params![session_id, limit as i64], |row| {
        Ok(FullLogEntry {
            session_id: row.get(0)?,
            request_id: row.get::<_, i64>(1)? as u64,
            command: row.get(2)?,
            output: row.get(3)?,
            error: row.get(4)?,
            timestamp: row.get(5)?,
        })
    })?;

    let mut history = Vec::new();
    for row in rows { history.push(row?); }
    history.reverse();
    Ok(history)
}

// ── Operator Management ────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct Operator {
    pub id: i64,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: String,
    pub api_key: String,
    pub created_at: String,
    pub last_login: Option<String>,
}

/// Hash an API key for storage using HMAC-SHA256 with a fixed server-side
/// context string. Raw keys are only shown once at creation time (or on
/// password login); the DB stores this keyed hash, and auth compares
/// hmac(incoming) against the stored value.
pub fn hash_api_key(raw_key: &str) -> String {
    use sha2::Sha256;
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    // The HMAC key is a fixed domain-separation string. It doesn't need to be
    // secret — its purpose is to prevent raw SHA-256 rainbow-table lookups
    // against the stored hashes if the DB is leaked.
    let mut mac = <HmacSha256 as Mac>::new_from_slice(b"rcm-api-key-v1").expect("HMAC key");
    mac.update(raw_key.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn create_operator(conn: &Connection, username: &str, password_hash: &str, role: &str, api_key: &str) -> Result<i64, rusqlite::Error> {
    let key_hash = hash_api_key(api_key);
    conn.execute(
        "INSERT INTO operators (username, password_hash, role, api_key, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![username, password_hash, role, key_hash, Utc::now().to_rfc3339()],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Regenerate a fresh API key for an operator. Returns the raw key (shown
/// once to the caller); the DB stores only the HMAC hash. Called on
/// password-based login so the browser receives a valid raw key instead
/// of the stored hash.
pub fn regenerate_api_key(conn: &Connection, operator_id: i64) -> Option<String> {
    let raw_key = uuid::Uuid::new_v4().to_string();
    let key_hash = hash_api_key(&raw_key);
    match conn.execute(
        "UPDATE operators SET api_key = ?1 WHERE id = ?2",
        params![key_hash, operator_id],
    ) {
        Ok(n) if n > 0 => Some(raw_key),
        _ => None,
    }
}

pub fn get_operator_by_key(conn: &Connection, api_key: &str) -> Option<Operator> {
    let key_hash = hash_api_key(api_key);
    conn.query_row(
        "SELECT id, username, password_hash, role, api_key, created_at, last_login FROM operators WHERE api_key = ?1",
        [&key_hash],
        |r| Ok(Operator {
            id: r.get(0)?, username: r.get(1)?, password_hash: r.get(2)?,
            role: r.get(3)?, api_key: r.get(4)?, created_at: r.get(5)?, last_login: r.get(6)?,
        })
    ).optional().unwrap_or(None)
}

pub fn get_operator_by_username(conn: &Connection, username: &str) -> Option<Operator> {
    conn.query_row(
        "SELECT id, username, password_hash, role, api_key, created_at, last_login FROM operators WHERE username = ?1",
        [username],
        |r| Ok(Operator {
            id: r.get(0)?, username: r.get(1)?, password_hash: r.get(2)?,
            role: r.get(3)?, api_key: r.get(4)?, created_at: r.get(5)?, last_login: r.get(6)?,
        })
    ).optional().unwrap_or(None)
}

pub fn list_operators(conn: &Connection) -> Vec<Operator> {
    let mut stmt = match conn.prepare(
        "SELECT id, username, password_hash, role, api_key, created_at, last_login FROM operators ORDER BY id"
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let result = match stmt.query_map([], |r| Ok(Operator {
        id: r.get(0)?, username: r.get(1)?, password_hash: r.get(2)?,
        role: r.get(3)?, api_key: r.get(4)?, created_at: r.get(5)?, last_login: r.get(6)?,
    })) {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(_) => vec![],
    };
    result
}

pub fn delete_operator(conn: &Connection, id: i64) -> bool {
    conn.execute("DELETE FROM operators WHERE id = ?1", [id]).unwrap_or(0) > 0
}

pub fn update_operator_login(conn: &Connection, id: i64) {
    if let Err(e) = conn.execute("UPDATE operators SET last_login = ?1 WHERE id = ?2", params![Utc::now().to_rfc3339(), id]) {
        warn!("Failed to update login timestamp for operator {}: {}", id, e);
    }
}

pub fn update_operator_password(conn: &Connection, id: i64, new_hash: &str) {
    if let Err(e) = conn.execute("UPDATE operators SET password_hash = ?1 WHERE id = ?2", params![new_hash, id]) {
        error!("Failed to update password for operator {}: {}", id, e);
    }
}

pub fn operator_count(conn: &Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM operators", [], |r| r.get(0)).unwrap_or(0)
}

// ── Audit Log ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditEntry {
    pub id: i64,
    pub operator_name: String,
    pub action: String,
    pub target_session: Option<u32>,
    pub details: Option<String>,
    pub timestamp: String,
}

pub fn audit_log(conn: &Connection, operator_id: i64, operator_name: &str, action: &str, target_session: Option<u32>, details: Option<&str>) {
    if let Err(e) = conn.execute(
        "INSERT INTO audit_log (operator_id, operator_name, action, target_session, details, timestamp) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![operator_id, operator_name, action, target_session.map(|s| s as i64), details, Utc::now().to_rfc3339()],
    ) {
        error!("Failed to write audit log [{}:{}]: {}", operator_name, action, e);
    }
}

pub fn get_audit_log(conn: &Connection, limit: usize) -> Vec<AuditEntry> {
    let mut stmt = match conn.prepare(
        "SELECT id, operator_name, action, target_session, details, timestamp FROM audit_log ORDER BY timestamp DESC LIMIT ?1"
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let result = match stmt.query_map([limit as i64], |r| Ok(AuditEntry {
        id: r.get(0)?,
        operator_name: r.get(1)?,
        action: r.get(2)?,
        target_session: r.get::<_, Option<i64>>(3)?.map(|v| v as u32),
        details: r.get(4)?,
        timestamp: r.get(5)?,
    })) {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(_) => vec![],
    };
    result
}

// ── Listener Management ────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ListenerConfig {
    pub id: i64,
    pub name: String,
    pub port: u16,
    pub transport: String,
    pub profile_json: Option<String>,
    pub auto_start: bool,
    pub created_at: String,
}

pub fn create_listener(conn: &Connection, name: &str, port: u16, transport: &str, profile_json: Option<&str>) -> Result<i64, rusqlite::Error> {
    conn.execute(
        "INSERT INTO listeners (name, port, transport, profile_json, auto_start, created_at) VALUES (?1, ?2, ?3, ?4, 1, ?5)",
        params![name, port as i64, transport, profile_json, Utc::now().to_rfc3339()],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn list_listeners(conn: &Connection) -> Vec<ListenerConfig> {
    let mut stmt = match conn.prepare(
        "SELECT id, name, port, transport, profile_json, auto_start, created_at FROM listeners ORDER BY id"
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let result = match stmt.query_map([], |r| Ok(ListenerConfig {
        id: r.get(0)?,
        name: r.get(1)?,
        port: r.get::<_, i64>(2)? as u16,
        transport: r.get(3)?,
        profile_json: r.get(4)?,
        auto_start: r.get::<_, i64>(5)? != 0,
        created_at: r.get(6)?,
    })) {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(_) => vec![],
    };
    result
}

pub fn get_listener(conn: &Connection, id: i64) -> Option<ListenerConfig> {
    conn.query_row(
        "SELECT id, name, port, transport, profile_json, auto_start, created_at FROM listeners WHERE id = ?1",
        [id],
        |r| Ok(ListenerConfig {
            id: r.get(0)?, name: r.get(1)?, port: r.get::<_, i64>(2)? as u16,
            transport: r.get(3)?, profile_json: r.get(4)?,
            auto_start: r.get::<_, i64>(5)? != 0, created_at: r.get(6)?,
        })
    ).optional().unwrap_or(None)
}

pub fn delete_listener(conn: &Connection, id: i64) -> bool {
    conn.execute("DELETE FROM listeners WHERE id = ?1", [id]).unwrap_or(0) > 0
}

// ── Webhook Configuration ──────────────────────────────────────────────

pub fn get_webhook_url(conn: &Connection) -> Option<String> {
    conn.query_row(
        "SELECT value FROM server_config WHERE key = 'webhook_url'",
        [], |r| r.get::<_, Vec<u8>>(0)
    ).optional().unwrap_or(None)
     .and_then(|bytes| String::from_utf8(bytes).ok())
     .filter(|s| !s.is_empty())
}

pub fn set_webhook_url(conn: &Connection, url: &str) {
    if let Err(e) = conn.execute(
        "INSERT OR REPLACE INTO server_config (key, value) VALUES ('webhook_url', ?1)",
        params![url.as_bytes()],
    ) {
        error!("Failed to set webhook URL: {}", e);
    }
}

// ── Auto-Recon Commands ────────────────────────────────────────────────

pub fn get_auto_recon(conn: &Connection) -> Vec<String> {
    let mut stmt = match conn.prepare(
        "SELECT command FROM auto_recon ORDER BY sort_order, id"
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let result = match stmt.query_map([], |r| r.get(0)) {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(_) => vec![],
    };
    result
}

pub fn add_auto_recon(conn: &Connection, command: &str) -> Result<i64, rusqlite::Error> {
    let max_order: i64 = conn.query_row(
        "SELECT COALESCE(MAX(sort_order), 0) FROM auto_recon", [], |r| r.get(0)
    ).unwrap_or(0);
    conn.execute(
        "INSERT INTO auto_recon (command, sort_order) VALUES (?1, ?2)",
        params![command, max_order + 1],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn remove_auto_recon(conn: &Connection, id: i64) -> bool {
    conn.execute("DELETE FROM auto_recon WHERE id = ?1", [id]).unwrap_or(0) > 0
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AutoReconEntry {
    pub id: i64,
    pub command: String,
    pub sort_order: i64,
}

pub fn list_auto_recon(conn: &Connection) -> Vec<AutoReconEntry> {
    let mut stmt = match conn.prepare(
        "SELECT id, command, sort_order FROM auto_recon ORDER BY sort_order, id"
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let result = match stmt.query_map([], |r| Ok(AutoReconEntry {
        id: r.get(0)?,
        command: r.get(1)?,
        sort_order: r.get(2)?,
    })) {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(_) => vec![],
    };
    result
}

// ── Session Tags & Notes ───────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionNote {
    pub id: i64,
    pub session_id: u32,
    pub tag: Option<String>,
    pub note: String,
    pub operator: String,
    pub timestamp: String,
}

pub fn add_session_note(conn: &Connection, session_id: u32, tag: Option<&str>, note: &str, operator: &str) -> Result<i64, rusqlite::Error> {
    conn.execute(
        "INSERT INTO session_notes (session_id, tag, note, operator, timestamp) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![session_id, tag, note, operator, Utc::now().to_rfc3339()],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn get_session_notes(conn: &Connection, session_id: u32) -> Vec<SessionNote> {
    let mut stmt = match conn.prepare(
        "SELECT id, session_id, tag, note, operator, timestamp FROM session_notes WHERE session_id = ?1 ORDER BY timestamp DESC"
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let result = match stmt.query_map([session_id], |r| Ok(SessionNote {
        id: r.get(0)?, session_id: r.get::<_, i64>(1)? as u32,
        tag: r.get(2)?, note: r.get(3)?, operator: r.get(4)?, timestamp: r.get(5)?,
    })) {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(_) => vec![],
    };
    result
}

pub fn get_session_tags(conn: &Connection, session_id: u32) -> Vec<String> {
    let mut stmt = match conn.prepare(
        "SELECT DISTINCT tag FROM session_notes WHERE session_id = ?1 AND tag IS NOT NULL AND tag != ''"
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let result = match stmt.query_map([session_id], |r| r.get(0))
         {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(_) => vec![],
    };
    result
}

pub fn delete_session_note(conn: &Connection, session_id: u32, note_id: i64) -> bool {
    conn.execute(
        "DELETE FROM session_notes WHERE id = ?1 AND session_id = ?2",
        params![note_id, session_id],
    ).unwrap_or(0) > 0
}


// ── Queued Tasks (Hibernation Mode) ───────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QueuedTask {
    pub task_id: String,
    pub session_id: i64,
    pub command: String,
    pub status: String,
    pub created_at: i64,
    pub claimed_at: Option<i64>,
    pub result: Option<String>,
    pub error: Option<String>,
    pub finished_at: Option<i64>,
}

/// Enqueue a command for a hibernating agent's next check-in.
/// Returns the task_id (UUID) that was assigned.
pub fn queue_task(conn: &Connection, session_id: i64, command: &str) -> Result<String, rusqlite::Error> {
    let task_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().timestamp();
    conn.execute(
        "INSERT INTO queued_tasks (task_id, session_id, command, status, created_at)
         VALUES (?1, ?2, ?3, 'pending', ?4)",
        params![task_id, session_id, command, now],
    )?;
    Ok(task_id)
}

/// Atomically claim up to `limit` pending tasks for a session.
///
/// Uses a single UPDATE with RETURNING (SQLite ≥ 3.35) falling back to a
/// SELECT + UPDATE pattern. The atomic claim ensures that if a hibernating
/// agent connects twice simultaneously (e.g. after a network hiccup), each
/// connection sees a different batch of tasks — never the same task twice.
pub fn poll_and_claim_tasks(
    conn: &Connection,
    session_id: i64,
    limit: usize,
) -> Vec<QueuedTask> {
    let now = chrono::Utc::now().timestamp();

    // Step 1: select pending task IDs
    let task_ids: Vec<String> = {
        let mut stmt = match conn.prepare(
            "SELECT task_id FROM queued_tasks
              WHERE session_id = ?1 AND status = 'pending'
              ORDER BY created_at ASC
              LIMIT ?2"
        ) {
            Ok(s) => s,
            Err(_) => return vec![],
        };
        // Bind to a named variable so the MappedRows temporary is dropped
        // before `stmt` goes out of scope at the end of this block.
        let x = match stmt.query_map(params![session_id, limit as i64], |r| r.get(0)) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => return vec![],
        }; x
    };

    if task_ids.is_empty() {
        return vec![];
    }

    // Step 2: claim each task atomically — only transitions pending → running.
    // A concurrent claim on the same task_id will find status != 'pending' and
    // update 0 rows, so only one claimer wins.
    for task_id in &task_ids {
        let _ = conn.execute(
            "UPDATE queued_tasks SET status = 'running', claimed_at = ?1
              WHERE task_id = ?2 AND status = 'pending'",
            params![now, task_id],
        );
    }

    // Step 3: return the tasks we successfully claimed
    let mut stmt = match conn.prepare(
        "SELECT task_id, session_id, command, status, created_at,
                claimed_at, result, error, finished_at
           FROM queued_tasks
          WHERE task_id IN (SELECT value FROM json_each(?1))
            AND status = 'running'
            AND claimed_at = ?2"
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    let id_json = serde_json::to_string(&task_ids).unwrap_or_else(|_| "[]".into());
    let x = match stmt.query_map(params![id_json, now], |r| {
        Ok(QueuedTask {
            task_id: r.get(0)?,
            session_id: r.get(1)?,
            command: r.get(2)?,
            status: r.get(3)?,
            created_at: r.get(4)?,
            claimed_at: r.get(5)?,
            result: r.get(6)?,
            error: r.get(7)?,
            finished_at: r.get(8)?,
        })
    }) {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(_) => vec![],
    }; x
}

/// Mark a task as completed with its output.
pub fn complete_task(conn: &Connection, task_id: &str, result: &str) {
    let now = chrono::Utc::now().timestamp();
    if let Err(e) = conn.execute(
        "UPDATE queued_tasks SET status = 'completed', result = ?1, finished_at = ?2
          WHERE task_id = ?3",
        params![result, now, task_id],
    ) {
        error!("complete_task {}: {}", task_id, e);
    }
}

/// Mark a task as failed with an error message.
pub fn fail_task(conn: &Connection, task_id: &str, error_msg: &str) {
    let now = chrono::Utc::now().timestamp();
    if let Err(e) = conn.execute(
        "UPDATE queued_tasks SET status = 'failed', error = ?1, finished_at = ?2
          WHERE task_id = ?3",
        params![error_msg, now, task_id],
    ) {
        error!("fail_task {}: {}", task_id, e);
    }
}

/// List all tasks for a session (for the `tasks` server command).
pub fn list_tasks(conn: &Connection, session_id: i64) -> Vec<QueuedTask> {
    let mut stmt = match conn.prepare(
        "SELECT task_id, session_id, command, status, created_at,
                claimed_at, result, error, finished_at
           FROM queued_tasks
          WHERE session_id = ?1
          ORDER BY created_at DESC
          LIMIT 100"
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let x = match stmt.query_map([session_id], |r| {
        Ok(QueuedTask {
            task_id: r.get(0)?,
            session_id: r.get(1)?,
            command: r.get(2)?,
            status: r.get(3)?,
            created_at: r.get(4)?,
            claimed_at: r.get(5)?,
            result: r.get(6)?,
            error: r.get(7)?,
            finished_at: r.get(8)?,
        })
    }) {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(_) => vec![],
    }; x
}

/// Delete all tasks for a session (cleanup after teardown).
pub fn clear_tasks(conn: &Connection, session_id: i64) {
    if let Err(e) = conn.execute(
        "DELETE FROM queued_tasks WHERE session_id = ?1",
        [session_id],
    ) {
        warn!("clear_tasks session {}: {}", session_id, e);
    }
}

// ── Queued Task Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod queued_task_tests {
    use super::*;
    use rusqlite::Connection;

    fn in_memory_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE queued_tasks (
                task_id TEXT PRIMARY KEY,
                session_id INTEGER NOT NULL,
                command TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at INTEGER NOT NULL,
                claimed_at INTEGER,
                result TEXT,
                error TEXT,
                finished_at INTEGER
             );
             CREATE INDEX idx_tasks_session ON queued_tasks(session_id);
             CREATE INDEX idx_tasks_status  ON queued_tasks(status);"
        ).unwrap();
        conn
    }

    #[test]
    fn queue_task_returns_uuid_string() {
        let conn = in_memory_db();
        let id = queue_task(&conn, 1, "whoami").unwrap();
        assert!(!id.is_empty());
        // Should parse as a UUID
        assert!(uuid::Uuid::parse_str(&id).is_ok());
    }

    #[test]
    fn queue_and_poll_roundtrip() {
        let conn = in_memory_db();
        let id = queue_task(&conn, 1, "id").unwrap();

        let tasks = poll_and_claim_tasks(&conn, 1, 10);
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].task_id, id);
        assert_eq!(tasks[0].command, "id");
        assert_eq!(tasks[0].status, "running");
    }

    #[test]
    fn poll_claims_correct_session_only() {
        let conn = in_memory_db();
        let _id1 = queue_task(&conn, 1, "cmd1").unwrap();
        let _id2 = queue_task(&conn, 2, "cmd2").unwrap();

        let tasks = poll_and_claim_tasks(&conn, 1, 10);
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].session_id, 1);
    }

    #[test]
    fn poll_respects_batch_limit() {
        let conn = in_memory_db();
        for i in 0..5 {
            queue_task(&conn, 1, &format!("cmd{}", i)).unwrap();
        }
        let tasks = poll_and_claim_tasks(&conn, 1, 3);
        assert_eq!(tasks.len(), 3);
    }

    #[test]
    fn poll_empty_when_no_pending() {
        let conn = in_memory_db();
        let tasks = poll_and_claim_tasks(&conn, 1, 10);
        assert!(tasks.is_empty());
    }

    #[test]
    fn poll_does_not_return_already_claimed_tasks() {
        let conn = in_memory_db();
        queue_task(&conn, 1, "cmd").unwrap();

        // First poll claims it
        let first = poll_and_claim_tasks(&conn, 1, 10);
        assert_eq!(first.len(), 1);

        // Second poll finds nothing pending
        let second = poll_and_claim_tasks(&conn, 1, 10);
        assert!(second.is_empty(), "already-claimed task should not be returned again");
    }

    #[test]
    fn complete_task_sets_status_and_result() {
        let conn = in_memory_db();
        let id = queue_task(&conn, 1, "whoami").unwrap();
        let tasks = poll_and_claim_tasks(&conn, 1, 1);
        assert_eq!(tasks.len(), 1);

        complete_task(&conn, &id, "root");

        let all = list_tasks(&conn, 1);
        assert_eq!(all[0].status, "completed");
        assert_eq!(all[0].result.as_deref(), Some("root"));
        assert!(all[0].finished_at.is_some());
    }

    #[test]
    fn fail_task_sets_status_and_error() {
        let conn = in_memory_db();
        let id = queue_task(&conn, 1, "bad_cmd").unwrap();
        let _ = poll_and_claim_tasks(&conn, 1, 1);

        fail_task(&conn, &id, "command not found");

        let all = list_tasks(&conn, 1);
        assert_eq!(all[0].status, "failed");
        assert_eq!(all[0].error.as_deref(), Some("command not found"));
    }

    #[test]
    fn list_tasks_returns_all_for_session() {
        let conn = in_memory_db();
        queue_task(&conn, 1, "a").unwrap();
        queue_task(&conn, 1, "b").unwrap();
        queue_task(&conn, 2, "c").unwrap();

        let tasks = list_tasks(&conn, 1);
        assert_eq!(tasks.len(), 2);
        assert!(tasks.iter().all(|t| t.session_id == 1));
    }

    #[test]
    fn clear_tasks_removes_all_for_session() {
        let conn = in_memory_db();
        queue_task(&conn, 1, "a").unwrap();
        queue_task(&conn, 1, "b").unwrap();
        queue_task(&conn, 2, "c").unwrap();

        clear_tasks(&conn, 1);

        assert!(list_tasks(&conn, 1).is_empty());
        assert_eq!(list_tasks(&conn, 2).len(), 1); // session 2 unaffected
    }

    #[test]
    fn poll_returns_tasks_in_created_at_order() {
        let conn = in_memory_db();
        // Insert with different timestamps
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO queued_tasks (task_id, session_id, command, status, created_at)
             VALUES ('id-1', 1, 'first', 'pending', ?1)",
            [now - 10],
        ).unwrap();
        conn.execute(
            "INSERT INTO queued_tasks (task_id, session_id, command, status, created_at)
             VALUES ('id-2', 1, 'second', 'pending', ?1)",
            [now],
        ).unwrap();

        let tasks = poll_and_claim_tasks(&conn, 1, 2);
        assert_eq!(tasks.len(), 2);
        // Oldest should come first
        assert_eq!(tasks[0].task_id, "id-1", "oldest task should be claimed first");
    }
}
