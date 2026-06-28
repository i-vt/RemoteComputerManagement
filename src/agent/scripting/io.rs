// src/agent/scripting/io.rs
use rhai::Engine;
use std::{fs, path::Path};
use serde_json::json;

pub fn register(engine: &mut Engine) {

    // ── Binary file I/O ───────────────────────────────────────────────────────

    // Read a file as hex-encoded bytes (works for any file, including binary).
    // internal_read is text-only; internal_read_bytes handles arbitrary content.
    engine.register_fn("internal_read_bytes", |path: &str| -> String {
        match fs::read(path) {
            Ok(bytes) => hex::encode(bytes),
            Err(e)    => format!("Error: {}", e),
        }
    });

    // Write hex-encoded bytes to a file (creates or overwrites).
    engine.register_fn("internal_write_bytes", |path: &str, data_hex: &str| -> String {
        let data = match hex::decode(data_hex) {
            Ok(d)  => d,
            Err(_) => data_hex.as_bytes().to_vec(), // fall back to raw UTF-8
        };
        match fs::write(path, &data) {
            Ok(_)  => format!("Wrote {} bytes", data.len()),
            Err(e) => format!("Error: {}", e),
        }
    });

    // ── Extended file operations ──────────────────────────────────────────────

    engine.register_fn("internal_copy", |src: &str, dst: &str| -> String {
        match fs::copy(src, dst) {
            Ok(n)  => format!("Copied {} bytes", n),
            Err(e) => format!("Error: {}", e),
        }
    });

    engine.register_fn("internal_move", |src: &str, dst: &str| -> String {
        // fs::rename fails across filesystems; fall back to copy+delete.
        if fs::rename(src, dst).is_ok() {
            return "Moved".to_string();
        }
        match fs::copy(src, dst) {
            Ok(_) => match fs::remove_file(src) {
                Ok(_)  => "Moved (copy+delete)".to_string(),
                Err(e) => format!("Copied but could not delete source: {}", e),
            },
            Err(e) => format!("Error: {}", e),
        }
    });

    engine.register_fn("internal_delete", |path: &str| -> String {
        let p = Path::new(path);
        let result = if p.is_dir() {
            fs::remove_dir_all(path)
        } else {
            fs::remove_file(path)
        };
        match result {
            Ok(_)  => "Deleted".to_string(),
            Err(e) => format!("Error: {}", e),
        }
    });

    engine.register_fn("internal_mkdir", |path: &str| -> String {
        match fs::create_dir_all(path) {
            Ok(_)  => "Created".to_string(),
            Err(e) => format!("Error: {}", e),
        }
    });

    engine.register_fn("internal_exists", |path: &str| -> String {
        if Path::new(path).exists() { "true".into() } else { "false".into() }
    });

    // Returns JSON: {size, is_dir, is_file, readonly, modified, created}
    engine.register_fn("internal_stat", |path: &str| -> String {
        match fs::metadata(path) {
            Ok(m) => {
                let modified = m.modified().ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let created = m.created().ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                json!({
                    "size":     m.len(),
                    "is_dir":   m.is_dir(),
                    "is_file":  m.is_file(),
                    "readonly": m.permissions().readonly(),
                    "modified": modified,
                    "created":  created,
                }).to_string()
            }
            Err(e) => format!("Error: {}", e),
        }
    });

    engine.register_fn("internal_file_size", |path: &str| -> String {
        fs::metadata(path).map(|m| m.len() as i64).unwrap_or(-1).to_string()
    });
}
