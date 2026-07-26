// src/agent/scripting/io.rs
use rhai::Engine;
use std::{fs, path::Path};
use serde_json::json;
use crate::strcrypt_rt;
use strcrypt::aes_str;

pub fn register(engine: &mut Engine) {

    // ── Binary file I/O ───────────────────────────────────────────────────────

    // Read a file as hex-encoded bytes (works for any file, including binary).
    // internal_read is text-only; internal_read_bytes handles arbitrary content.
    engine.register_fn(&aes_str!("internal_read_bytes"), |path: &str| -> String {
        match fs::read(path) {
            Ok(bytes) => hex::encode(bytes),
            Err(e)    => format!("{}{}", aes_str!("Error: "), e),
        }
    });

    // Write hex-encoded bytes to a file (creates or overwrites).
    engine.register_fn(&aes_str!("internal_write_bytes"), |path: &str, data_hex: &str| -> String {
        let data = match hex::decode(data_hex) {
            Ok(d)  => d,
            Err(_) => data_hex.as_bytes().to_vec(), // fall back to raw UTF-8
        };
        match fs::write(path, &data) {
            Ok(_)  => format!("{}{}{}", aes_str!("Wrote "), data.len(), aes_str!(" bytes")),
            Err(e) => format!("{}{}", aes_str!("Error: "), e),
        }
    });

    // ── Extended file operations ──────────────────────────────────────────────

    engine.register_fn(&aes_str!("internal_copy"), |src: &str, dst: &str| -> String {
        match fs::copy(src, dst) {
            Ok(n)  => format!("{}{}{}", aes_str!("Copied "), n, aes_str!(" bytes")),
            Err(e) => format!("{}{}", aes_str!("Error: "), e),
        }
    });

    engine.register_fn(&aes_str!("internal_move"), |src: &str, dst: &str| -> String {
        // fs::rename fails across filesystems; fall back to copy+delete.
        if fs::rename(src, dst).is_ok() {
            return aes_str!("Moved");
        }
        match fs::copy(src, dst) {
            Ok(_) => match fs::remove_file(src) {
                Ok(_)  => aes_str!("Moved (copy+delete)"),
                Err(e) => format!("{}{}", aes_str!("Copied but could not delete source: "), e),
            },
            Err(e) => format!("{}{}", aes_str!("Error: "), e),
        }
    });

    engine.register_fn(&aes_str!("internal_delete"), |path: &str| -> String {
        let p = Path::new(path);
        let result = if p.is_dir() {
            fs::remove_dir_all(path)
        } else {
            fs::remove_file(path)
        };
        match result {
            Ok(_)  => aes_str!("Deleted"),
            Err(e) => format!("{}{}", aes_str!("Error: "), e),
        }
    });

    engine.register_fn(&aes_str!("internal_mkdir"), |path: &str| -> String {
        match fs::create_dir_all(path) {
            Ok(_)  => aes_str!("Created"),
            Err(e) => format!("{}{}", aes_str!("Error: "), e),
        }
    });

    engine.register_fn(&aes_str!("internal_exists"), |path: &str| -> String {
        if Path::new(path).exists() { aes_str!("true") } else { aes_str!("false") }
    });

    // Returns JSON: {size, is_dir, is_file, readonly, modified, created}
    engine.register_fn(&aes_str!("internal_stat"), |path: &str| -> String {
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
                    aes_str!("size").as_str():     m.len(),
                    aes_str!("is_dir").as_str():   m.is_dir(),
                    aes_str!("is_file").as_str():  m.is_file(),
                    aes_str!("readonly").as_str(): m.permissions().readonly(),
                    aes_str!("modified").as_str(): modified,
                    aes_str!("created").as_str():  created,
                }).to_string()
            }
            Err(e) => format!("{}{}", aes_str!("Error: "), e),
        }
    });

    engine.register_fn(&aes_str!("internal_file_size"), |path: &str| -> String {
        fs::metadata(path).map(|m| m.len() as i64).unwrap_or(-1).to_string()
    });
}