// src/agent/scripting/helpers.rs
//
// Pure-Rust helper functions shared across scripting sub-modules.
// Nothing in here touches the Rhai engine directly.

use std::fs;
use sha2::{Sha256, Digest as Sha2Digest};
use hmac::{Hmac, Mac};
use md5::{Md5, Digest as Md5Digest};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use serde_json::json;

// ─────────────────────────────────────────────────────────────────────────────
// Hash helpers
// ─────────────────────────────────────────────────────────────────────────────

pub(super) fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

pub(super) fn sha256_bytes_hex(raw: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(raw);
    hex::encode(h.finalize())
}

pub(super) fn md5_hex(s: &str) -> String {
    let mut h = Md5::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

pub(super) fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> Result<String, String> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|e| format!("HMAC key error: {}", e))?;
    mac.update(data);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

pub(super) fn crc32_hash(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        let mut val = byte as u32;
        for _ in 0..8 {
            if (crc ^ val) & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
            val >>= 1;
        }
    }
    !crc
}

pub(super) fn fnv1a_hash(data: &[u8]) -> i64 {
    let mut h: u64 = 14695981039346656037;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h as i64
}

// ─────────────────────────────────────────────────────────────────────────────
// AES-256-GCM helpers
// ─────────────────────────────────────────────────────────────────────────────

pub(super) fn do_encrypt(cipher: &Aes256Gcm, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    match cipher.encrypt(nonce, plaintext) {
        Ok(ct) => {
            let mut out = nonce_bytes.to_vec();
            out.extend_from_slice(&ct);
            Ok(out)
        }
        Err(e) => Err(format!("AES Error: {}", e)),
    }
}

pub(super) fn do_decrypt(cipher: &Aes256Gcm, encrypted_data: &[u8]) -> Result<Vec<u8>, String> {
    if encrypted_data.len() < 12 {
        return Err("Data too short".to_string());
    }
    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    match cipher.decrypt(nonce, ciphertext) {
        Ok(pt) => Ok(pt),
        Err(e) => Err(format!("AES Error: {}", e)),
    }
}

pub(super) fn aes_cipher_from_hex(key_hex: &str) -> Result<Aes256Gcm, String> {
    let key_bytes = hex::decode(key_hex).map_err(|_| "Invalid key hex".to_string())?;
    if key_bytes.len() != 32 {
        return Err("Key must be 32 bytes".to_string());
    }
    Ok(Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes)))
}

// ─────────────────────────────────────────────────────────────────────────────
// Glob-to-regex conversion (for find_files)
// ─────────────────────────────────────────────────────────────────────────────

pub(super) fn glob_to_regex(pattern: &str) -> String {
    let mut r = String::from("(?i)^");
    for c in pattern.chars() {
        match c {
            '*' => r.push_str(".*"),
            '?' => r.push('.'),
            '.' | '+' | '^' | '$' | '{' | '}' | '|' | '(' | ')' | '[' | ']' | '\\' => {
                r.push('\\');
                r.push(c);
            }
            c => r.push(c),
        }
    }
    r.push('$');
    r
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON dotted-path accessor
// ─────────────────────────────────────────────────────────────────────────────

pub(super) fn json_get_path(json_str: &str, dotted_path: &str) -> String {
    let Ok(mut val) = serde_json::from_str::<serde_json::Value>(json_str) else {
        return "Error: invalid JSON".to_string();
    };
    for part in dotted_path.split('.') {
        val = if let Ok(i) = part.parse::<usize>() {
            match val.get(i) {
                Some(v) => v.clone(),
                None    => return "null".to_string(),
            }
        } else {
            match val.get(part) {
                Some(v) => v.clone(),
                None    => return "null".to_string(),
            }
        };
    }
    match val {
        serde_json::Value::String(s) => s,
        serde_json::Value::Null      => "null".to_string(),
        other                        => other.to_string(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Process helpers
// ─────────────────────────────────────────────────────────────────────────────

pub(super) fn kill_pid(pid: u32) -> String {
    if pid == 0 {
        return "Error: PID 0 is not a valid kill target".to_string();
    }
    #[cfg(target_os = "windows")]
    unsafe {
        use super::win_ffi::win_ext::*;
        let h = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        if h.is_null() {
            return format!("Error: OpenProcess failed ({})", GetLastError());
        }
        let ok = TerminateProcess(h, 1);
        CloseHandle(h);
        if ok != 0 { "Killed".into() }
        else { format!("Error: TerminateProcess failed ({})", GetLastError()) }
    }
    #[cfg(not(target_os = "windows"))]
    unsafe {
        let r = libc::kill(pid as libc::pid_t, libc::SIGKILL);
        if r == 0 { "Killed".into() }
        else { format!("Error: kill() returned {}", r) }
    }
}

pub(super) fn proc_env(pid: u32) -> String {
    #[cfg(target_os = "linux")]
    {
        let path = format!("/proc/{}/environ", pid);
        match fs::read(&path) {
            Ok(bytes) => {
                let pairs: Vec<serde_json::Value> = bytes
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .filter_map(|kv| {
                        let s = String::from_utf8_lossy(kv);
                        let mut it = s.splitn(2, '=');
                        let k = it.next()?;
                        let v = it.next().unwrap_or("");
                        Some(json!({ "key": k, "value": v }))
                    })
                    .collect();
                serde_json::to_string(&pairs).unwrap_or("[]".into())
            }
            Err(e) => format!("Error: {}", e),
        }
    }
    #[cfg(not(target_os = "linux"))]
    format!("Error: proc_env not supported on this platform (pid {})", pid)
}

pub(super) fn spawn_hidden(binary: &str, args_json: &str) -> String {
    let args: Vec<String> = serde_json::from_str(args_json).unwrap_or_default();
    let mut cmd = std::process::Command::new(binary);
    cmd.args(&args);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    match cmd.spawn() {
        Ok(child) => child.id().to_string(),
        Err(e)    => format!("Error: {}", e),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Directory / drive enumeration (pub — used by agent/mod.rs file browser)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn enumerate_drives() -> String {
    extern "system" { fn GetLogicalDrives() -> u32; }
    let mask = unsafe { GetLogicalDrives() };
    let entries: Vec<serde_json::Value> = (0..26u32)
        .filter(|i| mask & (1 << i) != 0)
        .map(|i| {
            let letter = (b'A' + i as u8) as char;
            let path   = format!("{}:\\", letter);
            json!({ "name": path, "is_dir": true, "is_drive": true,
                    "size": 0, "perms": "rw", "mod_time": 0 })
        })
        .collect();
    serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string())
}

#[cfg(target_os = "macos")]
fn enumerate_drives() -> String {
    collect_mount_dirs(&["/Volumes"])
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn enumerate_drives() -> String {
    collect_mount_dirs(&["/media", "/mnt", "/run/media"])
}

#[cfg(not(target_os = "windows"))]
fn collect_mount_dirs(bases: &[&str]) -> String {
    let mut entries = Vec::new();
    for &base in bases {
        if let Ok(rd) = fs::read_dir(base) {
            for entry in rd.flatten() {
                let meta = entry.metadata().ok();
                if !meta.as_ref().map(|m| m.is_dir()).unwrap_or(false) { continue; }
                let full_path = format!("{}/{}", base, entry.file_name().to_string_lossy());
                let modified  = meta.as_ref()
                    .and_then(|m| m.modified().ok())
                    .map(|t| t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs())
                    .unwrap_or(0);
                entries.push(json!({ "name": full_path, "is_dir": true, "is_drive": true,
                                     "size": 0, "perms": "rw", "mod_time": modified }));
            }
        }
    }
    entries.sort_by(|a, b| {
        a["name"].as_str().unwrap_or("").cmp(b["name"].as_str().unwrap_or(""))
    });
    serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string())
}

pub fn get_directory_json(path: &str) -> String {
    if path == "__drives__" {
        return enumerate_drives();
    }
    let mut entries = Vec::new();
    let search_path = if path.is_empty() { "." } else { path };
    if let Ok(read_dir) = fs::read_dir(search_path) {
        for entry_result in read_dir {
            if let Ok(entry) = entry_result {
                let metadata    = entry.metadata().ok();
                let is_dir      = metadata.as_ref().map(|m| m.is_dir()).unwrap_or(false);
                let size        = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
                let name        = entry.file_name().to_string_lossy().to_string();
                let permissions = if let Some(m) = &metadata {
                    if m.permissions().readonly() { "r" } else { "rw" }
                } else { "?" };
                let modified = metadata.as_ref()
                    .and_then(|m| m.modified().ok())
                    .map(|t| t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs())
                    .unwrap_or(0);
                entries.push(json!({
                    "name": name, "is_dir": is_dir,
                    "size": size, "perms": permissions, "mod_time": modified,
                }));
            }
        }
    } else {
        return json!({ "error": format!("Failed to read path: {}", path) }).to_string();
    }
    entries.sort_by(|a, b| {
        let a_dir = a["is_dir"].as_bool().unwrap_or(false);
        let b_dir = b["is_dir"].as_bool().unwrap_or(false);
        if a_dir == b_dir {
            a["name"].as_str().unwrap_or("").cmp(b["name"].as_str().unwrap_or(""))
        } else {
            b_dir.cmp(&a_dir)
        }
    });
    serde_json::to_string(&entries).unwrap_or("[]".into())
}
