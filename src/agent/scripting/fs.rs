// src/agent/scripting/fs.rs
use rhai::Engine;
use std::fs;
use super::helpers::get_directory_json;
use crate::strcrypt_rt;
use strcrypt::aes_str;

pub fn register(engine: &mut Engine) {
    engine.register_fn(&aes_str!("internal_read"), |path: &str| -> String {
        match fs::read_to_string(path) {
            Ok(c)  => c,
            Err(e) => format!("Error: {}", e),
        }
    });

    engine.register_fn(&aes_str!("internal_write"), |path: &str, data: &str| -> String {
        match fs::write(path, data) {
            Ok(_)  => aes_str!("Success"),
            Err(e) => format!("Error: {}", e),
        }
    });

    engine.register_fn(&aes_str!("internal_ls"), |path: &str| -> String {
        get_directory_json(path)
    });

    engine.register_fn(&aes_str!("internal_self_path"), || -> String {
        std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default()
    });
}
