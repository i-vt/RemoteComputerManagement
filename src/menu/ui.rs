// ./src/menu/ui.rs
use crate::common::SharedSessions;
use std::fs;

pub fn print_help() {
    eprintln!("\n=== Help ===");
    eprintln!(" [Global] sessions            - List active sessions");
    eprintln!(" [Global] interact <id>       - Enter session mode");
    eprintln!(" [Global] exit                - Shutdown server");
    eprintln!(" [Session] proxy start        - Start SOCKS5 (Random Ports)");
    eprintln!(" [Session] proxy stop         - Stop SOCKS5");
    eprintln!(" [Session] extension list     - List available memory extensions");
    eprintln!(" [Session] extension load <n> - Inject extension (e.g., 'extension load encrypt_test target.txt')");
    eprintln!(" [Session] upload <loc> <rem> - Upload file");
    eprintln!(" [Session] download [-r] <rem>- Download file");
    eprintln!(" [Session] inject <pid> <path>- Inject binary/shellcode into remote process");
    
    // [NEW] Keylogger Commands
    eprintln!(" [Session] keylogger:start    - Start background keystroke recording (Windows)");
    eprintln!(" [Session] keylogger:dump     - Retrieve captured keystrokes");
    eprintln!(" [Session] keylogger:stop     - Stop recording and detach hook");
    
    eprintln!(" [Session] background         - Return to global menu");
}

pub fn print_sessions(sessions: &SharedSessions) {
    let map = sessions.lock().unwrap();
    if map.is_empty() { 
        eprintln!("No sessions."); 
        return; 
    }
    eprintln!("ID    | IP Address        | Hostname");
    eprintln!("-----|-------------------|---------");
    for (id, s) in map.iter() {
        eprintln!("{:<4} | {:<16} | {}", id, s.addr.ip(), s.hostname);
    }
}

pub fn print_extensions() {
    eprintln!("\nAvailable Extensions (./extensions):");
    eprintln!("------------------------------------");
    if let Ok(entries) = fs::read_dir("./extensions") {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if name.ends_with(".rhai") {
                    eprintln!(" - {}", name.trim_end_matches(".rhai"));
                }
            }
        }
    } else {
        eprintln!("[-] Could not read ./extensions directory.");
    }
    println!();
}
