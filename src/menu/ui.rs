use crate::common::SharedSessions;
use std::fs;

pub fn print_help() {
    println!("\n=== Help ===");
    println!(" [Global] sessions            - List active sessions");
    println!(" [Global] interact <id>       - Enter session mode");
    println!(" [Global] exit                - Shutdown server");
    println!(" [Session] proxy start        - Start SOCKS5 (Random Ports)");
    println!(" [Session] proxy stop         - Stop SOCKS5");
    println!(" [Session] extension list     - List available memory extensions");
    println!(" [Session] extension load <n> - Inject extension (e.g., 'extension load encrypt_test target.txt')");
    println!(" [Session] upload <loc> <rem> - Upload file");
    println!(" [Session] download [-r] <rem>- Download file");
    println!(" [Session] background         - Return to global menu");
}

pub fn print_sessions(sessions: &SharedSessions) {
    let map = sessions.lock().unwrap();
    if map.is_empty() { 
        println!("No sessions."); 
        return; 
    }
    println!("ID   | IP Address        | Hostname");
    println!("-----|-------------------|---------");
    for (id, s) in map.iter() {
        println!("{:<4} | {:<16} | {}", id, s.addr.ip(), s.hostname);
    }
}

pub fn print_extensions() {
    println!("\nAvailable Extensions (./extensions):");
    println!("------------------------------------");
    if let Ok(entries) = fs::read_dir("./extensions") {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if name.ends_with(".rhai") {
                    println!(" - {}", name.trim_end_matches(".rhai"));
                }
            }
        }
    } else {
        println!("[-] Could not read ./extensions directory.");
    }
    println!();
}
