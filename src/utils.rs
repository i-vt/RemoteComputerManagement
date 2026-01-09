use uuid::Uuid;
use sha2::{Sha256, Digest};
use std::process::Command;

pub fn get_persistent_id() -> String {
    machine_uid::get().unwrap_or_else(|_| Uuid::new_v4().to_string())
}

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

pub fn execute_shell_command(cmd: &str) -> (String, String, i32) {
    let output = if cfg!(target_os = "windows") {
        Command::new("powershell").args(["-Command", cmd]).output()
    } else {
        Command::new("sh").args(["-c", cmd]).output()
    };

    match output {
        Ok(o) => (
            String::from_utf8_lossy(&o.stdout).to_string(),
            String::from_utf8_lossy(&o.stderr).to_string(),
            o.status.code().unwrap_or(-1),
        ),
        Err(e) => (String::new(), e.to_string(), -1),
    }
}
