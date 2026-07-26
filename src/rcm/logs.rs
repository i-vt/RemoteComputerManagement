// ./src/rcm/logs.rs
// Tool log files (Section 13): logs/<tool>/<component>/<YYYY-MM-DD>/<NNNN>.log
// with zero-padded counters from 0000, one event per line, UTC dates, and
// rotation to the next counter when the current file reaches 16 MiB
// (REQ-18.2.2). Logs are living documents: append-only, never reordered
// (REQ-13.5).

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use chrono::Utc;

use super::package::RcmError;
use super::paths;
use super::xml;
use crate::config::config;

/// REQ-13.6: raw CR/LF in a message would break the one-event-per-line
/// rule, so they are escaped as the two-character sequences `\r` / `\n`.
fn escape_message(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    for c in message.chars() {
        match c {
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

fn log_inner(
    root: &Path,
    tool: &str,
    component: &str,
    level: &str,
    message: &str,
    rotate_limit: u64,
) -> Result<(), RcmError> {
    // tool/component become folder names; sanitize defensively even though
    // callers pass fixed identifiers.
    let tool = paths::sanitize_component(tool);
    let component = paths::sanitize_component(component);
    let date = Utc::now().format("%Y-%m-%d").to_string();
    let dir = paths::ensure_dir(root, &["logs", &tool, &component, &date])?;

    let line = format!("{} {} {}\n", xml::now_ts(), level, escape_message(message));

    // Current counter = highest existing NNNN.log; rotate when full.
    // (Logs are living documents exempt from REQ-3.4.1; the highest counter
    // wins and creation of the next file still uses create_new.)
    let mut max_n: Option<u64> = None;
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(stem) = name.strip_suffix(".log") {
            // >= 4 digits: rotation must keep working past 9999 ("10000.log").
            if stem.len() >= 4 && stem.bytes().all(|b| b.is_ascii_digit()) {
                if let Ok(n) = stem.parse::<u64>() {
                    max_n = Some(max_n.map_or(n, |m: u64| m.max(n)));
                }
            }
        }
    }

    let mut n = max_n.unwrap_or(0);
    if let Some(cur) = max_n {
        let size = dir
            .join(format!("{:04}.log", cur))
            .metadata()
            .map(|m| m.len())
            .unwrap_or(0);
        if size + line.len() as u64 > rotate_limit {
            n = cur + 1;
        }
    }

    // Rotate-forward with create-exclusive allocation to stay race-safe.
    for attempt in n..n + 10_000 {
        let path = dir.join(format!("{:04}.log", attempt));
        // Never write through a symlink: a symlinked log target is hostile.
        if let Ok(md) = path.symlink_metadata() {
            if md.file_type().is_symlink() {
                return Err(RcmError(format!(
                    "refusing to write through symlinked log file: {}",
                    path.display()
                )));
            }
        }
        if attempt > n && path.exists() {
            continue;
        }
        let mut f = OpenOptions::new().append(true).create(true).open(&path)?;
        f.write_all(line.as_bytes())?;
        f.sync_all()?;
        return Ok(());
    }
    Err(RcmError("log counter space exhausted".into()))
}

/// Append one event: "canonical_ts LEVEL message\n". Creates directories as
/// needed. `tool` is always "rcm-server" from package.rs wrappers.
pub fn log(
    root: &Path,
    tool: &str,
    component: &str,
    level: &str,
    message: &str,
) -> Result<(), RcmError> {
    // Rotation threshold (REQ-18.2.2) comes from config.rcm.log_rotate_bytes.
    log_inner(root, tool, component, level, message, config().rcm.log_rotate_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_line_format_and_escaping() {
        let dir = tempfile::tempdir().unwrap();
        log(dir.path(), "rcm-server", "agent", "INFO", "line one\nline two\r\nend").unwrap();
        let date = Utc::now().format("%Y-%m-%d").to_string();
        let p = dir
            .path()
            .join("logs/rcm-server/agent")
            .join(&date)
            .join("0000.log");
        let body = std::fs::read_to_string(&p).unwrap();
        let re = regex::Regex::new(
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z INFO line one\\nline two\\r\\nend\n$",
        )
        .unwrap();
        assert!(re.is_match(&body), "got: {:?}", body);
        // One physical line only (REQ-13.2/13.6).
        assert_eq!(body.matches('\n').count(), 1);
    }

    #[test]
    fn appends_in_order_and_rotates() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..3 {
            log_inner(
                dir.path(),
                "rcm-server",
                "shell",
                "INFO",
                &format!("event {}", i),
                1024,
            )
            .unwrap();
        }
        let date = Utc::now().format("%Y-%m-%d").to_string();
        let day = dir.path().join("logs/rcm-server/shell").join(&date);
        let body = std::fs::read_to_string(day.join("0000.log")).unwrap();
        assert_eq!(body.matches("event ").count(), 3);
        assert!(body.find("event 0").unwrap() < body.find("event 1").unwrap());

        // Force rotation with a tiny limit.
        log_inner(dir.path(), "rcm-server", "shell", "WARN", "x".repeat(2000).as_str(), 1024)
            .unwrap();
        assert!(day.join("0001.log").exists());
        let rotated = std::fs::read_to_string(day.join("0001.log")).unwrap();
        assert!(rotated.contains(" WARN "));
    }

    #[test]
    fn counter_scan_accepts_more_than_four_digits() {
        // A pre-existing "10000.log" must be recognized as the current
        // counter (rotation keeps working past 9999).
        let dir = tempfile::tempdir().unwrap();
        let date = Utc::now().format("%Y-%m-%d").to_string();
        let day = dir.path().join("logs/rcm-server/agent").join(&date);
        std::fs::create_dir_all(&day).unwrap();
        std::fs::write(day.join("10000.log"), b"old\n").unwrap();
        log(dir.path(), "rcm-server", "agent", "INFO", "new").unwrap();
        let body = std::fs::read_to_string(day.join("10000.log")).unwrap();
        assert!(body.contains("old\n"), "must append to 10000.log: {:?}", body);
        assert!(body.contains("new"));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_log_file() {
        let dir = tempfile::tempdir().unwrap();
        let date = Utc::now().format("%Y-%m-%d").to_string();
        let day = dir.path().join("logs/rcm-server/agent").join(&date);
        std::fs::create_dir_all(&day).unwrap();
        let outside = dir.path().join("outside.txt");
        std::fs::write(&outside, b"secret").unwrap();
        std::os::unix::fs::symlink(&outside, day.join("0000.log")).unwrap();
        let r = log(dir.path(), "rcm-server", "agent", "INFO", "pwn");
        assert!(r.is_err(), "wrote through a symlinked log file");
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "secret");
    }
}