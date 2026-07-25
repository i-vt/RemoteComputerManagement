// src/server/logging.rs
use std::fs;
use std::path::{Path, PathBuf};
use std::io;
use chrono::Local;

use crate::config::config;

/// Initializes the tracing subscriber with a rolling daily file and stdout.
/// Returns a WorkerGuard that must be held by main() to flush logs on exit.
///
/// Uses tracing_appender::rolling::daily which creates a new log file each day.
/// This means cleanup_logs() can safely delete old files because the writer
/// always targets the current day's file, not an orphaned fd.
pub fn init() -> Result<tracing_appender::non_blocking::WorkerGuard, Box<dyn std::error::Error>> {
    // 1. Ensure logs directory exists
    let log_dir = &config().logging.log_dir;
    if !Path::new(log_dir).exists() {
        fs::create_dir(log_dir)?;
    }

    // 2. Run cleanup before starting new log
    if let Err(e) = cleanup_logs() {
        eprintln!("[-] Log cleanup failed: {}", e);
    }

    // 3. Rolling daily appender - creates a new file each day automatically.
    // File naming: logs/server.log.YYYY-MM-DD
    let file_appender = tracing_appender::rolling::daily(log_dir, "server.log");
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);

    eprintln!("[*] Logging to: {}/server.log.<date>", log_dir);

    // 4. Configure Subscriber
    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .with_level(true)
        .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339())
        .with_writer(file_writer)
        .init();

    Ok(guard)
}

/// Enforces the storage limit. Skips the current day's log file (which the
/// rolling appender is actively writing to). Public for periodic calls.
pub fn cleanup_logs() -> io::Result<()> {
    let cfg = &config().logging;
    let log_path = Path::new(&cfg.log_dir);
    if !log_path.exists() { return Ok(()); }

    // Current day's filename suffix - don't delete the active file
    let today = Local::now().format("%Y-%m-%d").to_string();

    let mut files: Vec<(PathBuf, u64, std::time::SystemTime)> = Vec::new();
    let mut total_size: u64 = 0;

    for entry in fs::read_dir(log_path)? {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_file() {
            let metadata = fs::metadata(&path)?;
            let size = metadata.len();
            let modified = metadata.modified()?;
            
            total_size += size;
            files.push((path, size, modified));
        }
    }

    if total_size > cfg.max_size_bytes {
        tracing::warn!("Log directory size ({} MB) exceeds limit, cleaning up...", total_size / 1024 / 1024);

        files.sort_by(|a, b| a.2.cmp(&b.2)); // oldest first

        for (path, size, _) in files {
            if total_size <= cfg.target_size_bytes {
                break;
            }

            // Skip the active log file
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if name.contains(&today) {
                continue;
            }

            if let Err(e) = fs::remove_file(&path) {
                tracing::warn!("Failed to delete old log {:?}: {}", path, e);
            } else {
                tracing::info!("Deleted old log: {:?}", path);
                total_size = total_size.saturating_sub(size);
            }
        }
    }

    Ok(())
}

/// Spawn a background tokio task that runs cleanup_logs() periodically.
/// Should be called once during server startup.
pub fn spawn_periodic_cleanup() {
    tokio::spawn(async {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(
            config().logging.cleanup_interval_secs,
        ));
        loop {
            interval.tick().await;
            if let Err(e) = cleanup_logs() {
                tracing::warn!("Periodic log cleanup failed: {}", e);
            }
        }
    });
}
