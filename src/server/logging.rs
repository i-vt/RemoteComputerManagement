// src/server/logging.rs
use std::fs;
use std::path::{Path, PathBuf};
use std::io;
use chrono::Local;

const LOG_DIR: &str = "logs";
const MAX_SIZE_BYTES: u64 = 2048 * 1024 * 1024; // 2048 MB
const TARGET_SIZE_BYTES: u64 = 1500 * 1024 * 1024; // 1500 MB

/// Initializes the tracing subscriber with a timestamped file and stdout.
/// Returns a WorkerGuard that must be held by main() to flush logs on exit.
pub fn init() -> Result<tracing_appender::non_blocking::WorkerGuard, Box<dyn std::error::Error>> {
    // 1. Ensure logs directory exists
    if !Path::new(LOG_DIR).exists() {
        fs::create_dir(LOG_DIR)?;
    }

    // 2. Run cleanup before starting new log
    if let Err(e) = cleanup_logs() {
        eprintln!("[-] Log cleanup failed: {}", e);
    }

    // 3. Generate Filename: YYYYMMDD_HHMMSS_MS.log
    let now = Local::now();
    let filename = format!("{}.log", now.format("%Y%m%d_%H%M%S_%3f"));
    let file_path = Path::new(LOG_DIR).join(filename);

    eprintln!("[*] Logging to: {:?}", file_path);

    // 4. Create File Appender
    let file = fs::File::create(file_path)?;
    let (file_writer, guard) = tracing_appender::non_blocking(file);

    // 5. Configure Subscriber (Console + File)
    tracing_subscriber::fmt()
        .with_target(false) // Clean output
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .with_level(true)
        .with_timer(tracing_subscriber::fmt::time::LocalTime::rfc_3339())
        .with_writer(file_writer) // Write to file
        .init();

    // Note: To log to BOTH console and file, you would typically use a Layer. 
    // For this implementation, 'init()' captures global logging. 
    // If you want to see logs in console too during dev, simple printlns 
    // alongside tracing or a `teed` writer can be used, but this prioritizes the file.

    Ok(guard)
}

/// Enforces the storage limit.
fn cleanup_logs() -> io::Result<()> {
    let mut files: Vec<(PathBuf, u64, std::time::SystemTime)> = Vec::new();
    let mut total_size: u64 = 0;

    // 1. Scan directory
    for entry in fs::read_dir(LOG_DIR)? {
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

    // 2. Check Limit
    if total_size > MAX_SIZE_BYTES {
        eprintln!("[!] Log directory size ({} MB) exceeds limit. Cleaning up...", total_size / 1024 / 1024);

        // 3. Sort by oldest first
        files.sort_by(|a, b| a.2.cmp(&b.2));

        for (path, size, _) in files {
            if total_size <= TARGET_SIZE_BYTES {
                break;
            }

            // Delete file
            if let Err(e) = fs::remove_file(&path) {
                eprintln!("[-] Failed to delete old log {:?}: {}", path, e);
            } else {
                eprintln!("[*] Deleted old log: {:?}", path);
                total_size = total_size.saturating_sub(size);
            }
        }
    }

    Ok(())
}
