use std::fs::File;
use std::fs::OpenOptions; 
use std::io::{Read, Write};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::path::{Path, PathBuf};
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct RecursiveReport {
    pub root_path: String,
    pub total_files_found: usize,
    pub total_success: usize, 
    pub failed_downloads: Vec<(String, String)>, 
}

#[derive(Serialize, Deserialize)]
struct FileMetadata {
    original_filepath: String,
    filename: String,
    extension: String,
    permissions: String,
    filesize_bytes: u64,
    sha256: String,
}

pub fn find_all_files(root: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let root_path = Path::new(root);
    
    if !root_path.exists() { return files; }
    if root_path.is_file() {
        files.push(root_path.to_path_buf());
        return files;
    }

    let mut dirs_to_visit = vec![root_path.to_path_buf()];

    while let Some(current_dir) = dirs_to_visit.pop() {
        match std::fs::read_dir(&current_dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        if !path.is_symlink() { dirs_to_visit.push(path); }
                    } else {
                        files.push(path);
                    }
                }
            },
            Err(_) => continue,
        }
    }
    files
}

pub fn read_file_to_b64(path: &str) -> Result<(String, String), String> {
    let path_obj = Path::new(path);
    if !path_obj.exists() { return Err(format!("File not found: {:?}", path)); }

    let meta = std::fs::metadata(path_obj).map_err(|e| e.to_string())?;
    let perm_string = if meta.permissions().readonly() { "readonly" } else { "writable" }.to_string();

    // Stream the file in chunks to avoid loading multi-GB files into memory
    let mut file = File::open(path_obj).map_err(|e| e.to_string())?;
    let file_size = meta.len() as usize;

    // Hard cap: reject files that would exceed the agent's transfer budget.
    // Without this, downloading a multi-GB ISO or database exhausts RAM
    // (the raw bytes + the 4/3× Base64 output both live in memory).
    const MAX_FILE_SIZE: usize = 500 * 1024 * 1024; // 500MB
    if file_size > MAX_FILE_SIZE {
        return Err(format!("File too large ({} MB). Max is {} MB.",
            file_size / (1024 * 1024), MAX_FILE_SIZE / (1024 * 1024)));
    }

    // For files under 10MB (or zero-size), read all at once.
    //
    // Special handling for size == 0: Linux pseudo-files in /proc and /sys
    // (high-value targets like /proc/self/maps, /proc/cpuinfo, /sys/class/*)
    // report metadata.len() of 0 but contain real content. Using take(0+1)
    // would limit the read to 1 byte. For zero-size files, we read up to
    // 10MB without take() to get the actual content.
    if file_size < 10 * 1024 * 1024 {
        use std::io::Read;
        let mut buffer = Vec::with_capacity(file_size.max(4096));
        if file_size == 0 {
            // Pseudo-file: read without take() limit, but cap at 10MB
            file.take(10 * 1024 * 1024).read_to_end(&mut buffer).map_err(|e| e.to_string())?;
        } else {
            // Normal file: cap at metadata size + 1
            file.take((file_size as u64) + 1).read_to_end(&mut buffer).map_err(|e| e.to_string())?;
        }
        return Ok((BASE64.encode(buffer), perm_string));
    }

    // For large files, stream and encode in chunks to limit memory usage.
    //
    // CRITICAL: std::io::Read::read() does NOT guarantee filling the buffer.
    // If we encode a partial read that isn't a multiple of 3 bytes, the Base64
    // encoder appends padding ('=') mid-stream, corrupting the final output.
    // We accumulate a carryover of 0-2 leftover bytes between reads and only
    // encode complete 3-byte-aligned blocks.
    use base64::engine::general_purpose::STANDARD as B64;
    // Cap pre-allocation at 32MB. For a 500MB file, pre-allocating the full
    // ~666MB base64 output as a contiguous block can OOM the agent on memory-
    // constrained systems. String will grow incrementally beyond the initial cap.
    let prealloc = (file_size * 4 / 3 + 4).min(32 * 1024 * 1024);
    let mut b64_output = String::with_capacity(prealloc);
    let mut chunk = vec![0u8; 3 * 1024 * 1024];
    let mut carry: Vec<u8> = Vec::new(); // 0–2 leftover bytes from previous read
    let mut total_read: usize = 0;

    loop {
        let n = file.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 {
            // Final carryover (0–2 bytes) — encode with padding, this is the real end
            if !carry.is_empty() {
                b64_output.push_str(&B64.encode(&carry));
            }
            break;
        }

        total_read += n;
        // Guard against infinite streams (/dev/urandom, named pipes) or files
        // that grew since we checked metadata. Without this, the loop appends
        // to b64_output endlessly until the agent is OOM-killed.
        if total_read > MAX_FILE_SIZE {
            return Err(format!("File exceeded {} MB during read (possible infinite stream)",
                MAX_FILE_SIZE / (1024 * 1024)));
        }

        // Prepend any leftover bytes from the previous iteration
        let mut combined = std::mem::take(&mut carry);
        combined.extend_from_slice(&chunk[..n]);

        // Encode only the largest 3-byte-aligned prefix
        let aligned = (combined.len() / 3) * 3;
        b64_output.push_str(&B64.encode(&combined[..aligned]));

        // Save the 0–2 remainder bytes for the next iteration
        carry = combined[aligned..].to_vec();
    }
    Ok((b64_output, perm_string))
}

pub fn save_download_with_metadata(session_id: u32, original_path: &str, b64_data: &str, permissions: &str) -> Result<String, String> {
    let bytes = BASE64.decode(b64_data).map_err(|e| format!("B64 Error: {}", e))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let hash = hex::encode(hasher.finalize());
    let size = bytes.len() as u64;

    let path_obj = Path::new(original_path);
    let full_filename = path_obj.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or("unknown.bin".into());
    let (stem, extension) = match full_filename.rsplit_once('.') { Some((s, e)) => (s, e), None => (full_filename.as_str(), "") };

    let safe_stem: String = stem.chars().take(32).collect();
    let safe_ext: String = extension.chars().take(16).collect();
    let now = chrono::Utc::now();
    let timestamp = now.format("%Y%m%d_%H%M%S_%3f").to_string();
    let date_folder = now.format("%Y-%m-%d").to_string();

    let core_name = format!("{}_{}_{}", timestamp, session_id, safe_stem);
    let final_filename = if safe_ext.is_empty() { core_name.clone() } else { format!("{}.{}", core_name, safe_ext) };
    let json_filename = format!("{}_{}_metadata.json", core_name, safe_ext);

    // Organize: downloads/session_<id>/<date>/
    let download_dir = format!("downloads/session_{}/{}", session_id, date_folder);
    let _ = std::fs::create_dir_all(&download_dir);
    let save_path = format!("{}/{}", download_dir, final_filename);
    let json_path = format!("{}/{}", download_dir, json_filename);

    let mut file = File::create(&save_path).map_err(|e| e.to_string())?;
    file.write_all(&bytes).map_err(|e| e.to_string())?;

    let meta = FileMetadata {
        original_filepath: original_path.to_string(),
        filename: full_filename.clone(),
        extension: extension.to_string(),
        permissions: permissions.to_string(),
        filesize_bytes: size,
        sha256: hash,
    };
    
    std::fs::write(&json_path, serde_json::to_string_pretty(&meta).unwrap())
        .map_err(|e| e.to_string())?;

    Ok(format!("Saved: {}", save_path))
}

pub fn save_batch_file(batch_ts: &str, session_id: u32, root_name: &str, rel_path: &str, b64_data: &str) -> Result<String, String> {
    use std::path::Component;

    let safe_root: String = root_name.chars().filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-').take(32).collect();
    let folder_name = format!("{}_{}_{}", batch_ts, session_id, safe_root);
    let base_dir = Path::new("downloads").join(folder_name);

    // Use Path::components() to safely parse the untrusted path.
    // This handles all edge cases: backslashes, Unicode, drive letters,
    // UNC paths, URL-encoded segments, and mixed separators.
    let input_path = Path::new(rel_path);
    let mut safe_parts: Vec<&std::ffi::OsStr> = Vec::new();

    for component in input_path.components() {
        match component {
            Component::Normal(seg) => {
                // Only allow normal path segments — no dots, no drive letters
                safe_parts.push(seg);
            }
            Component::Prefix(_) => {
                return Err(format!("Rejected path with drive/UNC prefix: {}", rel_path));
            }
            Component::RootDir => {
                // Leading `/` or `\` — skip but don't error (common in agent paths)
            }
            Component::CurDir => {
                // `.` — skip
            }
            Component::ParentDir => {
                // `..` — reject entirely, don't just skip
                return Err(format!("Rejected path with parent traversal: {}", rel_path));
            }
        }
    }

    if safe_parts.is_empty() {
        return Err(format!("Path resolved to empty after sanitization: {}", rel_path));
    }

    // Build the final path from only the safe normal components
    let mut final_path = base_dir.clone();
    for part in &safe_parts {
        final_path = final_path.join(part);
    }

    // Create ONLY the base directory (fully controlled by us), canonicalize it,
    // then verify containment BEFORE creating any attacker-influenced subdirs.
    // The old code created all directories first and then canonicalized, which
    // meant the canonicalize check was bypassed if the target dir didn't exist
    // (the original bug) or an attacker could trigger arbitrary directory creation
    // via symlink segments even when the file write was prevented.
    std::fs::create_dir_all(&base_dir).map_err(|e| format!("Create base dir: {}", e))?;
    let canonical_base = std::fs::canonicalize(&base_dir)
        .map_err(|e| format!("Cannot canonicalize base dir: {}", e))?;

    // Pre-creation symlink check: catches existing symlinks in the path.
    // NOTE: This check alone has a TOCTOU gap — paths that don't exist yet
    // return false from exists(), skipping the check. A concurrent attacker
    // could race to create a symlink after create_dir_all below. The post-
    // creation recheck below closes this window.
    let mut walk = canonical_base.clone();
    for part in &safe_parts {
        walk = walk.join(part);
        if let Ok(meta) = walk.symlink_metadata() {
            if meta.file_type().is_symlink() {
                return Err(format!("Symlink detected in path: {}", walk.display()));
            }
        }
    }

    // Now create the subdirectories
    if let Some(parent) = final_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("Create parent dir: {}", e))?;
    }

    // Post-creation recheck: directories now exist, so symlink_metadata can
    // detect any symlinks that were raced in during create_dir_all.
    let mut walk2 = canonical_base.clone();
    for part in &safe_parts {
        walk2 = walk2.join(part);
        if let Ok(meta) = walk2.symlink_metadata() {
            if meta.file_type().is_symlink() {
                return Err(format!("Symlink detected in path (post-create): {}", walk2.display()));
            }
        }
    }

    // Final belt-and-suspenders: canonicalize the now-existing parent and recheck
    let canonical_parent = std::fs::canonicalize(final_path.parent().unwrap_or(&base_dir))
        .map_err(|e| format!("Cannot canonicalize target dir: {}", e))?;
    if !canonical_parent.starts_with(&canonical_base) {
        return Err(format!("Path escapes base directory: {}", rel_path));
    }

    // Stream the base64 decode to disk in chunks to avoid holding both
    // the entire base64 string (~N bytes) and decoded bytes (~0.75N) in
    // memory simultaneously. For a 500MB file, this saves ~375MB of RAM.
    let mut file = File::create(&final_path).map_err(|e| format!("Create Error: {}", e))?;
    {
        // Process base64 in 64KB input chunks (produces ~48KB output each)
        const CHUNK_SIZE: usize = 65536; // must be multiple of 4 for base64
        let mut offset = 0;
        while offset < b64_data.len() {
            let end = (offset + CHUNK_SIZE).min(b64_data.len());
            // Ensure we don't split in the middle of a base64 group (4-char boundary)
            let end = if end < b64_data.len() { (end / 4) * 4 } else { end };
            if end <= offset { break; }
            let chunk_bytes = BASE64.decode(&b64_data[offset..end])
                .map_err(|e| format!("B64 Error at offset {}: {}", offset, e))?;
            file.write_all(&chunk_bytes).map_err(|e| format!("Write Error: {}", e))?;
            offset = end;
        }
    }

    Ok(final_path.to_string_lossy().to_string())
}

// Append to progress.txt
pub fn append_progress(batch_ts: &str, session_id: u32, root_name: &str, message: &str) {
    let safe_root: String = root_name.chars().filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-').take(32).collect();
    let folder_name = format!("{}_{}_{}", batch_ts, session_id, safe_root);
    let base_dir = Path::new("downloads").join(folder_name);
    
    // Ensure dir exists
    let _ = std::fs::create_dir_all(&base_dir);
    let progress_path = base_dir.join("progress.txt");

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(progress_path) {
        let _ = writeln!(file, "{}", message);
    }
}

// Remove progress.txt
pub fn remove_progress(batch_ts: &str, session_id: u32, root_name: &str) {
    let safe_root: String = root_name.chars().filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-').take(32).collect();
    let folder_name = format!("{}_{}_{}", batch_ts, session_id, safe_root);
    let progress_path = Path::new("downloads").join(folder_name).join("progress.txt");
    
    let _ = std::fs::remove_file(progress_path);
}

pub fn save_batch_report(batch_ts: &str, session_id: u32, root_name: &str, json_data: &str) -> Result<String, String> {
    let safe_root: String = root_name.chars().filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-').take(32).collect();
    let folder_name = format!("{}_{}_{}", batch_ts, session_id, safe_root);
    let base_dir = Path::new("downloads").join(folder_name);
    std::fs::create_dir_all(&base_dir)
        .map_err(|e| format!("Failed to create download directory: {}", e))?;

    // Clean up progress file before writing report (best-effort)
    let progress_path = base_dir.join("progress.txt");
    let _ = std::fs::remove_file(progress_path);

    let filename = format!("{}_{}_{}_metadata.json", batch_ts, session_id, safe_root);
    let file_path = base_dir.join(filename);

    std::fs::write(&file_path, json_data).map_err(|e| e.to_string())?;
    Ok(file_path.to_string_lossy().to_string())
}

pub fn write_file_simple(path: &str, b64_data: &str) -> Result<(), String> {
    let bytes = BASE64.decode(b64_data).map_err(|e| format!("B64 Error: {}", e))?;
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create parent directory: {}", e))?;
    }
    let mut file = File::create(path).map_err(|e| e.to_string())?;
    file.write_all(&bytes).map_err(|e| e.to_string())?;
    Ok(())
}
