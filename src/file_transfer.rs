use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::path::{Path, PathBuf, Component};
use std::ffi::{OsStr, OsString};
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use chrono::Utc;
use hex;

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

// ── Constants ───────────────────────────────────────────────────────────────

const MAX_FILE_SIZE: u64 = 500 * 1024 * 1024;          // 500 MB
const MAX_TOTAL_FILE_SIZE: u64 = 500 * 1024 * 1024;    // 500 MB
const MAX_CHUNK_B64_BYTES: usize = 16 * 1024 * 1024;   // ~12 MB decoded
const SMALL_FILE_THRESHOLD: u64 = 10 * 1024 * 1024;    // 10 MB

// ── Path sanitization helpers ─────────────────────────────────────────────────

fn sanitize_batch_ts(batch_ts: &str) -> String {
    let s: String = batch_ts
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
        .take(64)
        .collect();
    if s == "." || s == ".." {
        "invalid".to_string()
    } else {
        s
    }
}

fn sanitize_root_name(root_name: &str) -> String {
    let s: String = root_name
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
        .take(32)
        .collect();
    if s == "." || s == ".." {
        "invalid".to_string()
    } else {
        s
    }
}

/// Strip characters that are invalid on Windows *and* Unix so the filename
/// is portable and cannot be used for path traversal.
fn sanitize_filename_component(s: &str, max_len: usize) -> String {
    let invalid = ['/', '\\', '\0', ':', '*', '?', '"', '<', '>', '|'];
    s.chars()
        .filter(|c| !invalid.contains(c))
        .take(max_len)
        .collect()
}

/// Verify that the hardcoded `downloads` root is not a symlink and return
/// its canonical path.
fn verify_downloads_root() -> Result<PathBuf, String> {
    let root = Path::new("downloads");
    if let Ok(meta) = root.symlink_metadata() {
        if meta.file_type().is_symlink() {
            return Err("downloads root is a symlink".to_string());
        }
    }
    std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
    std::fs::canonicalize(root).map_err(|e| e.to_string())
}

/// Create a directory and all its parents, but refuse to follow or create
/// through symlinks.  Pre- and post-creation checks catch races.
fn ensure_safe_dir(path: &Path) -> Result<(), String> {
    // Fix: single metadata call eliminates TOCTOU between exists()/is_symlink()/is_dir()
    if let Ok(meta) = path.symlink_metadata() {
        if meta.file_type().is_symlink() {
            return Err(format!("Symlink detected at directory: {}", path.display()));
        }
        if !meta.is_dir() {
            return Err(format!("Path exists but is not a directory: {}", path.display()));
        }
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        ensure_safe_dir(parent)?;
    }

    std::fs::create_dir(path).map_err(|e| format!("Create dir: {}", e))?;

    if let Ok(meta) = path.symlink_metadata() {
        if meta.file_type().is_symlink() {
            return Err(format!("Race: symlink detected at directory: {}", path.display()));
        }
    }
    Ok(())
}

// ── Permission helpers ────────────────────────────────────────────────────────

#[cfg(unix)]
fn apply_permissions(path: &Path, permissions: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if permissions == "readonly" { 0o444 } else { 0o644 };
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms).map_err(|e| e.to_string())
}

#[cfg(not(unix))]
fn apply_permissions(_path: &Path, _permissions: &str) -> Result<(), String> {
    // Windows std lacks a cross-platform way to construct a readonly Permissions.
    // Use platform-specific APIs (e.g. SetFileAttributesW) if this is required.
    Ok(())
}

// ── Hard-link detection helper ───────────────────────────────────────────────

#[cfg(unix)]
fn is_hardlink(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    meta.is_file() && meta.nlink() > 1
}

#[cfg(not(unix))]
fn is_hardlink(_meta: &std::fs::Metadata) -> bool {
    false
}

// ── Safe path builder ─────────────────────────────────────────────────────────

/// Build a safe path under `base_dir` from `rel_path`, validating components
/// and checking for symlinks and hard links at every step.  Creates missing
/// directories along the way but refuses to follow or create through symlinks.
///
/// Returns the resolved final path (the file itself may not exist yet).
fn build_safe_path(base_dir: &Path, rel_path: &str) -> Result<PathBuf, String> {
    let input_path = Path::new(rel_path);
    let mut safe_parts: Vec<OsString> = Vec::new();
    for component in input_path.components() {
        match component {
            Component::Normal(seg) => {
                let seg_str = seg.to_string_lossy();
                let sanitized = sanitize_filename_component(&seg_str, 255);
                if sanitized.is_empty() {
                    return Err(format!("Path component sanitized to empty: {}", rel_path));
                }
                safe_parts.push(OsString::from(sanitized));
            }
            Component::Prefix(_) => {
                return Err(format!("Rejected path with drive/UNC prefix: {}", rel_path));
            }
            // Fix: reject absolute paths instead of silently skipping the root
            Component::RootDir => {
                return Err(format!("Rejected absolute path: {}", rel_path));
            }
            Component::CurDir => { /* skip */ }
            Component::ParentDir => {
                return Err(format!("Rejected path with parent traversal: {}", rel_path));
            }
        }
    }
    if safe_parts.is_empty() {
        return Err(format!("Path resolved to empty after sanitization: {}", rel_path));
    }

    // Ensure base exists and is canonical, and is not itself a symlink
    if let Ok(meta) = base_dir.symlink_metadata() {
        if meta.file_type().is_symlink() {
            return Err(format!("Symlink detected at base directory: {}", base_dir.display()));
        }
    }
    std::fs::create_dir_all(base_dir)
        .map_err(|e| format!("Create base dir: {}", e))?;
    let canonical_base = std::fs::canonicalize(base_dir)
        .map_err(|e| format!("Cannot canonicalize base dir: {}", e))?;

    // Walk and create directories, checking for symlinks at each step
    let mut walk = canonical_base.clone();
    let last_idx = safe_parts.len().saturating_sub(1);
    for (i, part) in safe_parts.iter().enumerate() {
        walk = walk.join(part);

        // If this component already exists, it must not be a symlink or hard link
        if let Ok(meta) = walk.symlink_metadata() {
            if meta.file_type().is_symlink() {
                return Err(format!("Symlink detected in path: {}", walk.display()));
            }
            if is_hardlink(&meta) {
                return Err(format!("Hard link detected in path: {}", walk.display()));
            }
        }

        if i < last_idx {
            // Intermediate component: must be a directory (or created as one)
            if !walk.exists() {
                std::fs::create_dir(&walk)
                    .map_err(|e| format!("Create dir '{}': {}", walk.display(), e))?;
                // Post-creation race check
                if let Ok(meta) = walk.symlink_metadata() {
                    if meta.file_type().is_symlink() {
                        return Err(format!("Race: symlink detected in path: {}", walk.display()));
                    }
                }
            } else if !walk.is_dir() {
                return Err(format!("Path component is not a directory: {}", walk.display()));
            }
        }
    }

    // Final path must not be a symlink or hard link (last-ditch check before open)
    if let Ok(meta) = walk.symlink_metadata() {
        if meta.file_type().is_symlink() {
            return Err(format!("Symlink detected at target path: {}", walk.display()));
        }
        if is_hardlink(&meta) {
            return Err(format!("Hard link detected at target path: {}", walk.display()));
        }
    }

    // Verify containment via the parent (final file may not exist yet)
    let parent = walk.parent().unwrap_or(&canonical_base);
    let canonical_parent = std::fs::canonicalize(parent)
        .map_err(|e| format!("Cannot canonicalize target dir: {}", e))?;
    if !canonical_parent.starts_with(&canonical_base) {
        return Err(format!("Path escapes base directory: {}", rel_path));
    }

    Ok(walk)
}

// ── File enumeration & reading ────────────────────────────────────────────────

pub fn find_all_files(root: &str) -> (Vec<PathBuf>, Vec<String>) {
    let mut files = Vec::new();
    let mut errors = Vec::new();
    let root_path = Path::new(root);
    
    // Fix: eliminate TOCTOU by using a single symlink_metadata call instead of exists()
    let root_meta = match root_path.symlink_metadata() {
        Ok(meta) => meta,
        Err(e) => {
            errors.push(format!("Root path does not exist or is inaccessible: {}", e));
            return (files, errors);
        }
    };
    if root_meta.file_type().is_symlink() {
        errors.push(format!("Root path is a symlink: {}", root_path.display()));
        return (files, errors);
    }
    if root_meta.is_file() {
        files.push(root_path.to_path_buf());
        return (files, errors);
    }
    if !root_meta.is_dir() {
        errors.push(format!("Root path is not a file or directory: {}", root_path.display()));
        return (files, errors);
    }

    let mut dirs_to_visit = vec![root_path.to_path_buf()];

    while let Some(current_dir) = dirs_to_visit.pop() {
        match std::fs::read_dir(&current_dir) {
            Ok(entries) => {
                for entry in entries {
                    match entry {
                        Ok(e) => {
                            let path = e.path();
                            // Fix: use DirEntry::file_type() to avoid following symlinks
                            match e.file_type() {
                                Ok(ft) => {
                                    if ft.is_symlink() {
                                        continue;
                                    }
                                    if ft.is_dir() {
                                        dirs_to_visit.push(path);
                                    } else if ft.is_file() {
                                        files.push(path);
                                    }
                                }
                                Err(e) => {
                                    errors.push(format!("Failed to get file type for {}: {}", path.display(), e));
                                }
                            }
                        }
                        Err(e) => {
                            errors.push(format!("Failed to read entry in {}: {}", current_dir.display(), e));
                        }
                    }
                }
            },
            Err(e) => {
                errors.push(format!("Failed to read directory {}: {}", current_dir.display(), e));
            }
        }
    }
    (files, errors)
}

/// Streaming variant of `find_all_files`.
///
/// Yields each file path to the caller via `callback` as soon as it is
/// discovered, rather than building a massive `Vec<PathBuf>` upfront.
/// This keeps memory usage O(1) with respect to file count — critical
/// for directories such as `C:\Users\<user>` that can contain 500 K+
/// files.
///
/// The callback is invoked synchronously from the walker; if it returns
/// `false` the walk aborts immediately.
///
/// Returns the list of non-fatal errors encountered (permission denied,
/// etc.) after the walk completes or is aborted.
pub fn find_all_files_cb<F>(root: &str, mut callback: F) -> Vec<String>
where
    F: FnMut(&Path) -> bool,
{
    let mut errors = Vec::new();
    let root_path = Path::new(root);

    let root_meta = match root_path.symlink_metadata() {
        Ok(meta) => meta,
        Err(e) => {
            errors.push(format!("Root path does not exist or is inaccessible: {}", e));
            return errors;
        }
    };
    if root_meta.file_type().is_symlink() {
        errors.push(format!("Root path is a symlink: {}", root_path.display()));
        return errors;
    }
    if root_meta.is_file() {
        let _ = callback(root_path);
        return errors;
    }
    if !root_meta.is_dir() {
        errors.push(format!("Root path is not a file or directory: {}", root_path.display()));
        return errors;
    }

    let mut dirs_to_visit = vec![root_path.to_path_buf()];

    while let Some(current_dir) = dirs_to_visit.pop() {
        match std::fs::read_dir(&current_dir) {
            Ok(entries) => {
                for entry in entries {
                    match entry {
                        Ok(e) => {
                            let path = e.path();
                            match e.file_type() {
                                Ok(ft) => {
                                    if ft.is_symlink() {
                                        continue;
                                    }
                                    if ft.is_dir() {
                                        dirs_to_visit.push(path);
                                    } else if ft.is_file() {
                                        if !callback(&path) {
                                            return errors; // caller aborted
                                        }
                                    }
                                }
                                Err(e) => {
                                    errors.push(format!(
                                        "Failed to get file type for {}: {}",
                                        path.display(), e
                                    ));
                                }
                            }
                        }
                        Err(e) => {
                            errors.push(format!(
                                "Failed to read entry in {}: {}",
                                current_dir.display(), e
                            ));
                        }
                    }
                }
            }
            Err(e) => {
                errors.push(format!(
                    "Failed to read directory {}: {}",
                    current_dir.display(), e
                ));
            }
        }
    }
    errors
}

pub fn read_file_to_b64(path: &str) -> Result<(String, String), String> {
    let path_obj = Path::new(path);
    if !path_obj.exists() { return Err(format!("File not found: {:?}", path)); }

    if let Ok(meta) = path_obj.symlink_metadata() {
        if meta.file_type().is_symlink() {
            return Err(format!("Symlink detected: {:?}", path));
        }
    }

    let meta = std::fs::metadata(path_obj).map_err(|e| e.to_string())?;
    let perm_string = if meta.permissions().readonly() { "readonly" } else { "writable" }.to_string();

    let mut file = File::open(path_obj).map_err(|e| e.to_string())?;
    let file_size_u64 = meta.len();

    if file_size_u64 > MAX_FILE_SIZE {
        return Err(format!("File too large ({} MB). Max is {} MB.",
            file_size_u64 / (1024 * 1024), MAX_FILE_SIZE / (1024 * 1024)));
    }

    if file_size_u64 < SMALL_FILE_THRESHOLD {
        let cap = (file_size_u64 as usize).max(4096);
        let mut buffer = Vec::with_capacity(cap);
        let bytes_read = if file_size_u64 == 0 {
            file.take(10 * 1024 * 1024).read_to_end(&mut buffer).map_err(|e| e.to_string())?
        } else {
            file.take(file_size_u64 + 1).read_to_end(&mut buffer).map_err(|e| e.to_string())?
        };
        // Fix: detect files that changed size between metadata() and read
        if file_size_u64 > 0 && bytes_read as u64 != file_size_u64 {
            return Err(format!("File size changed during read: expected {}, got {}", file_size_u64, bytes_read));
        }
        return Ok((BASE64.encode(buffer), perm_string));
    }

    use base64::engine::general_purpose::STANDARD as B64;
    let file_size = file_size_u64 as usize;
    let prealloc = (file_size * 4 / 3 + 4).min(32 * 1024 * 1024);
    let mut b64_output = String::with_capacity(prealloc);
    let mut chunk = vec![0u8; 3 * 1024 * 1024];
    let mut carry: Vec<u8> = Vec::new();
    let mut total_read: u64 = 0;

    loop {
        let n = file.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 {
            if !carry.is_empty() {
                b64_output.push_str(&B64.encode(&carry));
            }
            break;
        }

        total_read += n as u64;
        if total_read > MAX_FILE_SIZE {
            return Err(format!("File exceeded {} MB during read (possible infinite stream)",
                MAX_FILE_SIZE / (1024 * 1024)));
        }

        let mut combined = std::mem::take(&mut carry);
        combined.extend_from_slice(&chunk[..n]);

        let aligned = (combined.len() / 3) * 3;
        b64_output.push_str(&B64.encode(&combined[..aligned]));

        carry = combined[aligned..].to_vec();
    }
    Ok((b64_output, perm_string))
}

// ── Single-file save with metadata ────────────────────────────────────────────

pub fn save_download_with_metadata(session_id: u32, original_path: &str, b64_data: &str, permissions: &str) -> Result<String, String> {
    let bytes = BASE64.decode(b64_data).map_err(|e| format!("B64 Error: {}", e))?;
    // Fix: enforce decoded size limit
    if bytes.len() as u64 > MAX_TOTAL_FILE_SIZE {
        return Err(format!("Decoded file exceeds {} MB limit", MAX_TOTAL_FILE_SIZE / (1024 * 1024)));
    }
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let hash = hex::encode(hasher.finalize());
    let size = bytes.len() as u64;

    let path_obj = Path::new(original_path);
    let full_filename = path_obj.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or("unknown.bin".into());
    
    // Fix: don't treat a leading dot as an extension separator
    let (stem, extension) = match full_filename.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s, e),
        _ => (full_filename.as_str(), ""),
    };

    let safe_stem = sanitize_filename_component(stem, 32);
    let safe_ext = sanitize_filename_component(extension, 16);
    let now = Utc::now();
    let timestamp = now.format("%Y%m%d_%H%M%S_%.3f").to_string();
    let date_folder = now.format("%Y-%m-%d").to_string();

    let core_name = format!("{}_{}_{}", timestamp, session_id, safe_stem);
    let final_filename = if safe_ext.is_empty() { core_name.clone() } else { format!("{}.{}", core_name, safe_ext) };
    let json_filename = if safe_ext.is_empty() {
        format!("{}_metadata.json", core_name)
    } else {
        format!("{}_{}_metadata.json", core_name, safe_ext)
    };

    // Fix: use the canonical downloads root, not a relative string
    let canonical_downloads = verify_downloads_root()?;
    let download_dir = canonical_downloads.join(format!("session_{}", session_id)).join(&date_folder);
    ensure_safe_dir(&download_dir)?;

    // Verify containment: canonicalized download_dir must be under canonicalized downloads
    let canonical_download = std::fs::canonicalize(&download_dir)
        .map_err(|e| format!("Cannot canonicalize download dir: {}", e))?;
    if !canonical_download.starts_with(&canonical_downloads) {
        return Err("Download directory escapes base".to_string());
    }

    let save_path = download_dir.join(&final_filename);
    let json_path = download_dir.join(&json_filename);

    // Fix: reject symlinks and hard links at the target path
    if let Ok(meta) = save_path.symlink_metadata() {
        if meta.file_type().is_symlink() {
            return Err("Symlink detected at save path; refusing to write".to_string());
        }
        if is_hardlink(&meta) {
            return Err("Hard link detected at save path; refusing to write".to_string());
        }
    }
    if let Ok(meta) = json_path.symlink_metadata() {
        if meta.file_type().is_symlink() {
            return Err("Symlink detected at metadata path; refusing to write".to_string());
        }
        if is_hardlink(&meta) {
            return Err("Hard link detected at metadata path; refusing to write".to_string());
        }
    }

    let mut file = File::create(&save_path).map_err(|e| e.to_string())?;
    file.write_all(&bytes).map_err(|e| e.to_string())?;

    // Fix: apply the original permissions to the new file
    apply_permissions(&save_path, permissions)?;

    let meta = FileMetadata {
        original_filepath: original_path.to_string(),
        filename: full_filename.clone(),
        extension: extension.to_string(),
        permissions: permissions.to_string(),
        filesize_bytes: size,
        sha256: hash,
    };
    
    std::fs::write(&json_path, serde_json::to_string_pretty(&meta).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;

    Ok(format!("Saved: {}", save_path.display()))
}

// ── Chunked file transfer ─────────────────────────────────────────────────────

pub fn save_file_chunk(
    batch_ts: &str,
    session_id: u32,
    root_name: &str,
    rel_path: &str,
    chunk_idx: u64,
    total_chunks: u64,
    b64_data: &str,
) -> Result<bool, String> {
    use std::io::Write;

    if total_chunks == 0 {
        return Err("total_chunks cannot be zero".to_string());
    }
    if chunk_idx >= total_chunks {
        return Err(format!("chunk_idx {} out of bounds (total {})", chunk_idx, total_chunks));
    }
    if b64_data.len() > MAX_CHUNK_B64_BYTES {
        return Err(format!("Chunk too large: {} bytes (max {} MB)", b64_data.len(), MAX_CHUNK_B64_BYTES / (1024 * 1024)));
    }

    // Fix: use the canonical downloads root to avoid symlink races
    let canonical_downloads = verify_downloads_root()?;
    let safe_batch = sanitize_batch_ts(batch_ts);
    let safe_root = sanitize_root_name(root_name);
    let folder_name = format!("{}_{}_{}", safe_batch, session_id, safe_root);
    let base_dir = canonical_downloads.join(&folder_name);

    let final_path = build_safe_path(&base_dir, rel_path)?;

    // Race-harden: one last symlink/hardlink check right before we open the file
    if let Ok(meta) = final_path.symlink_metadata() {
        if meta.file_type().is_symlink() {
            return Err(format!("Race: symlink detected at target path: {}", final_path.display()));
        }
        if is_hardlink(&meta) {
            return Err(format!("Race: hard link detected at target path: {}", final_path.display()));
        }
    }

    // Fix: enforce in-order chunk delivery and total_chunks consistency
    let mut state_path = final_path.as_os_str().to_os_string();
    state_path.push(".chunk_state");
    let state_path = PathBuf::from(state_path);

    if let Ok(meta) = state_path.symlink_metadata() {
        if meta.file_type().is_symlink() {
            return Err(format!("Symlink detected at chunk state path: {}", state_path.display()));
        }
        if is_hardlink(&meta) {
            return Err(format!("Hard link detected at chunk state path: {}", state_path.display()));
        }
    }

    if chunk_idx > 0 {
        match std::fs::read_to_string(&state_path) {
            Ok(state) => {
                let parts: Vec<&str> = state.trim().split(',').collect();
                if parts.len() != 2 {
                    return Err("Corrupt chunk state".to_string());
                }
                let expected: u64 = parts[0].parse().map_err(|_| "Corrupt chunk state".to_string())?;
                let stored_total: u64 = parts[1].parse().map_err(|_| "Corrupt chunk state".to_string())?;
                if chunk_idx != expected {
                    return Err(format!("Out-of-order chunk: expected {}, got {}", expected, chunk_idx));
                }
                if total_chunks != stored_total {
                    return Err(format!("Total chunks mismatch: expected {}, got {}", stored_total, total_chunks));
                }
            }
            Err(_) => {
                return Err("Missing chunk state; chunk 0 must be sent first".to_string());
            }
        }
    }

    let chunk_bytes = BASE64.decode(b64_data)
        .map_err(|e| format!("Base64 decode chunk {}/{}: {}", chunk_idx, total_chunks, e))?;

    // Fix: enforce total reconstructed file size limit, ignoring existing file size for chunk 0
    // because File::create truncates the file.
    let current_size = if final_path.exists() && chunk_idx != 0 {
        std::fs::metadata(&final_path).map(|m| m.len()).unwrap_or(0)
    } else {
        0
    };
    if current_size + chunk_bytes.len() as u64 > MAX_TOTAL_FILE_SIZE {
        return Err(format!("Total file size would exceed {} MB", MAX_TOTAL_FILE_SIZE / (1024 * 1024)));
    }

    let mut file = if chunk_idx == 0 {
        File::create(&final_path).map_err(|e| format!("Create: {}", e))?
    } else {
        OpenOptions::new()
            .append(true)
            .open(&final_path)
            .map_err(|e| format!("Append open: {}", e))?
    };
    file.write_all(&chunk_bytes).map_err(|e| format!("Write: {}", e))?;

    // Atomic state update via temp file + rename
    let mut temp_state = state_path.as_os_str().to_os_string();
    temp_state.push(".tmp");
    let temp_state = PathBuf::from(temp_state);

    if let Ok(meta) = temp_state.symlink_metadata() {
        if meta.file_type().is_symlink() {
            return Err(format!("Symlink detected at temp chunk state path: {}", temp_state.display()));
        }
        if is_hardlink(&meta) {
            return Err(format!("Hard link detected at temp chunk state path: {}", temp_state.display()));
        }
    }

    std::fs::write(&temp_state, format!("{},{}", chunk_idx + 1, total_chunks))
        .map_err(|e| format!("Write temp chunk state: {}", e))?;
    std::fs::rename(&temp_state, &state_path)
        .map_err(|e| format!("Rename chunk state: {}", e))?;

    // Fix: `total_chunks > 0` and `chunk_idx < total_chunks` guarantees no overflow
    let is_final = chunk_idx + 1 >= total_chunks;
    if is_final {
        if let Ok(meta) = state_path.symlink_metadata() {
            if meta.file_type().is_symlink() {
                return Err(format!("Symlink detected at chunk state path: {}", state_path.display()));
            }
        }
        let _ = std::fs::remove_file(&state_path);
        let _ = std::fs::remove_file(&temp_state);
    }

    Ok(is_final)
}

pub fn save_batch_file(batch_ts: &str, session_id: u32, root_name: &str, rel_path: &str, b64_data: &str) -> Result<String, String> {
    let canonical_downloads = verify_downloads_root()?;
    let safe_batch = sanitize_batch_ts(batch_ts);
    let safe_root = sanitize_root_name(root_name);
    let folder_name = format!("{}_{}_{}", safe_batch, session_id, safe_root);
    let base_dir = canonical_downloads.join(&folder_name);

    let final_path = build_safe_path(&base_dir, rel_path)?;

    // Race-harden: one last symlink/hardlink check right before we open the file
    if let Ok(meta) = final_path.symlink_metadata() {
        if meta.file_type().is_symlink() {
            return Err(format!("Race: symlink detected at target path: {}", final_path.display()));
        }
        if is_hardlink(&meta) {
            return Err(format!("Race: hard link detected at target path: {}", final_path.display()));
        }
    }

    const CHUNK_SIZE: usize = 65536;
    const _: () = assert!(CHUNK_SIZE >= 4 && CHUNK_SIZE % 4 == 0, "CHUNK_SIZE must be >= 4 and a multiple of 4");

    let mut file = File::create(&final_path).map_err(|e| format!("Create Error: {}", e))?;
    let mut total_decoded: u64 = 0;
    let write_result = (|| {
        let mut offset = 0;
        while offset < b64_data.len() {
            let end = (offset + CHUNK_SIZE).min(b64_data.len());
            let end = if end < b64_data.len() { (end / 4) * 4 } else { end };
            if end <= offset { break; }
            let chunk_bytes = BASE64.decode(&b64_data[offset..end])
                .map_err(|e| format!("B64 Error at offset {}: {}", offset, e))?;
            
            total_decoded += chunk_bytes.len() as u64;
            if total_decoded > MAX_TOTAL_FILE_SIZE {
                return Err(format!("Total file size exceeded {} MB", MAX_TOTAL_FILE_SIZE / (1024 * 1024)));
            }
            
            file.write_all(&chunk_bytes).map_err(|e| format!("Write Error: {}", e))?;
            offset = end;
        }
        Ok(())
    })();

    if write_result.is_err() {
        let _ = std::fs::remove_file(&final_path);
    }
    write_result?;

    Ok(final_path.to_string_lossy().to_string())
}

pub fn append_progress(batch_ts: &str, session_id: u32, root_name: &str, message: &str) -> Result<(), String> {
    let canonical_downloads = verify_downloads_root()?;
    let safe_batch = sanitize_batch_ts(batch_ts);
    let safe_root = sanitize_root_name(root_name);
    let folder_name = format!("{}_{}_{}", safe_batch, session_id, safe_root);
    let base_dir = canonical_downloads.join(&folder_name);
    
    ensure_safe_dir(&base_dir)?;
    let progress_path = base_dir.join("progress.txt");

    // Fix: reject symlinks and hard links before opening
    if let Ok(meta) = progress_path.symlink_metadata() {
        if meta.file_type().is_symlink() {
            return Err("Progress path is a symlink; refusing to append".to_string());
        }
        if is_hardlink(&meta) {
            return Err("Progress path is a hard link; refusing to append".to_string());
        }
    }

    let mut file = OpenOptions::new().create(true).append(true).open(&progress_path)
        .map_err(|e| e.to_string())?;
    writeln!(file, "{}", message).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn remove_progress(batch_ts: &str, session_id: u32, root_name: &str) -> Result<(), String> {
    let canonical_downloads = verify_downloads_root()?;
    let safe_batch = sanitize_batch_ts(batch_ts);
    let safe_root = sanitize_root_name(root_name);
    let folder_name = format!("{}_{}_{}", safe_batch, session_id, safe_root);
    let progress_path = canonical_downloads.join(&folder_name).join("progress.txt");
    
    if let Ok(meta) = progress_path.symlink_metadata() {
        if meta.file_type().is_symlink() {
            return Err("Progress path is a symlink; refusing to remove".to_string());
        }
        if is_hardlink(&meta) {
            return Err("Progress path is a hard link; refusing to remove".to_string());
        }
    }
    std::fs::remove_file(&progress_path).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn save_batch_report(batch_ts: &str, session_id: u32, root_name: &str, json_data: &str) -> Result<String, String> {
    let canonical_downloads = verify_downloads_root()?;
    let safe_batch = sanitize_batch_ts(batch_ts);
    let safe_root = sanitize_root_name(root_name);
    let folder_name = format!("{}_{}_{}", safe_batch, session_id, safe_root);
    let base_dir = canonical_downloads.join(&folder_name);
    ensure_safe_dir(&base_dir)?;

    // Clean up progress file before writing report (best-effort)
    let progress_path = base_dir.join("progress.txt");
    if let Ok(meta) = progress_path.symlink_metadata() {
        if meta.file_type().is_symlink() {
            return Err("Progress path is a symlink; refusing to remove".to_string());
        }
        if is_hardlink(&meta) {
            return Err("Progress path is a hard link; refusing to remove".to_string());
        }
    }
    let _ = std::fs::remove_file(&progress_path);

    let filename = format!("{}.json", safe_root);
    let file_path = base_dir.join(&filename);

    // Fix: reject symlinks and hard links at the report path
    if let Ok(meta) = file_path.symlink_metadata() {
        if meta.file_type().is_symlink() {
            return Err("Report path is a symlink; refusing to write".to_string());
        }
        if is_hardlink(&meta) {
            return Err("Report path is a hard link; refusing to write".to_string());
        }
    }

    std::fs::write(&file_path, json_data).map_err(|e| e.to_string())?;
    Ok(file_path.to_string_lossy().to_string())
}

/// Write a decoded file relative to `base_dir`.  The path must be relative and
/// must not escape `base_dir`.  Symlinks and hard links are rejected.
pub fn write_file_simple(base_dir: &str, rel_path: &str, b64_data: &str) -> Result<(), String> {
    // Reject paths with parent traversal or absolute components
    for component in Path::new(rel_path).components() {
        match component {
            Component::ParentDir => {
                return Err("Path contains parent traversal (..)".to_string());
            }
            Component::Prefix(_) | Component::RootDir => {
                return Err("Path must be relative".to_string());
            }
            _ => {}
        }
    }
    if rel_path.is_empty() || rel_path == "." {
        return Err("Invalid path".to_string());
    }

    // Fix: canonicalize the base directory and use it for all operations
    let base = Path::new(base_dir);
    std::fs::create_dir_all(base).map_err(|e| format!("Create base dir: {}", e))?;
    let canonical_base = std::fs::canonicalize(base)
        .map_err(|e| format!("Cannot canonicalize base dir: {}", e))?;
    
    let full_path = canonical_base.join(rel_path);

    // Ensure parent directory exists and is safe
    if let Some(parent) = full_path.parent() {
        ensure_safe_dir(parent)?;
    }

    // Verify the resolved path stays inside base_dir
    let canonical_target = std::fs::canonicalize(&full_path)
        .or_else(|_| {
            full_path.parent()
                .map(|p| std::fs::canonicalize(p))
                .unwrap_or_else(|| Ok(canonical_base.clone()))
        })
        .map_err(|e| format!("Cannot canonicalize target: {}", e))?;
    if !canonical_target.starts_with(&canonical_base) {
        return Err("Path escapes base directory".to_string());
    }

    // Race-harden: refuse to open if the path is a symlink or hard link
    if let Ok(meta) = full_path.symlink_metadata() {
        if meta.file_type().is_symlink() {
            return Err("Symlink detected at target path".to_string());
        }
        if is_hardlink(&meta) {
            return Err("Hard link detected at target path".to_string());
        }
    }

    let bytes = BASE64.decode(b64_data).map_err(|e| format!("B64 Error: {}", e))?;
    // Fix: enforce decoded size limit
    if bytes.len() as u64 > MAX_TOTAL_FILE_SIZE {
        return Err(format!("Decoded file exceeds {} MB limit", MAX_TOTAL_FILE_SIZE / (1024 * 1024)));
    }
    let mut file = File::create(&full_path).map_err(|e| e.to_string())?;
    file.write_all(&bytes).map_err(|e| e.to_string())?;
    Ok(())
}

// ── Unit tests ────────────────────────────────────────────────────────────────
#[cfg(test)]
mod chunk_tests {
    use super::*;

    #[test]
    fn path_traversal_dot_dot_is_rejected() {
        let r = save_file_chunk("batch", 1, "root", "../../../etc/passwd", 0, 1, &BASE64.encode(b"x"));
        assert!(r.is_err(), "expected Err for path traversal");
        let e = r.unwrap_err().to_lowercase();
        assert!(e.contains("traversal") || e.contains("parent"),
            "expected traversal/parent error message, got: {}", e);
    }

    #[test]
    fn empty_rel_path_is_rejected() {
        let r = save_file_chunk("batch", 1, "root", "", 0, 1, &BASE64.encode(b"x"));
        assert!(r.is_err(), "empty rel_path must be rejected");
    }

    #[test]
    fn cur_dir_only_rel_path_is_rejected() {
        let r = save_file_chunk("batch", 1, "root", ".", 0, 1, &BASE64.encode(b"x"));
        assert!(r.is_err(), "'.' rel_path must be rejected after sanitization");
    }

    #[test]
    fn nested_traversal_is_rejected() {
        let r = save_file_chunk("batch", 1, "root", "subdir/../../escape.txt", 0, 1, &BASE64.encode(b"x"));
        assert!(r.is_err(), "nested traversal must be rejected");
    }

    #[test]
    fn invalid_base64_returns_error() {
        let batch = format!("ut_b64_{}", std::process::id());
        let r = save_file_chunk(&batch, 0, "r", "file.bin", 0, 1, "not!valid!base64@@@");
        let _ = std::fs::remove_dir_all(format!("downloads/{}_0_r", batch));
        assert!(r.is_err());
        let e = r.unwrap_err();
        assert!(e.to_lowercase().contains("base64"), "err: {}", e);
    }

    #[test]
    fn is_final_true_when_chunk_idx_plus_one_equals_total() {
        let batch = format!("ut_isfinal_{}", std::process::id());
        let cleanup = format!("downloads/{}_0_r", batch);
        // Fix: send all intermediate chunks in order so chunk-state validation passes
        for i in 0..4 {
            save_file_chunk(&batch, 0, "r", "f.bin", i, 5, &BASE64.encode(b"a"))
                .expect(&format!("chunk {} setup must succeed", i));
        }
        let r = save_file_chunk(&batch, 0, "r", "f.bin", 4, 5, &BASE64.encode(b"b"));
        let _ = std::fs::remove_dir_all(&cleanup);
        assert_eq!(r.unwrap(), true, "chunk 4 of 5 (0-indexed) is the last chunk");
    }

    #[test]
    fn is_final_false_when_more_chunks_remain() {
        let batch = format!("ut_notfinal_{}", std::process::id());
        let r = save_file_chunk(&batch, 0, "r", "f.bin", 0, 5, &BASE64.encode(b"x"));
        let _ = std::fs::remove_dir_all(format!("downloads/{}_0_r", batch));
        assert_eq!(r.unwrap(), false, "chunk 0 of 5 is not the last chunk");
    }

    #[test]
    fn is_final_true_for_single_chunk() {
        let batch = format!("ut_single_{}", std::process::id());
        let r = save_file_chunk(&batch, 0, "r", "f.bin", 0, 1, &BASE64.encode(b"x"));
        let _ = std::fs::remove_dir_all(format!("downloads/{}_0_r", batch));
        assert_eq!(r.unwrap(), true, "chunk 0 of 1 is both first and last");
    }

    #[test]
    fn root_name_special_chars_are_stripped() {
        let batch = format!("ut_root_{}", std::process::id());
        let r = save_file_chunk(&batch, 7, "ro/ot!@#", "f.bin", 0, 1, &BASE64.encode(b"x"));
        let _ = std::fs::remove_dir_all(format!("downloads/{}_7_root", batch));
        assert!(r.is_ok(), "special chars in root_name must be stripped, not rejected");
    }

    #[test]
    fn chunk_idx_out_of_bounds_is_rejected() {
        let r = save_file_chunk("batch", 1, "root", "f.bin", 5, 5, &BASE64.encode(b"x"));
        assert!(r.is_err(), "chunk_idx >= total_chunks must be rejected");
        let e = r.unwrap_err().to_lowercase();
        assert!(e.contains("out of bounds"), "expected out of bounds error, got: {}", e);
    }

    #[test]
    fn zero_total_chunks_is_rejected() {
        let r = save_file_chunk("batch", 1, "root", "f.bin", 0, 0, &BASE64.encode(b"x"));
        assert!(r.is_err(), "total_chunks == 0 must be rejected");
    }

    #[test]
    fn chunk_size_limit_is_enforced() {
        let huge = "A".repeat(MAX_CHUNK_B64_BYTES + 1);
        let r = save_file_chunk("batch", 1, "root", "f.bin", 0, 1, &huge);
        assert!(r.is_err(), "oversized chunk must be rejected");
        let e = r.unwrap_err().to_lowercase();
        assert!(e.contains("chunk too large"), "expected chunk size error, got: {}", e);
    }

    #[test]
    fn write_file_simple_rejects_absolute_path() {
        let r = write_file_simple("downloads", "/etc/passwd", &BASE64.encode(b"x"));
        assert!(r.is_err(), "absolute path must be rejected");
    }

    #[test]
    fn write_file_simple_rejects_traversal() {
        let r = write_file_simple("downloads", "../escape.txt", &BASE64.encode(b"x"));
        assert!(r.is_err(), "parent traversal must be rejected");
    }
}
