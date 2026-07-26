// ./src/rcm/counters.rs
// Unified duplicate-file / counter policy (REQ-3.4). Allocation is always
// atomic: create-exclusive (create_new / O_EXCL) try-and-increment per
// REQ-3.4.5, never list-then-create - a later atomic rename would otherwise
// silently replace an earlier winner, violating REQ-3.4.4.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use super::package::RcmError;

/// REQ-3.4.5: try-and-increment with create_new (O_EXCL). Returns the created
/// (empty) file's path, the File, and the counter that won. `name(0)` is the
/// first tried name; pass a closure encoding the counter scheme.
pub fn allocate(
    dir: &Path,
    name: impl Fn(u64) -> String,
) -> Result<(PathBuf, File, u64), RcmError> {
    // Generous bound: each iteration is a fresh O_EXCL attempt, so a hot loop
    // only occurs under genuine pathological contention.
    for i in 0..100_000u64 {
        let path = dir.join(name(i));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(f) => {
                // Never let a symlink stand in for a freshly allocated file.
                if let Ok(meta) = path.symlink_metadata() {
                    if meta.file_type().is_symlink() {
                        let _ = std::fs::remove_file(&path);
                        return Err(RcmError(format!(
                            "race: symlink at allocated path: {}",
                            path.display()
                        )));
                    }
                }
                return Ok((path, f, i));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(RcmError(format!(
                    "allocate in {}: {}",
                    dir.display(),
                    e
                )))
            }
        }
    }
    Err(RcmError(format!(
        "counter space exhausted in {}",
        dir.display()
    )))
}

/// REQ-3.4.1 naming for tool-generated files: stem.ext, stem.0.ext,
/// stem.1.ext, ... (ext without dot; empty ext -> stem, stem.0, ...).
pub fn tool_file(dir: &Path, stem: &str, ext: &str) -> Result<(PathBuf, File), RcmError> {
    let (path, file, _) = allocate(dir, |i| {
        let base = if i == 0 {
            stem.to_string()
        } else {
            format!("{}.{}", stem, i - 1)
        };
        if ext.is_empty() {
            base
        } else {
            format!("{}.{}", base, ext)
        }
    })?;
    Ok((path, file))
}

/// REQ-3.4.2 naming: `<stem>.<counter>.<ext>` with the built-in counter
/// starting at 0 (e.g. processlist.RCM.0.xml -> stem="processlist.RCM").
pub fn counted_file(
    dir: &Path,
    stem: &str,
    ext: &str,
) -> Result<(PathBuf, File, u64), RcmError> {
    allocate(dir, |i| {
        if ext.is_empty() {
            format!("{}.{}", stem, i)
        } else {
            format!("{}.{}.{}", stem, i, ext)
        }
    })
}

/// REQ-3.4.3 naming for collected downloads: f.txt, f.txt.1, f.txt.1.1, ...
/// The counter is appended after the full filename; the corresponding
/// sidecar carries the identical suffix before `.RCM.xml` (see sidecar.rs).
pub fn download_file(dir: &Path, filename: &str) -> Result<(PathBuf, File), RcmError> {
    let (path, file, _) = allocate(dir, |i| {
        if i == 0 {
            filename.to_string()
        } else {
            format!("{}{}", filename, ".1".repeat(i as usize))
        }
    })?;
    Ok((path, file))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_file_scheme() {
        let dir = tempfile::tempdir().unwrap();
        let (p0, _f) = tool_file(dir.path(), "a", "txt").unwrap();
        let (p1, _f) = tool_file(dir.path(), "a", "txt").unwrap();
        let (p2, _f) = tool_file(dir.path(), "a", "txt").unwrap();
        assert_eq!(p0.file_name().unwrap(), "a.txt");
        assert_eq!(p1.file_name().unwrap(), "a.0.txt");
        assert_eq!(p2.file_name().unwrap(), "a.1.txt");
        // Empty extension variant.
        let (q0, _f) = tool_file(dir.path(), "b", "").unwrap();
        let (q1, _f) = tool_file(dir.path(), "b", "").unwrap();
        assert_eq!(q0.file_name().unwrap(), "b");
        assert_eq!(q1.file_name().unwrap(), "b.0");
    }

    #[test]
    fn counted_file_scheme() {
        let dir = tempfile::tempdir().unwrap();
        let (p0, _f, c0) = counted_file(dir.path(), "keylog.RCM", "xml").unwrap();
        let (p1, _f, c1) = counted_file(dir.path(), "keylog.RCM", "xml").unwrap();
        assert_eq!(p0.file_name().unwrap(), "keylog.RCM.0.xml");
        assert_eq!(p1.file_name().unwrap(), "keylog.RCM.1.xml");
        assert_eq!((c0, c1), (0, 1));
    }

    #[test]
    fn download_file_scheme() {
        let dir = tempfile::tempdir().unwrap();
        let (p0, _f) = download_file(dir.path(), "f.txt").unwrap();
        let (p1, _f) = download_file(dir.path(), "f.txt").unwrap();
        let (p2, _f) = download_file(dir.path(), "f.txt").unwrap();
        assert_eq!(p0.file_name().unwrap(), "f.txt");
        assert_eq!(p1.file_name().unwrap(), "f.txt.1");
        assert_eq!(p2.file_name().unwrap(), "f.txt.1.1");
    }

    #[test]
    fn threaded_allocation_is_unique() {
        // REQ-3.4.5 fixture: 8 threads x 50 files, all names distinct.
        // tool_file keeps names short (the REQ-3.4.3 ".1.1..." suffix chain
        // would legitimately exceed NAME_MAX after ~125 duplicates).
        let dir = tempfile::tempdir().unwrap();
        let dir_path = std::sync::Arc::new(dir.path().to_path_buf());
        let mut handles = Vec::new();
        for _ in 0..8 {
            let d = dir_path.clone();
            handles.push(std::thread::spawn(move || {
                let mut names = Vec::new();
                for _ in 0..50 {
                    let (p, _f) = tool_file(&d, "a", "txt").unwrap();
                    names.push(p.file_name().unwrap().to_os_string());
                }
                names
            }));
        }
        let mut all: Vec<_> = Vec::new();
        for h in handles {
            all.extend(h.join().unwrap());
        }
        let uniq: std::collections::HashSet<_> = all.iter().collect();
        assert_eq!(all.len(), 400);
        assert_eq!(uniq.len(), 400);
    }
}