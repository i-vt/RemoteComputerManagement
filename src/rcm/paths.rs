// ./src/rcm/paths.rs
// Target-native path reconstruction (Section 8.1) and name sanitization
// (REQ-3.1.5). Reconstructed paths are attacker-controlled (they come from
// the target), so every component is sanitized, reserved Windows device
// names are defused (REQ-8.1.8), and directory creation refuses to follow
// symlinks (same posture as file_transfer.rs).

use std::path::{Path, PathBuf};

use super::package::RcmError;

/// REQ-3.1.5: replace `\ / : * ? " < > |` and control chars with '_'.
/// Case is preserved.
pub fn sanitize_component(s: &str) -> String {
    // Protocol constant fixed by REQ-3.1.5 - not a runtime tunable, so it
    // stays a const and is not part of the typed config tree.
    const INVALID: [char; 9] = ['\\', '/', ':', '*', '?', '"', '<', '>', '|'];
    s.chars()
        .map(|c| if INVALID.contains(&c) || c.is_control() { '_' } else { c })
        .collect()
}

/// Root folder name from hostname (REQ-3.1.2/3.1.5). Returns "" when nothing
/// usable remains (caller falls back to the instance id per REQ-3.1.3).
pub fn sanitize_root_name(hostname: &str) -> String {
    let s = sanitize_component(hostname).trim().to_string();
    // "." and ".." are never usable folder names.
    if s.is_empty() || s.chars().all(|c| c == '.') {
        String::new()
    } else {
        s
    }
}

/// REQ-8.1.8: CON, PRN, AUX, NUL, COM1-9, LPT1-9 - case-insensitive, with or
/// without an extension (the part before the first '.' is decisive).
pub fn is_reserved_device_name(component: &str) -> bool {
    let base = match component.find('.') {
        Some(i) => &component[..i],
        None => component,
    };
    let up = base.to_ascii_uppercase();
    matches!(up.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (up.len() == 4
            && (up.starts_with("COM") || up.starts_with("LPT"))
            && up.as_bytes()[3].is_ascii_digit()
            && up.as_bytes()[3] != b'0')
}

/// REQ-8.1.3 / 8.1.7 / 8.1.8: split a target-native path into sanitized
/// components for storage under `<pkg>/downloads/`. Accepts both '\\' and
/// '/' separators in any position.
pub fn reconstruct_download_components(original: &str) -> Vec<String> {
    let s = original.trim();
    let mut comps: Vec<String> = Vec::new();

    // The agent's UNC wire form uses EXACTLY two leading separators
    // ("\\server\share\..." or "//server/share/..."); those are rooted under
    // a reserved "UNC" top-level folder (REQ-8.1.7). ANY other leading
    // separator run (1, or 3+) is a POSIX path - POSIX permits duplicate
    // leading slashes - so the run is stripped like interior duplicates
    // (the split below already drops empty components).
    let lead = s
        .bytes()
        .take_while(|b| *b == b'/' || *b == b'\\')
        .count();
    let rest = if lead == 2 {
        comps.push("UNC".to_string());
        &s[2..]
    } else {
        s
    };

    for (i, raw) in rest.split(['\\', '/']).enumerate() {
        if raw.is_empty() || raw == "." {
            continue;
        }
        // Drive-letter prefix ("C:" or "C:foo") -> top-level folder "C"
        // (colon removed, REQ-8.1.3).
        if i == 0 && raw.len() >= 2 && raw.as_bytes()[1] == b':'
            && raw.as_bytes()[0].is_ascii_alphabetic()
        {
            comps.push((raw.as_bytes()[0] as char).to_string());
            let tail = &raw[2..];
            if tail.is_empty() {
                continue;
            }
            push_component(&mut comps, tail);
            continue;
        }
        // Never allow traversal out of the reconstruction tree.
        if raw == ".." {
            continue;
        }
        push_component(&mut comps, raw);
    }
    comps
}

/// Validated reconstruction for COLLECTED paths (store_collected /
/// store_collected_chunk): like [`reconstruct_download_components`] but
/// REJECTS paths that carry no filename component. Storing those would
/// create a FILE where later legitimate stores need a DIRECTORY (leaf-file
/// tree poisoning: "C:" creates file `downloads/C`, breaking every later
/// "C:\..." store). Rejected shapes:
/// - anything ending in a separator ("C:\a\", "/")
/// - a bare drive root ("C:", "C:\", also "C:." / "C:..")
/// - bare UNC prefixes ("\\", "//") and UNC share roots ("\\server\share")
/// A bare single-component relative name ("file.txt") remains allowed.
pub fn reconstruct_collected_components(original: &str) -> Result<Vec<String>, RcmError> {
    let trimmed = original.trim();
    let comps = reconstruct_download_components(original);
    if comps.is_empty() {
        return Err(RcmError(format!(
            "unusable collected path: {:?}",
            original
        )));
    }
    if trimmed.ends_with(['\\', '/']) {
        return Err(RcmError(format!(
            "collected path has no filename component (ends in a separator): {:?}",
            original
        )));
    }
    // Drive prefix consumed with no usable tail component ("C:", "C:.",
    // "C:.."). "C:file.txt" keeps TWO components and stays legal.
    let b = trimmed.as_bytes();
    if comps.len() == 1
        && b.len() >= 2
        && b[1] == b':'
        && b[0].is_ascii_alphabetic()
    {
        return Err(RcmError(format!(
            "collected path is a bare drive root (no filename component): {:?}",
            original
        )));
    }
    // UNC needs server + share + at least one path component below the
    // share root.
    if comps[0] == "UNC" && comps.len() <= 3 {
        return Err(RcmError(format!(
            "collected path is a UNC share root (no filename component): {:?}",
            original
        )));
    }
    Ok(comps)
}

/// Sanitize one path component and defuse reserved device names.
fn push_component(comps: &mut Vec<String>, raw: &str) {
    let mut c = sanitize_component(raw);
    if c.is_empty() || c == "." || c == ".." {
        return;
    }
    if is_reserved_device_name(&c) {
        c = format!("_{}", c);
    }
    comps.push(c);
}

/// Split "C:\\dir\\file.txt" -> ("file.txt", "C:\\dir") preserving the
/// original separators for the sidecar name/dirname keys (Table 2).
/// Falls back gracefully for POSIX and relative paths.
pub fn split_name_dirname(original: &str) -> (String, String) {
    let s = original.trim();
    let trimmed = s.trim_end_matches(['\\', '/']);
    match trimmed.rfind(['\\', '/']) {
        Some(i) => {
            let name = &trimmed[i + 1..];
            let dir = &trimmed[..i];
            (name.to_string(), dir.to_string())
        }
        None => (trimmed.to_string(), String::new()),
    }
}

/// Join sanitized components under `base`, creating each missing directory
/// but refusing to follow or create through symlinks (pre- and post-creation
/// checks, mirroring file_transfer.rs::ensure_safe_dir). Returns the final
/// directory path.
pub(crate) fn ensure_dir(base: &Path, components: &[&str]) -> Result<PathBuf, RcmError> {
    let mut cur = base.to_path_buf();
    for comp in components {
        cur = cur.join(comp);
        if let Ok(meta) = cur.symlink_metadata() {
            if meta.file_type().is_symlink() {
                return Err(RcmError(format!(
                    "symlink detected at directory: {}",
                    cur.display()
                )));
            }
            if !meta.is_dir() {
                return Err(RcmError(format!(
                    "path exists but is not a directory: {}",
                    cur.display()
                )));
            }
            continue;
        }
        match std::fs::create_dir(&cur) {
            Ok(()) => {}
            // A concurrent initializer created it first: fine, re-check below.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                return Err(RcmError(format!("create dir {}: {}", cur.display(), e)))
            }
        }
        // Re-check after creation to catch a symlink swapped in by a racer.
        if let Ok(meta) = cur.symlink_metadata() {
            if meta.file_type().is_symlink() {
                return Err(RcmError(format!(
                    "race: symlink detected at directory: {}",
                    cur.display()
                )));
            }
        }
    }
    Ok(cur)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_replaces_invalid_chars() {
        assert_eq!(sanitize_component("a\\b/c:d*e?f\"g<h>i|j"), "a_b_c_d_e_f_g_h_i_j");
        assert_eq!(sanitize_component("x\u{0007}y"), "x_y");
        // Case preserved.
        assert_eq!(sanitize_component("PlAnS.TxT"), "PlAnS.TxT");
    }

    #[test]
    fn root_name_fallbacks() {
        assert_eq!(sanitize_root_name("Bingy-Desktop"), "Bingy-Desktop");
        assert_eq!(sanitize_root_name("host:a?b"), "host_a_b");
        assert_eq!(sanitize_root_name(""), "");
        assert_eq!(sanitize_root_name("..."), "");
        // ':' sanitizes to '_' (REQ-3.1.5); "___" is still a usable name.
        assert_eq!(sanitize_root_name(":::"), "___");
    }

    #[test]
    fn reserved_device_names() {
        for n in ["CON", "con", "PRN", "AUX", "NUL", "COM1", "com9", "LPT1", "lPt9",
                  "con.txt", "COM1.exe", "nul.tar.gz"] {
            assert!(is_reserved_device_name(n), "{}", n);
        }
        for n in ["console", "COM0", "COM10", "LPT", "conman.txt", "a.con"] {
            assert!(!is_reserved_device_name(n), "{}", n);
        }
    }

    #[test]
    fn reconstruct_vectors() {
        assert_eq!(
            reconstruct_download_components("C:\\WINDOWS\\plAns.txt"),
            vec!["C", "WINDOWS", "plAns.txt"]
        );
        assert_eq!(
            reconstruct_download_components("C:/WINDOWS/plAns.txt"),
            vec!["C", "WINDOWS", "plAns.txt"]
        );
        assert_eq!(
            reconstruct_download_components("\\\\server\\share\\f.txt"),
            vec!["UNC", "server", "share", "f.txt"]
        );
        assert_eq!(
            reconstruct_download_components("//server/share/f.txt"),
            vec!["UNC", "server", "share", "f.txt"]
        );
        assert_eq!(
            reconstruct_download_components("/etc/passwd"),
            vec!["etc", "passwd"]
        );
        assert_eq!(
            reconstruct_download_components("sub/dir/f.txt"),
            vec!["sub", "dir", "f.txt"]
        );
    }

    #[test]
    fn reconstruct_reserved_and_traversal() {
        assert_eq!(
            reconstruct_download_components("C:\\CON\\con.txt"),
            vec!["C", "_CON", "_con.txt"]
        );
        assert_eq!(
            reconstruct_download_components("/dev/COM1"),
            vec!["dev", "_COM1"]
        );
        // Traversal components are dropped, never propagated.
        assert_eq!(
            reconstruct_download_components("../../etc/passwd"),
            vec!["etc", "passwd"]
        );
    }

    #[test]
    fn collected_components_reject_filename_less_paths() {
        for bad in [
            "", "   ", ".", "..", "../..",
            "C:", "C:\\", "C:/", "C:.", "C:..",
            "/", "\\\\", "//", "////",
            "\\\\server", "\\\\server\\share", "\\\\server\\share\\",
            "//server/share",
            "C:\\a\\", "a/b/",
        ] {
            assert!(
                reconstruct_collected_components(bad).is_err(),
                "{:?} must be rejected",
                bad
            );
        }
        // Allowed: bare relative name, drive-relative, UNC file, normal.
        assert_eq!(
            reconstruct_collected_components("file.txt").unwrap(),
            vec!["file.txt"]
        );
        assert_eq!(
            reconstruct_collected_components("C:file.txt").unwrap(),
            vec!["C", "file.txt"]
        );
        assert_eq!(
            reconstruct_collected_components("\\\\server\\share\\f.txt").unwrap(),
            vec!["UNC", "server", "share", "f.txt"]
        );
        assert_eq!(
            reconstruct_collected_components("C:\\a\\b.txt").unwrap(),
            vec!["C", "a", "b.txt"]
        );
    }

    #[test]
    fn posix_multi_slash_is_not_unc() {
        // POSIX duplicate leading slashes (3+, or mixed runs != 2) are POSIX
        // paths: stripped/collapsed, NOT routed under downloads/UNC/.
        assert_eq!(
            reconstruct_download_components("////etc///passwd"),
            vec!["etc", "passwd"]
        );
        assert_eq!(
            reconstruct_download_components("///etc/passwd"),
            vec!["etc", "passwd"]
        );
        assert_eq!(
            reconstruct_download_components("\\\\\\\\etc\\passwd"),
            vec!["etc", "passwd"]
        );
        // Exactly two separators (either kind) is the UNC wire form.
        assert_eq!(
            reconstruct_download_components("//server/share/f.txt"),
            vec!["UNC", "server", "share", "f.txt"]
        );
        assert_eq!(
            reconstruct_download_components("\\\\server\\share\\f.txt"),
            vec!["UNC", "server", "share", "f.txt"]
        );
        // Collected storage: multi-slash POSIX keeps its filename.
        assert_eq!(
            reconstruct_collected_components("////etc///passwd").unwrap(),
            vec!["etc", "passwd"]
        );
        // UNC share root with no file is still rejected; UNC file allowed.
        assert!(reconstruct_collected_components("//server/share").is_err());
        assert_eq!(
            reconstruct_collected_components("//server/share/f.txt").unwrap(),
            vec!["UNC", "server", "share", "f.txt"]
        );
        // A leading run of separators alone still has no filename.
        for bad in ["//", "///", "////", "\\\\\\\\"] {
            assert!(
                reconstruct_collected_components(bad).is_err(),
                "{:?} must be rejected",
                bad
            );
        }
    }

    #[test]
    fn split_name_dirname_vectors() {
        assert_eq!(
            split_name_dirname("C:\\dir\\file.txt"),
            ("file.txt".to_string(), "C:\\dir".to_string())
        );
        assert_eq!(
            split_name_dirname("/etc/passwd"),
            ("passwd".to_string(), "/etc".to_string())
        );
        assert_eq!(
            split_name_dirname("sub/dir/f.txt"),
            ("f.txt".to_string(), "sub/dir".to_string())
        );
        assert_eq!(
            split_name_dirname("file.txt"),
            ("file.txt".to_string(), String::new())
        );
    }
}
