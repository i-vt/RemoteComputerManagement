// ./src/rcm/manifest.rs
// Package manifest (Section 17.2): one <entry> per package file with
// path/size/sha256, sorted by path. Generation 0 seals the package; later
// generations (manifest.RCM.<n>.xml) cover post-seal modifications while
// prior generations are preserved (REQ-17.2.6).

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::package::{is_chunk_slot_name, RcmError};
use super::xml;

fn sha256_file(path: &Path) -> Result<String, RcmError> {
    // Streamed (REQ-18.2.1): the specification imposes no file-size limit.
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    std::io::copy(&mut f, &mut h)?;
    Ok(hex::encode(h.finalize()))
}

/// REQ-17.2.5 exclusions, applied to a package-relative path ('/' seps).
/// Manifest files themselves (all generations) are excluded - a manifest
/// hashes package data, not other manifests.
///
/// `*.tmp` and the chunk-transfer slot names (`*.part` / `*.part.state`
/// plus the numbered slots `*.part.<n>` / `*.part.<n>.state`, n = digits)
/// are only excluded when the file has NO metadata sidecar: in-flight
/// artifacts (atomic-write temps, chunked transfers) never have one, while
/// COMMITTED collected evidence always does (REQ-8.1.2) - a collected file
/// legitimately named "notes.tmp" must stay covered or its tampering would
/// be invisible. `*.sig` stays unconditionally excluded (spec-registered).
fn is_excluded(root: &Path, rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    let at_root = !rel.contains('/');
    if at_root && (name == "manifest.RCM.xml"
        || (name.starts_with("manifest.RCM.") && name.ends_with(".xml")))
    {
        return true;
    }
    if at_root && name == "custody.RCM.xml" {
        return true;
    }
    if name.ends_with(".sig") {
        return true;
    }
    if name.ends_with(".tmp") || is_chunk_slot_name(name) {
        if let Some(dl) = rel.strip_prefix("downloads/") {
            let sidecar = root
                .join("downloads.metadata")
                .join(format!("{}.RCM.xml", dl));
            // Excluded only as an in-flight artifact (no sidecar).
            return sidecar.symlink_metadata().is_err();
        }
        return true;
    }
    false
}

/// Recursively collect regular files under `dir`; symlinks are NEVER
/// followed or listed (package writes never create them - treat any found
/// symlink as hostile and skip it).
fn walk(root: &Path, dir: &Path, rel: &str, out: &mut Vec<String>) -> Result<(), RcmError> {
    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    for entry in rd {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let child_rel = if rel.is_empty() {
            name.clone()
        } else {
            format!("{}/{}", rel, name)
        };
        if ft.is_dir() {
            walk(root, &entry.path(), &child_rel, out)?;
        } else if ft.is_file() && !is_excluded(root, &child_rel) {
            out.push(child_rel);
        }
    }
    Ok(())
}

/// Next manifest path: generation 0 is manifest.RCM.xml; once it exists,
/// manifest.RCM.<n>.xml with n from 1 (REQ-17.2.6). pub(crate) so the
/// PackageManager can record the seal in the Section-13 log BEFORE the
/// manifest hashes the log file (the log entry must be part of the
/// generation it announces).
pub(crate) fn next_manifest_path(root: &Path) -> PathBuf {
    if !root.join("manifest.RCM.xml").exists() {
        return root.join("manifest.RCM.xml");
    }
    let mut n = 1u64;
    loop {
        let p = root.join(format!("manifest.RCM.{}.xml", n));
        if !p.exists() {
            return p;
        }
        n += 1;
    }
}

/// REQ-17.2.1/17.2.6: generate the next manifest generation. Atomic write.
/// `notes` carries optional per-path annotations rendered as `<note>`
/// entries (REQ-2.4 SHOULD: tool deviations may be recorded in the
/// manifest). Pass an empty slice when there is nothing to note.
/// Returns the manifest path.
pub fn seal(root: &Path, notes: &[(String, String)]) -> Result<PathBuf, RcmError> {
    let mut rels = Vec::new();
    walk(root, root, "", &mut rels)?;
    rels.sort(); // entries sorted by path ('/' separators already)

    let mut data = String::from("  <manifest version=\"1\">\n");
    for rel in &rels {
        let abs = root.join(rel);
        let size = abs.metadata()?.len();
        let digest = sha256_file(&abs)?;
        data.push_str("    <entry>\n");
        data.push_str(&format!("      <path>{}</path>\n", xml::xml_escape(rel)));
        data.push_str(&format!("      <size>{}</size>\n", size));
        data.push_str(&format!("      <sha256>{}</sha256>\n", digest));
        if let Some((_, note)) = notes.iter().find(|(p, _)| p == rel) {
            data.push_str(&format!("      <note>{}</note>\n", xml::xml_escape(note)));
        }
        data.push_str("    </entry>\n");
    }
    data.push_str("  </manifest>\n");

    let path = next_manifest_path(root);
    xml::atomic_write(&path, xml::xml_doc(&data, &xml::now_ts()).as_bytes())?;
    Ok(path)
}

/// One parsed `<entry>` of a manifest.
enum ManifestEntry {
    /// path, size, sha256.
    Valid(String, u64, String),
    /// Missing `<sha256>`/`<size>`, or an unparsable size. Silently
    /// SKIPPING such an entry would leave its file uncovered, so it is
    /// surfaced and treated as an integrity failure. Carries the entry's
    /// path when one could be extracted.
    Malformed(Option<String>),
}

/// Extract entries from a manifest document body. An `<entry>` that does
/// not yield a complete (path, size, sha256) tuple is kept as
/// [`ManifestEntry::Malformed`] - never silently dropped.
fn parse_manifest(body: &str) -> Vec<ManifestEntry> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(i) = rest.find("<entry>") {
        let tail = &rest[i..];
        let end = match tail.find("</entry>") {
            Some(e) => e,
            None => break,
        };
        let block = &tail[..end];
        let grab = |key: &str| -> Option<String> {
            let open = format!("<{}>", key);
            let close = format!("</{}>", key);
            let s = block.find(&open)? + open.len();
            let e = block[s..].find(&close)? + s;
            Some(block[s..e].to_string())
        };
        let path = grab("path").map(|p| xml::xml_unescape(p.trim()));
        match (path, grab("size"), grab("sha256")) {
            (Some(p), Some(sz), Some(h)) => match sz.trim().parse::<u64>() {
                Ok(size) => out.push(ManifestEntry::Valid(p, size, h.trim().to_string())),
                Err(_) => out.push(ManifestEntry::Malformed(Some(p))),
            },
            (p, _, _) => out.push(ManifestEntry::Malformed(p)),
        }
        rest = &tail[end + "</entry>".len()..];
    }
    out
}

/// An entry path must stay INSIDE the package root: absolute paths, drive
/// prefixes, UNC roots and any `..` component would let a forged manifest
/// point verification at files outside the package.
fn path_escapes_root(rel: &str) -> bool {
    if rel.is_empty() || rel.starts_with('/') || rel.starts_with('\\') {
        return true;
    }
    let b = rel.as_bytes();
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        return true; // drive prefix ("C:...")
    }
    rel.split(['/', '\\']).any(|c| c == "..")
}

/// REQ-17.2.4: verify the latest manifest generation; returns the list of
/// mismatching or missing package-relative paths (empty = OK).
pub fn verify(root: &Path) -> Result<Vec<String>, RcmError> {
    // Latest generation: the HIGHEST EXISTING manifest.RCM.<n>.xml if any,
    // else generation 0. Generations are discovered by listing (never by
    // scanning until the first gap): an attacker deleting manifest.RCM.1.xml
    // must not make verify silently fall back to an older generation and
    // ignore gen 2.
    let latest = if root.join("manifest.RCM.xml").exists() {
        let mut latest = root.join("manifest.RCM.xml");
        let mut best: Option<u64> = None;
        if let Ok(rd) = std::fs::read_dir(root) {
            for entry in rd.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if let Some(n) = name
                    .strip_prefix("manifest.RCM.")
                    .and_then(|s| s.strip_suffix(".xml"))
                    .and_then(|s| s.parse::<u64>().ok())
                {
                    if best.map_or(true, |b| n > b) {
                        best = Some(n);
                    }
                }
            }
        }
        if let Some(n) = best {
            latest = root.join(format!("manifest.RCM.{}.xml", n));
        }
        latest
    } else {
        return Err(RcmError(format!(
            "no manifest in package {}",
            root.display()
        )));
    };

    let body = std::fs::read_to_string(&latest)?;
    let mut bad = Vec::new();
    for entry in parse_manifest(&body) {
        let (rel, size, hash) = match entry {
            ManifestEntry::Valid(rel, size, hash) => (rel, size, hash),
            // A malformed entry is an integrity failure, never skipped:
            // its file would otherwise be silently uncovered.
            ManifestEntry::Malformed(Some(p)) => {
                bad.push(p);
                continue;
            }
            ManifestEntry::Malformed(None) => {
                bad.push("<malformed manifest entry>".to_string());
                continue;
            }
        };
        // Containment: never follow an entry path outside the package root.
        if path_escapes_root(&rel) {
            bad.push(rel);
            continue;
        }
        let abs = root.join(&rel);
        // symlink_metadata: a symlink (or any non-regular file) standing in
        // for a manifest entry is a MISMATCH, never followed.
        match abs.symlink_metadata() {
            Ok(md) if md.file_type().is_file() && md.len() == size => {
                match sha256_file(&abs) {
                    Ok(digest) => {
                        if digest != hash {
                            bad.push(rel);
                        }
                    }
                    // IO error while hashing: count as a mismatch for this
                    // path; do NOT abort the whole verification.
                    Err(_) => bad.push(rel),
                }
            }
            _ => bad.push(rel), // missing, symlink, non-regular, or wrong size
        }
    }
    Ok(bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn populate(root: &Path) {
        std::fs::create_dir_all(root.join("downloads/C")).unwrap();
        std::fs::create_dir_all(root.join("output/screenshots")).unwrap();
        std::fs::write(root.join("fingerprint.RCM.xml"), b"fp").unwrap();
        std::fs::write(root.join("downloads/C/plAns.txt"), b"data").unwrap();
        std::fs::write(root.join("custody.RCM.xml"), b"custody").unwrap();
        std::fs::write(root.join("output/screenshots/s.png.tmp"), b"tmp").unwrap();
        std::fs::write(root.join("downloads/C/big.part"), b"part").unwrap();
        std::fs::write(root.join("downloads/C/big.part.state"), b"0,2").unwrap();
        std::fs::write(root.join("manifest.RCM.xml.sig"), b"sig").unwrap();
    }

    #[test]
    fn seal_excludes_and_generates() {
        let dir = tempfile::tempdir().unwrap();
        populate(dir.path());

        let p0 = seal(dir.path(), &[]).unwrap();
        assert_eq!(p0.file_name().unwrap(), "manifest.RCM.xml");
        let body = std::fs::read_to_string(&p0).unwrap();
        assert!(body.contains("<manifest version=\"1\">"));
        assert!(body.contains("<path>downloads/C/plAns.txt</path>"));
        assert!(body.contains("<path>fingerprint.RCM.xml</path>"));
        // REQ-17.2.5 exclusions.
        for excluded in ["custody.RCM.xml", ".sig", ".tmp", ".part"] {
            assert!(!body.contains(excluded), "excluded: {}", excluded);
        }
        // Sorted by path.
        let i_fp = body.find("fingerprint.RCM.xml</path>").unwrap();
        let i_dl = body.find("downloads/C/plAns.txt</path>").unwrap();
        assert!(i_dl < i_fp, "entries sorted by path");
        assert_eq!(verify(dir.path()).unwrap(), Vec::<String>::new());

        // Second generation.
        std::fs::write(dir.path().join("downloads/C/new.txt"), b"n").unwrap();
        let p1 = seal(dir.path(), &[]).unwrap();
        assert_eq!(p1.file_name().unwrap(), "manifest.RCM.1.xml");
        assert!(p0.exists(), "prior generation preserved");
        let body1 = std::fs::read_to_string(&p1).unwrap();
        assert!(body1.contains("<path>downloads/C/new.txt</path>"));
        assert!(!body1.contains("manifest.RCM.xml</path>"));
        assert_eq!(verify(dir.path()).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn verify_reports_tamper_and_missing() {
        let dir = tempfile::tempdir().unwrap();
        populate(dir.path());
        seal(dir.path(), &[]).unwrap();
        std::fs::write(dir.path().join("downloads/C/plAns.txt"), b"evil").unwrap();
        std::fs::remove_file(dir.path().join("fingerprint.RCM.xml")).unwrap();
        let mut bad = verify(dir.path()).unwrap();
        bad.sort();
        assert_eq!(bad, vec!["downloads/C/plAns.txt", "fingerprint.RCM.xml"]);
    }

    #[test]
    fn verify_without_manifest_errors() {
        let dir = tempfile::tempdir().unwrap();
        assert!(verify(dir.path()).is_err());
    }

    #[test]
    fn collected_tmp_part_with_sidecar_stay_covered() {
        // Committed collected evidence ending .tmp/.part has a metadata
        // sidecar -> NOT excluded; tampering must be flagged.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("downloads/C/a")).unwrap();
        std::fs::create_dir_all(root.join("downloads.metadata/C/a")).unwrap();
        std::fs::write(root.join("downloads/C/a/notes.tmp"), b"evidence").unwrap();
        std::fs::write(root.join("downloads.metadata/C/a/notes.tmp.RCM.xml"), b"sc").unwrap();
        std::fs::write(root.join("downloads/C/a/dump.part"), b"evidence").unwrap();
        std::fs::write(root.join("downloads.metadata/C/a/dump.part.RCM.xml"), b"sc").unwrap();
        // In-flight artifacts (no sidecar) stay excluded.
        std::fs::write(root.join("downloads/C/a/big.part"), b"inflight").unwrap();
        std::fs::write(root.join("downloads/C/a/big.part.state"), b"1,2,8").unwrap();

        let p0 = seal(root, &[]).unwrap();
        let body = std::fs::read_to_string(&p0).unwrap();
        assert!(body.contains("<path>downloads/C/a/notes.tmp</path>"));
        assert!(body.contains("<path>downloads/C/a/dump.part</path>"));
        assert!(!body.contains("<path>downloads/C/a/big.part</path>"));
        assert!(!body.contains("big.part.state"));

        std::fs::write(root.join("downloads/C/a/notes.tmp"), b"TAMPERED").unwrap();
        let bad = verify(root).unwrap();
        assert!(
            bad.contains(&"downloads/C/a/notes.tmp".to_string()),
            "tampered collected .tmp not flagged: {:?}",
            bad
        );
    }

    #[test]
    fn numbered_chunk_slots_excluded_without_sidecar() {
        // In-flight numbered slot files (X.part.<n>, X.part.<n>.state) have
        // no sidecar: excluded like slot 0. Committed evidence with a
        // sidecar (notes.tmp) stays covered.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("downloads/C")).unwrap();
        std::fs::create_dir_all(root.join("downloads.metadata/C")).unwrap();
        std::fs::write(root.join("downloads/C/x.part.3"), b"inflight").unwrap();
        std::fs::write(root.join("downloads/C/x.part.3.state"), b"1,2,8,t-9").unwrap();
        std::fs::write(root.join("downloads/C/x.part.12"), b"inflight").unwrap();
        std::fs::write(root.join("downloads/C/notes.tmp"), b"evidence").unwrap();
        std::fs::write(root.join("downloads.metadata/C/notes.tmp.RCM.xml"), b"sc").unwrap();

        let p0 = seal(root, &[]).unwrap();
        let body = std::fs::read_to_string(&p0).unwrap();
        assert!(!body.contains("x.part.3"), "slot part sealed: {}", body);
        assert!(!body.contains("x.part.3.state"), "slot state sealed: {}", body);
        assert!(!body.contains("x.part.12"), "slot part sealed: {}", body);
        assert!(body.contains("<path>downloads/C/notes.tmp</path>"));
        // A non-numeric lookalike is NOT a slot name: stays covered.
        std::fs::write(root.join("downloads/C/y.part.x"), b"data").unwrap();
        let p1 = seal(root, &[]).unwrap();
        let body1 = std::fs::read_to_string(&p1).unwrap();
        assert!(body1.contains("<path>downloads/C/y.part.x</path>"));
    }

    #[test]
    fn verify_flags_malformed_entries() {
        // An <entry> missing <sha256> or carrying an unparsable size is an
        // integrity failure - never silently skipped (its file would be
        // left uncovered). A manifest that does not parse at all stays a
        // hard error (covered by verify_without_manifest_errors).
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("downloads/C")).unwrap();
        std::fs::write(root.join("downloads/C/good.txt"), b"g").unwrap();
        std::fs::write(root.join("downloads/C/nohash.txt"), b"n").unwrap();
        std::fs::write(root.join("downloads/C/badsize.txt"), b"b").unwrap();
        let good_digest = {
            use sha2::Digest;
            hex::encode(sha2::Sha256::digest(b"g"))
        };
        let doc = format!(
            "<RCM>\n  <manifest version=\"1\">\n    <entry>\n      <path>downloads/C/good.txt</path>\n      <size>1</size>\n      <sha256>{}</sha256>\n    </entry>\n    <entry>\n      <path>downloads/C/nohash.txt</path>\n      <size>1</size>\n    </entry>\n    <entry>\n      <path>downloads/C/badsize.txt</path>\n      <size>not-a-number</size>\n      <sha256>00</sha256>\n    </entry>\n  </manifest>\n</RCM>\n",
            good_digest
        );
        std::fs::write(root.join("manifest.RCM.xml"), doc).unwrap();
        let mut bad = verify(root).unwrap();
        bad.sort();
        assert_eq!(
            bad,
            vec!["downloads/C/badsize.txt", "downloads/C/nohash.txt"],
            "malformed entries must be flagged"
        );
    }

    #[test]
    fn verify_flags_escaping_entry_paths() {
        // Entry paths escaping the package root (.. components, absolute,
        // drive prefixes) are integrity failures and are NEVER joined onto
        // the root for reading.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("downloads/C")).unwrap();
        std::fs::write(root.join("downloads/C/good.txt"), b"g").unwrap();
        let good_digest = {
            use sha2::Digest;
            hex::encode(sha2::Sha256::digest(b"g"))
        };
        // A decoy OUTSIDE the package whose content matches the forged
        // entry: without containment, verification would "pass" it.
        let outside = dir.path().join("outside.txt");
        std::fs::write(&outside, b"g").unwrap();
        let doc = format!(
            "<RCM>\n  <manifest version=\"1\">\n    <entry>\n      <path>downloads/C/good.txt</path>\n      <size>1</size>\n      <sha256>{}</sha256>\n    </entry>\n    <entry>\n      <path>../outside.txt</path>\n      <size>1</size>\n      <sha256>{}</sha256>\n    </entry>\n    <entry>\n      <path>/etc/passwd</path>\n      <size>1</size>\n      <sha256>00</sha256>\n    </entry>\n    <entry>\n      <path>C:\\Windows\\evil</path>\n      <size>1</size>\n      <sha256>00</sha256>\n    </entry>\n    <entry>\n      <path>downloads/C/../../escape.txt</path>\n      <size>1</size>\n      <sha256>00</sha256>\n    </entry>\n  </manifest>\n</RCM>\n",
            good_digest, good_digest
        );
        std::fs::write(root.join("manifest.RCM.xml"), doc).unwrap();
        let mut bad = verify(root).unwrap();
        bad.sort();
        assert_eq!(
            bad,
            vec![
                "../outside.txt",
                "/etc/passwd",
                "C:\\Windows\\evil",
                "downloads/C/../../escape.txt"
            ],
            "escaping paths must be flagged, got {:?}",
            bad
        );
    }

    #[test]
    fn verify_uses_highest_existing_generation() {
        // Ported reproducer (adv_manifest_generation_gap): deleting
        // manifest.RCM.1.xml must not hide gen 2 from verify.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("downloads/C")).unwrap();
        std::fs::write(root.join("downloads/C/c.txt"), b"3").unwrap();
        seal(root, &[]).unwrap(); // gen 0
        seal(root, &[]).unwrap(); // gen 1
        seal(root, &[]).unwrap(); // gen 2
        assert!(root.join("manifest.RCM.2.xml").exists());
        std::fs::remove_file(root.join("manifest.RCM.1.xml")).unwrap();
        // Tamper a file only gen 2 covers... c.txt is in all generations;
        // tamper it and confirm verify still reads gen 2 (the gap must not
        // stop the scan at gen 0).
        std::fs::write(root.join("downloads/C/c.txt"), b"EVIL").unwrap();
        let bad = verify(root).unwrap();
        assert!(
            bad.iter().any(|p| p.contains("c.txt")),
            "verify ignored the newest generation across the gap: {:?}",
            bad
        );
    }
}
