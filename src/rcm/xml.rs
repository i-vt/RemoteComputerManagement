// ./src/rcm/xml.rs
// Common RCM XML envelope (Section 5), canonical timestamps (REQ-4.2.1) and
// the atomic-write primitive (REQ-6.3.1/6.3.2) shared by every RCM artifact.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use chrono::{DateTime, Utc};

use super::package::RcmError;

/// Specification version this module produces (REQ-5.1.6).
/// Protocol constant, not a tunable: it stays a pub const. The
/// config.rcm.spec_version key exists only as documentation and MUST mirror
/// this value; it is intentionally not read here.
pub const SPEC_VERSION: &str = "2.1";
/// RCM envelope major version (REQ-5.1.1). Protocol constant - see above.
pub const ENVELOPE_VERSION: &str = "1";

/// Escape the five predefined XML entities in element text and attribute
/// values (REQ-4.1.x well-formedness). Order matters: '&' first.
/// Additionally strips characters that are INVALID in XML 1.0 entirely:
/// every control char below 0x20 except \t \n \r, plus 0xFFFE/0xFFFF.
/// (Attacker-controlled values - path names, owners, keylog keys - would
/// otherwise produce documents no XML 1.0 parser accepts.)
pub fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => {
                let cp = c as u32;
                if (cp < 0x20 && c != '\t' && c != '\n' && c != '\r')
                    || cp == 0xFFFE
                    || cp == 0xFFFF
                {
                    // Drop: not representable in XML 1.0.
                    continue;
                }
                out.push(c);
            }
        }
    }
    out
}

/// Inverse of [`xml_escape`]; used when reading our own artifacts back
/// (manifest verification, fingerprint merge). Not part of the public
/// producer contract.
pub(crate) fn xml_unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let (entity, len) = if tail.starts_with("&amp;") {
            ("&", 5)
        } else if tail.starts_with("&lt;") {
            ("<", 4)
        } else if tail.starts_with("&gt;") {
            (">", 4)
        } else if tail.starts_with("&quot;") {
            ("\"", 6)
        } else if tail.starts_with("&apos;") {
            ("'", 6)
        } else {
            // Not an entity we emit; keep verbatim (tolerant reader).
            ("&", 1)
        };
        out.push_str(entity);
        rest = &tail[len..];
    }
    out.push_str(rest);
    out
}

/// Index of the tag-closing `>` in `s` (which starts at `<`), skipping over
/// quoted attribute values (a `>` inside quotes does not end the tag).
pub(crate) fn find_tag_end(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    let mut quote: Option<u8> = None;
    for (i, &c) in b.iter().enumerate() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (None, b'"') | (None, b'\'') => quote = Some(c),
            (None, b'>') => return Some(i),
            _ => {}
        }
    }
    None
}

/// Canonical timestamp: exactly `YYYY-MM-DDTHH:mm:ss.fffffffZ`
/// (7 fractional digits, UTC, literal `Z`) per REQ-4.2.1/4.2.2.
pub fn canonical_ts(dt: &DateTime<Utc>) -> String {
    // timestamp_subsec_nanos() / 100 truncates nanoseconds to 100 ns units,
    // yielding exactly 7 fractional digits.
    format!(
        "{}.{:07}Z",
        dt.format("%Y-%m-%dT%H:%M:%S"),
        dt.timestamp_subsec_nanos() / 100
    )
}

/// Canonical timestamp for the current UTC time.
pub fn now_ts() -> String {
    canonical_ts(&Utc::now())
}

/// Wrap data element(s) in the RCM envelope (REQ-5.1.1/5.1.4/5.1.6).
/// `data_elements` must already end with a newline. Exactly one `<timestamp>`
/// is emitted, as the LAST direct child of `<RCM>`.
pub fn xml_doc(data_elements: &str, timestamp: &str) -> String {
    // The timestamp is element text: escape it (defense in depth - callers
    // may pass agent-controlled values, e.g. a keylog capture endtime).
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<RCM version=\"{}\" specversion=\"{}\">\n{}  <timestamp>{}</timestamp>\n</RCM>\n",
        ENVELOPE_VERSION, SPEC_VERSION, data_elements, xml_escape(timestamp)
    )
}

/// REQ-6.3.1/6.3.2 atomic write: write `<path>.tmp` in the same directory,
/// fsync, then rename over the final name. The `.tmp` file is deleted on any
/// error so a failed write never masquerades as data (REQ-16.2).
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), RcmError> {
    let mut tmp_name = path.as_os_str().to_os_string();
    tmp_name.push(".tmp");
    let tmp = Path::new(&tmp_name).to_path_buf();

    enum Outcome {
        Done,
        Retry,
        Failed(RcmError),
    }

    // Concurrent atomic_writes to the SAME path are legal (last writer
    // wins). One racer's crash-leftover cleanup can remove the other's
    // in-flight .tmp; the victim's rename then fails ENOENT, which is
    // recoverable by simply retrying the whole write.
    for attempt in 0..5u32 {
        // Tracks whether WE created the .tmp in this attempt: only then is
        // it ours to remove on the error path (never delete a hostile
        // symlink or a racing writer's temp file).
        let mut created_tmp = false;
        let out = (|| -> Outcome {
            // Security posture: refuse to write through a symlinked final path.
            if let Ok(meta) = path.symlink_metadata() {
                if meta.file_type().is_symlink() {
                    return Outcome::Failed(RcmError(format!(
                        "refusing to write through symlink: {}",
                        path.display()
                    )));
                }
            }
            // Create the .tmp with O_EXCL so we never truncate or write
            // through a file someone else placed there.
            let mut f = match OpenOptions::new().write(true).create_new(true).open(&tmp)
            {
                Ok(f) => {
                    created_tmp = true;
                    f
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    match tmp.symlink_metadata() {
                        // A symlink at the .tmp path is hostile: hard error,
                        // never remove or follow it.
                        Ok(md) if md.file_type().is_symlink() => {
                            return Outcome::Failed(RcmError(format!(
                                "refusing to write through symlink: {}",
                                tmp.display()
                            )));
                        }
                        // A regular file is a crash leftover from a previous
                        // atomic_write: remove it and retry create_new ONCE.
                        Ok(_) => {
                            if let Err(e) = std::fs::remove_file(&tmp) {
                                return Outcome::Failed(e.into());
                            }
                            match OpenOptions::new()
                                .write(true)
                                .create_new(true)
                                .open(&tmp)
                            {
                                Ok(f) => {
                                    created_tmp = true;
                                    f
                                }
                                Err(e2)
                                    if e2.kind() == std::io::ErrorKind::AlreadyExists =>
                                {
                                    return Outcome::Failed(RcmError(format!(
                                        "racing writer at temp path: {}",
                                        tmp.display()
                                    )));
                                }
                                Err(e2) => return Outcome::Failed(e2.into()),
                            }
                        }
                        Err(e2) => return Outcome::Failed(e2.into()),
                    }
                }
                Err(e) => return Outcome::Failed(e.into()),
            };
            if let Err(e) = f.write_all(bytes) {
                return Outcome::Failed(e.into());
            }
            if let Err(e) = f.sync_all() {
                return Outcome::Failed(e.into());
            }
            match std::fs::rename(&tmp, path) {
                Ok(()) => {
                    // The rename consumed our .tmp (it IS the final file).
                    created_tmp = false;
                }
                // Our .tmp vanished underneath us: a racing writer took it
                // for a crash leftover. Recoverable - retry the write.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && attempt < 4 => {
                    return Outcome::Retry;
                }
                Err(e) => return Outcome::Failed(e.into()),
            }
            // fsync the containing directory so the rename itself is durable.
            #[cfg(unix)]
            {
                let parent = path.parent().unwrap_or_else(|| Path::new("."));
                if let Err(e) = std::fs::File::open(parent).and_then(|d| d.sync_all()) {
                    return Outcome::Failed(e.into());
                }
            }
            Outcome::Done
        })();
        match out {
            Outcome::Done => return Ok(()),
            Outcome::Retry => continue,
            Outcome::Failed(e) => {
                if created_tmp {
                    let _ = std::fs::remove_file(&tmp);
                }
                return Err(e);
            }
        }
    }
    Err(RcmError(format!(
        "atomic_write: too many racing retries for {}",
        path.display()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn escape_all_five_entities() {
        assert_eq!(
            xml_escape("a&b<c>d\"e'f"),
            "a&amp;b&lt;c&gt;d&quot;e&apos;f"
        );
        assert_eq!(xml_escape("plain"), "plain");
    }

    #[test]
    fn unescape_roundtrip() {
        let s = "a&b<c>d\"e'f & stuff";
        assert_eq!(xml_unescape(&xml_escape(s)), s);
    }

    #[test]
    fn canonical_timestamp_format() {
        // 2026-01-06T08:11:00.1232010Z (123201000 ns -> 1232010 x100ns)
        let dt = Utc.with_ymd_and_hms(2026, 1, 6, 8, 11, 0).unwrap()
            + chrono::Duration::nanoseconds(123_201_000);
        assert_eq!(canonical_ts(&dt), "2026-01-06T08:11:00.1232010Z");
        // Zero fraction still emits 7 digits.
        let dt0 = Utc.with_ymd_and_hms(2026, 1, 6, 8, 11, 0).unwrap();
        assert_eq!(canonical_ts(&dt0), "2026-01-06T08:11:00.0000000Z");
    }

    #[test]
    fn now_ts_matches_canonical_regex() {
        let re = regex::Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z$").unwrap();
        assert!(re.is_match(&now_ts()));
    }

    #[test]
    fn xml_doc_envelope_shape() {
        let doc = xml_doc("  <file version=\"1\">\n  </file>\n", "2026-01-06T08:11:00.1232010Z");
        assert!(doc.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<RCM version=\"1\" specversion=\"2.1\">\n"));
        assert!(doc.ends_with("  <timestamp>2026-01-06T08:11:00.1232010Z</timestamp>\n</RCM>\n"));
        // Exactly one <timestamp> as last direct child of <RCM>.
        assert_eq!(doc.matches("<timestamp>").count(), 1);
        let ts_pos = doc.find("<timestamp>").unwrap();
        let close_pos = doc.find("</RCM>").unwrap();
        assert!(ts_pos < close_pos);
    }

    #[test]
    fn atomic_write_creates_and_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.txt");
        atomic_write(&p, b"one").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"one");
        atomic_write(&p, b"two").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        // No .tmp left behind.
        assert!(!dir.path().join("f.txt.tmp").exists());
    }

    #[test]
    fn escape_strips_xml10_invalid_chars() {
        // Control chars below 0x20 (except \t \n \r) and U+FFFE/U+FFFF are
        // dropped; the five entities still escape.
        assert_eq!(xml_escape("a\u{0001}b\u{0007}c\u{001F}d"), "abcd");
        assert_eq!(xml_escape("x\ty\nz\rw"), "x\ty\nz\rw");
        assert_eq!(xml_escape("p\u{FFFE}q\u{FFFF}r"), "pqr");
        assert_eq!(xml_escape("\u{007F}del"), "\u{007F}del"); // DEL allowed
        assert_eq!(
            xml_escape("a&b<c>d\"e'f"),
            "a&amp;b&lt;c&gt;d&quot;e&apos;f"
        );
    }

    #[test]
    fn xml_doc_escapes_timestamp() {
        let doc = xml_doc("  <x/>\n", "2026-01-06T08:11:00.1232010Z</timestamp><injected>pwn</injected><timestamp>");
        assert!(!doc.contains("<injected>"), "timestamp injection: {}", doc);
        assert_eq!(doc.matches("<timestamp>").count(), 1);
    }

    #[test]
    fn atomic_write_recovers_crash_leftover_tmp() {
        // A regular file at the .tmp path is a crash leftover: removed and
        // retried once, write succeeds.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.txt");
        std::fs::write(dir.path().join("f.txt.tmp"), b"stale").unwrap();
        atomic_write(&p, b"fresh").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"fresh");
        assert!(!dir.path().join("f.txt.tmp").exists());
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_refuses_tmp_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.txt");
        let outside = dir.path().join("outside.txt");
        std::fs::write(&outside, b"secret").unwrap();
        std::os::unix::fs::symlink(&outside, dir.path().join("f.txt.tmp")).unwrap();
        let r = atomic_write(&p, b"pwn");
        assert!(r.is_err(), "wrote through a .tmp symlink");
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "secret");
        // The hostile symlink is left in place (never removed by us).
        assert!(dir.path().join("f.txt.tmp").symlink_metadata().unwrap().file_type().is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_refuses_final_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.txt");
        let outside = dir.path().join("outside.txt");
        std::fs::write(&outside, b"secret").unwrap();
        std::os::unix::fs::symlink(&outside, &p).unwrap();
        assert!(atomic_write(&p, b"pwn").is_err());
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "secret");
    }
}