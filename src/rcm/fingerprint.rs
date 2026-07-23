// ./src/rcm/fingerprint.rs
// Machine and account fingerprints (Section 7). fingerprint.RCM.xml is a
// LIVING document (REQ-3.4.6): upsert_entry merges at KEY level without
// ever deleting existing keys or entries (REQ-7.6.6); a key present in
// both old and new data with DIFFERENT values keeps the existing value
// and is reported via the tool log (REQ-7.6.3).
//
// MD5 is used ONLY for the version-1 fingerprint algorithms and the Table 2
// md5 key, per REQ-17.1.1; integrity elsewhere uses SHA-256.

use std::path::Path;

use md5::{Digest, Md5};

use super::logs;
use super::package::RcmError;
use super::xml;

pub fn md5_hex(input: &str) -> String {
    hex::encode(Md5::digest(input.as_bytes()))
}

/// REQ-7.2.2/7.2.3: each field trimmed + lowercased, joined with '-'.
pub fn windows_os_uid(os_version: &str, install_date: &str, hostname: &str, owner: &str) -> String {
    let norm = |s: &str| s.trim().to_lowercase();
    md5_hex(&format!(
        "{}-{}-{}-{}",
        norm(os_version),
        norm(install_date),
        norm(hostname),
        norm(owner)
    ))
}

/// REQ-7.3.2/7.3.4: serial trimmed verbatim-case, BIOS UUID trimmed +
/// uppercased, joined with '-'.
pub fn hardware_uid(boot_serial: &str, bios_uuid: &str) -> String {
    md5_hex(&format!(
        "{}-{}",
        boot_serial.trim(),
        bios_uuid.trim().to_uppercase()
    ))
}

/// REQ-7.4.1 service account: md5(lowercase "<provider>/<account>").
pub fn service_account_uid(provider: &str, account: &str) -> String {
    md5_hex(&format!("{}/{}", provider, account).to_lowercase().as_str())
}

/// REQ-7.4.1 local account: md5(lowercase "<hostname>/<username>").
pub fn local_account_uid(hostname: &str, username: &str) -> String {
    md5_hex(&format!("{}/{}", hostname, username).to_lowercase().as_str())
}

/// REQ-7.2.6: md5(lowercase uuid).
pub fn linux_rootfs_uid(root_uuid: &str) -> String {
    md5_hex(&root_uuid.trim().to_lowercase())
}

pub struct FingerprintEntry {
    pub target: String,        // "machine" | "account"
    pub fp_type: String,       // "os" | "hardware" | "user"
    pub version: u32,          // 1
    pub uid: Option<String>,
    /// ordered keys AFTER uid: e.g. [("hostname","USER-PC"),("osversion","6.1.7601"),("usertag","NONE")]
    pub fields: Vec<(String, String)>,
}

/// One segment of a parsed `<fingerprint>` block's content.
#[derive(Clone)]
enum Seg {
    /// A child element, kept VERBATIM (including any attributes, e.g.
    /// `<hash type="md5">...</hash>`, and self-closing `<x/>` forms) so a
    /// merge re-render never loses data (REQ-7.6.6).
    Elem {
        name: String,
        /// Inner text used only for the identical-vs-conflicting
        /// comparison (raw escaped bytes, matching entry_children output).
        cmp: String,
        /// Full element text, `<k ...>...</k>` or `<k .../>`, verbatim.
        raw: String,
    },
    /// Comments (`<!--...-->`), processing instructions (`<?...?>`) and
    /// other non-element markup, preserved verbatim in re-renders.
    Verbatim(String),
}

/// One parsed `<fingerprint ...>` block from an existing document.
struct ParsedEntry {
    target: String,
    fp_type: String,
    version: String,
    /// The opening tag verbatim (`<fingerprint ...>`), so attribute order,
    /// quoting style and unknown attributes survive a merge re-render.
    open_tag: String,
    /// Byte offsets of the block (`<fingerprint ...>...</fingerprint>`) in
    /// the parsed document: merges splice a replacement into exactly this
    /// range, leaving every other byte of the document untouched.
    start: usize,
    end: usize,
    /// Ordered content segments of the block.
    segs: Vec<Seg>,
}

fn attr(tag: &str, name: &str) -> Option<String> {
    let needle = format!("{}=\"", name);
    let start = tag.find(&needle)? + needle.len();
    let end = tag[start..].find('"')? + start;
    Some(xml::xml_unescape(&tag[start..end]))
}

use super::xml::find_tag_end;

/// Scan for the next `<fingerprint` tag whose following character is a
/// tag-name boundary (`>` or whitespace), SKIPPING `<!--...-->`, `<?...?>`
/// and `<![CDATA[...]]>` regions (mirrors the custody parser's
/// find_event_open): a `<fingerprint` inside one of those is markup
/// content, never a real entry. Without this, a ghost block inside a
/// comment/CDATA is treated as a REAL entry - a merge would splice new
/// keys INSIDE the comment (invisible to conformant XML tools) or the
/// ghost would shadow a real same-tuple entry. Returns the index of '<'.
fn find_fingerprint_open(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        if b[i] != b'<' {
            i += 1;
            continue;
        }
        let tail = &s[i..];
        if tail.starts_with("<!--") {
            // Unterminated comment swallows the rest of the input.
            match tail.find("-->") {
                Some(e) => i += e + 3,
                None => return None,
            }
            continue;
        }
        if tail.starts_with("<?") {
            match tail.find("?>") {
                Some(e) => i += e + 2,
                None => return None,
            }
            continue;
        }
        if tail.starts_with("<![CDATA[") {
            match tail.find("]]>") {
                Some(e) => i += e + 3,
                None => return None,
            }
            continue;
        }
        if let Some(after) = tail.strip_prefix("<fingerprint") {
            if after.starts_with('>') || after.starts_with(char::is_whitespace) {
                return Some(i);
            }
            // e.g. "<fingerprintx" - not our element.
        }
        i += 1;
    }
    None
}

/// Parse the inner content of a `<fingerprint>` block into ordered
/// segments. Returns None when the content is not parseable as element
/// children + preserved markup (the caller then refuses to rewrite).
fn parse_block_content(inner: &str) -> Option<Vec<Seg>> {
    let mut segs = Vec::new();
    let mut cur = inner;
    while let Some(lt) = cur.find('<') {
        let tail = &cur[lt..];
        if tail.starts_with("</") {
            // Stray closing tag inside the block: malformed.
            return None;
        }
        if tail.starts_with("<!--") {
            let end = tail.find("-->")?;
            let v = &tail[..end + 3];
            segs.push(Seg::Verbatim(v.to_string()));
            cur = &tail[end + 3..];
            continue;
        }
        if tail.starts_with("<?") {
            let end = tail.find("?>")?;
            segs.push(Seg::Verbatim(tail[..end + 2].to_string()));
            cur = &tail[end + 2..];
            continue;
        }
        if tail.starts_with("<!") {
            // CDATA or other markup declarations: preserve verbatim.
            if tail.starts_with("<![CDATA[") {
                let end = tail.find("]]>")?;
                segs.push(Seg::Verbatim(tail[..end + 3].to_string()));
                cur = &tail[end + 3..];
            } else {
                let gt = tail.find('>')?;
                segs.push(Seg::Verbatim(tail[..gt + 1].to_string()));
                cur = &tail[gt + 1..];
            }
            continue;
        }
        // Element: the tag NAME runs only to the first whitespace, '/' or
        // '>' - attributes never leak into the name.
        let after_lt = &tail[1..];
        let name_end = after_lt
            .find(|c: char| c.is_whitespace() || c == '/' || c == '>')?;
        let name = &after_lt[..name_end];
        if name.is_empty() {
            return None;
        }
        let gt = find_tag_end(tail)?;
        let self_closing = tail[..gt].trim_end().ends_with('/');
        if self_closing {
            segs.push(Seg::Elem {
                name: name.to_string(),
                cmp: String::new(),
                raw: tail[..gt + 1].to_string(),
            });
            cur = &tail[gt + 1..];
            continue;
        }
        let body = &tail[gt + 1..];
        let close_tag = format!("</{}>", name);
        let cpos = body.find(&close_tag)?;
        let raw_end = gt + 1 + cpos + close_tag.len();
        segs.push(Seg::Elem {
            name: name.to_string(),
            cmp: body[..cpos].to_string(),
            raw: tail[..raw_end].to_string(),
        });
        cur = &tail[raw_end..];
    }
    Some(segs)
}

/// Tolerant parser: extracts every direct `<fingerprint>` block (with its
/// byte range in `doc`). Content that does not parse fails the whole parse
/// (None) - the caller REFUSES to rewrite the document rather than risking
/// data loss (REQ-3.4.4).
fn parse_entries(doc: &str) -> Option<Vec<ParsedEntry>> {
    let mut out = Vec::new();
    let mut rest = doc;
    let mut base = 0usize; // byte offset of `rest` within `doc`
    loop {
        // Comment/PI/CDATA-aware scan: ghost `<fingerprint` markup inside
        // those regions is skipped, so the byte ranges recorded below NEVER
        // point into a comment/CDATA and merges/appends never land there.
        let open = match find_fingerprint_open(rest) {
            Some(i) => i,
            None => break,
        };
        let after_open = &rest[open..];
        let tag_end = find_tag_end(after_open)?;
        let open_tag = after_open[..=tag_end].to_string();
        let close = after_open.find("</fingerprint>")?;
        if close < tag_end {
            return None;
        }
        let inner = &after_open[tag_end + 1..close];
        let block_end = open + close + "</fingerprint>".len();

        let target = attr(&open_tag, "target").unwrap_or_default();
        let fp_type = attr(&open_tag, "type").unwrap_or_default();
        let version = attr(&open_tag, "version").unwrap_or_else(|| "1".into());

        let segs = parse_block_content(inner)?;

        out.push(ParsedEntry {
            target,
            fp_type,
            version,
            open_tag,
            start: base + open,
            end: base + block_end,
            segs,
        });
        base += block_end;
        rest = &after_open[close + "</fingerprint>".len()..];
    }
    Some(out)
}

/// Render the entry's child element list as (key, escaped-text) pairs,
/// uid first (Table 1 ordering).
fn entry_children(entry: &FingerprintEntry) -> Vec<(String, String)> {
    let mut v = Vec::new();
    if let Some(u) = &entry.uid {
        v.push(("uid".to_string(), xml::xml_escape(u)));
    }
    for (k, val) in &entry.fields {
        v.push((k.clone(), xml::xml_escape(val)));
    }
    v
}

fn render_entry(entry: &FingerprintEntry) -> String {
    let mut s = format!(
        "  <fingerprint target=\"{}\" type=\"{}\" version=\"{}\">\n",
        xml::xml_escape(&entry.target),
        xml::xml_escape(&entry.fp_type),
        entry.version
    );
    for (k, v) in entry_children(entry) {
        s.push_str(&format!("    <{}>{}</{}>\n", k, v, k));
    }
    s.push_str("  </fingerprint>\n");
    s
}

/// Outcome of an `upsert_entry` call.
#[derive(Debug, PartialEq, Eq)]
pub enum UpsertOutcome {
    /// Identical tuple + fields: nothing changed.
    NoChange,
    /// Same tuple; one or more previously absent keys were added.
    Merged,
    /// New (target,type,version) tuple: entry appended.
    Added,
    /// Same tuple, but at least one shared key carried a DIFFERENT value;
    /// the existing value was kept (REQ-7.6.3). Carries the conflicting
    /// key names. (New keys may also have been merged in the same call.)
    ConflictKept(Vec<String>),
}

/// Render a `<fingerprint>` block from its verbatim opening tag and
/// segments, in the SAME shape the parser captured (no leading indent, no
/// trailing newline - both belong to the surrounding document and stay
/// byte-verbatim): existing children keep their EXACT original text
/// (attributes, self-closing forms), comments and PIs are preserved, only
/// genuinely new keys are freshly rendered.
fn render_block_body(open_tag: &str, segs: &[Seg]) -> String {
    let mut s = String::new();
    s.push_str(open_tag);
    s.push('\n');
    for seg in segs {
        match seg {
            Seg::Elem { raw, .. } => {
                s.push_str("    ");
                s.push_str(raw);
                s.push('\n');
            }
            Seg::Verbatim(v) => {
                s.push_str("    ");
                s.push_str(v.trim());
                s.push('\n');
            }
        }
    }
    s.push_str("  </fingerprint>");
    s
}

/// Field keys become XML element NAMES verbatim: they MUST satisfy the
/// XML Name production (ASCII subset `^[A-Za-z_][A-Za-z0-9._-]*$`) or the
/// rendered tag is malformed (e.g. `<a b>`) and every future parse of the
/// document fails - bricking all later upserts.
fn is_valid_xml_name(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// REQ-7.6.2/7.6.3/7.6.5: read existing fingerprint.RCM.xml (tolerating its
/// absence), merge `entry` keyed by (target,type,version): identical ->
/// no-op; new tuple -> append; same tuple -> KEY-LEVEL merge: keys absent from
/// the existing entry are added; same key + same value -> no-op; same key +
/// different value -> the EXISTING value is kept and a WARN discrepancy line
/// naming that key is appended to the tool log (component "fingerprint",
/// REQ-7.6.3). Keys and entries are never deleted (living document,
/// REQ-7.6.6). Atomic write per Section 6.3.
pub fn upsert_entry(root: &Path, entry: &FingerprintEntry) -> Result<UpsertOutcome, RcmError> {
    // Field keys are interpolated into element names verbatim: validate
    // BEFORE touching the document - an invalid key must be a hard error
    // with the document left untouched (a rendered `<a b>` would be
    // malformed XML and brick every future upsert).
    for (k, _) in &entry.fields {
        if !is_valid_xml_name(k) {
            return Err(RcmError(format!(
                "invalid fingerprint field name (not an XML Name): {:?}",
                k
            )));
        }
    }

    let path = root.join("fingerprint.RCM.xml");
    let existing = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.into()),
    };

    // Fresh document: render the full envelope.
    if existing.trim().is_empty() {
        let data = render_entry(entry);
        xml::atomic_write(&path, xml::xml_doc(&data, &xml::now_ts()).as_bytes())?;
        return Ok(UpsertOutcome::Added);
    }

    let entries = match parse_entries(&existing) {
        Some(v) => v,
        // Unparseable existing document: refuse to destroy it (REQ-3.4.4).
        None => {
            return Err(RcmError(
                "fingerprint.RCM.xml exists but does not parse; refusing to rewrite".into(),
            ))
        }
    };

    let new_children = entry_children(entry);
    let mut matched = None;
    for (idx, e) in entries.iter().enumerate() {
        if e.target == entry.target
            && e.fp_type == entry.fp_type
            && e.version == entry.version.to_string()
        {
            matched = Some(idx);
            break;
        }
    }

    if let Some(idx) = matched {
        // KEY-LEVEL merge into the existing tuple (REQ-7.6.2/7.6.3).
        let mut merged = entries[idx].segs.clone();
        let mut conflicts: Vec<String> = Vec::new();
        let mut added_keys = false;
        for (k, v) in &new_children {
            let pos = merged
                .iter()
                .position(|s| matches!(s, Seg::Elem { name, .. } if name == k));
            match pos {
                Some(p) => {
                    if let Seg::Elem { cmp, .. } = &merged[p] {
                        if cmp != v {
                            // Same key, different value: keep the EXISTING
                            // value, record the discrepancy for THIS key only
                            // (REQ-7.6.3).
                            conflicts.push(k.clone());
                            let _ = logs::log(
                                root,
                                "rcm-server",
                                "fingerprint",
                                "WARN",
                                &format!(
                                    "fingerprint discrepancy for target={} type={} version={} key={}: existing value kept, new value rejected",
                                    entry.target, entry.fp_type, entry.version, k
                                ),
                            );
                        }
                    }
                }
                None => {
                    // Key absent from the existing entry: add it. uid goes
                    // first per Table 1 ordering (before the first element).
                    let seg = Seg::Elem {
                        name: k.clone(),
                        cmp: v.clone(),
                        raw: format!("<{}>{}</{}>", k, v, k),
                    };
                    if k == "uid" {
                        let at = merged
                            .iter()
                            .position(|s| matches!(s, Seg::Elem { .. }))
                            .unwrap_or(merged.len());
                        merged.insert(at, seg);
                    } else {
                        merged.push(seg);
                    }
                    added_keys = true;
                }
            }
        }
        if conflicts.is_empty() && !added_keys {
            return Ok(UpsertOutcome::NoChange);
        }
        let outcome = if conflicts.is_empty() {
            UpsertOutcome::Merged
        } else {
            UpsertOutcome::ConflictKept(conflicts)
        };
        // Splice: replace ONLY the matched block's byte range; every other
        // byte of the document - BOM, envelope, inter-block comments,
        // foreign top-level elements, trailing content - stays verbatim
        // (living document, REQ-7.6.6 / REQ-5.2.2).
        let e = &entries[idx];
        let mut doc = String::with_capacity(existing.len() + 64);
        doc.push_str(&existing[..e.start]);
        doc.push_str(&render_block_body(&e.open_tag, &merged));
        doc.push_str(&existing[e.end..]);
        xml::atomic_write(&path, doc.as_bytes())?;
        return Ok(outcome);
    }

    // New tuple: insert the new block right after the LAST fingerprint
    // block (or before </RCM> when there are none), preserving the rest of
    // the document byte-verbatim.
    let block = render_entry(entry);
    let block = block.trim_end(); // surrounding newlines come from the doc
    let mut doc = existing;
    if let Some(last) = entries.last() {
        doc.insert_str(last.end, &format!("\n{}", block));
    } else if let Some(pos) = doc.rfind("</RCM>") {
        doc.insert_str(pos, &format!("{}\n", block));
    } else {
        doc.push_str(block);
        doc.push('\n');
    }
    xml::atomic_write(&path, doc.as_bytes())?;
    Ok(UpsertOutcome::Added)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known-answer vectors from RCM-SPEC-001 Section 7 examples.
    #[test]
    fn known_answer_uids() {
        assert_eq!(
            windows_os_uid("6.1.7601", "20261212121240.000000-300", "USER-PC", "Bill User"),
            "61147a5ed5eca02b5fc1241be50c9197"
        );
        assert_eq!(
            hardware_uid("W-DCW2H0C073195", "412af010-43b2-18f2-0000-c5c239b71d30"),
            "61d1d73c9d44978637550e77e5a20b96"
        );
        assert_eq!(
            service_account_uid("beembo", "example@example.com"),
            "a70595c556a1e9bc402c12fbd664063e"
        );
        assert_eq!(
            local_account_uid("USER-PC", "Administrator"),
            "74d0fd404b39ad6f4a1f6736476499ff"
        );
        assert_eq!(
            linux_rootfs_uid("27a0727c-d9cb-c412-a618-9c573f9a015f"),
            "a098ec3e9cdd7183b6db428b64bdb7e0"
        );
    }

    fn os_entry() -> FingerprintEntry {
        FingerprintEntry {
            target: "machine".into(),
            fp_type: "os".into(),
            version: 1,
            uid: Some("61147a5ed5eca02b5fc1241be50c9197".into()),
            fields: vec![
                ("hostname".into(), "USER-PC".into()),
                ("osversion".into(), "6.1.7601".into()),
                ("usertag".into(), "NONE".into()),
            ],
        }
    }

    #[test]
    fn upsert_appends_then_noops_then_warns_on_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // New tuple -> appended.
        upsert_entry(root, &os_entry()).unwrap();
        let doc1 = std::fs::read_to_string(root.join("fingerprint.RCM.xml")).unwrap();
        assert_eq!(doc1.matches("<fingerprint ").count(), 1);
        assert!(doc1.contains("<uid>61147a5ed5eca02b5fc1241be50c9197</uid>"));

        // Identical -> no-op (file content unchanged).
        upsert_entry(root, &os_entry()).unwrap();
        let doc2 = std::fs::read_to_string(root.join("fingerprint.RCM.xml")).unwrap();
        assert_eq!(doc1.matches("<fingerprint ").count(), 1);
        assert_eq!(
            doc1.matches("<fingerprint ").count(),
            doc2.matches("<fingerprint ").count()
        );

        // Different tuple -> appended alongside.
        let mut hw = os_entry();
        hw.fp_type = "hardware".into();
        upsert_entry(root, &hw).unwrap();
        let doc3 = std::fs::read_to_string(root.join("fingerprint.RCM.xml")).unwrap();
        assert_eq!(doc3.matches("<fingerprint ").count(), 2);

        // Same tuple, conflicting field -> existing kept + WARN in the log.
        let mut conflict = os_entry();
        conflict.fields[0].1 = "OTHER-PC".into();
        upsert_entry(root, &conflict).unwrap();
        let doc4 = std::fs::read_to_string(root.join("fingerprint.RCM.xml")).unwrap();
        assert_eq!(doc4.matches("<fingerprint ").count(), 2);
        assert!(doc4.contains("<hostname>USER-PC</hostname>"));
        assert!(!doc4.contains("OTHER-PC"));

        let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let log_file = root
            .join("logs/rcm-server/fingerprint")
            .join(&date)
            .join("0000.log");
        let log_body = std::fs::read_to_string(log_file).unwrap();
        assert!(log_body.contains(" WARN "));
        assert!(log_body.contains("discrepancy"));
    }

    fn seed(root: &std::path::Path, body: &str) {
        std::fs::write(root.join("fingerprint.RCM.xml"), body).unwrap();
    }

    fn read_doc(root: &std::path::Path) -> String {
        std::fs::read_to_string(root.join("fingerprint.RCM.xml")).unwrap()
    }

    fn bare_entry(target: &str, ty: &str, fields: &[(&str, &str)]) -> FingerprintEntry {
        FingerprintEntry {
            target: target.into(),
            fp_type: ty.into(),
            version: 1,
            uid: None,
            fields: fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    // Ported: adv_attribute_bearing_child_is_dropped_by_merge.
    #[test]
    fn attribute_bearing_child_survives_merge() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        seed(
            root,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<RCM version=\"1\" specversion=\"2.1\">\n  <fingerprint target=\"machine\" type=\"os\" version=\"1\">\n    <hostname>USER-PC</hostname>\n    <hash type=\"md5\">deadbeef</hash>\n    <osversion>6.1</osversion>\n  </fingerprint>\n  <timestamp>2026-01-06T08:11:00.1232010Z</timestamp>\n</RCM>\n",
        );
        let out = upsert_entry(
            root,
            &bare_entry("machine", "os", &[("hostname", "USER-PC"), ("newkey", "v")]),
        )
        .unwrap();
        assert_eq!(out, UpsertOutcome::Merged);
        let doc = read_doc(root);
        // The attribute-bearing element round-trips UNTOUCHED, and every
        // key after it survives (REQ-7.6.6).
        assert!(
            doc.contains("<hash type=\"md5\">deadbeef</hash>"),
            "attribute-bearing child lost: {}",
            doc
        );
        assert!(doc.contains("<osversion>6.1</osversion>"));
        assert!(doc.contains("<newkey>v</newkey>"));
    }

    // Ported: self-closing children and comments/PIs round-trip verbatim.
    #[test]
    fn self_closing_children_and_comments_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        seed(
            root,
            "<RCM>\n  <fingerprint target=\"machine\" type=\"os\" version=\"1\">\n    <hostname>USER-PC</hostname>\n    <!-- imported -->\n    <?tool marker?>\n    <empty/>\n    <hash type=\"md5\"/>\n  </fingerprint>\n</RCM>\n",
        );
        let out = upsert_entry(
            root,
            &bare_entry("machine", "os", &[("hostname", "USER-PC"), ("k", "v")]),
        )
        .unwrap();
        assert_eq!(out, UpsertOutcome::Merged);
        let doc = read_doc(root);
        for kept in [
            "<!-- imported -->",
            "<?tool marker?>",
            "<empty/>",
            "<hash type=\"md5\"/>",
            "<k>v</k>",
        ] {
            assert!(doc.contains(kept), "lost {:?}: {}", kept, doc);
        }
    }

    // Ported: adv_attribute_order_and_single_quotes (order-insensitive
    // tuple matching; single-quoted attrs stay a distinct tuple).
    #[test]
    fn attribute_order_still_matches_tuple() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        seed(
            root,
            "<RCM>\n  <fingerprint version=\"1\" type=\"os\" target=\"machine\">\n    <hostname>H</hostname>\n  </fingerprint>\n</RCM>\n",
        );
        let out = upsert_entry(
            root,
            &bare_entry("machine", "os", &[("hostname", "H"), ("k2", "v")]),
        )
        .unwrap();
        assert_eq!(out, UpsertOutcome::Merged, "attribute order broke tuple matching");
        let doc = read_doc(root);
        assert_eq!(doc.matches("<fingerprint ").count(), 1);
        // The verbatim opening tag (original attribute order) survives.
        assert!(doc.contains("<fingerprint version=\"1\" type=\"os\" target=\"machine\">"));
    }

    // Ported: adv_entity_escaped_values_roundtrip.
    #[test]
    fn entity_escaped_values_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        seed(
            root,
            "<RCM>\n  <fingerprint target=\"machine\" type=\"os\" version=\"1\">\n    <hostname>a&amp;b&lt;c&gt;</hostname>\n  </fingerprint>\n</RCM>\n",
        );
        let out = upsert_entry(root, &bare_entry("machine", "os", &[("hostname", "a&b<c>")])).unwrap();
        assert_eq!(out, UpsertOutcome::NoChange);
    }

    // Ported: adv_gt_inside_attribute_value.
    #[test]
    fn gt_inside_attribute_value_parses() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        seed(
            root,
            "<RCM>\n  <fingerprint target=\"a&gt;b\" type=\"os\" version=\"1\">\n    <hostname>H</hostname>\n  </fingerprint>\n</RCM>\n",
        );
        let out = upsert_entry(
            root,
            &bare_entry("a>b", "os", &[("hostname", "H"), ("k", "v")]),
        )
        .unwrap();
        assert_eq!(out, UpsertOutcome::Merged);
        let doc = read_doc(root);
        assert!(doc.contains("<hostname>H</hostname>"));
        assert!(doc.contains("<k>v</k>"));
    }

    // Ported: adv_unparseable_document_refused_untouched.
    #[test]
    fn unparseable_document_refused_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let bad = "<RCM>\n  <fingerprint target=\"machine\" type=\"os\" version=\"1\">\n    <hostname>H</hostname>\n  <!-- no closing fingerprint tag -->\n</RCM>\n";
        seed(root, bad);
        let r = upsert_entry(root, &bare_entry("machine", "os", &[("hostname", "H")]));
        assert!(r.is_err(), "unparseable doc should be refused");
        assert_eq!(read_doc(root), bad, "unparseable doc was modified");
    }

    // Ported: adv_whitespace_sensitive_compare (byte-level compare, the
    // existing value is kept verbatim on conflict).
    #[test]
    fn whitespace_sensitive_compare_keeps_existing() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        seed(
            root,
            "<RCM>\n  <fingerprint target=\"machine\" type=\"os\" version=\"1\">\n    <hostname> H </hostname>\n  </fingerprint>\n</RCM>\n",
        );
        let out = upsert_entry(root, &bare_entry("machine", "os", &[("hostname", "H")])).unwrap();
        assert_eq!(out, UpsertOutcome::ConflictKept(vec!["hostname".into()]));
        let doc = read_doc(root);
        assert!(doc.contains("<hostname> H </hostname>"), "existing value not kept");
    }

    // Ported: adv_duplicate_same_tuple_entries.
    #[test]
    fn duplicate_same_tuple_entries_both_kept() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        seed(
            root,
            "<RCM>\n  <fingerprint target=\"machine\" type=\"os\" version=\"1\">\n    <hostname>FIRST</hostname>\n  </fingerprint>\n  <fingerprint target=\"machine\" type=\"os\" version=\"1\">\n    <hostname>SECOND</hostname>\n  </fingerprint>\n</RCM>\n",
        );
        let out = upsert_entry(
            root,
            &bare_entry("machine", "os", &[("hostname", "FIRST"), ("k", "v")]),
        )
        .unwrap();
        assert_eq!(out, UpsertOutcome::Merged);
        let doc = read_doc(root);
        assert_eq!(doc.matches("<fingerprint ").count(), 2, "duplicate entry lost");
        assert!(doc.contains("SECOND"), "second duplicate's data lost");
    }

    // Ported: adv_crlf_document / adv_cdata_like_sequence_preserved.
    #[test]
    fn crlf_and_cdata_like_content_survive() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(
            root.join("fingerprint.RCM.xml"),
            "<RCM>\r\n  <fingerprint target=\"machine\" type=\"os\" version=\"1\">\r\n    <hostname>H</hostname>\r\n  </fingerprint>\r\n</RCM>\r\n",
        )
        .unwrap();
        upsert_entry(root, &bare_entry("machine", "os", &[("hostname", "H"), ("k", "v")])).unwrap();
        let doc = read_doc(root);
        assert!(doc.contains("<hostname>H</hostname>"));
        assert!(doc.contains("<k>v</k>"));

        let dir2 = tempfile::tempdir().unwrap();
        let root2 = dir2.path();
        seed(
            root2,
            "<RCM>\n  <fingerprint target=\"machine\" type=\"os\" version=\"1\">\n    <note>a ]]> b</note>\n  </fingerprint>\n</RCM>\n",
        );
        upsert_entry(root2, &bare_entry("machine", "os", &[("note", "a ]]> b"), ("k", "v")])).unwrap();
        let doc2 = read_doc(root2);
        assert!(doc2.contains("a ]]> b"), "]]> value lost");
    }

    // Field keys are rendered as element NAMES - validate them
    // against the XML Name production or a key like "a b" renders `<a b>`
    // (malformed XML) and bricks every future upsert.
    #[test]
    fn invalid_xml_name_keys_rejected_doc_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // Seed a valid document first.
        upsert_entry(root, &bare_entry("machine", "os", &[("hostname", "H")])).unwrap();
        let before = read_doc(root);

        for bad_key in ["a b", "9lives", "a<b", "a/b", "", "a\"b", "a:b", "key\n"] {
            let r = upsert_entry(root, &bare_entry("machine", "os", &[(bad_key, "v")]));
            assert!(r.is_err(), "key {:?} accepted", bad_key);
            assert_eq!(read_doc(root), before, "doc modified by rejected key {:?}", bad_key);
        }
        // A fresh doc is likewise never created by an invalid key.
        let dir2 = tempfile::tempdir().unwrap();
        let r = upsert_entry(dir2.path(), &bare_entry("machine", "os", &[("a b", "v")]));
        assert!(r.is_err());
        assert!(!dir2.path().join("fingerprint.RCM.xml").exists());

        // Legal Name characters still work: letters, digits (not first),
        // '.', '_', '-'.
        let dir3 = tempfile::tempdir().unwrap();
        upsert_entry(
            dir3.path(),
            &bare_entry("machine", "os", &[("_ok", "1"), ("a.b-c_d9", "2")]),
        )
        .unwrap();
        let doc = std::fs::read_to_string(dir3.path().join("fingerprint.RCM.xml")).unwrap();
        assert!(doc.contains("<_ok>1</_ok>"));
        assert!(doc.contains("<a.b-c_d9>2</a.b-c_d9>"));
        // And the rendered doc still parses for the next upsert.
        upsert_entry(dir3.path(), &bare_entry("machine", "os", &[("more", "3")])).unwrap();
    }

    // Regions OUTSIDE the <fingerprint> blocks (BOM, inter-block
    // comments, foreign top-level elements, trailing content) survive both
    // the merge and the append path byte-verbatim.
    #[test]
    fn foreign_regions_preserved_byte_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let doc = "\u{FEFF}<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<RCM version=\"1\" specversion=\"2.1\">\n  <!-- leading comment -->\n  <foreign-elem a=\"1\">keep me</foreign-elem>\n  <fingerprint target=\"machine\" type=\"os\" version=\"1\">\n    <hostname>H</hostname>\n  </fingerprint>\n  <!-- inter-block comment -->\n  <fingerprint target=\"machine\" type=\"hardware\" version=\"1\">\n    <serial>S</serial>\n  </fingerprint>\n  <timestamp>2026-01-06T08:11:00.1232010Z</timestamp>\n</RCM>\n<!-- trailing content -->\n";
        seed(root, doc);

        // MERGE path.
        let out = upsert_entry(
            root,
            &bare_entry("machine", "os", &[("hostname", "H"), ("k", "v")]),
        )
        .unwrap();
        assert_eq!(out, UpsertOutcome::Merged);
        let merged = read_doc(root);
        assert!(merged.starts_with('\u{FEFF}'), "BOM lost: {:?}", merged);
        for kept in [
            "<!-- leading comment -->",
            "<foreign-elem a=\"1\">keep me</foreign-elem>",
            "<!-- inter-block comment -->",
            "<serial>S</serial>",
            "<!-- trailing content -->",
            "<k>v</k>",
        ] {
            assert!(merged.contains(kept), "merge lost {:?}: {}", kept, merged);
        }

        // APPEND path (new tuple) on top of the merged doc.
        let out2 = upsert_entry(root, &bare_entry("account", "user", &[("u", "1")])).unwrap();
        assert_eq!(out2, UpsertOutcome::Added);
        let appended = read_doc(root);
        for kept in [
            "<!-- leading comment -->",
            "<foreign-elem a=\"1\">keep me</foreign-elem>",
            "<!-- inter-block comment -->",
            "<serial>S</serial>",
            "<!-- trailing content -->",
            "<u>1</u>",
        ] {
            assert!(appended.contains(kept), "append lost {:?}: {}", kept, appended);
        }
        assert_eq!(appended.matches("<fingerprint ").count(), 3);
        assert!(appended.starts_with('\u{FEFF}'));
    }

    // A `<fingerprint>` inside a comment/PI/CDATA is markup
    // content, never a real entry - the parser must skip those regions so
    // merges/appends never land inside them.
    fn assert_python_parseable(doc: &str) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("doc.xml");
        std::fs::write(&p, doc).unwrap();
        let out = std::process::Command::new("python3")
            .arg("-c")
            .arg("import sys, xml.etree.ElementTree as ET; ET.parse(sys.argv[1])")
            .arg(&p)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "python xml parse failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // Reproducer (a): comment ghost + merge -> ADDED new block AFTER the
    // comment (not Merged-into-comment); doc parses; 1 real entry; comment
    // byte-verbatim.
    #[test]
    fn comment_ghost_not_merged_new_block_outside_comment() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let ghost = "  <!-- <fingerprint target=\"machine\" type=\"os\" version=\"1\">\n    <hostname>GHOST</hostname>\n  </fingerprint> -->";
        seed(
            root,
            &format!(
                "<RCM>\n{}\n  <timestamp>2026-01-06T08:11:00.1232010Z</timestamp>\n</RCM>\n",
                ghost
            ),
        );
        let out = upsert_entry(root, &bare_entry("machine", "os", &[("hostname", "REAL")]))
            .unwrap();
        assert_eq!(out, UpsertOutcome::Added, "ghost treated as a real entry");
        let doc = read_doc(root);
        assert!(doc.contains(ghost), "comment not byte-verbatim: {}", doc);
        // Real (non-comment) entry count is exactly 1.
        let entries = parse_entries(&doc).unwrap();
        assert_eq!(entries.len(), 1, "ghost counted as real entry");
        assert!(entries[0].segs.iter().any(|s| matches!(
            s,
            Seg::Elem { name, cmp, .. } if name == "hostname" && cmp == "REAL"
        )));
        // The new block lands AFTER the comment, never inside it.
        assert!(doc.find("<hostname>REAL</hostname>").unwrap() > doc.find("-->").unwrap());
        assert_python_parseable(&doc);
    }

    // Reproducer (b): ghost comment BEFORE a real same-tuple entry must not
    // shadow it - the merge hits the REAL entry; the ghost stays untouched.
    #[test]
    fn ghost_comment_does_not_shadow_real_entry() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let ghost = "  <!-- <fingerprint target=\"machine\" type=\"os\" version=\"1\"><hostname>GHOST</hostname></fingerprint> -->";
        seed(
            root,
            &format!(
                "<RCM>\n{}\n  <fingerprint target=\"machine\" type=\"os\" version=\"1\">\n    <hostname>REAL</hostname>\n  </fingerprint>\n</RCM>\n",
                ghost
            ),
        );
        let out = upsert_entry(
            root,
            &bare_entry("machine", "os", &[("hostname", "REAL"), ("k", "v")]),
        )
        .unwrap();
        assert_eq!(out, UpsertOutcome::Merged);
        let doc = read_doc(root);
        assert!(doc.contains(ghost), "ghost modified: {}", doc);
        // The new key landed in the REAL entry (after the ghost comment).
        let kpos = doc.find("<k>v</k>").expect("key not merged into real entry");
        assert!(kpos > doc.find("-->").unwrap(), "key spliced into the ghost");
        let entries = parse_entries(&doc).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0]
            .segs
            .iter()
            .any(|s| matches!(s, Seg::Elem { name, .. } if name == "k")));
        assert_python_parseable(&doc);
    }

    // Reproducer (c): CDATA ghost -> append inserts AFTER the CDATA, never
    // inside it.
    #[test]
    fn cdata_ghost_append_lands_outside_cdata() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let cdata = "  <![CDATA[<fingerprint target=\"machine\" type=\"os\" version=\"1\"><hostname>GHOST</hostname></fingerprint>]]>";
        seed(root, &format!("<RCM>\n{}\n</RCM>\n", cdata));
        let out = upsert_entry(root, &bare_entry("machine", "os", &[("hostname", "REAL")]))
            .unwrap();
        assert_eq!(out, UpsertOutcome::Added);
        let doc = read_doc(root);
        assert!(doc.contains(cdata), "CDATA not byte-verbatim: {}", doc);
        let real = doc.find("<hostname>REAL</hostname>").unwrap();
        assert!(real > doc.find("]]>").unwrap(), "block spliced into CDATA");
        assert_eq!(parse_entries(&doc).unwrap().len(), 1);
        assert_python_parseable(&doc);
    }

    // Reproducer (d): document with ONLY a comment ghost (no real entries)
    // -> new block appended outside the comment, comment untouched.
    #[test]
    fn only_comment_ghost_appends_outside_comment() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let ghost = "  <!-- retired: <fingerprint target=\"machine\" type=\"os\" version=\"1\"><hostname>OLD</hostname></fingerprint> -->";
        seed(
            root,
            &format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<RCM version=\"1\" specversion=\"2.1\">\n{}\n</RCM>\n",
                ghost
            ),
        );
        let out = upsert_entry(root, &bare_entry("machine", "os", &[("hostname", "NEW")]))
            .unwrap();
        assert_eq!(out, UpsertOutcome::Added);
        let doc = read_doc(root);
        assert!(doc.contains(ghost), "comment not byte-verbatim: {}", doc);
        let entries = parse_entries(&doc).unwrap();
        assert_eq!(entries.len(), 1, "real entry not appended");
        assert!(entries[0].segs.iter().any(|s| matches!(
            s,
            Seg::Elem { name, cmp, .. } if name == "hostname" && cmp == "NEW"
        )));
        assert!(doc.find("<hostname>NEW</hostname>").unwrap() > doc.find("-->").unwrap());
        assert_python_parseable(&doc);
    }

    #[test]
    fn uid_element_only_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let mut e = os_entry();
        e.uid = None;
        upsert_entry(dir.path(), &e).unwrap();
        let doc = std::fs::read_to_string(dir.path().join("fingerprint.RCM.xml")).unwrap();
        assert!(!doc.contains("<uid>"));
        // hostname is then the first child.
        assert!(doc.contains("version=\"1\">\n    <hostname>USER-PC</hostname>"));
    }
}
