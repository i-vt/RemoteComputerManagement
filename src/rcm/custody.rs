// ./src/rcm/custody.rs
// Chain of custody (Section 17.3). custody.RCM.xml is append-only
// (REQ-17.3.2): each append atomically rewrites the document with all prior
// <event> blocks preserved verbatim plus the new event. Tamper evidence
// comes from the chainhash (Table 11): sha256 of the previous <event>
// element (normalized by per-line surrounding-whitespace stripping,
// intra-text whitespace preserved) concatenated with the current actor,
// action and time.

use std::path::Path;

use sha2::{Digest, Sha256};

use super::package::RcmError;
use super::xml;

pub enum CustodyAction {
    Collect,
    Package,
    Transfer,
    Receive,
    Archive,
    Access,
}

impl CustodyAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            CustodyAction::Collect => "COLLECT",
            CustodyAction::Package => "PACKAGE",
            CustodyAction::Transfer => "TRANSFER",
            CustodyAction::Receive => "RECEIVE",
            CustodyAction::Archive => "ARCHIVE",
            CustodyAction::Access => "ACCESS",
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// One segment of the parsed `<custody>` element content: an event block
/// (verbatim, the chainhash covers it AS WRITTEN) or any other region
/// (comments, stray markup), also preserved verbatim.
enum CustodySeg {
    Event(String),
    Other(String),
}

/// Scan for the next `<event` tag whose following character is a tag-name
/// boundary (`>` or whitespace), SKIPPING `<!--...-->`, `<?...?>` and
/// `<![CDATA[...]]>` regions (same ordering as the fingerprint parser):
/// an `<event` inside one of those is markup content, never an event
/// open. Without this, a comment containing `<event>` either hard-errors
/// every future append forever (no matching `</event>`) or gets hashed
/// into the chain as a misidentified block. Returns the index of '<'.
fn find_event_open(s: &str) -> Option<usize> {
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
        if let Some(after) = tail.strip_prefix("<event") {
            if after.starts_with('>') || after.starts_with(char::is_whitespace) {
                return Some(i);
            }
            // e.g. "<events>" - not an event tag.
        }
        i += 1;
    }
    None
}

/// Parse the inner content of the `<custody>` element into event blocks
/// and preserved other regions. Any `<event` opening without a closing
/// `>` or without a matching `</event>` is a hard error (the chain must
/// never be silently restarted over a damaged document).
fn parse_custody_inner(inner: &str) -> Result<Vec<CustodySeg>, RcmError> {
    let mut out = Vec::new();
    let mut rest = inner;
    while let Some(i) = find_event_open(rest) {
        let head = &rest[..i];
        if !head.trim().is_empty() {
            out.push(CustodySeg::Other(head.to_string()));
        }
        let tail = &rest[i..];
        let tag_end = tail.find('>').ok_or_else(|| {
            RcmError("custody.RCM.xml: unterminated <event tag".into())
        })?;
        let close = tail.find("</event>").ok_or_else(|| {
            RcmError("custody.RCM.xml: <event> without matching </event>".into())
        })?;
        if close < tag_end {
            return Err(RcmError(
                "custody.RCM.xml: malformed <event> structure".into(),
            ));
        }
        out.push(CustodySeg::Event(
            tail[..close + "</event>".len()].to_string(),
        ));
        rest = &tail[close + "</event>".len()..];
    }
    if !rest.trim().is_empty() {
        out.push(CustodySeg::Other(rest.to_string()));
    }
    Ok(out)
}

/// Extract the VERBATIM opening tag and the inner content of the
/// `<custody>` element. An empty/missing document yields None (fresh
/// chain); a NON-empty document without a well-formed `<custody
/// ...>...</custody>` element is REFUSED rather than silently overwritten.
/// The opening-tag scan is quote-aware: a `>` inside a quoted attribute
/// value does not end the tag.
fn custody_inner(existing: &str) -> Result<Option<(String, String)>, RcmError> {
    if existing.trim().is_empty() {
        return Ok(None);
    }
    let open = existing.find("<custody").ok_or_else(|| {
        RcmError(
            "custody.RCM.xml exists but has no <custody> element; refusing to restart the chain"
                .into(),
        )
    })?;
    let tail = &existing[open..];
    let tag_end = xml::find_tag_end(tail).ok_or_else(|| {
        RcmError("custody.RCM.xml: unterminated <custody> tag".into())
    })?;
    let open_tag = tail[..=tag_end].to_string();
    let close = tail[tag_end..]
        .find("</custody>")
        .map(|c| c + tag_end)
        .ok_or_else(|| {
            RcmError("custody.RCM.xml: <custody> without </custody>; refusing to restart the chain".into())
        })?;
    Ok(Some((open_tag, tail[tag_end + 1..close].to_string())))
}

/// Extract every raw `<event...>...</event>` block, preserving the exact
/// serialization (the chainhash covers the block AS WRITTEN).
#[cfg(test)]
fn parse_event_blocks(doc: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = doc;
    while let Some(i) = find_event_open(rest) {
        let tail = &rest[i..];
        let end = match tail.find("</event>") {
            Some(e) => e,
            None => break,
        };
        out.push(tail[..end + "</event>".len()].to_string());
        rest = &tail[end + "</event>".len()..];
    }
    out
}

/// Chainhash input normalization (Table 11): PER-LINE surrounding-whitespace
/// stripping - trim leading/trailing whitespace of each line, join with no
/// separator, preserving intra-text whitespace. This is what makes the
/// computed chainhashes in the spec examples reproducible; stripping ALL
/// whitespace (including intra-text spaces) would produce chains
/// incompatible with other conformant tools.
fn strip_whitespace(s: &str) -> String {
    s.lines().map(|line| line.trim()).collect()
}

fn render_event(
    actor: &str,
    action: &str,
    time: &str,
    authorization: Option<&str>,
    details: Option<&str>,
    chainhash: Option<&str>,
) -> String {
    let mut s = String::from("    <event>\n");
    s.push_str(&format!("      <actor>{}</actor>\n", xml::xml_escape(actor)));
    s.push_str(&format!("      <action>{}</action>\n", xml::xml_escape(action)));
    s.push_str(&format!("      <time>{}</time>\n", xml::xml_escape(time)));
    s.push_str(&format!(
        "      <authorization>{}</authorization>\n",
        xml::xml_escape(authorization.unwrap_or("NONE"))
    ));
    if let Some(d) = details {
        s.push_str(&format!("      <details>{}</details>\n", xml::xml_escape(d)));
    }
    if let Some(h) = chainhash {
        s.push_str(&format!("      <chainhash>{}</chainhash>\n", h));
    }
    s.push_str("    </event>\n");
    s
}

/// Append a custody event. First event carries no chainhash; subsequent
/// chainhashes follow REQ-17.3 Table 11. Atomic rewrite of the whole
/// custody.RCM.xml with the new event appended.
pub fn append_event(
    root: &Path,
    actor: &str,
    action: CustodyAction,
    authorization: Option<&str>,
    details: Option<&str>,
) -> Result<(), RcmError> {
    let path = root.join("custody.RCM.xml");
    let existing = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.into()),
    };
    // Parse the existing document. A fundamentally unparseable document is
    // REFUSED (error) - never silently restart the chain over it. The
    // original `<custody ...>` opening tag is preserved verbatim (foreign
    // attributes survive); only fresh chains use the canonical tag.
    let (open_tag, segs) = match custody_inner(&existing)? {
        Some((tag, inner)) => (tag, parse_custody_inner(&inner)?),
        None => ("<custody version=\"1\">".to_string(), Vec::new()),
    };
    let prior: Vec<&String> = segs
        .iter()
        .filter_map(|s| match s {
            CustodySeg::Event(b) => Some(b),
            _ => None,
        })
        .collect();

    let time = xml::now_ts();
    let chainhash = prior.last().map(|prev| {
        sha256_hex(
            format!(
                "{}{}{}{}",
                strip_whitespace(prev),
                actor,
                action.as_str(),
                time
            )
            .as_bytes(),
        )
    });

    let mut data = String::from("  ");
    data.push_str(&open_tag);
    data.push('\n');
    for seg in &segs {
        match seg {
            CustodySeg::Event(block) => {
                // Prior blocks keep their inner text verbatim; normalize
                // only the outer indentation for a stable document shape.
                data.push_str("    ");
                data.push_str(block);
                data.push('\n');
            }
            CustodySeg::Other(text) => {
                // Regions that don't parse as events are preserved
                // verbatim (living document), never dropped.
                let t = text.trim();
                data.push_str("    ");
                data.push_str(t);
                data.push('\n');
            }
        }
    }
    data.push_str(&render_event(
        actor,
        action.as_str(),
        &time,
        authorization,
        details,
        chainhash.as_deref(),
    ));
    data.push_str("  </custody>\n");

    xml::atomic_write(&path, xml::xml_doc(&data, &time).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_only_with_chainhash() {
        let dir = tempfile::tempdir().unwrap();
        append_event(
            dir.path(),
            "collector-svc/2.1",
            CustodyAction::Collect,
            Some("AUTH-2026-0117"),
            Some("Initial collection of USER-PC"),
        )
        .unwrap();
        let doc1 = std::fs::read_to_string(dir.path().join("custody.RCM.xml")).unwrap();
        assert!(doc1.contains("<custody version=\"1\">"));
        assert_eq!(doc1.matches("<event>").count(), 1);
        assert!(!doc1.contains("<chainhash>"), "first event has no chainhash");
        assert!(doc1.contains("<authorization>AUTH-2026-0117</authorization>"));

        append_event(
            dir.path(),
            "collector-svc/2.1",
            CustodyAction::Package,
            Some("AUTH-2026-0117"),
            Some("Package sealed, manifest generation 0"),
        )
        .unwrap();
        let doc2 = std::fs::read_to_string(dir.path().join("custody.RCM.xml")).unwrap();
        assert_eq!(doc2.matches("<event>").count(), 2);
        assert_eq!(doc2.matches("<chainhash>").count(), 1);
        // First event preserved verbatim (append-only).
        assert!(doc2.contains("<details>Initial collection of USER-PC</details>"));

        // Chainhash independently reproducible: sha256 of the stripped first
        // <event> block + actor + action + time of the second event.
        let blocks = parse_event_blocks(&doc2);
        let t2_start = doc2.rfind("<time>").unwrap();
        let t2_end = doc2[t2_start..].find("</time>").unwrap() + t2_start;
        let t2 = &doc2[t2_start + 6..t2_end];
        let expect = sha256_hex(
            format!(
                "{}{}{}{}",
                strip_whitespace(&blocks[0]),
                "collector-svc/2.1",
                "PACKAGE",
                t2
            )
            .as_bytes(),
        );
        let ch_start = doc2.find("<chainhash>").unwrap() + "<chainhash>".len();
        let ch_end = doc2.find("</chainhash>").unwrap();
        assert_eq!(&doc2[ch_start..ch_end], &expect);
    }

    /// Known-answer vectors from the spec's computed custody example.
    /// Both verify ONLY with per-line surrounding-whitespace stripping
    /// (intra-text whitespace preserved).
    #[test]
    fn chainhash_known_answer_vectors() {
        // Vector 1: COLLECT event -> sha256(stripped + actor + action + time)
        // of the following PACKAGE event.
        let prev_collect = "<event>\n      <actor>collector-svc/2.1</actor>\n      <action>COLLECT</action>\n      <time>2026-01-06T08:11:00.123201Z</time>\n      <authorization>AUTH-2026-0117</authorization>\n      <details>Initial collection of USER-PC</details>\n    </event>";
        let h1 = sha256_hex(
            format!(
                "{}{}{}{}",
                strip_whitespace(prev_collect),
                "collector-svc/2.1",
                "PACKAGE",
                "2026-01-06T08:14:22.000000Z"
            )
            .as_bytes(),
        );
        assert_eq!(
            h1,
            "db04fed08b2fad6f7a112273f74e67fe9415f111cece5f0335c04b0f68276f61"
        );

        // Vector 2: the PACKAGE event (incl. the vector-1 chainhash) ->
        // chainhash of the following ACCESS event.
        let prev_package = "<event>\n      <actor>collector-svc/2.1</actor>\n      <action>PACKAGE</action>\n      <time>2026-01-06T08:14:22.000000Z</time>\n      <authorization>AUTH-2026-0117</authorization>\n      <details>Package sealed, manifest generation 0</details>\n      <chainhash>db04fed08b2fad6f7a112273f74e67fe9415f111cece5f0335c04b0f68276f61</chainhash>\n    </event>";
        let h2 = sha256_hex(
            format!(
                "{}{}{}{}",
                strip_whitespace(prev_package),
                "analyst-j.doe",
                "ACCESS",
                "2026-01-09T13:02:10.000000Z"
            )
            .as_bytes(),
        );
        assert_eq!(
            h2,
            "06dc8883026f796ddeb894691efcd094503b1243f134d99d50c78c5d0752b8cb"
        );
    }

    #[test]
    fn authorization_none_and_details_omitted() {
        let dir = tempfile::tempdir().unwrap();
        append_event(dir.path(), "analyst-j.doe", CustodyAction::Access, None, None).unwrap();
        let doc = std::fs::read_to_string(dir.path().join("custody.RCM.xml")).unwrap();
        assert!(doc.contains("<authorization>NONE</authorization>"));
        assert!(!doc.contains("<details>"));
    }

    #[test]
    fn attribute_bearing_event_and_comments_preserved() {
        // An <event ...> carrying attributes (e.g. written by a foreign
        // conformant tool) and a comment between events must survive the
        // append verbatim, and the chain must continue over them.
        let dir = tempfile::tempdir().unwrap();
        let foreign = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<RCM version=\"1\" specversion=\"2.1\">\n  <custody version=\"1\">\n    <!-- imported from tool X -->\n    <event tool=\"x\">\n      <actor>a</actor>\n      <action>COLLECT</action>\n      <time>2026-01-06T08:11:00.1232010Z</time>\n      <authorization>NONE</authorization>\n    </event>\n  </custody>\n  <timestamp>2026-01-06T08:11:00.1232010Z</timestamp>\n</RCM>\n";
        std::fs::write(dir.path().join("custody.RCM.xml"), foreign).unwrap();
        append_event(dir.path(), "analyst-j.doe", CustodyAction::Access, None, None).unwrap();
        let doc = std::fs::read_to_string(dir.path().join("custody.RCM.xml")).unwrap();
        assert!(doc.contains("<!-- imported from tool X -->"), "comment lost");
        assert!(doc.contains("<event tool=\"x\">"), "attribute-bearing event lost");
        assert_eq!(doc.matches("</event>").count(), 2);
        // The new event chains over the attribute-bearing prior event.
        assert_eq!(doc.matches("<chainhash>").count(), 1);
    }

    // An `<event` inside a comment/PI/CDATA region is markup
    // content, never an event open. Case (a): no later `</event>` -
    // appends must keep working (previously they hard-errored forever).
    #[test]
    fn event_like_text_in_comment_is_not_an_event() {
        let dir = tempfile::tempdir().unwrap();
        let doc = "<RCM>\n  <custody version=\"1\">\n    <!-- <event> forged, never closed -->\n    <?pi <event> also forged?>\n    <![CDATA[<event> cdata forged]]>\n  </custody>\n</RCM>\n";
        std::fs::write(dir.path().join("custody.RCM.xml"), doc).unwrap();
        append_event(dir.path(), "analyst-j.doe", CustodyAction::Access, None, None).unwrap();
        let out = std::fs::read_to_string(dir.path().join("custody.RCM.xml")).unwrap();
        // The comment/PI/CDATA regions are preserved verbatim and exactly
        // ONE real event exists (the one we just appended; no chainhash,
        // since it is the first real event).
        assert!(out.contains("<!-- <event> forged, never closed -->"));
        assert!(out.contains("<?pi <event> also forged?>"));
        assert!(out.contains("<![CDATA[<event> cdata forged]]>"));
        assert_eq!(out.matches("</event>").count(), 1);
        assert!(!out.contains("<chainhash>"));
        // And the chain keeps appending afterwards.
        append_event(dir.path(), "analyst-j.doe", CustodyAction::Access, None, None).unwrap();
        let out2 = std::fs::read_to_string(dir.path().join("custody.RCM.xml")).unwrap();
        assert_eq!(out2.matches("</event>").count(), 2);
        assert_eq!(out2.matches("<chainhash>").count(), 1);
    }

    // A comment containing a FULL `<event>...</event>`
    // pair must not be hashed into the chain - the chain covers only real
    // events.
    #[test]
    fn commented_event_block_not_hashed_into_chain() {
        let dir = tempfile::tempdir().unwrap();
        let real = "<event>\n      <actor>a</actor>\n      <action>COLLECT</action>\n      <time>2026-01-06T08:11:00.1232010Z</time>\n      <authorization>NONE</authorization>\n    </event>";
        let doc = format!(
            "<RCM>\n  <custody version=\"1\">\n    <!-- <event><actor>forged</actor></event> -->\n    {}\n  </custody>\n</RCM>\n",
            real
        );
        std::fs::write(dir.path().join("custody.RCM.xml"), doc).unwrap();
        append_event(dir.path(), "analyst-j.doe", CustodyAction::Access, None, None).unwrap();
        let out = std::fs::read_to_string(dir.path().join("custody.RCM.xml")).unwrap();
        assert!(out.contains("<!-- <event><actor>forged</actor></event> -->"));
        // Two real events, one chainhash - computed over the REAL prior
        // event (parse_event_blocks uses the same skip-aware scanner).
        let blocks = parse_event_blocks(&out);
        assert_eq!(blocks.len(), 2, "comment block counted as event");
        let t2_start = out.rfind("<time>").unwrap();
        let t2_end = out[t2_start..].find("</time>").unwrap() + t2_start;
        let t2 = &out[t2_start + 6..t2_end];
        let expect = sha256_hex(
            format!(
                "{}{}{}{}",
                strip_whitespace(&blocks[0]),
                "analyst-j.doe",
                "ACCESS",
                t2
            )
            .as_bytes(),
        );
        let ch_start = out.find("<chainhash>").unwrap() + "<chainhash>".len();
        let ch_end = out.find("</chainhash>").unwrap();
        assert_eq!(&out[ch_start..ch_end], &expect, "chain hashed a misidentified block");
    }

    // The <custody> opening-tag scan is quote-aware and the
    // original tag (foreign attributes, `>` inside a quoted value) is
    // preserved verbatim - not re-rendered as the canonical constant.
    #[test]
    fn custody_open_tag_quote_aware_and_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let doc = "<RCM>\n  <custody version=\"1\" note=\"x>y\">\n  </custody>\n</RCM>\n";
        std::fs::write(dir.path().join("custody.RCM.xml"), doc).unwrap();
        append_event(dir.path(), "analyst-j.doe", CustodyAction::Access, None, None).unwrap();
        let out = std::fs::read_to_string(dir.path().join("custody.RCM.xml")).unwrap();
        assert!(
            out.contains("<custody version=\"1\" note=\"x>y\">"),
            "original open tag lost or mis-scanned: {}",
            out
        );
        assert_eq!(out.matches("</event>").count(), 1);
    }

    #[test]
    fn unparseable_document_refused_untouched() {
        let dir = tempfile::tempdir().unwrap();
        // Garbage that is not a custody document at all.
        let bad = "this is not xml at all";
        std::fs::write(dir.path().join("custody.RCM.xml"), bad).unwrap();
        let r = append_event(dir.path(), "a", CustodyAction::Access, None, None);
        assert!(r.is_err(), "garbage document silently restarted");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("custody.RCM.xml")).unwrap(),
            bad,
            "refused document was modified"
        );

        // An <event> without </event>: fundamentally unparseable.
        let dir2 = tempfile::tempdir().unwrap();
        let bad2 = "<RCM>\n  <custody version=\"1\">\n    <event>\n      <actor>a</actor>\n  </custody>\n</RCM>\n";
        std::fs::write(dir2.path().join("custody.RCM.xml"), bad2).unwrap();
        let r2 = append_event(dir2.path(), "a", CustodyAction::Access, None, None);
        assert!(r2.is_err(), "unterminated event silently restarted");
        assert_eq!(
            std::fs::read_to_string(dir2.path().join("custody.RCM.xml")).unwrap(),
            bad2
        );
    }
}
