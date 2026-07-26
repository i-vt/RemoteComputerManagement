// ./src/rcm/sidecar.rs
// Collection metadata sidecars (Section 8.2, Table 2). One sidecar per
// collected file, named per REQ-3.3.4 (full filename + ".RCM.xml"), written
// atomically (Section 6.3).

use std::path::{Path, PathBuf};

use super::package::RcmError;
use super::paths;
use super::xml;

/// Optional agent-supplied metadata for one collected file. `None` fields
/// render as the literal `NONE` (REQ-4.3.1), except `group`, which is
/// omitted entirely when absent (REQ-4.3.2 / Table 2 "Conditional").
pub struct FileMeta {
    pub name: String,                   // original filename (verbatim case)
    pub dirname: String,                // original dir path (verbatim)
    pub size: u64,
    pub md5: String,                    // lowercase hex
    pub sha256: String,                 // lowercase hex
    pub modified: Option<String>,       // canonical ts; None -> literal NONE
    pub accessed: Option<String>,
    pub created: Option<String>,
    pub owner: Option<String>,          // None -> NONE
    pub group: Option<String>,          // None -> element OMITTED
}

fn or_none(v: &Option<String>) -> String {
    v.clone().unwrap_or_else(|| "NONE".to_string())
}

/// Full RCM XML document with a `<file version="1">` data element, keys in
/// Table 2 order: name, dirname, size, md5, hash(type="sha256"),
/// modifiedtime, accessedtime, createdtime, owner, group (optional).
pub fn render_file_meta(m: &FileMeta, action_ts: &str) -> String {
    let mut el = String::from("  <file version=\"1\">\n");
    macro_rules! kv {
        ($k:expr, $v:expr) => {
            el.push_str(&format!(
                "    <{}>{}</{}>\n",
                $k,
                xml::xml_escape(&$v),
                $k
            ))
        };
    }
    kv!("name", m.name);
    kv!("dirname", m.dirname);
    kv!("size", m.size.to_string());
    kv!("md5", m.md5);
    el.push_str(&format!(
        "    <hash type=\"sha256\">{}</hash>\n",
        xml::xml_escape(&m.sha256)
    ));
    kv!("modifiedtime", or_none(&m.modified));
    kv!("accessedtime", or_none(&m.accessed));
    kv!("createdtime", or_none(&m.created));
    kv!("owner", or_none(&m.owner));
    if let Some(g) = &m.group {
        kv!("group", g.clone());
    }
    el.push_str("  </file>\n");
    xml::xml_doc(&el, action_ts)
}

/// Write `<root>/downloads.metadata/<stored_rel>.RCM.xml` atomically
/// (REQ-3.3.4 / REQ-8.1.2). `stored_rel` is the file's path relative to the
/// package's `downloads/` folder, using '/' separators and already carrying
/// any REQ-3.4.3 counter suffix.
pub fn write_sidecar(
    root: &Path,
    stored_rel: &str,
    m: &FileMeta,
    action_ts: &str,
) -> Result<PathBuf, RcmError> {
    let meta_root = paths::ensure_dir(root, &["downloads.metadata"])?;
    let comps: Vec<&str> = stored_rel.split('/').filter(|c| !c.is_empty()).collect();
    if comps.is_empty() {
        return Err(RcmError("empty sidecar relative path".into()));
    }
    let dir = paths::ensure_dir(&meta_root, &comps[..comps.len() - 1])?;
    let sidecar = dir.join(format!("{}.RCM.xml", comps[comps.len() - 1]));
    xml::atomic_write(&sidecar, render_file_meta(m, action_ts).as_bytes())?;
    Ok(sidecar)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_meta() -> FileMeta {
        FileMeta {
            name: "goodplans.txt".into(),
            dirname: "C:\\Windows".into(),
            size: 1024,
            md5: "2cad20c19a8eb9bb11a9f76527aec9bc".into(),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .into(),
            modified: Some("2019-10-16T12:11:21.1230000Z".into()),
            accessed: None,
            created: None,
            owner: Some("Dr. good".into()),
            group: None,
        }
    }

    #[test]
    fn table2_key_order_and_none_handling() {
        let doc = render_file_meta(&sample_meta(), "2026-01-06T08:11:00.1232010Z");
        // Envelope + data element.
        assert!(doc.contains("<RCM version=\"1\" specversion=\"2.1\">"));
        assert!(doc.contains("<file version=\"1\">"));
        // Keys in exact Table 2 order.
        let keys = [
            "<name>", "<dirname>", "<size>", "<md5>", "<hash type=\"sha256\">",
            "<modifiedtime>", "<accessedtime>", "<createdtime>", "<owner>",
        ];
        let mut last = 0usize;
        for k in keys {
            let pos = doc.find(k).unwrap_or_else(|| panic!("missing {}", k));
            assert!(pos > last, "{} out of order", k);
            last = pos;
        }
        // Absent times -> literal NONE; group omitted entirely (REQ-4.3.2).
        assert!(doc.contains("<accessedtime>NONE</accessedtime>"));
        assert!(doc.contains("<createdtime>NONE</createdtime>"));
        assert!(!doc.contains("<group>"));
        // dirname backslash preserved verbatim in escaped form.
        assert!(doc.contains("<dirname>C:\\Windows</dirname>"));
    }

    #[test]
    fn group_emitted_when_present() {
        let mut m = sample_meta();
        m.group = Some("staff".into());
        let doc = render_file_meta(&m, "2026-01-06T08:11:00.1232010Z");
        assert!(doc.contains("<group>staff</group>"));
        assert!(doc.find("<owner>").unwrap() < doc.find("<group>").unwrap());
    }

    #[test]
    fn sidecar_written_under_downloads_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_sidecar(
            dir.path(),
            "C/WINDOWS/plAns.txt",
            &sample_meta(),
            "2026-01-06T08:11:00.1232010Z",
        )
        .unwrap();
        assert_eq!(
            p,
            dir.path()
                .join("downloads.metadata/C/WINDOWS/plAns.txt.RCM.xml")
        );
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(body.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    }
}