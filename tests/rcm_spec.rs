// ./tests/rcm_spec.rs
// End-to-end conformance test for the src/rcm module against
// RCM-SPEC-001 v2.1 (Level 2 + Screenshot + Keylogger). Hermetic: every
// package is built inside a tempfile::tempdir(); no real downloads/ tree
// is ever touched.

use chrono::Utc;
use rcm::rcm::package::{CollectedMeta, KeyCapture, KeyEvent, PackageManager, ScreenshotMeta};
use rcm::rcm::custody::CustodyAction;

/// Minimal well-formedness check (no XML crate): UTF-8 declaration, single
/// <RCM> root, exactly one <timestamp> as the last direct child, and
/// balanced open/close tags for every tag name that appears.
fn assert_well_formed_rcm(doc: &str) {
    assert!(
        doc.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<RCM version=\"1\" specversion=\"2.1\">\n"),
        "bad envelope head: {:?}",
        &doc[..doc.len().min(120)]
    );
    assert!(doc.ends_with("</RCM>\n"), "bad envelope tail");
    assert_eq!(doc.matches("<RCM ").count(), 1, "single root");
    assert_eq!(doc.matches("</RCM>").count(), 1, "single root close");
    assert_eq!(doc.matches("<timestamp>").count(), 1, "exactly one timestamp");
    assert_eq!(doc.matches("</timestamp>").count(), 1);
    // <timestamp> is the LAST direct child of <RCM>.
    let tail = doc.rfind("</timestamp>").unwrap();
    assert!(doc[tail..].starts_with("</timestamp>\n</RCM>\n"));

    // Balanced tags for every simple tag name we emit.
    for tag in [
        "file", "name", "dirname", "size", "md5", "hash", "modifiedtime",
        "accessedtime", "createdtime", "owner", "group", "manifest", "entry",
        "path", "sha256", "custody", "event", "actor", "action", "time",
        "authorization", "details", "chainhash", "screenshot", "originalsize",
        "isfullscreen", "isminimized", "activewindow", "pid", "imagename",
        "windowtitle", "session", "user", "monitor", "keylog", "capture",
        "starttime", "endtime", "keys", "fingerprint", "uid", "hostname",
        "usertag",
    ] {
        let opens = doc.matches(&format!("<{}>", tag)).count()
            + doc.matches(&format!("<{} ", tag)).count();
        let closes = doc.matches(&format!("</{}>", tag)).count();
        assert_eq!(opens, closes, "unbalanced <{}> in:\n{}", tag, doc);
    }
}

fn canonical_re() -> regex::Regex {
    regex::Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z$").unwrap()
}

#[test]
fn end_to_end_rcm_spec_v2_1() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path();

    // ── Create package (REQ-3.1/3.2) ────────────────────────────────────
    let pm = PackageManager::create_or_open(base, "USER-PC", "computer-1").unwrap();
    assert_eq!(pm.root_name(), "USER-PC");
    let root = pm.root().to_path_buf();
    for sub in [
        "downloads",
        "downloads.metadata",
        "logs",
        "output/screenshots",
        "output/keylogger",
    ] {
        assert!(root.join(sub).is_dir(), "missing subfolder {}", sub);
    }
    assert_eq!(
        std::fs::read_to_string(root.join(".rcmtarget")).unwrap(),
        "computer-1\n"
    );

    // ── store_collected: path reconstruction + sidecar (Sec 8) ──────────
    let meta = CollectedMeta {
        modified: Some("2019-10-16T12:11:21.1230000Z".into()),
        accessed: None,
        created: None,
        owner: Some("Dr. good".into()),
        group: None,
    };
    let rel = pm
        .store_collected("C:\\WINDOWS\\plAns.txt", b"plans-1", &meta)
        .unwrap();
    assert_eq!(rel, "downloads/C/WINDOWS/plAns.txt");
    assert_eq!(std::fs::read(root.join(&rel)).unwrap(), b"plans-1");

    let sidecar = std::fs::read_to_string(
        root.join("downloads.metadata/C/WINDOWS/plAns.txt.RCM.xml"),
    )
    .unwrap();
    assert_well_formed_rcm(&sidecar);
    // Table 2 key order.
    let keys = [
        "<name>", "<dirname>", "<size>", "<md5>", "<hash type=\"sha256\">",
        "<modifiedtime>", "<accessedtime>", "<createdtime>", "<owner>",
    ];
    let mut last = 0;
    for k in keys {
        let pos = sidecar.find(k).unwrap_or_else(|| panic!("missing {}", k));
        assert!(pos > last, "{} out of order", k);
        last = pos;
    }
    assert!(sidecar.contains("<name>plAns.txt</name>")); // verbatim case
    assert!(sidecar.contains("<dirname>C:\\WINDOWS</dirname>"));
    assert!(sidecar.contains("<modifiedtime>2019-10-16T12:11:21.1230000Z</modifiedtime>"));
    assert!(sidecar.contains("<accessedtime>NONE</accessedtime>")); // NONE for absent
    assert!(sidecar.contains("<createdtime>NONE</createdtime>"));
    assert!(!sidecar.contains("<group>")); // not applicable -> omitted

    // ── Chunk flow: .part + .part.state, strict order, finalize (6.3.5) ─
    let dmeta = CollectedMeta::default();
    assert!(!pm
        .store_collected_chunk("/etc/passwd", 0, 2, b"root:x:0", "t-pw", &dmeta)
        .unwrap());
    assert!(root.join("downloads/etc/passwd.part").exists());
    assert!(root.join("downloads/etc/passwd.part.state").exists());
    // Out-of-order delivery rejected, partial file retained.
    assert!(pm
        .store_collected_chunk("/etc/passwd", 3, 2, b"!!!", "t-pw", &dmeta)
        .is_err());
    assert!(root.join("downloads/etc/passwd.part").exists());
    assert!(pm
        .store_collected_chunk("/etc/passwd", 1, 2, b":0:", "t-pw", &dmeta)
        .unwrap());
    assert!(!root.join("downloads/etc/passwd.part").exists());
    assert!(!root.join("downloads/etc/passwd.part.state").exists());
    assert_eq!(
        std::fs::read(root.join("downloads/etc/passwd")).unwrap(),
        b"root:x:0:0:"
    );
    assert!(root.join("downloads.metadata/etc/passwd.RCM.xml").exists());

    // ── Seal: manifest generation 0 + exclusions + verify (17.2) ────────
    assert!(!pm.is_sealed());
    let m0 = pm.seal().unwrap();
    assert_eq!(m0.file_name().unwrap(), "manifest.RCM.xml");
    assert!(pm.is_sealed());
    let manifest0 = std::fs::read_to_string(&m0).unwrap();
    assert_well_formed_rcm(&manifest0);
    assert!(manifest0.contains("<path>downloads/C/WINDOWS/plAns.txt</path>"));
    assert!(manifest0.contains("<path>downloads/etc/passwd</path>"));
    assert!(manifest0.contains("<path>fingerprint.RCM.xml</path>"));
    for excluded in [
        "manifest.RCM.xml</path>",
        "custody.RCM.xml",
        ".tmp</path>",
        ".part</path>",
        ".part.state</path>",
        ".sig</path>",
    ] {
        assert!(!manifest0.contains(excluded), "excluded: {}", excluded);
    }
    // Entries sorted by path.
    let i_dl = manifest0.find("<path>downloads/C/WINDOWS/plAns.txt</path>").unwrap();
    let i_etc = manifest0.find("<path>downloads/etc/passwd</path>").unwrap();
    let i_fp = manifest0.find("<path>fingerprint.RCM.xml</path>").unwrap();
    assert!(i_dl < i_etc && i_etc < i_fp);
    assert_eq!(pm.verify().unwrap(), Vec::<String>::new());

    // ── Store after seal + reseal -> manifest.RCM.1.xml (REQ-17.2.6) ────
    pm.store_collected("C:\\WINDOWS\\plAns2.txt", b"plans-2", &dmeta)
        .unwrap();
    let m1 = pm.seal().unwrap();
    assert_eq!(m1.file_name().unwrap(), "manifest.RCM.1.xml");
    assert!(m0.exists(), "prior manifest generation preserved");
    let manifest1 = std::fs::read_to_string(&m1).unwrap();
    assert_well_formed_rcm(&manifest1);
    assert!(manifest1.contains("<path>downloads/C/WINDOWS/plAns2.txt</path>"));
    assert_eq!(pm.verify().unwrap(), Vec::<String>::new());

    // ── Custody: two events, second carries a chainhash (17.3) ──────────
    pm.custody(
        "collector-svc/2.1",
        CustodyAction::Collect,
        Some("AUTH-2026-0117"),
        Some("Initial collection of USER-PC"),
    )
    .unwrap();
    pm.custody("collector-svc/2.1", CustodyAction::Package, Some("AUTH-2026-0117"), None)
        .unwrap();
    let custody = std::fs::read_to_string(root.join("custody.RCM.xml")).unwrap();
    assert_well_formed_rcm(&custody);
    // seal() already added PACKAGE events above; exactly the two COLLECT-
    // actor events we appended plus the seal-time PACKAGE events exist, and
    // every event after the first has a chainhash.
    let n_events = custody.matches("<event>").count();
    let n_chains = custody.matches("<chainhash>").count();
    assert!(n_events >= 2);
    assert_eq!(n_chains, n_events - 1, "first event has no chainhash");
    assert!(custody.contains("<authorization>AUTH-2026-0117</authorization>"));

    // ── Keylog naming (Sec 12) ──────────────────────────────────────────
    let caps = vec![KeyCapture {
        starttime: "2026-01-24T09:15:00.0000000Z".into(),
        endtime: Some("2026-01-24T09:16:12.0000000Z".into()),
        user: Some("USER-PC\\Administrator".into()),
        events: vec![
            KeyEvent {
                time: "2026-01-24T09:15:02.0000000Z".into(),
                pid: Some("1364".into()),
                imagename: Some("notepad.exe".into()),
                windowtitle: Some("Untitled - Notepad".into()),
                keys: "Hello world[ENTER]".into(),
            },
            KeyEvent {
                time: "2026-01-24T09:15:40.0000000Z".into(),
                pid: None,
                imagename: None,
                windowtitle: None,
                keys: "weather tomorrow[ENTER]".into(),
            },
        ],
    }];
    let krel = pm.store_keylog(&caps).unwrap();
    assert_eq!(krel, "output/keylogger/keylog.RCM.0.xml");
    let kdoc = std::fs::read_to_string(root.join(&krel)).unwrap();
    assert_well_formed_rcm(&kdoc);
    assert!(kdoc.contains("<keylog version=\"1\">"));
    assert_eq!(kdoc.matches("<event>").count(), 2);
    assert!(kdoc.contains("<keys>Hello world[ENTER]</keys>"));
    assert!(kdoc.contains("<pid>NONE</pid>"));
    let krel2 = pm.store_keylog(&caps).unwrap();
    assert_eq!(krel2, "output/keylogger/keylog.RCM.1.xml");

    // ── Screenshot naming + sidecar (Sec 11) ────────────────────────────
    let shot = ScreenshotMeta {
        captured_at: chrono::DateTime::parse_from_rfc3339("2026-01-06T09:21:33Z")
            .unwrap()
            .with_timezone(&Utc),
        toolspecific: "monitor0".into(),
        ext: "jpg".into(),
        originalsize: Some("680x320".into()),
        isfullscreen: Some(false),
        isminimized: Some(false),
        activewindow: Some(true),
        pid: Some("1364".into()),
        imagename: Some("calc.exe".into()),
        windowtitle: Some("Calculator".into()),
        session: Some("1".into()),
        user: Some("USER-PC\\Administrator".into()),
        monitor: Some("1".into()),
    };
    let srel = pm.store_screenshot(b"\xff\xd8\xff", &shot).unwrap();
    assert_eq!(
        srel,
        "output/screenshots/screenshot.20260106-092133.monitor0.jpg"
    );
    let sdoc = std::fs::read_to_string(root.join(format!("{}.RCM.xml", srel))).unwrap();
    assert_well_formed_rcm(&sdoc);
    assert!(sdoc.contains("<screenshot version=\"1\">"));
    assert!(sdoc.contains("<originalsize>680x320</originalsize>"));
    assert!(sdoc.contains("<activewindow>True</activewindow>"));
    assert!(sdoc.contains("<isfullscreen>False</isfullscreen>"));
    // Screenshot sidecar timestamp = capture time (REQ-4.2.5).
    assert!(sdoc.contains("<timestamp>2026-01-06T09:21:33.0000000Z</timestamp>"));

    // ── Canonical timestamps everywhere we emitted one ──────────────────
    let re = canonical_re();
    for doc in [&sidecar, &manifest0, &manifest1, &custody, &kdoc, &sdoc] {
        let ts_start = doc.find("<timestamp>").unwrap() + "<timestamp>".len();
        let ts_end = doc.find("</timestamp>").unwrap();
        let ts = &doc[ts_start..ts_end];
        assert!(re.is_match(ts), "non-canonical timestamp {:?}", ts);
    }
}
