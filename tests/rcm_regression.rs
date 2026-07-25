// tests/rcm_regression.rs
//
// Regression tests
// creation race, chunk-0 evidence
// preservation, XML control chars / timestamp injection, manifest
// exclusions / generation gap, sidecar-failure orphans, meta-cache cap,
// filename-less path rejection. All hermetic via tempfile.

use std::path::Path;
use std::sync::Arc;

use rcm::rcm::custody::CustodyAction;
use rcm::rcm::{CollectedMeta, KeyCapture, KeyEvent, PackageManager, ScreenshotMeta};

fn pm(dir: &tempfile::TempDir) -> Arc<PackageManager> {
    PackageManager::create_or_open(dir.path(), "ADV-PC", "adv-1").unwrap()
}

fn meta() -> CollectedMeta {
    CollectedMeta::default()
}

// ── helpers ────────────────────────────────────────────────────────────────

/// Minimal XML 1.0 well-formedness checker sufficient for these docs:
/// rejects raw control chars (except tab/lf/cr), raw ']]>' in content,
/// unmatched tags, and unterminated comments/tags.
fn assert_well_formed(doc: &str, what: &str) {
    for (i, c) in doc.chars().enumerate() {
        if (c as u32) < 0x20 && c != '\t' && c != '\n' && c != '\r' {
            panic!(
                "{}: control char U+{:04X} at char {} — invalid in XML 1.0",
                what, c as u32, i
            );
        }
        assert!(
            (c as u32) != 0xFFFE && (c as u32) != 0xFFFF,
            "{}: U+{:04X} invalid in XML 1.0",
            what,
            c as u32
        );
    }
    let mut depth: Vec<String> = Vec::new();
    let mut rest = doc;
    if let Some(end) = rest.find("?>") {
        rest = &rest[end + 2..];
    }
    let mut text = String::new();
    while let Some(lt) = rest.find('<') {
        text.push_str(&rest[..lt]);
        assert!(!text.contains("]]>"), "{}: raw ']]>' in text content", what);
        text.clear();
        let tail = &rest[lt..];
        if tail.starts_with("<!--") {
            let end = tail.find("-->").expect("unterminated comment");
            rest = &tail[end + 3..];
            continue;
        }
        let gt = tail.find('>').expect("unterminated tag");
        let tag = &tail[1..gt];
        if let Some(name) = tag.strip_prefix('/') {
            let open = depth
                .pop()
                .unwrap_or_else(|| panic!("{}: close without open: {}", what, name));
            assert_eq!(open, name.trim(), "{}: mismatched tags", what);
        } else if tag.starts_with('?') || tag.starts_with('!') || tag.ends_with('/') {
            // pi / doctype-ish / self-closing
        } else {
            depth.push(tag.split_whitespace().next().unwrap().to_string());
        }
        rest = &tail[gt + 1..];
    }
    assert!(depth.is_empty(), "{}: unclosed tags: {:?}", what, depth);
}

fn walk(dir: &Path, rel: &str, out: &mut Vec<String>) {
    if !dir.exists() {
        return;
    }
    for e in std::fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        let name = e.file_name().to_string_lossy().into_owned();
        let child = format!("{}/{}", rel, name);
        let ft = e.file_type().unwrap();
        if ft.is_dir() {
            walk(&e.path(), &child, out);
        } else if ft.is_file() {
            out.push(child);
        }
    }
}

/// Every stored download has exactly one sidecar and vice versa.
fn assert_sidecar_pairing(root: &Path) {
    let mut files = Vec::new();
    walk(&root.join("downloads"), "downloads", &mut files);
    let mut metas = Vec::new();
    walk(&root.join("downloads.metadata"), "downloads.metadata", &mut metas);
    let sidecars: std::collections::HashSet<String> = metas
        .iter()
        .filter(|m| m.ends_with(".RCM.xml"))
        .map(|m| {
            m.trim_start_matches("downloads.metadata/")
                .trim_end_matches(".RCM.xml")
                .to_string()
        })
        .collect();
    let data: std::collections::HashSet<String> = files
        .iter()
        .map(|f| f.trim_start_matches("downloads/").to_string())
        .filter(|f| !f.ends_with(".part") && !f.ends_with(".part.state"))
        .collect();
    let missing_sidecar: Vec<_> = data.difference(&sidecars).collect();
    let orphan_sidecar: Vec<_> = sidecars.difference(&data).collect();
    assert!(
        missing_sidecar.is_empty(),
        "data files WITHOUT sidecars: {:?}",
        missing_sidecar
    );
    assert!(
        orphan_sidecar.is_empty(),
        "sidecars WITHOUT data files: {:?}",
        orphan_sidecar
    );
}

// ── Creation race ──────────────────────

#[test]
fn regression_8_threads_create_or_open_one_folder() {
    let dir = tempfile::tempdir().unwrap();
    let base = Arc::new(dir.path().to_path_buf());
    let mut handles = Vec::new();
    for _ in 0..8 {
        let b = base.clone();
        handles.push(std::thread::spawn(move || {
            PackageManager::create_or_open(&b, "RACE-HOST", "inst-race").unwrap()
        }));
    }
    let mut roots = Vec::new();
    for h in handles {
        roots.push(h.join().unwrap().root().to_path_buf());
    }
    let uniq: std::collections::HashSet<_> = roots.iter().collect();
    assert_eq!(uniq.len(), 1, "more than one root folder created: {:?}", uniq);
    let n = std::fs::read_dir(base.as_path()).unwrap().count();
    assert_eq!(n, 1, "expected exactly one package folder, found {}", n);
}

// ── Chunk-0 never touches committed evidence ────────────────────────

#[test]
fn regression_chunk0_preserves_committed_part_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let m = pm(&dir);
    // Collected file legitimately named "X.part" (sidecar exists ->
    // committed evidence). A chunk-0 for "X" must NOT delete/overwrite it:
    // the transfer claims the NEXT slot and finalizes normally.
    m.store_collected("C:\\data.part", b"EVIDENCE", &meta()).unwrap();
    assert!(!m
        .store_collected_chunk("C:\\data", 0, 2, b"chunk0", "t-ev", &meta())
        .unwrap());
    // Evidence file AND sidecar intact; transfer lives in slot 1.
    assert_eq!(
        std::fs::read(m.root().join("downloads/C/data.part")).unwrap(),
        b"EVIDENCE"
    );
    assert!(m
        .root()
        .join("downloads.metadata/C/data.part.RCM.xml")
        .exists());
    assert!(!m.root().join("downloads/C/data.part.state").exists());
    assert!(m.root().join("downloads/C/data.part.1").exists());
    assert!(m
        .store_collected_chunk("C:\\data", 1, 2, b"chunk1", "t-ev", &meta())
        .unwrap());
    // No orphans after finalization (the .part here IS the data file, so
    // the generic pairing helper's .part filter does not apply).
    assert!(!m.root().join("downloads/C/data.part.1").exists());
    assert!(!m.root().join("downloads/C/data.part.1.state").exists());
    let mut files = Vec::new();
    walk(&m.root().join("downloads"), "downloads", &mut files);
    files.sort();
    assert_eq!(
        files,
        vec![
            "downloads/C/data".to_string(),
            "downloads/C/data.part".to_string()
        ]
    );
    let mut metas = Vec::new();
    walk(&m.root().join("downloads.metadata"), "downloads.metadata", &mut metas);
    metas.sort();
    assert_eq!(
        metas,
        vec![
            "downloads.metadata/C/data.RCM.xml".to_string(),
            "downloads.metadata/C/data.part.RCM.xml".to_string()
        ]
    );
}

// ── XML control chars + timestamp injection ──

#[test]
fn regression_sidecar_entities_and_control_chars() {
    let dir = tempfile::tempdir().unwrap();
    let m = pm(&dir);
    let r = m
        .store_collected("C:\\d\\a&b'q\"x.t<xt", b"x", &meta())
        .unwrap();
    let sc = std::fs::read_to_string(m.root().join(format!(
        "downloads.metadata/{}.RCM.xml",
        r.trim_start_matches("downloads/")
    )))
    .unwrap();
    assert_well_formed(&sc, "sidecar with entities");

    let r2 = m
        .store_collected("C:\\d\\evil\x01\x07\x7f.txt", b"x", &meta())
        .unwrap();
    let sc2 = std::fs::read_to_string(m.root().join(format!(
        "downloads.metadata/{}.RCM.xml",
        r2.trim_start_matches("downloads/")
    )))
    .unwrap();
    assert_well_formed(&sc2, "sidecar with control chars");

    let m3 = CollectedMeta {
        owner: Some("ad\x01min".into()),
        ..Default::default()
    };
    let r3 = m.store_collected("C:\\d\\o.txt", b"x", &m3).unwrap();
    let sc3 = std::fs::read_to_string(m.root().join(format!(
        "downloads.metadata/{}.RCM.xml",
        r3.trim_start_matches("downloads/")
    )))
    .unwrap();
    assert_well_formed(&sc3, "sidecar with control-char owner");
}

#[test]
fn regression_keylog_keys_entities_and_control_chars() {
    let dir = tempfile::tempdir().unwrap();
    let m = pm(&dir);
    let caps = vec![KeyCapture {
        starttime: "2026-01-24T09:15:00.0000000Z".into(),
        endtime: Some("2026-01-24T09:16:12.0000000Z".into()),
        user: Some("a&b<c>".into()),
        events: vec![KeyEvent {
            time: "2026-01-24T09:15:02.0000000Z".into(),
            pid: Some("1".into()),
            imagename: Some("cmd.exe".into()),
            windowtitle: Some("t\"q'<>&".into()),
            keys: "password\x01\x07\x7f[ENTER]".into(),
        }],
    }];
    let rel = m.store_keylog(&caps).unwrap();
    let doc = std::fs::read_to_string(m.root().join(&rel)).unwrap();
    assert_well_formed(&doc, "keylog with control chars");
}

#[test]
fn regression_keylog_endtime_timestamp_injection() {
    let dir = tempfile::tempdir().unwrap();
    let m = pm(&dir);
    let caps = vec![KeyCapture {
        starttime: "2026-01-24T09:15:00.0000000Z".into(),
        endtime: Some(
            "2026-01-24T09:16:12.0000000Z</timestamp><injected attr=\"x\">pwn</injected><timestamp>"
                .into(),
        ),
        user: None,
        events: vec![],
    }];
    let rel = m.store_keylog(&caps).unwrap();
    let doc = std::fs::read_to_string(m.root().join(&rel)).unwrap();
    assert!(
        !doc.contains("<injected"),
        "XML INJECTION: agent-controlled endtime embedded verbatim"
    );
    assert_well_formed(&doc, "keylog with hostile endtime");
}

#[test]
fn regression_screenshot_meta_entities_and_control_chars() {
    let dir = tempfile::tempdir().unwrap();
    let m = pm(&dir);
    let shot = ScreenshotMeta {
        captured_at: chrono::DateTime::parse_from_rfc3339("2026-01-06T09:21:33Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        toolspecific: "mon\x01itor".into(),
        ext: "png".into(),
        originalsize: Some("1x1".into()),
        isfullscreen: None,
        isminimized: None,
        activewindow: None,
        pid: Some("4\x074".into()),
        imagename: Some("a&b.exe".into()),
        windowtitle: Some("w\x01t".into()),
        session: None,
        user: None,
        monitor: None,
    };
    let rel = m.store_screenshot(b"\x89PNG", &shot).unwrap();
    let doc =
        std::fs::read_to_string(m.root().join(format!("{}.RCM.xml", rel))).unwrap();
    assert_well_formed(&doc, "screenshot sidecar with control chars");
}

#[test]
fn regression_custody_details_entities_and_control_chars() {
    let dir = tempfile::tempdir().unwrap();
    let m = pm(&dir);
    m.custody(
        "analyst <script> & \"co\"",
        CustodyAction::Access,
        Some("AUTH'\"<>&"),
        Some("details with \x01 bell\x07 and ]]><event>spoof</event>"),
    )
    .unwrap();
    m.custody("second", CustodyAction::Access, None, None).unwrap();
    let doc = std::fs::read_to_string(m.root().join("custody.RCM.xml")).unwrap();
    assert_eq!(
        doc.matches("<event>").count(),
        2,
        "escaped details text was parsed as a real event block"
    );
    assert_well_formed(&doc, "custody with hostile details");
}

// ── Manifest excludes collected .tmp/.part ─

#[test]
fn regression_manifest_covers_collected_tmp_part_files() {
    let dir = tempfile::tempdir().unwrap();
    let m = pm(&dir);
    let r_tmp = m.store_collected("C:\\a\\notes.tmp", b"evidence", &meta()).unwrap();
    let r_part = m.store_collected("C:\\a\\dump.part", b"evidence", &meta()).unwrap();
    let r_sig = m.store_collected("C:\\a\\letter.sig", b"evidence", &meta()).unwrap();
    let r_ok = m.store_collected("C:\\a\\report.txt", b"evidence", &meta()).unwrap();
    m.seal().unwrap();
    let body = std::fs::read_to_string(m.root().join("manifest.RCM.xml")).unwrap();
    assert!(body.contains(&r_ok), "normal collected file missing from manifest");
    // Committed collected evidence ending .tmp/.part IS covered (sidecar
    // exists); .sig stays spec-excluded.
    assert!(body.contains(&r_tmp), "collected .tmp missing from manifest");
    assert!(body.contains(&r_part), "collected .part missing from manifest");
    assert!(!body.contains(&r_sig), ".sig must stay spec-excluded");
    // Tampering the .tmp is flagged.
    std::fs::write(m.root().join(&r_tmp), b"TAMPERED").unwrap();
    let bad = m.verify().unwrap();
    assert!(
        bad.contains(&r_tmp),
        "INTEGRITY GAP: tampering of collected notes.tmp invisible: {:?}",
        bad
    );
}

// ── Verify generation gap ─────────────────

#[test]
fn regression_manifest_generation_gap() {
    let dir = tempfile::tempdir().unwrap();
    let m = pm(&dir);
    m.store_collected("C:\\a.txt", b"1", &meta()).unwrap();
    m.seal().unwrap(); // gen 0
    m.store_collected("C:\\b.txt", b"2", &meta()).unwrap();
    m.seal().unwrap(); // gen 1
    m.store_collected("C:\\c.txt", b"3", &meta()).unwrap();
    m.seal().unwrap(); // gen 2
    // Delete gen 1: verify must still use gen 2 (the highest EXISTING
    // generation), not stop at the gap.
    std::fs::remove_file(m.root().join("manifest.RCM.1.xml")).unwrap();
    std::fs::write(m.root().join("downloads/C/c.txt"), b"EVIL").unwrap();
    let bad = m.verify().unwrap();
    assert!(
        bad.iter().any(|p| p.contains("c.txt")),
        "verify ignored the newest generation across the gap: {:?}",
        bad
    );
}

// ── Sidecar-failure orphans ─────────────────

#[test]
fn regression_counter_chain_name_max_explosion_no_orphans() {
    let dir = tempfile::tempdir().unwrap();
    let m = pm(&dir);
    // 100-char base name: each duplicate adds ".1"; around ~77 dups the
    // name exceeds NAME_MAX and allocation fails - the package must stay
    // consistent either way (no data-file-without-sidecar orphans).
    let base = "b".repeat(100);
    let p = format!("C:\\d\\{}", base);
    for i in 0..120 {
        if m.store_collected(&p, b"x", &meta()).is_err() {
            println!("counter chain broke at duplicate {}", i);
            break;
        }
    }
    assert_sidecar_pairing(m.root());

    // 255-byte final component: data file fits NAME_MAX, sidecar does not
    // -> clean Err, no orphan data file.
    let name = "n".repeat(255);
    let p = format!("C:\\d\\{}", name);
    let r = m.store_collected(&p, b"x", &meta());
    assert!(r.is_err(), "255-byte component should fail: {:?}", r);
    assert_sidecar_pairing(m.root());
}

// ── Meta cache cap ─────────────────────────────────────────────────

#[test]
fn regression_meta_cache_capped_fifo() {
    let dir = tempfile::tempdir().unwrap();
    let m = pm(&dir);
    for i in 0..5000u64 {
        m.note_file_meta(
            "batch",
            &format!("rel/{}.txt", i),
            &format!("C:\\abs\\{}.txt", i),
            meta(),
        );
    }
    // Oldest evicted (FIFO), newest retained; cache bounded.
    assert!(m.peek_file_meta("batch", "rel/0.txt").is_none());
    assert!(m.peek_file_meta("batch", "rel/3975.txt").is_none());
    assert!(m.peek_file_meta("batch", "rel/3976.txt").is_some());
    assert!(m.peek_file_meta("batch", "rel/4999.txt").is_some());
}

// ── Filename-less paths rejected, no tree poisoning ───────────────

#[test]
fn regression_filename_less_paths_rejected_no_poisoning() {
    let dir = tempfile::tempdir().unwrap();
    let m = pm(&dir);
    for bad in [
        "C:", "C:\\", "C:/", "/", "\\\\", "//", "\\\\server\\share", "C:\\a\\", "",
    ] {
        let r = m.store_collected(bad, b"x", &meta());
        assert!(r.is_err(), "path {:?} should be rejected, got {:?}", bad, r);
    }
    // No artifacts (in particular no file named "C").
    let mut files = Vec::new();
    walk(&m.root().join("downloads"), "downloads", &mut files);
    assert!(files.is_empty(), "rejected paths left artifacts: {:?}", files);
    // Later legitimate stores still work.
    assert_eq!(
        m.store_collected("C:\\a.txt", b"y", &meta()).unwrap(),
        "downloads/C/a.txt"
    );
    assert_eq!(
        m.store_collected("file.txt", b"z", &meta()).unwrap(),
        "downloads/file.txt"
    );
    assert_sidecar_pairing(m.root());
}

// ── Per-transfer chunk slots (same-total cross-transfer mixing) ────
//
// Two chunked transfers of the SAME path with the SAME total_chunks used to
// share "<X>.part"/"<X>.part.state": transfer B's chunk-0 restart truncated
// A's part and A's late chunks appended into B's bytes (final content
// "BBBBA1A1"-style mixes, undetectable by manifest verify). Every transfer
// now owns a slot named by its 4-field state's transfer_id.

#[test]
fn regression_concurrent_same_path_transfers_do_not_mix() {
    let dir = tempfile::tempdir().unwrap();
    let m = pm(&dir);
    let path = "C:\\loot\\big.bin";

    // A starts, then B's chunk 0 "restart" arrives with the same total.
    assert!(!m
        .store_collected_chunk(path, 0, 2, b"A0", "req-A", &meta())
        .unwrap());
    assert!(!m
        .store_collected_chunk(path, 0, 2, b"B0", "req-B", &meta())
        .unwrap());
    // B did NOT truncate A: B got the next slot.
    assert_eq!(
        std::fs::read(m.root().join("downloads/C/loot/big.bin.part")).unwrap(),
        b"A0"
    );
    assert_eq!(
        std::fs::read(m.root().join("downloads/C/loot/big.bin.part.1")).unwrap(),
        b"B0"
    );

    // A's late chunk 1 must append to A's OWN part, never to B's.
    assert!(m
        .store_collected_chunk(path, 1, 2, b"A1", "req-A", &meta())
        .unwrap());
    assert!(m
        .store_collected_chunk(path, 1, 2, b"B1", "req-B", &meta())
        .unwrap());

    // Both finalized unmixed, via REQ-3.4.3 counter allocation: X and X.1.
    let x = std::fs::read(m.root().join("downloads/C/loot/big.bin")).unwrap();
    let x1 = std::fs::read(m.root().join("downloads/C/loot/big.bin.1")).unwrap();
    assert_eq!(x, b"A0A1", "first finalize must be A's unmixed content");
    assert_eq!(x1, b"B0B1", "second finalize must be B's unmixed content");
    // No transfer residue in any slot.
    assert!(!m.root().join("downloads/C/loot/big.bin.part").exists());
    assert!(!m.root().join("downloads/C/loot/big.bin.part.state").exists());
    assert!(!m.root().join("downloads/C/loot/big.bin.part.1").exists());
    assert!(!m.root().join("downloads/C/loot/big.bin.part.1.state").exists());
    assert_sidecar_pairing(m.root());
}

#[test]
fn regression_chunk_nonzero_unknown_transfer_id_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let m = pm(&dir);
    assert!(!m
        .store_collected_chunk("/v/f.bin", 0, 3, b"AA", "req-known", &meta())
        .unwrap());
    // Chunk > 0 carrying a foreign id must NOT append to the live slot.
    let r = m.store_collected_chunk("/v/f.bin", 1, 3, b"BB", "req-unknown", &meta());
    let err = format!("{:?}", r.unwrap_err());
    assert!(
        err.contains("no in-flight transfer with this id"),
        "unexpected error: {}",
        err
    );
    assert_eq!(
        std::fs::read(m.root().join("downloads/v/f.bin.part")).unwrap(),
        b"AA"
    );
    // No in-flight transfer at all: same error.
    let r2 = m.store_collected_chunk("/w/g.bin", 1, 2, b"X", "req-none", &meta());
    assert!(r2.is_err());
}

#[test]
fn regression_same_id_chunk0_retry_truncates_and_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let m = pm(&dir);
    // Start a transfer, abandon it, then retry chunk 0 with the SAME id:
    // the slot is truncated and restarted cleanly (not a new slot).
    assert!(!m
        .store_collected_chunk("/r/big", 0, 2, &[0xAA; 100], "req-r", &meta())
        .unwrap());
    assert!(!m
        .store_collected_chunk("/r/big", 0, 2, &[0xCC; 50], "req-r", &meta())
        .unwrap());
    assert_eq!(
        std::fs::read(m.root().join("downloads/r/big.part")).unwrap(),
        vec![0xCC; 50]
    );
    assert_eq!(
        std::fs::read_to_string(m.root().join("downloads/r/big.part.state")).unwrap(),
        "1,2,50,req-r"
    );
    assert!(m
        .store_collected_chunk("/r/big", 1, 2, &[0xBB; 10], "req-r", &meta())
        .unwrap());
    let data = std::fs::read(m.root().join("downloads/r/big")).unwrap();
    assert_eq!(data.len(), 60);
    assert!(data[..50].iter().all(|&b| b == 0xCC));
    assert!(data[50..].iter().all(|&b| b == 0xBB));
    // The retry never spilled into a second slot.
    assert!(!m.root().join("downloads/r/big.part.1").exists());
}

#[test]
fn regression_chunk_state_field_counts_strict() {
    let dir = tempfile::tempdir().unwrap();
    let m = pm(&dir);
    // 2-, 3- (legacy) and 5-field states are NOT proof of an in-flight
    // transfer: chunk > 0 errors out, and the artifacts are never touched.
    for (i, garbage) in ["1,2", "1,2,3", "1,2,3,tid,extra"].iter().enumerate() {
        let d = m.root().join("downloads/s");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(format!("f{}.part", i)), b"PRE").unwrap();
        std::fs::write(d.join(format!("f{}.part.state", i)), garbage).unwrap();
        let rel = format!("/s/f{}", i);
        let r = m.store_collected_chunk(&rel, 1, 2, b"NEW", "req-s", &meta());
        assert!(r.is_err(), "{}-field state {:?} accepted", i + 2, garbage);
        assert_eq!(
            std::fs::read(d.join(format!("f{}.part", i))).unwrap(),
            b"PRE"
        );
        // Chunk 0 also refuses the slot (committed evidence) and moves on
        // (single-chunk transfer -> finalizes immediately).
        assert!(m
            .store_collected_chunk(&rel, 0, 1, b"Z", "req-s", &meta())
            .unwrap());
        assert_eq!(
            std::fs::read(d.join(format!("f{}.part", i))).unwrap(),
            b"PRE",
            "garbage-state .part was modified"
        );
        assert_eq!(
            std::fs::read_to_string(d.join(format!("f{}.part.state", i))).unwrap(),
            *garbage,
            "garbage state file was modified"
        );
    }
}

#[test]
fn regression_chunk_slot_exhaustion_errors() {
    let dir = tempfile::tempdir().unwrap();
    let m = pm(&dir);
    // 8 concurrent transfers of the same path fill every slot...
    for i in 0..8 {
        assert!(
            !m.store_collected_chunk(
                "/busy/f",
                0,
                2,
                b"x",
                &format!("req-{}", i),
                &meta()
            )
            .unwrap(),
            "transfer {} should claim a slot",
            i
        );
    }
    // ...the 9th gets a clear error instead of mixing into a foreign slot.
    let r = m.store_collected_chunk("/busy/f", 0, 2, b"y", "req-8", &meta());
    let err = format!("{:?}", r.unwrap_err());
    assert!(
        err.contains("too many concurrent transfers"),
        "unexpected error: {}",
        err
    );
    // Completing one transfer frees its slot for a new transfer.
    assert!(m
        .store_collected_chunk("/busy/f", 1, 2, b"z", "req-3", &meta())
        .unwrap());
    assert!(!m
        .store_collected_chunk("/busy/f", 0, 2, b"w", "req-8", &meta())
        .unwrap());
}

// ── POSIX multi-slash paths are not UNC ────────────────────────────

#[test]
fn regression_posix_multi_slash_paths_not_unc() {
    let dir = tempfile::tempdir().unwrap();
    let m = pm(&dir);
    // POSIX duplicate leading slashes: stored as a plain POSIX tree.
    assert_eq!(
        m.store_collected("////etc///passwd", b"pw", &meta()).unwrap(),
        "downloads/etc/passwd"
    );
    assert!(!m.root().join("downloads/UNC").exists());
    // Genuine UNC wire form (exactly two separators) stays under UNC/.
    assert_eq!(
        m.store_collected("//server/share/f.txt", b"s", &meta()).unwrap(),
        "downloads/UNC/server/share/f.txt"
    );
    assert_eq!(
        m.store_collected("\\\\server2\\share2\\g.txt", b"s2", &meta())
            .unwrap(),
        "downloads/UNC/server2/share2/g.txt"
    );
    // UNC share root with no file still rejected; multi-slash dir too.
    assert!(m.store_collected("//server/share", b"x", &meta()).is_err());
    assert!(m.store_collected("////", b"x", &meta()).is_err());
    assert!(m.store_collected("////etc/", b"x", &meta()).is_err());
    assert_sidecar_pairing(m.root());
}
