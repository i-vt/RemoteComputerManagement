// tests/test_rcm_meta.rs
//
// Regression tests for the RCM review findings:
//   FIX 1 - meta cache must survive until a chunked transfer finalizes
//           (peek per chunk, take on finalize), so recursive multi-chunk
//           downloads land at the ANNOUNCED absolute path with the
//           announced metadata (findings #1/#2).
//   FIX 2 - fingerprint upsert is a KEY-LEVEL merge (osversion added to the
//           seeded tuple; conflicts keep the existing value per key).
//   FIX 4 - chunk_idx == 0 is a fresh restart: stale .part/.part.state are
//           discarded instead of permanently blocking the transfer.
//
// All packages live in a hermetic `tempfile::TempDir`.

use rcm::rcm::fingerprint::{FingerprintEntry, UpsertOutcome};
use rcm::rcm::{CollectedMeta, PackageManager};
use std::path::Path;
use std::sync::Arc;

fn pkg(base: &Path, hostname: &str) -> Arc<PackageManager> {
    PackageManager::create_or_open(base, hostname, &format!("inst-{}", hostname))
        .expect("create_or_open")
}

// ── Meta-cache lifecycle across a multi-chunk recursive download ──────

/// Mirror the session.rs `file:chunk|` handler semantics: peek the meta
/// cache for EVERY chunk, store with the peeked abs+meta, evict only after
/// finalization (Ok(true)).
fn session_style_chunk(
    p: &PackageManager,
    batch_ts: &str,
    rel: &str,
    idx: u64,
    total: u64,
    bytes: &[u8],
) -> bool {
    let (abs, meta) = p
        .peek_file_meta(batch_ts, rel)
        .unwrap_or_else(|| (rel.to_string(), CollectedMeta::default()));
    let fin = p
        .store_collected_chunk(&abs, idx, total, bytes, batch_ts, &meta)
        .unwrap_or_else(|e| panic!("chunk {}/{} failed: {}", idx, total, e));
    if fin {
        let _ = p.take_file_meta(batch_ts, rel);
    }
    fin
}

#[test]
fn meta_cache_survives_multi_chunk_recursive_download() {
    let dir = tempfile::tempdir().unwrap();
    let p = pkg(dir.path(), "VICTIM-PC");

    let batch = "2026-01-06T08:11:00.1232010Z";
    let rel = "Documents/a/big.bin";
    // Announced absolute path, exactly as a Windows agent reports it
    // (backslash separators; verbatim separators must reach the sidecar).
    let abs = "C:\\Users\\victim\\Documents\\a\\big.bin";
    let modified = "2026-01-05T22:00:00.0000000Z";
    p.note_file_meta(
        batch,
        rel,
        abs,
        CollectedMeta {
            modified: Some(modified.to_string()),
            accessed: None,
            created: None,
            owner: Some("victim".to_string()),
            group: None,
        },
    );

    // Chunk 0 must NOT consume the cache entry.
    assert!(!session_style_chunk(&p, batch, rel, 0, 3, b"AAA"));
    assert!(
        p.peek_file_meta(batch, rel).is_some(),
        "meta entry evicted before finalization"
    );
    // The .part lives at the ABS reconstruction, never under rel.
    let part = p.root().join("downloads/C/Users/victim/Documents/a/big.bin.part");
    assert!(part.exists(), ".part missing at abs reconstruction");
    assert!(
        !p.root().join("downloads/Documents").exists(),
        "fallback rel path must not be used when meta was announced"
    );

    assert!(!session_style_chunk(&p, batch, rel, 1, 3, b"BBB"));
    assert!(session_style_chunk(&p, batch, rel, 2, 3, b"CCC"));

    // Finalized content landed under downloads/C/Users/victim/Documents/a/.
    let final_path = p.root().join("downloads/C/Users/victim/Documents/a/big.bin");
    assert_eq!(std::fs::read(&final_path).unwrap(), b"AAABBBCCC");
    assert!(!part.exists());
    assert!(!part.with_file_name("big.bin.part.state").exists());
    // Cache entry evicted on finalize.
    assert!(p.peek_file_meta(batch, rel).is_none());

    // Sidecar carries the ANNOUNCED metadata: modified time and the
    // verbatim dirname (backslash separators) - not the rel-derived one.
    let sc = std::fs::read_to_string(
        p.root()
            .join("downloads.metadata/C/Users/victim/Documents/a/big.bin.RCM.xml"),
    )
    .expect("sidecar");
    assert!(
        sc.contains(&format!("<modifiedtime>{}</modifiedtime>", modified)),
        "announced modified time missing: {}",
        sc
    );
    assert!(
        sc.contains("<dirname>C:\\Users\\victim\\Documents\\a</dirname>"),
        "verbatim dirname missing: {}",
        sc
    );
    assert!(sc.contains("<name>big.bin</name>"));
    assert!(sc.contains("<owner>victim</owner>"));
}

// ── Fingerprint upsert is a key-level merge ───────────────────────────

#[test]
fn fingerprint_seed_then_osversion_merges() {
    let dir = tempfile::tempdir().unwrap();
    // create_or_open seeds (machine,os,1) with
    // [hostname, usertag, private_rcm_computerid] - no osversion.
    let p = pkg(dir.path(), "USER-PC");

    let entry = FingerprintEntry {
        target: "machine".into(),
        fp_type: "os".into(),
        version: 1,
        uid: None,
        fields: vec![
            ("hostname".into(), "USER-PC".into()),
            ("osversion".into(), "6.1.7601".into()),
            ("usertag".into(), "NONE".into()),
            ("private_rcm_computerid".into(), "inst-USER-PC".into()),
        ],
    };
    let outcome = p.update_fingerprint(&entry).unwrap();
    assert_eq!(outcome, UpsertOutcome::Merged);

    let doc = std::fs::read_to_string(p.root().join("fingerprint.RCM.xml")).unwrap();
    assert_eq!(doc.matches("<fingerprint ").count(), 1, "no duplicate entry");
    assert!(doc.contains("<osversion>6.1.7601</osversion>"));
    assert!(doc.contains("<hostname>USER-PC</hostname>"));

    // No discrepancy logged for the merge.
    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let log_file = p
        .root()
        .join("logs/rcm-server/fingerprint")
        .join(&date)
        .join("0000.log");
    if log_file.exists() {
        let body = std::fs::read_to_string(&log_file).unwrap();
        assert!(!body.contains("discrepancy"), "spurious WARN: {}", body);
    }
}

#[test]
fn fingerprint_conflict_keeps_existing_value_and_names_key() {
    let dir = tempfile::tempdir().unwrap();
    let p = pkg(dir.path(), "USER-PC");

    let mut entry = FingerprintEntry {
        target: "machine".into(),
        fp_type: "os".into(),
        version: 1,
        uid: None,
        fields: vec![
            ("hostname".into(), "OTHER-PC".into()), // conflicts with seed
            ("osversion".into(), "6.1.7601".into()), // new key, merges
            ("usertag".into(), "NONE".into()),
            ("private_rcm_computerid".into(), "inst-USER-PC".into()),
        ],
    };
    let outcome = p.update_fingerprint(&entry).unwrap();
    assert_eq!(outcome, UpsertOutcome::ConflictKept(vec!["hostname".into()]));

    let doc = std::fs::read_to_string(p.root().join("fingerprint.RCM.xml")).unwrap();
    assert!(doc.contains("<hostname>USER-PC</hostname>"), "existing kept");
    assert!(!doc.contains("OTHER-PC"));
    assert!(doc.contains("<osversion>6.1.7601</osversion>"), "new key merged");

    // The discrepancy WARN names the key (REQ-7.6.3).
    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let body = std::fs::read_to_string(
        p.root()
            .join("logs/rcm-server/fingerprint")
            .join(&date)
            .join("0000.log"),
    )
    .unwrap();
    assert!(body.contains(" WARN "));
    assert!(body.contains("key=hostname"));

    // Identical re-upsert is a no-op.
    entry.fields[0].1 = "USER-PC".into();
    assert_eq!(p.update_fingerprint(&entry).unwrap(), UpsertOutcome::NoChange);
}

// ── Chunk 0 restarts a stale transfer instead of blocking ─────────────

#[test]
fn chunk_zero_restarts_stale_part_transfer() {
    let dir = tempfile::tempdir().unwrap();
    let p = pkg(dir.path(), "HOST-RESTART");
    let meta = CollectedMeta::default();
    let rel = "data/blob.bin";

    // Start a 3-chunk transfer and abandon it after chunk 0.
    assert!(!p.store_collected_chunk(rel, 0, 3, b"OLD", "t-r", &meta).unwrap());
    let part = p.root().join("downloads/data/blob.bin.part");
    let state = p.root().join("downloads/data/blob.bin.part.state");
    assert!(part.exists() && state.exists());

    // Restart at chunk 0: stale .part/.part.state are discarded, NOT an
    // error, and the new transfer completes with correct content.
    assert!(!p.store_collected_chunk(rel, 0, 3, b"AAA", "t-r", &meta).unwrap());
    assert_eq!(std::fs::read(&part).unwrap(), b"AAA");
    assert!(!p.store_collected_chunk(rel, 1, 3, b"BBB", "t-r", &meta).unwrap());
    assert!(p.store_collected_chunk(rel, 2, 3, b"CCC", "t-r", &meta).unwrap());

    assert_eq!(
        std::fs::read(p.root().join("downloads/data/blob.bin")).unwrap(),
        b"AAABBBCCC"
    );
    assert!(!part.exists(), "orphan .part left behind");
    assert!(!state.exists(), "orphan .part.state left behind");

    // Strict in-order for idx > 0 is unchanged.
    assert!(!p.store_collected_chunk(rel, 0, 3, b"111", "t-r2", &meta).unwrap());
    assert!(p.store_collected_chunk(rel, 2, 3, b"333", "t-r2", &meta).is_err());
}
