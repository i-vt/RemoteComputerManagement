// tests/test_recursive_download.rs
//
// Functional tests for the chunked recursive-download pipeline, ported to the
// RCM data collection packages (SPEC §5, §8). Every test transfers files via
// PackageManager::store_collected_chunk exactly as session.rs does on receipt
// of a `file:chunk` message, then verifies each stored file's SHA-256 hash
// matches the original - and that the RCM layout (downloads/, downloads.metadata/,
// no leftover .part) is produced.
//
// All packages live in a hermetic `tempfile::TempDir`.
//
// Test groups
// ───────────
//   fixture_three_nested_folders - structured tree, variety of file types/sizes
//   fixture_random_tree - seed-based PRNG tree of arbitrary shape
//   single_file_1gb - 1 GiB file, chunked at 8 MiB (#[ignore])
//   batch_report_in_custody_log - batch summary lands in custody/log, no json file
//   directory_structure - rel_paths reconstruct under downloads/
//   windows_backslash_paths - backslash rel_paths normalised per REQ-8.1
//   corrupted_transfer_fails_hash_check - tamper detection via seal + verify

use rcm::rcm::{CollectedMeta, PackageManager};
use rcm::rcm::custody::CustodyAction;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

// ── SHA-256 helpers ───────────────────────────────────────────────────────────

/// Hash a file on disk, reading in 64 KB chunks (works for any size).
fn sha256_file(p: &Path) -> [u8; 32] {
    let mut h  = Sha256::new();
    let mut f  = std::fs::File::open(p).expect("open for hashing");
    let mut buf = vec![0u8; 65_536];
    loop {
        let n = f.read(&mut buf).unwrap();
        if n == 0 { break; }
        h.update(&buf[..n]);
    }
    h.finalize().into()
}

/// Hash a byte slice.
fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

// ── Transfer helpers ──────────────────────────────────────────────────────────

fn pkg(base: &Path, hostname: &str) -> Arc<PackageManager> {
    PackageManager::create_or_open(base, hostname, &format!("inst-{}", hostname))
        .expect("create_or_open")
}

fn collected(pkg: &PackageManager, rel: &str) -> PathBuf {
    pkg.root().join("downloads").join(rel)
}

/// Drive bytes through store_collected_chunk in 8 MiB pieces, mirroring what
/// the agent's handle_recursive_download / handle_file_download_chunked sends
/// and what session.rs now stores via the RCM package.
fn transfer(pkg: &PackageManager, rel_path: &str, content: &[u8]) {
    const CHUNK: usize = 8 * 1024 * 1024;

    if content.is_empty() {
        let fin = pkg
            .store_collected_chunk(rel_path, 0, 1, b"", rel_path, &CollectedMeta::default())
            .expect("empty-file chunk");
        assert!(fin, "single empty chunk must finalize");
        return;
    }

    let chunks: Vec<&[u8]> = content.chunks(CHUNK).collect();
    let total = chunks.len() as u64;
    for (i, chunk) in chunks.iter().enumerate() {
        let fin = pkg
            .store_collected_chunk(rel_path, i as u64, total, chunk, rel_path, &CollectedMeta::default())
            .unwrap_or_else(|e| panic!("chunk {}/{} failed: {}", i + 1, total, e));
        assert_eq!(fin, i as u64 + 1 == total, "finalization flag on chunk {}", i);
    }
}

/// Assert SHA-256 of the stored file == SHA-256 of content, plus the RCM
/// layout: file under downloads/, sidecar under downloads.metadata/, and no
/// .part residue. `stored_rel` is the normalised storage path (differs from
/// the wire path when the agent sent backslash separators).
fn verify_stored(pkg: &PackageManager, stored_rel: &str, content: &[u8]) {
    let saved = collected(pkg, stored_rel);
    assert!(saved.exists(), "saved file missing: {}", saved.display());
    let saved_hash   = sha256_file(&saved);
    let content_hash = sha256_bytes(content);
    assert_eq!(
        saved_hash, content_hash,
        "SHA-256 mismatch for {}: saved {:x?} ≠ expected {:x?}",
        stored_rel, &saved_hash[..4], &content_hash[..4]
    );
    let sc = pkg.root()
        .join("downloads.metadata")
        .join(format!("{}.RCM.xml", stored_rel));
    assert!(sc.is_file(), "sidecar missing: {}", sc.display());
    let part = saved.with_file_name(format!(
        "{}.part",
        saved.file_name().unwrap().to_string_lossy()
    ));
    assert!(!part.exists(), ".part left behind: {}", part.display());
}

/// Transfer then verify the stored result at the same (already normalised)
/// relative path.
fn transfer_and_verify(pkg: &PackageManager, rel_path: &str, content: &[u8]) {
    transfer(pkg, rel_path, content);
    verify_stored(pkg, rel_path, content);
}

// ── Pseudo-random bytes (no rand crate needed for content generation) ─────────

/// Fast deterministic byte generator (PCG64-family LCG).
fn pseudo_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 33) as u8
        })
        .collect()
}

// ── Test 1: three nested folders with variety of files ───────────────────────
//
// Tree (stored under <pkg>/downloads/project/...):
//   project/
//   ├── readme.txt (UTF-8 text, ~1 KB)
//   ├── empty.bin (0 bytes)
//   ├── data.bin (binary, ~100 KB)
//   ├── large.bin (binary, 12 MB - spans two 8 MB chunks)
//   ├── alpha/
//   │   ├── config.toml (TOML-like text, ~2 KB)
//   │   ├── logo.png (fake PNG header + random body, ~50 KB)
//   │   └── deep/
//   │       ├── code.rs (Rust source text, ~3 KB)
//   │       └── nested/
//   │           └── archive.bin (binary, ~5 MB)
//   ├── beta/
//   │   ├── report.txt (text, ~10 KB)
//   │   └── assets/
//   │       ├── font.bin (fake binary font, ~200 KB)
//   │       └── theme.css (CSS text, ~4 KB)
//   └── gamma/
//       ├── database.bin (fake DB blob, ~1 MB)
//       ├── script.py (Python text, ~800 B)
//       └── logs/
//           ├── app.log (log text, ~10 MB - also spans two chunks)
//           └── error.log (small text, ~200 B)

#[test]
fn fixture_three_nested_folders() {
    let dir = tempfile::tempdir().unwrap();
    let p = pkg(dir.path(), "HOST-3NEST");

    struct Entry { rel: &'static str, content: Vec<u8> }
    let entries: Vec<Entry> = vec![
        Entry { rel: "project/readme.txt",              content: b"# Project README\n\nThis is a test project.\n".repeat(25) },
        Entry { rel: "project/empty.bin",               content: vec![] },
        Entry { rel: "project/data.bin",                content: pseudo_bytes(0x1111, 100_000) },
        Entry { rel: "project/large.bin",               content: pseudo_bytes(0x2222, 12 * 1024 * 1024) },
        Entry { rel: "project/alpha/config.toml",       content: b"[server]\nhost = \"localhost\"\nport = 8080\n".repeat(40) },
        Entry { rel: "project/alpha/logo.png",          content: { let mut v = b"\x89PNG\r\n\x1a\n".to_vec(); v.extend(pseudo_bytes(0x3333, 50_000)); v } },
        Entry { rel: "project/alpha/deep/code.rs",      content: b"fn main() { println!(\"hello\"); }\n".repeat(90) },
        Entry { rel: "project/alpha/deep/nested/archive.bin", content: pseudo_bytes(0x4444, 5 * 1024 * 1024) },
        Entry { rel: "project/beta/report.txt",         content: b"Report line.\n".repeat(800) },
        Entry { rel: "project/beta/assets/font.bin",    content: pseudo_bytes(0x5555, 200_000) },
        Entry { rel: "project/beta/assets/theme.css",   content: b"body { margin: 0; }\n".repeat(200) },
        Entry { rel: "project/gamma/database.bin",      content: pseudo_bytes(0x6666, 1024 * 1024) },
        Entry { rel: "project/gamma/script.py",         content: b"print('hello')\n".repeat(53) },
        Entry { rel: "project/gamma/logs/app.log",      content: b"INFO 2025-01-01 event ok\n".repeat(430_000) },
        Entry { rel: "project/gamma/logs/error.log",    content: b"ERROR nothing\n".repeat(15) },
    ];

    for e in &entries {
        transfer_and_verify(&p, e.rel, &e.content);
    }
}

// ── Test 2: randomly generated file tree ─────────────────────────────────────

#[test]
fn fixture_random_tree() {
    let dir = tempfile::tempdir().unwrap();
    let p = pkg(dir.path(), "HOST-RAND");

    // Seeded PRNG state (xorshift64)
    let mut rng_state: u64 = 0xDEAD_BEEF_1234_5678;
    let mut rng = || -> u64 {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state << 17;
        rng_state
    };

    // Build a tree: for each path depth 0..=4, create 0-5 files with sizes
    // ranging from 1 byte to 3 MB.
    let depth_names = ["random_tree", "alpha", "beta/sub", "gamma/deep/nest", "delta/a/b/c"];
    let mut total_files = 0usize;

    for depth_path in &depth_names {
        let num_files = (rng() % 5 + 1) as usize;
        for fi in 0..num_files {
            let size  = (rng() % (3 * 1024 * 1024) + 1) as usize;
            let seed  = rng();
            let rel   = format!("{}/file_{:03}.bin", depth_path, fi);
            transfer_and_verify(&p, &rel, &pseudo_bytes(seed, size));
            total_files += 1;
        }
    }

    assert!(total_files >= 5, "expected at least 5 files in random tree, got {}", total_files);
}

// ── Test 3: 1 GiB file ───────────────────────────────────────────────────────
// Marked #[ignore] so it doesn't run in normal CI (requires ~2 GB disk, ~30s).
// Run explicitly with: cargo test single_file_1gb -- --ignored

#[ignore]
#[test]
fn single_file_1gb() {
    const GIB: usize = 1 << 30;
    const CHUNK: usize = 8 * 1024 * 1024;

    let dir = tempfile::tempdir().unwrap();
    let p = pkg(dir.path(), "HOST-1GB");
    let rel = "bigfiles/one_gib.bin";

    // Compute SHA-256 while generating content (never holds the full GiB in RAM).
    let total_chunks = GIB / CHUNK;
    let mut hasher   = Sha256::new();
    let mut buf      = vec![0u8; CHUNK];

    for chunk_idx in 0u64..total_chunks as u64 {
        for (i, b) in buf.iter_mut().enumerate() {
            let pos = chunk_idx * CHUNK as u64 + i as u64;
            *b = (pos.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407) >> 24) as u8;
        }
        hasher.update(&buf);
        let fin = p
            .store_collected_chunk(rel, chunk_idx, total_chunks as u64, &buf, "t-1gb", &CollectedMeta::default())
            .unwrap_or_else(|e| panic!("chunk {} failed: {}", chunk_idx, e));
        assert_eq!(fin, chunk_idx as usize + 1 == total_chunks);
    }
    let expected_hash: [u8; 32] = hasher.finalize().into();

    // Verify the stored file by reading it back in chunks
    let saved_hash = sha256_file(&collected(&p, rel));
    assert_eq!(saved_hash, expected_hash, "1 GiB SHA-256 mismatch");
}

// ── Test 4: batch report goes to custody + log, not a json file ──────────────
//
// The old loot storage wrote <root>.json report files into downloads/.
// Under RCM the batch summary is a custody COLLECT event plus a Sec-13 log
// line - no report file on disk.

#[test]
fn batch_report_in_custody_log_not_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let p = pkg(dir.path(), "HOST-REPORT");

    // Mirror what session.rs does for file:report_batch|.
    let json = r#"{"root_path":"/home/user","total_files_found":3,"total_success":3,"failed_downloads":[]}"#;
    p.log("agent", "INFO", &format!("batch report {}: {}", "MyLootDir", json)).unwrap();
    p.custody("rcm-server", CustodyAction::Collect, None,
        Some("batch b1: 3 found, 3 collected, 0 failed")).unwrap();

    let custody_xml = std::fs::read_to_string(p.root().join("custody.RCM.xml")).unwrap();
    assert!(custody_xml.contains("3 found, 3 collected, 0 failed"),
        "custody summary missing: {}", custody_xml);
    assert!(custody_xml.contains("COLLECT"), "COLLECT action missing");

    // The log line landed under logs/rcm-server/agent/<date>/.
    let logs_dir = p.root().join("logs").join("rcm-server").join("agent");
    assert!(logs_dir.is_dir(), "agent log dir missing");

    // No report json file anywhere in the package downloads tree.
    let mut stack = vec![p.root().to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let e = e.unwrap();
            let ft = e.file_type().unwrap();
            if ft.is_dir() {
                stack.push(e.path());
            } else {
                let name = e.file_name().into_string().unwrap();
                assert!(!name.ends_with(".json"),
                    "report json file must not exist: {}", e.path().display());
            }
        }
    }
}

// ── Test 5: directory structure inside the package ───────────────────────────

#[test]
fn directory_contents_nested_under_downloads() {
    // rel_path = "Documents/sub/file.txt" must land at
    //   <pkg>/downloads/Documents/sub/file.txt
    // so the loot browser sees a "Documents/" subfolder, not loose files.

    let dir = tempfile::tempdir().unwrap();
    let p = pkg(dir.path(), "HOST-DOCS");

    let files = [
        ("Documents/top.txt",          pseudo_bytes(1, 512)),
        ("Documents/sub/mid.txt",       pseudo_bytes(2, 1024)),
        ("Documents/sub/deep/end.bin",  pseudo_bytes(3, 2048)),
    ];

    for (rel, content) in &files {
        transfer_and_verify(&p, rel, content);
    }

    let dl = p.root().join("downloads");
    assert!(dl.join("Documents").is_dir(), "Documents/ subfolder must exist");
    assert!(dl.join("Documents/sub").is_dir(), "Documents/sub/ must exist");
    assert!(dl.join("Documents/sub/deep").is_dir(), "Documents/sub/deep/ must exist");
}

// ── Test 6: Windows backslash paths are handled correctly ────────────────────

#[test]
fn windows_backslash_rel_paths_are_normalised() {
    // REQ-8.1: reconstruction accepts both separators, so a Windows agent's
    // backslash rel_paths land in proper directories (no literal '\'
    // filenames on Linux).

    let dir = tempfile::tempdir().unwrap();
    let p = pkg(dir.path(), "HOST-WIN");

    let cases = [
        ("Documents/passwords.txt",          "Documents/passwords.txt",         pseudo_bytes(10, 256)),
        ("Documents/Reports/q1.xlsx",        "Documents/Reports/q1.xlsx",       pseudo_bytes(11, 1024)),
        ("Documents\\Reports\\q2.xlsx",      "Documents/Reports/q2.xlsx",       pseudo_bytes(12, 1024)),
        ("Documents\\Backup\\old_pass.txt",  "Documents/Backup/old_pass.txt",   pseudo_bytes(13, 128)),
    ];

    for (wire, stored_rel, content) in &cases {
        transfer(&p, wire, content);
        // When the wire path used backslashes, the stored path must be the
        // normalised forward-slash layout.
        verify_stored(&p, stored_rel, content);
    }

    // Absolute Windows paths reconstruct under the drive-letter folder.
    transfer(&p, "C:\\Users\\user1\\Documents\\pw.txt", b"secret");
    verify_stored(&p, "C/Users/user1/Documents/pw.txt", b"secret");
}

// ── Test 7: tampering is detected by seal + verify ───────────────────────────

#[test]
fn corrupted_transfer_fails_hash_check() {
    let dir = tempfile::tempdir().unwrap();
    let p = pkg(dir.path(), "HOST-TAMPER");

    let original = pseudo_bytes(0xABCD, 4096);
    transfer(&p, "root/file.bin", &original);

    // Baseline: sealed package verifies clean.
    p.seal().unwrap();
    assert!(p.verify().unwrap().is_empty(), "fresh seal must verify");

    // Tamper with byte 100 on disk.
    let saved = collected(&p, "root/file.bin");
    let mut data = std::fs::read(&saved).unwrap();
    data[100] ^= 0xFF;
    std::fs::write(&saved, &data).unwrap();

    // The raw hash no longer matches the original content…
    let saved_hash   = sha256_file(&saved);
    let content_hash = sha256_bytes(&original);
    assert_ne!(saved_hash, content_hash, "corrupted file should differ");

    // …and the RCM manifest verification reports the mismatch.
    let mismatches = p.verify().unwrap();
    assert!(mismatches.iter().any(|m| m.contains("file.bin")),
        "verify() must flag the tampered file: {:?}", mismatches);
}
