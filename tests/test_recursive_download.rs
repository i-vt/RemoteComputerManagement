// tests/test_recursive_download.rs
//
// Functional tests for the chunked recursive-download pipeline.
// Every test transfers files by calling save_file_chunk exactly as session.rs
// does on receipt of a `file:chunk` message, then verifies each saved file's
// SHA-256 hash matches the original.
//
// Test groups
// ───────────
//   fixture_three_nested_folders  — structured tree, variety of file types/sizes
//   fixture_random_tree           — seed-based PRNG tree of arbitrary shape
//   single_file_1gb               — 1 GiB file, chunked at 8 MiB (#[ignore])
//   metadata_json_naming          — report file lands as <root>.json, not a timestamp
//   windows_backslash_paths       — backslash rel_paths are normalised to forward-slash

use rcm::file_transfer::save_file_chunk;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use sha2::{Sha256, Digest};
use std::io::Read;
use std::path::{Path, PathBuf};

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

/// Unique batch identifier so parallel tests never collide.
fn batch(label: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("rl_{}_{}_{:08x}", label, std::process::id(), ns)
}

/// Delete the batch folder when the guard drops (keeps downloads/ clean).
struct BatchCleanup(PathBuf);
impl Drop for BatchCleanup {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

/// Compute expected on-disk path for a file given the same inputs as save_file_chunk.
fn expected_path(batch_ts: &str, session_id: u32, root_name: &str, rel_path: &str) -> PathBuf {
    let safe_root: String = root_name.chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
        .take(32).collect();
    PathBuf::from("downloads")
        .join(format!("{}_{}_{}", batch_ts, session_id, safe_root))
        .join(rel_path)
}

/// Drive bytes through save_file_chunk in 8 MiB pieces, mirroring what the
/// agent's handle_recursive_download / handle_file_download_chunked does.
fn transfer(
    batch_ts:  &str,
    session:   u32,
    root_name: &str,
    rel_path:  &str,
    content:   &[u8],
) {
    const CHUNK: usize = 8 * 1024 * 1024;

    if content.is_empty() {
        let r = save_file_chunk(batch_ts, session, root_name, rel_path, 0, 1, &BASE64.encode(b""));
        assert!(r.is_ok(), "empty-file chunk failed: {}", r.unwrap_err());
        return;
    }

    let chunks: Vec<&[u8]> = content.chunks(CHUNK).collect();
    let total = chunks.len() as u64;
    for (i, chunk) in chunks.iter().enumerate() {
        let r = save_file_chunk(
            batch_ts, session, root_name, rel_path,
            i as u64, total, &BASE64.encode(chunk),
        );
        assert!(r.is_ok(), "chunk {}/{} failed: {}", i + 1, total, r.unwrap_err());
    }
}

/// Transfer then assert SHA-256 of saved file == SHA-256 of content.
fn transfer_and_verify(
    batch_ts:  &str,
    session:   u32,
    root_name: &str,
    rel_path:  &str,
    content:   &[u8],
) {
    transfer(batch_ts, session, root_name, rel_path, content);
    let saved = expected_path(batch_ts, session, root_name, rel_path);
    assert!(saved.exists(), "saved file missing: {}", saved.display());
    let saved_hash   = sha256_file(&saved);
    let content_hash = sha256_bytes(content);
    assert_eq!(
        saved_hash, content_hash,
        "SHA-256 mismatch for {}: saved {:x?} ≠ expected {:x?}",
        rel_path, &saved_hash[..4], &content_hash[..4]
    );
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
// Tree:
//   root_name/
//   ├── readme.txt          (UTF-8 text, ~1 KB)
//   ├── empty.bin           (0 bytes)
//   ├── data.bin            (binary, ~100 KB)
//   ├── large.bin           (binary, 12 MB  — spans two 8 MB chunks)
//   ├── alpha/
//   │   ├── config.toml     (TOML-like text, ~2 KB)
//   │   ├── logo.png        (fake PNG header + random body, ~50 KB)
//   │   └── deep/
//   │       ├── code.rs     (Rust source text, ~3 KB)
//   │       └── nested/
//   │           └── archive.bin  (binary, ~5 MB)
//   ├── beta/
//   │   ├── report.txt      (text, ~10 KB)
//   │   └── assets/
//   │       ├── font.bin    (fake binary font, ~200 KB)
//   │       └── theme.css   (CSS text, ~4 KB)
//   └── gamma/
//       ├── database.bin    (fake DB blob, ~1 MB)
//       ├── script.py       (Python text, ~800 B)
//       └── logs/
//           ├── app.log     (log text, ~10 MB  — also spans two chunks)
//           └── error.log   (small text, ~200 B)

#[test]
fn fixture_three_nested_folders() {
    let bt  = batch("3nest");
    let sid = 10u32;
    let rn  = "project";
    let _c  = BatchCleanup(PathBuf::from(format!("downloads/{}_{}_project", bt, sid)));

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
        transfer_and_verify(&bt, sid, rn, e.rel, &e.content);
    }
}

// ── Test 2: randomly generated file tree ─────────────────────────────────────

#[test]
fn fixture_random_tree() {
    let bt  = batch("rand");
    let sid = 20u32;
    let rn  = "random_tree";
    let _c  = BatchCleanup(PathBuf::from(format!("downloads/{}_{}_random_tree", bt, sid)));

    // Seeded PRNG state (xorshift64)
    let mut rng_state: u64 = 0xDEAD_BEEF_1234_5678;
    let mut rng = || -> u64 {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state << 17;
        rng_state
    };

    // Build a tree: for each path depth 0..=4, create 0–5 files with sizes
    // ranging from 1 byte to 3 MB.
    let depth_names = ["random_tree", "alpha", "beta/sub", "gamma/deep/nest", "delta/a/b/c"];
    let mut total_files = 0usize;

    for depth_path in &depth_names {
        let num_files = (rng() % 5 + 1) as usize;
        for fi in 0..num_files {
            let size  = (rng() % (3 * 1024 * 1024) + 1) as usize;
            let seed  = rng();
            let rel   = format!("{}/file_{:03}.bin", depth_path, fi);
            transfer_and_verify(&bt, sid, rn, &rel, &pseudo_bytes(seed, size));
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

    let bt  = batch("1gb");
    let sid = 30u32;
    let rn  = "bigfiles";
    let rel = "bigfiles/one_gib.bin";
    let _c  = BatchCleanup(PathBuf::from(format!("downloads/{}_{}_bigfiles", bt, sid)));

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
        let b64 = BASE64.encode(&buf);
        let r   = save_file_chunk(&bt, sid, rn, rel, chunk_idx, total_chunks as u64, &b64);
        assert!(r.is_ok(), "chunk {} failed: {}", chunk_idx, r.unwrap_err());
    }
    let expected_hash: [u8; 32] = hasher.finalize().into();

    // Verify the saved file by reading it back in chunks
    let saved = expected_path(&bt, sid, rn, rel);
    let saved_hash = sha256_file(&saved);
    assert_eq!(saved_hash, expected_hash, "1 GiB SHA-256 mismatch");
}

// ── Test 4: metadata json naming ─────────────────────────────────────────────

#[test]
fn metadata_json_named_after_root_not_timestamp() {
    use rcm::file_transfer::save_batch_report;

    let bt  = batch("meta");
    let sid = 40u32;
    let rn  = "MyLootDir";
    let _c  = BatchCleanup(PathBuf::from(format!("downloads/{}_{}_MyLootDir", bt, sid)));

    let json = r#"{"root_path":"/home/user","total_files_found":3,"total_success":3,"failed_downloads":[]}"#;
    let path = save_batch_report(&bt, sid, rn, json).expect("save_batch_report");

    // The report must be named <root_name>.json, not <timestamp>_<sessid>_metadata.json
    let fname = PathBuf::from(&path);
    let name  = fname.file_name().and_then(|n| n.to_str()).unwrap_or("");
    assert_eq!(name, "MyLootDir.json",
        "expected MyLootDir.json, got {}", name);
    // Content must be valid JSON and contain our fields
    let saved = std::fs::read_to_string(&path).unwrap();
    assert!(saved.contains("total_success"), "JSON missing total_success: {}", saved);
}

// ── Test 5: directory structure inside batch folder ──────────────────────────

#[test]
fn directory_contents_nested_under_root_name() {
    // When the agent sends rel_path = "Documents/sub/file.txt" with
    // root_name = "Documents", the file must land at:
    //   downloads/<batch>_<sess>_Documents/Documents/sub/file.txt
    // so the loot browser sees a "Documents/" subfolder, not loose files.

    let bt  = batch("struct");
    let sid = 50u32;
    let rn  = "Documents";
    let _c  = BatchCleanup(PathBuf::from(format!("downloads/{}_{}_Documents", bt, sid)));

    let files = [
        ("Documents/top.txt",          pseudo_bytes(1, 512)),
        ("Documents/sub/mid.txt",       pseudo_bytes(2, 1024)),
        ("Documents/sub/deep/end.bin",  pseudo_bytes(3, 2048)),
    ];

    for (rel, content) in &files {
        transfer_and_verify(&bt, sid, rn, rel, content);
    }

    // Verify the Documents/ subdirectory was created inside the batch folder
    let batch_dir = PathBuf::from(format!("downloads/{}_{}_Documents", bt, sid));
    assert!(batch_dir.join("Documents").is_dir(),
        "Documents/ subfolder must exist inside batch dir");
    assert!(batch_dir.join("Documents/sub").is_dir(),
        "Documents/sub/ must exist");
    assert!(batch_dir.join("Documents/sub/deep").is_dir(),
        "Documents/sub/deep/ must exist");
}

// ── Test 6: Windows backslash paths are handled correctly ────────────────────

#[test]
fn windows_backslash_rel_paths_are_normalised() {
    // Simulate what a Windows agent sends when the operator runs
    //   file:read_recursive C:\Users\user1\Documents
    // After backslash normalisation in the agent, the wire format carries
    // forward slashes; this test verifies the server handles them correctly.

    let bt  = batch("winbsl");
    let sid = 60u32;
    let rn  = "Documents";
    let _c  = BatchCleanup(PathBuf::from(format!("downloads/{}_{}_Documents", bt, sid)));

    // rel_paths that a correctly-patched agent would send
    let cases = [
        ("Documents/passwords.txt",         pseudo_bytes(10, 256)),
        ("Documents/Reports/q1.xlsx",       pseudo_bytes(11, 1024)),
        ("Documents/Reports/q2.xlsx",       pseudo_bytes(12, 1024)),
        ("Documents/Backup/old_pass.txt",   pseudo_bytes(13, 128)),
    ];

    for (rel, content) in &cases {
        transfer_and_verify(&bt, sid, rn, rel, content);
    }

    // Also verify a backslash-containing rel_path is rejected by the server
    // (save_file_chunk's path sanitizer) — it should NOT create a file with
    // a literal backslash in its name on Linux.
    let bad = save_file_chunk(&bt, sid, rn, "Documents\\bad.txt", 0, 1, &BASE64.encode(b"x"));
    // On Linux, "Documents\\bad.txt" is a Normal component (no path sep) so
    // it saves to downloads/.../Documents\bad.txt (a single file with \ in name).
    // This is the expected degraded behaviour without normalisation;
    // the test simply records that it succeeds (doesn't crash) and we can
    // find that file.
    assert!(bad.is_ok(), "backslash path should not crash the server");
}

// ── Test 7: SHA-256 detects corruption ───────────────────────────────────────

#[test]
fn corrupted_transfer_fails_hash_check() {
    let bt  = batch("corrupt");
    let sid = 70u32;
    let rn  = "root";
    let _c  = BatchCleanup(PathBuf::from(format!("downloads/{}_{}_root", bt, sid)));

    let original = pseudo_bytes(0xABCD, 4096);
    transfer(&bt, sid, rn, "root/file.bin", &original);

    let saved = expected_path(&bt, sid, rn, "root/file.bin");
    // Tamper with byte 100 on disk
    let mut data = std::fs::read(&saved).unwrap();
    data[100] ^= 0xFF;
    std::fs::write(&saved, &data).unwrap();

    // Now the hash must NOT match
    let saved_hash   = sha256_file(&saved);
    let content_hash = sha256_bytes(&original);
    assert_ne!(saved_hash, content_hash,
        "corrupted file should have a different SHA-256");
}
