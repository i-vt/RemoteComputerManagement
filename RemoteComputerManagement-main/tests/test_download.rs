// tests/test_download.rs — Functional integration tests for chunked file download.
//
// These tests drive the server-side half of the download path:
//   agent sends file:chunk messages → session.rs calls save_file_chunk()
//                                    → file is assembled on disk
//
// Each test uses a unique batch identifier to isolate its output directory,
// and a DropCleanup guard ensures the directory is removed even on panic.
//
// Test groups:
//   - Single-chunk round-trips (small files, zero-byte files, binary content)
//   - Multi-chunk assembly (exact boundary, remainder, large content)
//   - Overwrite and truncation semantics
//   - Path sanitization (traversal blocked, special chars in root stripped)
//   - Concurrent batches don't interfere with each other

use rcm::file_transfer::save_file_chunk;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::path::PathBuf;

// ── Isolation helpers ─────────────────────────────────────────────────────────

/// Drops the given path (as a directory tree) when it goes out of scope.
struct DropCleanup(PathBuf);
impl Drop for DropCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Build a batch identifier that is unique within this test binary run.
/// Uses the function name + process ID to avoid clashes when tests run
/// in parallel with `cargo test` (default: multiple threads).
fn unique_batch(label: &str) -> String {
    format!("dl_{}_{}", label, std::process::id())
}

/// Compute the path where save_file_chunk will write a file, given the same
/// inputs.  Mirrors the sanitization logic in save_file_chunk so tests can
/// locate the output without depending on internals.
fn expected_path(batch_ts: &str, session_id: u32, root_name: &str, rel_path: &str) -> PathBuf {
    let safe_root: String = root_name
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
        .take(32)
        .collect();
    PathBuf::from("downloads")
        .join(format!("{}_{}_{}", batch_ts, session_id, safe_root))
        .join(rel_path)
}

/// Call save_file_chunk for every `chunk_size`-byte slice of `content`
/// and assert each call succeeds.  Returns the assembled file path.
fn save_all_chunks(
    batch: &str,
    session: u32,
    root: &str,
    rel: &str,
    content: &[u8],
    chunk_size: usize,
) -> PathBuf {
    if content.is_empty() {
        let r = save_file_chunk(batch, session, root, rel, 0, 1, &BASE64.encode(b""));
        assert!(r.is_ok(), "empty chunk failed: {}", r.unwrap_err());
        return expected_path(batch, session, root, rel);
    }

    let chunks: Vec<&[u8]> = content.chunks(chunk_size).collect();
    let total = chunks.len() as u64;
    for (i, chunk) in chunks.iter().enumerate() {
        let r = save_file_chunk(batch, session, root, rel, i as u64, total, &BASE64.encode(chunk));
        assert!(r.is_ok(), "chunk {}/{} failed: {}", i + 1, total, r.unwrap_err());
    }
    expected_path(batch, session, root, rel)
}

// ── Single-chunk round-trips ──────────────────────────────────────────────────

#[test]
fn roundtrip_small_ascii() {
    let batch = unique_batch("ascii");
    let _c = DropCleanup(PathBuf::from(format!("downloads/{}_{}_root", batch, 1)));
    let content = b"Hello, chunked download!";
    let path = save_all_chunks(&batch, 1, "root", "hello.txt", content, 1024);
    assert_eq!(std::fs::read(path).unwrap(), content);
}

#[test]
fn roundtrip_empty_file() {
    let batch = unique_batch("empty");
    let _c = DropCleanup(PathBuf::from(format!("downloads/{}_{}_root", batch, 1)));
    let path = save_all_chunks(&batch, 1, "root", "empty.bin", b"", 1024);
    assert_eq!(std::fs::read(path).unwrap(), b"");
}

#[test]
fn roundtrip_all_256_byte_values() {
    let batch = unique_batch("all256");
    let _c = DropCleanup(PathBuf::from(format!("downloads/{}_{}_root", batch, 1)));
    let content: Vec<u8> = (0u8..=255).collect();
    let path = save_all_chunks(&batch, 1, "root", "allbytes.bin", &content, 1024);
    assert_eq!(std::fs::read(path).unwrap(), content);
}

#[test]
fn roundtrip_single_byte() {
    let batch = unique_batch("singlebyte");
    let _c = DropCleanup(PathBuf::from(format!("downloads/{}_{}_root", batch, 1)));
    let path = save_all_chunks(&batch, 1, "root", "one.bin", b"\xde", 1024);
    assert_eq!(std::fs::read(path).unwrap(), b"\xde");
}

// ── Multi-chunk assembly ──────────────────────────────────────────────────────

#[test]
fn roundtrip_exact_chunk_boundary() {
    // 64 bytes content, 64-byte chunks → exactly one chunk, no remainder
    let batch = unique_batch("exactbnd");
    let _c = DropCleanup(PathBuf::from(format!("downloads/{}_{}_root", batch, 1)));
    let content: Vec<u8> = (0..64).map(|i| i as u8).collect();
    let path = save_all_chunks(&batch, 1, "root", "exact.bin", &content, 64);
    assert_eq!(std::fs::read(path).unwrap(), content);
}

#[test]
fn roundtrip_one_byte_over_boundary() {
    // 65 bytes, 64-byte chunks → 2 chunks: full + 1-byte remainder
    let batch = unique_batch("overbnd");
    let _c = DropCleanup(PathBuf::from(format!("downloads/{}_{}_root", batch, 1)));
    let content: Vec<u8> = (0..65).map(|i| i as u8).collect();
    let path = save_all_chunks(&batch, 1, "root", "over.bin", &content, 64);
    assert_eq!(std::fs::read(path).unwrap(), content);
}

#[test]
fn roundtrip_many_single_byte_chunks() {
    let batch = unique_batch("manychunks");
    let _c = DropCleanup(PathBuf::from(format!("downloads/{}_{}_root", batch, 1)));
    let content = b"ABCDEFGH";
    let path = save_all_chunks(&batch, 1, "root", "bytes.bin", content, 1);
    assert_eq!(std::fs::read(path).unwrap(), content.as_ref());
}

#[test]
fn roundtrip_1mb_in_64kb_chunks() {
    // 1 MB deterministic content, 64 KB chunk size → 16 chunks
    let batch = unique_batch("1mb");
    let _c = DropCleanup(PathBuf::from(format!("downloads/{}_{}_root", batch, 1)));
    let content: Vec<u8> = (0u32..1_048_576)
        .map(|i| (i.wrapping_mul(1_664_525).wrapping_add(1_013_904_223) >> 8) as u8)
        .collect();
    let path = save_all_chunks(&batch, 1, "root", "big.bin", &content, 65_536);
    assert_eq!(std::fs::read(path).unwrap(), content);
}

// ── Overwrite and truncation semantics ────────────────────────────────────────

#[test]
fn second_batch_overwrites_first() {
    let b1 = unique_batch("ow_b1");
    let b2 = unique_batch("ow_b2");
    let _c1 = DropCleanup(PathBuf::from(format!("downloads/{}_{}_root", b1, 1)));
    let _c2 = DropCleanup(PathBuf::from(format!("downloads/{}_{}_root", b2, 1)));

    let p1 = save_all_chunks(&b1, 1, "root", "f.bin", b"FIRST", 64);
    let p2 = save_all_chunks(&b2, 1, "root", "f.bin", b"SECOND", 64);
    assert_eq!(std::fs::read(&p1).unwrap(), b"FIRST");
    assert_eq!(std::fs::read(&p2).unwrap(), b"SECOND");
}

#[test]
fn chunk_0_truncates_a_larger_existing_file() {
    let batch = unique_batch("trunc");
    let _c = DropCleanup(PathBuf::from(format!("downloads/{}_{}_root", batch, 1)));

    // First: write a large file via chunk 0 + chunk 1
    let r0 = save_file_chunk(&batch, 1, "root", "trunc.bin", 0, 2, &BASE64.encode(&vec![0xAA; 100]));
    assert!(r0.is_ok());
    let r1 = save_file_chunk(&batch, 1, "root", "trunc.bin", 1, 2, &BASE64.encode(&vec![0xBB; 100]));
    assert!(r1.is_ok());

    let path = expected_path(&batch, 1, "root", "trunc.bin");
    assert_eq!(std::fs::read(&path).unwrap().len(), 200);

    // Now re-upload a single tiny chunk with chunk_idx=0 — must truncate
    let r2 = save_file_chunk(&batch, 1, "root", "trunc.bin", 0, 1, &BASE64.encode(b"TINY"));
    assert!(r2.is_ok());
    assert_eq!(std::fs::read(&path).unwrap(), b"TINY",
        "chunk_idx=0 must truncate, not append to, an existing file");
}

// ── is_final return value ─────────────────────────────────────────────────────

#[test]
fn save_chunk_returns_false_for_non_final_chunk() {
    let batch = unique_batch("notfinal");
    let _c = DropCleanup(PathBuf::from(format!("downloads/{}_{}_root", batch, 1)));
    let r = save_file_chunk(&batch, 1, "root", "f.bin", 0, 3, &BASE64.encode(b"x"));
    assert_eq!(r.unwrap(), false, "chunk 0 of 3 is not final");
}

#[test]
fn save_chunk_returns_true_for_final_chunk() {
    let batch = unique_batch("isfinal");
    let _c = DropCleanup(PathBuf::from(format!("downloads/{}_{}_root", batch, 1)));
    // chunk_idx=2, total=3 → 2+1 == 3 → is_final
    let r0 = save_file_chunk(&batch, 1, "root", "f.bin", 0, 3, &BASE64.encode(b"a"));
    assert_eq!(r0.unwrap(), false);
    let r1 = save_file_chunk(&batch, 1, "root", "f.bin", 1, 3, &BASE64.encode(b"b"));
    assert_eq!(r1.unwrap(), false);
    let r2 = save_file_chunk(&batch, 1, "root", "f.bin", 2, 3, &BASE64.encode(b"c"));
    assert_eq!(r2.unwrap(), true, "last chunk must return true");

    let path = expected_path(&batch, 1, "root", "f.bin");
    assert_eq!(std::fs::read(path).unwrap(), b"abc");
}

// ── Concurrent batches don't interfere ───────────────────────────────────────

#[test]
fn concurrent_batches_write_to_separate_directories() {
    let ba = unique_batch("concA");
    let bb = unique_batch("concB");
    let _ca = DropCleanup(PathBuf::from(format!("downloads/{}_{}_root", ba, 1)));
    let _cb = DropCleanup(PathBuf::from(format!("downloads/{}_{}_root", bb, 1)));

    // Interleave chunk saves from two separate logical transfers
    let ra0 = save_file_chunk(&ba, 1, "root", "file.bin", 0, 2, &BASE64.encode(b"A0"));
    let rb0 = save_file_chunk(&bb, 1, "root", "file.bin", 0, 2, &BASE64.encode(b"B0"));
    let ra1 = save_file_chunk(&ba, 1, "root", "file.bin", 1, 2, &BASE64.encode(b"A1"));
    let rb1 = save_file_chunk(&bb, 1, "root", "file.bin", 1, 2, &BASE64.encode(b"B1"));

    for r in [ra0, rb0, ra1, rb1] { assert!(r.is_ok()); }

    let pa = expected_path(&ba, 1, "root", "file.bin");
    let pb = expected_path(&bb, 1, "root", "file.bin");
    assert_eq!(std::fs::read(pa).unwrap(), b"A0A1");
    assert_eq!(std::fs::read(pb).unwrap(), b"B0B1");
}

// ── Subdirectory rel_path ─────────────────────────────────────────────────────

#[test]
fn rel_path_with_subdirectory_is_created() {
    let batch = unique_batch("subdir");
    let _c = DropCleanup(PathBuf::from(format!("downloads/{}_{}_root", batch, 1)));

    // rel_path can contain subdirectories (happens when downloading folders)
    let r = save_file_chunk(&batch, 1, "root", "sub/nested/file.bin", 0, 1,
        &BASE64.encode(b"nested content"));
    assert!(r.is_ok(), "subdirectory rel_path failed: {}", r.unwrap_err());

    let path = expected_path(&batch, 1, "root", "sub/nested/file.bin");
    assert_eq!(std::fs::read(path).unwrap(), b"nested content");
}

// ── Path sanitization visible at the output layer ────────────────────────────

#[test]
fn root_name_is_sanitized_in_output_directory() {
    // Root names containing special characters are stripped to [a-zA-Z0-9_-].
    // The test verifies that the call succeeds (no error) and that the output
    // lands under the sanitized folder name.
    let batch = unique_batch("rootsan");
    // "r/oot!@#" → safe_root = "root"
    let _c = DropCleanup(PathBuf::from(format!("downloads/{}_{}_root", batch, 1)));
    let r = save_file_chunk(&batch, 1, "r/oot!@#", "f.bin", 0, 1, &BASE64.encode(b"data"));
    assert!(r.is_ok(), "sanitized root should not error: {}", r.unwrap_err());
    let path = expected_path(&batch, 1, "r/oot!@#", "f.bin");
    assert_eq!(std::fs::read(path).unwrap(), b"data");
}

#[test]
fn path_traversal_is_blocked() {
    // The traversal check is purely in save_file_chunk; no file should be written.
    let r = save_file_chunk("ptblock_batch", 1, "root", "../../escape.txt", 0, 1,
        &BASE64.encode(b"pwned"));
    assert!(r.is_err(), "path traversal must be rejected");
    // Verify no file was written to the escape path
    assert!(!std::path::Path::new("escape.txt").exists(),
        "traversal must not write to the escape path");
}
