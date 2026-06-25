// tests/test_upload.rs — Integration tests for chunked file upload.
//
// These tests call the public `handle_file_write_chunked` function directly
// (it is `pub fn` in the `pub mod rcm::agent::handlers::files` chain) and
// verify end-to-end behaviour: base64 encode → chunk → reconstruct on disk.
//
// Structure:
//   - Helper utilities
//   - Single-chunk round-trips
//   - Multi-chunk assembly (exact boundary, remainder, large files)
//   - Idempotency and overwrite semantics
//   - Ordering sensitivity (documents expected wrong-output for out-of-order)
//   - Concurrent uploads to the same agent (different batch IDs)

use rcm::agent::handlers::files::handle_file_write_chunked;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use tempfile::TempDir;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Encode `data` as base64 and return a `file:write_chunk` command string.
fn chunk_cmd(dir: &TempDir, filename: &str, batch: &str, idx: u64, total: u64, data: &[u8]) -> String {
    let path = dir.path().join(filename).to_string_lossy().to_string();
    format!("file:write_chunk|{}|{}|{}|{}|{}", batch, path, idx, total, BASE64.encode(data))
}

fn file_path(dir: &TempDir, name: &str) -> String {
    dir.path().join(name).to_string_lossy().to_string()
}

/// Upload `content` to `filename` inside `dir` using `chunk_size`-byte pieces,
/// all with the given `batch_ts`.  Panics on any chunk error.
fn upload(dir: &TempDir, filename: &str, batch: &str, content: &[u8], chunk_size: usize) {
    if content.is_empty() {
        // Zero-byte file: one empty chunk
        let (_, err, code) = handle_file_write_chunked(&chunk_cmd(dir, filename, batch, 0, 1, b""));
        assert_eq!(code, 0, "empty upload failed: {}", err);
        return;
    }

    let chunks: Vec<&[u8]> = content.chunks(chunk_size).collect();
    let total = chunks.len() as u64;

    for (i, chunk) in chunks.iter().enumerate() {
        let (_, err, code) = handle_file_write_chunked(
            &chunk_cmd(dir, filename, batch, i as u64, total, chunk)
        );
        assert_eq!(code, 0, "chunk {}/{} failed: {}", i + 1, total, err);
    }
}

/// Read the file back and compare to expected bytes.
fn assert_file_eq(dir: &TempDir, filename: &str, expected: &[u8]) {
    let actual = std::fs::read(dir.path().join(filename))
        .expect("output file missing");
    assert_eq!(actual, expected,
        "file content mismatch: got {} bytes, expected {} bytes",
        actual.len(), expected.len());
}

// ── Single-chunk round-trips ──────────────────────────────────────────────────

#[test]
fn roundtrip_small_ascii() {
    let dir = tempfile::tempdir().unwrap();
    let content = b"Hello, chunked upload!";
    upload(&dir, "ascii.txt", "batch1", content, 1024);
    assert_file_eq(&dir, "ascii.txt", content);
}

#[test]
fn roundtrip_all_256_byte_values() {
    let dir = tempfile::tempdir().unwrap();
    let content: Vec<u8> = (0u8..=255).collect();
    upload(&dir, "binary.bin", "b256", &content, 1024);
    assert_file_eq(&dir, "binary.bin", &content);
}

#[test]
fn roundtrip_empty_file() {
    let dir = tempfile::tempdir().unwrap();
    upload(&dir, "empty.bin", "bempty", b"", 8);
    assert_file_eq(&dir, "empty.bin", b"");
}

#[test]
fn roundtrip_single_byte() {
    let dir = tempfile::tempdir().unwrap();
    upload(&dir, "one.bin", "bone", b"\xff", 1024);
    assert_file_eq(&dir, "one.bin", b"\xff");
}

// ── Multi-chunk assembly ──────────────────────────────────────────────────────

#[test]
fn roundtrip_content_exactly_one_chunk_boundary() {
    let dir = tempfile::tempdir().unwrap();
    // 32 bytes content, 32 bytes chunk → exactly 1 chunk, no remainder
    let content: Vec<u8> = (0..32u8).collect();
    upload(&dir, "exact.bin", "bexact", &content, 32);
    assert_file_eq(&dir, "exact.bin", &content);
}

#[test]
fn roundtrip_content_one_byte_over_chunk_boundary() {
    let dir = tempfile::tempdir().unwrap();
    // 33 bytes, 32-byte chunks → 2 chunks: full + 1-byte remainder
    let content: Vec<u8> = (0..33u8).collect();
    upload(&dir, "over.bin", "bover", &content, 32);
    assert_file_eq(&dir, "over.bin", &content);
}

#[test]
fn roundtrip_many_small_chunks() {
    let dir = tempfile::tempdir().unwrap();
    let content = b"ABCDEFGHIJKLMNOP"; // 16 bytes
    upload(&dir, "small.bin", "bsmall", content, 1); // 16 chunks of 1 byte each
    assert_file_eq(&dir, "small.bin", content);
}

#[test]
fn roundtrip_1mb_file_in_64kb_chunks() {
    let dir = tempfile::tempdir().unwrap();
    // 1 MB of pseudo-random-ish bytes (deterministic, no rand dependency)
    let content: Vec<u8> = (0u32..1024 * 1024)
        .map(|i| ((i as u64).wrapping_mul(6364136223846793005_u64).wrapping_add(1442695040888963407_u64) >> 24) as u8)
        .collect();
    upload(&dir, "mb.bin", "bmb", &content, 64 * 1024);
    assert_file_eq(&dir, "mb.bin", &content);
}

// ── Overwrite semantics ───────────────────────────────────────────────────────

#[test]
fn second_upload_overwrites_first() {
    let dir = tempfile::tempdir().unwrap();
    upload(&dir, "overwrite.bin", "b1", b"FIRST CONTENT", 64);
    upload(&dir, "overwrite.bin", "b2", b"SECOND", 64);
    assert_file_eq(&dir, "overwrite.bin", b"SECOND");
}

#[test]
fn chunk_0_always_truncates_regardless_of_previous_content() {
    let dir = tempfile::tempdir().unwrap();

    // Write a 100-byte file
    let large: Vec<u8> = vec![0xAA; 100];
    upload(&dir, "trunc.bin", "b_large", &large, 32);
    assert_file_eq(&dir, "trunc.bin", &large);

    // Now send a single small chunk_idx=0 — must truncate, not append
    let path = file_path(&dir, "trunc.bin");
    let cmd = format!("file:write_chunk|b_small|{}|0|1|{}", path, BASE64.encode(b"TINY"));
    let (_, err, code) = handle_file_write_chunked(&cmd);
    assert_eq!(code, 0, "err: {}", err);
    assert_eq!(std::fs::read(&path).unwrap(), b"TINY",
        "chunk_idx=0 must truncate a pre-existing larger file");
}

// ── Ordering sensitivity ──────────────────────────────────────────────────────

#[test]
fn out_of_order_delivery_fails_not_corrupts() {
    // The handler requires strict in-order delivery.  Sending a non-zero
    // chunk index when the file has not yet been initialised (chunk 0 never
    // arrived) fails immediately with an OS error rather than creating a
    // ghost file or silently writing corrupt data.
    //
    // This is a stronger guarantee than "wrong content" — the transport
    // layer must deliver in order, and deviations cause a visible, auditable
    // error rather than a silent data integrity failure.
    let dir = tempfile::tempdir().unwrap();
    let path = file_path(&dir, "ooo.bin");

    // chunk 1 arrives before chunk 0: must fail (no file to append to)
    let c1 = format!("file:write_chunk|booo|{}|1|2|{}", path, BASE64.encode(b"SECOND"));
    let (_, err1, code1) = handle_file_write_chunked(&c1);
    assert_eq!(code1, 1, "chunk 1 without chunk 0 must fail; err: {}", err1);

    // No file should have been created by the failed write
    assert!(!std::path::Path::new(&path).exists(),
        "out-of-order chunk must not leave a partial file on disk");

    // chunk 0 arriving after the failed chunk 1 still creates the file normally
    let c0 = format!("file:write_chunk|booo|{}|0|2|{}", path, BASE64.encode(b"FIRST_"));
    let (_, err0, code0) = handle_file_write_chunked(&c0);
    assert_eq!(code0, 0, "chunk 0 after failed chunk 1 must succeed; err: {}", err0);

    // Only chunk 0's content is present — the rejected chunk 1 was never written
    assert_eq!(std::fs::read(&path).unwrap(), b"FIRST_",
        "only chunk 0 content should be present; chunk 1 was rejected");
}

// ── Concurrent uploads to the same agent (different batch IDs) ───────────────

#[test]
fn two_concurrent_uploads_to_different_paths_do_not_interfere() {
    let dir = tempfile::tempdir().unwrap();

    // Interleave chunks of two separate files
    let path_a = file_path(&dir, "file_a.bin");
    let path_b = file_path(&dir, "file_b.bin");

    let a0 = format!("file:write_chunk|batchA|{}|0|2|{}", path_a, BASE64.encode(b"A1"));
    let b0 = format!("file:write_chunk|batchB|{}|0|2|{}", path_b, BASE64.encode(b"B1"));
    let a1 = format!("file:write_chunk|batchA|{}|1|2|{}", path_a, BASE64.encode(b"A2"));
    let b1 = format!("file:write_chunk|batchB|{}|1|2|{}", path_b, BASE64.encode(b"B2"));

    for cmd in &[a0, b0, a1, b1] {
        let (_, err, code) = handle_file_write_chunked(cmd);
        assert_eq!(code, 0, "err: {}", err);
    }

    assert_eq!(std::fs::read(&path_a).unwrap(), b"A1A2");
    assert_eq!(std::fs::read(&path_b).unwrap(), b"B1B2");
}

// ── Completion and progress message format ────────────────────────────────────

#[test]
fn completion_message_is_returned_on_last_chunk() {
    let dir = tempfile::tempdir().unwrap();
    let path = file_path(&dir, "msg.bin");

    // 3 chunks; last is idx=2
    for i in 0u64..3 {
        let cmd = format!("file:write_chunk|bm|{}|{}|3|{}", path, i, BASE64.encode(b"x"));
        let (msg, _, code) = handle_file_write_chunked(&cmd);
        assert_eq!(code, 0);
        if i == 2 {
            assert!(msg.contains("complete") || msg.contains("Upload"),
                "final chunk should say complete, got: {}", msg);
        } else {
            assert!(!msg.contains("complete"),
                "non-final chunk {} should not say complete: {}", i, msg);
        }
    }
}

#[test]
fn progress_message_contains_chunk_fraction() {
    let dir = tempfile::tempdir().unwrap();
    let path = file_path(&dir, "frac.bin");

    // chunk 0 of 5 → "1/5"
    let cmd = format!("file:write_chunk|bf|{}|0|5|{}", path, BASE64.encode(b"x"));
    let (msg, _, code) = handle_file_write_chunked(&cmd);
    assert_eq!(code, 0);
    assert!(msg.contains('1') && msg.contains('5'),
        "progress msg should mention 1/5, got: {}", msg);
}
