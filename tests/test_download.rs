// tests/test_download.rs - Functional integration tests for collected-file
// storage through the RCM data collection packages (SPEC §5, §8).
//
// These tests drive the same API surface that session.rs uses on receipt of
// `file:data` / `file:chunk` wire messages:
//   PackageManager::store_collected / store_collected_chunk
//
// Every test is hermetic: packages are created inside a `tempfile::TempDir`,
// never in the real downloads/ tree.
//
// Test groups:
//   - Single-shot round-trips (small files, zero-byte files, binary content)
//   - Multi-chunk assembly (exact boundary, remainder, large content)
//   - Mid-transfer .part semantics and out-of-order rejection
//   - Re-collection counter semantics (no silent overwrite)
//   - Path traversal containment
//   - Concurrent packages isolated (two targets, one base dir)

use rcm::rcm::{CollectedMeta, PackageManager};
use std::path::{Path, PathBuf};
use std::sync::Arc;

// ── Isolation helpers ─────────────────────────────────────────────────────────

/// Create (or open) a package for `hostname` inside the tempdir base.
fn pkg(base: &Path, hostname: &str) -> Arc<PackageManager> {
    PackageManager::create_or_open(base, hostname, &format!("inst-{}", hostname))
        .expect("create_or_open")
}

/// Absolute path of a collected file inside the package's downloads/ tree.
fn collected(pkg: &PackageManager, rel: &str) -> PathBuf {
    pkg.root().join("downloads").join(rel)
}

/// Absolute path of the sidecar for a collected file.
fn sidecar(pkg: &PackageManager, rel: &str) -> PathBuf {
    pkg.root()
        .join("downloads.metadata")
        .join(format!("{}.RCM.xml", rel))
}

/// Store `content` in 1-chunk-or-more pieces via store_collected_chunk,
/// mirroring the agent's chunked transfer. Returns Ok(()) when all chunks
/// were accepted; the final call must report finalization.
fn store_in_chunks(pkg: &PackageManager, path: &str, content: &[u8], chunk_size: usize) {
    if content.is_empty() {
        let fin = pkg
            .store_collected_chunk(path, 0, 1, b"", path, &CollectedMeta::default())
            .expect("empty chunk");
        assert!(fin, "single empty chunk must finalize");
        return;
    }
    let chunks: Vec<&[u8]> = content.chunks(chunk_size).collect();
    let total = chunks.len() as u64;
    for (i, chunk) in chunks.iter().enumerate() {
        let fin = pkg
            .store_collected_chunk(path, i as u64, total, chunk, path, &CollectedMeta::default())
            .unwrap_or_else(|e| panic!("chunk {}/{} failed: {}", i + 1, total, e));
        assert_eq!(fin, i as u64 + 1 == total, "finalization flag on chunk {}", i);
    }
}

/// Assert the RCM layout for a stored collected file: data under downloads/,
/// sidecar under downloads.metadata/, no leftover .part state.
fn assert_rcm_layout(pkg: &PackageManager, rel: &str, content: &[u8]) {
    let data = collected(pkg, rel);
    assert!(data.is_file(), "collected file missing: {}", data.display());
    assert_eq!(std::fs::read(&data).unwrap(), content, "content mismatch");

    let sc = sidecar(pkg, rel);
    assert!(sc.is_file(), "sidecar missing: {}", sc.display());
    let sc_xml = std::fs::read_to_string(&sc).unwrap();
    assert!(sc_xml.contains("<file version=\"1\">"), "sidecar not a file meta doc");
    assert!(sc_xml.contains("<sha256>") || sc_xml.contains("sha256"),
        "sidecar missing sha256: {}", sc_xml);

    // No transfer residue.
    let part = data.with_file_name(format!(
        "{}.part",
        data.file_name().unwrap().to_string_lossy()
    ));
    assert!(!part.exists(), ".part left behind: {}", part.display());
}

// ── Single-shot round-trips (file:data path) ─────────────────────────────────

#[test]
fn roundtrip_small_ascii() {
    let dir = tempfile::tempdir().unwrap();
    let p = pkg(dir.path(), "HOST-A");
    let content = b"Hello, RCM collection!";
    let stored = p
        .store_collected("C:/docs/hello.txt", content, &CollectedMeta::default())
        .unwrap();
    assert_eq!(stored, "downloads/C/docs/hello.txt");
    assert_rcm_layout(&p, "C/docs/hello.txt", content);
}

#[test]
fn roundtrip_empty_file() {
    let dir = tempfile::tempdir().unwrap();
    let p = pkg(dir.path(), "HOST-A");
    let stored = p
        .store_collected("/tmp/empty.bin", b"", &CollectedMeta::default())
        .unwrap();
    assert_eq!(stored, "downloads/tmp/empty.bin");
    assert_rcm_layout(&p, "tmp/empty.bin", b"");
}

#[test]
fn roundtrip_all_256_byte_values() {
    let dir = tempfile::tempdir().unwrap();
    let p = pkg(dir.path(), "HOST-A");
    let content: Vec<u8> = (0u8..=255).collect();
    p.store_collected("C:/bin/allbytes.bin", &content, &CollectedMeta::default())
        .unwrap();
    assert_rcm_layout(&p, "C/bin/allbytes.bin", &content);
}

#[test]
fn roundtrip_single_byte() {
    let dir = tempfile::tempdir().unwrap();
    let p = pkg(dir.path(), "HOST-A");
    p.store_collected("one.bin", b"\xde", &CollectedMeta::default()).unwrap();
    assert_rcm_layout(&p, "one.bin", b"\xde");
}

// ── Multi-chunk assembly (file:chunk path) ────────────────────────────────────

#[test]
fn roundtrip_exact_chunk_boundary() {
    // 64 bytes content, 64-byte chunks -> exactly one chunk, no remainder
    let dir = tempfile::tempdir().unwrap();
    let p = pkg(dir.path(), "HOST-A");
    let content: Vec<u8> = (0..64).map(|i| i as u8).collect();
    store_in_chunks(&p, "exact.bin", &content, 64);
    assert_rcm_layout(&p, "exact.bin", &content);
}

#[test]
fn roundtrip_one_byte_over_boundary() {
    // 65 bytes, 64-byte chunks -> 2 chunks: full + 1-byte remainder
    let dir = tempfile::tempdir().unwrap();
    let p = pkg(dir.path(), "HOST-A");
    let content: Vec<u8> = (0..65).map(|i| i as u8).collect();
    store_in_chunks(&p, "over.bin", &content, 64);
    assert_rcm_layout(&p, "over.bin", &content);
}

#[test]
fn roundtrip_many_single_byte_chunks() {
    let dir = tempfile::tempdir().unwrap();
    let p = pkg(dir.path(), "HOST-A");
    let content = b"ABCDEFGH";
    store_in_chunks(&p, "bytes.bin", content, 1);
    assert_rcm_layout(&p, "bytes.bin", content);
}

#[test]
fn roundtrip_1mb_in_64kb_chunks() {
    // 1 MB deterministic content, 64 KB chunk size -> 16 chunks
    let dir = tempfile::tempdir().unwrap();
    let p = pkg(dir.path(), "HOST-A");
    let content: Vec<u8> = (0u32..1_048_576)
        .map(|i| (i.wrapping_mul(1_664_525).wrapping_add(1_013_904_223) >> 8) as u8)
        .collect();
    store_in_chunks(&p, "big.bin", &content, 65_536);
    assert_rcm_layout(&p, "big.bin", &content);
}

// ── .part semantics and ordering ──────────────────────────────────────────────

#[test]
fn part_file_exists_only_mid_transfer() {
    let dir = tempfile::tempdir().unwrap();
    let p = pkg(dir.path(), "HOST-A");

    let fin = p
        .store_collected_chunk("f.bin", 0, 3, b"a", "t-f", &CollectedMeta::default())
        .unwrap();
    assert!(!fin, "chunk 0 of 3 is not final");
    let part = collected(&p, "f.bin.part");
    assert!(part.is_file(), ".part must exist mid-transfer");
    assert!(collected(&p, "f.bin.part.state").is_file(), "state file must exist");
    assert!(!collected(&p, "f.bin").exists(), "final file must not exist yet");

    assert!(!p.store_collected_chunk("f.bin", 1, 3, b"b", "t-f", &CollectedMeta::default()).unwrap());
    assert!(p.store_collected_chunk("f.bin", 2, 3, b"c", "t-f", &CollectedMeta::default()).unwrap());

    assert!(!part.exists(), ".part must be renamed away on finalize");
    assert!(!collected(&p, "f.bin.part.state").exists(), "state file removed");
    assert_rcm_layout(&p, "f.bin", b"abc");
}

#[test]
fn out_of_order_chunk_is_rejected_and_part_kept() {
    let dir = tempfile::tempdir().unwrap();
    let p = pkg(dir.path(), "HOST-A");

    p.store_collected_chunk("f.bin", 0, 3, b"a", "t-f", &CollectedMeta::default())
        .unwrap();
    let r = p.store_collected_chunk("f.bin", 2, 3, b"c", "t-f", &CollectedMeta::default());
    assert!(r.is_err(), "out-of-order chunk must be rejected");
    assert!(collected(&p, "f.bin.part").is_file(), ".part kept for resumption");

    // The transfer can still resume correctly afterwards.
    assert!(!p.store_collected_chunk("f.bin", 1, 3, b"b", "t-f", &CollectedMeta::default()).unwrap());
    assert!(p.store_collected_chunk("f.bin", 2, 3, b"c", "t-f", &CollectedMeta::default()).unwrap());
    assert_rcm_layout(&p, "f.bin", b"abc");
}

#[test]
fn chunk_indices_validated() {
    let dir = tempfile::tempdir().unwrap();
    let p = pkg(dir.path(), "HOST-A");
    assert!(p
        .store_collected_chunk("f.bin", 0, 0, b"x", "t-f", &CollectedMeta::default())
        .is_err());
    assert!(p
        .store_collected_chunk("f.bin", 5, 5, b"x", "t-f", &CollectedMeta::default())
        .is_err());
}

// ── Re-collection counter semantics (REQ-3.4.3: never overwrite) ─────────────

#[test]
fn second_collection_gets_counter_suffix_first_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let p = pkg(dir.path(), "HOST-A");

    let s1 = p.store_collected("f.bin", b"FIRST", &CollectedMeta::default()).unwrap();
    let s2 = p.store_collected("f.bin", b"SECOND", &CollectedMeta::default()).unwrap();
    assert_eq!(s1, "downloads/f.bin");
    assert_eq!(s2, "downloads/f.bin.1");
    assert_eq!(std::fs::read(collected(&p, "f.bin")).unwrap(), b"FIRST");
    assert_eq!(std::fs::read(collected(&p, "f.bin.1")).unwrap(), b"SECOND");
    assert!(sidecar(&p, "f.bin").is_file());
    assert!(sidecar(&p, "f.bin.1").is_file());
}

#[test]
fn chunk_zero_restarts_in_progress_transfer() {
    // Chunk 0 is a FRESH RESTART: the stale .part/.part.state are discarded
    // and the new transfer replaces the old one (the agent has no
    // mid-transfer resume protocol, so a re-sent chunk 0 must not
    // permanently block the file).
    let dir = tempfile::tempdir().unwrap();
    let p = pkg(dir.path(), "HOST-A");

    p.store_collected_chunk("trunc.bin", 0, 2, &[0xAA; 100], "t-tr", &CollectedMeta::default())
        .unwrap();
    // Restart at chunk 0 - accepted, stale state gone.
    assert!(!p
        .store_collected_chunk("trunc.bin", 0, 2, &[0xCC; 50], "t-tr", &CollectedMeta::default())
        .unwrap());

    // Finish the restarted transfer; content is the restarted bytes only.
    assert!(p
        .store_collected_chunk("trunc.bin", 1, 2, &[0xBB; 100], "t-tr", &CollectedMeta::default())
        .unwrap());
    let data = std::fs::read(collected(&p, "trunc.bin")).unwrap();
    assert_eq!(data.len(), 150);
    assert!(data[..50].iter().all(|&b| b == 0xCC));
    assert!(data[50..].iter().all(|&b| b == 0xBB));
    // No orphan transfer state remains.
    assert!(!collected(&p, "trunc.bin.part").exists());
    assert!(!collected(&p, "trunc.bin.part.state").exists());
}

// ── Traversal containment ─────────────────────────────────────────────────────

#[test]
fn path_traversal_is_contained_inside_package() {
    let dir = tempfile::tempdir().unwrap();
    let p = pkg(dir.path(), "HOST-A");

    // ".." components are dropped during reconstruction; the file can never
    // escape the package's downloads/ tree.
    let stored = p
        .store_collected("../../../etc/passwd", b"pwned", &CollectedMeta::default())
        .unwrap();
    assert_eq!(stored, "downloads/etc/passwd");
    let data = collected(&p, "etc/passwd");
    assert!(data.is_file());
    assert!(data.starts_with(p.root()), "must stay inside the package");
    assert!(!dir.path().join("escape.txt").exists());
    assert!(!Path::new("escape.txt").exists());
}

// ── Concurrent packages don't interfere ──────────────────────────────────────

#[test]
fn concurrent_packages_write_to_separate_roots() {
    let dir = tempfile::tempdir().unwrap();
    let pa = pkg(dir.path(), "HOST-A");
    let pb = pkg(dir.path(), "HOST-B");

    // Interleave chunk saves from two separate logical transfers.
    assert!(!pa.store_collected_chunk("file.bin", 0, 2, b"A0", "t-a", &CollectedMeta::default()).unwrap());
    assert!(!pb.store_collected_chunk("file.bin", 0, 2, b"B0", "t-b", &CollectedMeta::default()).unwrap());
    assert!(pa.store_collected_chunk("file.bin", 1, 2, b"A1", "t-a", &CollectedMeta::default()).unwrap());
    assert!(pb.store_collected_chunk("file.bin", 1, 2, b"B1", "t-b", &CollectedMeta::default()).unwrap());

    assert_eq!(std::fs::read(collected(&pa, "file.bin")).unwrap(), b"A0A1");
    assert_eq!(std::fs::read(collected(&pb, "file.bin")).unwrap(), b"B0B1");
    assert_ne!(pa.root(), pb.root(), "packages must have distinct roots");
    assert!(collected(&pa, "file.bin").starts_with(pa.root()));
    assert!(collected(&pb, "file.bin").starts_with(pb.root()));
}

// ── Subdirectory rel paths ────────────────────────────────────────────────────

#[test]
fn rel_path_with_subdirectory_is_created() {
    let dir = tempfile::tempdir().unwrap();
    let p = pkg(dir.path(), "HOST-A");
    store_in_chunks(&p, "sub/nested/file.bin", b"nested content", 1024);
    assert_rcm_layout(&p, "sub/nested/file.bin", b"nested content");
}