// tests/test_streaming_zip.rs
//
// Tests for src/streaming_zip.rs — write_zip_directory().
//
// All tests run in TempDir so the host filesystem is unchanged.
// The produced ZIP bytes are verified using the `zip` crate (already
// in Cargo.toml), which constitutes a true round-trip.

use rcm::streaming_zip::write_zip_directory;
use std::io::Cursor;
use tempfile::TempDir;
use zip::ZipArchive;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Write a directory tree and stream it through write_zip_directory.
/// Returns the raw ZIP bytes.
fn zip_dir(dir: &TempDir) -> Vec<u8> {
    let mut buf = Vec::new();
    write_zip_directory(&mut buf, dir.path(), dir.path())
        .expect("write_zip_directory should not fail");
    buf
}

/// Open the produced bytes as a ZipArchive (panics on invalid ZIP).
fn open_zip(bytes: Vec<u8>) -> ZipArchive<Cursor<Vec<u8>>> {
    ZipArchive::new(Cursor::new(bytes))
        .expect("produced bytes should be a valid ZIP archive")
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn zip_empty_directory_produces_valid_archive() {
    let dir = TempDir::new().unwrap();
    let bytes = zip_dir(&dir);
    assert!(!bytes.is_empty(), "even an empty-dir archive should have non-zero bytes");
    // Must be parseable as a ZIP.
    let _ = open_zip(bytes);
}

#[test]
fn zip_single_file_is_readable_with_correct_content() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("hello.txt"), b"hello world").unwrap();
    let mut archive = open_zip(zip_dir(&dir));
    assert_eq!(archive.len(), 1, "archive should contain exactly one entry");
    let mut entry = archive.by_index(0).unwrap();
    assert!(entry.name().contains("hello.txt"),
        "entry name should contain 'hello.txt': {}", entry.name());
    let mut content = Vec::new();
    std::io::copy(&mut entry, &mut content).unwrap();
    assert_eq!(content, b"hello world");
}

#[test]
fn zip_multiple_files_all_present() {
    let dir = TempDir::new().unwrap();
    let names = ["alpha.txt", "beta.bin", "gamma.rs"];
    for (i, name) in names.iter().enumerate() {
        std::fs::write(dir.path().join(name), format!("content_{}", i).as_bytes()).unwrap();
    }
    let mut archive = open_zip(zip_dir(&dir));
    assert_eq!(archive.len(), 3, "archive should contain three entries");
    let mut found: std::collections::HashSet<String> = Default::default();
    for i in 0..archive.len() {
        let entry = archive.by_index(i).unwrap();
        found.insert(entry.name().to_string());
    }
    for name in &names {
        assert!(found.iter().any(|n| n.contains(name)),
            "expected to find '{}' in archive: {:?}", name, found);
    }
}

#[test]
fn zip_binary_file_content_preserved_exactly() {
    let dir = TempDir::new().unwrap();
    let binary_data: Vec<u8> = (0u8..=255).collect();
    std::fs::write(dir.path().join("binary.bin"), &binary_data).unwrap();
    let mut archive = open_zip(zip_dir(&dir));
    let mut entry = archive.by_index(0).unwrap();
    let mut content = Vec::new();
    std::io::copy(&mut entry, &mut content).unwrap();
    assert_eq!(content, binary_data, "binary data should be preserved byte-for-byte");
}

#[test]
fn zip_nested_directory_structure_preserved() {
    let dir = TempDir::new().unwrap();
    let sub = dir.path().join("sub");
    let deep = sub.join("deep");
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::write(dir.path().join("root.txt"), b"root").unwrap();
    std::fs::write(sub.join("mid.txt"), b"mid").unwrap();
    std::fs::write(deep.join("leaf.txt"), b"leaf").unwrap();

    let bytes = zip_dir(&dir);
    let mut archive = open_zip(bytes);

    let mut names: Vec<String> = (0..archive.len())
        .map(|i| archive.by_index(i).unwrap().name().to_string())
        .collect();
    names.sort();

    assert!(names.iter().any(|n| n.contains("root.txt")), "root.txt missing: {:?}", names);
    assert!(names.iter().any(|n| n.contains("mid.txt")), "mid.txt missing: {:?}", names);
    assert!(names.iter().any(|n| n.contains("leaf.txt")), "leaf.txt missing: {:?}", names);
}

#[test]
fn zip_large_file_produces_correct_content() {
    let dir = TempDir::new().unwrap();
    let large: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
    std::fs::write(dir.path().join("large.bin"), &large).unwrap();

    let mut archive = open_zip(zip_dir(&dir));
    let mut entry = archive.by_index(0).unwrap();
    let mut content = Vec::new();
    std::io::copy(&mut entry, &mut content).unwrap();
    assert_eq!(content.len(), large.len(),
        "large file length should be preserved: got {} expected {}", content.len(), large.len());
    assert_eq!(content, large, "large file content should be byte-identical");
}

#[test]
fn zip_output_bytes_start_with_local_file_header_signature() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("f.txt"), b"x").unwrap();
    let bytes = zip_dir(&dir);
    // Local file header signature: PK\x03\x04
    assert!(bytes.len() >= 4, "archive should be at least 4 bytes");
    assert_eq!(&bytes[0..4], b"PK\x03\x04",
        "first 4 bytes should be the local file header magic: {:?}", &bytes[0..4]);
}

#[test]
fn zip_empty_file_is_preserved() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("empty.txt"), b"").unwrap();
    let mut archive = open_zip(zip_dir(&dir));
    let mut entry = archive.by_index(0).unwrap();
    let mut content = Vec::new();
    std::io::copy(&mut entry, &mut content).unwrap();
    assert!(content.is_empty(), "empty file should produce empty entry content");
}

#[test]
fn zip_output_to_cursor_matches_output_to_vec() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("match.txt"), b"same").unwrap();

    let mut vec_out = Vec::new();
    write_zip_directory(&mut vec_out, dir.path(), dir.path()).unwrap();

    let mut cursor_out = Cursor::new(Vec::new());
    write_zip_directory(&mut cursor_out, dir.path(), dir.path()).unwrap();

    assert_eq!(vec_out.len(), cursor_out.get_ref().len(),
        "output to Vec and output to Cursor should produce the same number of bytes");
}
