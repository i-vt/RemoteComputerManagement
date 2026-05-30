// tests/test_file_transfer.rs — File transfer and serialization tests

use rcm::file_transfer;
use std::fs;
use std::path::Path;

fn setup_test_dir(name: &str) -> String {
    let dir = format!("/tmp/rcm_test_ft_{}", name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn test_find_all_files_empty_dir() {
    let dir = setup_test_dir("empty");
    let files = file_transfer::find_all_files(&dir);
    assert!(files.is_empty());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_find_all_files_flat() {
    let dir = setup_test_dir("flat");
    fs::write(format!("{}/a.txt", dir), "aaa").unwrap();
    fs::write(format!("{}/b.txt", dir), "bbb").unwrap();

    let files = file_transfer::find_all_files(&dir);
    assert_eq!(files.len(), 2);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_find_all_files_nested() {
    let dir = setup_test_dir("nested");
    fs::create_dir_all(format!("{}/sub/deep", dir)).unwrap();
    fs::write(format!("{}/root.txt", dir), "r").unwrap();
    fs::write(format!("{}/sub/mid.txt", dir), "m").unwrap();
    fs::write(format!("{}/sub/deep/leaf.txt", dir), "l").unwrap();

    let files = file_transfer::find_all_files(&dir);
    assert_eq!(files.len(), 3);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_find_all_files_single_file() {
    let path = "/tmp/rcm_test_single_file.txt";
    fs::write(path, "content").unwrap();
    let files = file_transfer::find_all_files(path);
    assert_eq!(files.len(), 1);
    let _ = fs::remove_file(path);
}

#[test]
fn test_find_all_files_nonexistent() {
    let files = file_transfer::find_all_files("/tmp/rcm_nonexistent_dir_12345");
    assert!(files.is_empty());
}

#[test]
fn test_read_file_to_b64_roundtrip() {
    let path = "/tmp/rcm_test_b64.bin";
    let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
    fs::write(path, &data).unwrap();

    let (b64, perms) = file_transfer::read_file_to_b64(path).unwrap();
    assert!(!b64.is_empty());
    assert!(perms == "writable" || perms == "readonly");

    // Decode and verify
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    let decoded = BASE64.decode(&b64).unwrap();
    assert_eq!(decoded, data);

    let _ = fs::remove_file(path);
}

#[test]
fn test_read_file_nonexistent() {
    let result = file_transfer::read_file_to_b64("/tmp/rcm_no_such_file.bin");
    assert!(result.is_err());
}

#[test]
fn test_write_file_simple() {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    let path = "/tmp/rcm_test_write_simple.txt";
    let content = b"Hello, World!";
    let b64 = BASE64.encode(content);

    file_transfer::write_file_simple(path, &b64).unwrap();
    let read_back = fs::read(path).unwrap();
    assert_eq!(read_back, content);

    let _ = fs::remove_file(path);
}

#[test]
fn test_write_file_creates_parent_dirs() {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    let path = "/tmp/rcm_test_nested_write/sub/dir/file.txt";
    let b64 = BASE64.encode(b"nested");

    file_transfer::write_file_simple(path, &b64).unwrap();
    assert!(Path::new(path).exists());

    let _ = fs::remove_dir_all("/tmp/rcm_test_nested_write");
}

#[test]
fn test_recursive_report_serialization() {
    let report = file_transfer::RecursiveReport {
        root_path: "/test".into(),
        total_files_found: 10,
        total_success: 8,
        failed_downloads: vec![
            ("file1.txt".into(), "permission denied".into()),
            ("file2.txt".into(), "too large".into()),
        ],
    };
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("\"total_success\":8"));
    assert!(json.contains("permission denied"));

    let parsed: file_transfer::RecursiveReport = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.total_files_found, 10);
    assert_eq!(parsed.failed_downloads.len(), 2);
}
