// tests/test_w1_security.rs
//
// Coverage for the wave-1 server/API hardening batch:
//   - streaming_zip: symlinks inside a zipped tree are never followed
//   - RBAC role helpers: hierarchy matrix via the public API
//
// Handler-level role gates (viewer -> 403 on loot/IOC/RCM/proxy mutations)
// are exercised end-to-end by tests/docker/scripts/test_02_rbac.sh; the
// tests here pin the pieces that can be verified without a live server.

use rcm::api::middleware::{role_at_least, role_rank};
use rcm::streaming_zip::write_zip_directory;
use std::io::Cursor;
use tempfile::TempDir;
use zip::ZipArchive;

#[test]
fn role_hierarchy_is_total_order() {
    assert!(role_rank("admin") > role_rank("operator"));
    assert!(role_rank("operator") > role_rank("viewer"));
    assert!(role_at_least("admin", "operator"));
    assert!(role_at_least("operator", "viewer"));
    assert!(!role_at_least("viewer", "operator"));
    // Unknown roles rank as viewer: enough for read, never for execute.
    assert!(role_at_least("bogus-role", "viewer"));
    assert!(!role_at_least("bogus-role", "operator"));
}

#[cfg(unix)]
#[test]
fn zip_walk_never_follows_symlinks() {
    let dir = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    std::fs::write(outside.path().join("secret.txt"), b"classified").unwrap();

    let loot = dir.path().join("loot");
    std::fs::create_dir(&loot).unwrap();
    std::fs::write(loot.join("ok.txt"), b"fine").unwrap();
    // A file symlink and a directory symlink planted inside the tree.
    std::os::unix::fs::symlink(outside.path().join("secret.txt"), loot.join("linked.txt")).unwrap();
    std::os::unix::fs::symlink(outside.path(), loot.join("linked_dir")).unwrap();

    let mut buf = Vec::new();
    write_zip_directory(&mut buf, dir.path(), dir.path()).expect("zip should succeed");

    let mut zip = ZipArchive::new(Cursor::new(buf)).expect("valid zip");
    let mut names = Vec::new();
    for i in 0..zip.len() {
        names.push(zip.by_index(i).unwrap().name().to_string());
    }
    assert!(names.iter().any(|n| n.ends_with("loot/ok.txt")), "names: {:?}", names);
    assert!(!names.iter().any(|n| n.contains("linked")), "symlinks must be skipped: {:?}", names);
    // The escaping content must not appear anywhere in the archive.
    let mut whole = Vec::new();
    for i in 0..zip.len() {
        use std::io::Read;
        let mut f = zip.by_index(i).unwrap();
        let mut content = Vec::new();
        f.read_to_end(&mut content).unwrap();
        whole.extend_from_slice(&content);
    }
    assert!(!whole.windows(b"classified".len()).any(|w| w == b"classified"));
}
