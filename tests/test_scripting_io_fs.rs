// tests/test_scripting_io_fs.rs
//
// Tests for scripting/{io,fs,system,sysinfo}.rs
//
// All filesystem tests use TempDir so the host is left unchanged.

use rcm::agent::scripting::ExtensionManager;
use tempfile::TempDir;

fn run(script: &str) -> String {
    ExtensionManager::new().run_script(script, vec![])
}

fn p(dir: &TempDir, name: &str) -> String {
    dir.path().join(name).to_string_lossy().to_string().replace('\\', "\\\\")
}

// ─────────────────────────────────────────────────────────────────────────────
// scripting/fs.rs  — text read / write / ls
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn fs_write_and_read_round_trip() {
    let dir = TempDir::new().unwrap();
    let path = p(&dir, "hello.txt");
    run(&format!(r#"internal_write("{}", "hello world")"#, path));
    let content = run(&format!(r#"internal_read("{}")"#, path));
    assert_eq!(content, "hello world");
}

#[test]
fn fs_read_missing_file_returns_error() {
    let result = run(r#"internal_read("/no/such/file/rcm_test_xyz.txt")"#);
    assert!(result.starts_with("Error"), "missing file read should error: {}", result);
}

#[test]
fn fs_write_creates_intermediate_result_ok() {
    let dir = TempDir::new().unwrap();
    let path = p(&dir, "test_write.txt");
    let result = run(&format!(r#"internal_write("{}", "data")"#, path));
    assert_eq!(result, "Success");
}

#[test]
fn fs_ls_returns_json_array_with_correct_fields() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.txt"), "x").unwrap();
    std::fs::create_dir(dir.path().join("subdir")).unwrap();
    let dir_path = dir.path().to_string_lossy().to_string().replace('\\', "\\\\");
    let json = run(&format!(r#"internal_ls("{}")"#, dir_path));
    let entries: serde_json::Value = serde_json::from_str(&json)
        .expect("internal_ls should return valid JSON");
    assert!(entries.is_array(), "ls should return a JSON array");
    let arr = entries.as_array().unwrap();
    assert!(arr.len() >= 2, "should see at least the file and subdir");
    for entry in arr {
        assert!(entry["name"].is_string(), "each entry must have a name field");
        assert!(entry["is_dir"].is_boolean(), "each entry must have is_dir");
    }
}

#[test]
fn fs_ls_directories_sorted_before_files() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("z_file.txt"), "").unwrap();
    std::fs::create_dir(dir.path().join("a_dir")).unwrap();
    let dir_path = dir.path().to_string_lossy().to_string().replace('\\', "\\\\");
    let json = run(&format!(r#"internal_ls("{}")"#, dir_path));
    let entries: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
    assert!(entries[0]["is_dir"].as_bool().unwrap_or(false), "directories should sort first");
}

#[test]
fn fs_self_path_is_nonempty() {
    let result = run(r#"internal_self_path()"#);
    assert!(!result.is_empty(), "self_path should return a non-empty string");
}

// ─────────────────────────────────────────────────────────────────────────────
// scripting/io.rs  — binary read / write / copy / move / delete / mkdir / stat
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn io_write_bytes_and_read_bytes_round_trip() {
    let dir = TempDir::new().unwrap();
    let path = p(&dir, "bin.dat");
    let hex_in = "deadbeef0102030405";
    run(&format!(r#"internal_write_bytes("{}", "{}")"#, path, hex_in));
    let hex_out = run(&format!(r#"internal_read_bytes("{}")"#, path));
    assert_eq!(hex_out, hex_in, "binary round-trip should match exactly");
}

#[test]
fn io_read_bytes_text_file_returns_hex() {
    let dir = TempDir::new().unwrap();
    let path = p(&dir, "ascii.txt");
    std::fs::write(dir.path().join("ascii.txt"), "A").unwrap();
    let result = run(&format!(r#"internal_read_bytes("{}")"#, path));
    assert_eq!(result, "41", "'A' in hex is 41");
}

#[test]
fn io_copy_creates_identical_file() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("src.txt"), "content").unwrap();
    let src = p(&dir, "src.txt");
    let dst = p(&dir, "dst.txt");
    let result = run(&format!(r#"internal_copy("{}", "{}")"#, src, dst));
    assert!(result.contains("Copied"), "copy should report success: {}", result);
    assert!(dir.path().join("src.txt").exists(), "src should still exist after copy");
    assert_eq!(
        std::fs::read_to_string(dir.path().join("dst.txt")).unwrap(),
        "content"
    );
}

#[test]
fn io_move_removes_source() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("mv_src.txt"), "moved").unwrap();
    let src = p(&dir, "mv_src.txt");
    let dst = p(&dir, "mv_dst.txt");
    run(&format!(r#"internal_move("{}", "{}")"#, src, dst));
    assert!(!dir.path().join("mv_src.txt").exists(), "source should be gone after move");
    assert_eq!(
        std::fs::read_to_string(dir.path().join("mv_dst.txt")).unwrap(),
        "moved"
    );
}

#[test]
fn io_delete_file() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("del.txt"), "bye").unwrap();
    let path = p(&dir, "del.txt");
    let result = run(&format!(r#"internal_delete("{}")"#, path));
    assert_eq!(result, "Deleted");
    assert!(!dir.path().join("del.txt").exists());
}

#[test]
fn io_delete_directory_tree() {
    let dir = TempDir::new().unwrap();
    let sub = dir.path().join("subtree");
    std::fs::create_dir_all(sub.join("nested")).unwrap();
    std::fs::write(sub.join("nested").join("file.txt"), "x").unwrap();
    let path = sub.to_string_lossy().to_string().replace('\\', "\\\\");
    let result = run(&format!(r#"internal_delete("{}")"#, path));
    assert_eq!(result, "Deleted");
    assert!(!sub.exists(), "directory tree should be gone");
}

#[test]
fn io_mkdir_creates_nested_dirs() {
    let dir = TempDir::new().unwrap();
    let nested = dir.path().join("a").join("b").join("c")
        .to_string_lossy().to_string().replace('\\', "\\\\");
    let result = run(&format!(r#"internal_mkdir("{}")"#, nested));
    assert_eq!(result, "Created");
    assert!(dir.path().join("a").join("b").join("c").exists());
}

#[test]
fn io_exists_true_and_false() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("real.txt"), "").unwrap();
    let real   = p(&dir, "real.txt");
    let absent = p(&dir, "no_such_file_xyz.txt");
    let t = run(&format!(r#"internal_exists("{}")"#, real));
    let f = run(&format!(r#"internal_exists("{}")"#, absent));
    assert_eq!(t.trim(), "true",  "existing file should return true");
    assert_eq!(f.trim(), "false", "missing file should return false");
}

#[test]
fn io_stat_fields_present_and_correct() {
    let dir = TempDir::new().unwrap();
    let content = "hello stat";
    std::fs::write(dir.path().join("stat.txt"), content).unwrap();
    let path = p(&dir, "stat.txt");
    let json = run(&format!(r#"internal_stat("{}")"#, path));
    let v: serde_json::Value = serde_json::from_str(&json)
        .expect("internal_stat should return valid JSON");
    assert_eq!(v["is_file"].as_bool(), Some(true));
    assert_eq!(v["is_dir"].as_bool(), Some(false));
    assert_eq!(v["size"].as_u64(), Some(content.len() as u64));
}

#[test]
fn io_file_size_matches_content_length() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("sz.txt"), "12345").unwrap();
    let path = p(&dir, "sz.txt");
    let result = run(&format!(r#"internal_file_size("{}")"#, path));
    let size: i64 = result.parse().expect("file_size should return an integer: {result}");
    assert_eq!(size, 5);
}

#[test]
fn io_file_size_missing_file_returns_minus_one() {
    let result = run(r#"internal_file_size("/no/such/file_xyz_rcm.txt")"#);
    assert_eq!(result.trim(), "-1");
}

// ─────────────────────────────────────────────────────────────────────────────
// scripting/system.rs  — env, exec_os, procs, sleep
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn system_env_path_is_nonempty() {
    let result = run(r#"internal_env("PATH")"#);
    assert!(!result.is_empty(), "PATH should not be empty");
    assert_ne!(result, "Not Found");
}

#[test]
fn system_env_missing_var_returns_not_found() {
    let result = run(r#"internal_env("THIS_VAR_DEFINITELY_DOES_NOT_EXIST_RCM_XYZ")"#);
    assert_eq!(result, "Not Found");
}

#[test]
fn system_exec_os_echo() {
    #[cfg(target_os = "windows")]
    let script = r#"exec_os("echo hello")"#;
    #[cfg(not(target_os = "windows"))]
    let script = r#"exec_os("echo hello")"#;
    let result = run(script);
    assert!(result.trim().contains("hello"), "exec_os echo should return 'hello': {}", result);
}

#[test]
fn system_exec_os_timeout_fires() {
    let start = std::time::Instant::now();
    run(r#"exec_os_timeout("sleep 10", 1)"#);
    assert!(
        start.elapsed().as_secs() < 8,
        "timeout should fire well before the 10s sleep completes"
    );
}

#[test]
fn system_procs_contains_test_runner_pid() {
    let pid = std::process::id().to_string();
    let result = run(r#"internal_procs()"#);
    assert!(
        result.contains(&pid),
        "process list should contain this test's PID ({}): {}", pid, &result[..200.min(result.len())]
    );
}

#[test]
fn system_sleep_blocks_for_minimum_duration() {
    let start = std::time::Instant::now();
    run(r#"internal_sleep(200)"#);
    assert!(
        start.elapsed().as_millis() >= 150,
        "sleep(200ms) should block for at least 150ms"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// scripting/sysinfo.rs  — hostname, username, interfaces, uptime, disk
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn sysinfo_hostname_is_nonempty() {
    let h = run(r#"internal_hostname()"#);
    assert!(!h.is_empty(), "hostname should not be empty");
    assert!(!h.starts_with("Error"), "hostname should not error: {}", h);
}

#[test]
fn sysinfo_hostname_matches_sys_info() {
    let expected = sys_info::hostname().unwrap_or_default();
    if expected.is_empty() { return; } // skip if sys_info fails
    let result = run(r#"internal_hostname()"#);
    assert_eq!(result, expected);
}

#[test]
fn sysinfo_username_is_nonempty() {
    let u = run(r#"internal_username()"#);
    assert!(!u.is_empty(), "username should not be empty");
    assert!(!u.starts_with("Error"), "username should not error: {}", u);
}

#[test]
fn sysinfo_network_interfaces_contains_loopback() {
    let json = run(r#"internal_network_interfaces()"#);
    assert!(!json.starts_with("Error"), "network_interfaces should not error: {}", json);
    let v: serde_json::Value = serde_json::from_str(&json)
        .expect("network_interfaces should return JSON");
    assert!(v.is_array(), "should be a JSON array");
    // Some Docker environments enumerate no interfaces — skip rather than fail.
    let ifaces = v.as_array().unwrap();
    if ifaces.is_empty() { eprintln!("[SKIP] no network interfaces enumerated"); return; }
    // Loopback is present on every OS that exposes interfaces.
    let has_loopback = ifaces.iter().any(|iface| {
        iface["name"].as_str().map(|n|
            n.contains("lo") || n.contains("Loopback") || n.contains("loop")
        ).unwrap_or(false)
    });
    assert!(has_loopback, "loopback interface should appear in list: {}", json);
}

#[test]
fn sysinfo_uptime_is_positive() {
    let result = run(r#"internal_uptime()"#);
    let uptime: i64 = result.parse().expect("uptime should be an integer: {result}");
    assert!(uptime > 0, "uptime should be positive: {}", uptime);
}

#[test]
fn sysinfo_disk_info_valid_json() {
    let json = run(r#"internal_disk_info()"#);
    assert!(!json.starts_with("Error"), "disk_info should not error: {}", json);
    let v: serde_json::Value = serde_json::from_str(&json)
        .expect("disk_info should return JSON");
    let total = v["total_kb"].as_u64().unwrap_or(0);
    assert!(total > 0, "total_kb should be positive: {}", json);
}

#[test]
fn sysinfo_sysinfo_json_has_expected_keys() {
    let json = run(r#"internal_sysinfo_json()"#);
    let v: serde_json::Value = serde_json::from_str(&json)
        .expect("sysinfo_json should return JSON");
    for key in &["hostname", "os_type", "os_release", "cpu_num", "mem_total_kb"] {
        assert!(v.get(key).is_some(), "sysinfo_json should contain key '{}': {}", key, json);
    }
}
