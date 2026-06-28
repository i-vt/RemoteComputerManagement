// tests/test_scripting_search_state.rs
//
// Tests for scripting/{search,state,loader,credential}.rs
// All filesystem tests use TempDir for isolation.

use rcm::agent::scripting::ExtensionManager;
use tempfile::TempDir;

fn run(script: &str) -> String {
    ExtensionManager::new().run_script(script, vec![])
}

fn run_on(em: &mut ExtensionManager, script: &str) -> String {
    em.run_script(script, vec![])
}

fn p(dir: &TempDir, name: &str) -> String {
    dir.path().join(name).to_string_lossy().to_string().replace('\\', "\\\\")
}

// ─────────────────────────────────────────────────────────────────────────────
// scripting/search.rs  — grep
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn grep_finds_match_in_single_file() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("data.txt"), "foo bar\nbaz qux\nfoo again\n").unwrap();
    let path = p(&dir, "data.txt");
    let json = run(&format!(r#"internal_grep("foo", "{}", false)"#, path));
    let matches: serde_json::Value = serde_json::from_str(&json)
        .expect("grep should return JSON");
    assert_eq!(matches.as_array().unwrap().len(), 2, "should find two 'foo' lines: {}", json);
    assert_eq!(matches[0]["line"].as_i64(), Some(1));
    assert_eq!(matches[1]["line"].as_i64(), Some(3));
}

#[test]
fn grep_no_matches_returns_empty_array() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("empty_matches.txt"), "hello world\n").unwrap();
    let path = p(&dir, "empty_matches.txt");
    let json = run(&format!(r#"internal_grep("ZZZNOMATCH", "{}", false)"#, path));
    assert_eq!(json.trim(), "[]");
}

#[test]
fn grep_recursive_finds_nested_matches() {
    let dir = TempDir::new().unwrap();
    let sub = dir.path().join("sub");
    std::fs::create_dir(&sub).unwrap();
    std::fs::write(dir.path().join("root.txt"), "secret_token=abc\n").unwrap();
    std::fs::write(sub.join("nested.txt"), "secret_token=xyz\n").unwrap();
    let root = dir.path().to_string_lossy().to_string().replace('\\', "\\\\");
    let json = run(&format!(r#"internal_grep("secret_token", "{}", true)"#, root));
    let matches: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(matches.as_array().unwrap().len(), 2,
        "recursive grep should find both files: {}", json);
}

#[test]
fn grep_invalid_regex_returns_error() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("g.txt"), "x").unwrap();
    let path = p(&dir, "g.txt");
    let result = run(&format!(r#"internal_grep("[invalid", "{}", false)"#, path));
    assert!(result.starts_with("Error"), "invalid regex should error: {}", result);
}

// ─────────────────────────────────────────────────────────────────────────────
// scripting/search.rs  — find_files
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn find_files_glob_matches_by_extension() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.rs"), "").unwrap();
    std::fs::write(dir.path().join("b.rs"), "").unwrap();
    std::fs::write(dir.path().join("c.txt"), "").unwrap();
    let root = dir.path().to_string_lossy().to_string().replace('\\', "\\\\");
    let json = run(&format!(r#"internal_find_files("{}", "*.rs", 1)"#, root));
    let files: serde_json::Value = serde_json::from_str(&json).unwrap();
    let arr = files.as_array().unwrap();
    assert_eq!(arr.len(), 2, "should find exactly two .rs files: {}", json);
    for f in arr {
        assert!(f.as_str().unwrap().ends_with(".rs"), "should only match .rs: {}", f);
    }
}

#[test]
fn find_files_depth_limit_respected() {
    let dir = TempDir::new().unwrap();
    let deep = dir.path().join("a").join("b").join("c");
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::write(deep.join("deep.txt"), "").unwrap();
    std::fs::write(dir.path().join("shallow.txt"), "").unwrap();
    let root = dir.path().to_string_lossy().to_string().replace('\\', "\\\\");
    let json = run(&format!(r#"internal_find_files("{}", "*.txt", 1)"#, root));
    let files: serde_json::Value = serde_json::from_str(&json).unwrap();
    let arr = files.as_array().unwrap();
    assert_eq!(arr.len(), 1, "depth=1 should only find shallow.txt: {}", json);
}

// ─────────────────────────────────────────────────────────────────────────────
// scripting/search.rs  — regex_match, regex_findall
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn regex_match_true_for_digit_in_string() {
    let result = run(r#"internal_regex_match("\\d+", "abc123def")"#);
    assert_eq!(result.trim(), "true");
}

#[test]
fn regex_match_false_when_no_match() {
    let result = run(r#"internal_regex_match("\\d+", "no digits here")"#);
    assert_eq!(result.trim(), "false");
}

#[test]
fn regex_match_invalid_pattern_returns_false() {
    let result = run(r#"internal_regex_match("[z-a]", "test")"#);
    assert_eq!(result.trim(), "false", "invalid regex should return false (not panic)");
}

#[test]
fn regex_findall_extracts_all_matches() {
    let json = run(r#"internal_regex_findall("\\d+", "a1b22c333")"#);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0].as_str(), Some("1"));
    assert_eq!(arr[1].as_str(), Some("22"));
    assert_eq!(arr[2].as_str(), Some("333"));
}

#[test]
fn regex_findall_no_match_returns_empty_array() {
    let json = run(r#"internal_regex_findall("\\d+", "no numbers")"#);
    assert_eq!(json.trim(), "[]");
}

// ─────────────────────────────────────────────────────────────────────────────
// scripting/search.rs  — json_get
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn json_get_top_level_key() {
    let result = run(r#"internal_json_get("{\"name\": \"alice\"}", "name")"#);
    assert_eq!(result, "alice");
}

#[test]
fn json_get_nested_key() {
    let result = run(r#"internal_json_get("{\"a\": {\"b\": 42}}", "a.b")"#);
    assert_eq!(result, "42");
}

#[test]
fn json_get_array_index() {
    let result = run(r#"internal_json_get("{\"x\": [10, 20, 30]}", "x.1")"#);
    assert_eq!(result, "20");
}

#[test]
fn json_get_missing_path_returns_null() {
    let result = run(r#"internal_json_get("{\"a\": 1}", "b.c.d")"#);
    assert_eq!(result, "null");
}

#[test]
fn json_get_invalid_json_returns_error() {
    let result = run(r#"internal_json_get("not json", "key")"#);
    assert!(result.starts_with("Error"), "invalid JSON should error: {}", result);
}

// ─────────────────────────────────────────────────────────────────────────────
// scripting/state.rs  — in-session KV store
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn state_set_and_get_basic() {
    let mut em = ExtensionManager::new();
    run_on(&mut em, r#"internal_state_set("mykey", "myval")"#);
    let val = run_on(&mut em, r#"internal_state_get("mykey")"#);
    assert_eq!(val, "myval");
}

#[test]
fn state_get_missing_key_returns_empty() {
    let mut em = ExtensionManager::new();
    let val = run_on(&mut em, r#"internal_state_get("no_such_key_xyz")"#);
    assert_eq!(val, "");
}

#[test]
fn state_overwrite_existing_key() {
    let mut em = ExtensionManager::new();
    run_on(&mut em, r#"internal_state_set("k", "first")"#);
    run_on(&mut em, r#"internal_state_set("k", "second")"#);
    let val = run_on(&mut em, r#"internal_state_get("k")"#);
    assert_eq!(val, "second");
}

#[test]
fn state_delete_removes_key() {
    let mut em = ExtensionManager::new();
    run_on(&mut em, r#"internal_state_set("del_me", "gone")"#);
    let del_result = run_on(&mut em, r#"internal_state_delete("del_me")"#);
    assert_eq!(del_result, "Deleted");
    assert_eq!(run_on(&mut em, r#"internal_state_get("del_me")"#), "");
}

#[test]
fn state_delete_missing_key() {
    let mut em = ExtensionManager::new();
    let result = run_on(&mut em, r#"internal_state_delete("nonexistent_rcm_xyz")"#);
    assert_eq!(result, "Not found");
}

#[test]
fn state_keys_lists_all_set_keys() {
    let mut em = ExtensionManager::new();
    run_on(&mut em, r#"internal_state_set("alpha", "1")"#);
    run_on(&mut em, r#"internal_state_set("beta", "2")"#);
    run_on(&mut em, r#"internal_state_set("gamma", "3")"#);
    let keys_json = run_on(&mut em, r#"internal_state_keys()"#);
    let keys: serde_json::Value = serde_json::from_str(&keys_json).unwrap();
    let arr = keys.as_array().unwrap();
    assert!(arr.len() >= 3, "should have at least 3 keys: {}", keys_json);
    let key_strs: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
    assert!(key_strs.contains(&"alpha"));
    assert!(key_strs.contains(&"beta"));
    assert!(key_strs.contains(&"gamma"));
}

#[test]
fn state_clear_removes_all_keys() {
    let mut em = ExtensionManager::new();
    run_on(&mut em, r#"internal_state_set("a", "1")"#);
    run_on(&mut em, r#"internal_state_set("b", "2")"#);
    let clear_result = run_on(&mut em, r#"internal_state_clear()"#);
    assert_eq!(clear_result, "Cleared");
    let keys_json = run_on(&mut em, r#"internal_state_keys()"#);
    assert_eq!(keys_json.trim(), "[]");
}

#[test]
fn state_persists_across_multiple_run_script_calls() {
    let mut em = ExtensionManager::new();
    // Set two different keys in separate calls.
    run_on(&mut em, r#"internal_state_set("k1", "hello")"#);
    run_on(&mut em, r#"internal_state_set("k2", "world")"#);
    // Overwrite k1 in a third call.
    run_on(&mut em, r#"internal_state_set("k1", "updated")"#);
    // Both keys must be visible in a fourth call.
    let v1 = run_on(&mut em, r#"internal_state_get("k1")"#);
    let v2 = run_on(&mut em, r#"internal_state_get("k2")"#);
    assert_eq!(v1, "updated", "k1 should reflect latest write");
    assert_eq!(v2, "world",   "k2 should persist from earlier call");
}

// ─────────────────────────────────────────────────────────────────────────────
// scripting/loader.rs  — exec_script, load_script
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn loader_exec_script_evaluates_rhai() {
    let result = run(r#"internal_exec_script("let x = 40 + 2; x.to_string()")"#);
    assert_eq!(result.trim(), "42");
}

#[test]
fn loader_exec_script_invalid_rhai_returns_exception_string() {
    let result = run(r#"internal_exec_script("this is not valid rhai !!!")"#);
    assert!(
        result.starts_with("[Script Exception]"),
        "invalid RHAI should return Script Exception: {}", result
    );
}

#[test]
fn loader_exec_script_has_isolated_scope() {
    // Variable set in child script should not be visible in parent.
    let mut em = ExtensionManager::new();
    run_on(&mut em, r#"internal_exec_script("let secret = 999")"#);
    let result = run_on(&mut em, r#"
        if is_def_var("secret") { "leaked" } else { "isolated" }
    "#);
    assert_eq!(result.trim(), "isolated", "child exec_script scope should not leak");
}

#[test]
fn loader_exec_script_can_call_rhai_builtins() {
    let result = run(r#"internal_exec_script("(6 * 7).to_string()")"#);
    assert_eq!(result.trim(), "42");
}

// ─────────────────────────────────────────────────────────────────────────────
// scripting/credential.rs  — file discovery helpers with TempDir mock HOME
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn credential_ssh_keys_finds_rsa_key() {
    let dir = TempDir::new().unwrap();
    let ssh = dir.path().join(".ssh");
    std::fs::create_dir(&ssh).unwrap();
    std::fs::write(ssh.join("id_rsa"), "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n").unwrap();
    std::fs::write(ssh.join("known_hosts"), "github.com ...").unwrap(); // not a key
    let ssh_str = ssh.to_string_lossy().to_string().replace('\\', "\\\\");
    let json = run(&format!(r#"internal_ssh_keys("{}")"#, ssh_str));
    let v: serde_json::Value = serde_json::from_str(&json)
        .expect("ssh_keys should return JSON: {json}");
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1, "should find exactly one private key: {}", json);
    assert_eq!(arr[0]["key_type"].as_str(), Some("rsa"));
    assert!(arr[0]["content"].as_str().unwrap().contains("BEGIN RSA PRIVATE KEY"));
}

#[test]
fn credential_ssh_keys_no_keys_returns_empty_array() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("known_hosts"), "github.com ...").unwrap();
    let path = dir.path().to_string_lossy().to_string().replace('\\', "\\\\");
    let json = run(&format!(r#"internal_ssh_keys("{}")"#, path));
    assert_eq!(json.trim(), "[]");
}

#[test]
fn credential_sweep_correct_structure() {
    // Override HOME to a TempDir so the sweep runs on our controlled structure.
    let dir = TempDir::new().unwrap();
    let aws = dir.path().join(".aws");
    std::fs::create_dir(&aws).unwrap();
    std::fs::write(aws.join("credentials"), "[default]\naws_access_key_id=TEST").unwrap();

    // We can't easily override HOME in a test without unsafe tricks.
    // Instead verify the JSON structure returned by credential_sweep.
    let json = run(r#"internal_credential_sweep()"#);
    let v: serde_json::Value = serde_json::from_str(&json)
        .expect("credential_sweep should return JSON");
    assert!(v.is_array(), "credential_sweep should return an array");
    let arr = v.as_array().unwrap();
    // Verify each entry has the expected fields.
    for entry in arr {
        assert!(entry["name"].is_string(), "each entry should have name: {}", entry);
        assert!(entry["path"].is_string(), "each entry should have path: {}", entry);
        assert!(entry["exists"].is_boolean(), "each entry should have exists: {}", entry);
        assert!(entry["size"].is_number(), "each entry should have size: {}", entry);
    }
    // Expected names are present.
    let names: Vec<&str> = arr.iter()
        .filter_map(|e| e["name"].as_str())
        .collect();
    assert!(names.contains(&"aws_creds"), "should check aws_creds: {:?}", names);
    assert!(names.contains(&"ssh_keys"), "should check ssh_keys: {:?}", names);
    assert!(names.contains(&"vault_token"), "should check vault_token: {:?}", names);
}
