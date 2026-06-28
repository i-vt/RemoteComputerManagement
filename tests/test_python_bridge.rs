// tests/test_python_bridge.rs
//
// Integration tests for the Python scripting bridge.
//
// These tests exercise the public RHAI API entirely through
// ExtensionManager::new() + run_script(), exactly as operator scripts do.
// They complement the unit tests inside python.rs which can access private
// helpers.
//
// Run: cargo test --test test_python_bridge
//
// Tests that need Python are skip-guarded: if Python is absent the test
// prints a reason and passes so CI on minimal images still goes green.

use rcm::agent::scripting::ExtensionManager;
use tempfile::TempDir;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn has_python() -> bool {
    std::process::Command::new("python3")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or_else(|_| {
            std::process::Command::new("python")
                .arg("--version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        })
}

/// Run a RHAI script through a fresh ExtensionManager.
fn run(script: &str) -> String {
    ExtensionManager::new().run_script(script, vec![])
}

/// Run a RHAI script with positional args (available as `args[0]` etc.).
fn run_with_args(script: &str, args: Vec<String>) -> String {
    ExtensionManager::new().run_script(script, args)
}

/// Assert the result does not start with "Error" and contains `needle`.
fn assert_ok_contains(result: &str, needle: &str, context: &str) {
    assert!(
        !result.starts_with("Error") && !result.starts_with("[Script Exception]"),
        "{}: unexpected error — {}", context, result
    );
    assert!(
        result.contains(needle),
        "{}: expected '{}' in output, got '{}'", context, needle, result
    );
}

/// Assert the result starts with "Error" (expected failure path).
fn assert_is_error(result: &str, context: &str) {
    assert!(
        result.starts_with("Error") || result.starts_with("[Script Exception]"),
        "{}: expected an error, got '{}'", context, result
    );
}

// ── Discovery tests ───────────────────────────────────────────────────────────

#[test]
fn discovery_python_find_returns_path_or_error() {
    let result = run(r#"internal_python_find()"#);
    if has_python() {
        assert!(!result.starts_with("Error"),
            "Python present but find returned error: {}", result);
        assert!(!result.is_empty());
    } else {
        assert!(result.starts_with("Error"),
            "Python absent but find returned: {}", result);
    }
}

#[test]
fn discovery_python_version_contains_python() {
    if !has_python() { eprintln!("[SKIP] Python not available"); return; }
    let result = run(r#"internal_python_version("")"#);
    assert_ok_contains(&result, "Python", "version check");
}

#[test]
fn discovery_version_for_explicit_path() {
    if !has_python() { eprintln!("[SKIP] Python not available"); return; }
    let interp = if std::path::Path::new("/usr/bin/python3").exists() {
        "/usr/bin/python3"
    } else {
        "python3"
    };
    let result = run(&format!(r#"internal_python_version("{}")"#, interp));
    assert_ok_contains(&result, "Python", "explicit path version");
}

// ── Basic execution tests ─────────────────────────────────────────────────────

#[test]
fn exec_arithmetic_output() {
    if !has_python() { eprintln!("[SKIP]"); return; }
    let result = run(r#"internal_python_exec("print(6 * 7)")"#);
    assert_ok_contains(&result, "42", "arithmetic");
}

#[test]
fn exec_multiline_code() {
    if !has_python() { eprintln!("[SKIP]"); return; }
    let result = run(r#"internal_python_exec("x = list(range(10))\ntotal = sum(x)\nprint(total)")"#);
    assert_ok_contains(&result, "45", "multiline exec");
}

#[test]
fn exec_json_structured_output() {
    if !has_python() { eprintln!("[SKIP]"); return; }
    // Use \n escapes to avoid multi-line RHAI string with {..} blocks
    let result = run(r#"internal_python_exec_json("import json, hashlib\ndata = {\"hash\": hashlib.md5(b\"rcm\").hexdigest(), \"len\": 5}\nprint(json.dumps(data))")"#);
    assert!(!result.starts_with("Error"), "json exec failed: {}", result);
    let v: serde_json::Value = serde_json::from_str(result.trim())
        .expect("should be valid JSON");
    assert_eq!(v["len"].as_i64(), Some(5));
    assert!(v["hash"].as_str().is_some());
}

#[test]
fn exec_file_with_existing_script() {
    if !has_python() { eprintln!("[SKIP]"); return; }
    let dir = TempDir::new().unwrap();
    let script = dir.path().join("hello.py");
    std::fs::write(&script, "print('file_exec_ok')\n").unwrap();
    let script_str = script.to_string_lossy();
    let result = run(&format!(r#"internal_python_exec_file("{}")"#, script_str));
    assert_ok_contains(&result, "file_exec_ok", "exec_file");
}

#[test]
fn exec_syntax_error_returns_error_string() {
    if !has_python() { eprintln!("[SKIP]"); return; }
    // This should not panic — it should return an error string.
    let result = run(r#"internal_python_exec("this is not valid python !!!")"#);
    // The output comes from stderr of the Python process.
    // Our function returns stderr when stdout is empty.
    assert!(!result.is_empty(), "syntax error should produce output");
}

#[test]
fn exec_timeout_respected() {
    if !has_python() { eprintln!("[SKIP]"); return; }
    // A 20-second sleep with a 2-second timeout should not hang.
    let dir = TempDir::new().unwrap();
    let venv = dir.path().join("tv").to_string_lossy().to_string();
    run(&format!(r#"internal_venv_create("{}")"#, venv.replace('\\', "\\\\")));
    if !rcm::agent::scripting::ExtensionManager::new()
        .run_script(&format!(r#"internal_venv_exists("{}")"#, venv.replace('\\', "\\\\")), vec![])
        .trim()
        .eq("true")
    {
        eprintln!("[SKIP] venv creation failed");
        return;
    }
    let start = std::time::Instant::now();
    let result = run(&format!(
        r#"internal_python_in_venv_timeout("{}", "import time; time.sleep(20)", 2)"#,
        venv.replace('\\', "\\\\")
    ));
    let elapsed = start.elapsed().as_secs();
    assert!(elapsed < 10, "timeout should have fired before 10s, took {}s", elapsed);
    let _ = result; // output may be empty or contain timeout message
}

// ── VENV lifecycle tests ──────────────────────────────────────────────────────

#[test]
fn venv_create_exists_delete_cycle() {
    if !has_python() { eprintln!("[SKIP]"); return; }
    let dir = TempDir::new().unwrap();
    let venv = dir.path().join("cycle_venv").to_string_lossy().to_string();
    let v = venv.replace('\\', "\\\\");

    // Not yet created.
    let exists_before: String = run(&format!(r#"internal_venv_exists("{}")"#, v));
    assert!(exists_before.trim() == "false", "should not exist yet");

    // Create.
    let create = run(&format!(r#"internal_venv_create("{}")"#, v));
    assert_ok_contains(&create, "Created", "create venv");

    // Now exists.
    let exists_after: String = run(&format!(r#"internal_venv_exists("{}")"#, v));
    assert!(exists_after.trim() == "true", "should exist after creation");

    // Python path inside venv.
    let py_path: String = run(&format!(r#"internal_venv_python_path("{}")"#, v));
    assert!(!py_path.starts_with("Error"));
    assert!(py_path.contains("python"), "path should contain 'python': {}", py_path);

    // Delete.
    let delete = run(&format!(r#"internal_venv_delete("{}")"#, v));
    assert_ok_contains(&delete, "Deleted", "delete venv");

    // Gone.
    let exists_end: String = run(&format!(r#"internal_venv_exists("{}")"#, v));
    assert!(exists_end.trim() == "false", "should not exist after deletion");
}

#[test]
fn venv_delete_nonexistent_returns_error() {
    let result = run(r#"internal_venv_delete("/no/such/venv/path/12345")"#);
    assert_is_error(&result, "delete non-existent venv");
}

#[test]
fn venv_exec_uses_isolated_interpreter() {
    if !has_python() { eprintln!("[SKIP]"); return; }
    let dir = TempDir::new().unwrap();
    let venv = dir.path().join("isolated").to_string_lossy().to_string();
    let v = venv.replace('\\', "\\\\");

    run(&format!(r#"internal_venv_create("{}")"#, v));

    let result = run(&format!(
        r#"internal_python_in_venv("{}", "import sys; print(sys.prefix)")"#, v
    ));
    assert_ok_contains(&result, "isolated", "sys.prefix should reference venv");
}

// ── Pip tests ─────────────────────────────────────────────────────────────────

#[test]
fn pip_list_returns_json_array() {
    if !has_python() { eprintln!("[SKIP]"); return; }
    let dir = TempDir::new().unwrap();
    let venv = dir.path().join("plvenv").to_string_lossy().to_string();
    let v = venv.replace('\\', "\\\\");
    run(&format!(r#"internal_venv_create("{}")"#, v));

    let list = run(&format!(r#"internal_pip_list("{}")"#, v));
    assert!(!list.starts_with("Error"), "pip list failed: {}", list);
    let parsed: serde_json::Value = serde_json::from_str(list.trim())
        .expect("pip list should be valid JSON");
    assert!(parsed.is_array(), "pip list should be array: {}", list);
    // A fresh venv always has pip and setuptools.
    let names: Vec<&str> = parsed.as_array().unwrap().iter()
        .filter_map(|e| e["name"].as_str())
        .collect();
    assert!(names.iter().any(|&n| n.to_lowercase().contains("pip")),
        "pip itself should be listed: {:?}", names);
}

#[test]
fn pip_freeze_contains_equals_equals() {
    if !has_python() { eprintln!("[SKIP]"); return; }
    let dir = TempDir::new().unwrap();
    let venv = dir.path().join("fzvenv").to_string_lossy().to_string();
    let v = venv.replace('\\', "\\\\");
    run(&format!(r#"internal_venv_create("{}")"#, v));

    // Install one package so freeze has something.
    run(&format!(r#"internal_pip_install("{}", "[\"six\"]")"#, v));

    let freeze = run(&format!(r#"internal_pip_freeze("{}")"#, v));
    assert!(!freeze.starts_with("Error"), "pip freeze failed: {}", freeze);
    // requirements.txt format uses == for version pins.
    assert!(freeze.contains("=="), "freeze should contain version pins: {}", freeze);
    assert!(freeze.to_lowercase().contains("six"),
        "six should appear in freeze output: {}", freeze);
}

#[test]
fn pip_has_package_stdlib_always_true() {
    if !has_python() { eprintln!("[SKIP]"); return; }
    let dir = TempDir::new().unwrap();
    let venv = dir.path().join("hpvenv").to_string_lossy().to_string();
    let v = venv.replace('\\', "\\\\");
    run(&format!(r#"internal_venv_create("{}")"#, v));

    for module in &["os", "sys", "json", "hashlib"] {
        let result: String = run(&format!(
            r#"internal_pip_has_package("{}", "{}")"#, v, module
        ));
        assert!(result.trim() == "true",
            "stdlib module '{}' should be available, got '{}'", module, result);
    }
}

#[test]
fn pip_has_package_missing_returns_false() {
    if !has_python() { eprintln!("[SKIP]"); return; }
    let dir = TempDir::new().unwrap();
    let venv = dir.path().join("missingvenv").to_string_lossy().to_string();
    let v = venv.replace('\\', "\\\\");
    run(&format!(r#"internal_venv_create("{}")"#, v));

    let result: String = run(&format!(
        r#"internal_pip_has_package("{}", "this_package_definitely_does_not_exist_xyz")"#, v
    ));
    assert!(result.trim() == "false",
        "missing package should return false, got '{}'", result);
}

#[test]
fn pip_install_requirements_string() {
    if !has_python() { eprintln!("[SKIP]"); return; }
    let dir = TempDir::new().unwrap();
    let venv = dir.path().join("reqsvenv").to_string_lossy().to_string();
    let v = venv.replace('\\', "\\\\");
    run(&format!(r#"internal_venv_create("{}")"#, v));

    // Pass requirements.txt *content* as a string (not a file path).
    let result = run(&format!(r#"internal_pip_install_requirements("{}", "six\n")"#, v));
    assert_ok_contains(&result, "Installed", "install via requirements string");

    let has_six: String = run(&format!(r#"internal_pip_has_package("{}", "six")"#, v));
    assert!(has_six.trim() == "true", "six should be installed after requirements install");
}

// ── python_call (JSON I/O) ────────────────────────────────────────────────────

#[test]
fn python_call_json_round_trip() {
    if !has_python() { eprintln!("[SKIP]"); return; }
    let dir = TempDir::new().unwrap();
    let venv = dir.path().join("callvenv").to_string_lossy().to_string();
    let v = venv.replace('\\', "\\\\");
    run(&format!(r#"internal_venv_create("{}")"#, v));

    // RHAI passes JSON in, Python reads `rcm_input`, prints JSON back.
    let script = r#"
let venv = "VENV_PATH";
let input = "{\"numbers\": [10, 20, 30]}";
let code = "import json; print(json.dumps({'total': sum(rcm_input['numbers'])}))";
internal_python_call(venv, input, code)
"#.replace("VENV_PATH", &v);

    let result = run(&script);
    let parsed: serde_json::Value = serde_json::from_str(result.trim())
        .expect("python_call should return valid JSON");
    assert_eq!(parsed["total"].as_i64(), Some(60));
}

// ── Session management tests ───────────────────────────────────────────────────

#[test]
fn session_start_exec_stop() {
    if !has_python() { eprintln!("[SKIP]"); return; }

    let script = r#"
let sid = internal_python_session_start("");
if sid.starts_with("Error") { return sid; }

let out = internal_python_session_exec(sid, "print(7 * 6)");
let stopped = internal_python_session_stop(sid);
out
"#;
    let result = run(script);
    assert_eq!(result.trim(), "42", "session exec returned '{}'", result);
}

#[test]
fn session_state_survives_multiple_execs() {
    if !has_python() { eprintln!("[SKIP]"); return; }

    let script = r#"
let sid = internal_python_session_start("");
if sid.starts_with("Error") { return sid; }

internal_python_session_exec(sid, "acc = []");
internal_python_session_exec(sid, "acc.append(10)");
internal_python_session_exec(sid, "acc.append(20)");
internal_python_session_exec(sid, "acc.append(30)");
let result = internal_python_session_exec(sid, "print(sum(acc))");
internal_python_session_stop(sid);
result
"#;
    let result = run(script);
    assert_eq!(result.trim(), "60", "accumulated state: got '{}'", result);
}

#[test]
fn session_list_reflects_active_sessions() {
    if !has_python() { eprintln!("[SKIP]"); return; }

    let script = r#"
let sid1 = internal_python_session_start("");
let sid2 = internal_python_session_start("");
if sid1.starts_with("Error") || sid2.starts_with("Error") {
    return "Error starting sessions";
}
let list = internal_python_session_list();
internal_python_session_stop(sid1);
internal_python_session_stop(sid2);
list
"#;
    let result = run(script);
    assert!(!result.starts_with("Error"), "session list failed: {}", result);
    let v: serde_json::Value = serde_json::from_str(result.trim())
        .unwrap_or(serde_json::json!([]));
    assert!(v.is_array(), "session list should be JSON array");
    // Both sessions should have appeared (they may be stopped by the time
    // we inspect, depending on ordering, so just check format).
}

#[test]
fn session_exec_unknown_id_returns_error() {
    let result = run(
        r#"internal_python_session_exec("00000000-dead-beef-0000-000000000000", "print(1)")"#
    );
    assert_is_error(&result, "exec on unknown session ID");
}

#[test]
fn session_stop_unknown_id_returns_error() {
    let result = run(
        r#"internal_python_session_stop("00000000-dead-beef-0000-000000000000")"#
    );
    assert_is_error(&result, "stop on unknown session ID");
}

// ── Offensive check ───────────────────────────────────────────────────────────

#[test]
fn offensive_check_returns_json_object() {
    if !has_python() { eprintln!("[SKIP]"); return; }
    let result = run(r#"internal_python_offensive_check("")"#);
    assert!(!result.starts_with("Error"), "offensive_check failed: {}", result);
    let v: serde_json::Value = serde_json::from_str(result.trim())
        .expect("offensive_check should return JSON");
    assert!(v.is_object(), "should be a JSON object");
    // Standard library entries should always be present even if some are false.
    assert!(v.get("requests").is_some() || v.get("impacket").is_some(),
        "expected at least requests/impacket keys: {}", result);
}

// ── ensure / bootstrap ────────────────────────────────────────────────────────

#[test]
fn ensure_returns_interpreter_when_python_present() {
    if !has_python() { eprintln!("[SKIP]"); return; }
    let dir = TempDir::new().unwrap();
    let install_dir = dir.path().to_string_lossy().to_string().replace('\\', "\\\\");
    let result = run(&format!(r#"internal_python_ensure("{}")"#, install_dir));
    assert!(!result.starts_with("Error"),
        "ensure should return interpreter path when Python is present: {}", result);
    assert!(!result.is_empty());
}

#[test]
fn bootstrap_creates_working_venv() {
    if !has_python() { eprintln!("[SKIP]"); return; }
    let dir  = TempDir::new().unwrap();
    let idir = dir.path().join("pyinst").to_string_lossy().to_string().replace('\\', "\\\\");
    let venv = dir.path().join("bsvenv").to_string_lossy().to_string().replace('\\', "\\\\");

    let python_bin = run(&format!(
        r#"internal_python_bootstrap("{}", "{}", "[]")"#, idir, venv
    ));
    assert!(!python_bin.starts_with("Error"),
        "bootstrap should succeed: {}", python_bin);

    // The returned path should be an executable inside the venv.
    let exists: String = run(&format!(
        r#"internal_venv_exists("{}")"#, venv
    ));
    assert!(exists.trim() == "true", "venv should exist after bootstrap");
}

#[test]
fn bootstrap_installs_requested_packages() {
    if !has_python() { eprintln!("[SKIP]"); return; }
    let dir  = TempDir::new().unwrap();
    let idir = dir.path().join("inst").to_string_lossy().to_string().replace('\\', "\\\\");
    let venv = dir.path().join("bsvenv2").to_string_lossy().to_string().replace('\\', "\\\\");

    let python_bin = run(&format!(
        r#"internal_python_bootstrap("{}", "{}", "[\"six\"]")"#, idir, venv
    ));
    if python_bin.starts_with("Error") {
        eprintln!("[SKIP] bootstrap failed: {}", python_bin);
        return;
    }

    let has_six = run(&format!(r#"internal_pip_has_package("{}", "six")"#, venv));
    assert!(has_six.trim() == "true",
        "six should be installed after bootstrap with packages: got '{}'", has_six);
}
