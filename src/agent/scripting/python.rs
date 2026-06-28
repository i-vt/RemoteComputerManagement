// src/agent/scripting/python.rs
//
// Python bridge for the RHAI scripting engine.
//
// Design: subprocess-based rather than PyO3 embedding.  This means:
//   • No python3-dev headers needed at agent build time.
//   • Works with whatever Python is installed on the target at runtime.
//   • VENVs are real Python venvs — operator can install arbitrary packages.
//
// Data exchange pattern:
//   RHAI calls internal_python_in_venv_json(venv, code)
//   Python script prints a single JSON line to stdout
//   RHAI receives the JSON string → use internal_json_get to extract fields
//
// Persistent session:
//   internal_python_session_start(venv_path) → session_id
//   internal_python_session_exec(session_id, code) → String
//   internal_python_session_stop(session_id)
//   The session keeps a Python subprocess alive between calls, amortising
//   startup cost.  Useful for iterative workflows.

use rhai::Engine;
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex, OnceLock},
    collections::HashMap,
    time::Duration,
};
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Persistent session store
// ─────────────────────────────────────────────────────────────────────────────

struct Session {
    stdin:  std::process::ChildStdin,
    stdout: std::io::BufReader<std::process::ChildStdout>,
    child:  std::process::Child,
}

// SAFETY: we only access sessions from inside the Mutex.
unsafe impl Send for Session {}

static SESSIONS: OnceLock<Mutex<HashMap<String, Session>>> = OnceLock::new();

fn sessions() -> &'static Mutex<HashMap<String, Session>> {
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Platform helpers
// ─────────────────────────────────────────────────────────────────────────────

fn venv_python(venv: &str) -> PathBuf {
    #[cfg(target_os = "windows")]
    return PathBuf::from(venv).join("Scripts").join("python.exe");
    #[cfg(not(target_os = "windows"))]
    return PathBuf::from(venv).join("bin").join("python3");
}

fn venv_pip(venv: &str) -> PathBuf {
    #[cfg(target_os = "windows")]
    return PathBuf::from(venv).join("Scripts").join("pip.exe");
    #[cfg(not(target_os = "windows"))]
    return PathBuf::from(venv).join("bin").join("pip");
}

/// Find the system Python interpreter. Tries python3 then python.
fn find_python() -> Option<String> {
    for candidate in &["python3", "python", "python3.12", "python3.11", "python3.10"] {
        if Command::new(candidate)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return Some(candidate.to_string());
        }
    }
    None
}

/// Write code to a temp .py file, returning the path. Caller must delete.
fn write_temp_script(code: &str) -> Result<PathBuf, String> {
    let path = std::env::temp_dir().join(format!("rcm_{}.py", Uuid::new_v4()));
    fs::write(&path, code).map_err(|e| format!("Error writing temp script: {}", e))?;
    Ok(path)
}

/// Run an interpreter with a list of args; returns (stdout, stderr, exit_code).
fn run_cmd(interpreter: &Path, args: &[&str], timeout: Duration) -> (String, String, i32) {
    let mut cmd = Command::new(interpreter);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c)  => c,
        Err(e) => return (String::new(), e.to_string(), -1),
    };

    // Drain pipes on background threads (mirrors utils::execute_shell_command_timeout).
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let (otx, orx) = std::sync::mpsc::channel::<String>();
    let (etx, erx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut s = String::new();
        if let Some(mut p) = stdout_pipe { let _ = p.read_to_string(&mut s); }
        let _ = otx.send(s);
    });
    std::thread::spawn(move || {
        let mut s = String::new();
        if let Some(mut p) = stderr_pipe { let _ = p.read_to_string(&mut s); }
        let _ = etx.send(s);
    });

    let grace = Duration::from_secs(3);
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let out = orx.recv_timeout(grace).unwrap_or_default();
                let err = erx.recv_timeout(grace).unwrap_or_default();
                return (out, err, status.code().unwrap_or(-1));
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    let out = orx.recv_timeout(grace).unwrap_or_default();
                    let err = erx.recv_timeout(grace).unwrap_or_default();
                    return (out, err, -1);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return (String::new(), e.to_string(), -1),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Registration
// ─────────────────────────────────────────────────────────────────────────────

pub fn register(engine: &mut Engine) {

    // ── Discovery ─────────────────────────────────────────────────────────────

    /// Find the system Python interpreter path.
    engine.register_fn("internal_python_find", || -> String {
        find_python().unwrap_or_else(|| "Error: Python not found".into())
    });

    /// Return the Python version string for an interpreter path (or "python3").
    engine.register_fn("internal_python_version", |interpreter: &str| -> String {
        let interp = if interpreter.is_empty() {
            match find_python() { Some(p) => p, None => return "Error: Python not found".into() }
        } else {
            interpreter.to_string()
        };
        let (out, err, code) = run_cmd(
            Path::new(&interp), &["--version"], Duration::from_secs(10)
        );
        if code == 0 { out.trim().to_string() } else { format!("Error: {}", err) }
    });

    // ── Basic execution (system Python) ───────────────────────────────────────

    /// Execute Python code using the system interpreter.
    /// Returns combined stdout+stderr.
    engine.register_fn("internal_python_exec", |code: &str| -> String {
        let interp = match find_python() {
            Some(p) => p,
            None    => return "Error: Python not found on PATH".into(),
        };
        let tmp = match write_temp_script(code) {
            Ok(p)  => p,
            Err(e) => return e,
        };
        let (out, err, _) = run_cmd(
            Path::new(&interp), &[tmp.to_str().unwrap_or("")], Duration::from_secs(60)
        );
        let _ = fs::remove_file(&tmp);
        if !err.is_empty() && out.is_empty() { err } else { out }
    });

    /// Execute a Python script file with the system interpreter.
    engine.register_fn("internal_python_exec_file", |script_path: &str| -> String {
        let interp = match find_python() {
            Some(p) => p,
            None    => return "Error: Python not found".into(),
        };
        let (out, err, _) = run_cmd(
            Path::new(&interp), &[script_path], Duration::from_secs(300)
        );
        if !err.is_empty() && out.is_empty() { err } else { out }
    });

    /// Execute Python code and return its stdout as a JSON string.
    /// Python should print a single JSON value to stdout.
    engine.register_fn("internal_python_exec_json", |code: &str| -> String {
        let interp = match find_python() {
            Some(p) => p,
            None    => return "Error: Python not found".into(),
        };
        let tmp = match write_temp_script(code) {
            Ok(p)  => p,
            Err(e) => return e,
        };
        let (out, err, _) = run_cmd(
            Path::new(&interp), &[tmp.to_str().unwrap_or("")], Duration::from_secs(60)
        );
        let _ = fs::remove_file(&tmp);
        if out.trim().is_empty() { format!("Error: {}", err) } else { out.trim().to_string() }
    });

    // ── VENV management ───────────────────────────────────────────────────────

    /// Create a Python virtual environment at venv_path using the system python3.
    engine.register_fn("internal_venv_create", |venv_path: &str| -> String {
        let interp = match find_python() {
            Some(p) => p,
            None    => return "Error: Python not found".into(),
        };
        let (out, err, code) = run_cmd(
            Path::new(&interp),
            &["-m", "venv", venv_path],
            Duration::from_secs(60),
        );
        if code == 0 {
            format!("Created venv at {}", venv_path)
        } else {
            format!("Error: {}\n{}", err, out)
        }
    });

    /// Create a venv using a specific interpreter (full path or name on PATH).
    engine.register_fn("internal_venv_create_with", |interpreter: &str, venv_path: &str| -> String {
        let (out, err, code) = run_cmd(
            Path::new(interpreter),
            &["-m", "venv", venv_path],
            Duration::from_secs(60),
        );
        if code == 0 {
            format!("Created venv at {} using {}", venv_path, interpreter)
        } else {
            format!("Error: {}\n{}", err, out)
        }
    });

    /// Check whether a venv directory looks like a valid venv.
    engine.register_fn("internal_venv_exists", |venv_path: &str| -> String {
        if venv_python(venv_path).exists() { "true".into() } else { "false".into() }
    });

    /// Remove a virtual environment directory entirely.
    engine.register_fn("internal_venv_delete", |venv_path: &str| -> String {
        if !venv_python(venv_path).exists() {
            return format!("Error: no venv found at {}", venv_path);
        }
        match fs::remove_dir_all(venv_path) {
            Ok(_)  => format!("Deleted venv at {}", venv_path),
            Err(e) => format!("Error: {}", e),
        }
    });

    /// Return the path to the Python interpreter inside a venv.
    engine.register_fn("internal_venv_python_path", |venv_path: &str| -> String {
        venv_python(venv_path).to_string_lossy().to_string()
    });

    // ── Pip operations ────────────────────────────────────────────────────────

    /// Install packages into a venv.
    /// packages_json: JSON array of package specifiers, e.g. ["requests", "impacket>=0.11"]
    engine.register_fn("internal_pip_install", |venv_path: &str, packages_json: &str| -> String {
        let packages: Vec<String> = match serde_json::from_str(packages_json) {
            Ok(p)  => p,
            Err(_) => vec![packages_json.to_string()], // treat as single package name
        };
        if packages.is_empty() { return "Error: no packages specified".into(); }
        let pip = venv_pip(venv_path);
        if !pip.exists() { return format!("Error: pip not found in venv {}", venv_path); }
        let mut args = vec!["install", "--quiet"];
        let pkg_strs: Vec<&str> = packages.iter().map(String::as_str).collect();
        args.extend_from_slice(&pkg_strs);
        let (out, err, code) = run_cmd(&pip, &args, Duration::from_secs(300));
        if code == 0 {
            format!("Installed: {}", packages.join(", "))
        } else {
            format!("Error (exit {}):\n{}\n{}", code, out, err)
        }
    });

    /// Install packages from a requirements.txt string (not a file path — the content itself).
    engine.register_fn("internal_pip_install_requirements", |venv_path: &str, req_content: &str| -> String {
        let pip = venv_pip(venv_path);
        if !pip.exists() { return format!("Error: pip not found in venv {}", venv_path); }
        let tmp = std::env::temp_dir().join(format!("rcm_req_{}.txt", Uuid::new_v4()));
        if fs::write(&tmp, req_content).is_err() {
            return "Error: could not write requirements file".into();
        }
        let tmp_str = tmp.to_string_lossy().to_string();
        let (out, err, code) = run_cmd(
            &pip, &["install", "-r", &tmp_str, "--quiet"], Duration::from_secs(300)
        );
        let _ = fs::remove_file(&tmp);
        if code == 0 { "Installed requirements".into() }
        else { format!("Error (exit {}):\n{}\n{}", code, out, err) }
    });

    /// Uninstall packages from a venv.
    engine.register_fn("internal_pip_uninstall", |venv_path: &str, packages_json: &str| -> String {
        let packages: Vec<String> = match serde_json::from_str(packages_json) {
            Ok(p)  => p,
            Err(_) => vec![packages_json.to_string()],
        };
        let pip = venv_pip(venv_path);
        if !pip.exists() { return format!("Error: pip not found in venv {}", venv_path); }
        let mut args = vec!["uninstall", "-y"];
        let pkg_strs: Vec<&str> = packages.iter().map(String::as_str).collect();
        args.extend_from_slice(&pkg_strs);
        let (_, err, code) = run_cmd(&pip, &args, Duration::from_secs(60));
        if code == 0 { format!("Uninstalled: {}", packages.join(", ")) }
        else { format!("Error: {}", err) }
    });

    /// List installed packages in a venv — returns JSON array of {name, version}.
    engine.register_fn("internal_pip_list", |venv_path: &str| -> String {
        let pip = venv_pip(venv_path);
        if !pip.exists() { return format!("Error: pip not found in venv {}", venv_path); }
        let (out, err, code) = run_cmd(&pip, &["list", "--format=json"], Duration::from_secs(30));
        if code == 0 { out.trim().to_string() }
        else { format!("Error: {}", err) }
    });

    /// Return the output of pip freeze (requirements.txt format) for a venv.
    engine.register_fn("internal_pip_freeze", |venv_path: &str| -> String {
        let pip = venv_pip(venv_path);
        if !pip.exists() { return format!("Error: pip not found in venv {}", venv_path); }
        let (out, err, code) = run_cmd(&pip, &["freeze"], Duration::from_secs(30));
        if code == 0 { out } else { format!("Error: {}", err) }
    });

    /// Check whether a package is installed in a venv.
    engine.register_fn("internal_pip_has_package", |venv_path: &str, package: &str| -> String {
        let python = venv_python(venv_path);
        if !python.exists() { return "false".into(); }
        let code = format!("import importlib.util; exit(0 if importlib.util.find_spec('{}') else 1)", package);
        let tmp = match write_temp_script(&code) { Ok(p) => p, Err(_) => return "false".into() };
        let (_, _, exit) = run_cmd(&python, &[tmp.to_str().unwrap_or("")], Duration::from_secs(10));
        let _ = fs::remove_file(&tmp);
        if exit == 0 { "true".into() } else { "false".into() }
    });

    // ── Execute in venv ───────────────────────────────────────────────────────

    /// Execute Python code inside a venv. Returns combined output.
    engine.register_fn("internal_python_in_venv", |venv_path: &str, code: &str| -> String {
        let python = venv_python(venv_path);
        if !python.exists() {
            return format!("Error: venv Python not found at {}", python.display());
        }
        let tmp = match write_temp_script(code) {
            Ok(p)  => p,
            Err(e) => return e,
        };
        let (out, err, _) = run_cmd(&python, &[tmp.to_str().unwrap_or("")], Duration::from_secs(300));
        let _ = fs::remove_file(&tmp);
        if !err.is_empty() && out.is_empty() { err } else { out }
    });

    /// Execute Python code in venv with a custom timeout (seconds).
    engine.register_fn("internal_python_in_venv_timeout", |venv_path: &str, code: &str, timeout_secs: i64| -> String {
        let python = venv_python(venv_path);
        if !python.exists() {
            return format!("Error: venv Python not found at {}", python.display());
        }
        let tmp = match write_temp_script(code) {
            Ok(p)  => p,
            Err(e) => return e,
        };
        let timeout = Duration::from_secs(timeout_secs.max(1) as u64);
        let (out, err, _) = run_cmd(&python, &[tmp.to_str().unwrap_or("")], timeout);
        let _ = fs::remove_file(&tmp);
        if !err.is_empty() && out.is_empty() { err } else { out }
    });

    /// Execute a .py file inside a venv.
    engine.register_fn("internal_python_file_in_venv", |venv_path: &str, script_path: &str| -> String {
        let python = venv_python(venv_path);
        if !python.exists() {
            return format!("Error: venv Python not found at {}", python.display());
        }
        let (out, err, _) = run_cmd(&python, &[script_path], Duration::from_secs(300));
        if !err.is_empty() && out.is_empty() { err } else { out }
    });

    /// Execute Python code in a venv and return only the JSON stdout.
    /// Python script should print one JSON value to stdout; other output is discarded.
    engine.register_fn("internal_python_in_venv_json", |venv_path: &str, code: &str| -> String {
        let python = venv_python(venv_path);
        if !python.exists() {
            return format!("Error: venv Python not found at {}", python.display());
        }
        let tmp = match write_temp_script(code) {
            Ok(p)  => p,
            Err(e) => return e,
        };
        let (out, err, code_exit) = run_cmd(&python, &[tmp.to_str().unwrap_or("")], Duration::from_secs(300));
        let _ = fs::remove_file(&tmp);
        if out.trim().is_empty() {
            format!("Error (exit {}): {}", code_exit, err)
        } else {
            out.trim().to_string()
        }
    });

    /// Pass a RHAI value as JSON to a Python script, get JSON back.
    /// Injects `rcm_input` as a parsed Python object at the top of the script.
    engine.register_fn("internal_python_call", |venv_path: &str, input_json: &str, code: &str| -> String {
        let python = venv_python(venv_path);
        if !python.exists() {
            return format!("Error: venv Python not found at {}", python.display());
        }
        let wrapper = format!(
            "import json as _json\nrcm_input = _json.loads({})\n\n{}",
            serde_json::to_string(input_json).unwrap_or_else(|_| "\"{}\"".into()),
            code
        );
        let tmp = match write_temp_script(&wrapper) {
            Ok(p)  => p,
            Err(e) => return e,
        };
        let (out, err, _) = run_cmd(&python, &[tmp.to_str().unwrap_or("")], Duration::from_secs(300));
        let _ = fs::remove_file(&tmp);
        if out.trim().is_empty() { format!("Error: {}", err) } else { out.trim().to_string() }
    });

    // ── Persistent session ────────────────────────────────────────────────────
    // The session keeps a Python subprocess alive between calls.
    // The Python side runs a JSON RPC loop reading from stdin.

    /// Start a persistent Python session. Returns a session ID string.
    /// venv_path: path to venv, or "" to use system Python.
    engine.register_fn("internal_python_session_start", |venv_path: &str| -> String {
        let python: PathBuf = if venv_path.is_empty() {
            match find_python() {
                Some(p) => PathBuf::from(p),
                None    => return "Error: Python not found".into(),
            }
        } else {
            venv_python(venv_path)
        };
        if python.is_absolute() && !python.exists() {
            return format!("Error: interpreter not found at {}", python.display());
        }

        // The session loop: read one JSON line {"code":"..."}, exec, print result.
        let loop_code = r#"
import sys, json, io, traceback, builtins

_globals = {'__builtins__': builtins}
sys.stdout.flush()

while True:
    raw = sys.stdin.readline()
    if not raw:
        break
    try:
        req = json.loads(raw.strip())
        code = req.get('code', '')
        _buf = io.StringIO()
        _old = sys.stdout
        sys.stdout = _buf
        try:
            exec(compile(code, '<rcm>', 'exec'), _globals)
        finally:
            sys.stdout = _old
        output = _buf.getvalue()
        result = json.dumps({'output': output, 'error': None})
    except Exception as exc:
        result = json.dumps({'output': '', 'error': traceback.format_exc()})
    _old.write(result + '\n')
    _old.flush()
"#;
        let tmp = match write_temp_script(loop_code) {
            Ok(p)  => p,
            Err(e) => return format!("Error writing session script: {}", e),
        };

        let child = Command::new(&python)
            .arg(tmp.to_str().unwrap_or(""))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();

        match child {
            Ok(mut c) => {
                let stdin  = match c.stdin.take()  { Some(s) => s, None => return "Error: no stdin".into() };
                let stdout = match c.stdout.take() { Some(s) => s, None => return "Error: no stdout".into() };
                let id = Uuid::new_v4().to_string();
                let session = Session {
                    stdin,
                    stdout: std::io::BufReader::new(stdout),
                    child: c,
                };
                if let Ok(mut store) = sessions().lock() {
                    store.insert(id.clone(), session);
                    // The temp file will be cleaned up when session is stopped.
                    id
                } else {
                    "Error: session store poisoned".into()
                }
            }
            Err(e) => format!("Error starting session: {}", e),
        }
    });

    /// Execute code in a persistent session. Returns the script's stdout.
    engine.register_fn("internal_python_session_exec", |session_id: &str, code: &str| -> String {
        let Ok(mut store) = sessions().lock() else {
            return "Error: session store poisoned".into();
        };
        let Some(session) = store.get_mut(session_id) else {
            return format!("Error: session '{}' not found", session_id);
        };
        let msg = match serde_json::to_string(&serde_json::json!({ "code": code })) {
            Ok(s)  => s + "\n",
            Err(e) => return format!("Error serialising code: {}", e),
        };
        if session.stdin.write_all(msg.as_bytes()).is_err() {
            return "Error: session stdin closed".into();
        }
        if session.stdin.flush().is_err() {
            return "Error: session stdin flush failed".into();
        }
        let mut line = String::new();
        use std::io::BufRead;
        if session.stdout.read_line(&mut line).is_err() {
            return "Error: session stdout closed".into();
        }
        let resp: serde_json::Value = match serde_json::from_str(line.trim()) {
            Ok(v)  => v,
            Err(_) => return line,
        };
        if let Some(err) = resp["error"].as_str() {
            if !err.is_empty() { return format!("PythonError:\n{}", err); }
        }
        resp["output"].as_str().unwrap_or("").to_string()
    });

    /// Stop a persistent Python session and clean up.
    engine.register_fn("internal_python_session_stop", |session_id: &str| -> String {
        let Ok(mut store) = sessions().lock() else {
            return "Error: session store poisoned".into();
        };
        if let Some(mut session) = store.remove(session_id) {
            let _ = session.child.kill();
            let _ = session.child.wait();
            format!("Session '{}' stopped", session_id)
        } else {
            format!("Error: session '{}' not found", session_id)
        }
    });

    /// List active persistent session IDs.
    engine.register_fn("internal_python_session_list", || -> String {
        match sessions().lock() {
            Ok(store) => {
                let ids: Vec<&String> = store.keys().collect();
                serde_json::to_string(&ids).unwrap_or("[]".into())
            }
            Err(_) => "Error: session store poisoned".into(),
        }
    });

    // ── Convenience wrappers for common offensive Python libraries ────────────

    /// Check which offensive Python libraries are available in a venv.
    /// Returns JSON object: {impacket, bloodhound, pwntools, scapy, paramiko, ...}
    engine.register_fn("internal_python_offensive_check", |venv_path: &str| -> String {
        let python = if venv_path.is_empty() {
            match find_python() { Some(p) => PathBuf::from(p), None => return "Error: Python not found".into() }
        } else {
            venv_python(venv_path)
        };
        let check_code = r#"
import json, importlib.util
libs = [
    "impacket", "bloodhound", "pwntools", "scapy", "paramiko",
    "ldap3", "dnspython", "requests", "cryptography", "pyOpenSSL",
    "pypsrp", "pykerberos", "certipy", "certipy-ad", "pypykatz",
]
result = {lib: importlib.util.find_spec(lib.replace("-","_").split("/")[0]) is not None for lib in libs}
print(json.dumps(result))
"#;
        let tmp = match write_temp_script(check_code) {
            Ok(p)  => p,
            Err(e) => return e,
        };
        let (out, err, _) = run_cmd(&python, &[tmp.to_str().unwrap_or("")], Duration::from_secs(15));
        let _ = fs::remove_file(&tmp);
        if out.trim().is_empty() { format!("Error: {}", err) } else { out.trim().to_string() }
    });

    /// Install a curated set of offensive Python packages into a venv.
    /// tier: "minimal" | "standard" | "full"
    ///   minimal:  requests, cryptography, dnspython
    ///   standard: + impacket, ldap3, paramiko, scapy
    ///   full:     + bloodhound, pypykatz, certipy-ad, pwntools
    engine.register_fn("internal_python_install_offensive", |venv_path: &str, tier: &str| -> String {
        let pip = venv_pip(venv_path);
        if !pip.exists() { return format!("Error: pip not found in venv {}", venv_path); }
        let packages: &[&str] = match tier {
            "minimal"  => &["requests", "cryptography", "dnspython"],
            "standard" => &["requests", "cryptography", "dnspython",
                            "impacket", "ldap3", "paramiko", "scapy"],
            "full"     => &["requests", "cryptography", "dnspython",
                            "impacket", "ldap3", "paramiko", "scapy",
                            "bloodhound", "pypykatz", "certipy-ad", "pwntools"],
            _          => return format!("Error: unknown tier '{}' — use minimal|standard|full", tier),
        };
        let mut args = vec!["install", "--quiet"];
        args.extend_from_slice(packages);
        let (out, err, code) = run_cmd(&pip, &args, Duration::from_secs(600));
        if code == 0 {
            format!("Installed {} tier ({} packages)", tier, packages.len())
        } else {
            format!("Error (exit {}):\n{}\n{}", code, out, err)
        }
    });

    // logging
    engine.register_fn("print_python_log", |msg: &str| {
        eprintln!("[Python] {}", msg);
    });

    // Install helpers registered separately (defined below in this file).
    register_python_install(engine);
}

// ═════════════════════════════════════════════════════════════════════════════
// Python installation — called from register() at the bottom of the file.
//
// Strategy (attempted in order):
//   1. System already has Python → return its path immediately.
//   2. Portable install already exists at install_dir → return that path.
//   3. OS package manager (apt/yum/dnf/pacman/apk/brew/winget) — may need root.
//   4. python-build-standalone — pre-compiled portable binary downloaded from
//      GitHub, extracted into install_dir.  No root, no compilation, ~50 MB.
// ═════════════════════════════════════════════════════════════════════════════

// ── Portable-install helpers ──────────────────────────────────────────────────

/// Path to the Python interpreter inside a python-build-standalone install.
fn portable_python_bin(install_dir: &str) -> PathBuf {
    #[cfg(target_os = "windows")]
    return PathBuf::from(install_dir).join("python").join("python.exe");
    #[cfg(not(target_os = "windows"))]
    return PathBuf::from(install_dir).join("python").join("bin").join("python3");
}

/// Current target triple suffix used in python-build-standalone asset names.
fn pbs_asset_suffix() -> &'static str {
    // Determined at Rust compile time → correct for the agent binary's target.
    #[cfg(all(target_os = "linux",   target_arch = "x86_64"))]   return "x86_64-unknown-linux-gnu-install_only.tar.gz";
    #[cfg(all(target_os = "linux",   target_arch = "aarch64"))]  return "aarch64-unknown-linux-gnu-install_only.tar.gz";
    #[cfg(all(target_os = "macos",   target_arch = "x86_64"))]   return "x86_64-apple-darwin-install_only.tar.gz";
    #[cfg(all(target_os = "macos",   target_arch = "aarch64"))]  return "aarch64-apple-darwin-install_only.tar.gz";
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]   return "x86_64-pc-windows-msvc-install_only.tar.gz";
    #[cfg(not(any(
        all(target_os = "linux",   target_arch = "x86_64"),
        all(target_os = "linux",   target_arch = "aarch64"),
        all(target_os = "macos",   target_arch = "x86_64"),
        all(target_os = "macos",   target_arch = "aarch64"),
        all(target_os = "windows", target_arch = "x86_64"),
    )))]
    return "x86_64-unknown-linux-gnu-install_only.tar.gz"; // safe fallback
}

/// Query GitHub releases API and return the download URL for the right asset.
fn fetch_pbs_url() -> Result<String, String> {
    let client = reqwest::blocking::Client::new();
    let resp = client
        .get("https://api.github.com/repos/indygreg/python-build-standalone/releases/latest")
        .header("User-Agent", "rcm-agent/1.0")
        .send()
        .map_err(|e| format!("GitHub API error: {}", e))?;
    let json: serde_json::Value = resp.json()
        .map_err(|e| format!("JSON parse error: {}", e))?;
    let suffix = pbs_asset_suffix();
    json["assets"].as_array()
        .ok_or_else(|| "No assets in release".to_string())?
        .iter()
        .find(|a| a["name"].as_str().map(|n| n.ends_with(suffix)).unwrap_or(false))
        .and_then(|a| a["browser_download_url"].as_str())
        .map(str::to_string)
        .ok_or_else(|| format!("No asset matching suffix '{}' in latest release", suffix))
}

/// Download a URL to a local file path, streaming (no full in-memory load).
fn download_to_file(url: &str, dest: &Path) -> Result<u64, String> {
    let client = reqwest::blocking::Client::new();
    let mut resp = client
        .get(url)
        .header("User-Agent", "rcm-agent/1.0")
        .send()
        .map_err(|e| format!("Download error: {}", e))?;
    let mut file = fs::File::create(dest)
        .map_err(|e| format!("Cannot create {}: {}", dest.display(), e))?;
    let bytes = resp.copy_to(&mut file)
        .map_err(|e| format!("Write error: {}", e))?;
    Ok(bytes)
}

/// Extract a .tar.gz archive into dest_dir using flate2 + tar (no subprocess).
fn extract_tarball(tarball: &Path, dest_dir: &str) -> Result<(), String> {
    use flate2::read::GzDecoder;
    use tar::Archive;
    fs::create_dir_all(dest_dir)
        .map_err(|e| format!("Cannot create {}: {}", dest_dir, e))?;
    let file = fs::File::open(tarball)
        .map_err(|e| format!("Cannot open tarball: {}", e))?;
    let gz = GzDecoder::new(file);
    let mut archive = Archive::new(gz);
    archive.unpack(dest_dir)
        .map_err(|e| format!("Extraction failed: {}", e))?;
    Ok(())
}

/// Download python-build-standalone and extract into install_dir.
/// Returns the path to the Python interpreter on success.
fn install_portable_python(install_dir: &str) -> Result<String, String> {
    // Skip if already present.
    let bin = portable_python_bin(install_dir);
    if bin.exists() {
        return Ok(bin.to_string_lossy().to_string());
    }
    let url = fetch_pbs_url()?;
    let tarball = std::env::temp_dir().join(format!("rcm_pbs_{}.tar.gz", Uuid::new_v4()));
    let bytes = download_to_file(&url, &tarball)?;
    let _ = eprintln!("[python-install] downloaded {} bytes from {}", bytes, url);
    extract_tarball(&tarball, install_dir)?;
    let _ = fs::remove_file(&tarball);
    // Verify the interpreter actually runs.
    let (out, _, code) = run_cmd(&bin, &["--version"], Duration::from_secs(10));
    if code != 0 {
        return Err(format!("Extracted Python failed --version check: {}", out));
    }
    Ok(bin.to_string_lossy().to_string())
}

/// Try OS package managers in turn; return Ok(interpreter) on success.
fn try_package_managers() -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        // winget — available on Windows 10 1709+ without admin for user installs.
        let (_, _, code) = run_cmd(
            Path::new("winget"),
            &["install", "--id", "Python.Python.3.12", "--silent",
              "--accept-package-agreements", "--accept-source-agreements"],
            Duration::from_secs(300),
        );
        if code == 0 {
            if let Some(p) = find_python() { return Ok(p); }
        }
        // Chocolatey — if installed.
        let (_, _, code) = run_cmd(
            Path::new("choco"),
            &["install", "python3", "-y", "--no-progress"],
            Duration::from_secs(300),
        );
        if code == 0 {
            if let Some(p) = find_python() { return Ok(p); }
        }
    }
    #[cfg(target_os = "macos")]
    {
        // Homebrew.
        let (_, _, code) = run_cmd(
            Path::new("brew"),
            &["install", "python3"],
            Duration::from_secs(300),
        );
        if code == 0 {
            if let Some(p) = find_python() { return Ok(p); }
        }
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        // Linux: try each common package manager in turn.
        let attempts: &[(&str, &[&str])] = &[
            ("apt-get", &["install", "-y", "--no-install-recommends",
                          "python3", "python3-venv", "python3-pip"]),
            ("apt",     &["install", "-y", "--no-install-recommends",
                          "python3", "python3-venv", "python3-pip"]),
            ("dnf",     &["install", "-y", "python3", "python3-pip"]),
            ("yum",     &["install", "-y", "python3", "python3-pip"]),
            ("pacman",  &["-S", "--noconfirm", "python", "python-pip"]),
            ("apk",     &["add", "--no-cache", "python3", "py3-pip"]),
            ("zypper",  &["install", "-y", "python3", "python3-pip"]),
        ];
        for (mgr, args) in attempts {
            if Command::new(mgr).arg("--version")
               .stdout(Stdio::null()).stderr(Stdio::null())
               .status().map(|s| s.success()).unwrap_or(false)
            {
                let (_, _, code) = run_cmd(Path::new(mgr), args, Duration::from_secs(300));
                if code == 0 {
                    if let Some(p) = find_python() { return Ok(p); }
                }
            }
        }
    }
    Err("No package manager succeeded".to_string())
}

/// Ensure python3-venv is available; install it if not (Linux only).
fn ensure_venv_module(interpreter: &str) -> Result<(), String> {
    let (_, _, code) = run_cmd(
        Path::new(interpreter),
        &["-m", "venv", "--help"],
        Duration::from_secs(10),
    );
    if code == 0 { return Ok(()); }
    // Try to install via apt-get on Debian/Ubuntu.
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let _ = run_cmd(
            Path::new("apt-get"),
            &["install", "-y", "python3-venv"],
            Duration::from_secs(120),
        );
    }
    // Re-check.
    let (_, _, code) = run_cmd(
        Path::new(interpreter),
        &["-m", "venv", "--help"],
        Duration::from_secs(10),
    );
    if code == 0 { Ok(()) } else { Err("python3-venv not available and could not install it".to_string()) }
}

// ── Public registration ───────────────────────────────────────────────────────

pub fn register_python_install(engine: &mut Engine) {

    // ── Ensure Python is available ────────────────────────────────────────────

    /// Return the path to a working Python interpreter, installing one if needed.
    ///
    /// install_dir: directory where a portable Python will be placed if nothing
    ///              else works, e.g. "/tmp/.rcm_py_runtime" or "%TEMP%\rcm_py".
    ///              If Python is already on PATH, this directory is never used.
    engine.register_fn("internal_python_ensure", |install_dir: &str| -> String {
        // 1. Already on PATH?
        if let Some(p) = find_python() { return p; }

        // 2. Portable install already present?
        let bin = portable_python_bin(install_dir);
        if bin.exists() { return bin.to_string_lossy().to_string(); }

        // 3. Try OS package manager.
        if let Ok(p) = try_package_managers() { return p; }

        // 4. Download python-build-standalone.
        match install_portable_python(install_dir) {
            Ok(p)  => p,
            Err(e) => format!("Error: {}", e),
        }
    });

    /// Force-download python-build-standalone into install_dir regardless of
    /// whether Python is already present.  Returns interpreter path or error.
    engine.register_fn("internal_python_install_portable", |install_dir: &str| -> String {
        match install_portable_python(install_dir) {
            Ok(p)  => p,
            Err(e) => format!("Error: {}", e),
        }
    });

    /// Try only the OS package manager (apt/yum/winget/brew …).
    /// Returns interpreter path or error.  May require elevated privileges.
    engine.register_fn("internal_python_install_system", || -> String {
        match try_package_managers() {
            Ok(p)  => p,
            Err(e) => format!("Error: {}", e),
        }
    });

    // ── One-shot bootstrap ────────────────────────────────────────────────────

    /// Ensure Python → create a venv → optionally install packages → return
    /// the venv Python path.  This is the single call that sets up everything.
    ///
    /// install_dir:   where to put portable Python if needed
    /// venv_path:     where to create the venv
    /// packages_json: JSON array of pip packages to install, or "" to skip
    engine.register_fn("internal_python_bootstrap",
        |install_dir: &str, venv_path: &str, packages_json: &str| -> String {

        // 1. Ensure interpreter exists.
        let interp = {
            if let Some(p) = find_python() { p }
            else {
                let bin = portable_python_bin(install_dir);
                if bin.exists() {
                    bin.to_string_lossy().to_string()
                } else if let Ok(p) = try_package_managers() {
                    p
                } else {
                    match install_portable_python(install_dir) {
                        Ok(p)  => p,
                        Err(e) => return format!("Error installing Python: {}", e),
                    }
                }
            }
        };

        // 2. Ensure python3-venv module is available.
        if let Err(e) = ensure_venv_module(&interp) {
            return format!("Error: {}", e);
        }

        // 3. Create venv (idempotent — venv skips if already valid).
        let venv_bin = venv_python(venv_path);
        if !venv_bin.exists() {
            let (out, err, code) = run_cmd(
                Path::new(&interp), &["-m", "venv", venv_path], Duration::from_secs(60),
            );
            if code != 0 {
                return format!("Error creating venv: {} {}", out, err);
            }
        }

        // 4. Upgrade pip silently.
        let pip = venv_pip(venv_path);
        let _ = run_cmd(
            &pip, &["install", "--upgrade", "pip", "--quiet"], Duration::from_secs(120),
        );

        // 5. Install requested packages.
        if !packages_json.is_empty() {
            let packages: Vec<String> =
                serde_json::from_str(packages_json).unwrap_or_default();
            if !packages.is_empty() {
                let mut args = vec!["install", "--quiet"];
                let pkg_strs: Vec<&str> = packages.iter().map(String::as_str).collect();
                args.extend_from_slice(&pkg_strs);
                let (out, err, code) = run_cmd(&pip, &args, Duration::from_secs(300));
                if code != 0 {
                    return format!("Venv created but pip install failed: {} {}", out, err);
                }
            }
        }

        venv_bin.to_string_lossy().to_string()
    });

    // ── venv-module guard ─────────────────────────────────────────────────────

    /// Check whether the venv module is functional for a given interpreter.
    /// If not, attempt to install python3-venv via apt-get.
    engine.register_fn("internal_python_ensure_venv", |interpreter: &str| -> String {
        match ensure_venv_module(interpreter) {
            Ok(_)  => "venv module available".into(),
            Err(e) => format!("Error: {}", e),
        }
    });

    // ── Download URL introspection ────────────────────────────────────────────

    /// Return the download URL for the latest python-build-standalone release
    /// matching the current agent platform.  Useful for verifying or pre-staging.
    engine.register_fn("internal_python_pbs_url", || -> String {
        match fetch_pbs_url() {
            Ok(url) => url,
            Err(e)  => format!("Error: {}", e),
        }
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// Unit + integration tests
// ═════════════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tempfile::TempDir;

    // ── Skip guard ────────────────────────────────────────────────────────────
    // Tests that need Python call `require_python!()` as their first statement.
    // The macro prints a clear reason and returns so `cargo test` still passes.

    macro_rules! require_python {
        () => {
            if find_python().is_none() {
                eprintln!("[SKIP] Python not found on PATH — install python3 to run this test");
                return;
            }
        };
    }

    // ── Platform / path helpers (no Python needed) ────────────────────────────

    #[test]
    fn test_pbs_asset_suffix_is_valid() {
        let s = pbs_asset_suffix();
        assert!(!s.is_empty(), "suffix must not be empty");
        assert!(s.ends_with("install_only.tar.gz"),
            "suffix '{}' should end with install_only.tar.gz", s);
        assert!(s.contains("x86_64") || s.contains("aarch64"),
            "suffix should contain an arch: {}", s);
    }

    #[test]
    fn test_venv_python_path_structure() {
        let p = venv_python("/tmp/myvenv");
        let s = p.to_string_lossy();
        assert!(s.contains("myvenv"), "path should contain venv dir name");
        #[cfg(target_os = "windows")]
        assert!(s.ends_with("python.exe"), "Windows venv python = python.exe, got {}", s);
        #[cfg(not(target_os = "windows"))]
        assert!(s.ends_with("python3"), "Unix venv python = python3, got {}", s);
    }

    #[test]
    fn test_venv_pip_path_structure() {
        let p = venv_pip("/tmp/myvenv");
        let s = p.to_string_lossy();
        assert!(s.contains("myvenv"), "pip path should contain venv dir name");
        #[cfg(target_os = "windows")]
        assert!(s.ends_with("pip.exe"), "Windows pip = pip.exe, got {}", s);
        #[cfg(not(target_os = "windows"))]
        assert!(s.ends_with("pip"), "Unix pip ends with pip, got {}", s);
    }

    #[test]
    fn test_portable_python_bin_structure() {
        let p = portable_python_bin("/opt/pyruntime");
        let s = p.to_string_lossy();
        assert!(s.contains("pyruntime"), "should contain install dir");
        assert!(s.contains("python"), "should reference a python binary");
    }

    #[test]
    fn test_write_temp_script_creates_file() {
        let code = "print('hello')\n";
        let path = write_temp_script(code).expect("write_temp_script should succeed");
        assert!(path.exists(), "temp file should exist after write");
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, code);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_write_temp_script_unique_names() {
        let p1 = write_temp_script("a = 1").unwrap();
        let p2 = write_temp_script("b = 2").unwrap();
        assert_ne!(p1, p2, "each call should produce a unique temp file");
        std::fs::remove_file(&p1).ok();
        std::fs::remove_file(&p2).ok();
    }

    // ── Python discovery (no network, no venv) ────────────────────────────────

    #[test]
    fn test_find_python_result_consistent() {
        // Two calls should return the same result.
        let a = find_python();
        let b = find_python();
        assert_eq!(a, b, "find_python() should be deterministic");
    }

    // ── run_cmd basic invocation ──────────────────────────────────────────────

    #[test]
    fn test_run_cmd_version() {
        require_python!();
        let interp = find_python().unwrap();
        let (out, err, code) = run_cmd(
            Path::new(&interp), &["--version"], Duration::from_secs(10)
        );
        assert_eq!(code, 0, "python --version should exit 0, stderr: {}", err);
        let combined = format!("{}{}", out, err);
        assert!(combined.to_lowercase().contains("python"),
            "output should mention 'python': {}", combined);
    }

    #[test]
    fn test_run_cmd_timeout_kills() {
        require_python!();
        let interp = find_python().unwrap();
        // 10-second sleep with a 1-second timeout should be killed.
        let (_, _, code) = run_cmd(
            Path::new(&interp),
            &["-c", "import time; time.sleep(10)"],
            Duration::from_secs(1),
        );
        assert_ne!(code, 0, "timed-out process should not exit 0");
    }

    // ── Python code execution ─────────────────────────────────────────────────

    #[test]
    fn test_python_exec_arithmetic() {
        require_python!();
        let code = "print(6 * 7)";
        let tmp = write_temp_script(code).unwrap();
        let interp = find_python().unwrap();
        let (out, _, code_exit) = run_cmd(Path::new(&interp), &[tmp.to_str().unwrap()], Duration::from_secs(10));
        std::fs::remove_file(&tmp).ok();
        assert_eq!(code_exit, 0);
        assert!(out.trim().contains("42"), "expected 42, got '{}'", out.trim());
    }

    #[test]
    fn test_python_exec_multiline() {
        require_python!();
        let code = "x = [i**2 for i in range(5)]\nprint(sum(x))";
        let tmp = write_temp_script(code).unwrap();
        let interp = find_python().unwrap();
        let (out, _, _) = run_cmd(Path::new(&interp), &[tmp.to_str().unwrap()], Duration::from_secs(10));
        std::fs::remove_file(&tmp).ok();
        assert_eq!(out.trim(), "30", "sum of squares 0..4 should be 30");
    }

    #[test]
    fn test_python_exec_json_output() {
        require_python!();
        let code = "import json\nprint(json.dumps({'key': 'value', 'n': 42}))";
        let tmp = write_temp_script(code).unwrap();
        let interp = find_python().unwrap();
        let (out, _, _) = run_cmd(Path::new(&interp), &[tmp.to_str().unwrap()], Duration::from_secs(10));
        std::fs::remove_file(&tmp).ok();
        let parsed: serde_json::Value = serde_json::from_str(out.trim())
            .expect("output should be valid JSON");
        assert_eq!(parsed["key"].as_str(), Some("value"));
        assert_eq!(parsed["n"].as_i64(), Some(42));
    }

    #[test]
    fn test_python_exec_stdlib_import() {
        require_python!();
        let code = "import os, sys, json, hashlib; print('ok')";
        let tmp = write_temp_script(code).unwrap();
        let interp = find_python().unwrap();
        let (out, err, code_exit) = run_cmd(Path::new(&interp), &[tmp.to_str().unwrap()], Duration::from_secs(10));
        std::fs::remove_file(&tmp).ok();
        assert_eq!(code_exit, 0, "stdlib imports should succeed; stderr: {}", err);
        assert!(out.trim() == "ok");
    }

    #[test]
    fn test_python_syntax_error_exits_nonzero() {
        require_python!();
        let code = "this is not valid python !!!";
        let tmp = write_temp_script(code).unwrap();
        let interp = find_python().unwrap();
        let (_, err, code_exit) = run_cmd(Path::new(&interp), &[tmp.to_str().unwrap()], Duration::from_secs(10));
        std::fs::remove_file(&tmp).ok();
        assert_ne!(code_exit, 0, "syntax error should exit nonzero");
        assert!(!err.is_empty(), "stderr should contain error info");
    }

    // ── VENV lifecycle ────────────────────────────────────────────────────────

    #[test]
    fn test_venv_create_and_exists() {
        require_python!();
        let dir = TempDir::new().unwrap();
        let venv = dir.path().join("testvenv").to_string_lossy().to_string();
        let interp = find_python().unwrap();

        // Venv should not exist yet.
        assert!(!venv_python(&venv).exists(), "venv should not exist before creation");

        // Create.
        let (_, err, code) = run_cmd(
            Path::new(&interp), &["-m", "venv", &venv], Duration::from_secs(60)
        );
        if code != 0 {
            eprintln!("[SKIP] venv creation failed (python3-venv not installed?): {}", err);
            return;
        }

        // Interpreter must exist inside the venv.
        assert!(venv_python(&venv).exists(), "venv Python binary should exist after creation");
        assert!(venv_pip(&venv).exists(), "venv pip should exist after creation");
    }

    #[test]
    fn test_venv_python_runs() {
        require_python!();
        let dir = TempDir::new().unwrap();
        let venv = dir.path().join("runvenv").to_string_lossy().to_string();
        let interp = find_python().unwrap();
        let (_, _, c) = run_cmd(Path::new(&interp), &["-m", "venv", &venv], Duration::from_secs(60));
        if c != 0 { eprintln!("[SKIP] venv creation failed"); return; }

        let vpy = venv_python(&venv);
        let (out, err, code) = run_cmd(&vpy, &["--version"], Duration::from_secs(10));
        assert_eq!(code, 0, "venv python --version should succeed; {}", err);
        let combined = format!("{}{}", out, err);
        assert!(combined.to_lowercase().contains("python"), "got: {}", combined);
    }

    // ── Pip operations ────────────────────────────────────────────────────────

    #[test]
    fn test_pip_list_returns_json() {
        require_python!();
        let dir = TempDir::new().unwrap();
        let venv = dir.path().join("pipvenv").to_string_lossy().to_string();
        let interp = find_python().unwrap();
        let (_, _, c) = run_cmd(Path::new(&interp), &["-m", "venv", &venv], Duration::from_secs(60));
        if c != 0 { eprintln!("[SKIP] venv creation failed"); return; }

        let pip = venv_pip(&venv);
        let (out, err, code) = run_cmd(&pip, &["list", "--format=json"], Duration::from_secs(30));
        assert_eq!(code, 0, "pip list should succeed; {}", err);
        let parsed: serde_json::Value = serde_json::from_str(out.trim())
            .expect("pip list output should be valid JSON");
        assert!(parsed.is_array(), "pip list --format=json should return an array");
    }

    #[test]
    fn test_pip_install_tiny_package() {
        require_python!();
        let dir = TempDir::new().unwrap();
        let venv = dir.path().join("installvenv").to_string_lossy().to_string();
        let interp = find_python().unwrap();
        let (_, _, c) = run_cmd(Path::new(&interp), &["-m", "venv", &venv], Duration::from_secs(60));
        if c != 0 { eprintln!("[SKIP] venv creation failed"); return; }

        let pip = venv_pip(&venv);
        // `six` is extremely small (~30KB) and has no dependencies.
        let (out, err, code) = run_cmd(
            &pip, &["install", "six", "--quiet"], Duration::from_secs(120)
        );
        assert_eq!(code, 0, "pip install six should succeed; stdout: {} stderr: {}", out, err);

        // Verify it's importable.
        let vpy = venv_python(&venv);
        let check = "import six; print(six.__version__)";
        let tmp = write_temp_script(check).unwrap();
        let (out2, _, code2) = run_cmd(&vpy, &[tmp.to_str().unwrap()], Duration::from_secs(10));
        std::fs::remove_file(&tmp).ok();
        assert_eq!(code2, 0, "import six should work after install");
        assert!(!out2.trim().is_empty(), "six.__version__ should not be empty");
    }

    #[test]
    fn test_pip_has_package_stdlib() {
        require_python!();
        // Standard library modules should always be findable via importlib.util.find_spec.
        let dir = TempDir::new().unwrap();
        let venv = dir.path().join("stdlibvenv").to_string_lossy().to_string();
        let interp = find_python().unwrap();
        let (_, _, c) = run_cmd(Path::new(&interp), &["-m", "venv", &venv], Duration::from_secs(60));
        if c != 0 { eprintln!("[SKIP] venv creation failed"); return; }

        let vpy = venv_python(&venv);
        for module in &["os", "sys", "json", "hashlib", "pathlib"] {
            let code = format!(
                "import importlib.util; exit(0 if importlib.util.find_spec('{}') else 1)",
                module
            );
            let tmp = write_temp_script(&code).unwrap();
            let (_, _, code_exit) = run_cmd(&vpy, &[tmp.to_str().unwrap()], Duration::from_secs(10));
            std::fs::remove_file(&tmp).ok();
            assert_eq!(code_exit, 0, "stdlib module '{}' should be importable", module);
        }
    }

    #[test]
    fn test_pip_install_requirements_content() {
        require_python!();
        let dir = TempDir::new().unwrap();
        let venv = dir.path().join("reqsvenv").to_string_lossy().to_string();
        let interp = find_python().unwrap();
        let (_, _, c) = run_cmd(Path::new(&interp), &["-m", "venv", &venv], Duration::from_secs(60));
        if c != 0 { eprintln!("[SKIP] venv creation failed"); return; }

        let pip = venv_pip(&venv);
        let req_content = "six\n";
        let tmp = std::env::temp_dir().join(format!("rcm_req_test_{}.txt", std::process::id()));
        std::fs::write(&tmp, req_content).unwrap();
        let tmp_str = tmp.to_string_lossy().to_string();
        let (_, err, code) = run_cmd(
            &pip, &["install", "-r", &tmp_str, "--quiet"], Duration::from_secs(120)
        );
        std::fs::remove_file(&tmp).ok();
        assert_eq!(code, 0, "pip install -r requirements should succeed; {}", err);
    }

    // ── Execute in venv ───────────────────────────────────────────────────────

    #[test]
    fn test_exec_in_venv_basic() {
        require_python!();
        let dir = TempDir::new().unwrap();
        let venv = dir.path().join("execvenv").to_string_lossy().to_string();
        let interp = find_python().unwrap();
        let (_, _, c) = run_cmd(Path::new(&interp), &["-m", "venv", &venv], Duration::from_secs(60));
        if c != 0 { eprintln!("[SKIP] venv creation failed"); return; }

        let vpy = venv_python(&venv);
        let code = "import sys; print(sys.prefix)";
        let tmp = write_temp_script(code).unwrap();
        let (out, _, code_exit) = run_cmd(&vpy, &[tmp.to_str().unwrap()], Duration::from_secs(10));
        std::fs::remove_file(&tmp).ok();
        assert_eq!(code_exit, 0);
        // sys.prefix should point to the venv directory.
        assert!(out.trim().contains("execvenv"),
            "sys.prefix '{}' should reference the venv dir", out.trim());
    }

    #[test]
    fn test_exec_in_venv_uses_installed_package() {
        require_python!();
        let dir = TempDir::new().unwrap();
        let venv = dir.path().join("pkgvenv").to_string_lossy().to_string();
        let interp = find_python().unwrap();
        let (_, _, c) = run_cmd(Path::new(&interp), &["-m", "venv", &venv], Duration::from_secs(60));
        if c != 0 { eprintln!("[SKIP] venv creation failed"); return; }

        // Install six.
        let pip = venv_pip(&venv);
        let (_, _, pip_code) = run_cmd(&pip, &["install", "six", "--quiet"], Duration::from_secs(120));
        if pip_code != 0 { eprintln!("[SKIP] pip install failed"); return; }

        // Execute code that uses six.
        let vpy = venv_python(&venv);
        let code = "import six; print(six.PY3)";
        let tmp = write_temp_script(code).unwrap();
        let (out, _, code_exit) = run_cmd(&vpy, &[tmp.to_str().unwrap()], Duration::from_secs(10));
        std::fs::remove_file(&tmp).ok();
        assert_eq!(code_exit, 0);
        assert!(out.trim() == "True", "six.PY3 should be True, got '{}'", out.trim());
    }

    // ── Persistent session ────────────────────────────────────────────────────

    #[test]
    fn test_session_lifecycle() {
        require_python!();
        let interp = find_python().unwrap();

        // Build the session loop script manually (mirrors what register_fn does).
        let loop_code = r#"
import sys, json, io, traceback, builtins
_globals = {'__builtins__': builtins}
while True:
    raw = sys.stdin.readline()
    if not raw: break
    try:
        req = json.loads(raw.strip())
        code = req.get('code', '')
        _buf = io.StringIO()
        _old = sys.stdout
        sys.stdout = _buf
        try:
            exec(compile(code, '<rcm>', 'exec'), _globals)
        finally:
            sys.stdout = _old
        output = _buf.getvalue()
        result = json.dumps({'output': output, 'error': None})
    except Exception as exc:
        sys.stdout = _old
        result = json.dumps({'output': '', 'error': traceback.format_exc()})
    _old.write(result + '\n')
    _old.flush()
"#;
        let tmp = write_temp_script(loop_code).unwrap();
        let mut child = std::process::Command::new(&interp)
            .arg(tmp.to_str().unwrap())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("should start session process");

        let mut stdin  = child.stdin.take().unwrap();
        let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());

        // Send a simple command.
        let msg = serde_json::to_string(&serde_json::json!({"code": "print('hello')"})).unwrap();
        stdin.write_all(format!("{}\n", msg).as_bytes()).unwrap();
        stdin.flush().unwrap();

        let mut line = String::new();
        use std::io::BufRead;
        stdout.read_line(&mut line).unwrap();
        let resp: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert!(resp["error"].is_null() || resp["error"].as_str() == Some(""),
            "no error expected: {:?}", resp["error"]);
        assert_eq!(resp["output"].as_str().unwrap().trim(), "hello");

        child.kill().ok();
        child.wait().ok();
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_session_state_persists_between_calls() {
        require_python!();
        let interp = find_python().unwrap();
        let loop_code = r#"
import sys, json, io, traceback, builtins
_globals = {'__builtins__': builtins}
while True:
    raw = sys.stdin.readline()
    if not raw: break
    try:
        req = json.loads(raw.strip())
        _buf = io.StringIO()
        _old = sys.stdout
        sys.stdout = _buf
        try:
            exec(compile(req.get('code',''), '<rcm>', 'exec'), _globals)
        finally:
            sys.stdout = _old
        result = json.dumps({'output': _buf.getvalue(), 'error': None})
    except Exception:
        sys.stdout = _old
        result = json.dumps({'output': '', 'error': traceback.format_exc()})
    _old.write(result + '\n')
    _old.flush()
"#;
        let tmp = write_temp_script(loop_code).unwrap();
        let mut child = std::process::Command::new(&interp)
            .arg(tmp.to_str().unwrap())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("should start session");

        let mut stdin  = child.stdin.take().unwrap();
        let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
        use std::io::BufRead;

        // First call: define a variable.
        let msg1 = serde_json::json!({"code": "x = 42"});
        stdin.write_all(format!("{}\n", msg1).as_bytes()).unwrap();
        stdin.flush().unwrap();
        let mut l1 = String::new();
        stdout.read_line(&mut l1).unwrap();

        // Second call: read the variable.
        let msg2 = serde_json::json!({"code": "print(x * 2)"});
        stdin.write_all(format!("{}\n", msg2).as_bytes()).unwrap();
        stdin.flush().unwrap();
        let mut l2 = String::new();
        stdout.read_line(&mut l2).unwrap();

        let resp2: serde_json::Value = serde_json::from_str(l2.trim()).unwrap();
        assert_eq!(resp2["output"].as_str().unwrap().trim(), "84",
            "x defined in call 1 should be accessible in call 2");

        child.kill().ok();
        child.wait().ok();
        std::fs::remove_file(&tmp).ok();
    }

    // ── RHAI engine integration ───────────────────────────────────────────────

    fn make_engine() -> rhai::Engine {
        let mut engine = rhai::Engine::new();
        super::register(&mut engine);
        engine
    }

    #[test]
    fn test_rhai_internal_python_find() {
        let engine = make_engine();
        let result: String = engine.eval(r#"internal_python_find()"#).unwrap();
        if find_python().is_none() {
            assert!(result.starts_with("Error"), "No Python → should return error, got '{}'", result);
        } else {
            assert!(!result.starts_with("Error"), "Python present → should return path, got '{}'", result);
            assert!(!result.is_empty());
        }
    }

    #[test]
    fn test_rhai_internal_python_version() {
        require_python!();
        let engine = make_engine();
        let result: String = engine.eval(r#"internal_python_version("")"#).unwrap();
        assert!(result.to_lowercase().contains("python"),
            "version string should mention Python: {}", result);
    }

    #[test]
    fn test_rhai_internal_python_exec_arithmetic() {
        require_python!();
        let engine = make_engine();
        let result: String = engine.eval(r#"internal_python_exec("print(6 * 7)")"#).unwrap();
        assert!(result.trim() == "42", "expected 42, got '{}'", result.trim());
    }

    #[test]
    fn test_rhai_internal_python_exec_json() {
        require_python!();
        let engine = make_engine();
        let result: String = engine.eval(
            r#"internal_python_exec_json("import json; print(json.dumps({'x': 99}))")"#
        ).unwrap();
        let v: serde_json::Value = serde_json::from_str(result.trim()).unwrap();
        assert_eq!(v["x"].as_i64(), Some(99));
    }

    #[test]
    fn test_rhai_venv_create_and_exec() {
        require_python!();
        let dir = TempDir::new().unwrap();
        let venv = dir.path().join("rhaivenv").to_string_lossy().to_string();
        let engine = make_engine();

        // Create venv.
        let create_result: String = engine.eval(
            &format!(r#"internal_venv_create("{}")"#, venv.replace('\\', "\\\\"))
        ).unwrap();
        if create_result.starts_with("Error") {
            eprintln!("[SKIP] venv creation failed (python3-venv not installed?): {}", create_result);
            return;
        }

        // venv should now exist.
        let exists: String = engine.eval(
            &format!(r#"internal_venv_exists("{}")"#, venv.replace('\\', "\\\\"))
        ).unwrap_or_default();
        assert!(exists.trim() == "true", "venv should exist after creation, got: {}", exists);

        // Execute code in it.
        let exec_result: String = engine.eval(
            &format!(r#"internal_python_in_venv("{}", "import sys; print('venv_ok')")"#,
                venv.replace('\\', "\\\\"))
        ).unwrap();
        assert!(exec_result.trim() == "venv_ok", "got '{}'", exec_result.trim());
    }

    #[test]
    fn test_rhai_pip_list_is_json_array() {
        require_python!();
        let dir = TempDir::new().unwrap();
        let venv = dir.path().join("piplistvenv").to_string_lossy().to_string();
        let interp = find_python().unwrap();
        let (_, _, c) = run_cmd(Path::new(&interp), &["-m", "venv", &venv], Duration::from_secs(60));
        if c != 0 { eprintln!("[SKIP] venv creation failed"); return; }

        let engine = make_engine();
        let result: String = engine.eval(
            &format!(r#"internal_pip_list("{}")"#, venv.replace('\\', "\\\\"))
        ).unwrap();
        let v: serde_json::Value = serde_json::from_str(result.trim()).unwrap();
        assert!(v.is_array(), "pip list should be JSON array, got: {}", result);
    }

    #[test]
    fn test_rhai_python_call_with_json_input() {
        require_python!();
        let dir = TempDir::new().unwrap();
        let venv = dir.path().join("callvenv").to_string_lossy().to_string();
        let interp = find_python().unwrap();
        let (_, _, c) = run_cmd(Path::new(&interp), &["-m", "venv", &venv], Duration::from_secs(60));
        if c != 0 { eprintln!("[SKIP] venv creation failed"); return; }

        let engine = make_engine();
        let code = r#"import json; print(json.dumps({'sum': sum(rcm_input['numbers'])}))"#;
        let input = r#"{"numbers": [1, 2, 3, 4, 5]}"#;
        let result: String = engine.eval(&format!(
            r#"internal_python_call("{}", "{}", "{}")"#,
            venv.replace('\\', "\\\\"),
            input.replace('"', "\\\""),
            code.replace('"', "\\\"")
        )).unwrap();
        let v: serde_json::Value = serde_json::from_str(result.trim()).unwrap();
        assert_eq!(v["sum"].as_i64(), Some(15));
    }

    #[test]
    fn test_rhai_nonexistent_venv_error() {
        let engine = make_engine();
        let result: String = engine.eval(
            r#"internal_python_in_venv("/this/does/not/exist/venv", "print('hi')")"#
        ).unwrap();
        assert!(result.starts_with("Error"),
            "non-existent venv should return Error, got '{}'", result);
    }

    #[test]
    fn test_rhai_session_start_stop() {
        require_python!();
        let engine = make_engine();

        // Start session with system Python.
        let sid: String = engine.eval(r#"internal_python_session_start("")"#).unwrap();
        assert!(!sid.starts_with("Error"), "session start should succeed: {}", sid);
        assert!(!sid.is_empty());

        // Execute something in the session.
        let out: String = engine.eval(
            &format!(r#"internal_python_session_exec("{}", "print(1+1)")"#, sid)
        ).unwrap();
        assert!(out.trim() == "2", "expected '2', got '{}'", out.trim());

        // List should contain the session.
        let list: String = engine.eval(r#"internal_python_session_list()"#).unwrap();
        assert!(list.contains(&sid), "session list should contain session id");

        // Stop.
        let stop: String = engine.eval(
            &format!(r#"internal_python_session_stop("{}")"#, sid)
        ).unwrap();
        assert!(stop.contains("stopped"), "stop should confirm: {}", stop);
    }

    #[test]
    fn test_rhai_session_state_persists() {
        require_python!();
        let engine = make_engine();
        let sid: String = engine.eval(r#"internal_python_session_start("")"#).unwrap();
        if sid.starts_with("Error") { eprintln!("[SKIP] session start failed: {}", sid); return; }

        // Set a variable in one exec.
        let _ = engine.eval::<String>(
            &format!(r#"internal_python_session_exec("{}", "counter = 100")"#, sid)
        ).unwrap();

        // Read it in another exec.
        let out: String = engine.eval(
            &format!(r#"internal_python_session_exec("{}", "print(counter + 1)")"#, sid)
        ).unwrap();
        assert!(out.trim() == "101", "cross-call state: expected 101, got '{}'", out.trim());

        let _ = engine.eval::<String>(
            &format!(r#"internal_python_session_stop("{}")"#, sid)
        ).unwrap();
    }

    #[test]
    fn test_rhai_pbs_url_structure() {
        // This tests the URL resolution logic without downloading.
        // It does make a GitHub API request, so it's gated on network availability.
        // Skip gracefully if we get a connection error.
        let engine = make_engine();
        let url: String = engine.eval(r#"internal_python_pbs_url()"#).unwrap();
        if url.starts_with("Error") {
            eprintln!("[SKIP] GitHub API unavailable: {}", url);
            return;
        }
        assert!(url.starts_with("https://"), "URL should be HTTPS: {}", url);
        assert!(url.contains("python-build-standalone"), "URL should reference pbs: {}", url);
        assert!(url.ends_with(".tar.gz"), "URL should be a tar.gz: {}", url);
        // The URL should match our platform suffix.
        let suffix = pbs_asset_suffix();
        assert!(url.ends_with(suffix), "URL '{}' should end with '{}'", url, suffix);
    }
}
