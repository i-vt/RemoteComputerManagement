// py_bridge_showcase.rhai — agent-side extension
//
// A guided tour of the entire Python bridge (all 35 bindings in
// src/agent/scripting/python.rs). Each section is independent: a failure in
// one is reported inline and does not abort the rest.
//
// Args:
//   args[0] = venv path      (default "/tmp/.rcm_showcase_venv")
//   args[1] = sections       ("all" = 1-8, or a comma list, e.g. "1,3,4,7")
//   args[2] = "install"      also run section 10 (interpreter bootstrap)
//   args[3] = "offensive"    also run section 9 (offensive packages)
// Sections 9 and 10 are heavy/networked, so they are gated behind their
// flags even under "all". Section 99 deletes the demo venv (not in "all").
//
// Examples:
//   ext:load <b64>                                   # sections 1-8
//   ext:load <b64> /var/tmp/sv all offensive         # + offensive minimal tier
//   ext:load <b64> /var/tmp/sv 99                    # cleanup
//
// Run it through the py_showcase_orchestrator module to see how a
// server-side module delegates all Python work to the agent.

// ── Helpers ───────────────────────────────────────────────────────────────────

// The bridge never throws — it reports problems as strings. One check
// covers every call in this file.
fn ok(r) { !r.starts_with("Error") && !r.starts_with("PythonError") }

fn clip(s) {
    if s.len() > 300 { s.sub_string(0, 300) + " ...[truncated]" } else { s }
}

fn banner(title) { "\n---------- " + title + " ----------\n" }

// ── Section 1: discovery ──────────────────────────────────────────────────────
// internal_python_find / internal_python_version / internal_python_pbs_url

fn sec_discovery() {
    let out = banner("1. DISCOVERY");
    let interp = internal_python_find();
    out += "python_find        -> " + interp + "\n";
    if ok(interp) {
        out += "python_version     -> " + internal_python_version(interp) + "\n";
    } else {
        out += "python_version     -> skipped (none on PATH)\n";
    }
    // Where a portable runtime would come from if bootstrap had to download one.
    out += "pbs_url            -> " + clip(internal_python_pbs_url()) + "\n";
    out
}

// ── Section 2: basic execution (system interpreter) ───────────────────────────
// internal_python_exec / internal_python_exec_json / error strings

fn sec_exec_system(interp_ok) {
    let out = banner("2. EXEC (system python)");
    if !interp_ok {
        return out + "skipped: no interpreter on PATH (rerun with the 'install' flag)\n";
    }

    let r1 = internal_python_exec("print('hello from the bridge'); print('math: 6*7 =', 6*7)");
    out += "exec               -> " + clip(r1) + "\n";

    // JSON-out variant: Python prints ONE JSON value, Rhai gets it verbatim.
    let r2 = internal_python_exec_json(
        "import json; print(json.dumps({'answer': 42, 'ok': True, 'items': [1, 2, 3]}))");
    out += "exec_json          -> " + r2 + "\n";
    out += "  json_get answer  -> " + internal_json_get(r2, "answer") + "\n";
    out += "  json_get items.2 -> " + internal_json_get(r2, "items.2") + "\n";

    // Errors come back as data, not crashes — same check as `ok()` uses.
    let r3 = internal_python_exec("this is not valid python");
    out += "bad code           -> " + clip(r3) + "   (note: no 'Error' prefix — " +
           "exec returns combined stderr; design your checks accordingly)\n";
    out
}

// ── Section 3: venv lifecycle ─────────────────────────────────────────────────
// internal_venv_exists / internal_venv_create_with / internal_venv_python_path
// (internal_venv_create = same but insists on PATH python; _delete in sec 99)

fn sec_venv(venv, interp) {
    let out = banner("3. VENV LIFECYCLE");
    let ex = internal_venv_exists(venv);
    out += "venv_exists        -> " + ex + "\n";
    if ex != "true" {
        let r = internal_venv_create_with(interp, venv);
        out += "venv_create_with   -> " + clip(r) + "\n";
    }
    out += "venv_python_path   -> " + internal_venv_python_path(venv) + "\n";
    out
}

// ── Section 4: pip on the fly ─────────────────────────────────────────────────
// internal_pip_has_package / _install / _install_requirements /
// _uninstall / _list / _freeze

fn sec_pip(venv) {
    let out = banner("4. PIP ON THE FLY");

    // Idempotent install: check first, install only when missing.
    if internal_pip_has_package(venv, "six") == "true" {
        out += "six                -> already installed (has_package skip)\n";
    } else {
        out += "pip_install        -> " +
               clip(internal_pip_install(venv, "[\"six>=1.16\"]")) + "\n";
    }

    // pip_list returns a JSON array of {name, version}; index into it.
    let lst = internal_pip_list(venv);
    out += "pip_list[0]        -> " + internal_json_get(lst, "0.name") +
           " " + internal_json_get(lst, "0.version") + "\n";

    // pip_freeze in requirements format; grep it for our package.
    out += "pip_freeze grep    -> " + clip(internal_grep(internal_pip_freeze(venv), "six")) + "\n";

    // Requirements CONTENT (not a path) — real requirements syntax works,
    // including --index-url / --extra-index-url / -f lines for mirrors.
    out += "pip_req_install    -> " +
           clip(internal_pip_install_requirements(venv, "colorama==0.4.6\n")) + "\n";
    out += "has colorama       -> " + internal_pip_has_package(venv, "colorama") + "\n";
    out += "pip_uninstall      -> " +
           clip(internal_pip_uninstall(venv, "[\"colorama\"]")) + "\n";
    out += "has colorama       -> " + internal_pip_has_package(venv, "colorama") + "\n";
    out
}

// ── Section 5: running inside the venv ────────────────────────────────────────
// internal_python_in_venv / _in_venv_json / _in_venv_timeout

fn sec_run_in_venv(venv) {
    let out = banner("5. RUN IN VENV");
    out += "in_venv            -> " + clip(internal_python_in_venv(venv,
        "import sys; print('exe   :', sys.executable); print('prefix:', sys.prefix)")) + "\n";

    let j = internal_python_in_venv_json(venv,
        "import json, sys; print(json.dumps({'exe': sys.executable, 'ver': sys.version.split()[0]}))");
    out += "in_venv_json       -> " + j + "\n";
    out += "  json_get ver     -> " + internal_json_get(j, "ver") + "\n";

    // Timeout variant: the child is killed at the deadline and whatever it
    // managed to print is returned — here 'start' survives, the rest doesn't.
    let t = internal_python_in_venv_timeout(venv,
        "import time; print('start', flush=True); time.sleep(30)", 2);
    out += "in_venv_timeout(2) -> '" + t + "'  (killed mid-run; partial stdout kept)\n";
    out
}

// ── Section 6: structured JSON I/O ────────────────────────────────────────────
// internal_python_call — Rhai passes JSON in as `rcm_input`, Python prints
// JSON back. The cleanest way to move data both directions.

fn sec_json_io(venv) {
    let out = banner("6. STRUCTURED JSON I/O (python_call)");
    let input = "{\"numbers\": [10, 20, 30]}";
    let code = "import json; ns = rcm_input['numbers']; " +
               "print(json.dumps({'total': sum(ns), 'avg': sum(ns) / len(ns)}))";
    let res = internal_python_call(venv, input, code);
    out += "python_call        -> " + res + "\n";
    out += "  json_get total   -> " + internal_json_get(res, "total") + "\n";
    out += "  json_get avg     -> " + internal_json_get(res, "avg") + "\n";
    out
}

// ── Section 7: persistent sessions ────────────────────────────────────────────
// internal_python_session_start / _exec / _list / _stop
// One live interpreter, state carries across calls, JSON-RPC over stdin.

fn sec_sessions(venv) {
    let out = banner("7. PERSISTENT SESSIONS");
    let sid = internal_python_session_start(venv);
    if !ok(sid) {
        return out + "session_start      -> " + sid + "\n";
    }
    out += "session_start      -> " + sid.sub_string(0, 8) + "...\n";

    // State persists between execs: set in one call, read in the next.
    internal_python_session_exec(sid, "rcm_state = {'counter': 41}");
    let r1 = internal_python_session_exec(sid, "print('counter =', rcm_state['counter'] + 1)");
    out += "exec (state)       -> " + r1 + "\n";

    // Exceptions surface as 'PythonError:' strings and DON'T kill the session.
    let r2 = internal_python_session_exec(sid, "print(1 / 0)");
    out += "exec (1/0)         -> " + clip(r2) + "\n";

    let r3 = internal_python_session_exec(sid, "print('session survived the exception')");
    out += "exec (after error) -> " + r3 + "\n";

    out += "session_list       -> " + internal_python_session_list() + "\n";
    out += "session_stop       -> " + internal_python_session_stop(sid) + "\n";
    out
}

// ── Section 8: script files ───────────────────────────────────────────────────
// internal_python_exec_file (system python) / internal_python_file_in_venv

fn sec_files(venv, interp_ok) {
    let out = banner("8. SCRIPT FILES");
    let path = "rcm_showcase_fib.py";
    let src = "import json\n" +
              "def fib(n):\n" +
              "    a, b = 0, 1\n" +
              "    for _ in range(n):\n" +
              "        a, b = b, a + b\n" +
              "    return a\n" +
              "print(json.dumps({'fib_10': fib(10)}))\n";
    out += "write file         -> " + internal_write(path, src) + "\n";
    if interp_ok {
        out += "exec_file (system) -> " + clip(internal_python_exec_file(path)) + "\n";
    }
    out += "file_in_venv       -> " + clip(internal_python_file_in_venv(venv, path)) + "\n";
    out += "delete file        -> " + internal_delete(path) + "\n";
    out
}

// ── Section 9: offensive package tiers (gated) ────────────────────────────────
// internal_python_offensive_check / internal_python_install_offensive

fn sec_offensive(venv) {
    let out = banner("9. OFFENSIVE PACKAGE TIERS");
    out += "check (before)     -> " + internal_python_offensive_check(venv) + "\n";
    // minimal = requests+cryptography+dnspython, standard + impacket/ldap3/
    // paramiko/scapy, full + bloodhound/pypykatz/certipy-ad/pwntools.
    out += "install minimal    -> " + clip(internal_python_install_offensive(venv, "minimal")) + "\n";
    out += "check (after)      -> " + internal_python_offensive_check(venv) + "\n";
    out
}

// ── Section 10: interpreter bootstrap (gated) ─────────────────────────────────
// internal_python_ensure / internal_python_ensure_venv / internal_python_bootstrap
// Force-variants internal_python_install_portable(dir) and
// internal_python_install_system() skip the cheap paths and always act —
// commented out here because they download/install unconditionally.

fn sec_bootstrap(install_dir, venv) {
    let out = banner("10. INTERPRETER BOOTSTRAP");
    let interp = internal_python_ensure(install_dir);
    out += "python_ensure      -> " + clip(interp) + "\n";
    if !ok(interp) { return out; }

    // Make sure the OS venv module exists (installs python3-venv via the
    // package manager when missing).
    out += "ensure_venv        -> " + internal_python_ensure_venv(interp) + "\n";

    // One-shot: interpreter + venv + pip upgrade (+ packages if the JSON
    // array is non-empty — "" skips). Returns the venv's python path.
    let boot = venv + "_boot";
    let bp = internal_python_bootstrap(install_dir, boot, "");
    out += "bootstrap          -> " + clip(bp) + "\n";
    out += "bootstrap cleanup  -> " + internal_venv_delete(boot) + "\n";
    out
}

// ── Section 99: cleanup ───────────────────────────────────────────────────────

fn sec_cleanup(venv) {
    let out = banner("99. CLEANUP");
    out += "venv_delete        -> " + internal_venv_delete(venv) + "\n";
    out
}

// ── Entry point ───────────────────────────────────────────────────────────────

print_python_log("py_bridge_showcase: start");

let venv     = "/tmp/.rcm_showcase_venv";
let sections = "all";
let do_install   = false;
let do_offensive = false;
if args.len() > 0 { venv     = args[0]; }
if args.len() > 1 { sections = args[1]; }
if args.len() > 2 && args[2] == "install"   { do_install   = true; }
if args.len() > 3 && args[3] == "offensive" { do_offensive = true; }

let sel = "," + sections + ",";
let all = sections == "all";
let s1  = all || sel.contains(",1,");
let s2  = all || sel.contains(",2,");
let s3  = all || sel.contains(",3,");
let s4  = all || sel.contains(",4,");
let s5  = all || sel.contains(",5,");
let s6  = all || sel.contains(",6,");
let s7  = all || sel.contains(",7,");
let s8  = all || sel.contains(",8,");
// 9 and 10 are excluded from "all" unless their flags are passed.
let s9  = do_offensive && (all || sel.contains(",9,"));
let s10 = do_install   && (all || sel.contains(",10,"));
let s99 = sel.contains(",99,");

let interp = internal_python_find();
let interp_ok = ok(interp);

let needs_venv = s4 || s5 || s6 || s7 || s8 || s9;
let venv_ok = true;
if needs_venv {
    if !interp_ok {
        venv_ok = false;
    } else if internal_venv_exists(venv) != "true" {
        let made = internal_venv_create_with(interp, venv);
        print_python_log("py_bridge_showcase: " + made);
        if !ok(made) { venv_ok = false; }
    }
}

let report = "=== PYTHON BRIDGE SHOWCASE ===\n";
report += "venv=" + venv + " sections=" + sections +
          " install=" + do_install.to_string() +
          " offensive=" + do_offensive.to_string() + "\n";

if s1  { report += sec_discovery(); }
if s2  { report += sec_exec_system(interp_ok); }
if s3  { report += sec_venv(venv, interp); }
if s4 && venv_ok { report += sec_pip(venv); }
else if s4 { report += banner("4. PIP ON THE FLY") + "skipped: no usable interpreter/venv\n"; }
if s5 && venv_ok { report += sec_run_in_venv(venv); }
if s6 && venv_ok { report += sec_json_io(venv); }
if s7 && venv_ok { report += sec_sessions(venv); }
if s8 && venv_ok { report += sec_files(venv, interp_ok); }
else if s8 { report += banner("8. SCRIPT FILES") + "skipped: no usable venv\n"; }
if s9  { report += sec_offensive(venv); }
if s10 { report += sec_bootstrap("/tmp/.rcm_showcase_runtime", venv); }
if s99 { report += sec_cleanup(venv); }

if needs_venv && !venv_ok {
    report += "\nNOTE: venv-dependent sections were skipped. Either install " +
              "Python on the target or rerun with args[2] = \"install\".\n";
}

print_python_log("py_bridge_showcase: done");
report
