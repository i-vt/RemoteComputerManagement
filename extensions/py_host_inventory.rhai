// py_host_inventory.rhai — agent-side extension (runs inside the agent)
//
// Collects a full host inventory through a real CPython subprocess (the
// Python bridge, src/agent/scripting/python.rs). Python is used purely as a
// portable stdlib toolkit here — no pip packages are needed.
//
// Usage (args array):
//   args[0] = venv path      (optional, default "/tmp/.rcm_inv_venv")
//   args[1] = report label   (optional, default "default"; used as the
//                             state-store key suffix and report header)
//
// Examples:
//   ext:load <base64(script)>                              -> defaults
//   ext:load <base64(script)> /var/tmp/inv prod-box-01    -> custom venv + label
//
// What it demonstrates:
//   • interpreter bootstrap   (internal_python_ensure)
//   • venv lifecycle          (internal_venv_exists / internal_venv_create_with)
//   • code exec with JSON out (internal_python_in_venv_json)
//   • JSON field extraction   (internal_json_get, dotted paths)
//   • cross-run mutex         (internal_mutex_create / internal_mutex_release)
//   • shared KV state         (internal_state_set / internal_state_get)
//   • bridge logging          (print_python_log)
//
// The collected JSON is cached in the agent state store under
// "py_host_inventory.<label>.json" so later extensions can reuse it without
// re-running Python.

// ── Core logic ────────────────────────────────────────────────────────────────

fn collect(venv, label) {
    // 1. Make sure some Python exists on the target. Checks PATH first, then
    //    an existing portable runtime, then the OS package manager, then
    //    downloads python-build-standalone into install_dir.
    print_python_log("py_host_inventory: ensuring interpreter");
    let interp = internal_python_ensure("/tmp/.rcm_py_runtime");
    if interp.starts_with("Error") {
        return "Error ensuring Python: " + interp;
    }

    // 2. Reuse the venv if one is already valid; otherwise create it with the
    //    interpreter we just ensured (create_with, because a portable runtime
    //    is not necessarily on PATH for the plain internal_venv_create).
    if internal_venv_exists(venv) != "true" {
        print_python_log("py_host_inventory: creating venv at " + venv);
        let made = internal_venv_create_with(interp, venv);
        if made.starts_with("Error") {
            return made;
        }
    }

    // 3. Run the inventory. The Python side prints exactly ONE JSON line to
    //    stdout; internal_python_in_venv_json returns just that line.
    //    stdlib only, single-quoted strings only (this text lives inside a
    //    Rhai string literal), no backslashes (chr(92) is used for Windows).
    let py_code = "
import json, os, platform, shutil, socket

def read_file(path):
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except Exception:
        return None

info = {}
info['hostname'] = socket.gethostname()
info['user'] = os.environ.get('USER') or os.environ.get('USERNAME') or 'unknown'
info['os'] = platform.platform()
info['arch'] = platform.machine()
info['cpus'] = os.cpu_count() or 0
info['python'] = platform.python_version()
info['cwd'] = os.getcwd()

# Uptime (Linux /proc, best-effort elsewhere -> -1)
up = read_file('/proc/uptime')
info['uptime_sec'] = int(float(up.split()[0])) if up else -1

# Total RAM (POSIX sysconf, best-effort elsewhere -> -1)
try:
    info['mem_total_mb'] = int(os.sysconf('SC_PHYS_PAGES') * os.sysconf('SC_PAGE_SIZE') / 1048576)
except Exception:
    info['mem_total_mb'] = -1

# Primary disk usage (C:\\ on Windows via chr(92), / elsewhere)
root = '/' if os.name != 'nt' else 'C:' + chr(92)
try:
    du = shutil.disk_usage(root)
    info['disk_total_gb'] = round(du.total / 1073741824, 1)
    info['disk_used_pct'] = round(100.0 * du.used / du.total, 1)
except Exception:
    info['disk_total_gb'] = -1
    info['disk_used_pct'] = -1

# Primary IP: UDP connect sends no traffic, only picks the egress interface;
# falls back to hostname resolution, then loopback.
info['primary_ip'] = '127.0.0.1'
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    s.connect(('192.0.2.1', 80))
    info['primary_ip'] = s.getsockname()[0]
    s.close()
except Exception:
    try:
        info['primary_ip'] = socket.gethostbyname(socket.gethostname())
    except Exception:
        pass

# Listening TCP ports from /proc/net/tcp{,6} (state 0A = LISTEN); the hex
# port is the second half of the local_address field. Empty elsewhere.
listeners = []
try:
    for path in ['/proc/net/tcp', '/proc/net/tcp6']:
        with open(path, 'r') as f:
            next(f)
            for line in f:
                parts = line.split()
                if parts[3] == '0A':
                    listeners.append(int(parts[1].split(':')[1], 16))
except Exception:
    pass
info['listen_count'] = len(set(listeners))
info['listen_ports'] = sorted(set(listeners))[:32]

print(json.dumps(info))
";

    print_python_log("py_host_inventory: running inventory in " + venv);
    let out = internal_python_in_venv_json(venv, py_code);
    if out.starts_with("Error") {
        return "Error running inventory Python: " + out;
    }

    // 4. Cache the raw JSON for other extensions on this agent.
    internal_state_set("py_host_inventory." + label + ".json", out);

    // 5. Render the human-readable report.
    let report = "=== HOST INVENTORY [" + label + "] ===\n";
    report += "Hostname    : " + internal_json_get(out, "hostname") + "\n";
    report += "User        : " + internal_json_get(out, "user") + "\n";
    report += "OS          : " + internal_json_get(out, "os") + "\n";
    report += "Arch        : " + internal_json_get(out, "arch") + "\n";
    report += "CPUs        : " + internal_json_get(out, "cpus") + "\n";
    report += "Python      : " + internal_json_get(out, "python") + "\n";
    report += "Primary IP  : " + internal_json_get(out, "primary_ip") + "\n";
    report += "CWD         : " + internal_json_get(out, "cwd") + "\n";

    let up = internal_json_get(out, "uptime_sec");
    if up != "-1" {
        report += "Uptime      : " + up + " s\n";
    }

    let mem = internal_json_get(out, "mem_total_mb");
    if mem != "-1" {
        report += "Memory      : " + mem + " MB total\n";
    }

    let disk = internal_json_get(out, "disk_total_gb");
    if disk != "-1" {
        report += "Disk        : " + disk + " GB, "
                + internal_json_get(out, "disk_used_pct") + "% used\n";
    }

    report += "Listeners   : " + internal_json_get(out, "listen_count")
            + " (" + internal_json_get(out, "listen_ports") + ")\n";

    report += "Run ID      : " + internal_uuid() + "\n";
    report += "(raw JSON cached in state key py_host_inventory." + label + ".json)";
    report
}

// ── Entry point ───────────────────────────────────────────────────────────────

print_python_log("py_host_inventory: start");

let venv  = "/tmp/.rcm_inv_venv";
let label = "default";
if args.len() > 0 { venv  = args[0]; }
if args.len() > 1 { label = args[1]; }

// Cross-run mutex: two operators deploying this extension at once would
// otherwise race the venv creation. internal_mutex_create returns the
// strings "true"/"false" (lockfile under the temp dir on Linux/macOS,
// CreateMutexA on Windows).
if internal_mutex_create("py_host_inventory") != "true" {
    return "Error: another py_host_inventory run is in progress on this agent";
}

let report = collect(venv, label);

internal_mutex_release("py_host_inventory");
report
