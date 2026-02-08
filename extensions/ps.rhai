// extensions/ps.rhai
print_log("Enumerating Processes...");

// 1. Get raw list from Rust native helper
// Returns string format: "PID|Name\nPID|Name..."
let raw_list = internal_procs();

let lines = raw_list.split('\n');
let output = "=== PROCESS LIST ===\n";
output += " PID      | Name\n";
output += "----------|------------------------\n";

let common_targets = ["notepad.exe", "explorer.exe", "calc.exe", "msedge.exe", "cmd.exe", "powershell.exe"];
let suggestions = "";

for line in lines {
    let parts = line.split('|');
    
    if parts.len() == 2 {
        let pid = parts[0];
        let name = parts[1];
        
        // Basic Formatting: Pad PID to 8 chars
        let padding = "        "; 
        let pid_display = pid + padding;
        pid_display = pid_display.sub_string(0, 8);
        
        output += " " + pid_display + " | " + name + "\n";

        // Check for interesting injection targets
        for target in common_targets {
            // Case-insensitive check (simplified)
            if name.to_lower() == target {
                suggestions += "[*] Found Target: " + name + " (PID: " + pid + ")\n";
            }
        }
    }
}

output += "--------------------------------\n";

if suggestions.len() > 0 {
    output += "\n[!] Potential Injection Targets:\n" + suggestions;
}

return output;
