print_log("Starting System Survey...");

// 1. Get Basic Metrics (Host, OS, RAM)
let basic_info = internal_sysinfo();

// 2. Get Environment Context
let user = internal_env("USERNAME");
if user == "Not Found" {
    user = internal_env("USER"); // Linux fallback
}

let domain = internal_env("USERDOMAIN");
let path = internal_env("PATH");

// 3. Construct Report
let report = "=== CLIENT TELEMETRY ===\n";
report += basic_info + "\n";
report += "------------------------\n";
report += "Current User: " + user + "\n";
if domain != "Not Found" {
    report += "Domain: " + domain + "\n";
}
report += "Path Length: " + path.len() + " chars\n";

// 4. (Optional) Run Safe Shell Command for IP info
// This uses the 'exec_os' helper if you kept it in client_scripting.rs
// let ip_data = exec_os("ipconfig");
// report += "\n[Network Config]\n" + ip_data;

return report;
