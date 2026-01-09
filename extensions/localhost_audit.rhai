print_log("Starting Localhost Web Audit...");

// Common ports for internal dashboards/services
let ports = ["80", "8080", "8000", "8081", "3000", "5000", "9000", "9200"];
let results = "=== LOCAL WEB SERVICES ===\n";
let found = 0;

for port in ports {
    let url = "http://127.0.0.1:" + port;
    
    // Attempt HTTP GET
    let resp = internal_http_get(url);
    
    if resp.contains("Request Error") {
        // Port is closed or not HTTP
    } else {
        found = found + 1;
        // Simple heuristic: get length and first 50 chars
        let preview = resp;
        if resp.len() > 50 {
            preview = resp.sub_string(0, 50); // Rhai string slice
        }
        results = results + "[+] OPEN: " + url + " (Size: " + resp.len() + ")\n    Preview: " + preview + "...\n";
    }
}

if found == 0 {
    return "No common internal web services found.";
}

return results;
