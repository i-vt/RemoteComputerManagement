print_log("Starting Internal Network Scan...");

// 1. Validate Arguments
if args.len() == 0 {
    return "Error: Missing argument. Usage: extension load scanner http://192.168.1.";
}

let base_url = args[0];
let results = "=== SCAN RESULTS (" + base_url + "*) ===\n";
let found_count = 0;

// 2. Loop through IP range (1 to 20 for speed in this demo)
// You can increase this range, but remember it runs sequentially.
for i in 1..21 {
    let target = base_url + i;
    
    // Call Native Rust HTTP Client
    let resp = internal_http_get(target);
    
    // 3. Analyze Result
    if resp.contains("Request Error") {
        // Host is likely down or port closed
    } else {
        found_count += 1;
        
        // Grab a snippet of the page title or content
        let preview = resp;
        if resp.len() > 50 {
            preview = resp.sub_string(0, 50);
        }
        
        results += "[+] ALIVE: " + target + "\n";
        results += "    Size: " + resp.len() + " bytes\n";
        results += "    Preview: " + preview + "...\n";
    }
}

if found_count == 0 {
    results += "No active web services found in range .1 - .20\n";
}

return results;
