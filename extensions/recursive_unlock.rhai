print_log("Starting Recursive Decryption...");

// 1. Check Arguments
if args.len() < 2 {
    return "Usage: extension load recursive_unlock <directory> <hex_key>";
}

let target_dir = args[0];
let key = args[1];

print_log("Target Directory: " + target_dir);
print_log("Using Key: " + key);

// 2. Call Native Rust Function
// This runs purely in memory on the client. It walks the directory tree,
// reads every file, attempts AES-256-GCM decryption, and overwrites 
// the file with the plaintext if successful.
let result = internal_decrypt_recursive(target_dir, key);

return result;
