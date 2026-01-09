print_log("Starting Decryption...");

// Check Arguments
if args.len() < 2 {
    return "Usage: extension load decrypt_test <target_file> <hex_key>";
}

let target_file = args[0];
let key = args[1];

// Call Native Decrypt Function
let result = internal_decrypt_file(target_file, key);

if result == "Success" {
    return "File decrypted successfully: " + target_file;
} else {
    return "Operation Failed: " + result;
}
