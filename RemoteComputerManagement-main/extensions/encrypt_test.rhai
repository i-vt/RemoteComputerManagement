print_log("Starting Encryption Test...");

if args.len() == 0 {
    return "Usage: encrypt_test <target_file>";
}

let target_file = args[0];

// 1. Generate Session Key
let key = internal_keygen();
print_log("Generated Session Key: " + key);

// 2. Perform Encryption
// Note: In a real scenario, you would exfiltrate 'key' securely before this step.
let result = internal_encrypt_file(target_file, key);

if result == "Success" {
    return "File encrypted successfully: " + target_file + "\nKey: " + key;
} else {
    return "Operation Failed: " + result;
}
