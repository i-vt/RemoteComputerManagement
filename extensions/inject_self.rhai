// Usage: extension load inject_self <b64_shellcode>
// Best for: Testing payload logic without leaving process

if args.len() < 1 { return "Usage: <payload>"; }
print_log("Injecting into SELF...");
return native_inject_self(args[0]);
