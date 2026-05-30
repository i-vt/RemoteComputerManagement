// Usage: extension load inject_module_stomping <pid> <dll_name> <payload>
// Example: ... 1234 amsi.dll ...

if args.len() < 3 { return "Usage: <pid> <dll_name> <payload>"; }

print_log("Forcing load of " + args[1] + " into PID " + args[0] + " and stomping...");
return native_inject_module_stomping(args[0], args[1], args[2]);
