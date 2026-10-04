// mem.rhai - process memory read/write/search helper.
//
// Usage:
//   mem read    <pid> <addr_hex> <size>     -> hex bytes (Windows + Linux)
//   mem write   <pid> <addr_hex> <data_hex> -> byte count (Windows only)
//   mem regions <pid>                       -> JSON region list (Windows + Linux)
//   mem scan    <pid> <pattern_hex>         -> hit addresses (Linux only)
//
// Platform limits come from the API itself; unsupported calls return their
// own "Error: ... not supported" text, which this script passes through.

if args.len() < 2 {
    return "Usage: mem <read|write|regions|scan> <pid> [addr_hex|pattern_hex] [size|data_hex]";
}
let cmd = args[0];
let pid = args[1];

if cmd == "read" {
    if args.len() < 4 { return "Usage: mem read <pid> <addr_hex> <size>"; }
    let r = internal_mem_read(pid, args[2], args[3].to_int());
    if r.starts_with("Error:") { return r; }
    return "read " + (r.len / 2) + " bytes from pid " + pid + " @ " + args[2] + ": " + r;
}

if cmd == "write" {
    if args.len() < 4 { return "Usage: mem write <pid> <addr_hex> <data_hex>"; }
    return internal_mem_write(pid, args[2], args[3]);
}

if cmd == "regions" {
    let r = internal_mem_regions(pid);
    if r.starts_with("Error:") { return r; }
    return r;
}

if cmd == "scan" {
    if args.len() < 3 { return "Usage: mem scan <pid> <pattern_hex>"; }
    return internal_mem_scan(pid, args[2]);
}

return "Usage: mem <read|write|regions|scan> <pid> [addr_hex|pattern_hex] [size|data_hex]";
