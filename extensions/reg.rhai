// reg.rhai - Windows registry read/write helper.
//
// Usage:
//   reg read   <hive> <key> <value_name>          -> value as string
//   reg write  <hive> <key> <value_name> <data>   -> REG_SZ write
//   reg delval <hive> <key> <value_name>
//   reg delkey <hive> <parent_key> <subkey>
//   reg lskeys <hive> <key>                       -> JSON array of subkeys
//   reg lsvals <hive> <key>                       -> JSON array of values
//
// hive: HKCU | HKLM | HKCR | HKU. Writes are REG_SZ only (API limitation,
// stated here so operators do not expect DWORD/BINARY).

// Registry is Windows-only; bail early with an honest message elsewhere.
if internal_env("OS") != "Windows_NT" {
    return "reg targets Windows hosts only (registry is Windows-only).";
}

if args.len() < 1 {
    return "Usage: reg <read|write|delval|delkey|lskeys|lsvals> <hive> <key> [value_name] [data]";
}
let cmd = args[0];

if cmd == "read" {
    if args.len() < 4 { return "Usage: reg read <hive> <key> <value_name>"; }
    return internal_reg_read(args[1], args[2], args[3]);
}

if cmd == "write" {
    if args.len() < 5 { return "Usage: reg write <hive> <key> <value_name> <data>"; }
    return internal_reg_write(args[1], args[2], args[3], args[4]);
}

if cmd == "delval" {
    if args.len() < 4 { return "Usage: reg delval <hive> <key> <value_name>"; }
    return internal_reg_delete_value(args[1], args[2], args[3]);
}

if cmd == "delkey" {
    if args.len() < 4 { return "Usage: reg delkey <hive> <parent_key> <subkey>"; }
    return internal_reg_delete_key(args[1], args[2], args[3]);
}

if cmd == "lskeys" {
    if args.len() < 3 { return "Usage: reg lskeys <hive> <key>"; }
    return internal_reg_enum_keys(args[1], args[2]);
}

if cmd == "lsvals" {
    if args.len() < 3 { return "Usage: reg lsvals <hive> <key>"; }
    return internal_reg_enum_values(args[1], args[2]);
}

return "Usage: reg <read|write|delval|delkey|lskeys|lsvals> <hive> <key> [value_name] [data]";
