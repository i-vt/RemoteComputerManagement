// svc.rhai - Windows service control helper.
//
// Usage:
//   svc list                                  -> JSON array of services
//   svc start  <name>
//   svc stop   <name>
//   svc create <name> <display> <binary_path>  -> auto-start service
//   svc delete <name>
//
// Service control is Windows-only; bail early with an honest message
// elsewhere.

if internal_env("OS") != "Windows_NT" {
    return "svc targets Windows hosts only (service control is Windows-only).";
}

if args.len() < 1 {
    return "Usage: svc <list|start|stop|create|delete> [name] [display] [binary_path]";
}
let cmd = args[0];

if cmd == "list" {
    return internal_service_enum();
}

if cmd == "start" {
    if args.len() < 2 { return "Usage: svc start <name>"; }
    return internal_service_start(args[1]);
}

if cmd == "stop" {
    if args.len() < 2 { return "Usage: svc stop <name>"; }
    return internal_service_stop(args[1]);
}

if cmd == "create" {
    if args.len() < 4 { return "Usage: svc create <name> <display> <binary_path>"; }
    return internal_service_create(args[1], args[2], args[3], true);
}

if cmd == "delete" {
    if args.len() < 2 { return "Usage: svc delete <name>"; }
    return internal_service_delete(args[1]);
}

return "Usage: svc <list|start|stop|create|delete> [name] [display] [binary_path]";
