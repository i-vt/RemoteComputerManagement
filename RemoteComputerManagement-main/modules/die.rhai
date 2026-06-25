// modules/die.rhai
//
// Orders the agent to self-destruct: deletes its own binary from disk then exits.
// Use for clean teardown at the end of an engagement.
//
// WARNING: this is irreversible — the agent will not reconnect.
// Broadcast with care; running this via the Broadcast → Module route
// will terminate every connected session simultaneously.

fn run(session_id) {
    let status = send_c2_command(session_id, "sys:die");
    print("Termination sent to session " + session_id + " — " + status);
    "Terminated"
}
