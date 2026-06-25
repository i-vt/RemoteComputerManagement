// modules/activate.rhai
//
// Switches the session to fast-beacon mode immediately on connect.
// Add to Auto-Recon (Module tab) so every new session checks in rapidly
// from the start rather than waiting out the full sleep interval first.
//
// Sends: beacon:mode active
// To revert on a session: beacon:mode passive  (or click the beacon toggle)

fn run(session_id) {
    let status = send_c2_command(session_id, "beacon:mode active");
    print("Activated fast mode for session " + session_id + " — " + status);
    "Activated"
}
