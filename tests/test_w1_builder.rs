// tests/test_w1_builder.rs - Tests for the shared build validation module
// (rcm::build_validate) consumed by both the CLI builder and the REST API.

use std::path::PathBuf;

use rcm::build_validate::{
    check_format_platform, check_hibernation_transport, confine_server_path,
    random_sign_identity, sanitize_sign_field,
};

// ── : hibernation x transport ──────────────────────────────────────

#[test]
fn hibernation_http_and_https_rejected() {
    let err = check_hibernation_transport(true, "http").unwrap_err();
    assert!(err.contains("http"), "error names the transport: {err}");
    assert!(err.contains("hibernation"), "error names the mode: {err}");
    assert!(check_hibernation_transport(true, "https").is_err());
}

#[test]
fn hibernation_connection_transports_accepted() {
    for t in ["tls", "tcp_plain", "tcp-plain", "named_pipe", "named-pipe"] {
        assert!(check_hibernation_transport(true, t).is_ok(), "transport={t}");
    }
}

#[test]
fn no_hibernation_any_transport_accepted() {
    for t in ["tls", "http", "https"] {
        assert!(check_hibernation_transport(false, t).is_ok(), "transport={t}");
    }
}

// ── : format x platform ────────────────────────────────────────────

#[test]
fn dll_and_service_rejected_off_windows() {
    for format in ["dll", "service"] {
        for platform in ["linux", "linux-musl", "macos"] {
            let err = check_format_platform(format, platform).unwrap_err();
            assert!(err.contains("platform=windows"), "{format}/{platform}: {err}");
 // The message lists the supported format x platform combos.
            assert!(err.contains("supported combinations"), "{format}/{platform}: {err}");
        }
        assert!(check_format_platform(format, "windows").is_ok());
    }
}

#[test]
fn shellcode_pipeline_formats_rejected_off_windows() {
    for format in ["shellcode", "donut", "pe_to_shellcode", "bin"] {
        assert!(check_format_platform(format, "linux").is_err(), "format={format}");
        assert!(check_format_platform(format, "windows").is_ok(), "format={format}");
    }
}

#[test]
fn exe_and_stager_accepted_on_all_platforms_including_musl() {
    for format in ["exe", "stager", "pic_c"] {
        for platform in ["linux", "linux-musl", "windows", "macos"] {
            assert!(
                check_format_platform(format, platform).is_ok(),
                "format={format} platform={platform}"
            );
        }
    }
}

// ── : signing identity randomization ───────────────────────────────

#[test]
fn sign_identity_differs_across_calls() {
    let a = random_sign_identity();
    let b = random_sign_identity();
 // The uuid tag embedded in url/cn guarantees uniqueness.
    assert_ne!(a.url, b.url);
    assert_ne!(a.cn, b.cn);
}

#[test]
fn sign_identity_fields_look_plausible() {
    let id = random_sign_identity();
    assert!(!id.name.is_empty());
    assert!(id.url.starts_with("https://"), "url: {}", id.url);
    assert!(!id.cn.is_empty());
 // No static IOC strings.
    assert!(!id.name.contains("RCM"));
    assert!(!id.url.contains("localhost"));
    assert!(!id.cn.contains("RCM"));
}

#[test]
fn sanitize_sign_field_strips_subj_metacharacters() {
    assert_eq!(sanitize_sign_field("ACME/Corp\\Update"), "ACMECorpUpdate");
    assert_eq!(sanitize_sign_field("a\nb\0c"), "abc");
    assert_eq!(sanitize_sign_field("plain name"), "plain name");
}

// ── : server-side path confinement ─────────────────────────────────

fn roots(cwd: &PathBuf, temp: &PathBuf) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let icon_roots = vec![cwd.join("assets").join("icons"), temp.clone()];
    let cert_roots = vec![cwd.join("certs"), temp.clone()];
    (icon_roots, cert_roots)
}

#[test]
fn confinement_rejects_absolute_paths_outside_roots() {
    let cwd = PathBuf::from("/srv/app");
    let temp = PathBuf::from("/tmp");
    let (icon_roots, cert_roots) = roots(&cwd, &temp);
    assert!(confine_server_path("/etc/passwd", &cwd, &icon_roots).is_err());
    assert!(confine_server_path("/etc/ssl/private/ca.key", &cwd, &cert_roots).is_err());
    assert!(confine_server_path("/srv/app/dist/x.exe", &cwd, &icon_roots).is_err());
 // An icon root is not a certs root and vice versa.
    assert!(confine_server_path("/srv/app/assets/icons/a.ico", &cwd, &cert_roots).is_err());
}

#[test]
fn confinement_accepts_paths_inside_roots() {
    let cwd = PathBuf::from("/srv/app");
    let temp = PathBuf::from("/tmp");
    let (icon_roots, cert_roots) = roots(&cwd, &temp);
 // Relative paths resolve against the base.
    assert!(confine_server_path("assets/icons/driver.ico", &cwd, &icon_roots).is_ok());
    assert!(confine_server_path("certs/overlay", &cwd, &cert_roots).is_ok());
 // The per-job upload temp dir is a legal absolute path.
    assert!(confine_server_path("/tmp/rcm-build-abc/icon.ico", &cwd, &icon_roots).is_ok());
    assert!(confine_server_path("/tmp/rcm-build-abc", &cwd, &cert_roots).is_ok());
    assert!(confine_server_path("/srv/app/assets/icons/driver.ico", &cwd, &icon_roots).is_ok());
}

#[test]
fn confinement_rejects_traversal_and_empty() {
    let cwd = PathBuf::from("/srv/app");
    let temp = PathBuf::from("/tmp");
    let (icon_roots, _) = roots(&cwd, &temp);
    assert!(confine_server_path("../../etc/passwd", &cwd, &icon_roots).is_err());
    assert!(confine_server_path("assets/icons/../../secret", &cwd, &icon_roots).is_err());
    assert!(confine_server_path("", &cwd, &icon_roots).is_err());
    assert!(confine_server_path("   ", &cwd, &icon_roots).is_err());
}
