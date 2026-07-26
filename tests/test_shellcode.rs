// tests/test_shellcode.rs - Integration tests for DLL->shellcode conversion.
//
// Black-box tests over the public shellcode API (rcm::shellcode) plus
// CLI-level tests of the builder binary's --format shellcode path.
//
// The conversion is byte-for-byte compatible with sRDI's ConvertToShellcode
// (https://github.com/monoxgas/sRDI, BSD 3-Clause). The golden vectors below
// (stub SHA-256, full-blob SHA-256, exact 69-byte bootstrap) were produced
// by sRDI's own Python reference implementation - if they ever change, the
// compatibility guarantee is broken and the change must be deliberate.

use rcm::rdi_stub::RDI_STUB_X64;
use rcm::shellcode::{
    convert_dll_to_shellcode, encode_base64, encode_c_array, encode_hex, encode_shellcode,
    validate_x64_dll, ShellcodeEncoding, ShellcodeError, ShellcodeOptions,
    BOOTSTRAP_SIZE_X64, DEFAULT_FUNCTION_HASH, RDI_STUB_LEN,
};
use sha2::{Digest, Sha256};

// ── Golden vectors (from sRDI reference, Python/ShellcodeRDI.py) ────────────

const STUB_SHA256: &str = "bd6355b5936ba19259a37cbd4fea8b7ea99a5edfa1898e293128e823b1e6af1a";
const FULL_SHA256: &str = "69e7d4218be23c1b1a57cfc131fb35d10454c3eb24520e5a0fdb28455f551921";
const FULL_LEN: usize = 3357; // 69 + 2772 + 512 + 4

/// Exact 69-byte bootstrap for (hash=0x10, user_data=b"None", flags=0,
/// dll_len=512). Any drift here breaks the RIP-relative call into the stub.
const GOLDEN_BOOTSTRAP: [u8; 69] = [
    0xE8, 0x00, 0x00, 0x00, 0x00, 0x59, 0x49, 0x89, 0xC8, 0xBA, 0x10, 0x00, 0x00, 0x00, 0x49, 0x81,
    0xC0, 0x14, 0x0D, 0x00, 0x00, 0x41, 0xB9, 0x04, 0x00, 0x00, 0x00, 0x56, 0x48, 0x89, 0xE6, 0x48,
    0x83, 0xE4, 0xF0, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x89, 0x4C, 0x24, 0x28, 0x48, 0x81, 0xC1, 0x14,
    0x0B, 0x00, 0x00, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x05, 0x00, 0x00, 0x00,
    0x48, 0x89, 0xF4, 0x5E, 0xC3,
];

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Build a structurally-valid x64 DLL header of `size` bytes.
/// Mirrors the fixture in src/shellcode.rs's unit tests; conversion never
/// maps sections, so zeroed section data is fine.
fn fake_dll(size: usize) -> Vec<u8> {
    let mut d = vec![0u8; size.max(512)];
    d[0] = b'M';
    d[1] = b'Z';
    let pe_off = 0x80usize;
    d[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
    d[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
    let fh = pe_off + 4;
    d[fh..fh + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
    d[fh + 18..fh + 20].copy_from_slice(&0x2022u16.to_le_bytes()); // DLL|exec|LAA
    d[fh + 20..fh + 22].copy_from_slice(&0x020Bu16.to_le_bytes()); // PE32+
    d
}

fn sha256_hex(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

fn default_opts() -> ShellcodeOptions {
    ShellcodeOptions::default()
}

// ── Golden vector tests ─────────────────────────────────────────────────────

#[test]
fn golden_stub_matches_srdi_reference() {
    assert_eq!(RDI_STUB_X64.len(), 2772, "stub size drifted");
    assert_eq!(
        sha256_hex(RDI_STUB_X64),
        STUB_SHA256,
        "embedded RDI stub no longer matches the sRDI reference blob"
    );
}

#[test]
fn golden_full_conversion_matches_srdi_reference() {
    let sc = convert_dll_to_shellcode(&fake_dll(512), &default_opts()).unwrap();
    assert_eq!(sc.len(), FULL_LEN);
    assert_eq!(
        sha256_hex(&sc),
        FULL_SHA256,
        "full conversion output diverged from the sRDI reference"
    );
}

#[test]
fn golden_bootstrap_bytes_exact() {
    let sc = convert_dll_to_shellcode(&fake_dll(512), &default_opts()).unwrap();
    assert_eq!(&sc[..BOOTSTRAP_SIZE_X64], &GOLDEN_BOOTSTRAP[..]);
}

// ── Public API surface ──────────────────────────────────────────────────────

#[test]
fn constants_are_consistent() {
    assert_eq!(RDI_STUB_LEN, RDI_STUB_X64.len());
    assert_eq!(BOOTSTRAP_SIZE_X64, 69);
    assert_eq!(DEFAULT_FUNCTION_HASH, 0x10);
}

#[test]
fn conversion_is_deterministic() {
    let dll = fake_dll(2048);
    let a = convert_dll_to_shellcode(&dll, &default_opts()).unwrap();
    let b = convert_dll_to_shellcode(&dll, &default_opts()).unwrap();
    assert_eq!(a, b);
}

#[test]
fn conversion_layout_scales_with_inputs() {
    for (dll_len, ud_len) in [(512usize, 4usize), (1000, 0), (4096, 64), (65536, 1024)] {
        let opts = ShellcodeOptions {
            user_data: vec![0xAB; ud_len],
            ..default_opts()
        };
        let sc = convert_dll_to_shellcode(&fake_dll(dll_len), &opts).unwrap();
        assert_eq!(
            sc.len(),
            BOOTSTRAP_SIZE_X64 + RDI_STUB_LEN + dll_len + ud_len,
            "dll_len={dll_len} ud_len={ud_len}"
        );
        // DLL lands immediately after the stub; user data is the trailer
        assert_eq!(&sc[BOOTSTRAP_SIZE_X64 + RDI_STUB_LEN..][..2], b"MZ");
        if ud_len > 0 {
            assert!(sc[sc.len() - ud_len..].iter().all(|&b| b == 0xAB));
        }
    }
}

#[test]
fn conversion_embeds_options_as_immediates() {
    let dll = fake_dll(1000);
    let opts = ShellcodeOptions {
        function_hash: 0xC0FFEE00,
        user_data: b"PAYLOAD".to_vec(),
        flags: 1,
    };
    let sc = convert_dll_to_shellcode(&dll, &opts).unwrap();
    let dll_offset = (BOOTSTRAP_SIZE_X64 - 5 + RDI_STUB_LEN) as u32;

    let u32_at = |off: usize| u32::from_le_bytes(sc[off..off + 4].try_into().unwrap());
    assert_eq!(u32_at(10), 0xC0FFEE00);                    // mov edx, hash
    assert_eq!(u32_at(17), dll_offset + dll.len() as u32); // add r8, user_data loc
    assert_eq!(u32_at(23), 7);                             // mov r9d, ud len
    assert_eq!(u32_at(47), dll_offset);                    // add rcx, dll offset
    assert_eq!(u32_at(55), 1);                             // mov [rsp+0x20], flags
}

#[test]
fn dll_offset_points_exactly_at_dll_start() {
    // The dll_offset immediate in `add rcx, <dll_offset>` is relative to the
    // `pop rcx` at offset 5 (the RIP captured by `call $+5`), NOT to the
    // shellcode base: rcx = base + 5, then rcx += dll_offset must land on
    // the DLL's first byte.
    let dll = fake_dll(3000);
    let sc = convert_dll_to_shellcode(&dll, &default_opts()).unwrap();
    let dll_offset = u32::from_le_bytes(sc[47..51].try_into().unwrap()) as usize;
    let dll_start = 5 + dll_offset;
    assert_eq!(&sc[dll_start..dll_start + 2], b"MZ");
    assert_eq!(dll_start, BOOTSTRAP_SIZE_X64 + RDI_STUB_LEN);
}

// ── PE validation ───────────────────────────────────────────────────────────

#[test]
fn validate_accepts_minimal_x64_dll() {
    assert!(validate_x64_dll(&fake_dll(512)).is_ok());
}

#[test]
fn validate_rejects_each_bad_variant() {
    // Empty / tiny input
    assert_eq!(validate_x64_dll(&[]), Err(ShellcodeError::TooSmall));
    assert_eq!(validate_x64_dll(&[0u8; 16]), Err(ShellcodeError::TooSmall));

    // DOS magic
    let mut d = fake_dll(512);
    d[1] = b'X';
    assert_eq!(validate_x64_dll(&d), Err(ShellcodeError::BadDosMagic));

    // e_lfanew pointing past EOF
    let mut d = fake_dll(512);
    d[0x3C..0x40].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    assert_eq!(validate_x64_dll(&d), Err(ShellcodeError::TruncatedHeaders));

    // PE signature
    let mut d = fake_dll(512);
    d[0x82] = b'X';
    assert_eq!(validate_x64_dll(&d), Err(ShellcodeError::BadPeSignature));

    // Non-AMD64
    let mut d = fake_dll(512);
    d[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes()); // i386
    assert_eq!(validate_x64_dll(&d), Err(ShellcodeError::NotAmd64(0x014C)));

    // EXE, not DLL
    let mut d = fake_dll(512);
    d[0x96..0x98].copy_from_slice(&0x0022u16.to_le_bytes());
    assert_eq!(validate_x64_dll(&d), Err(ShellcodeError::NotADll));

    // PE32 optional-header magic
    let mut d = fake_dll(512);
    d[0x98..0x9A].copy_from_slice(&0x010Bu16.to_le_bytes());
    assert_eq!(validate_x64_dll(&d), Err(ShellcodeError::NotPe32Plus(0x010B)));
}

#[test]
fn validate_handles_e_lfanew_at_end_of_file() {
    // PE header near the end of the buffer: valid as long as sig+filehdr+magic fit
    let mut d = vec![0u8; 1024];
    d[0] = b'M';
    d[1] = b'Z';
    let pe_off = 1024 - 26; // exactly enough room: 4 + 20 + 2
    d[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
    d[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
    let fh = pe_off + 4;
    d[fh..fh + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    d[fh + 18..fh + 20].copy_from_slice(&0x2022u16.to_le_bytes());
    d[fh + 20..fh + 22].copy_from_slice(&0x020Bu16.to_le_bytes());
    assert!(validate_x64_dll(&d).is_ok());

    // One byte shorter and it must fail
    let d2 = &d[..1023];
    assert_eq!(validate_x64_dll(d2), Err(ShellcodeError::TruncatedHeaders));
}

#[test]
fn error_display_messages_are_actionable() {
    assert!(ShellcodeError::NotAmd64(0x014C).to_string().contains("64-bit"));
    assert!(ShellcodeError::NotADll.to_string().contains("DLL"));
    assert!(ShellcodeError::NotPe32Plus(0x010B).to_string().contains("PE32+"));
}

// ── Encoders ────────────────────────────────────────────────────────────────

#[test]
fn base64_handles_binary_and_padding() {
    // RFC 4648 vectors
    assert_eq!(encode_base64(b""), "");
    assert_eq!(encode_base64(b"f"), "Zg==");
    assert_eq!(encode_base64(b"fo"), "Zm8=");
    assert_eq!(encode_base64(b"foo"), "Zm9v");
    assert_eq!(encode_base64(b"foob"), "Zm9vYg==");
    assert_eq!(encode_base64(b"fooba"), "Zm9vYmE=");
    assert_eq!(encode_base64(b"foobar"), "Zm9vYmFy");

    // All 256 byte values: verify against an independent decoder in-test
    let data: Vec<u8> = (0..=255).collect();
    let enc = encode_base64(&data);
    assert_eq!(enc.len(), 344); // ceil(256/3)*4
    assert_eq!(base64_decode(&enc), data);
}

#[test]
fn base64_shellcode_roundtrip() {
    let sc = convert_dll_to_shellcode(&fake_dll(1024), &default_opts()).unwrap();
    let enc = encode_base64(&sc);
    assert_eq!(base64_decode(&enc), sc);
}

/// Minimal standard-alphabet base64 decoder used to independently verify
/// the encoder (no external crates).
fn base64_decode(s: &str) -> Vec<u8> {
    fn val(c: u8) -> u32 {
        match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("invalid base64 char"),
        }
    }
    let bytes: Vec<&u8> = s.as_bytes().iter().filter(|&&c| c != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut n: u32 = 0;
        for (i, &&c) in chunk.iter().enumerate() {
            n |= val(c) << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 { out.push((n >> 8) as u8); }
        if chunk.len() > 3 { out.push(n as u8); }
    }
    out
}

#[test]
fn hex_encoder_is_lowercase_and_complete() {
    let data: Vec<u8> = (0..=255).collect();
    let h = encode_hex(&data);
    assert_eq!(h.len(), 512);
    assert!(h.starts_with("000102030405060708090a0b0c0d0e0f"));
    assert!(h.ends_with("f8f9fafbfcfdfeff"));
}

#[test]
fn c_array_is_compilable_shape() {
    let c = encode_c_array(&[0x90u8; 25], "payload");
    assert!(c.starts_with("unsigned char payload[] = {\n"));
    assert!(c.contains("0x90, "));
    assert!(c.ends_with("};\nunsigned int payload_len = 25;\n"));
    // 25 bytes -> 2 full lines of 12 + 1 byte on the last line
    assert_eq!(c.matches('\n').count(), 2 + 2 + 2); // header + 3 data lines + "};\n" + len line
}

#[test]
fn encode_shellcode_dispatches_per_encoding() {
    let sc = convert_dll_to_shellcode(&fake_dll(512), &default_opts()).unwrap();
    assert_eq!(encode_shellcode(&sc, ShellcodeEncoding::Raw, "x"), sc);
    assert_eq!(
        encode_shellcode(&sc, ShellcodeEncoding::Base64, "x"),
        encode_base64(&sc).into_bytes()
    );
    assert_eq!(
        encode_shellcode(&sc, ShellcodeEncoding::Hex, "x"),
        encode_hex(&sc).into_bytes()
    );
    let c = encode_shellcode(&sc, ShellcodeEncoding::CArray, "rcm_sc");
    assert!(c.starts_with(b"unsigned char rcm_sc[] = {"));
}

// ── Builder CLI (runs the actual builder binary) ────────────────────────────

/// The builder binary is built by cargo alongside the integration tests.
fn builder() -> std::process::Command {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_builder"));
    // Isolate side effects (dist/, c2_audit.db) in a temp directory.
    let dir = tempfile::tempdir().expect("tempdir");
    // The builder's first preflight is find_project_root(): it requires a
    // Cargo.toml at CWD (existence only - the content is never parsed for
    // the early-exit paths exercised here).
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"rcm-cli-test\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
    )
    .expect("write stub Cargo.toml");
    cmd.current_dir(dir.path());
    // Keep the tempdir alive for the lifetime of the Command by leaking -
    // tests are short-lived processes, so this is acceptable here.
    std::mem::forget(dir);
    cmd
}

#[test]
fn cli_help_advertises_shellcode_options() {
    let out = builder().arg("--help").output().expect("run builder --help");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    for needle in ["shellcode", "--sc-hash", "--sc-userdata", "--sc-flags", "--sc-output"] {
        assert!(text.contains(needle), "builder --help missing '{needle}'");
    }
}

#[test]
fn cli_rejects_shellcode_on_linux_with_clear_error() {
    let out = builder()
        .args(["--format", "shellcode", "--platform", "linux"])
        .output()
        .expect("run builder");
    assert!(!out.status.success(), "shellcode+linux must fail");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--platform windows"),
        "error should point at --platform windows, got: {err}"
    );
}

#[test]
fn cli_rejects_shellcode_on_macos_with_clear_error() {
    let out = builder()
        .args(["--format", "shellcode", "--platform", "macos"])
        .output()
        .expect("run builder");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--platform windows"));
}

#[test]
fn cli_rejects_malformed_sc_hash_at_parse_time() {
    let out = builder()
        .args(["--format", "shellcode", "--platform", "windows", "--sc-hash", "0xZZZ"])
        .output()
        .expect("run builder");
    assert_eq!(out.status.code(), Some(2), "clap parse errors exit with code 2");
    assert!(String::from_utf8_lossy(&out.stderr).contains("hex"));
}

#[test]
fn cli_accepts_decimal_and_hex_sc_hash() {
    // --profile-file /nonexistent makes the builder exit right after arg
    // parsing (before any compilation), so a passing parse is observable as
    // "reached the profile-read stage" instead of a clap error.
    for hash in ["0xDEADBEEF", "3735928559", "16"] {
        let out = builder()
            .args([
                "--format", "shellcode", "--platform", "windows",
                "--sc-hash", hash,
                "--profile-file", "/nonexistent/profile.json",
            ])
            .output()
            .expect("run builder");
        let err = String::from_utf8_lossy(&out.stderr);
        assert_ne!(
            out.status.code(),
            Some(2),
            "hash '{hash}' triggered a clap parse error: {err}"
        );
        assert!(
            err.contains("profile") || err.contains("nonexistent"),
            "hash '{hash}': expected to reach profile read, got: {err}"
        );
    }
}

#[test]
fn cli_rejects_unknown_sc_output_at_parse_time() {
    let out = builder()
        .args(["--format", "shellcode", "--platform", "windows", "--sc-output", "pdf"])
        .output()
        .expect("run builder");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn cli_sni_and_alpn_aliases_both_parse() {
    // Regression test for the pre-existing mismatch: the API and README used
    // --sni/--alpn while the CLI only defined --sni-override/--alpn-protocols.
    // Both spellings must now parse. The nonexistent profile file makes the
    // builder exit right after parsing, before compilation begins.
    for flag_pair in [["--sni", "cdn.example.com"], ["--sni-override", "cdn.example.com"]] {
        let out = builder()
            .args([
                "--platform", "linux", flag_pair[0], flag_pair[1],
                "--profile-file", "/nonexistent/profile.json",
            ])
            .output()
            .expect("run builder");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            !err.contains("unexpected argument"),
            "'{}' rejected: {err}", flag_pair[0]
        );
    }
    for flag_pair in [["--alpn", "h2,http/1.1"], ["--alpn-protocols", "h2,http/1.1"]] {
        let out = builder()
            .args([
                "--platform", "linux", flag_pair[0], flag_pair[1],
                "--profile-file", "/nonexistent/profile.json",
            ])
            .output()
            .expect("run builder");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            !err.contains("unexpected argument"),
            "'{}' rejected: {err}", flag_pair[0]
        );
    }
}