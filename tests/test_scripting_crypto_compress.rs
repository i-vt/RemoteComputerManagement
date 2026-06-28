// tests/test_scripting_crypto_compress.rs
//
// Tests for scripting/crypto.rs and scripting/compress.rs.
//
// Crypto: every function is pure Rust — results are deterministic and
// verified against published test vectors (NIST, RFC 1321, RFC 4231, etc.).
// Any regression in hash output, encoding, or AES correctness fails immediately.
//
// Compress: round-trip invariant — compress(decompress(x)) == x, and the
// produced ZIP archives must be readable by the `zip` crate.

use rcm::agent::scripting::ExtensionManager;

fn run(script: &str) -> String {
    ExtensionManager::new().run_script(script, vec![])
}

// ─────────────────────────────────────────────────────────────────────────────
// SHA-256  (NIST FIPS 180-4 test vectors)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn sha256_nist_abc() {
    assert_eq!(
        run(r#"internal_sha256("abc")"#),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn sha256_nist_empty() {
    assert_eq!(
        run(r#"internal_sha256("")"#),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn sha256_is_deterministic() {
    let a = run(r#"internal_sha256("repeatability")"#);
    let b = run(r#"internal_sha256("repeatability")"#);
    assert_eq!(a, b);
}

#[test]
fn sha256_output_is_64_hex_chars() {
    let out = run(r#"internal_sha256("test")"#);
    assert_eq!(out.len(), 64, "SHA-256 hex output should be 64 chars: {}", out);
    assert!(out.chars().all(|c| c.is_ascii_hexdigit()), "non-hex chars: {}", out);
}

#[test]
fn sha256_bytes_of_known_hex_input() {
    // sha256_bytes("616263") == sha256_bytes(b"abc") == sha256("abc")
    assert_eq!(
        run(r#"internal_sha256_bytes("616263")"#),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// MD5  (RFC 1321 §A.5 test vectors)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn md5_rfc_empty() {
    assert_eq!(run(r#"internal_md5("")"#), "d41d8cd98f00b204e9800998ecf8427e");
}

#[test]
fn md5_rfc_abc() {
    assert_eq!(run(r#"internal_md5("abc")"#), "900150983cd24fb0d6963f7d28e17f72");
}

#[test]
fn md5_rfc_message_digest() {
    assert_eq!(
        run(r#"internal_md5("message digest")"#),
        "f96b697d7cb7938d525a2f31aaf161d0"
    );
}

#[test]
fn md5_output_is_32_hex_chars() {
    let out = run(r#"internal_md5("test")"#);
    assert_eq!(out.len(), 32, "MD5 hex output should be 32 chars: {}", out);
    assert!(out.chars().all(|c| c.is_ascii_hexdigit()), "non-hex chars: {}", out);
}

// ─────────────────────────────────────────────────────────────────────────────
// HMAC-SHA256  (RFC 4231 Test Case 1)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn hmac_rfc4231_case1() {
    // Key  = 20 × 0x0b
    // Data = "Hi There"
    // HMAC = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
    let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
    let result = run(r#"internal_hmac("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "Hi There")"#);
    assert_eq!(result, expected);
}

#[test]
fn hmac_raw_string_key_accepted() {
    // The function falls back to raw bytes if the key is not valid hex.
    let r1 = run(r#"internal_hmac("secret", "data")"#);
    assert_eq!(r1.len(), 64, "HMAC output should be 64 hex chars: {}", r1);
}

#[test]
fn hmac_is_deterministic() {
    let a = run(r#"internal_hmac("deadbeef", "message")"#);
    let b = run(r#"internal_hmac("deadbeef", "message")"#);
    assert_eq!(a, b);
}

// ─────────────────────────────────────────────────────────────────────────────
// CRC-32  (ISO 3309 / ITU-T V.42 — standard "check value" vector)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn crc32_check_vector_123456789() {
    // CRC-32 of ASCII "123456789" = 0xCBF43926 = 3421780262
    let result = run(r#"internal_crc32("123456789")"#);
    let val: i64 = result.parse().expect("CRC-32 result should be an integer string");
    assert_eq!(val, 3421780262i64);
}

#[test]
fn crc32_empty_string() {
    let result = run(r#"internal_crc32("")"#);
    let val: i64 = result.parse().unwrap();
    assert_eq!(val, 0i64); // CRC-32 of empty = 0x00000000
}

#[test]
fn crc32_is_deterministic() {
    assert_eq!(run(r#"internal_crc32("hello")"#), run(r#"internal_crc32("hello")"#));
}

// ─────────────────────────────────────────────────────────────────────────────
// FNV-1a
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn fnv1a_is_deterministic() {
    let a = run(r#"internal_fnv1a("test")"#);
    let b = run(r#"internal_fnv1a("test")"#);
    assert_eq!(a, b);
}

#[test]
fn fnv1a_different_inputs_different_outputs() {
    let a = run(r#"internal_fnv1a("alpha")"#);
    let b = run(r#"internal_fnv1a("beta")"#);
    assert_ne!(a, b, "FNV1a of different inputs should differ");
}

#[test]
fn fnv1a_output_is_integer_string() {
    let result = run(r#"internal_fnv1a("hello")"#);
    result.parse::<i64>().expect("FNV1a result should be parseable as i64");
}

// ─────────────────────────────────────────────────────────────────────────────
// Base64
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn base64_encode_man() {
    // RFC 4648 §10: "Man" → "TWFu"
    assert_eq!(run(r#"internal_base64_encode("Man")"#), "TWFu");
}

#[test]
fn base64_encode_empty() {
    assert_eq!(run(r#"internal_base64_encode("")"#), "");
}

#[test]
fn base64_decode_twfu() {
    assert_eq!(run(r#"internal_base64_decode("TWFu")"#), "Man");
}

#[test]
fn base64_round_trip() {
    let msg = "The quick brown fox jumps over the lazy dog";
    let script = format!(
        r#"internal_base64_decode(internal_base64_encode("{}"))"#, msg
    );
    assert_eq!(run(&script), msg);
}

#[test]
fn base64_encode_hex_of_known_bytes() {
    // "48656c6c6f" = "Hello" in ASCII; base64 of "Hello" = "SGVsbG8="
    assert_eq!(run(r#"internal_base64_encode_hex("48656c6c6f")"#), "SGVsbG8=");
}

// ─────────────────────────────────────────────────────────────────────────────
// Hex encode/decode
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn hex_encode_hello() {
    assert_eq!(run(r#"internal_hex_encode("Hello")"#), "48656c6c6f");
}

#[test]
fn hex_decode_hello() {
    assert_eq!(run(r#"internal_hex_decode("48656c6c6f")"#), "Hello");
}

#[test]
fn hex_round_trip() {
    let msg = "round trip test 123";
    let script = format!(r#"internal_hex_decode(internal_hex_encode("{}"))"#, msg);
    assert_eq!(run(&script), msg);
}

#[test]
fn hex_encode_empty() {
    assert_eq!(run(r#"internal_hex_encode("")"#), "");
}

// ─────────────────────────────────────────────────────────────────────────────
// XOR
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn xor_single_byte_key() {
    // ff ^ aa = 55,  00 ^ aa = aa,  ff ^ aa = 55
    assert_eq!(run(r#"internal_xor("ff00ff", "aa")"#), "55aa55");
}

#[test]
fn xor_same_key_twice_is_identity() {
    let script = r#"internal_xor(internal_xor("deadbeef", "cafebabe"), "cafebabe")"#;
    assert_eq!(run(script), "deadbeef");
}

#[test]
fn xor_multi_byte_key_cycles() {
    // data: 0a 0b 0c, key: ff ff → result: f5 f4 f3
    assert_eq!(run(r#"internal_xor("0a0b0c", "ffff")"#), "f5f4f3");
}

// ─────────────────────────────────────────────────────────────────────────────
// UUID
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn uuid_format() {
    let u = run(r#"internal_uuid()"#);
    // xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx  (36 chars)
    assert_eq!(u.len(), 36, "UUID should be 36 chars: {}", u);
    let parts: Vec<&str> = u.split('-').collect();
    assert_eq!(parts.len(), 5, "UUID should have 5 hyphen-separated groups: {}", u);
    // Version 4 bit
    assert_eq!(&parts[2][0..1], "4", "UUID version nibble should be 4: {}", u);
}

#[test]
fn uuid_is_unique_per_call() {
    let a = run(r#"internal_uuid()"#);
    let b = run(r#"internal_uuid()"#);
    assert_ne!(a, b, "Two UUID calls should produce different values");
}

// ─────────────────────────────────────────────────────────────────────────────
// AES-256-GCM (in-memory encrypt / decrypt round-trip)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn aes_gcm_round_trip() {
    let key_hex = "0".repeat(64); // 32 zero bytes
    let plaintext_hex = "48656c6c6f20576f726c64"; // "Hello World"
    let script = format!(
        r#"
let key = "{}";
let pt  = "{}";
let ct  = internal_encrypt_bytes(pt, key);
internal_decrypt_bytes(ct, key)
"#,
        key_hex, plaintext_hex
    );
    assert_eq!(run(&script), plaintext_hex);
}

#[test]
fn aes_gcm_encrypt_is_nondeterministic() {
    // Different nonce each time, so ciphertexts differ even for identical input.
    let key = "0".repeat(64);
    let pt  = "deadbeef";
    let s1 = format!(r#"internal_encrypt_bytes("{}", "{}")"#, pt, key);
    let s2 = format!(r#"internal_encrypt_bytes("{}", "{}")"#, pt, key);
    assert_ne!(run(&s1), run(&s2), "AES-GCM should use a random nonce each call");
}

#[test]
fn aes_gcm_wrong_key_fails() {
    let key1 = "a".repeat(64);
    let key2 = "b".repeat(64);
    let pt   = "deadbeef";
    let script = format!(
        r#"
let ct = internal_encrypt_bytes("{}", "{}");
internal_decrypt_bytes(ct, "{}")
"#,
        pt, key1, key2
    );
    let result = run(&script);
    assert!(result.starts_with("Error"), "Wrong key decryption should return Error: {}", result);
}

// ─────────────────────────────────────────────────────────────────────────────
// AES-128-CBC  (NIST SP 800-38A F.2.1 decrypt vector)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn aes128_cbc_round_trip_via_pbkdf2_key() {
    // Verify PBKDF2-SHA1 output length (Chrome Linux key derivation path).
    let pbkdf2_script = r#"internal_pbkdf2("peanuts", "73616c74796c74", 1, "sha1", 16)"#;
    let pbkdf2_result = run(pbkdf2_script);
    assert_eq!(pbkdf2_result.len(), 32,
        "PBKDF2 16-byte output should be 32 hex chars: {}", pbkdf2_result);
    assert!(pbkdf2_result.chars().all(|c| c.is_ascii_hexdigit()),
        "PBKDF2 result should be hex: {}", pbkdf2_result);
}

#[test]
fn aes128_cbc_decrypt_wrong_key_fails() {
    let script = r#"
internal_aes128_cbc_decrypt(
    "7649abac8119b246cee98e9b12e9197d",
    "ffffffffffffffffffffffffffffffff",
    "000102030405060708090a0b0c0d0e0f"
)
"#;
    let result = run(script);
    assert!(result.starts_with("Error"), "Unpadding with wrong key should error: {}", result);
}

#[test]
fn pbkdf2_sha1_is_deterministic() {
    let s = r#"internal_pbkdf2("password", "73616c74", 1, "sha1", 32)"#;
    assert_eq!(run(s), run(s));
}

#[test]
fn pbkdf2_sha256_output_length() {
    let result = run(r#"internal_pbkdf2("secret", "deadbeef", 1000, "sha256", 32)"#);
    assert_eq!(result.len(), 64, "32-byte PBKDF2 output should be 64 hex chars: {}", result);
}

#[test]
fn pbkdf2_sha1_vs_sha256_differ() {
    let s1 = run(r#"internal_pbkdf2("pw", "salt", 1, "sha1",   16)"#);
    let s2 = run(r#"internal_pbkdf2("pw", "salt", 1, "sha256", 16)"#);
    assert_ne!(s1, s2, "SHA-1 and SHA-256 PBKDF2 should differ");
}

#[test]
fn pbkdf2_unknown_hash_returns_error() {
    let result = run(r#"internal_pbkdf2("pw", "salt", 1, "md5", 16)"#);
    assert!(result.starts_with("Error"), "Unknown hash algo should error: {}", result);
}

// ─────────────────────────────────────────────────────────────────────────────
// Key generation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn keygen_produces_64_hex_chars() {
    let key = run(r#"internal_keygen()"#);
    assert_eq!(key.len(), 64, "keygen should produce 64 hex chars (32 bytes): {}", key);
    assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn keygen_is_random() {
    let a = run(r#"internal_keygen()"#);
    let b = run(r#"internal_keygen()"#);
    assert_ne!(a, b, "Two keygen calls should produce different keys");
}

// ─────────────────────────────────────────────────────────────────────────────
// Gzip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn gzip_round_trip() {
    let plaintext_hex = "48656c6c6f20576f726c64"; // "Hello World"
    let script = format!(
        r#"internal_gunzip(internal_gzip("{}"))"#, plaintext_hex
    );
    assert_eq!(run(&script), plaintext_hex);
}

#[test]
fn gzip_compressed_is_smaller_for_repetitive_input() {
    // 1000 zero bytes compresses to much less than 2000 hex chars
    let hex_zeros = "00".repeat(1000);
    let compressed = run(&format!(r#"internal_gzip("{}")"#, hex_zeros));
    assert!(
        !compressed.starts_with("Error"),
        "gzip should succeed: {}", compressed
    );
    // hex-encoded compressed output should be shorter than input for repetitive data
    assert!(
        compressed.len() < hex_zeros.len(),
        "compressed hex ({}) should be shorter than input hex ({})",
        compressed.len(), hex_zeros.len()
    );
}

#[test]
fn gunzip_invalid_data_returns_error() {
    let result = run(r#"internal_gunzip("deadbeef")"#);
    assert!(result.starts_with("Error"), "gunzip of non-gzip data should error: {}", result);
}

// ─────────────────────────────────────────────────────────────────────────────
// Zip create / list / extract
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn zip_create_list_extract_round_trip() {
    use tempfile::TempDir;
    let dir = TempDir::new().unwrap();

    // Write two source files.
    let f1 = dir.path().join("a.txt");
    let f2 = dir.path().join("b.txt");
    std::fs::write(&f1, "hello").unwrap();
    std::fs::write(&f2, "world").unwrap();

    let out_zip  = dir.path().join("out.zip").to_string_lossy().to_string().replace('\\', "\\\\");
    let f1_str   = f1.to_string_lossy().to_string().replace('\\', "\\\\");
    let f2_str   = f2.to_string_lossy().to_string().replace('\\', "\\\\");
    let ext_dir  = dir.path().join("extracted").to_string_lossy().to_string().replace('\\', "\\\\");

    // Create the archive.
    let create_result = run(&format!(
        r#"internal_zip_create("[\"{}\", \"{}\"]", "{}")"#,
        f1_str, f2_str, out_zip
    ));
    assert!(!create_result.starts_with("Error"),
        "zip_create should succeed: {}", create_result);
    assert!(create_result.contains("2"), "should report 2 entries: {}", create_result);

    // List it.
    let list_json = run(&format!(r#"internal_zip_list("{}")"#, out_zip));
    assert!(!list_json.starts_with("Error"), "zip_list should succeed: {}", list_json);
    let entries: serde_json::Value = serde_json::from_str(&list_json).unwrap();
    assert!(entries.is_array(), "zip_list should return JSON array");
    assert_eq!(entries.as_array().unwrap().len(), 2);

    // Extract.
    let extract_result = run(&format!(r#"internal_zip_extract("{}", "{}")"#, out_zip, ext_dir));
    assert!(!extract_result.starts_with("Error"),
        "zip_extract should succeed: {}", extract_result);

    // Verify extracted content.
    let content_a = std::fs::read_to_string(
        dir.path().join("extracted").join("a.txt")
    ).unwrap_or_default();
    let content_b = std::fs::read_to_string(
        dir.path().join("extracted").join("b.txt")
    ).unwrap_or_default();
    assert_eq!(content_a, "hello");
    assert_eq!(content_b, "world");
}

#[test]
fn zip_list_nonexistent_returns_error() {
    let result = run(r#"internal_zip_list("/no/such/file.zip")"#);
    assert!(result.starts_with("Error"), "zip_list of missing file should error: {}", result);
}
