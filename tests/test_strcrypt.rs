// ./tests/test_strcrypt.rs
//
// Binary-leak proof and end-to-end check for the strcrypt compile-time
// string cryptor:
//   1. A record built byte-for-byte like the aes_str! expansion must not
//      contain the plaintext anywhere (ciphertext || nonce || iv || tag).
//   2. The real macro must round-trip through the runtime decryptor.

use rcm::strcrypt_rt;
use strcrypt::aes_str;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

// Build an encrypted record exactly the way the strcrypt proc-macro does
// at expansion time: master from the four env shards, per-string nonce
// and IV, skey = SHA256(master || nonce), AES-256-GCM seal, tag split
// off the end.
fn encrypt_record(plaintext: &str) -> ([u8; 32], [u8; 12], [u8; 16], Vec<u8>) {
    let mut buf = Vec::with_capacity(64);
    for shard in [
        env!("RCM_STRCRYPT_S1"),
        env!("RCM_STRCRYPT_S2"),
        env!("RCM_STRCRYPT_S3"),
        env!("RCM_STRCRYPT_S4"),
    ] {
        buf.extend_from_slice(&hex::decode(shard).unwrap());
    }
    let master = Sha256::digest(&buf);

    let mut rng = rand::thread_rng();
    let mut nonce = [0u8; 32];
    let mut iv = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    rng.fill_bytes(&mut iv);

    let mut key_material = Vec::with_capacity(64);
    key_material.extend_from_slice(&master);
    key_material.extend_from_slice(&nonce);
    let key = Sha256::digest(&key_material);

    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let sealed = cipher
        .encrypt(Nonce::from_slice(&iv), plaintext.as_bytes())
        .unwrap();
    let (ct, tag) = sealed.split_at(sealed.len() - 16);
    let mut tag_arr = [0u8; 16];
    tag_arr.copy_from_slice(tag);
    (nonce, iv, tag_arr, ct.to_vec())
}

#[test]
fn plaintext_absent_from_emitted_record() {
    let secret = "ntdll.dll";
    let (nonce, iv, tag, ct) = encrypt_record(secret);

    // The record is exactly the bytes the macro expansion carries.
    let mut record = Vec::new();
    record.extend_from_slice(&ct);
    record.extend_from_slice(&nonce);
    record.extend_from_slice(&iv);
    record.extend_from_slice(&tag);

    assert!(
        !contains_subslice(&record, secret.as_bytes()),
        "plaintext leaked into the emitted record"
    );
    // No individual component may contain it either.
    assert!(!contains_subslice(&ct, secret.as_bytes()));
    assert!(!contains_subslice(&nonce, secret.as_bytes()));
    assert!(!contains_subslice(&iv, secret.as_bytes()));
    assert!(!contains_subslice(&tag, secret.as_bytes()));

    // Sanity: the record still decrypts back to the secret.
    assert_eq!(strcrypt_rt::decrypt(&nonce, &iv, &tag, &ct), secret);
}

#[test]
fn tampered_record_does_not_recover_plaintext() {
    let secret = "ntdll.dll";
    let (nonce, iv, mut tag, ct) = encrypt_record(secret);
    tag[7] ^= 0x40;
    let out = strcrypt_rt::decrypt(&nonce, &iv, &tag, &ct);
    assert_ne!(out, secret);
}

#[test]
fn macro_round_trip() {
    let s = aes_str!("ntdll.dll");
    assert_eq!(s, "ntdll.dll");

    let wide = aes_str!("C:\\Windows\\System32\\kernel32.dll");
    assert_eq!(wide, "C:\\Windows\\System32\\kernel32.dll");

    let empty = aes_str!("");
    assert_eq!(empty, "");
}

#[test]
fn macro_invocations_are_independent() {
    // Two call sites for related strings must each decrypt correctly with
    // their own rotating key material.
    assert_eq!(aes_str!("amsi.dll"), "amsi.dll");
    assert_eq!(aes_str!("AmsiScanBuffer"), "AmsiScanBuffer");
    assert_eq!(aes_str!("EtwEventWrite"), "EtwEventWrite");
}
