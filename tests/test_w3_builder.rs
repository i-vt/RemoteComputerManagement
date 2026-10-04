//! Wave-3 builder checks: config-blob text carrier round-trip.
//!
//! build.rs embeds the encrypted C2 config as chunked base64 text
//! (CONFIG_CIPHER_B64, a concat! of short literals) decoded inside the
//! generated get_config(); the crypto itself is unchanged. These tests pin
//! the carrier format using the same primitives the generated code uses.

use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

#[test]
fn carrier_roundtrip_decrypts_original() {
    let key = [7u8; 32];
    let nonce = [3u8; 12];
    let plaintext: Vec<u8> = (0u8..=255).cycle().take(4096).collect();

    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&key))
        .encrypt(aes_gcm::Nonce::from_slice(&nonce), plaintext.as_slice())
        .unwrap();

    // The carrier as build.rs emits it: base64 text, chunked into 100-char
    // concat! lines (ASCII, so chunking on byte offsets is safe).
    let b64 = BASE64.encode(&cipher);
    assert!(b64.bytes().all(|b| b.is_ascii_graphic() || b == b'='));
    let rejoined: String = b64
        .as_bytes()
        .chunks(100)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    assert_eq!(rejoined, b64);

    // Mirror of the generated get_config(): decode then decrypt.
    let decoded = BASE64.decode(&rejoined).unwrap();
    assert_eq!(decoded, cipher);
    let back = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&key))
        .decrypt(aes_gcm::Nonce::from_slice(&nonce), decoded.as_slice())
        .unwrap();
    assert_eq!(back, plaintext);
}

#[test]
fn carrier_rejects_corrupt_text() {
    // get_config() exits on decode failure; the decode step itself must
    // reject non-base64 content.
    assert!(BASE64.decode("not*valid*base64!!!").is_err());
}
