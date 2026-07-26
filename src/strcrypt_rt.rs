// ./src/strcrypt_rt.rs
//
// Runtime half of the strcrypt compile-time string cryptor. The strcrypt
// proc-macro encrypts string literals at build time and emits only
// (nonce, iv, tag, ciphertext) byte arrays; this module re-derives the
// per-string key and decrypts on use. See strcrypt/src/lib.rs for the
// full key schedule.
//
// The master key never exists as a single static image in the binary:
// build.rs emits it as four independent 16-byte hex shards
// (RCM_STRCRYPT_S1..S4) which are decoded and hashed together here on
// first use.
//
// Decryption never panics and never reveals which check failed; every
// failure mode returns the same fixed, non-informative string. Hot call
// sites should cache the result in a OnceLock (or use decrypt_cached)
// so the AES-GCM open runs only once per string.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

// Fixed, non-informative value returned for every failure mode (bad tag,
// bad key, bad utf8). It deliberately says nothing about what went wrong.
const DECRYPT_FAILED: &str = "<rcm>";

static MASTER_KEY: OnceLock<[u8; 32]> = OnceLock::new();

// Reassemble the master key from the four build-time shards and cache it.
// The shards live as four separate small statics via env!(); they are
// only combined in memory here.
fn master_key() -> &'static [u8; 32] {
    MASTER_KEY.get_or_init(|| {
        let mut buf = Vec::with_capacity(64);
        for shard in [
            env!("RCM_STRCRYPT_S1"),
            env!("RCM_STRCRYPT_S2"),
            env!("RCM_STRCRYPT_S3"),
            env!("RCM_STRCRYPT_S4"),
        ] {
            // A malformed shard yields a wrong master key; every decrypt
            // then fails closed to DECRYPT_FAILED instead of panicking.
            match hex::decode(shard) {
                Ok(bytes) => buf.extend_from_slice(&bytes),
                Err(_) => buf.extend_from_slice(&[0u8; 16]),
            }
        }
        let digest = Sha256::digest(&buf);
        let mut key = [0u8; 32];
        key.copy_from_slice(&digest);
        key
    })
}

// Per-string rotating key: skey = SHA256(master || nonce).
fn string_key(nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(master_key());
    hasher.update(nonce);
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

// Decrypt one record emitted by the aes_str! macro. The tag is passed
// separately (not appended to the ciphertext) so a static layout matches
// the macro's expansion exactly; it is rejoined here for the GCM open.
pub fn decrypt(nonce: &[u8; 32], iv: &[u8; 12], tag: &[u8; 16], ct: &[u8]) -> String {
    let key = string_key(nonce);
    let cipher = match Aes256Gcm::new_from_slice(&key) {
        Ok(cipher) => cipher,
        Err(_) => return DECRYPT_FAILED.to_string(),
    };
    let mut sealed = Vec::with_capacity(ct.len() + 16);
    sealed.extend_from_slice(ct);
    sealed.extend_from_slice(tag);
    match cipher.decrypt(Nonce::from_slice(iv), sealed.as_ref()) {
        Ok(plaintext) => {
            String::from_utf8(plaintext).unwrap_or_else(|_| DECRYPT_FAILED.to_string())
        }
        Err(_) => DECRYPT_FAILED.to_string(),
    }
}

// Once-per-string variant for hot paths: the caller owns the OnceLock,
// the AES-GCM open runs only on the first call.
pub fn decrypt_cached<'a>(
    cell: &'a OnceLock<String>,
    nonce: &[u8; 32],
    iv: &[u8; 12],
    tag: &[u8; 16],
    ct: &[u8],
) -> &'a str {
    cell.get_or_init(|| decrypt(nonce, iv, tag, ct)).as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    // Build an encrypted record exactly the way the strcrypt proc-macro
    // does at expansion time.
    fn encrypt_fixture(plaintext: &str) -> ([u8; 32], [u8; 12], [u8; 16], Vec<u8>) {
        let mut rng = rand::thread_rng();
        let mut nonce = [0u8; 32];
        let mut iv = [0u8; 12];
        rng.fill_bytes(&mut nonce);
        rng.fill_bytes(&mut iv);

        let key = string_key(&nonce);
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
    fn round_trip() {
        let (nonce, iv, tag, ct) = encrypt_fixture("ntdll.dll");
        assert_eq!(decrypt(&nonce, &iv, &tag, &ct), "ntdll.dll");
    }

    #[test]
    fn round_trip_empty() {
        let (nonce, iv, tag, ct) = encrypt_fixture("");
        assert_eq!(decrypt(&nonce, &iv, &tag, &ct), "");
    }

    #[test]
    fn tampered_tag_fails_closed() {
        let (nonce, iv, mut tag, ct) = encrypt_fixture("EtwEventWrite");
        tag[0] ^= 0x01;
        assert_eq!(decrypt(&nonce, &iv, &tag, &ct), DECRYPT_FAILED);
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        let (nonce, iv, tag, mut ct) = encrypt_fixture("AmsiScanBuffer");
        let last = ct.len() - 1;
        ct[last] ^= 0x80;
        assert_eq!(decrypt(&nonce, &iv, &tag, &ct), DECRYPT_FAILED);
    }

    #[test]
    fn wrong_nonce_fails_closed() {
        let (mut nonce, iv, tag, ct) = encrypt_fixture("kernel32.dll");
        nonce[31] ^= 0x01;
        assert_eq!(decrypt(&nonce, &iv, &tag, &ct), DECRYPT_FAILED);
    }

    #[test]
    fn wrong_iv_fails_closed() {
        let (nonce, mut iv, tag, ct) = encrypt_fixture("amsi.dll");
        iv[0] ^= 0x01;
        assert_eq!(decrypt(&nonce, &iv, &tag, &ct), DECRYPT_FAILED);
    }

    #[test]
    fn cached_variant_decrypts_once() {
        let (nonce, iv, tag, ct) = encrypt_fixture("VirtualAlloc");
        let cell = OnceLock::new();
        let first = decrypt_cached(&cell, &nonce, &iv, &tag, &ct);
        assert_eq!(first, "VirtualAlloc");
        // Second call serves the cached value and stays correct.
        assert_eq!(decrypt_cached(&cell, &nonce, &iv, &tag, &ct), "VirtualAlloc");
    }

    #[test]
    fn distinct_records_for_same_plaintext() {
        // Rotating keys: two encryptions of one string share nothing.
        let (n1, _i1, t1, c1) = encrypt_fixture("ntdll.dll");
        let (n2, i2, t2, c2) = encrypt_fixture("ntdll.dll");
        assert_ne!(n1, n2);
        assert_ne!(t1, t2);
        assert_ne!(c1, c2);
        // Cross-decrypt with the other record's nonce must fail closed.
        assert_eq!(decrypt(&n1, &i2, &t2, &c2), DECRYPT_FAILED);
    }
}