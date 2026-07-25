// strcrypt: compile-time AES-256-GCM string encryption for the RCM agent.
//
// aes_str!("literal") encrypts the literal at macro-expansion time and
// emits only a per-string nonce, an IV, a GCM tag and the ciphertext as
// byte-string literals. The plaintext never appears in the expanded
// source or in the compiled binary's string pool; it is recovered at
// runtime by strcrypt_rt::decrypt in the main crate.
//
// Per-string rotating key schedule:
//   master = SHA256(shard1 || shard2 || shard3 || shard4)
//            where the shards are the hex-decoded RCM_STRCRYPT_S1..S4
//            env vars emitted by build.rs (fresh every build)
//   nonce  = 32 random bytes, fresh per macro invocation
//   iv     = 12 random bytes, fresh per macro invocation
//   skey   = SHA256(master || nonce)
//   ct,tag = AES-256-GCM(skey, iv) over the literal bytes
//
// Because the nonce rotates per string, identical plaintexts encrypt to
// unrelated records and no single static key protects more than one
// string.
//
// The expansion calls strcrypt_rt::decrypt through a relative path, so
// every call site must bring the module into scope: `use crate::strcrypt_rt;`
// inside the agent, `use rcm::strcrypt_rt;` in integration tests.

use proc_macro::TokenStream;
use quote::quote;
use rand::RngCore;
use sha2::{Digest, Sha256};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

// Reassemble the master key from the four build-time shards. These are
// read from the environment of the rustc process that is expanding the
// macro; build.rs exports them via cargo:rustc-env on every build.
fn master_key() -> Result<[u8; 32], String> {
    let mut buf = Vec::with_capacity(64);
    for i in 1..=4u8 {
        let name = format!("RCM_STRCRYPT_S{}", i);
        let hex_shard = std::env::var(&name)
            .map_err(|_| format!("env var {} is not set (build.rs must emit it)", name))?;
        let shard = hex_decode(&hex_shard)
            .ok_or_else(|| format!("env var {} is not valid hex", name))?;
        if shard.len() != 16 {
            return Err(format!("env var {} must decode to 16 bytes", name));
        }
        buf.extend_from_slice(&shard);
    }
    let digest = Sha256::digest(&buf);
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    Ok(key)
}

fn expand(lit: &syn::LitStr) -> Result<proc_macro2::TokenStream, String> {
    let plaintext = lit.value();
    let master = master_key()?;

    // Fresh nonce and IV per invocation: this is what makes the keys
    // rotate from string to string even within one build.
    let mut rng = rand::thread_rng();
    let mut nonce = [0u8; 32];
    let mut iv = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    rng.fill_bytes(&mut iv);

    let mut key_material = Vec::with_capacity(64);
    key_material.extend_from_slice(&master);
    key_material.extend_from_slice(&nonce);
    let key = Sha256::digest(&key_material);

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let sealed = cipher
        .encrypt(Nonce::from_slice(&iv), plaintext.as_bytes())
        .map_err(|_| "AES-256-GCM encryption failed".to_string())?;
    // aes-gcm appends the 16-byte tag to the ciphertext; split it so the
    // record layout matches strcrypt_rt::decrypt's parameters.
    let (ct, tag) = sealed.split_at(sealed.len() - 16);

    // Byte-string literals render every byte as an escape, so nothing
    // readable survives into the expanded source.
    let nonce_lit = proc_macro2::Literal::byte_string(&nonce);
    let iv_lit = proc_macro2::Literal::byte_string(&iv);
    let tag_lit = proc_macro2::Literal::byte_string(tag);
    let ct_lit = proc_macro2::Literal::byte_string(ct);

    Ok(quote! {
        strcrypt_rt::decrypt(#nonce_lit, #iv_lit, #tag_lit, #ct_lit)
    })
}

#[proc_macro]
pub fn aes_str(input: TokenStream) -> TokenStream {
    let lit = match syn::parse::<syn::LitStr>(input) {
        Ok(lit) => lit,
        Err(err) => {
            return syn::Error::new(
                err.span(),
                "aes_str! expects a single string literal",
            )
            .to_compile_error()
            .into();
        }
    };
    match expand(&lit) {
        Ok(tokens) => tokens.into(),
        Err(msg) => syn::Error::new(lit.span(), msg).to_compile_error().into(),
    }
}
