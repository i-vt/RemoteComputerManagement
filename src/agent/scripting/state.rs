// src/agent/scripting/state.rs
//
// In-memory KV store that persists across calls within the same agent session.
// The Arc<Mutex<HashMap>> lives on ExtensionManager and is cloned into each
// closure so all functions share the same underlying map.

use rhai::Engine;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use crate::strcrypt_rt;
use strcrypt::aes_str;

pub fn register(engine: &mut Engine, state: Arc<Mutex<HashMap<String, String>>>) {

    let s = state.clone();
    engine.register_fn(&aes_str!("internal_state_set"), move |key: &str, value: &str| -> String {
        match s.lock() {
            Ok(mut g) => { g.insert(key.to_string(), value.to_string()); aes_str!("OK") }
            Err(e)    => format!("{}{}", aes_str!("Error: lock poisoned: "), e),
        }
    });

    let s = state.clone();
    engine.register_fn(&aes_str!("internal_state_get"), move |key: &str| -> String {
        match s.lock() {
            Ok(g)  => g.get(key).cloned().unwrap_or_else(|| "".into()),
            Err(e) => format!("{}{}", aes_str!("Error: lock poisoned: "), e),
        }
    });

    let s = state.clone();
    engine.register_fn(&aes_str!("internal_state_delete"), move |key: &str| -> String {
        match s.lock() {
            Ok(mut g) => if g.remove(key).is_some() { aes_str!("Deleted") } else { aes_str!("Not found") },
            Err(e)    => format!("{}{}", aes_str!("Error: lock poisoned: "), e),
        }
    });

    let s = state.clone();
    engine.register_fn(&aes_str!("internal_state_keys"), move || -> String {
        match s.lock() {
            Ok(g) => {
                let keys: Vec<&String> = g.keys().collect();
                serde_json::to_string(&keys).unwrap_or("[]".into())
            }
            Err(e) => format!("{}{}", aes_str!("Error: lock poisoned: "), e),
        }
    });

    let s = state.clone();
    engine.register_fn(&aes_str!("internal_state_clear"), move || -> String {
        match s.lock() {
            Ok(mut g) => { g.clear(); aes_str!("Cleared") }
            Err(e)    => format!("{}{}", aes_str!("Error: lock poisoned: "), e),
        }
    });
}