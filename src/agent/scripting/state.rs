// src/agent/scripting/state.rs
//
// In-memory KV store that persists across calls within the same agent session.
// The Arc<Mutex<HashMap>> lives on ExtensionManager and is cloned into each
// closure so all functions share the same underlying map.

use rhai::Engine;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

pub fn register(engine: &mut Engine, state: Arc<Mutex<HashMap<String, String>>>) {

    let s = state.clone();
    engine.register_fn("internal_state_set", move |key: &str, value: &str| -> String {
        match s.lock() {
            Ok(mut g) => { g.insert(key.to_string(), value.to_string()); "OK".into() }
            Err(e)    => format!("Error: lock poisoned: {}", e),
        }
    });

    let s = state.clone();
    engine.register_fn("internal_state_get", move |key: &str| -> String {
        match s.lock() {
            Ok(g)  => g.get(key).cloned().unwrap_or_else(|| "".into()),
            Err(e) => format!("Error: lock poisoned: {}", e),
        }
    });

    let s = state.clone();
    engine.register_fn("internal_state_delete", move |key: &str| -> String {
        match s.lock() {
            Ok(mut g) => if g.remove(key).is_some() { "Deleted".into() } else { "Not found".into() },
            Err(e)    => format!("Error: lock poisoned: {}", e),
        }
    });

    let s = state.clone();
    engine.register_fn("internal_state_keys", move || -> String {
        match s.lock() {
            Ok(g) => {
                let keys: Vec<&String> = g.keys().collect();
                serde_json::to_string(&keys).unwrap_or("[]".into())
            }
            Err(e) => format!("Error: lock poisoned: {}", e),
        }
    });

    let s = state.clone();
    engine.register_fn("internal_state_clear", move || -> String {
        match s.lock() {
            Ok(mut g) => { g.clear(); "Cleared".into() }
            Err(e)    => format!("Error: lock poisoned: {}", e),
        }
    });
}
