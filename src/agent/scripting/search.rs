// src/agent/scripting/search.rs
use rhai::Engine;
use std::fs;
use walkdir::WalkDir;
use regex::Regex;
use serde_json::json;
use super::helpers::{glob_to_regex, json_get_path};

pub fn register(engine: &mut Engine) {

    // ── File content search ───────────────────────────────────────────────────

    // Grep for a regex pattern across a file or directory tree.
    // Returns JSON array of {file, line, content} objects (max 10k matches).
    engine.register_fn("internal_grep", |pattern: &str, path: &str, recursive: bool| -> String {
        let re = match Regex::new(pattern) {
            Ok(r)  => r,
            Err(e) => return format!("Error: invalid regex: {}", e),
        };
        let mut results = Vec::new();
        let walker = if recursive {
            WalkDir::new(path)
        } else {
            WalkDir::new(path).max_depth(1)
        };
        'outer: for entry in walker.into_iter().filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() { continue; }
            if let Ok(content) = fs::read_to_string(entry.path()) {
                for (line_no, line) in content.lines().enumerate() {
                    if re.is_match(line) {
                        results.push(json!({
                            "file":    entry.path().display().to_string(),
                            "line":    line_no + 1,
                            "content": line,
                        }));
                        if results.len() >= 10_000 { break 'outer; }
                    }
                }
            }
        }
        serde_json::to_string(&results).unwrap_or("[]".into())
    });

    // Find files matching a glob pattern (*, ?) under root.
    // max_depth <= 0 means unlimited depth.
    // Returns JSON array of paths (max 50k entries).
    engine.register_fn("internal_find_files", |root: &str, pattern: &str, max_depth: i64| -> String {
        let re_str = glob_to_regex(pattern);
        let re = match Regex::new(&re_str) {
            Ok(r)  => r,
            Err(e) => return format!("Error: {}", e),
        };
        let depth = if max_depth <= 0 { usize::MAX } else { max_depth as usize };
        let results: Vec<String> = WalkDir::new(root)
            .max_depth(depth)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| re.is_match(&e.file_name().to_string_lossy()))
            .map(|e| e.path().display().to_string())
            .take(50_000)
            .collect();
        serde_json::to_string(&results).unwrap_or("[]".into())
    });

    // ── Regex ─────────────────────────────────────────────────────────────────

    engine.register_fn("internal_regex_match", |pattern: &str, text: &str| -> String {
        if Regex::new(pattern).map(|re| re.is_match(text)).unwrap_or(false) {
            "true".into()
        } else {
            "false".into()
        }
    });

    // Returns JSON array of all non-overlapping match strings.
    engine.register_fn("internal_regex_findall", |pattern: &str, text: &str| -> String {
        let re = match Regex::new(pattern) {
            Ok(r)  => r,
            Err(e) => return format!("Error: {}", e),
        };
        let matches: Vec<&str> = re.find_iter(text).map(|m| m.as_str()).collect();
        serde_json::to_string(&matches).unwrap_or("[]".into())
    });

    // ── JSON dotted-path accessor ─────────────────────────────────────────────
    // Traverses nested objects and arrays by a dot-separated path.
    // Array indices are accepted as numeric path segments ("results.0.name").

    engine.register_fn("internal_json_get", |json_str: &str, path: &str| -> String {
        json_get_path(json_str, path)
    });
}
