// ./src/rcm/mod.rs
// RCM-SPEC-001 v2.1 "RCM Data Collection and Packaging" - server-side module.
//
// Conformance claim: RCM Level 2 (Collector) + Screenshot (Sec 11) +
// Keylogger (Sec 12). Dirwalk (Sec 9), processlist (Sec 10), email (Sec 14)
// and netstat (Sec 15) are intentionally not implemented (a-la-carte per
// REQ-2.2).

pub mod xml;
pub mod paths;
pub mod counters;
pub mod sidecar;
pub mod fingerprint;
pub mod manifest;
pub mod custody;
pub mod logs;
pub mod package;
pub mod registry;

pub use fingerprint::UpsertOutcome;
pub use package::{
    PackageManager, CollectedMeta, ScreenshotMeta, KeyCapture, KeyEvent, RcmError,
};

// Re-export the global registry accessor so callers can write `rcm::registry()`
// (value namespace) alongside the `rcm::registry` module (type namespace).
pub use registry::registry;
