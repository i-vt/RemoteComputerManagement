// src/config_consts.rs
//
// Compile-time-only constants: values that CANNOT come from the runtime
// typed config tree (src/config.rs) because they are used in const-eval
// contexts - array sizes, const fns, match patterns, type-level constants -
// or because they are fixed by the OS ABI or a wire/file format rather
// than being operator-tunable.
//
// Rule: a value lives here only if `config()` (runtime, non-const) cannot
// legally appear at its use site. Everything else belongs in src/config.rs.
// Each entry carries a one-line provenance comment naming its origin.

// ── COFF relocation type tags (x64) ─────────────────────────────────────────
// Provenance: src/agent/inmem.rs (bof) - used as match patterns when
// relocating BOF sections, so they must remain consts. Values are fixed by
// the PE/COFF specification.

/// IMAGE_REL_AMD64_ADDR64 - 64-bit absolute address relocation.
pub const IMAGE_REL_AMD64_ADDR64: u16 = 1;
/// IMAGE_REL_AMD64_ADDR32NB - 32-bit address w/o image base (RVA).
pub const IMAGE_REL_AMD64_ADDR32NB: u16 = 3;
/// IMAGE_REL_AMD64_REL32 - 32-bit PC-relative relocation.
pub const IMAGE_REL_AMD64_REL32: u16 = 4;

// ── Ekko sleep-mask PE header backup ────────────────────────────────────────
// Provenance: src/agent/evasion/sleep.rs (HEADER_BACKUP) - used as the size
// of a stack array (`[u8; N]`), a const-eval context. 4 KiB covers all
// standard PE headers.

/// Bytes of PE header backed up and zeroed by ekko_sleep (4 KiB).
pub const EKKO_HEADER_BACKUP_BYTES: usize = 0x1000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coff_reloc_tags_match_pe_coff_spec() {
        // Values pinned by the PE/COFF specification (x64 relocation types).
        assert_eq!(IMAGE_REL_AMD64_ADDR64, 1);
        assert_eq!(IMAGE_REL_AMD64_ADDR32NB, 3);
        assert_eq!(IMAGE_REL_AMD64_REL32, 4);
    }

    #[test]
    fn ekko_header_backup_is_one_page() {
        assert_eq!(EKKO_HEADER_BACKUP_BYTES, 4096);
    }
}