// src/streaming_zip.rs
//
// Streaming ZIP writer using data descriptors and ZIP64 extensions.
//
// Design goals:
//   • No temp file — output goes directly to any Write impl (channel, socket, file)
//   • Constant RAM usage — only the current file's 64 KB copy buffer is live
//   • ZIP64 throughout — handles files and archives of any size (tested to TB scale)
//   • Files stored uncompressed (method = 0) — compression is optional and would
//     require holding compressed output in RAM before writing the local header
//
// Wire format per file entry:
//   local_file_header  (30 fixed + filename_len + 20 ZIP64 extra)
//   raw_file_data      (any length)
//   data_descriptor    (24: sig(4) + crc32(4) + comp_size(8) + uncomp_size(8))
//
// Followed by the central directory and end records (ZIP64 + standard EOCD).
//
// Data descriptors (GP bit 3) let us write local headers before we know the
// file's CRC-32 or size, eliminating the need to seek back.  All major unzip
// tools (7-zip, info-zip, macOS, Windows Explorer, Python zipfile) accept this.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

// ── CRC-32/ISO-HDLC (polynomial 0xEDB88320) ──────────────────────────────────

const fn build_crc32_table() -> [u32; 256] {
    let poly: u32 = 0xEDB8_8320;
    let mut t = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0u8;
        while k < 8 {
            if c & 1 != 0 { c = poly ^ (c >> 1); } else { c >>= 1; }
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}
static CRC32_TABLE: [u32; 256] = build_crc32_table();

struct Crc32(u32);
impl Crc32 {
    fn new()  -> Self  { Crc32(0xFFFF_FFFF) }
    fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.0 = CRC32_TABLE[((self.0 ^ b as u32) & 0xFF) as usize] ^ (self.0 >> 8);
        }
    }
    fn finish(self) -> u32 { self.0 ^ 0xFFFF_FFFF }
}

// ── Little-endian helpers ─────────────────────────────────────────────────────

#[inline] fn w16(w: &mut impl Write, v: u16) -> io::Result<()> { w.write_all(&v.to_le_bytes()) }
#[inline] fn w32(w: &mut impl Write, v: u32) -> io::Result<()> { w.write_all(&v.to_le_bytes()) }
#[inline] fn w64(w: &mut impl Write, v: u64) -> io::Result<()> { w.write_all(&v.to_le_bytes()) }

// ── ZIP signatures (little-endian, written as u32) ───────────────────────────

const LFH:    u32 = 0x0403_4B50; // Local File Header
const DD:     u32 = 0x0807_4B50; // Data Descriptor
const CDH:    u32 = 0x0201_4B50; // Central Directory Header
const EOCD:   u32 = 0x0605_4B50; // End of Central Directory
const Z64EOD: u32 = 0x0606_4B50; // ZIP64 End of Central Directory
const Z64LOC: u32 = 0x0706_4B50; // ZIP64 EOCD Locator

// ── Metadata collected while writing local entries, used for central dir ─────

struct CdEntry {
    name:   Vec<u8>,  // UTF-8 path, dirs end with '/'
    crc:    u32,
    size:   u64,      // both compressed and uncompressed (Stored)
    offset: u64,      // byte offset of local header from start of archive
    mtime:  u16,      // DOS time
    mdate:  u16,      // DOS date
    is_dir: bool,
}

/// Approximate Unix-epoch → DOS date/time.
/// Only used for metadata; transfer correctness does not depend on it.
fn to_dos(unix_secs: u64) -> (u16, u16) {
    let s   = ((unix_secs        % 60) / 2) as u16;   // 2-second resolution
    let min = ((unix_secs /   60) % 60) as u16;
    let h   = ((unix_secs / 3600) % 24) as u16;
    let time = (h << 11) | (min << 5) | s;
    // Fixed date 2024-01-01: (2024-1980=44)<<9 | 1<<5 | 1 = 22561
    (time, 22561)
}

// ── Local entry writers ───────────────────────────────────────────────────────

/// Write one file's local header + data + data descriptor.
/// The header has GP bit 3 set (data descriptor follows) so CRC and sizes
/// are written as zeros there and supplied afterward in the data descriptor.
fn write_file_entry<W, R>(
    out:    &mut W,
    src:    &mut R,
    name:   &[u8],
    mt:     (u16, u16),   // (dos_time, dos_date)
    pos:    &mut u64,     // running byte offset, updated in place
) -> io::Result<CdEntry>
where
    W: Write,
    R: Read,
{
    let name_len: u16 = name.len() as u16;
    // ZIP64 extra field for local header:
    //   tag (2) + data_size (2) + original_size (8) + compressed_size (8) = 20 bytes
    // Sizes are zero here; actual values go in the data descriptor.
    const EXTRA_LEN: u16 = 20;

    let local_offset = *pos;

    // Local file header (30 fixed bytes)
    w32(out, LFH)?;
    w16(out, 45)?;              // version needed to extract: 4.5 (ZIP64)
    w16(out, 0x0808)?;          // GP flags: bit3=data-descriptor, bit11=UTF-8
    w16(out, 0)?;               // compression method: Stored
    w16(out, mt.0)?;            // mod time
    w16(out, mt.1)?;            // mod date
    w32(out, 0)?;               // CRC-32 placeholder
    w32(out, 0xFFFF_FFFF)?;     // compressed size  (0xFFFFFFFF → see ZIP64 extra)
    w32(out, 0xFFFF_FFFF)?;     // uncompressed size (0xFFFFFFFF → see ZIP64 extra)
    w16(out, name_len)?;
    w16(out, EXTRA_LEN)?;
    out.write_all(name)?;
    // ZIP64 extra field
    w16(out, 0x0001)?;   // Zip64 Extended Information Extra Field tag
    w16(out, 16)?;       // size of following data (orig+comp = 8+8)
    w64(out, 0)?;        // original size placeholder
    w64(out, 0)?;        // compressed size placeholder
    *pos += 30 + name_len as u64 + EXTRA_LEN as u64;

    // Stream file data, computing CRC-32 and byte count on the fly.
    // 64 KB buffer: small enough to avoid significant RAM overhead even for
    // millions of tiny files, large enough to keep syscall overhead low.
    let mut crc = Crc32::new();
    let mut size: u64 = 0;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 { break; }
        out.write_all(&buf[..n])?;
        crc.update(&buf[..n]);
        size += n as u64;
    }
    *pos += size;
    let crc_val = crc.finish();

    // Data descriptor (ZIP64 format): sig | crc32 | comp_size (8) | uncomp_size (8)
    // Using 8-byte sizes to match the ZIP64 local header.
    w32(out, DD)?;
    w32(out, crc_val)?;
    w64(out, size)?;   // compressed  = uncompressed for Stored
    w64(out, size)?;
    *pos += 24; // 4+4+8+8

    Ok(CdEntry {
        name: name.to_vec(), crc: crc_val, size,
        offset: local_offset, mtime: mt.0, mdate: mt.1, is_dir: false,
    })
}

/// Write a directory entry (zero-byte, no data descriptor needed).
fn write_dir_entry<W: Write>(
    out:  &mut W,
    name: &[u8],   // must end with '/'
    mt:   (u16, u16),
    pos:  &mut u64,
) -> io::Result<CdEntry> {
    let name_len: u16 = name.len() as u16;
    let local_offset = *pos;

    w32(out, LFH)?;
    w16(out, 20)?;         // version needed: 2.0
    w16(out, 0x0800)?;     // GP flags: bit11=UTF-8
    w16(out, 0)?;          // method: Stored
    w16(out, mt.0)?;
    w16(out, mt.1)?;
    w32(out, 0)?;          // CRC-32 = 0
    w32(out, 0)?;          // compressed size = 0
    w32(out, 0)?;          // uncompressed size = 0
    w16(out, name_len)?;
    w16(out, 0)?;          // no extra field
    out.write_all(name)?;
    *pos += 30 + name_len as u64;

    Ok(CdEntry {
        name: name.to_vec(), crc: 0, size: 0,
        offset: local_offset, mtime: mt.0, mdate: mt.1, is_dir: true,
    })
}

// ── Central directory + end records ──────────────────────────────────────────

fn write_central_directory<W: Write>(
    out:     &mut W,
    entries: &[CdEntry],
    pos:     &mut u64,
) -> io::Result<()> {
    let cd_start  = *pos;

    for e in entries {
        let name_len: u16 = e.name.len() as u16;
        // Central directory ZIP64 extra field for files:
        //   tag(2) + data_size(2) + orig_size(8) + comp_size(8) + local_hdr_offset(8) = 28 bytes
        let extra_len: u16 = if e.is_dir { 0 } else { 28 };

        w32(out, CDH)?;
        w16(out, 0x031E)?;    // version made by: Unix host, ZIP spec 3.0
        w16(out, if e.is_dir { 20 } else { 45 })?;   // version needed to extract
        w16(out, if e.is_dir { 0x0800 } else { 0x0808 })?; // GP flags (same as local)
        w16(out, 0)?;         // compression method: Stored
        w16(out, e.mtime)?;
        w16(out, e.mdate)?;
        w32(out, e.crc)?;
        // Use 0xFFFFFFFF to signal "see ZIP64 extra field"
        w32(out, if e.is_dir { 0 } else { 0xFFFF_FFFF })?; // compressed size
        w32(out, if e.is_dir { 0 } else { 0xFFFF_FFFF })?; // uncompressed size
        w16(out, name_len)?;
        w16(out, extra_len)?;
        w16(out, 0)?;         // comment length
        w16(out, 0)?;         // disk number start
        w16(out, 0)?;         // internal file attributes
        // External file attributes: Unix mode in high 16 bits
        w32(out, if e.is_dir { 0x41ED_0000 } else { 0x81A4_0000 })?;
        // Local header offset: 0xFFFFFFFF → see ZIP64 extra
        w32(out, if e.is_dir && e.offset <= 0xFFFF_FFFE {
            e.offset as u32
        } else {
            0xFFFF_FFFF
        })?;
        out.write_all(&e.name)?;
        *pos += 46 + name_len as u64;

        if !e.is_dir {
            // ZIP64 extra field: original size + compressed size + local header offset
            w16(out, 0x0001)?;        // ZIP64 tag
            w16(out, 24)?;            // data size: 3 × u64
            w64(out, e.size)?;        // original size
            w64(out, e.size)?;        // compressed size (= original for Stored)
            w64(out, e.offset)?;      // relative offset of local file header
            *pos += 28;
        }
    }

    let cd_size  = *pos - cd_start;
    let n        = entries.len() as u64;

    // ZIP64 End of Central Directory Record (56 bytes)
    w32(out, Z64EOD)?;
    w64(out, 44)?;        // size of this record after these 12 bytes = 56 - 12 = 44
    w16(out, 0x031E)?;    // version made by
    w16(out, 45)?;        // version needed to extract (4.5 for ZIP64)
    w32(out, 0)?;         // number of this disk
    w32(out, 0)?;         // disk with start of central directory
    w64(out, n)?;         // total entries on this disk
    w64(out, n)?;         // total entries in central directory
    w64(out, cd_size)?;   // size of central directory
    w64(out, cd_start)?;  // offset of start of central directory
    *pos += 56;

    // ZIP64 End of Central Directory Locator (20 bytes)
    w32(out, Z64LOC)?;
    w32(out, 0)?;              // disk with ZIP64 EOCD
    w64(out, *pos - 56)?;      // relative offset of ZIP64 EOCD record
    w32(out, 1)?;              // total number of disks
    *pos += 20;

    // End of Central Directory Record (22 bytes, required by all tools)
    let n16  = n.min(0xFFFF) as u16;
    let sz32 = cd_size.min(0xFFFF_FFFF) as u32;
    let of32 = cd_start.min(0xFFFF_FFFF) as u32;
    w32(out, EOCD)?;
    w16(out, 0)?; w16(out, 0)?;  // disk number / disk with start of CD
    w16(out, n16)?;              // entries on this disk
    w16(out, n16)?;              // total entries (capped for ZIP64 compat check)
    w32(out, sz32)?;
    w32(out, of32)?;
    w16(out, 0)?;                // comment length
    *pos += 22;

    Ok(())
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Write the contents of `root` as a streaming ZIP archive to `out`.
///
/// `base` must be the parent of `root`; it determines how entries appear in
/// the archive.  For example:
/// ```text
///   base = downloads/
///   root = downloads/20240101_session/
///   → archive contains  20240101_session/etc/passwd,  etc.
/// ```
///
/// The function uses an explicit stack traversal (no recursion), a 64 KB copy
/// buffer, and ZIP64 data descriptors, so RAM usage is O(1) regardless of the
/// number or size of files.  The central directory is kept in a `Vec<CdEntry>`
/// which grows to O(num_files × ~100 bytes) — for a million files that is
/// roughly 100 MB, which is acceptable.
pub fn write_zip_directory<W: Write>(
    out:  &mut W,
    base: &Path,
    root: &Path,
) -> io::Result<()> {
    let mut pos: u64 = 0;
    let mut entries: Vec<CdEntry> = Vec::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let read_dir = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(_) => continue,
        };

        // Sort children for deterministic zip ordering
        let mut children: Vec<PathBuf> = read_dir.flatten().map(|e| e.path()).collect();
        children.sort();

        for path in children {
            let rel = match path.strip_prefix(base) {
                Ok(r) => r.to_string_lossy().replace('\\', "/"),
                Err(_) => continue,
            };

            let meta = match std::fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };

            let unix_secs = meta.modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let mt = to_dos(unix_secs);

            if path.is_dir() {
                // Directory entries end with '/' per ZIP convention
                let dir_name = format!("{}/", rel);
                let e = write_dir_entry(out, dir_name.as_bytes(), mt, &mut pos)?;
                entries.push(e);
                stack.push(path);
            } else if path.is_file() {
                let mut f = std::fs::File::open(&path)?;
                let e = write_file_entry(out, &mut f, rel.as_bytes(), mt, &mut pos)?;
                entries.push(e);
            }
        }
    }

    write_central_directory(out, &entries, &mut pos)
}
