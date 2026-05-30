// src/bin/client_service.rs
//
// Windows Service wrapper. Registers as a service with the SCM and runs
// the agent in the service context. Install with:
//   sc create RCMAgent binPath= "C:\path\to\service.exe"
//   sc start RCMAgent

#[cfg(target_os = "windows")]
mod win_service {
    use std::ffi::c_void;
    use std::ptr;
    use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

    static RUNNING: AtomicBool = AtomicBool::new(true);
    static SERVICE_STATUS_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

    #[repr(C)]
    struct SERVICE_STATUS {
        dw_service_type: u32,
        dw_current_state: u32,
        dw_controls_accepted: u32,
        dw_win32_exit_code: u32,
        dw_service_specific_exit_code: u32,
        dw_check_point: u32,
        dw_wait_hint: u32,
    }

    #[repr(C)]
    struct SERVICE_TABLE_ENTRY {
        lp_service_name: *const u8,
        lp_service_proc: unsafe extern "system" fn(u32, *mut *mut u8),
    }

    extern "system" {
        fn StartServiceCtrlDispatcherA(table: *const SERVICE_TABLE_ENTRY) -> i32;
        fn RegisterServiceCtrlHandlerA(name: *const u8, handler: unsafe extern "system" fn(u32)) -> *mut c_void;
        fn SetServiceStatus(handle: *mut c_void, status: *mut SERVICE_STATUS) -> i32;
    }

    const SERVICE_WIN32_OWN_PROCESS: u32 = 0x10;
    const SERVICE_RUNNING: u32 = 4;
    const SERVICE_STOPPED: u32 = 1;
    const SERVICE_ACCEPT_STOP: u32 = 1;
    const SERVICE_CONTROL_STOP: u32 = 1;

    unsafe extern "system" fn service_ctrl_handler(control: u32) {
        if control == SERVICE_CONTROL_STOP {
            RUNNING.store(false, Ordering::Relaxed);
            let mut status = SERVICE_STATUS {
                dw_service_type: SERVICE_WIN32_OWN_PROCESS,
                dw_current_state: SERVICE_STOPPED,
                dw_controls_accepted: 0,
                dw_win32_exit_code: 0,
                dw_service_specific_exit_code: 0,
                dw_check_point: 0,
                dw_wait_hint: 0,
            };
            SetServiceStatus(SERVICE_STATUS_HANDLE.load(Ordering::Relaxed), &mut status);
        }
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u8) {
        SERVICE_STATUS_HANDLE.store(RegisterServiceCtrlHandlerA(
            b"RCMAgent\0".as_ptr(),
            service_ctrl_handler,
        ), Ordering::Relaxed);

        let mut status = SERVICE_STATUS {
            dw_service_type: SERVICE_WIN32_OWN_PROCESS,
            dw_current_state: SERVICE_RUNNING,
            dw_controls_accepted: SERVICE_ACCEPT_STOP,
            dw_win32_exit_code: 0,
            dw_service_specific_exit_code: 0,
            dw_check_point: 0,
            dw_wait_hint: 0,
        };
        SetServiceStatus(SERVICE_STATUS_HANDLE.load(Ordering::Relaxed), &mut status);

        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(_) => {
                // Report service stopped on failure
                let mut fail_status = SERVICE_STATUS {
                    dw_service_type: SERVICE_WIN32_OWN_PROCESS,
                    dw_current_state: SERVICE_STOPPED,
                    dw_controls_accepted: 0,
                    dw_win32_exit_code: 1,
                    dw_service_specific_exit_code: 0,
                    dw_check_point: 0,
                    dw_wait_hint: 0,
                };
                SetServiceStatus(SERVICE_STATUS_HANDLE.load(Ordering::Relaxed), &mut fail_status);
                return;
            }
        };
        rt.block_on(async {
            let _ = rcm::agent::run().await;
        });
    }

    pub fn run_as_service() {
        unsafe {
            let table = [
                SERVICE_TABLE_ENTRY {
                    lp_service_name: b"RCMAgent\0".as_ptr(),
                    lp_service_proc: service_main,
                },
                SERVICE_TABLE_ENTRY {
                    lp_service_name: ptr::null(),
                    lp_service_proc: std::mem::zeroed(),
                },
            ];
            StartServiceCtrlDispatcherA(table.as_ptr());
        }
    }
}

#[cfg(target_os = "windows")]
fn main() {
    win_service::run_as_service();
}

#[cfg(not(target_os = "windows"))]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("[!] Service mode is Windows-only, running as normal agent");
    rcm::agent::run().await
}
