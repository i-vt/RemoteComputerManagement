// src/agent/scripting/winext.rs
use rhai::Engine;

pub fn register(engine: &mut Engine) {

    // ── Windows Event Log ─────────────────────────────────────────────────────

    // Query Windows Event Log.
    // log_name: "Security" | "System" | "Application" | custom channel
    // xpath:    XPath filter string, e.g. "*[System[EventID=4624]]" or "*"
    // max:      maximum number of events to return (capped at 500)
    // Returns JSON array of raw XML event strings.
    engine.register_fn("internal_eventlog_query", |log_name: &str, xpath: &str, max: i64| -> String {
        #[cfg(target_os = "windows")]
        {
            use super::win_ffi::evtlog_ext::*;
            let limit = max.max(1).min(500) as u32;
            unsafe {
                let channel = to_wide(log_name);
                let query   = to_wide(xpath);
                let h_query = EvtQuery(
                    std::ptr::null_mut(),
                    channel.as_ptr(),
                    query.as_ptr(),
                    EVT_QUERY_CHANNEL_PATH | EVT_QUERY_REVERSE_DIRECTION,
                );
                if h_query.is_null() { return "Error: EvtQuery failed".into(); }
                let mut events = Vec::new();
                let mut batch  = [std::ptr::null_mut::<std::ffi::c_void>(); 10];
                let mut returned: u32 = 0;
                'outer: loop {
                    returned = 0;
                    if EvtNext(h_query, batch.len() as u32, batch.as_mut_ptr() as *mut EVT_HANDLE, 1000, 0, &mut returned) == 0 { break; }
                    for &evt in &batch[..returned as usize] {
                        let xml = render_event_xml(evt);
                        EvtClose(evt);
                        events.push(xml);
                        if events.len() >= limit as usize { break 'outer; }
                    }
                }
                EvtClose(h_query);
                serde_json::to_string(&events).unwrap_or("[]".into())
            }
        }
        #[cfg(not(target_os = "windows"))]
        format!("Error: eventlog_query is Windows only ({}, {})", log_name, xpath)
    });

    // Clear a Windows Event Log channel (requires admin).
    engine.register_fn("internal_eventlog_clear", |log_name: &str| -> String {
        #[cfg(target_os = "windows")]
        {
            use super::win_ffi::evtlog_ext::*;
            let channel = to_wide(log_name);
            unsafe {
                let ok = EvtClearLog(
                    std::ptr::null_mut(),
                    channel.as_ptr(),
                    std::ptr::null(),
                    0,
                );
                if ok != 0 { format!("Cleared: {}", log_name) }
                else { "Error: EvtClearLog failed (check admin rights)".into() }
            }
        }
        #[cfg(not(target_os = "windows"))]
        format!("Error: eventlog_clear is Windows only ({})", log_name)
    });

    // ── Windows Services ──────────────────────────────────────────────────────

    // Enumerate all services — returns JSON array of {name, display_name, state, pid}.
    engine.register_fn("internal_service_enum", || -> String {
        #[cfg(target_os = "windows")]
        {
            use super::win_ffi::svc_ext::*;
            unsafe {
                let h_scm = OpenSCManagerA(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS);
                if h_scm.is_null() { return "Error: OpenSCManager failed".into(); }
                let mut bytes_needed: DWORD = 0;
                let mut returned:     DWORD = 0;
                let mut resume:       DWORD = 0;
                // First call: get required buffer size.
                EnumServicesStatusExA(h_scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                    SERVICE_STATE_ALL, std::ptr::null_mut(), 0,
                    &mut bytes_needed, &mut returned, &mut resume, std::ptr::null());
                let mut buf = vec![0u8; bytes_needed as usize];
                resume = 0;
                let ok = EnumServicesStatusExA(h_scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                    SERVICE_STATE_ALL, buf.as_mut_ptr(), buf.len() as DWORD,
                    &mut bytes_needed, &mut returned, &mut resume, std::ptr::null());
                CloseServiceHandle(h_scm);
                if ok == 0 { return "Error: EnumServicesStatusEx failed".into(); }
                // Parse the variable-length ENUM_SERVICE_STATUS_PROCESS array.
                let services = parse_service_list(&buf, returned);
                serde_json::to_string(&services).unwrap_or("[]".into())
            }
        }
        #[cfg(not(target_os = "windows"))]
        "Error: service_enum is Windows only".into()
    });

    engine.register_fn("internal_service_start", |name: &str| -> String {
        #[cfg(target_os = "windows")]
        {
            use std::ffi::CString;
            use super::win_ffi::svc_ext::*;
            let cname = match CString::new(name) { Ok(s) => s, Err(_) => return "Error: invalid name".into() };
            unsafe {
                let h_scm = OpenSCManagerA(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS);
                if h_scm.is_null() { return "Error: OpenSCManager failed".into(); }
                let h_svc = OpenServiceA(h_scm, cname.as_ptr(), SERVICE_ALL_ACCESS);
                CloseServiceHandle(h_scm);
                if h_svc.is_null() { return format!("Error: service '{}' not found", name); }
                let ok = StartServiceA(h_svc, 0, std::ptr::null());
                CloseServiceHandle(h_svc);
                if ok != 0 { format!("Started: {}", name) } else { "Error: StartService failed".into() }
            }
        }
        #[cfg(not(target_os = "windows"))]
        format!("Error: service_start is Windows only ({})", name)
    });

    engine.register_fn("internal_service_stop", |name: &str| -> String {
        #[cfg(target_os = "windows")]
        {
            use std::ffi::CString;
            use super::win_ffi::svc_ext::*;
            let cname = match CString::new(name) { Ok(s) => s, Err(_) => return "Error: invalid name".into() };
            unsafe {
                let h_scm = OpenSCManagerA(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS);
                if h_scm.is_null() { return "Error: OpenSCManager failed".into(); }
                let h_svc = OpenServiceA(h_scm, cname.as_ptr(), SERVICE_ALL_ACCESS);
                CloseServiceHandle(h_scm);
                if h_svc.is_null() { return format!("Error: service '{}' not found", name); }
                let mut status = ServiceStatus {
                    dw_service_type: 0, dw_current_state: 0, dw_controls_accepted: 0,
                    dw_win32_exit_code: 0, dw_service_specific_exit: 0, dw_check_point: 0, dw_wait_hint: 0,
                };
                let ok = ControlService(h_svc, SERVICE_CONTROL_STOP, &mut status);
                CloseServiceHandle(h_svc);
                if ok != 0 { format!("Stopped: {}", name) } else { "Error: ControlService failed".into() }
            }
        }
        #[cfg(not(target_os = "windows"))]
        format!("Error: service_stop is Windows only ({})", name)
    });

    engine.register_fn("internal_service_create", |name: &str, display: &str, binary_path: &str, auto_start: bool| -> String {
        #[cfg(target_os = "windows")]
        {
            use std::ffi::CString;
            use super::win_ffi::svc_ext::*;
            let cname    = match CString::new(name)        { Ok(s) => s, Err(_) => return "Error: invalid name".into() };
            let cdisp    = match CString::new(display)     { Ok(s) => s, Err(_) => return "Error: invalid display".into() };
            let cbin     = match CString::new(binary_path) { Ok(s) => s, Err(_) => return "Error: invalid path".into() };
            let start_type = if auto_start { SERVICE_AUTO_START } else { SERVICE_DEMAND_START };
            unsafe {
                let h_scm = OpenSCManagerA(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS);
                if h_scm.is_null() { return "Error: OpenSCManager failed (admin required)".into(); }
                let h_svc = CreateServiceA(
                    h_scm, cname.as_ptr(), cdisp.as_ptr(),
                    SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, start_type,
                    SERVICE_ERROR_NORMAL, cbin.as_ptr(),
                    std::ptr::null(), std::ptr::null_mut(), std::ptr::null(),
                    std::ptr::null(), std::ptr::null(),
                );
                CloseServiceHandle(h_scm);
                if h_svc.is_null() { return "Error: CreateService failed".into(); }
                CloseServiceHandle(h_svc);
                format!("Created service: {}", name)
            }
        }
        #[cfg(not(target_os = "windows"))]
        format!("Error: service_create is Windows only ({})", name)
    });

    engine.register_fn("internal_service_delete", |name: &str| -> String {
        #[cfg(target_os = "windows")]
        {
            use std::ffi::CString;
            use super::win_ffi::svc_ext::*;
            let cname = match CString::new(name) { Ok(s) => s, Err(_) => return "Error: invalid name".into() };
            unsafe {
                let h_scm = OpenSCManagerA(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS);
                if h_scm.is_null() { return "Error: OpenSCManager failed".into(); }
                let h_svc = OpenServiceA(h_scm, cname.as_ptr(), SERVICE_ALL_ACCESS);
                CloseServiceHandle(h_scm);
                if h_svc.is_null() { return format!("Error: service '{}' not found", name); }
                let ok = DeleteService(h_svc);
                CloseServiceHandle(h_svc);
                if ok != 0 { format!("Deleted: {}", name) } else { "Error: DeleteService failed".into() }
            }
        }
        #[cfg(not(target_os = "windows"))]
        format!("Error: service_delete is Windows only ({})", name)
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Windows helpers
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
unsafe fn render_event_xml(evt: super::win_ffi::evtlog_ext::EVT_HANDLE) -> String {
    use super::win_ffi::evtlog_ext::*;
    let mut used: u32 = 0; let mut prop: u32 = 0;
    EvtRender(std::ptr::null_mut(), evt, EVT_RENDER_EVENT_XML, 0, std::ptr::null_mut(), &mut used, &mut prop);
    if used == 0 { return String::new(); }
    let mut buf = vec![0u16; (used as usize + 1) / 2 + 1];
    EvtRender(std::ptr::null_mut(), evt, EVT_RENDER_EVENT_XML, used, buf.as_mut_ptr() as _, &mut used, &mut prop);
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

#[cfg(target_os = "windows")]
fn parse_service_list(buf: &[u8], count: u32) -> Vec<serde_json::Value> {
    // ENUM_SERVICE_STATUS_PROCESS has two pointer-width strings (name, display)
    // followed by SERVICE_STATUS_PROCESS. On 64-bit: 8+8+36 = 52 bytes per entry.
    let entry_size = if cfg!(target_pointer_width = "64") { 56usize } else { 36usize };
    (0..count as usize)
        .filter_map(|i| {
            let off = i * entry_size;
            if off + entry_size > buf.len() { return None; }
            // First field: pointer to service name string (relative to buf base).
            let name_ptr = if cfg!(target_pointer_width = "64") {
                u64::from_le_bytes(buf[off..off+8].try_into().ok()?) as usize
            } else {
                u32::from_le_bytes(buf[off..off+4].try_into().ok()?) as usize
            };
            let base = buf.as_ptr() as usize;
            let state_off = if cfg!(target_pointer_width = "64") { off + 16 + 4 } else { off + 8 + 4 };
            let state = u32::from_le_bytes(buf.get(state_off..state_off+4)?.try_into().ok()?);
            let pid_off = state_off + 24;
            let pid = u32::from_le_bytes(buf.get(pid_off..pid_off+4)?.try_into().ok()?);
            let name = if name_ptr > base {
                let rel = name_ptr - base;
                let end = buf[rel..].iter().position(|&b| b == 0).unwrap_or(0);
                String::from_utf8_lossy(&buf[rel..rel+end]).to_string()
            } else { String::new() };
            Some(serde_json::json!({
                "name":  name,
                "state": state,
                "pid":   pid,
            }))
        })
        .collect()
}
