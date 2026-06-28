// src/agent/scripting/registry.rs
//
// Direct Windows Registry access via RegOpenKeyExA / RegQueryValueExA etc.
// Avoids spawning reg.exe which generates Sysmon Event ID 1 / Event 4688.
// All functions are no-ops that return descriptive errors on non-Windows.

use rhai::Engine;

pub fn register(engine: &mut Engine) {

    // Read a registry value. hive: "HKCU"|"HKLM"|"HKCR"|"HKU"
    // Returns the value as a string; DWORD/QWORD values are formatted as decimal.
    engine.register_fn("internal_reg_read", |hive: &str, key: &str, value_name: &str| -> String {
        #[cfg(target_os = "windows")]
        {
            use std::ffi::CString;
            use super::win_ffi::reg_ext::*;
            let hroot = match resolve_hive(hive) { Some(h) => h, None => return format!("Error: unknown hive {}", hive) };
            let ckey  = match CString::new(key)        { Ok(s) => s, Err(_) => return "Error: invalid key".into() };
            let cval  = match CString::new(value_name) { Ok(s) => s, Err(_) => return "Error: invalid name".into() };
            unsafe {
                let mut hkey: HKEY = std::ptr::null_mut();
                if RegOpenKeyExA(hroot, ckey.as_ptr(), 0, KEY_READ, &mut hkey) != ERROR_SUCCESS {
                    return "Error: key not found".into();
                }
                let mut data_type: DWORD = 0;
                let mut data_size: DWORD = 0;
                // Query size first.
                RegQueryValueExA(hkey, cval.as_ptr(), std::ptr::null_mut(), &mut data_type, std::ptr::null_mut(), &mut data_size);
                let mut buf = vec![0u8; data_size as usize + 2];
                let ret = RegQueryValueExA(hkey, cval.as_ptr(), std::ptr::null_mut(), &mut data_type, buf.as_mut_ptr(), &mut data_size);
                RegCloseKey(hkey);
                if ret != ERROR_SUCCESS { return format!("Error: query failed ({})", ret); }
                format_reg_value(data_type, &buf[..data_size as usize])
            }
        }
        #[cfg(not(target_os = "windows"))]
        format!("Error: Registry is Windows only ({}/{}/{}", hive, key, value_name)
    });

    // Write a string (REG_SZ) registry value.
    engine.register_fn("internal_reg_write", |hive: &str, key: &str, value_name: &str, data: &str| -> String {
        #[cfg(target_os = "windows")]
        {
            use std::ffi::CString;
            use super::win_ffi::reg_ext::*;
            let hroot = match resolve_hive(hive) { Some(h) => h, None => return format!("Error: unknown hive {}", hive) };
            let ckey  = match CString::new(key)        { Ok(s) => s, Err(_) => return "Error: invalid key".into() };
            let cval  = match CString::new(value_name) { Ok(s) => s, Err(_) => return "Error: invalid name".into() };
            let mut bytes: Vec<u8> = data.as_bytes().to_vec(); bytes.push(0); // null-terminate
            unsafe {
                let mut hkey: HKEY = std::ptr::null_mut();
                let mut disp: DWORD = 0;
                if RegCreateKeyExA(hroot, ckey.as_ptr(), 0, std::ptr::null_mut(), REG_OPTION_NON_VOLATILE, KEY_WRITE, std::ptr::null_mut(), &mut hkey, &mut disp) != ERROR_SUCCESS {
                    return "Error: could not open/create key".into();
                }
                let ret = RegSetValueExA(hkey, cval.as_ptr(), 0, REG_SZ, bytes.as_ptr(), bytes.len() as DWORD);
                RegCloseKey(hkey);
                if ret == ERROR_SUCCESS { "OK".into() } else { format!("Error: {}", ret) }
            }
        }
        #[cfg(not(target_os = "windows"))]
        format!("Error: Registry is Windows only")
    });

    // Delete a registry value.
    engine.register_fn("internal_reg_delete_value", |hive: &str, key: &str, value_name: &str| -> String {
        #[cfg(target_os = "windows")]
        {
            use std::ffi::CString;
            use super::win_ffi::reg_ext::*;
            let hroot = match resolve_hive(hive) { Some(h) => h, None => return format!("Error: unknown hive {}", hive) };
            let ckey  = match CString::new(key)        { Ok(s) => s, Err(_) => return "Error: invalid key".into() };
            let cval  = match CString::new(value_name) { Ok(s) => s, Err(_) => return "Error: invalid name".into() };
            unsafe {
                let mut hkey: HKEY = std::ptr::null_mut();
                if RegOpenKeyExA(hroot, ckey.as_ptr(), 0, KEY_WRITE, &mut hkey) != ERROR_SUCCESS {
                    return "Error: key not found".into();
                }
                let ret = RegDeleteValueA(hkey, cval.as_ptr());
                RegCloseKey(hkey);
                if ret == ERROR_SUCCESS { "Deleted".into() } else { format!("Error: {}", ret) }
            }
        }
        #[cfg(not(target_os = "windows"))]
        "Error: Registry is Windows only".into()
    });

    // Delete a registry key (and all its values).
    engine.register_fn("internal_reg_delete_key", |hive: &str, parent_key: &str, subkey: &str| -> String {
        #[cfg(target_os = "windows")]
        {
            use std::ffi::CString;
            use super::win_ffi::reg_ext::*;
            let hroot  = match resolve_hive(hive)    { Some(h) => h, None => return format!("Error: unknown hive {}", hive) };
            let cparent = match CString::new(parent_key) { Ok(s) => s, Err(_) => return "Error: invalid key".into() };
            let csub   = match CString::new(subkey)  { Ok(s) => s, Err(_) => return "Error: invalid subkey".into() };
            unsafe {
                let mut hkey: HKEY = std::ptr::null_mut();
                if RegOpenKeyExA(hroot, cparent.as_ptr(), 0, KEY_WRITE, &mut hkey) != ERROR_SUCCESS {
                    return "Error: parent key not found".into();
                }
                let ret = RegDeleteKeyA(hkey, csub.as_ptr());
                RegCloseKey(hkey);
                if ret == ERROR_SUCCESS { "Deleted".into() } else { format!("Error: {}", ret) }
            }
        }
        #[cfg(not(target_os = "windows"))]
        "Error: Registry is Windows only".into()
    });

    // Enumerate subkeys of a registry key — returns JSON array of names.
    engine.register_fn("internal_reg_enum_keys", |hive: &str, key: &str| -> String {
        #[cfg(target_os = "windows")]
        {
            use std::ffi::CString;
            use super::win_ffi::reg_ext::*;
            let hroot = match resolve_hive(hive) { Some(h) => h, None => return format!("Error: unknown hive {}", hive) };
            let ckey  = match CString::new(key)  { Ok(s) => s, Err(_) => return "Error: invalid key".into() };
            unsafe {
                let mut hkey: HKEY = std::ptr::null_mut();
                if RegOpenKeyExA(hroot, ckey.as_ptr(), 0, KEY_READ, &mut hkey) != ERROR_SUCCESS {
                    return "Error: key not found".into();
                }
                let mut names = Vec::new();
                let mut idx = 0u32;
                loop {
                    let mut name_buf = vec![0i8; 256];
                    let mut name_len = 256u32;
                    let ret = RegEnumKeyExA(hkey, idx, name_buf.as_mut_ptr(), &mut name_len,
                        std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut());
                    if ret == ERROR_NO_MORE_ITEMS { break; }
                    if ret != ERROR_SUCCESS { break; }
                    let name = String::from_utf8_lossy(
                        &name_buf[..name_len as usize].iter().map(|&b| b as u8).collect::<Vec<_>>()
                    ).to_string();
                    names.push(name);
                    idx += 1;
                }
                RegCloseKey(hkey);
                serde_json::to_string(&names).unwrap_or("[]".into())
            }
        }
        #[cfg(not(target_os = "windows"))]
        "Error: Registry is Windows only".into()
    });

    // Enumerate values in a registry key — returns JSON array of {name, type, data}.
    engine.register_fn("internal_reg_enum_values", |hive: &str, key: &str| -> String {
        #[cfg(target_os = "windows")]
        {
            use std::ffi::CString;
            use super::win_ffi::reg_ext::*;
            let hroot = match resolve_hive(hive) { Some(h) => h, None => return format!("Error: unknown hive {}", hive) };
            let ckey  = match CString::new(key)  { Ok(s) => s, Err(_) => return "Error: invalid key".into() };
            unsafe {
                let mut hkey: HKEY = std::ptr::null_mut();
                if RegOpenKeyExA(hroot, ckey.as_ptr(), 0, KEY_READ, &mut hkey) != ERROR_SUCCESS {
                    return "Error: key not found".into();
                }
                let mut values = Vec::new();
                let mut idx = 0u32;
                loop {
                    let mut name_buf  = vec![0i8;  256];
                    let mut name_len  = 256u32;
                    let mut data_buf  = vec![0u8; 4096];
                    let mut data_size = 4096u32;
                    let mut data_type = 0u32;
                    let ret = RegEnumValueA(hkey, idx,
                        name_buf.as_mut_ptr(), &mut name_len,
                        std::ptr::null_mut(), &mut data_type,
                        data_buf.as_mut_ptr(), &mut data_size);
                    if ret == ERROR_NO_MORE_ITEMS { break; }
                    if ret != ERROR_SUCCESS { break; }
                    let name = String::from_utf8_lossy(
                        &name_buf[..name_len as usize].iter().map(|&b| b as u8).collect::<Vec<_>>()
                    ).to_string();
                    let data = format_reg_value(data_type, &data_buf[..data_size as usize]);
                    values.push(serde_json::json!({ "name": name, "type": reg_type_name(data_type), "data": data }));
                    idx += 1;
                }
                RegCloseKey(hkey);
                serde_json::to_string(&values).unwrap_or("[]".into())
            }
        }
        #[cfg(not(target_os = "windows"))]
        "Error: Registry is Windows only".into()
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers (Windows only)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn resolve_hive(hive: &str) -> Option<super::win_ffi::reg_ext::HKEY> {
    use super::win_ffi::reg_ext::*;
    match hive.to_uppercase().as_str() {
        "HKCU" | "HKEY_CURRENT_USER"   => Some(HKEY_CURRENT_USER),
        "HKLM" | "HKEY_LOCAL_MACHINE"  => Some(HKEY_LOCAL_MACHINE),
        "HKCR" | "HKEY_CLASSES_ROOT"   => Some(HKEY_CLASSES_ROOT),
        "HKU"  | "HKEY_USERS"          => Some(HKEY_USERS),
        _                              => None,
    }
}

#[cfg(target_os = "windows")]
fn format_reg_value(data_type: u32, data: &[u8]) -> String {
    use super::win_ffi::reg_ext::*;
    match data_type {
        REG_SZ | REG_EXPAND_SZ => {
            let nul = data.chunks_exact(2)
                .position(|w| w[0] == 0 && w[1] == 0)
                .map(|i| i * 2)
                .unwrap_or(data.len());
            let wide: Vec<u16> = data[..nul].chunks_exact(2)
                .map(|w| u16::from_le_bytes([w[0], w[1]]))
                .collect();
            String::from_utf16_lossy(&wide)
        }
        REG_DWORD => {
            if data.len() >= 4 { u32::from_le_bytes([data[0], data[1], data[2], data[3]]).to_string() }
            else { "Error: short DWORD".into() }
        }
        REG_QWORD => {
            if data.len() >= 8 {
                u64::from_le_bytes(data[..8].try_into().unwrap_or([0u8; 8])).to_string()
            } else { "Error: short QWORD".into() }
        }
        REG_BINARY => hex::encode(data),
        _ => hex::encode(data),
    }
}

#[cfg(target_os = "windows")]
fn reg_type_name(t: u32) -> &'static str {
    use super::win_ffi::reg_ext::*;
    match t {
        REG_SZ        => "REG_SZ",
        REG_EXPAND_SZ => "REG_EXPAND_SZ",
        REG_BINARY    => "REG_BINARY",
        REG_DWORD     => "REG_DWORD",
        REG_QWORD     => "REG_QWORD",
        _             => "REG_UNKNOWN",
    }
}
