use std::fs::File;
use std::fs::OpenOptions; 
use std::io::{Read, Write};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::path::{Path, PathBuf};
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct RecursiveReport {
    pub root_path: String,
    pub total_files_found: usize,
    pub total_success: usize, 
    pub failed_downloads: Vec<(String, String)>, 
}

#[derive(Serialize, Deserialize)]
struct FileMetadata {
    original_filepath: String,
    filename: String,
    extension: String,
    permissions: String,
    filesize_bytes: u64,
    sha256: String,
}

pub fn find_all_files(root: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let root_path = Path::new(root);
    
    if !root_path.exists() { return files; }
    if root_path.is_file() {
        files.push(root_path.to_path_buf());
        return files;
    }

    let mut dirs_to_visit = vec![root_path.to_path_buf()];

    while let Some(current_dir) = dirs_to_visit.pop() {
        match std::fs::read_dir(&current_dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        if !path.is_symlink() { dirs_to_visit.push(path); }
                    } else {
                        files.push(path);
                    }
                }
            },
            Err(_) => continue,
        }
    }
    files
}

pub fn read_file_to_b64(path: &str) -> Result<(String, String), String> {
    let path_obj = Path::new(path);
    if !path_obj.exists() { return Err(format!("File not found: {:?}", path)); }

    let meta = std::fs::metadata(path_obj).map_err(|e| e.to_string())?;
    let perm_string = if meta.permissions().readonly() { "readonly" } else { "writable" }.to_string();

    let mut file = File::open(path_obj).map_err(|e| e.to_string())?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).map_err(|e| e.to_string())?;

    Ok((BASE64.encode(buffer), perm_string))
}

pub fn save_download_with_metadata(session_id: u32, original_path: &str, b64_data: &str, permissions: &str) -> Result<String, String> {
    let bytes = BASE64.decode(b64_data).map_err(|e| format!("B64 Error: {}", e))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let hash = hex::encode(hasher.finalize());
    let size = bytes.len() as u64;

    let path_obj = Path::new(original_path);
    let full_filename = path_obj.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or("unknown.bin".into());
    let (stem, extension) = match full_filename.rsplit_once('.') { Some((s, e)) => (s, e), None => (full_filename.as_str(), "") };

    let safe_stem: String = stem.chars().take(32).collect();
    let safe_ext: String = extension.chars().take(16).collect();
    let now = chrono::Utc::now();
    let timestamp = now.format("%Y%d%m_%H%M%S_%3f").to_string();

    let core_name = format!("{}_{}_{}", timestamp, session_id, safe_stem);
    let final_filename = if safe_ext.is_empty() { core_name.clone() } else { format!("{}.{}", core_name, safe_ext) };
    let json_filename = format!("{}_{}_metadata.json", core_name, safe_ext);

    let _ = std::fs::create_dir_all("downloads");
    let save_path = format!("downloads/{}", final_filename);
    let json_path = format!("downloads/{}", json_filename);

    let mut file = File::create(&save_path).map_err(|e| e.to_string())?;
    file.write_all(&bytes).map_err(|e| e.to_string())?;

    let meta = FileMetadata {
        original_filepath: original_path.to_string(),
        filename: full_filename.clone(),
        extension: extension.to_string(),
        permissions: permissions.to_string(),
        filesize_bytes: size,
        sha256: hash,
    };
    
    // [FIXED] Map the IO error to String
    std::fs::write(&json_path, serde_json::to_string_pretty(&meta).unwrap())
        .map_err(|e| e.to_string())?;

    Ok(format!("Saved: {}", save_path))
}

pub fn save_batch_file(batch_ts: &str, session_id: u32, root_name: &str, rel_path: &str, b64_data: &str) -> Result<String, String> {
    let safe_root: String = root_name.chars().filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-').take(32).collect();
    let folder_name = format!("{}_{}_{}", batch_ts, session_id, safe_root);
    let base_dir = Path::new("downloads").join(folder_name);

    let clean_rel_path = rel_path.replace("..", "").replace('\\', "/"); 
    let final_path = base_dir.join(clean_rel_path.trim_start_matches('/'));

    if let Some(parent) = final_path.parent() { std::fs::create_dir_all(parent).map_err(|e| e.to_string())?; }

    let bytes = BASE64.decode(b64_data).map_err(|e| format!("B64 Error: {}", e))?;
    let mut file = File::create(&final_path).map_err(|e| format!("Create Error: {}", e))?;
    file.write_all(&bytes).map_err(|e| format!("Write Error: {}", e))?;

    Ok(final_path.to_string_lossy().to_string())
}

// Append to progress.txt
pub fn append_progress(batch_ts: &str, session_id: u32, root_name: &str, message: &str) {
    let safe_root: String = root_name.chars().filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-').take(32).collect();
    let folder_name = format!("{}_{}_{}", batch_ts, session_id, safe_root);
    let base_dir = Path::new("downloads").join(folder_name);
    
    // Ensure dir exists
    let _ = std::fs::create_dir_all(&base_dir);
    let progress_path = base_dir.join("progress.txt");

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(progress_path) {
        let _ = writeln!(file, "{}", message);
    }
}

// Remove progress.txt
pub fn remove_progress(batch_ts: &str, session_id: u32, root_name: &str) {
    let safe_root: String = root_name.chars().filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-').take(32).collect();
    let folder_name = format!("{}_{}_{}", batch_ts, session_id, safe_root);
    let progress_path = Path::new("downloads").join(folder_name).join("progress.txt");
    
    let _ = std::fs::remove_file(progress_path);
}

pub fn save_batch_report(batch_ts: &str, session_id: u32, root_name: &str, json_data: &str) -> Result<String, String> {
    let safe_root: String = root_name.chars().filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-').take(32).collect();
    let folder_name = format!("{}_{}_{}", batch_ts, session_id, safe_root);
    let base_dir = Path::new("downloads").join(folder_name);
    let _ = std::fs::create_dir_all(&base_dir);

    // Clean up progress file before writing report
    let progress_path = base_dir.join("progress.txt");
    let _ = std::fs::remove_file(progress_path);

    let filename = format!("{}_{}_{}_metadata.json", batch_ts, session_id, safe_root);
    let file_path = base_dir.join(filename);

    std::fs::write(&file_path, json_data).map_err(|e| e.to_string())?;
    Ok(file_path.to_string_lossy().to_string())
}

pub fn write_file_simple(path: &str, b64_data: &str) -> Result<(), String> {
    let bytes = BASE64.decode(b64_data).map_err(|e| format!("B64 Error: {}", e))?;
    if let Some(parent) = Path::new(path).parent() { let _ = std::fs::create_dir_all(parent); }
    let mut file = File::create(path).map_err(|e| e.to_string())?;
    file.write_all(&bytes).map_err(|e| e.to_string())?;
    Ok(())
}
