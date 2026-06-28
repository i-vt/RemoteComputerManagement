// src/agent/scripting/compress.rs
use rhai::Engine;
use std::{fs, io::{self, Read, Write}};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};

pub fn register(engine: &mut Engine) {

    // ── Gzip ──────────────────────────────────────────────────────────────────

    engine.register_fn("internal_gzip", |data_hex: &str| -> String {
        let data = match hex::decode(data_hex) {
            Ok(d)  => d,
            Err(_) => data_hex.as_bytes().to_vec(),
        };
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        if encoder.write_all(&data).is_err() { return "Error: write failed".into(); }
        match encoder.finish() {
            Ok(compressed) => hex::encode(compressed),
            Err(e)         => format!("Error: {}", e),
        }
    });

    engine.register_fn("internal_gunzip", |data_hex: &str| -> String {
        let data = match hex::decode(data_hex) {
            Ok(d)  => d,
            Err(e) => return format!("Error: {}", e),
        };
        let mut decoder = GzDecoder::new(data.as_slice());
        let mut out = Vec::new();
        match decoder.read_to_end(&mut out) {
            Ok(_)  => hex::encode(out),
            Err(e) => format!("Error: {}", e),
        }
    });

    // ── Zip ───────────────────────────────────────────────────────────────────

    // Create a zip archive from a JSON array of file paths.
    // ["path1", "path2", ...] → writes output_path, returns entry count or error.
    engine.register_fn("internal_zip_create", |paths_json: &str, output_path: &str| -> String {
        let paths: Vec<String> = match serde_json::from_str(paths_json) {
            Ok(p)  => p,
            Err(e) => return format!("Error parsing paths: {}", e),
        };
        let file = match fs::File::create(output_path) {
            Ok(f)  => f,
            Err(e) => return format!("Error creating archive: {}", e),
        };
        let mut zip = zip::ZipWriter::new(file);
        let opts = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        let mut count = 0usize;
        let mut errors = Vec::new();
        for path in &paths {
            let name = std::path::Path::new(path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| path.clone());
            match fs::read(path) {
                Ok(data) => {
                    if zip.start_file(&name, opts).is_ok() {
                        let _ = zip.write_all(&data);
                        count += 1;
                    } else {
                        errors.push(name);
                    }
                }
                Err(e) => errors.push(format!("{}: {}", name, e)),
            }
        }
        let _ = zip.finish();
        if errors.is_empty() {
            format!("Created {} entries", count)
        } else {
            format!("Created {} entries; errors: {}", count, errors.join(", "))
        }
    });

    // Extract all entries from zip_path into output_dir.
    engine.register_fn("internal_zip_extract", |zip_path: &str, output_dir: &str| -> String {
        let file = match fs::File::open(zip_path) {
            Ok(f)  => f,
            Err(e) => return format!("Error: {}", e),
        };
        let mut archive = match zip::ZipArchive::new(file) {
            Ok(a)  => a,
            Err(e) => return format!("Error: {}", e),
        };
        let _ = fs::create_dir_all(output_dir);
        let mut count = 0usize;
        let mut errors = Vec::new();
        for i in 0..archive.len() {
            let mut entry = match archive.by_index(i) { Ok(e) => e, Err(_) => continue };
            let out_path = std::path::Path::new(output_dir).join(entry.name());
            if entry.is_dir() {
                let _ = fs::create_dir_all(&out_path);
            } else {
                if let Some(parent) = out_path.parent() { let _ = fs::create_dir_all(parent); }
                match fs::File::create(&out_path) {
                    Ok(mut f) => { let _ = io::copy(&mut entry, &mut f); count += 1; }
                    Err(e)    => errors.push(format!("{}: {}", entry.name(), e)),
                }
            }
        }
        if errors.is_empty() { format!("Extracted {} files", count) }
        else { format!("Extracted {}; errors: {}", count, errors.join(", ")) }
    });

    // List entries in a zip archive — returns JSON array of {name, size, compressed}.
    engine.register_fn("internal_zip_list", |zip_path: &str| -> String {
        let file = match fs::File::open(zip_path) {
            Ok(f)  => f,
            Err(e) => return format!("Error: {}", e),
        };
        let mut archive = match zip::ZipArchive::new(file) {
            Ok(a)  => a,
            Err(e) => return format!("Error: {}", e),
        };
        let mut entries = Vec::new();
        for i in 0..archive.len() {
            if let Ok(e) = archive.by_index(i) {
                entries.push(serde_json::json!({
                    "name":       e.name().to_string(),
                    "size":       e.size(),
                    "compressed": e.compressed_size(),
                    "is_dir":     e.is_dir(),
                }));
            }
        }
        serde_json::to_string(&entries).unwrap_or("[]".into())
    });
}
