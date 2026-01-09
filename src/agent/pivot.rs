use tokio::net::{TcpListener};
use tokio::sync::mpsc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use crate::common::PivotFrame;

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
                    
                    println!("[Pivot] New Downstream Link #{} from {}", link_id, addr);

                    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
                    downstream_links.lock().unwrap().insert(link_id, tx);

                    let upstream_inner = upstream_tx.clone();
                    let links_inner = downstream_links.clone();

                    // [NEW] Send Initial "Link Start" Frame with Metadata (The IP)
                    let init_frame = PivotFrame {
                        stream_id: link_id,
                        destination: 0,
                        source: link_id,
                        data: vec![], // Empty data, just metadata
                        metadata: addr.to_string(), // <--- THE REAL IP
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
                                                metadata: String::new(), // No need to send IP on every packet
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

        format!("Pivot Listener (Agent-to-Agent) started on port {}", port)
    }

    pub fn handle_downstream_frame(&self, frame: PivotFrame) {
        let links = self.downstream_links.lock().unwrap();
        if let Some(tx) = links.get(&frame.destination) {
            let _ = tx.send(frame.data);
        }
    }
}
