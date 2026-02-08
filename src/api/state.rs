// src/api/state.rs
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use tokio::sync::oneshot;
use rhai::AST;

use crate::common::{SharedSessions, CommandResponse};
use crate::database::DbPool; // [FIXED] Updated import from DbRef to DbPool

pub type SharedResults = Arc<Mutex<HashMap<(u32, u64), CommandResponse>>>;
pub type SharedScripts = Arc<Mutex<HashMap<String, AST>>>;

pub struct ProxyHandle {
    pub session_id: u32,
    pub tunnel_port: u16,
    pub socks_port: u16,
    pub stop_tx: oneshot::Sender<()>,
}

pub type SharedProxies = Arc<Mutex<HashMap<u32, ProxyHandle>>>;

#[derive(Clone)]
pub struct ApiContext {
    pub sessions: SharedSessions,
    pub db: DbPool, // [FIXED] Updated type usage
    pub results: SharedResults,
    pub proxies: SharedProxies,
    pub scripts: SharedScripts,
    pub api_key: String,
}
