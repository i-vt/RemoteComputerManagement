// src/api/models.rs
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Clone)]
pub struct CommandRequest {
    pub command: String,
}

#[derive(Deserialize)]
pub struct BroadcastModuleRequest {
    pub module_name: String,
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Deserialize)]
pub struct ExtensionPayload {
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Serialize)]
pub struct SessionDto {
    pub id: u32,
    pub hostname: String,
    pub ip: String,
    pub os: String,
    pub computer_id: String,
    pub has_proxy: bool,
    pub parent_id: Option<u32>,
    pub is_active: bool,
    pub profile: String, // [NEW] Added profile field
}

#[derive(Serialize)]
pub struct ProxyDto {
    pub session_id: u32,
    pub tunnel_port: u16,
    pub socks_port: u16,
}

#[derive(Deserialize, Debug)]
pub struct IpWhoIsResponse {
    pub ip: String,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub country_code: String,
    #[serde(default)]
    pub city: String,
    #[serde(default)]
    pub connection: IpWhoIsConnection,
    #[serde(default)]
    pub success: bool,
}

#[derive(Deserialize, Debug, Default)]
pub struct IpWhoIsConnection {
    #[serde(default)]
    pub isp: String,
}

#[derive(Serialize, Debug)]
pub struct GeoIpResult {
    pub ip: String,
    pub country: String,
    pub country_code: String,
    pub city: String,
    pub isp: String,
}

#[derive(Serialize)]
pub struct UnifiedHistoryDto {
    pub session_id: u32,
    pub request_id: u64,
    pub command: String,
    pub output: Option<String>,
    pub error: Option<String>,
    pub timestamp: String,
}
