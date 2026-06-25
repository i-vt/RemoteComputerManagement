// src/bin/client.rs 
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
use rcm::agent;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    agent::run().await
}
