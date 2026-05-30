// src/bin/client.rs 
use rcm::agent;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    agent::run().await
}
