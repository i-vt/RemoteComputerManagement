// src/bin/client.rs 
use secure_c2::agent;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    agent::run().await
}
