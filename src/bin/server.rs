// src/bin/server.rs
use secure_c2::server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // [NEW] Initialize Logging & Cleanup
    // The _guard must stay in scope for the duration of the program!
    let _guard = server::logging::init()?;

    tracing::info!("Starting SecureC2 Server...");
    
    if let Err(e) = server::run().await {
        tracing::error!("Server crashed: {}", e);
        return Err(e);
    }
    
    Ok(())
}
