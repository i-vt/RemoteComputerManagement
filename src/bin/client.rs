#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
use rcm::agent;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Observability: the connect path (notably hibernation mode) logs via
    // tracing's warn!/debug!, which are silent no-ops until a subscriber is
    // installed. Install a minimal stderr subscriber ONLY when the embedded
    // config has debug = true - release agent builds must stay quiet (OPSEC),
    // so they get no subscriber at all. When enabled, allow DEBUG so the
    // connect-path diagnostics are actually visible (WARN would hide them).
    if agent::config::load().debug {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }
    agent::run().await
}
