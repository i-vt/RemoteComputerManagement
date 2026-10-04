pub mod handlers;
pub mod proxy;
pub mod ui;

use rustyline::{DefaultEditor, Result};
use crate::api::SharedProxies;
use crate::common::SharedSessions;

pub fn run(sessions: SharedSessions, proxies: SharedProxies) -> Result<()> {
    let mut rl = DefaultEditor::new()?;
    if rl.load_history("history.txt").is_err() {}

    let mut current_session_id: Option<u32> = None;
    let mut shutdown_requested = false;

    eprintln!("[*] C2 Interactive Menu Ready. Type 'help' for commands.");

    loop {
        let prompt = match current_session_id {
            Some(id) => format!("\x1b[33mSession[{}]\x1b[0m > ", id), 
            None => "\x1b[36mC2\x1b[0m > ".to_string(),                  
        };

        match rl.readline(&prompt) {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() { continue; }
                let _ = rl.add_history_entry(line);

                // Check for background command first
                if current_session_id.is_some() && (line == "bg" || line == "background") {
                    if let Some(id) = current_session_id {
                        eprintln!("[*] Backgrounded session {}.", id);
                    }
                    current_session_id = None;
                    continue;
                }

                // Dispatch
                if let Some(id) = current_session_id {
                    handlers::handle_session(line, id, &sessions, proxies.clone());
                    
                    // Safety check: if session died during command, drop back to menu
                    let map = &*sessions;
                    if !map.contains_key(&id) {
                        eprintln!("[-] Session lost.");
                        current_session_id = None;
                    }
                } else if handlers::handle_global(line, &sessions, &mut current_session_id) {
                    // exit/quit: unwind the REPL first so history is saved,
                    // then hand off to the server's graceful-shutdown path.
                    shutdown_requested = true;
                    break;
                }
            },
            Err(_) => break,
        }
    }

    let _ = rl.save_history("history.txt");
    if shutdown_requested {
        handlers::request_shutdown();
    }
    Ok(())
}