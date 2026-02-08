// ./src/lib.rs
#[macro_use]
extern crate litcrypt;

// Generate the secret key for this compilation unit
use_litcrypt!();

// [FIX] Re-export the macro so submodules can use `use crate::lc;`
pub use litcrypt::lc;

pub mod common;
pub mod utils;
pub mod database;
pub mod pki;
pub mod menu;
pub mod file_transfer;
pub mod socks;
pub mod api;
pub mod agent;
pub mod server;
pub mod transport;
pub mod traffic;
