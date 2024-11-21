mod error;
pub mod compressor;
pub mod crypto;
pub mod win_api;

pub use self::error::{Error, Result};

const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
const ITERATIONS: usize = 100_000;
#[cfg(target_os = "linux")]
const IV_LEN: usize = 16;
#[cfg(target_os = "windows")]
const NONCE_LEN: usize = 12; // AES-GCM standard
