pub mod crypto;

const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
#[cfg(target_os = "linux")]
const IV_LEN: usize = 16;
#[cfg(target_os = "windows")]
const NONCE_LEN: usize = 12; // AES-GCM standard
const ITERATIONS: usize = 100_000;
