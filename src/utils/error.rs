pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub enum Error {
    KeyFailHmac,
    EncryptFail,
    DecryptFail,
    CryptoError {error: String},
    FolderNotFound,
    FileCreateFail(String),
    CompressionFailed,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {}

#[cfg(target_os = "windows")]
impl From<ring::error::Unspecified> for Error {
    fn from(_: ring::error::Unspecified) -> Self {
        Error::CryptoError {error: "Unspecified error in ring".to_string()}
        // CryptoError("Unspecified error in ring".to_string())
    }
}
