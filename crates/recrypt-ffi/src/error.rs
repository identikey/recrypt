//! Error types for recrypt-ffi operations

use thiserror::Error;

#[derive(Error, Debug)]
pub enum FfiError {
    #[error("OpenFHE operation failed: {0}")]
    OpenFhe(String),

    #[error("liboqs operation failed: {0}")]
    LibOqs(String),

    #[error("ED25519 signature verification failed")]
    Ed25519Verification,

    #[error("Invalid key material: {0}")]
    InvalidKey(String),

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),
}

// OpenFHE signals failure via C++ exceptions; cxx surfaces them as
// cxx::Exception carrying the exception message.
impl From<cxx::Exception> for FfiError {
    fn from(e: cxx::Exception) -> Self {
        FfiError::OpenFhe(e.what().to_string())
    }
}
