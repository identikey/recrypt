use thiserror::Error;

#[derive(Error, Debug)]
pub enum WireError {
    #[error("Envelope error: {0}")]
    Envelope(String),

    #[error("dCBOR error: {0}")]
    Dcbor(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Base58 decode error: {0}")]
    Base58(#[from] bs58::decode::Error),

    #[error("Armor parse error: {0}")]
    ArmorParse(String),

    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Wrong envelope type: expected {expected}, got {actual}")]
    WrongType { expected: String, actual: String },

    #[error("Version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: u32, actual: u32 },

    #[error("Signature verification failed: {0}")]
    SignatureVerification(String),

    #[error("Core error: {0}")]
    Core(#[from] recrypt_core::error::CoreError),
}

pub type WireResult<T> = Result<T, WireError>;
