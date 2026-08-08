use thiserror::Error;

#[derive(Error, Debug)]
pub enum WireError {
    #[error("Envelope error: {0}")]
    Envelope(String),

    #[error("dCBOR error: {0}")]
    Dcbor(String),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Armor parse error: {0}")]
    ArmorParse(String),

    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    #[error("Encoding error: {0}")]
    Encoding(String),

    /// Base58 was asked to handle something that is not an identifier.
    /// See `encoding::B58_MAX_BYTES` — base58 is O(n²), so this is a refusal,
    /// not a buffer limit.
    #[error(
        "value is {len} bytes, over the {max}-byte base58 limit; \
         use base64 for blobs this size (encoding-conventions.md §2)"
    )]
    EncodingTooLarge { len: usize, max: usize },

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
