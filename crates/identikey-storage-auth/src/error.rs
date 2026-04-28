//! Auth service error types

use thiserror::Error;

pub type AuthResult<T> = Result<T, AuthError>;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Not authorized: {0}")]
    NotAuthorized(String),

    #[error("Capability expired")]
    CapabilityExpired,

    #[error("Capability signature invalid")]
    InvalidSignature,

    #[error("Operation not permitted: {0}")]
    OperationNotPermitted(String),

    #[error("Already exists: {0}")]
    AlreadyExists(String),

    #[error("Invalid fingerprint: {0}")]
    InvalidFingerprint(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Invalid encoding: {0}")]
    InvalidEncoding(String),

    #[error("Capability chain exceeds max depth ({max})")]
    ChainTooDeep { max: usize },

    #[error("Capability chain invalid: {0}")]
    ChainInvalid(String),

    #[error("Unknown issuer: {0}")]
    UnknownIssuer(String),

    #[error("Signature error: {0}")]
    Signature(#[from] recrypt_core::error::CoreError),

    #[cfg(feature = "sqlite")]
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
}
