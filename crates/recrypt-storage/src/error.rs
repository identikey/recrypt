//! Storage error types

use std::path::PathBuf;
use thiserror::Error;

pub type StorageResult<T> = Result<T, StorageError>;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Chunk not found: {0}")]
    NotFound(String),

    #[error("Hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Storage backend error: {0}")]
    Backend(String),

    #[error("Invalid path: {0}")]
    InvalidPath(PathBuf),

    #[error("Chunk too large: {size} bytes (max {max})")]
    TooLarge { size: usize, max: usize },

    #[cfg(feature = "sqlite")]
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
}
