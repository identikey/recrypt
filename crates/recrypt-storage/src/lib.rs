//! recrypt-storage: Content-addressed blob storage
//!
//! Provides async storage backends for encrypted chunks, keyed by Blake3 hash.
//! No authorization logic — that lives in the Auth Service.
//!
//! ## Backends
//!
//! | Backend           | Use Case              | Feature Flag |
//! |-------------------|-----------------------|--------------|
//! | `InMemoryStorage` | Unit tests            | (always)     |
//! | `LocalFileStorage`| Integration tests     | (always)     |
//! | `S3Storage`       | Production (Minio/S3) | `s3`         |
//!
//! ## Example
//!
//! ```rust,ignore
//! use recrypt_storage::{ChunkStorage, InMemoryStorage};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let storage = InMemoryStorage::new();
//!
//!     let data = b"Hello, chunks!";
//!     let hash = blake3::hash(data);
//!
//!     storage.put(&hash, data).await?;
//!     let retrieved = storage.get(&hash).await?;
//!     assert_eq!(retrieved, data);
//!
//!     Ok(())
//! }
//! ```

mod error;
mod traits;

mod local;
mod memory;

#[cfg(feature = "s3")]
mod s3;

pub mod gc;

// Re-exports
pub use error::{StorageError, StorageResult};
pub use traits::{ChunkStorage, hash_from_base58, hash_to_base58};

pub use local::LocalFileStorage;
pub use memory::InMemoryStorage;

#[cfg(feature = "s3")]
pub use s3::S3Storage;
