//! identikey-storage-auth: Authorization for content-addressed storage
//!
//! Provides ownership tracking, capability issuance, and provider indexing
//! for the Recrypt storage layer.
//!
//! ## Features
//!
//! | Feature  | Description                    |
//! |----------|--------------------------------|
//! | (none)   | In-memory backends only        |
//! | `sqlite` | SQLite persistence             |
//!
//! ## Example
//!
//! ```rust,ignore
//! use identikey_storage_auth::{
//!     InMemoryOwnershipStore, InMemoryProviderIndex,
//!     OwnershipStore, ProviderIndex, Capability, Operation,
//! };
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let ownership = InMemoryOwnershipStore::new();
//!     let providers = InMemoryProviderIndex::new();
//!
//!     // Register file ownership
//!     let file_hash = blake3::hash(b"encrypted content");
//!     ownership.register(&owner_fingerprint, &file_hash).await?;
//!
//!     // Issue capability
//!     let cap = Capability::new(
//!         file_hash,
//!         grantee_fingerprint,
//!         vec![Operation::Read],
//!         Some(expires_at),
//!         issuer_fingerprint,
//!     );
//!     let mut signed_cap = cap;
//!     signed_cap.sign(&signing_keys)?;
//!
//!     Ok(())
//! }
//! ```

mod account;
mod capability;
mod error;
mod fingerprint;
mod grant;
mod ownership;

pub mod memory;

#[cfg(feature = "sqlite")]
pub mod sqlite;

// Re-exports
pub use account::{AccountRecord, AccountStore, InMemoryAccountStore};
pub use capability::{Capability, Operation};
pub use error::{AuthError, AuthResult};
pub use fingerprint::PublicKeyFingerprint;
pub use grant::{AccessGrant, GrantId, GrantStore, InMemoryGrantStore};
pub use ownership::OwnershipStore;

pub use memory::InMemoryOwnershipStore;

#[cfg(feature = "sqlite")]
pub use sqlite::{SqliteAccountStore, SqliteOwnershipStore};
