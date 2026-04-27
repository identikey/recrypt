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
//! use std::collections::BTreeSet;
//! use identikey_storage_auth::{
//!     Capability, MemberCapability, PublicKeyFingerprint,
//! };
//!
//! // Issue a keyspace-scoped capability
//! let cap = Capability::new(
//!     keyspace_id,
//!     0, // keyspace_version
//!     grantee_fingerprint,
//!     BTreeSet::from([MemberCapability::Read]),
//!     Some(expires_at),
//!     issuer_fingerprint,
//! );
//! let mut signed_cap = cap;
//! signed_cap.sign(&signing_keys)?;
//! ```

mod account;
mod capability;
mod error;
mod fingerprint;
mod grant;
pub mod keyspace;
pub mod keyspace_store;
mod ownership;

pub mod memory;

#[cfg(feature = "sqlite")]
pub mod sqlite;

// Re-exports
pub use account::{AccountRecord, AccountStore, InMemoryAccountStore};
pub use capability::Capability;
pub use error::{AuthError, AuthResult};
pub use fingerprint::PublicKeyFingerprint;
pub use grant::{AccessGrant, GrantId, GrantStore, InMemoryGrantStore};
pub use ownership::OwnershipStore;

pub use keyspace::{
    DecryptionPolicy, KeyspaceDoc, KeyspaceDocHash, KeyspaceId, Member, MemberCapability,
    RotationMode,
};
pub use keyspace_store::{InMemoryKeyspaceStore, KeyspaceStore};
pub use memory::InMemoryOwnershipStore;

#[cfg(feature = "sqlite")]
pub use sqlite::{SqliteAccountStore, SqliteGrantStore, SqliteKeyspaceStore, SqliteOwnershipStore};
