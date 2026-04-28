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
//! use identikey_storage_auth::{Capability, Permission, SubjectKind};
//!
//! let cap = Capability::new(
//!     file_hash,
//!     SubjectKind::File,
//!     grantee_fingerprint,
//!     issuer_fingerprint,
//!     BTreeSet::from([Permission::Read]),
//!     Some(expires_at),
//! );
//! let signed_envelope = cap.sign(&signing_keys)?;
//! let parsed = Capability::verify(&signed_envelope, &issuer_keys, policy)?;
//! ```

mod account;
mod capability;
mod capability_chain;
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
pub use capability::{Capability, SubjectKind};
pub use capability_chain::{verify_chain, BundledResolver, ChainPolicy, ParentResolver};
pub use error::{AuthError, AuthResult};
pub use fingerprint::PublicKeyFingerprint;
pub use grant::{AccessGrant, GrantId, GrantStore, InMemoryGrantStore};
pub use ownership::OwnershipStore;

pub use keyspace::{
    DecryptionPolicy, KeyspaceDoc, KeyspaceDocHash, KeyspaceId, Member, Permission,
    RotationMode,
};
pub use keyspace_store::{InMemoryKeyspaceStore, KeyspaceStore};
pub use memory::InMemoryOwnershipStore;

#[cfg(feature = "sqlite")]
pub use sqlite::{SqliteAccountStore, SqliteGrantStore, SqliteKeyspaceStore, SqliteOwnershipStore};
