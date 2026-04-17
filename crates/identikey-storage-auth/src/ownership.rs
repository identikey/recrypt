//! Ownership tracking: who owns which content-addressed files.
//!
//! File-level grant methods have been removed in favour of keyspace-scoped
//! [`AccessGrant`](crate::grant::AccessGrant) records managed by
//! [`GrantStore`](crate::grant::GrantStore).

use async_trait::async_trait;
use blake3::Hash;

use crate::error::AuthResult;
use crate::fingerprint::PublicKeyFingerprint;

/// Tracks file ownership (content-addressed).
#[async_trait]
pub trait OwnershipStore: Send + Sync {
    /// Register a new file as owned by a public key.
    ///
    /// Returns error if file is already registered to a different owner.
    async fn register(&self, owner: &PublicKeyFingerprint, file_hash: &Hash) -> AuthResult<()>;

    /// Check if a public key owns a file.
    async fn is_owner(&self, owner: &PublicKeyFingerprint, file_hash: &Hash) -> AuthResult<bool>;

    /// List all files owned by a public key.
    async fn list_owned(&self, owner: &PublicKeyFingerprint) -> AuthResult<Vec<Hash>>;

    /// Transfer ownership to another public key.
    ///
    /// Only the current owner can transfer.
    async fn transfer(
        &self,
        from: &PublicKeyFingerprint,
        to: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<()>;

    /// Remove file record entirely (for cleanup).
    async fn unregister(&self, owner: &PublicKeyFingerprint, file_hash: &Hash) -> AuthResult<()>;
}
