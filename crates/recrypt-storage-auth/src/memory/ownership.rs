//! In-memory ownership store

use std::collections::HashMap;
use std::sync::RwLock;

use async_trait::async_trait;
use blake3::Hash;

use crate::error::{AuthError, AuthResult};
use crate::fingerprint::PublicKeyFingerprint;
use crate::ownership::OwnershipStore;

/// In-memory ownership store for testing
#[derive(Default)]
pub struct InMemoryOwnershipStore {
    /// file_hash -> owner
    owners: RwLock<HashMap<Hash, PublicKeyFingerprint>>,
}

impl InMemoryOwnershipStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of registered files
    pub fn file_count(&self) -> usize {
        self.owners.read().unwrap().len()
    }

    /// Clear all data
    pub fn clear(&self) {
        self.owners.write().unwrap().clear();
    }
}

#[async_trait]
impl OwnershipStore for InMemoryOwnershipStore {
    async fn register(&self, owner: &PublicKeyFingerprint, file_hash: &Hash) -> AuthResult<()> {
        let mut owners = self.owners.write().unwrap();

        if let Some(existing) = owners.get(file_hash) {
            if existing != owner {
                return Err(AuthError::AlreadyExists(format!(
                    "File {file_hash} already owned by different key"
                )));
            }
            // Already registered to same owner — idempotent
            return Ok(());
        }

        owners.insert(*file_hash, *owner);
        Ok(())
    }

    async fn is_owner(&self, owner: &PublicKeyFingerprint, file_hash: &Hash) -> AuthResult<bool> {
        let owners = self.owners.read().unwrap();
        Ok(owners.get(file_hash) == Some(owner))
    }

    async fn list_owned(&self, owner: &PublicKeyFingerprint) -> AuthResult<Vec<Hash>> {
        let owners = self.owners.read().unwrap();
        Ok(owners
            .iter()
            .filter(|(_, o)| *o == owner)
            .map(|(h, _)| *h)
            .collect())
    }

    async fn transfer(
        &self,
        from: &PublicKeyFingerprint,
        to: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<()> {
        let mut owners = self.owners.write().unwrap();

        match owners.get(file_hash) {
            Some(current) if current == from => {
                owners.insert(*file_hash, *to);
                Ok(())
            }
            Some(_) => Err(AuthError::NotAuthorized("Only owner can transfer".into())),
            None => Err(AuthError::FileNotFound(file_hash.to_string())),
        }
    }

    async fn unregister(&self, owner: &PublicKeyFingerprint, file_hash: &Hash) -> AuthResult<()> {
        // Verify ownership
        if !self.is_owner(owner, file_hash).await? {
            return Err(AuthError::NotAuthorized("Only owner can unregister".into()));
        }

        // Remove ownership
        self.owners.write().unwrap().remove(file_hash);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(n: u8) -> PublicKeyFingerprint {
        PublicKeyFingerprint::from_bytes([n; 32])
    }

    #[tokio::test]
    async fn test_register_and_ownership() {
        let store = InMemoryOwnershipStore::new();
        let owner = fp(1);
        let file = blake3::hash(b"test");

        store.register(&owner, &file).await.unwrap();

        assert!(store.is_owner(&owner, &file).await.unwrap());
        assert!(!store.is_owner(&fp(2), &file).await.unwrap());
    }

    #[tokio::test]
    async fn test_register_idempotent() {
        let store = InMemoryOwnershipStore::new();
        let owner = fp(1);
        let file = blake3::hash(b"test");

        store.register(&owner, &file).await.unwrap();
        store.register(&owner, &file).await.unwrap(); // Should succeed
    }

    #[tokio::test]
    async fn test_register_conflict() {
        let store = InMemoryOwnershipStore::new();
        let file = blake3::hash(b"test");

        store.register(&fp(1), &file).await.unwrap();
        let result = store.register(&fp(2), &file).await;

        assert!(matches!(result, Err(AuthError::AlreadyExists(_))));
    }

    #[tokio::test]
    async fn test_transfer_ownership() {
        let store = InMemoryOwnershipStore::new();
        let alice = fp(1);
        let bob = fp(2);
        let file = blake3::hash(b"test");

        store.register(&alice, &file).await.unwrap();
        store.transfer(&alice, &bob, &file).await.unwrap();

        assert!(!store.is_owner(&alice, &file).await.unwrap());
        assert!(store.is_owner(&bob, &file).await.unwrap());
    }
}
