//! In-memory storage backend (for testing)

use std::collections::HashMap;
use std::sync::RwLock;

use async_trait::async_trait;
use blake3::Hash;

use crate::error::{StorageError, StorageResult};
use crate::traits::{BlobStorage, hash_to_base58, raw_hash_to_base58};

/// In-memory storage for unit tests
///
/// Thread-safe via `RwLock`. Not persistent — data lost on drop.
///
/// The `outboards` map is keyed by `"{base58(hash)}.obao"`.
#[derive(Default)]
pub struct InMemoryStorage {
    /// Keyed by Blake3 hash; value is ciphertext bytes.
    blobs: RwLock<HashMap<Hash, Vec<u8>>>,
    /// Outboard blobs keyed by `"{base58(hash)}.obao"`
    outboards: RwLock<HashMap<String, Vec<u8>>>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored blobs
    pub fn len(&self) -> usize {
        self.blobs.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total bytes stored (ciphertext only, excludes outboards)
    pub fn total_size(&self) -> usize {
        self.blobs.read().unwrap().values().map(|v| v.len()).sum()
    }

    /// Clear all stored blobs and outboards
    pub fn clear(&self) {
        self.blobs.write().unwrap().clear();
        self.outboards.write().unwrap().clear();
    }
}

#[async_trait]
impl BlobStorage for InMemoryStorage {
    async fn put(&self, hash: &Hash, data: &[u8]) -> StorageResult<()> {
        let computed = blake3::hash(data);
        if computed != *hash {
            return Err(StorageError::HashMismatch {
                expected: hash_to_base58(hash),
                actual: hash_to_base58(&computed),
            });
        }

        self.blobs.write().unwrap().insert(*hash, data.to_vec());
        Ok(())
    }

    async fn get(&self, hash: &Hash) -> StorageResult<Vec<u8>> {
        self.blobs
            .read()
            .unwrap()
            .get(hash)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(hash_to_base58(hash)))
    }

    async fn exists(&self, hash: &Hash) -> StorageResult<bool> {
        Ok(self.blobs.read().unwrap().contains_key(hash))
    }

    async fn delete(&self, hash: &Hash) -> StorageResult<()> {
        self.blobs.write().unwrap().remove(hash);
        Ok(())
    }

    async fn list(&self) -> StorageResult<Vec<Hash>> {
        Ok(self.blobs.read().unwrap().keys().copied().collect())
    }

    async fn put_with_outboard(
        &self,
        hash: &[u8; 32],
        ciphertext: Vec<u8>,
        outboard: Vec<u8>,
    ) -> StorageResult<()> {
        let b3_hash = blake3::Hash::from(*hash);
        let key = raw_hash_to_base58(hash);
        self.blobs.write().unwrap().insert(b3_hash, ciphertext);
        if !outboard.is_empty() {
            self.outboards
                .write()
                .unwrap()
                .insert(format!("{key}.obao"), outboard);
        }
        Ok(())
    }

    async fn get_with_outboard(&self, hash: &[u8; 32]) -> StorageResult<(Vec<u8>, Vec<u8>)> {
        let b3_hash = blake3::Hash::from(*hash);
        let key = raw_hash_to_base58(hash);
        let ciphertext = self
            .blobs
            .read()
            .unwrap()
            .get(&b3_hash)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(key.clone()))?;
        let outboard = self
            .outboards
            .read()
            .unwrap()
            .get(&format!("{key}.obao"))
            .cloned()
            .unwrap_or_default();
        Ok((ciphertext, outboard))
    }

    async fn delete_with_outboard(&self, hash: &[u8; 32]) -> StorageResult<()> {
        let b3_hash = blake3::Hash::from(*hash);
        let key = raw_hash_to_base58(hash);
        self.blobs.write().unwrap().remove(&b3_hash);
        self.outboards
            .write()
            .unwrap()
            .remove(&format!("{key}.obao"));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_roundtrip() {
        let storage = InMemoryStorage::new();
        let data = b"Hello, storage!";
        let hash = blake3::hash(data);

        storage.put(&hash, data).await.unwrap();
        let retrieved = storage.get(&hash).await.unwrap();
        assert_eq!(retrieved, data);
    }

    #[tokio::test]
    async fn test_hash_mismatch() {
        let storage = InMemoryStorage::new();
        let data = b"Hello";
        let wrong_hash = blake3::hash(b"Wrong");

        let result = storage.put(&wrong_hash, data).await;
        assert!(matches!(result, Err(StorageError::HashMismatch { .. })));
    }

    #[tokio::test]
    async fn test_not_found() {
        let storage = InMemoryStorage::new();
        let hash = blake3::hash(b"nonexistent");

        let result = storage.get(&hash).await;
        assert!(matches!(result, Err(StorageError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_exists() {
        let storage = InMemoryStorage::new();
        let data = b"exists";
        let hash = blake3::hash(data);

        assert!(!storage.exists(&hash).await.unwrap());
        storage.put(&hash, data).await.unwrap();
        assert!(storage.exists(&hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_delete_idempotent() {
        let storage = InMemoryStorage::new();
        let hash = blake3::hash(b"deleteme");

        // Delete nonexistent — should succeed
        storage.delete(&hash).await.unwrap();

        // Put then delete
        storage.put(&hash, b"deleteme").await.unwrap();
        storage.delete(&hash).await.unwrap();
        assert!(!storage.exists(&hash).await.unwrap());

        // Delete again — still succeeds
        storage.delete(&hash).await.unwrap();
    }

    #[tokio::test]
    async fn test_list() {
        let storage = InMemoryStorage::new();

        let data1 = b"chunk1";
        let data2 = b"chunk2";
        let hash1 = blake3::hash(data1);
        let hash2 = blake3::hash(data2);

        storage.put(&hash1, data1).await.unwrap();
        storage.put(&hash2, data2).await.unwrap();

        let mut hashes = storage.list().await.unwrap();
        hashes.sort_by_key(|a| a.to_hex());

        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains(&hash1));
        assert!(hashes.contains(&hash2));
    }
}
