//! Provider index: where files are stored
//!
//! Tracks file locations across storage providers, enabling hosting agility
//! (files can be moved between providers without breaking references).

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use async_trait::async_trait;
use blake3::Hash;

use crate::error::{StorageError, StorageResult};

/// A storage provider URL
pub type ProviderUrl = String;

/// Tracks file locations across storage providers
#[async_trait]
pub trait ProviderIndex: Send + Sync {
    /// Register a file's location
    ///
    /// A file can be stored at multiple providers for redundancy.
    async fn register(&self, file_hash: &Hash, provider_url: &ProviderUrl) -> StorageResult<()>;

    /// Look up all locations for a file
    async fn lookup(&self, file_hash: &Hash) -> StorageResult<Vec<ProviderUrl>>;

    /// Update a file's location (migration)
    async fn update_location(
        &self,
        file_hash: &Hash,
        old_url: &ProviderUrl,
        new_url: &ProviderUrl,
    ) -> StorageResult<()>;

    /// Remove a location (file deleted from provider)
    async fn remove_location(
        &self,
        file_hash: &Hash,
        provider_url: &ProviderUrl,
    ) -> StorageResult<()>;

    /// Remove all locations for a file
    async fn unregister(&self, file_hash: &Hash) -> StorageResult<()>;

    /// Check if a file has any registered locations
    async fn exists(&self, file_hash: &Hash) -> StorageResult<bool>;

    /// List all files at a provider (for provider management)
    async fn list_at_provider(&self, provider_url: &ProviderUrl) -> StorageResult<Vec<Hash>>;
}

/// In-memory provider index for testing
#[derive(Default)]
pub struct InMemoryProviderIndex {
    /// file_hash -> set of provider URLs
    locations: RwLock<HashMap<Hash, HashSet<ProviderUrl>>>,
}

impl InMemoryProviderIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of tracked files
    pub fn file_count(&self) -> usize {
        self.locations.read().unwrap().len()
    }

    /// Clear all data
    pub fn clear(&self) {
        self.locations.write().unwrap().clear();
    }
}

#[async_trait]
impl ProviderIndex for InMemoryProviderIndex {
    async fn register(&self, file_hash: &Hash, provider_url: &ProviderUrl) -> StorageResult<()> {
        let mut locations = self.locations.write().unwrap();
        locations
            .entry(*file_hash)
            .or_default()
            .insert(provider_url.clone());
        Ok(())
    }

    async fn lookup(&self, file_hash: &Hash) -> StorageResult<Vec<ProviderUrl>> {
        let locations = self.locations.read().unwrap();
        match locations.get(file_hash) {
            Some(urls) => Ok(urls.iter().cloned().collect()),
            None => Ok(vec![]),
        }
    }

    async fn update_location(
        &self,
        file_hash: &Hash,
        old_url: &ProviderUrl,
        new_url: &ProviderUrl,
    ) -> StorageResult<()> {
        let mut locations = self.locations.write().unwrap();

        if let Some(urls) = locations.get_mut(file_hash) {
            urls.remove(old_url);
            urls.insert(new_url.clone());
            Ok(())
        } else {
            Err(StorageError::NotFound(file_hash.to_string()))
        }
    }

    async fn remove_location(
        &self,
        file_hash: &Hash,
        provider_url: &ProviderUrl,
    ) -> StorageResult<()> {
        let mut locations = self.locations.write().unwrap();

        if let Some(urls) = locations.get_mut(file_hash) {
            urls.remove(provider_url);
            if urls.is_empty() {
                locations.remove(file_hash);
            }
        }
        Ok(())
    }

    async fn unregister(&self, file_hash: &Hash) -> StorageResult<()> {
        self.locations.write().unwrap().remove(file_hash);
        Ok(())
    }

    async fn exists(&self, file_hash: &Hash) -> StorageResult<bool> {
        let locations = self.locations.read().unwrap();
        Ok(locations
            .get(file_hash)
            .map(|s| !s.is_empty())
            .unwrap_or(false))
    }

    async fn list_at_provider(&self, provider_url: &ProviderUrl) -> StorageResult<Vec<Hash>> {
        let locations = self.locations.read().unwrap();
        Ok(locations
            .iter()
            .filter(|(_, urls)| urls.contains(provider_url))
            .map(|(h, _)| *h)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_register_and_lookup() {
        let index = InMemoryProviderIndex::new();
        let file = blake3::hash(b"test");
        let url = "https://s3.example.com/bucket/file".to_string();

        index.register(&file, &url).await.unwrap();

        let locations = index.lookup(&file).await.unwrap();
        assert_eq!(locations, vec![url]);
    }

    #[tokio::test]
    async fn test_multiple_providers() {
        let index = InMemoryProviderIndex::new();
        let file = blake3::hash(b"test");

        let url1 = "https://provider1.com/file".to_string();
        let url2 = "https://provider2.com/file".to_string();

        index.register(&file, &url1).await.unwrap();
        index.register(&file, &url2).await.unwrap();

        let locations = index.lookup(&file).await.unwrap();
        assert_eq!(locations.len(), 2);
        assert!(locations.contains(&url1));
        assert!(locations.contains(&url2));
    }

    #[tokio::test]
    async fn test_update_location() {
        let index = InMemoryProviderIndex::new();
        let file = blake3::hash(b"test");

        let old_url = "https://old.com/file".to_string();
        let new_url = "https://new.com/file".to_string();

        index.register(&file, &old_url).await.unwrap();
        index
            .update_location(&file, &old_url, &new_url)
            .await
            .unwrap();

        let locations = index.lookup(&file).await.unwrap();
        assert_eq!(locations, vec![new_url]);
    }

    #[tokio::test]
    async fn test_exists() {
        let index = InMemoryProviderIndex::new();
        let file = blake3::hash(b"test");

        assert!(!index.exists(&file).await.unwrap());

        index
            .register(&file, &"https://example.com".to_string())
            .await
            .unwrap();
        assert!(index.exists(&file).await.unwrap());
    }

    #[tokio::test]
    async fn test_list_at_provider() {
        let index = InMemoryProviderIndex::new();
        let provider = "https://s3.example.com".to_string();

        let file1 = blake3::hash(b"file1");
        let file2 = blake3::hash(b"file2");
        let file3 = blake3::hash(b"file3");

        index.register(&file1, &provider).await.unwrap();
        index.register(&file2, &provider).await.unwrap();
        index
            .register(&file3, &"https://other.com".to_string())
            .await
            .unwrap();

        let files = index.list_at_provider(&provider).await.unwrap();
        assert_eq!(files.len(), 2);
        assert!(files.contains(&file1));
        assert!(files.contains(&file2));
    }
}
