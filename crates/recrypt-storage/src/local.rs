//! Local filesystem storage backend

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use blake3::Hash;
use tokio::fs;

use crate::error::{StorageError, StorageResult};
use crate::traits::{BlobStorage, hash_from_base58, hash_to_base58, raw_hash_to_base58};

/// Algorithm prefix for Blake3 hashes (enables future hash agility)
const HASH_ALG_PREFIX: &str = "b3";

/// Local filesystem storage
///
/// Stores blob as files named by their base58 hash with algorithm prefix.
/// Structure: `{root}/blob/b3/{hash_base58}`
pub struct LocalFileStorage {
    root: PathBuf,
}

impl LocalFileStorage {
    /// Create storage at the given root directory
    ///
    /// Creates the directory structure if it doesn't exist.
    pub async fn new(root: impl AsRef<Path>) -> StorageResult<Self> {
        let root = root.as_ref().to_path_buf();
        let blob_dir = root.join("blob").join(HASH_ALG_PREFIX);
        fs::create_dir_all(&blob_dir).await?;
        Ok(Self { root })
    }

    fn chunk_path(&self, hash: &Hash) -> PathBuf {
        self.root
            .join("blob")
            .join(HASH_ALG_PREFIX)
            .join(hash_to_base58(hash))
    }

    fn outboard_path(&self, hash: &[u8; 32]) -> PathBuf {
        self.root
            .join("blob")
            .join(HASH_ALG_PREFIX)
            .join(format!("{}.obao", raw_hash_to_base58(hash)))
    }
}

#[async_trait]
impl BlobStorage for LocalFileStorage {
    async fn put(&self, hash: &Hash, data: &[u8]) -> StorageResult<()> {
        let computed = blake3::hash(data);
        if computed != *hash {
            return Err(StorageError::HashMismatch {
                expected: hash_to_base58(hash),
                actual: hash_to_base58(&computed),
            });
        }

        let path = self.chunk_path(hash);
        fs::write(&path, data).await?;
        Ok(())
    }

    async fn get(&self, hash: &Hash) -> StorageResult<Vec<u8>> {
        let path = self.chunk_path(hash);
        match fs::read(&path).await {
            Ok(data) => {
                // Verify on read (defense in depth)
                let computed = blake3::hash(&data);
                if computed != *hash {
                    return Err(StorageError::HashMismatch {
                        expected: hash_to_base58(hash),
                        actual: hash_to_base58(&computed),
                    });
                }
                Ok(data)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(StorageError::NotFound(hash_to_base58(hash)))
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn exists(&self, hash: &Hash) -> StorageResult<bool> {
        let path = self.chunk_path(hash);
        Ok(path.exists())
    }

    async fn delete(&self, hash: &Hash) -> StorageResult<()> {
        let path = self.chunk_path(hash);
        match fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn list(&self) -> StorageResult<Vec<Hash>> {
        let blob_dir = self.root.join("blob").join(HASH_ALG_PREFIX);
        let mut hashes = Vec::new();

        let mut entries = fs::read_dir(&blob_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if let Some(name) = entry.file_name().to_str()
                && let Some(hash) = hash_from_base58(name)
            {
                hashes.push(hash);
            }
        }

        Ok(hashes)
    }

    async fn put_with_outboard(
        &self,
        hash: &[u8; 32],
        ciphertext: Vec<u8>,
        outboard: Vec<u8>,
    ) -> StorageResult<()> {
        let b3_hash = blake3::Hash::from(*hash);
        let ct_path = self.chunk_path(&b3_hash);
        fs::write(&ct_path, &ciphertext).await?;
        if !outboard.is_empty() {
            let ob_path = self.outboard_path(hash);
            fs::write(&ob_path, &outboard).await?;
        }
        Ok(())
    }

    async fn get_with_outboard(
        &self,
        hash: &[u8; 32],
    ) -> StorageResult<(Vec<u8>, Vec<u8>)> {
        let b3_hash = blake3::Hash::from(*hash);
        let ct_path = self.chunk_path(&b3_hash);
        let ciphertext = match fs::read(&ct_path).await {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(StorageError::NotFound(raw_hash_to_base58(hash)));
            }
            Err(e) => return Err(e.into()),
        };
        let ob_path = self.outboard_path(hash);
        let outboard = match fs::read(&ob_path).await {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        Ok((ciphertext, outboard))
    }

    async fn delete_with_outboard(
        &self,
        hash: &[u8; 32],
    ) -> StorageResult<()> {
        let b3_hash = blake3::Hash::from(*hash);
        let ct_path = self.chunk_path(&b3_hash);
        match fs::remove_file(&ct_path).await {
            Ok(()) | Err(_) => {} // idempotent
        }
        let ob_path = self.outboard_path(hash);
        match fs::remove_file(&ob_path).await {
            Ok(()) | Err(_) => {} // idempotent — .obao may not exist
        }
        Ok(())
    }
}
