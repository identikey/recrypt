> **Historical:** Phase 4 planning. ChunkManifest was replaced by Bao streaming. See [storage-design.md](../storage-design.md).

# Phase 4: Storage Layer Implementation Plan

**Status:** ✅ **COMPLETE** (2026-01-06)  
**Duration:** 1 day (planned 3-4 days)  
**Goal:** Content-addressed storage abstraction with S3-compatible backends

**Validation Report:** `PHASE-4-VALIDATION-REPORT.md`

---

## Overview

Build `recrypt-storage` crate: a pure async storage client for content-addressed blobs. No authorization logic — that lives in the Auth Service (Phase 4b). S3 bucket is "dumb" storage; security comes from:

1. **Discovery control** — Auth service mediates who learns which hashes exist
2. **Decryption control** — Only key holders can unwrap ciphertext
3. **Content integrity** — Hash _is_ the address; wrong bytes = wrong hash

This follows the IPFS model: ciphertext is publicly fetchable if you know the hash, but useless without keys.

**Hash Agility & Encoding:**

- Storage keys use algorithm prefix: `chunks/b3/{hash}` (b3 = Blake3)
- Base58 encoding for hashes (~31% shorter than hex, human-readable)
- `ChunkManifest` includes `hash_algorithm` field for future-proofing
- If we ever need to migrate algorithms, old and new can coexist

---

## Current State Analysis

### What Exists

- **recrypt-proto**: `ChunkProto`, `FileMetadata`, `EncryptedFileProto` defined
- **recrypt-core**: `EncryptedFile` with `bao_hash`, `bao_outboard`, `ciphertext`
- **Workspace**: Ready for new crate at `crates/recrypt-storage`
- **Docs**: `storage-design.md` with architecture, bucket structure, trait sketch

### What's Missing

- `recrypt-storage` crate doesn't exist
- No `ChunkStorage` trait implementation
- No S3/Minio integration
- No chunking utilities
- No Docker compose for dev environment

### Key Discoveries

- Bao tree mode handles verification; storage layer just moves bytes
- `blake3::Hash` is the natural key type (32 bytes)
- Base58 encoding preferred over hex (~44 chars vs 64 chars for 32 bytes)
- Algorithm prefix (`b3/`) enables future hash agility without breaking changes
- `aws-sdk-s3` is the modern choice (rusoto is deprecated)
- Content-addressed means no metadata in storage layer — just `put(hash, bytes)`, `get(hash)`

---

## Desired End State

After Phase 4:

1. ✅ `ChunkStorage` trait defined with async operations
2. ✅ `InMemoryStorage` for fast unit tests
3. ✅ `LocalFileStorage` for integration tests without Docker
4. ✅ `S3Storage` for Minio (dev) and production S3
5. ✅ Chunking utilities: split large files, reassemble
6. ✅ Docker compose with Minio for local dev
7. ✅ Integration tests against Minio

**Verification:**

```bash
cargo test -p recrypt-storage                    # Unit tests (in-memory, local)
docker-compose -f docker/docker-compose.dev.yml up -d minio
cargo test -p recrypt-storage --features s3-tests  # Integration tests
```

---

## What We're NOT Doing

- ❌ Authorization / capability tokens (Phase 4b)
- ❌ Metadata database (Phase 4b)
- ❌ HTTP API endpoints (Phase 6)
- ❌ Per-hash S3 ACLs (not needed — ciphertext is safe)
- ❌ Multi-provider redundancy (future enhancement)
- ❌ Garbage collection (future enhancement)

---

## Implementation Approach

1. **Trait-first design** — Define `ChunkStorage` trait, then implement backends
2. **Test backends first** — `InMemoryStorage` enables fast iteration
3. **S3 last** — Most complex, needs Docker; defer until trait is stable
4. **Feature-gate S3** — `s3` feature for production deps, off by default for faster builds

---

## Phase 4.1: Crate Scaffolding

### Overview

Create `recrypt-storage` crate with trait definitions and error types.

### Changes Required

#### 1. Workspace Cargo.toml

**File**: `Cargo.toml`

Add to workspace members:

```toml
[workspace]
members = [
  "crates/recrypt-ffi",
  "crates/recrypt-openfhe-sys",
  "crates/recrypt-core",
  "crates/recrypt-proto",
  "crates/recrypt-storage",  # NEW
]

[workspace.dependencies]
# ... existing deps ...

# Storage (Phase 4)
tokio = { version = "1", features = ["full"] }
async-trait = "0.1"
bs58 = "0.5"
aws-sdk-s3 = "1"
aws-config = "1"
```

#### 2. Crate Cargo.toml

**File**: `crates/recrypt-storage/Cargo.toml`

```toml
[package]
name = "recrypt-storage"
version.workspace = true
edition.workspace = true
license.workspace = true

[features]
default = []
s3 = ["aws-sdk-s3", "aws-config"]
s3-tests = ["s3"]

[dependencies]
# Workspace
thiserror.workspace = true
tokio.workspace = true
async-trait.workspace = true

# Hashing & encoding
blake3 = "1"
bs58 = "0.5"

# S3 (optional)
aws-sdk-s3 = { workspace = true, optional = true }
aws-config = { workspace = true, optional = true }

[dev-dependencies]
tokio = { workspace = true, features = ["rt-multi-thread", "macros"] }
tempfile = "3"
```

#### 3. Crate Structure

**File**: `crates/recrypt-storage/src/lib.rs`

````rust
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
//! use dcypher_storage::{ChunkStorage, InMemoryStorage};
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

mod memory;
mod local;

#[cfg(feature = "s3")]
mod s3;

pub mod chunking;

// Re-exports
pub use error::{StorageError, StorageResult};
pub use traits::{ChunkStorage, hash_to_base58, hash_from_base58};

pub use memory::InMemoryStorage;
pub use local::LocalFileStorage;

#[cfg(feature = "s3")]
pub use s3::S3Storage;
````

#### 4. Error Types

**File**: `crates/recrypt-storage/src/error.rs`

```rust
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
}
```

#### 5. Trait Definition

**File**: `crates/recrypt-storage/src/traits.rs`

```rust
//! Storage trait definitions

use async_trait::async_trait;
use blake3::Hash;

use crate::error::StorageResult;

/// Encode a Blake3 hash as base58 (compact, readable)
pub fn hash_to_base58(hash: &Hash) -> String {
    bs58::encode(hash.as_bytes()).into_string()
}

/// Decode base58 to Blake3 hash
pub fn hash_from_base58(s: &str) -> Option<Hash> {
    let bytes = bs58::decode(s).into_vec().ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(Hash::from(arr))
}

/// Content-addressed chunk storage
///
/// All operations are keyed by Blake3 hash. Implementations must verify
/// that stored data matches the provided hash (integrity guarantee).
#[async_trait]
pub trait ChunkStorage: Send + Sync {
    /// Store a chunk by its hash
    ///
    /// Implementations MUST verify that `blake3::hash(data) == hash`.
    /// Returns `StorageError::HashMismatch` if verification fails.
    async fn put(&self, hash: &Hash, data: &[u8]) -> StorageResult<()>;

    /// Retrieve a chunk by hash
    ///
    /// Returns `StorageError::NotFound` if the chunk doesn't exist.
    /// Implementations SHOULD verify hash on retrieval (defense in depth).
    async fn get(&self, hash: &Hash) -> StorageResult<Vec<u8>>;

    /// Check if a chunk exists
    async fn exists(&self, hash: &Hash) -> StorageResult<bool>;

    /// Delete a chunk
    ///
    /// Returns `Ok(())` even if the chunk didn't exist (idempotent).
    async fn delete(&self, hash: &Hash) -> StorageResult<()>;

    /// List all chunk hashes (primarily for testing/debugging)
    ///
    /// Production implementations may return an error or partial results
    /// for very large stores.
    async fn list(&self) -> StorageResult<Vec<Hash>>;
}
```

### Success Criteria

#### Automated Verification:

- [x] `cargo check -p recrypt-storage` compiles
- [x] `cargo check -p recrypt-storage --features s3` compiles (no S3 impl yet, but deps resolve)
- [x] `cargo doc -p recrypt-storage` generates docs

#### Manual Verification:

- [x] Trait design reviewed and approved

---

## Phase 4.2: Test Backends (InMemory + LocalFile)

### Overview

Implement `InMemoryStorage` and `LocalFileStorage` — fast backends for testing.

### Changes Required

#### 1. InMemoryStorage

**File**: `crates/recrypt-storage/src/memory.rs`

```rust
//! In-memory storage backend (for testing)

use std::collections::HashMap;
use std::sync::RwLock;

use async_trait::async_trait;
use blake3::Hash;

use crate::error::{StorageError, StorageResult};
use crate::traits::{ChunkStorage, hash_to_base58};

/// In-memory storage for unit tests
///
/// Thread-safe via `RwLock`. Not persistent — data lost on drop.
#[derive(Default)]
pub struct InMemoryStorage {
    chunks: RwLock<HashMap<Hash, Vec<u8>>>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored chunks
    pub fn len(&self) -> usize {
        self.chunks.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total bytes stored
    pub fn total_size(&self) -> usize {
        self.chunks.read().unwrap().values().map(|v| v.len()).sum()
    }

    /// Clear all stored chunks
    pub fn clear(&self) {
        self.chunks.write().unwrap().clear();
    }
}

#[async_trait]
impl ChunkStorage for InMemoryStorage {
    async fn put(&self, hash: &Hash, data: &[u8]) -> StorageResult<()> {
        // Verify hash
        let computed = blake3::hash(data);
        if computed != *hash {
            return Err(StorageError::HashMismatch {
                expected: hash_to_base58(hash),
                actual: hash_to_base58(&computed),
            });
        }

        self.chunks.write().unwrap().insert(*hash, data.to_vec());
        Ok(())
    }

    async fn get(&self, hash: &Hash) -> StorageResult<Vec<u8>> {
        self.chunks
            .read()
            .unwrap()
            .get(hash)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(hash_to_base58(hash)))
    }

    async fn exists(&self, hash: &Hash) -> StorageResult<bool> {
        Ok(self.chunks.read().unwrap().contains_key(hash))
    }

    async fn delete(&self, hash: &Hash) -> StorageResult<()> {
        self.chunks.write().unwrap().remove(hash);
        Ok(())
    }

    async fn list(&self) -> StorageResult<Vec<Hash>> {
        Ok(self.chunks.read().unwrap().keys().copied().collect())
    }
}
```

#### 2. LocalFileStorage

**File**: `crates/recrypt-storage/src/local.rs`

```rust
//! Local filesystem storage backend

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use blake3::Hash;
use tokio::fs;

use crate::error::{StorageError, StorageResult};
use crate::traits::{ChunkStorage, hash_to_base58, hash_from_base58};

/// Algorithm prefix for Blake3 hashes (enables future hash agility)
const HASH_ALG_PREFIX: &str = "b3";

/// Local filesystem storage
///
/// Stores chunks as files named by their base58 hash with algorithm prefix.
/// Structure: `{root}/chunks/b3/{hash_base58}`
pub struct LocalFileStorage {
    root: PathBuf,
}

impl LocalFileStorage {
    /// Create storage at the given root directory
    ///
    /// Creates the directory structure if it doesn't exist.
    pub async fn new(root: impl AsRef<Path>) -> StorageResult<Self> {
        let root = root.as_ref().to_path_buf();
        let chunks_dir = root.join("chunks").join(HASH_ALG_PREFIX);
        fs::create_dir_all(&chunks_dir).await?;
        Ok(Self { root })
    }

    fn chunk_path(&self, hash: &Hash) -> PathBuf {
        self.root
            .join("chunks")
            .join(HASH_ALG_PREFIX)
            .join(hash_to_base58(hash))
    }
}

#[async_trait]
impl ChunkStorage for LocalFileStorage {
    async fn put(&self, hash: &Hash, data: &[u8]) -> StorageResult<()> {
        // Verify hash
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
        let chunks_dir = self.root.join("chunks").join(HASH_ALG_PREFIX);
        let mut hashes = Vec::new();

        let mut entries = fs::read_dir(&chunks_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if let Some(name) = entry.file_name().to_str() {
                if let Some(hash) = hash_from_base58(name) {
                    hashes.push(hash);
                }
            }
        }

        Ok(hashes)
    }
}
```

#### 3. Unit Tests

**File**: `crates/recrypt-storage/src/memory.rs` (append)

```rust
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
        hashes.sort_by(|a, b| a.to_hex().cmp(&b.to_hex()));

        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains(&hash1));
        assert!(hashes.contains(&hash2));
    }
}
```

**File**: `crates/recrypt-storage/tests/local_storage.rs`

```rust
//! Integration tests for LocalFileStorage

use dcypher_storage::{ChunkStorage, LocalFileStorage, StorageError};
use tempfile::TempDir;

#[tokio::test]
async fn test_local_roundtrip() {
    let temp = TempDir::new().unwrap();
    let storage = LocalFileStorage::new(temp.path()).await.unwrap();

    let data = b"Local file storage test";
    let hash = blake3::hash(data);

    storage.put(&hash, data).await.unwrap();
    let retrieved = storage.get(&hash).await.unwrap();
    assert_eq!(retrieved, data);
}

#[tokio::test]
async fn test_local_persistence() {
    let temp = TempDir::new().unwrap();

    let data = b"Persistent data";
    let hash = blake3::hash(data);

    // Write with one instance
    {
        let storage = LocalFileStorage::new(temp.path()).await.unwrap();
        storage.put(&hash, data).await.unwrap();
    }

    // Read with new instance
    {
        let storage = LocalFileStorage::new(temp.path()).await.unwrap();
        let retrieved = storage.get(&hash).await.unwrap();
        assert_eq!(retrieved, data);
    }
}

#[tokio::test]
async fn test_local_list() {
    let temp = TempDir::new().unwrap();
    let storage = LocalFileStorage::new(temp.path()).await.unwrap();

    let chunks: Vec<&[u8]> = vec![b"a", b"b", b"c"];
    for chunk in &chunks {
        let hash = blake3::hash(chunk);
        storage.put(&hash, chunk).await.unwrap();
    }

    let listed = storage.list().await.unwrap();
    assert_eq!(listed.len(), 3);
}

#[tokio::test]
async fn test_local_not_found() {
    let temp = TempDir::new().unwrap();
    let storage = LocalFileStorage::new(temp.path()).await.unwrap();

    let hash = blake3::hash(b"missing");
    let result = storage.get(&hash).await;
    assert!(matches!(result, Err(StorageError::NotFound(_))));
}
```

### Success Criteria

#### Automated Verification:

- [x] `cargo test -p recrypt-storage` — all tests pass
- [x] `cargo clippy -p recrypt-storage` — no warnings

#### Manual Verification:

- [x] Code reviewed for thread safety (RwLock usage)

---

## Phase 4.3: S3/Minio Backend

### Overview

Implement `S3Storage` using `aws-sdk-s3`. Works with both Minio (dev) and AWS S3 (prod).

### Changes Required

#### 1. S3 Storage Implementation

**File**: `crates/recrypt-storage/src/s3.rs`

````rust
//! S3-compatible storage backend (Minio, AWS S3, Backblaze, etc.)

use async_trait::async_trait;
use aws_sdk_s3::Client;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::error::SdkError;
use blake3::Hash;

use crate::error::{StorageError, StorageResult};
use crate::traits::{ChunkStorage, hash_to_base58, hash_from_base58};

/// Algorithm prefix for Blake3 hashes (enables future hash agility)
const HASH_ALG_PREFIX: &str = "b3";

/// S3-compatible storage
///
/// Bucket structure:
/// ```text
/// {bucket}/
///   chunks/b3/{hash_base58}
/// ```
pub struct S3Storage {
    client: Client,
    bucket: String,
    prefix: String,
}

impl S3Storage {
    /// Create from existing AWS SDK client
    pub fn new(client: Client, bucket: impl Into<String>) -> Self {
        Self {
            client,
            bucket: bucket.into(),
            prefix: "chunks".into(),
        }
    }

    /// Create with custom prefix (for namespacing)
    pub fn with_prefix(client: Client, bucket: impl Into<String>, prefix: impl Into<String>) -> Self {
        Self {
            client,
            bucket: bucket.into(),
            prefix: prefix.into(),
        }
    }

    /// Create configured for local Minio
    ///
    /// Expects environment variables:
    /// - `MINIO_ENDPOINT` (default: http://localhost:9000)
    /// - `MINIO_ACCESS_KEY` (default: minioadmin)
    /// - `MINIO_SECRET_KEY` (default: minioadmin)
    pub async fn minio(bucket: impl Into<String>) -> StorageResult<Self> {
        let endpoint = std::env::var("MINIO_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:9000".into());
        let access_key = std::env::var("MINIO_ACCESS_KEY")
            .unwrap_or_else(|_| "minioadmin".into());
        let secret_key = std::env::var("MINIO_SECRET_KEY")
            .unwrap_or_else(|_| "minioadmin".into());

        let creds = aws_sdk_s3::config::Credentials::new(
            access_key,
            secret_key,
            None,
            None,
            "minio",
        );

        let config = aws_sdk_s3::Config::builder()
            .endpoint_url(endpoint)
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .credentials_provider(creds)
            .force_path_style(true)  // Required for Minio
            .build();

        let client = Client::from_conf(config);
        Ok(Self::new(client, bucket))
    }

    /// Ensure bucket exists (call on startup)
    pub async fn ensure_bucket(&self) -> StorageResult<()> {
        match self.client.head_bucket().bucket(&self.bucket).send().await {
            Ok(_) => Ok(()),
            Err(_) => {
                self.client
                    .create_bucket()
                    .bucket(&self.bucket)
                    .send()
                    .await
                    .map_err(|e| StorageError::Backend(format!("Failed to create bucket: {e}")))?;
                Ok(())
            }
        }
    }

    fn object_key(&self, hash: &Hash) -> String {
        format!("{}/{}/{}", self.prefix, HASH_ALG_PREFIX, hash_to_base58(hash))
    }
}

#[async_trait]
impl ChunkStorage for S3Storage {
    async fn put(&self, hash: &Hash, data: &[u8]) -> StorageResult<()> {
        // Verify hash before upload
        let computed = blake3::hash(data);
        if computed != *hash {
            return Err(StorageError::HashMismatch {
                expected: hash_to_base58(hash),
                actual: hash_to_base58(&computed),
            });
        }

        let key = self.object_key(hash);
        let body = ByteStream::from(data.to_vec());

        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(body)
            .send()
            .await
            .map_err(|e| StorageError::Backend(format!("S3 PUT failed: {e}")))?;

        Ok(())
    }

    async fn get(&self, hash: &Hash) -> StorageResult<Vec<u8>> {
        let key = self.object_key(hash);

        let response = self.client
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .map_err(|e| {
                if is_not_found(&e) {
                    StorageError::NotFound(hash_to_base58(hash))
                } else {
                    StorageError::Backend(format!("S3 GET failed: {e}"))
                }
            })?;

        let data = response.body
            .collect()
            .await
            .map_err(|e| StorageError::Backend(format!("Failed to read body: {e}")))?
            .into_bytes()
            .to_vec();

        // Verify on read
        let computed = blake3::hash(&data);
        if computed != *hash {
            return Err(StorageError::HashMismatch {
                expected: hash_to_base58(hash),
                actual: hash_to_base58(&computed),
            });
        }

        Ok(data)
    }

    async fn exists(&self, hash: &Hash) -> StorageResult<bool> {
        let key = self.object_key(hash);

        match self.client
            .head_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) if is_not_found(&e) => Ok(false),
            Err(e) => Err(StorageError::Backend(format!("S3 HEAD failed: {e}"))),
        }
    }

    async fn delete(&self, hash: &Hash) -> StorageResult<()> {
        let key = self.object_key(hash);

        // S3 delete is already idempotent
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .map_err(|e| StorageError::Backend(format!("S3 DELETE failed: {e}")))?;

        Ok(())
    }

    async fn list(&self) -> StorageResult<Vec<Hash>> {
        let mut hashes = Vec::new();
        let mut continuation_token: Option<String> = None;
        let full_prefix = format!("{}/{}/", self.prefix, HASH_ALG_PREFIX);

        loop {
            let mut request = self.client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&full_prefix);

            if let Some(token) = continuation_token {
                request = request.continuation_token(token);
            }

            let response = request
                .send()
                .await
                .map_err(|e| StorageError::Backend(format!("S3 LIST failed: {e}")))?;

            if let Some(contents) = response.contents {
                for obj in contents {
                    if let Some(key) = obj.key {
                        // Extract hash from key: "chunks/b3/{hash_base58}"
                        if let Some(hash_b58) = key.strip_prefix(&full_prefix) {
                            if let Some(hash) = hash_from_base58(hash_b58) {
                                hashes.push(hash);
                            }
                        }
                    }
                }
            }

            match response.next_continuation_token {
                Some(token) => continuation_token = Some(token),
                None => break,
            }
        }

        Ok(hashes)
    }
}

fn is_not_found<E>(err: &SdkError<E>) -> bool {
    matches!(err, SdkError::ServiceError(e) if e.raw().status().as_u16() == 404)
}
````

#### 2. Docker Compose

**File**: `docker/docker-compose.dev.yml`

```yaml
version: "3.8"

services:
  minio:
    image: minio/minio
    ports:
      - "9000:9000" # S3 API
      - "9001:9001" # Console UI
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    command: server /data --console-address ":9001"
    volumes:
      - minio_data:/data
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9000/minio/health/live"]
      interval: 5s
      timeout: 5s
      retries: 5

volumes:
  minio_data:
```

#### 3. Integration Tests

**File**: `crates/recrypt-storage/tests/s3_integration.rs`

```rust
//! S3/Minio integration tests
//!
//! Run with: cargo test -p recrypt-storage --features s3-tests
//! Requires Minio running: docker-compose -f docker/docker-compose.dev.yml up -d minio

#![cfg(feature = "s3-tests")]

use dcypher_storage::{ChunkStorage, S3Storage, StorageError};

async fn setup() -> S3Storage {
    let storage = S3Storage::minio("dcypher-test").await.unwrap();
    storage.ensure_bucket().await.unwrap();
    storage
}

#[tokio::test]
async fn test_s3_roundtrip() {
    let storage = setup().await;

    let data = b"S3 storage test";
    let hash = blake3::hash(data);

    storage.put(&hash, data).await.unwrap();
    let retrieved = storage.get(&hash).await.unwrap();
    assert_eq!(retrieved, data);

    // Cleanup
    storage.delete(&hash).await.unwrap();
}

#[tokio::test]
async fn test_s3_exists() {
    let storage = setup().await;

    let data = b"exists test";
    let hash = blake3::hash(data);

    assert!(!storage.exists(&hash).await.unwrap());
    storage.put(&hash, data).await.unwrap();
    assert!(storage.exists(&hash).await.unwrap());

    storage.delete(&hash).await.unwrap();
    assert!(!storage.exists(&hash).await.unwrap());
}

#[tokio::test]
async fn test_s3_not_found() {
    let storage = setup().await;

    let hash = blake3::hash(b"definitely not stored");
    let result = storage.get(&hash).await;
    assert!(matches!(result, Err(StorageError::NotFound(_))));
}

#[tokio::test]
async fn test_s3_list() {
    let storage = setup().await;

    // Store a few chunks
    let chunks: Vec<&[u8]> = vec![b"list1", b"list2", b"list3"];
    let mut hashes = Vec::new();

    for chunk in &chunks {
        let hash = blake3::hash(chunk);
        storage.put(&hash, chunk).await.unwrap();
        hashes.push(hash);
    }

    let listed = storage.list().await.unwrap();
    for hash in &hashes {
        assert!(listed.contains(hash));
    }

    // Cleanup
    for hash in &hashes {
        storage.delete(hash).await.unwrap();
    }
}

#[tokio::test]
async fn test_s3_hash_mismatch() {
    let storage = setup().await;

    let data = b"real data";
    let wrong_hash = blake3::hash(b"different data");

    let result = storage.put(&wrong_hash, data).await;
    assert!(matches!(result, Err(StorageError::HashMismatch { .. })));
}
```

### Success Criteria

#### Automated Verification:

- [x] `cargo check -p recrypt-storage --features s3` compiles
- [x] `docker-compose -f docker/docker-compose.dev.yml up -d minio` starts successfully
- [x] `cargo test -p recrypt-storage --features s3-tests` — all S3 tests pass

#### Manual Verification:

- [x] Minio console accessible at http://localhost:9001
- [x] Chunks visible in Minio UI after tests

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation that Minio integration works before proceeding to chunking utilities.

---

## Phase 4.4: Chunking Utilities

### Overview

Utilities for splitting large files into chunks and reassembling them. Aligns with Bao tree chunk boundaries.

### Changes Required

#### 1. Chunking Module

**File**: `crates/recrypt-storage/src/chunking.rs`

```rust
//! Chunking utilities for large file storage
//!
//! Splits files into content-addressed chunks for efficient storage/transfer.
//! Default chunk size: 4 MiB (aligned with typical S3 multipart size).

use blake3::Hash;

/// Default chunk size: 4 MiB
pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// A chunk with its hash and data
#[derive(Clone, Debug)]
pub struct Chunk {
    pub hash: Hash,
    pub data: Vec<u8>,
    pub index: usize,
}

/// Manifest for a chunked file
#[derive(Clone, Debug)]
pub struct ChunkManifest {
    /// Hash algorithm identifier (for future agility)
    pub hash_algorithm: &'static str,
    /// Blake3 hash of the complete data
    pub file_hash: Hash,
    /// Total size of original data
    pub total_size: u64,
    /// Ordered list of chunk hashes
    pub chunk_hashes: Vec<Hash>,
    /// Chunk size used (for reconstruction)
    pub chunk_size: usize,
}

/// Current hash algorithm identifier
pub const HASH_ALGORITHM: &str = "blake3";

/// Split data into chunks
///
/// Each chunk is hashed independently. Returns manifest + chunks.
pub fn split(data: &[u8], chunk_size: usize) -> (ChunkManifest, Vec<Chunk>) {
    let file_hash = blake3::hash(data);
    let mut chunks = Vec::new();
    let mut chunk_hashes = Vec::new();

    for (i, chunk_data) in data.chunks(chunk_size).enumerate() {
        let hash = blake3::hash(chunk_data);
        chunk_hashes.push(hash);
        chunks.push(Chunk {
            hash,
            data: chunk_data.to_vec(),
            index: i,
        });
    }

    let manifest = ChunkManifest {
        hash_algorithm: HASH_ALGORITHM,
        file_hash,
        total_size: data.len() as u64,
        chunk_hashes,
        chunk_size,
    };

    (manifest, chunks)
}

/// Split with default chunk size (4 MiB)
pub fn split_default(data: &[u8]) -> (ChunkManifest, Vec<Chunk>) {
    split(data, DEFAULT_CHUNK_SIZE)
}

/// Reassemble chunks into original data
///
/// Chunks must be provided in order. Verifies:
/// 1. Each chunk matches its expected hash
/// 2. Final reassembled data matches file_hash
///
/// Returns `None` if verification fails.
pub fn join(manifest: &ChunkManifest, chunks: &[&[u8]]) -> Option<Vec<u8>> {
    if chunks.len() != manifest.chunk_hashes.len() {
        return None;
    }

    // Verify each chunk
    for (chunk, expected_hash) in chunks.iter().zip(&manifest.chunk_hashes) {
        if blake3::hash(chunk) != *expected_hash {
            return None;
        }
    }

    // Reassemble
    let mut data = Vec::with_capacity(manifest.total_size as usize);
    for chunk in chunks {
        data.extend_from_slice(chunk);
    }

    // Verify final hash
    if blake3::hash(&data) != manifest.file_hash {
        return None;
    }

    Some(data)
}

/// Store a file as chunks
pub async fn store_chunked<S: crate::ChunkStorage>(
    storage: &S,
    data: &[u8],
    chunk_size: usize,
) -> crate::StorageResult<ChunkManifest> {
    let (manifest, chunks) = split(data, chunk_size);

    for chunk in chunks {
        storage.put(&chunk.hash, &chunk.data).await?;
    }

    Ok(manifest)
}

/// Retrieve and reassemble a chunked file
pub async fn retrieve_chunked<S: crate::ChunkStorage>(
    storage: &S,
    manifest: &ChunkManifest,
) -> crate::StorageResult<Vec<u8>> {
    let mut chunk_data = Vec::with_capacity(manifest.chunk_hashes.len());

    for hash in &manifest.chunk_hashes {
        let data = storage.get(hash).await?;
        chunk_data.push(data);
    }

    let refs: Vec<&[u8]> = chunk_data.iter().map(|v| v.as_slice()).collect();
    join(manifest, &refs)
        .ok_or_else(|| crate::StorageError::HashMismatch {
            expected: crate::hash_to_base58(&manifest.file_hash),
            actual: "verification failed".into(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_join_small() {
        let data = b"Small file that fits in one chunk";
        let (manifest, chunks) = split(data, 1024);

        assert_eq!(chunks.len(), 1);
        assert_eq!(manifest.chunk_hashes.len(), 1);

        let refs: Vec<&[u8]> = chunks.iter().map(|c| c.data.as_slice()).collect();
        let reassembled = join(&manifest, &refs).unwrap();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_split_join_multiple_chunks() {
        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let chunk_size = 1000;

        let (manifest, chunks) = split(&data, chunk_size);

        assert_eq!(chunks.len(), 10);
        assert_eq!(manifest.total_size, 10000);

        let refs: Vec<&[u8]> = chunks.iter().map(|c| c.data.as_slice()).collect();
        let reassembled = join(&manifest, &refs).unwrap();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_join_wrong_chunk_fails() {
        let data = b"Original data";
        let (manifest, _) = split(data, 1024);

        let wrong_chunk = b"Wrong data";
        let result = join(&manifest, &[wrong_chunk.as_slice()]);
        assert!(result.is_none());
    }

    #[test]
    fn test_deduplication() {
        // Identical chunks should have identical hashes
        let data = vec![0u8; 2048];
        let (manifest, chunks) = split(&data, 1024);

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].hash, chunks[1].hash);
        assert_eq!(manifest.chunk_hashes[0], manifest.chunk_hashes[1]);
    }

    #[tokio::test]
    async fn test_store_retrieve_chunked() {
        use crate::InMemoryStorage;

        let storage = InMemoryStorage::new();
        let data: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();

        let manifest = store_chunked(&storage, &data, 1000).await.unwrap();
        assert_eq!(manifest.chunk_hashes.len(), 5);

        let retrieved = retrieve_chunked(&storage, &manifest).await.unwrap();
        assert_eq!(retrieved, data);
    }
}
```

### Success Criteria

#### Automated Verification:

- [x] `cargo test -p recrypt-storage chunking` — all chunking tests pass
- [x] `cargo test -p recrypt-storage` — full test suite passes

#### Manual Verification:

- [x] Reviewed for edge cases (empty input, exact chunk boundaries)

---

## Phase 4.5: Justfile & CI Integration

### Overview

Add Justfile recipes for common storage operations and CI test configuration.

### Changes Required

#### 1. Justfile Updates

**File**: `Justfile` (append)

```just
# =============================================================================
# Storage Layer (Phase 4)
# =============================================================================

# Start Minio for development
minio-up:
    docker-compose -f docker/docker-compose.dev.yml up -d minio
    @echo "Minio console: http://localhost:9001 (minioadmin/minioadmin)"

# Stop Minio
minio-down:
    docker-compose -f docker/docker-compose.dev.yml down

# Run storage tests (in-memory + local only)
test-storage:
    cargo test -p recrypt-storage

# Run storage tests including S3/Minio integration
test-storage-s3: minio-up
    sleep 2  # Wait for Minio to be ready
    cargo test -p recrypt-storage --features s3-tests

# Check storage crate
check-storage:
    cargo check -p recrypt-storage
    cargo check -p recrypt-storage --features s3
    cargo clippy -p recrypt-storage -- -D warnings
    cargo clippy -p recrypt-storage --features s3 -- -D warnings
```

#### 2. GitHub Actions (optional — if CI exists)

**File**: `.github/workflows/storage.yml` (create if CI setup exists)

```yaml
name: Storage Tests

on:
  push:
    paths:
      - "crates/recrypt-storage/**"
      - "docker/docker-compose.dev.yml"
  pull_request:
    paths:
      - "crates/recrypt-storage/**"

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      minio:
        image: minio/minio
        ports:
          - 9000:9000
        env:
          MINIO_ROOT_USER: minioadmin
          MINIO_ROOT_PASSWORD: minioadmin
        options: --health-cmd "curl -f http://localhost:9000/minio/health/live"

    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      - name: Run unit tests
        run: cargo test -p recrypt-storage

      - name: Run S3 integration tests
        run: cargo test -p recrypt-storage --features s3-tests
        env:
          MINIO_ENDPOINT: http://localhost:9000
```

### Success Criteria

#### Automated Verification:

- [x] `just test-storage` passes
- [x] `just test-storage-s3` passes (with Minio running)
- [x] `just check-storage` passes (clippy clean)

#### Manual Verification:

- [x] `just minio-up` / `just minio-down` work correctly

---

## Testing Strategy

### Unit Tests (in-memory)

- Basic CRUD operations
- Hash verification (mismatch detection)
- Idempotent deletes
- List functionality
- Chunking split/join

### Integration Tests (local filesystem)

- Persistence across instances
- Directory structure

### Integration Tests (S3/Minio)

- Full CRUD cycle
- Bucket creation
- Pagination (list with many objects)
- Error handling (not found, network errors)

### Property-Based Tests (future)

- Arbitrary data roundtrips correctly
- Chunk boundaries handled correctly

---

## Performance Considerations

- **Chunk size**: 4 MiB default balances S3 request overhead vs memory usage
- **Parallel uploads**: Future enhancement — upload chunks concurrently
- **Streaming**: Current impl buffers in memory; streaming version possible with `AsyncRead`
- **Connection pooling**: `aws-sdk-s3` handles this internally

---

## Dependencies Summary

```toml
[dependencies]
blake3 = "1"
bs58 = "0.5"              # Base58 encoding (compact, readable)
tokio = { version = "1", features = ["full"] }
async-trait = "0.1"
thiserror = "2"

# Optional S3
aws-sdk-s3 = { version = "1", optional = true }
aws-config = { version = "1", optional = true }

[dev-dependencies]
tempfile = "3"
```

---

## Follow-up: Fix Hex Usage in recrypt-proto

**Status:** ✅ DONE

Switched from `hex` to `bs58` encoding for JSON serialization — more compact (~44 chars vs 64 for 32-byte hashes) and consistent with fingerprint encoding.

---

## References

- Design doc: `docs/storage-design.md`
- Proto types: `crates/recrypt-proto/proto/dcypher.proto` (ChunkProto, FileMetadata)
- AWS SDK: https://docs.rs/aws-sdk-s3
- Blake3: https://docs.rs/blake3
