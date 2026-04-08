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

/// Encode a raw 32-byte hash as base58
pub fn raw_hash_to_base58(hash: &[u8; 32]) -> String {
    bs58::encode(hash).into_string()
}

/// Content-addressed chunk storage
///
/// All operations are keyed by Blake3 hash. Implementations must verify
/// that stored data matches the provided hash (integrity guarantee).
#[async_trait]
pub trait BlobStorage: Send + Sync {
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

    // ── Two-object API (bao-tree layout) ────────────────────────────────────
    //
    // Each encrypted file is stored as two sibling objects keyed by the
    // Blake3 root hash of the ciphertext:
    //
    //   blob/b3/{base58(hash)}       — ciphertext blob
    //   blob/b3/{base58(hash)}.obao  — bao-tree outboard (omitted for ≤16 KiB)
    //
    // When `outboard` is empty the sibling `.obao` object is not stored.
    // `get_with_outboard` returns an empty `Vec` for the outboard in that case.
    //
    // TODO(future): return `impl AsyncRead` once bao-tree gains stable streaming
    // support and the API can do incremental verification without buffering the
    // entire ciphertext. For now, `Vec<u8>` is correct and consistent with how
    // Group B's encrypt/decrypt path works.
    //
    // TODO(future): use S3 multipart upload for the ciphertext object once the
    // interface supports streaming inputs. The current `Vec<u8>` interface
    // issues a single PutObject call, which is sufficient for the first cut.

    /// Store a ciphertext blob and its sibling outboard atomically.
    ///
    /// If `outboard` is empty (file ≤ 16 KiB), the `.obao` sibling is skipped.
    ///
    /// Key format:
    /// - Ciphertext: `blob/b3/{base58(hash)}`
    /// - Outboard:   `blob/b3/{base58(hash)}.obao`
    async fn put_with_outboard(
        &self,
        hash: &[u8; 32],
        ciphertext: Vec<u8>,
        outboard: Vec<u8>,
    ) -> StorageResult<()>;

    /// Retrieve a ciphertext blob and its outboard sibling.
    ///
    /// Returns `(ciphertext_bytes, outboard_bytes)`. `outboard_bytes` is empty
    /// when no `.obao` sibling exists (small-file case).
    ///
    /// Returns `StorageError::NotFound` if the ciphertext object is absent.
    async fn get_with_outboard(
        &self,
        hash: &[u8; 32],
    ) -> StorageResult<(Vec<u8>, Vec<u8>)>;

    /// Delete both the ciphertext and (if present) the outboard sibling.
    ///
    /// Succeeds even if neither object exists (idempotent).
    async fn delete_with_outboard(
        &self,
        hash: &[u8; 32],
    ) -> StorageResult<()>;
}
