//! Orphan GC sweep: delete ciphertext + outboard objects with no metadata record.
//!
//! ## Background
//!
//! When a client uploads ciphertext to storage but the metadata POST never
//! lands (crash, network error, etc.) the objects are orphaned. This module
//! provides an application-level sweep to reclaim them.
//!
//! S3 incomplete-multipart-upload cleanup is handled separately via a bucket
//! lifecycle rule (see `docs/deployment.md`). This sweep covers fully-uploaded
//! objects whose metadata record is missing.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use recrypt_storage::gc::{GcOptions, MockMetadataIndex};
//! use recrypt_storage::InMemoryStorage;
//!
//! let storage = InMemoryStorage::new();
//! let index = MockMetadataIndex::default();
//! let opts = GcOptions::default();
//! let report = storage.gc_orphans(&index, opts).await.unwrap();
//! println!("{} orphans deleted", report.orphans_found);
//! ```

use std::time::{Duration, SystemTime};

use async_trait::async_trait;

use crate::error::StorageResult;
use crate::memory::InMemoryStorage;
use crate::traits::{ChunkStorage, hash_to_base58};

// ── MetadataIndex trait ──────────────────────────────────────────────────────

/// Lookup interface the GC uses to determine whether a hash has an associated
/// metadata record.
///
/// Implemented by the metadata service / auth crate as needed. Defined here so
/// `recrypt-storage` does not depend on the metadata crate directly.
#[async_trait]
pub trait MetadataIndex: Send + Sync {
    /// Returns `true` if a metadata record exists for the given hash.
    async fn has_metadata(&self, hash: &[u8; 32]) -> StorageResult<bool>;
}

// ── GcOptions ────────────────────────────────────────────────────────────────

/// Configuration for an orphan GC sweep.
#[derive(Debug, Clone)]
pub struct GcOptions {
    /// Orphans younger than this are kept so in-flight uploads can finish.
    pub max_upload_lifetime: Duration,
    /// If `true`, scan and report but do not delete anything.
    pub dry_run: bool,
}

impl Default for GcOptions {
    fn default() -> Self {
        Self {
            max_upload_lifetime: Duration::from_secs(24 * 60 * 60), // 24 h
            dry_run: false,
        }
    }
}

// ── GcReport ─────────────────────────────────────────────────────────────────

/// Summary returned after a GC sweep.
#[derive(Debug, Default)]
pub struct GcReport {
    /// Total objects scanned (each ciphertext + outboard pair counts as one).
    pub scanned: u64,
    /// Number of distinct hashes identified as orphans.
    pub orphans_found: u64,
    /// Total bytes that were (or would have been) reclaimed.
    pub bytes_reclaimed: u64,
    /// Keys that were (or would have been) deleted.
    pub deleted_keys: Vec<String>,
}

// ── InMemoryStorage::gc_orphans ───────────────────────────────────────────────

impl InMemoryStorage {
    /// Scan in-memory storage for orphaned objects and optionally delete them.
    ///
    /// An object is considered an orphan when:
    /// 1. `metadata.has_metadata(hash)` returns `false`, AND
    /// 2. The object was inserted more than `opts.max_upload_lifetime` ago.
    ///
    /// Both the ciphertext and its `.obao` sibling are deleted together.
    pub async fn gc_orphans(
        &self,
        metadata: &dyn MetadataIndex,
        opts: GcOptions,
    ) -> StorageResult<GcReport> {
        let now = SystemTime::now();
        let entries = self.snapshot_entries(); // releases lock

        let mut report = GcReport::default();

        for (hash, data_len, inserted_at) in entries {
            report.scanned += 1;

            // Age check: skip objects that might still be uploading.
            let age = now.duration_since(inserted_at).unwrap_or(Duration::ZERO);
            if age < opts.max_upload_lifetime {
                continue;
            }

            let hash_bytes: [u8; 32] = *hash.as_bytes();
            if metadata.has_metadata(&hash_bytes).await? {
                continue;
            }

            // It's an orphan.
            let b58 = hash_to_base58(&hash);
            let ct_key = format!("chunks/b3/{}", b58);
            let ob_key = format!("chunks/b3/{}.obao", b58);

            let ob_len = self.outboard_len(&hash);
            let total_bytes = (data_len + ob_len) as u64;

            report.orphans_found += 1;
            report.bytes_reclaimed += total_bytes;
            report.deleted_keys.push(ct_key);
            if ob_len > 0 {
                report.deleted_keys.push(ob_key);
            }

            if !opts.dry_run {
                // Delete both ciphertext and outboard sibling.
                self.delete_with_outboard(&hash_bytes).await?;
            }
        }

        Ok(report)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
pub mod tests {
    use std::collections::HashSet;

    use super::*;

    /// Minimal `MetadataIndex` backed by a `HashSet`.
    #[derive(Default)]
    pub struct MockMetadataIndex {
        known: HashSet<[u8; 32]>,
    }

    impl MockMetadataIndex {
        pub fn with_hashes(hashes: impl IntoIterator<Item = [u8; 32]>) -> Self {
            Self {
                known: hashes.into_iter().collect(),
            }
        }
    }

    #[async_trait]
    impl MetadataIndex for MockMetadataIndex {
        async fn has_metadata(&self, hash: &[u8; 32]) -> StorageResult<bool> {
            Ok(self.known.contains(hash))
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Insert data bypassing hash verification (for testing arbitrary orphans).
    ///
    /// Uses `put_with_outboard` with the raw bytes passed in; the "hash" is
    /// computed by blake3 so the storage integrity check passes.
    async fn insert_chunk(storage: &InMemoryStorage, data: &[u8]) -> [u8; 32] {
        let hash = blake3::hash(data);
        storage
            .put(&hash, data)
            .await
            .expect("put failed");
        *hash.as_bytes()
    }

    async fn insert_chunk_with_outboard(
        storage: &InMemoryStorage,
        data: &[u8],
        outboard: &[u8],
    ) -> [u8; 32] {
        let hash = blake3::hash(data);
        let hash_bytes = *hash.as_bytes();
        storage
            .put_with_outboard(&hash_bytes, data.to_vec(), outboard.to_vec())
            .await
            .expect("put_with_outboard failed");
        hash_bytes
    }

    // ── Test 1: in-memory happy path ──────────────────────────────────────────

    #[tokio::test]
    async fn test_gc_deletes_orphans() {
        let storage = InMemoryStorage::new();

        let h1 = insert_chunk(&storage, b"chunk one").await;
        let h2 = insert_chunk(&storage, b"chunk two").await;
        let h3 = insert_chunk(&storage, b"chunk three").await;

        // Only h1 has metadata; h2 and h3 are orphans.
        let index = MockMetadataIndex::with_hashes([h1]);

        let opts = GcOptions {
            max_upload_lifetime: Duration::ZERO, // treat everything as old enough
            dry_run: false,
        };

        let report = storage.gc_orphans(&index, opts).await.unwrap();

        assert_eq!(report.scanned, 3, "should have scanned all 3 entries");
        assert_eq!(report.orphans_found, 2, "h2 and h3 are orphans");
        assert!(report.bytes_reclaimed > 0);

        // h2 and h3 must be gone; h1 must survive.
        let still_has_h1 = storage
            .exists(&blake3::Hash::from(h1))
            .await
            .unwrap();
        assert!(still_has_h1, "h1 must survive (it has metadata)");

        let still_has_h2 = storage
            .exists(&blake3::Hash::from(h2))
            .await
            .unwrap();
        assert!(!still_has_h2, "h2 must be deleted");

        let still_has_h3 = storage
            .exists(&blake3::Hash::from(h3))
            .await
            .unwrap();
        assert!(!still_has_h3, "h3 must be deleted");
    }

    // ── Test 2: dry-run mode ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_gc_dry_run_does_not_delete() {
        let storage = InMemoryStorage::new();

        let h1 = insert_chunk(&storage, b"chunk alpha").await;
        let h2 = insert_chunk(&storage, b"chunk beta").await;
        let h3 = insert_chunk(&storage, b"chunk gamma").await;

        let index = MockMetadataIndex::with_hashes([h1]);

        let opts = GcOptions {
            max_upload_lifetime: Duration::ZERO,
            dry_run: true,
        };

        let report = storage.gc_orphans(&index, opts).await.unwrap();

        assert_eq!(report.orphans_found, 2);
        assert!(!report.deleted_keys.is_empty(), "dry-run still reports keys");

        // Nothing should be deleted.
        for hash_bytes in [h1, h2, h3] {
            let exists = storage
                .exists(&blake3::Hash::from(hash_bytes))
                .await
                .unwrap();
            assert!(exists, "dry-run must not delete anything");
        }
    }

    // ── Test 3: age threshold keeps young orphans ─────────────────────────────

    #[tokio::test]
    async fn test_gc_age_threshold_keeps_young_orphans() {
        let storage = InMemoryStorage::new();

        // Insert orphans (no metadata for any of them).
        insert_chunk(&storage, b"young orphan 1").await;
        insert_chunk(&storage, b"young orphan 2").await;

        let index = MockMetadataIndex::default(); // nothing has metadata

        let opts = GcOptions {
            max_upload_lifetime: Duration::from_secs(3600), // 1 hour
            dry_run: false,
        };

        let report = storage.gc_orphans(&index, opts).await.unwrap();

        // All objects are younger than 1 hour, so none should be deleted.
        assert_eq!(
            report.orphans_found, 0,
            "young orphans must not be deleted"
        );
        assert_eq!(report.bytes_reclaimed, 0);
    }

    // ── Test 4: outboard sibling counted in bytes_reclaimed ───────────────────

    #[tokio::test]
    async fn test_gc_outboard_sibling_bytes_counted() {
        let storage = InMemoryStorage::new();

        let ciphertext = b"encrypted content";
        let outboard = b"outboard tree data";

        let _hash_bytes =
            insert_chunk_with_outboard(&storage, ciphertext, outboard).await;

        // No metadata — it's an orphan.
        let index = MockMetadataIndex::default();

        let opts = GcOptions {
            max_upload_lifetime: Duration::ZERO,
            dry_run: false,
        };

        let report = storage.gc_orphans(&index, opts).await.unwrap();

        assert_eq!(report.orphans_found, 1);
        let expected_bytes = (ciphertext.len() + outboard.len()) as u64;
        assert_eq!(
            report.bytes_reclaimed, expected_bytes,
            "bytes_reclaimed must include both ciphertext and outboard"
        );

        // Deleted keys should include both.
        let has_ct_key = report
            .deleted_keys
            .iter()
            .any(|k| !k.ends_with(".obao"));
        let has_ob_key = report.deleted_keys.iter().any(|k| k.ends_with(".obao"));
        assert!(has_ct_key, "ciphertext key must appear in deleted_keys");
        assert!(has_ob_key, "outboard key must appear in deleted_keys");

        // Storage must be empty.
        assert!(storage.is_empty(), "storage must be empty after GC");
    }
}
