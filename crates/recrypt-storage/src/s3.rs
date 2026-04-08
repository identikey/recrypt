//! S3-compatible storage backend (Minio, AWS S3, Backblaze, etc.)

use async_trait::async_trait;
use aws_sdk_s3::Client;
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::primitives::ByteStream;
use blake3::Hash;

use crate::error::{StorageError, StorageResult};
use crate::traits::{ChunkStorage, hash_from_base58, hash_to_base58, raw_hash_to_base58};

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
    pub fn with_prefix(
        client: Client,
        bucket: impl Into<String>,
        prefix: impl Into<String>,
    ) -> Self {
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
        let endpoint =
            std::env::var("MINIO_ENDPOINT").unwrap_or_else(|_| "http://localhost:9000".into());
        let access_key = std::env::var("MINIO_ACCESS_KEY").unwrap_or_else(|_| "minioadmin".into());
        let secret_key = std::env::var("MINIO_SECRET_KEY").unwrap_or_else(|_| "minioadmin".into());

        let creds =
            aws_sdk_s3::config::Credentials::new(access_key, secret_key, None, None, "minio");

        let config = aws_sdk_s3::Config::builder()
            .endpoint_url(endpoint)
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .credentials_provider(creds)
            .force_path_style(true) // Required for Minio
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .build();

        let client = Client::from_conf(config);
        Ok(Self::new(client, bucket))
    }

    /// Ensure bucket exists (call on startup)
    pub async fn ensure_bucket(&self) -> StorageResult<()> {
        // Try to create bucket - S3/Minio returns success if it already exists
        match self
            .client
            .create_bucket()
            .bucket(&self.bucket)
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => {
                // Check if bucket already exists by trying head_bucket
                match self.client.head_bucket().bucket(&self.bucket).send().await {
                    Ok(_) => Ok(()), // Bucket exists, we're good
                    Err(_) => Err(StorageError::Backend(format!(
                        "Failed to create or access bucket: {e}"
                    ))),
                }
            }
        }
    }

    fn object_key(&self, hash: &Hash) -> String {
        format!(
            "{}/{}/{}",
            self.prefix,
            HASH_ALG_PREFIX,
            hash_to_base58(hash)
        )
    }

    fn outboard_key(&self, hash: &[u8; 32]) -> String {
        format!(
            "{}/{}/{}.obao",
            self.prefix,
            HASH_ALG_PREFIX,
            raw_hash_to_base58(hash)
        )
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

        let response = self
            .client
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

        let data = response
            .body
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

        match self
            .client
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

    async fn put_with_outboard(
        &self,
        hash: &[u8; 32],
        ciphertext: Vec<u8>,
        outboard: Vec<u8>,
    ) -> StorageResult<()> {
        let b3_hash = Hash::from(*hash);
        let key = self.object_key(&b3_hash);
        let body = ByteStream::from(ciphertext);
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(body)
            .send()
            .await
            .map_err(|e| StorageError::Backend(format!("S3 PUT ciphertext failed: {e}")))?;

        if !outboard.is_empty() {
            let ob_key = self.outboard_key(hash);
            let ob_body = ByteStream::from(outboard);
            self.client
                .put_object()
                .bucket(&self.bucket)
                .key(&ob_key)
                .body(ob_body)
                .send()
                .await
                .map_err(|e| StorageError::Backend(format!("S3 PUT outboard failed: {e}")))?;
        }

        Ok(())
    }

    async fn get_with_outboard(
        &self,
        hash: &[u8; 32],
    ) -> StorageResult<(Vec<u8>, Vec<u8>)> {
        let b3_hash = Hash::from(*hash);
        let key = self.object_key(&b3_hash);
        let b58 = raw_hash_to_base58(hash);

        let response = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .map_err(|e| {
                if is_not_found(&e) {
                    StorageError::NotFound(b58.clone())
                } else {
                    StorageError::Backend(format!("S3 GET ciphertext failed: {e}"))
                }
            })?;

        let ciphertext = response
            .body
            .collect()
            .await
            .map_err(|e| StorageError::Backend(format!("Failed to read ciphertext body: {e}")))?
            .into_bytes()
            .to_vec();

        let ob_key = self.outboard_key(hash);
        let outboard = match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&ob_key)
            .send()
            .await
        {
            Ok(resp) => resp
                .body
                .collect()
                .await
                .map_err(|e| StorageError::Backend(format!("Failed to read outboard body: {e}")))?
                .into_bytes()
                .to_vec(),
            Err(e) if is_not_found(&e) => Vec::new(),
            Err(e) => return Err(StorageError::Backend(format!("S3 GET outboard failed: {e}"))),
        };

        Ok((ciphertext, outboard))
    }

    async fn delete_with_outboard(
        &self,
        hash: &[u8; 32],
    ) -> StorageResult<()> {
        let b3_hash = Hash::from(*hash);
        let key = self.object_key(&b3_hash);
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .map_err(|e| StorageError::Backend(format!("S3 DELETE ciphertext failed: {e}")))?;

        let ob_key = self.outboard_key(hash);
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(&ob_key)
            .send()
            .await
            .map_err(|e| StorageError::Backend(format!("S3 DELETE outboard failed: {e}")))?;

        Ok(())
    }

    async fn list(&self) -> StorageResult<Vec<Hash>> {
        let mut hashes = Vec::new();
        let mut continuation_token: Option<String> = None;
        let full_prefix = format!("{}/{}/", self.prefix, HASH_ALG_PREFIX);

        loop {
            let mut request = self
                .client
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
                        if let Some(hash_b58) = key.strip_prefix(&full_prefix)
                            && let Some(hash) = hash_from_base58(hash_b58)
                        {
                            hashes.push(hash);
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

// ── Orphan GC ─────────────────────────────────────────────────────────────────

#[cfg(feature = "s3")]
impl S3Storage {
    /// Scan S3 storage for orphaned objects and optionally delete them.
    ///
    /// Lists all objects under `{prefix}/b3/`, extracts hashes by stripping the
    /// prefix and the optional `.obao` suffix, then base58-decodes. Deduplicates
    /// ciphertext + outboard pairs per hash before checking metadata and age.
    ///
    /// Key-parsing logic:
    /// 1. Strip `"{prefix}/b3/"` from the object key.
    /// 2. If the remainder ends with `.obao`, strip that suffix — it's an outboard.
    /// 3. Base58-decode the remaining string to obtain the 32-byte hash.
    /// 4. Keys that don't parse are silently skipped (defensive).
    pub async fn gc_orphans(
        &self,
        metadata: &dyn crate::gc::MetadataIndex,
        opts: crate::gc::GcOptions,
    ) -> StorageResult<crate::gc::GcReport> {
        use std::collections::HashMap;
        use std::time::{Duration, SystemTime};

        let now = SystemTime::now();
        let full_prefix = format!("{}/{}/", self.prefix, HASH_ALG_PREFIX);
        let mut continuation_token: Option<String> = None;

        // Key: hash bytes; Value: (ciphertext_size, outboard_size, last_modified_of_ciphertext)
        let mut seen: HashMap<[u8; 32], (u64, u64, SystemTime)> = HashMap::new();

        loop {
            let mut req = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&full_prefix);

            if let Some(token) = continuation_token.take() {
                req = req.continuation_token(token);
            }

            let resp = req
                .send()
                .await
                .map_err(|e| StorageError::Backend(format!("S3 LIST failed during GC: {e}")))?;

            if let Some(contents) = resp.contents {
                for obj in contents {
                    let key = match obj.key {
                        Some(k) => k,
                        None => continue,
                    };
                    let size = obj.size.unwrap_or(0) as u64;
                    // Convert S3 DateTime (seconds since epoch) to SystemTime.
                    let last_modified: SystemTime = obj
                        .last_modified
                        .map(|dt| {
                            let secs = dt.secs().max(0) as u64;
                            SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
                        })
                        .unwrap_or(SystemTime::UNIX_EPOCH);

                    // Strip prefix. Remaining: `{b58}` or `{b58}.obao`.
                    let suffix = match key.strip_prefix(&full_prefix) {
                        Some(s) => s,
                        None => continue,
                    };

                    let (b58, is_outboard) = if let Some(b) = suffix.strip_suffix(".obao") {
                        (b, true)
                    } else {
                        (suffix, false)
                    };

                    let hash = match hash_from_base58(b58) {
                        Some(h) => *h.as_bytes(),
                        None => continue, // skip unrecognised keys defensively
                    };

                    let entry = seen.entry(hash).or_insert((0, 0, last_modified));
                    if is_outboard {
                        entry.1 += size;
                    } else {
                        entry.0 += size;
                        // Use ciphertext's last_modified as canonical age.
                        entry.2 = last_modified;
                    }
                }
            }

            match resp.next_continuation_token {
                Some(token) => continuation_token = Some(token),
                None => break,
            }
        }

        // Evaluate each unique hash.
        let mut report = crate::gc::GcReport::default();

        for (hash_bytes, (ct_size, ob_size, last_modified)) in seen {
            report.scanned += 1;

            let age = now
                .duration_since(last_modified)
                .unwrap_or(Duration::ZERO);
            if age < opts.max_upload_lifetime {
                continue;
            }

            if metadata.has_metadata(&hash_bytes).await? {
                continue;
            }

            let b58 = raw_hash_to_base58(&hash_bytes);
            let ct_key = format!("{}{}", full_prefix, b58);
            let ob_key = format!("{}{}.obao", full_prefix, b58);

            report.orphans_found += 1;
            report.bytes_reclaimed += ct_size + ob_size;
            report.deleted_keys.push(ct_key.clone());
            if ob_size > 0 {
                report.deleted_keys.push(ob_key.clone());
            }

            if !opts.dry_run {
                self.client
                    .delete_object()
                    .bucket(&self.bucket)
                    .key(&ct_key)
                    .send()
                    .await
                    .map_err(|e| {
                        StorageError::Backend(format!("S3 DELETE ciphertext failed: {e}"))
                    })?;

                if ob_size > 0 {
                    self.client
                        .delete_object()
                        .bucket(&self.bucket)
                        .key(&ob_key)
                        .send()
                        .await
                        .map_err(|e| {
                            StorageError::Backend(format!("S3 DELETE outboard failed: {e}"))
                        })?;
                }
            }
        }

        Ok(report)
    }
}

fn is_not_found<E>(err: &SdkError<E>) -> bool {
    matches!(err, SdkError::ServiceError(e) if e.raw().status().as_u16() == 404)
}
