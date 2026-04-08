//! S3/Minio integration tests
//!
//! Run with: cargo test -p recrypt-storage --features s3-tests
//! Requires Minio running: docker-compose -f docker/docker-compose.dev.yml up -d minio

#![cfg(feature = "s3-tests")]

use recrypt_storage::{BlobStorage, S3Storage, StorageError};

async fn setup() -> S3Storage {
    let storage = S3Storage::minio("recrypt-test").await.unwrap();
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
