//! Integration tests for LocalFileStorage

use recrypt_storage::{BlobStorage, LocalFileStorage, StorageError};
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
