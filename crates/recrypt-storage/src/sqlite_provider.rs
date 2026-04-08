//! SQLite-backed provider index

use std::sync::Mutex;

use async_trait::async_trait;
use blake3::Hash;
use rusqlite::Connection;

use crate::error::{StorageError, StorageResult};
use crate::provider::{ProviderIndex, ProviderUrl};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS provider_locations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_hash BLOB NOT NULL,
    provider_url TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE(file_hash, provider_url)
);

CREATE INDEX IF NOT EXISTS idx_locations_file
    ON provider_locations(file_hash);
CREATE INDEX IF NOT EXISTS idx_locations_provider
    ON provider_locations(provider_url);
"#;

fn init_schema(conn: &Connection) -> StorageResult<()> {
    conn.execute_batch(SCHEMA)?;
    Ok(())
}

/// SQLite-backed provider index
pub struct SqliteProviderIndex {
    conn: Mutex<Connection>,
}

impl SqliteProviderIndex {
    /// Open or create a database at the given path
    pub fn open(path: &str) -> StorageResult<Self> {
        let conn = Connection::open(path)?;
        init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Create an in-memory database (for testing)
    pub fn in_memory() -> StorageResult<Self> {
        let conn = Connection::open_in_memory()?;
        init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }
}

#[async_trait]
impl ProviderIndex for SqliteProviderIndex {
    async fn register(&self, file_hash: &Hash, provider_url: &ProviderUrl) -> StorageResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO provider_locations (file_hash, provider_url, created_at) VALUES (?, ?, ?)",
            (file_hash.as_bytes().as_slice(), provider_url, Self::now()),
        )?;
        Ok(())
    }

    async fn lookup(&self, file_hash: &Hash) -> StorageResult<Vec<ProviderUrl>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT provider_url FROM provider_locations WHERE file_hash = ?")?;

        let urls = stmt
            .query_map([file_hash.as_bytes().as_slice()], |row| {
                row.get::<_, String>(0)
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(urls)
    }

    async fn update_location(
        &self,
        file_hash: &Hash,
        old_url: &ProviderUrl,
        new_url: &ProviderUrl,
    ) -> StorageResult<()> {
        let conn = self.conn.lock().unwrap();
        let updated = conn.execute(
            "UPDATE provider_locations SET provider_url = ? WHERE file_hash = ? AND provider_url = ?",
            (new_url, file_hash.as_bytes().as_slice(), old_url),
        )?;

        if updated == 0 {
            return Err(StorageError::NotFound(file_hash.to_string()));
        }
        Ok(())
    }

    async fn remove_location(
        &self,
        file_hash: &Hash,
        provider_url: &ProviderUrl,
    ) -> StorageResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM provider_locations WHERE file_hash = ? AND provider_url = ?",
            (file_hash.as_bytes().as_slice(), provider_url),
        )?;
        Ok(())
    }

    async fn unregister(&self, file_hash: &Hash) -> StorageResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM provider_locations WHERE file_hash = ?",
            [file_hash.as_bytes().as_slice()],
        )?;
        Ok(())
    }

    async fn exists(&self, file_hash: &Hash) -> StorageResult<bool> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM provider_locations WHERE file_hash = ?",
            [file_hash.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    async fn list_at_provider(&self, provider_url: &ProviderUrl) -> StorageResult<Vec<Hash>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT file_hash FROM provider_locations WHERE provider_url = ?")?;

        let hashes = stmt
            .query_map([provider_url], |row| {
                let bytes: Vec<u8> = row.get(0)?;
                Ok(bytes)
            })?
            .filter_map(|r| r.ok())
            .filter_map(|bytes| {
                if bytes.len() == 32 {
                    let arr: [u8; 32] = bytes.try_into().ok()?;
                    Some(Hash::from(arr))
                } else {
                    None
                }
            })
            .collect();

        Ok(hashes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sqlite_provider_roundtrip() {
        let index = SqliteProviderIndex::in_memory().unwrap();
        let file = blake3::hash(b"test");
        let url = "https://s3.example.com/bucket/file".to_string();

        index.register(&file, &url).await.unwrap();

        let locations = index.lookup(&file).await.unwrap();
        assert_eq!(locations, vec![url]);

        assert!(index.exists(&file).await.unwrap());
    }

    #[tokio::test]
    async fn test_sqlite_multiple_providers() {
        let index = SqliteProviderIndex::in_memory().unwrap();
        let file = blake3::hash(b"test");

        index
            .register(&file, &"https://provider1.com".to_string())
            .await
            .unwrap();
        index
            .register(&file, &"https://provider2.com".to_string())
            .await
            .unwrap();

        let locations = index.lookup(&file).await.unwrap();
        assert_eq!(locations.len(), 2);
    }
}
