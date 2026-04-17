//! SQLite ownership store

use std::sync::Mutex;

use async_trait::async_trait;
use blake3::Hash;
use rusqlite::Connection;

use super::schema::init_schema;
use crate::error::{AuthError, AuthResult};
use crate::fingerprint::PublicKeyFingerprint;
use crate::ownership::OwnershipStore;

/// SQLite-backed ownership store
pub struct SqliteOwnershipStore {
    conn: Mutex<Connection>,
}

impl SqliteOwnershipStore {
    /// Open or create a database at the given path
    pub fn open(path: &str) -> AuthResult<Self> {
        let conn = Connection::open(path)?;
        init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Create an in-memory database (for testing)
    pub fn in_memory() -> AuthResult<Self> {
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
impl OwnershipStore for SqliteOwnershipStore {
    async fn register(&self, owner: &PublicKeyFingerprint, file_hash: &Hash) -> AuthResult<()> {
        let conn = self.conn.lock().unwrap();

        // Check for existing different owner
        let existing: Option<Vec<u8>> = conn
            .query_row(
                "SELECT owner_fingerprint FROM ownership WHERE file_hash = ?",
                [file_hash.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .ok();

        if let Some(existing_owner) = existing {
            if existing_owner != owner.as_bytes().as_slice() {
                return Err(AuthError::AlreadyExists(format!(
                    "File {file_hash} already owned by different key"
                )));
            }
            return Ok(()); // Idempotent
        }

        conn.execute(
            "INSERT INTO ownership (file_hash, owner_fingerprint, created_at) VALUES (?, ?, ?)",
            (
                file_hash.as_bytes().as_slice(),
                owner.as_bytes().as_slice(),
                Self::now(),
            ),
        )?;

        Ok(())
    }

    async fn is_owner(&self, owner: &PublicKeyFingerprint, file_hash: &Hash) -> AuthResult<bool> {
        let conn = self.conn.lock().unwrap();

        let result: Option<Vec<u8>> = conn
            .query_row(
                "SELECT owner_fingerprint FROM ownership WHERE file_hash = ?",
                [file_hash.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .ok();

        Ok(result
            .map(|v| v == owner.as_bytes().as_slice())
            .unwrap_or(false))
    }

    async fn list_owned(&self, owner: &PublicKeyFingerprint) -> AuthResult<Vec<Hash>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt =
            conn.prepare("SELECT file_hash FROM ownership WHERE owner_fingerprint = ?")?;

        let hashes = stmt
            .query_map([owner.as_bytes().as_slice()], |row| {
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

    async fn transfer(
        &self,
        from: &PublicKeyFingerprint,
        to: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<()> {
        if !self.is_owner(from, file_hash).await? {
            return Err(AuthError::NotAuthorized("Only owner can transfer".into()));
        }

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE ownership SET owner_fingerprint = ? WHERE file_hash = ?",
            (to.as_bytes().as_slice(), file_hash.as_bytes().as_slice()),
        )?;

        Ok(())
    }

    async fn unregister(&self, owner: &PublicKeyFingerprint, file_hash: &Hash) -> AuthResult<()> {
        if !self.is_owner(owner, file_hash).await? {
            return Err(AuthError::NotAuthorized("Only owner can unregister".into()));
        }

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM ownership WHERE file_hash = ?",
            [file_hash.as_bytes().as_slice()],
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(n: u8) -> PublicKeyFingerprint {
        PublicKeyFingerprint::from_bytes([n; 32])
    }

    #[tokio::test]
    async fn test_sqlite_ownership_roundtrip() {
        let store = SqliteOwnershipStore::in_memory().unwrap();
        let owner = fp(1);
        let file = blake3::hash(b"test");

        store.register(&owner, &file).await.unwrap();
        assert!(store.is_owner(&owner, &file).await.unwrap());

        let owned = store.list_owned(&owner).await.unwrap();
        assert_eq!(owned.len(), 1);
    }

    #[tokio::test]
    async fn test_sqlite_transfer() {
        let store = SqliteOwnershipStore::in_memory().unwrap();
        let alice = fp(1);
        let bob = fp(2);
        let file = blake3::hash(b"test");

        store.register(&alice, &file).await.unwrap();
        store.transfer(&alice, &bob, &file).await.unwrap();

        assert!(!store.is_owner(&alice, &file).await.unwrap());
        assert!(store.is_owner(&bob, &file).await.unwrap());
    }
}
