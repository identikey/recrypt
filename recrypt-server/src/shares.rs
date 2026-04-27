//! Share policy storage trait and implementations.
//!
//! A `SharePolicy` carries the recryption key for an Alice→Bob share. The
//! [`ShareStore`] trait abstracts over in-memory and SQLite-backed storage so
//! that the server can be configured at startup.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use recrypt_core::pre::BackendId;
use tokio::sync::RwLock;

use crate::error::{ServerError, ServerResult};

pub type ShareId = String;
pub type PublicKeyFingerprint = String; // base58

/// Persistent share record for a Alice→Bob recryption authorization.
#[derive(Clone, Debug)]
pub struct SharePolicy {
    pub id: ShareId,
    pub from_fingerprint: PublicKeyFingerprint,
    pub to_fingerprint: PublicKeyFingerprint,
    pub file_hash: blake3::Hash,
    pub recrypt_key: Vec<u8>,
    /// Serialized original wrapped key (`Ciphertext::to_bytes()`).
    /// Stored so `get_recrypted_share` can recrypt it without loading the
    /// full file from storage (the file envelope does not embed the wrapped key).
    pub wrapped_key: Vec<u8>,
    pub backend_id: BackendId,
    pub created_at: u64,
}

#[async_trait]
pub trait ShareStore: Send + Sync {
    async fn create(&self, policy: SharePolicy) -> ServerResult<ShareId>;
    async fn get(&self, id: &ShareId) -> ServerResult<Option<SharePolicy>>;
    async fn delete(&self, id: &ShareId) -> ServerResult<()>;
    async fn list_outgoing(&self, from: &PublicKeyFingerprint) -> ServerResult<Vec<SharePolicy>>;
    async fn list_incoming(&self, to: &PublicKeyFingerprint) -> ServerResult<Vec<SharePolicy>>;
}

/// In-memory implementation backed by `RwLock<HashMap<...>>`.
#[derive(Default)]
pub struct InMemoryShareStore {
    inner: RwLock<HashMap<ShareId, SharePolicy>>,
}

impl InMemoryShareStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn shared() -> Arc<dyn ShareStore> {
        Arc::new(Self::new())
    }
}

#[async_trait]
impl ShareStore for InMemoryShareStore {
    async fn create(&self, policy: SharePolicy) -> ServerResult<ShareId> {
        let id = policy.id.clone();
        let mut guard = self.inner.write().await;
        guard.insert(id.clone(), policy);
        Ok(id)
    }

    async fn get(&self, id: &ShareId) -> ServerResult<Option<SharePolicy>> {
        Ok(self.inner.read().await.get(id).cloned())
    }

    async fn delete(&self, id: &ShareId) -> ServerResult<()> {
        self.inner.write().await.remove(id);
        Ok(())
    }

    async fn list_outgoing(&self, from: &PublicKeyFingerprint) -> ServerResult<Vec<SharePolicy>> {
        Ok(self
            .inner
            .read()
            .await
            .values()
            .filter(|p| &p.from_fingerprint == from)
            .cloned()
            .collect())
    }

    async fn list_incoming(&self, to: &PublicKeyFingerprint) -> ServerResult<Vec<SharePolicy>> {
        Ok(self
            .inner
            .read()
            .await
            .values()
            .filter(|p| &p.to_fingerprint == to)
            .cloned()
            .collect())
    }
}

// ---------------------------------------------------------------------------
// SQLite implementation
// ---------------------------------------------------------------------------

/// SQLite-backed share store using a shared `tokio_rusqlite::Connection`.
pub struct SqliteShareStore {
    conn: Arc<tokio_rusqlite::Connection>,
}

impl SqliteShareStore {
    /// Create the `shares` table if it does not exist. Safe to call multiple
    /// times against the same connection.
    pub async fn new(conn: Arc<tokio_rusqlite::Connection>) -> ServerResult<Self> {
        conn.call(|c| {
            c.execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS shares (
                    share_id    TEXT PRIMARY KEY,
                    from_fp     TEXT NOT NULL,
                    to_fp       TEXT NOT NULL,
                    file_hash   TEXT NOT NULL,
                    recrypt_key BLOB NOT NULL,
                    wrapped_key BLOB NOT NULL DEFAULT X'',
                    backend_id  TEXT NOT NULL,
                    created_at  INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_shares_from ON shares(from_fp);
                CREATE INDEX IF NOT EXISTS idx_shares_to   ON shares(to_fp);
                "#,
            )?;
            Ok::<_, rusqlite::Error>(())
        })
        .await
        .map_err(map_sqlite_err)?;
        Ok(Self { conn })
    }
}

fn map_sqlite_err(e: tokio_rusqlite::Error) -> ServerError {
    ServerError::Internal(format!("sqlite error: {e}"))
}

#[allow(dead_code)]
fn map_rusqlite_err(e: rusqlite::Error) -> ServerError {
    ServerError::Internal(format!("sqlite error: {e}"))
}

fn row_to_policy(row: &rusqlite::Row<'_>) -> rusqlite::Result<SharePolicy> {
    let id: String = row.get(0)?;
    let from_fp: String = row.get(1)?;
    let to_fp: String = row.get(2)?;
    let file_hash_b58: String = row.get(3)?;
    let recrypt_key: Vec<u8> = row.get(4)?;
    let wrapped_key: Vec<u8> = row.get(5)?;
    let backend_id_s: String = row.get(6)?;
    let created_at: i64 = row.get(7)?;

    let hash_bytes = bs58::decode(&file_hash_b58).into_vec().map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(e))
    })?;
    if hash_bytes.len() != 32 {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            3,
            rusqlite::types::Type::Text,
            "file_hash not 32 bytes".into(),
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&hash_bytes);
    let backend_id: BackendId = backend_id_s.parse().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            6,
            rusqlite::types::Type::Text,
            "invalid backend_id".into(),
        )
    })?;

    Ok(SharePolicy {
        id,
        from_fingerprint: from_fp,
        to_fingerprint: to_fp,
        file_hash: blake3::Hash::from(arr),
        recrypt_key,
        wrapped_key,
        backend_id,
        created_at: created_at as u64,
    })
}

#[async_trait]
impl ShareStore for SqliteShareStore {
    async fn create(&self, policy: SharePolicy) -> ServerResult<ShareId> {
        let id = policy.id.clone();
        let id_for_call = id.clone();
        self.conn
            .call(move |c| {
                let tx = c.transaction()?;
                tx.execute(
                    "INSERT OR REPLACE INTO shares
                     (share_id, from_fp, to_fp, file_hash, recrypt_key, wrapped_key, backend_id, created_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    rusqlite::params![
                        id_for_call,
                        policy.from_fingerprint,
                        policy.to_fingerprint,
                        bs58::encode(policy.file_hash.as_bytes()).into_string(),
                        policy.recrypt_key,
                        policy.wrapped_key,
                        policy.backend_id.to_string(),
                        policy.created_at as i64,
                    ],
                )?;
                tx.commit()?;
                Ok::<_, rusqlite::Error>(())
            })
            .await
            .map_err(map_sqlite_err)?;
        Ok(id)
    }

    async fn get(&self, id: &ShareId) -> ServerResult<Option<SharePolicy>> {
        let id = id.clone();
        self.conn
            .call(move |c| {
                let mut stmt = c.prepare(
                    "SELECT share_id, from_fp, to_fp, file_hash, recrypt_key, wrapped_key, backend_id, created_at
                     FROM shares WHERE share_id = ?",
                )?;
                let mut rows = stmt.query([id])?;
                if let Some(row) = rows.next()? {
                    Ok::<_, rusqlite::Error>(Some(row_to_policy(row)?))
                } else {
                    Ok(None)
                }
            })
            .await
            .map_err(map_sqlite_err)
    }

    async fn delete(&self, id: &ShareId) -> ServerResult<()> {
        let id = id.clone();
        self.conn
            .call(move |c| {
                let tx = c.transaction()?;
                tx.execute("DELETE FROM shares WHERE share_id = ?", [id])?;
                tx.commit()?;
                Ok::<(), rusqlite::Error>(())
            })
            .await
            .map_err(map_sqlite_err)
    }

    async fn list_outgoing(&self, from: &PublicKeyFingerprint) -> ServerResult<Vec<SharePolicy>> {
        let from = from.clone();
        self.conn
            .call(move |c| {
                let mut stmt = c.prepare(
                    "SELECT share_id, from_fp, to_fp, file_hash, recrypt_key, wrapped_key, backend_id, created_at
                     FROM shares WHERE from_fp = ?",
                )?;
                let rows = stmt.query_map([from], row_to_policy)?;
                let mut out = Vec::new();
                for r in rows {
                    out.push(r?);
                }
                Ok::<_, rusqlite::Error>(out)
            })
            .await
            .map_err(map_sqlite_err)
    }

    async fn list_incoming(&self, to: &PublicKeyFingerprint) -> ServerResult<Vec<SharePolicy>> {
        let to = to.clone();
        self.conn
            .call(move |c| {
                let mut stmt = c.prepare(
                    "SELECT share_id, from_fp, to_fp, file_hash, recrypt_key, wrapped_key, backend_id, created_at
                     FROM shares WHERE to_fp = ?",
                )?;
                let rows = stmt.query_map([to], row_to_policy)?;
                let mut out = Vec::new();
                for r in rows {
                    out.push(r?);
                }
                Ok::<_, rusqlite::Error>(out)
            })
            .await
            .map_err(map_sqlite_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(id: &str, from: &str, to: &str) -> SharePolicy {
        SharePolicy {
            id: id.into(),
            from_fingerprint: from.into(),
            to_fingerprint: to.into(),
            file_hash: blake3::hash(id.as_bytes()),
            recrypt_key: vec![1, 2, 3, 4],
            wrapped_key: vec![5, 6, 7, 8],
            backend_id: BackendId::Mock,
            created_at: 42,
        }
    }

    #[tokio::test]
    async fn inmem_roundtrip() {
        let store = InMemoryShareStore::new();
        store.create(sample("a", "alice", "bob")).await.unwrap();
        store.create(sample("b", "alice", "carol")).await.unwrap();
        assert_eq!(
            store
                .get(&"a".into())
                .await
                .unwrap()
                .unwrap()
                .to_fingerprint,
            "bob"
        );
        assert_eq!(store.list_outgoing(&"alice".into()).await.unwrap().len(), 2);
        assert_eq!(store.list_incoming(&"bob".into()).await.unwrap().len(), 1);
        store.delete(&"a".into()).await.unwrap();
        assert!(store.get(&"a".into()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn sqlite_create_get_list() {
        let conn = Arc::new(tokio_rusqlite::Connection::open_in_memory().await.unwrap());
        let store = SqliteShareStore::new(conn).await.unwrap();

        store.create(sample("a", "alice", "bob")).await.unwrap();
        store.create(sample("b", "alice", "carol")).await.unwrap();

        let got = store.get(&"a".into()).await.unwrap().unwrap();
        assert_eq!(got.to_fingerprint, "bob");
        assert_eq!(got.recrypt_key, vec![1, 2, 3, 4]);

        let outgoing = store.list_outgoing(&"alice".into()).await.unwrap();
        assert_eq!(outgoing.len(), 2);

        let incoming = store.list_incoming(&"bob".into()).await.unwrap();
        assert_eq!(incoming.len(), 1);
        assert_eq!(incoming[0].id, "a");

        store.delete(&"a".into()).await.unwrap();
        assert!(store.get(&"a".into()).await.unwrap().is_none());
    }
}
