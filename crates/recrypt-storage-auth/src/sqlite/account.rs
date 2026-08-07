//! SQLite-backed [`AccountStore`] using `tokio_rusqlite`.

use std::sync::Arc;

use async_trait::async_trait;

use crate::account::{AccountRecord, AccountStore};
use crate::error::{AuthError, AuthResult};
use crate::fingerprint::PublicKeyFingerprint;

/// SQLite-backed account store.
///
/// Holds an `Arc<tokio_rusqlite::Connection>` so that callers can share a
/// single connection (and therefore a single SQLite file) across multiple
/// stores. Schema is created on construction.
pub struct SqliteAccountStore {
    conn: Arc<tokio_rusqlite::Connection>,
}

impl SqliteAccountStore {
    /// Open or create a database file at `path` in WAL mode.
    pub async fn open(path: &str) -> AuthResult<Self> {
        let conn = tokio_rusqlite::Connection::open(path)
            .await
            .map_err(map_rusqlite_err)?;
        conn.call(|c| {
            c.pragma_update(None, "journal_mode", "WAL")?;
            Ok::<_, rusqlite::Error>(())
        })
        .await
        .map_err(map_call_err)?;
        Self::new(Arc::new(conn)).await
    }

    /// Wrap an existing shared connection. Initializes the schema.
    pub async fn new(conn: Arc<tokio_rusqlite::Connection>) -> AuthResult<Self> {
        conn.call(|c| {
            c.execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS accounts (
                    fingerprint TEXT PRIMARY KEY,
                    ed25519_pk  BLOB NOT NULL,
                    ml_dsa_pk   BLOB NOT NULL,
                    created_at  INTEGER NOT NULL
                );
                "#,
            )?;
            Ok::<_, rusqlite::Error>(())
        })
        .await
        .map_err(map_call_err)?;
        Ok(Self { conn })
    }
}

fn map_rusqlite_err(e: rusqlite::Error) -> AuthError {
    AuthError::Storage(format!("sqlite error: {e}"))
}

fn map_call_err(e: tokio_rusqlite::Error) -> AuthError {
    AuthError::Storage(format!("sqlite error: {e}"))
}

fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<AccountRecord> {
    Ok(AccountRecord {
        fingerprint: row.get(0)?,
        ed25519_pk: row.get(1)?,
        ml_dsa_pk: row.get(2)?,
        created_at: row.get::<_, i64>(3)? as u64,
    })
}

#[async_trait]
impl AccountStore for SqliteAccountStore {
    async fn register(&self, record: AccountRecord) -> AuthResult<()> {
        self.conn
            .call(move |c| {
                let tx = c.transaction()?;
                tx.execute(
                    "INSERT OR REPLACE INTO accounts
                     (fingerprint, ed25519_pk, ml_dsa_pk, created_at)
                     VALUES (?, ?, ?, ?)",
                    rusqlite::params![
                        record.fingerprint,
                        record.ed25519_pk,
                        record.ml_dsa_pk,
                        record.created_at as i64,
                    ],
                )?;
                tx.commit()?;
                Ok::<_, rusqlite::Error>(())
            })
            .await
            .map_err(map_call_err)
    }

    async fn get(&self, fingerprint: &PublicKeyFingerprint) -> AuthResult<Option<AccountRecord>> {
        let fp = fingerprint.to_base58();
        self.conn
            .call(move |c| {
                let mut stmt = c.prepare(
                    "SELECT fingerprint, ed25519_pk, ml_dsa_pk, created_at
                     FROM accounts WHERE fingerprint = ?",
                )?;
                let mut rows = stmt.query([fp])?;
                if let Some(row) = rows.next()? {
                    Ok::<_, rusqlite::Error>(Some(row_to_record(row)?))
                } else {
                    Ok(None)
                }
            })
            .await
            .map_err(map_call_err)
    }

    async fn exists(&self, fingerprint: &PublicKeyFingerprint) -> AuthResult<bool> {
        let fp = fingerprint.to_base58();
        self.conn
            .call(move |c| {
                let mut stmt = c.prepare("SELECT 1 FROM accounts WHERE fingerprint = ? LIMIT 1")?;
                let mut rows = stmt.query([fp])?;
                Ok::<_, rusqlite::Error>(rows.next()?.is_some())
            })
            .await
            .map_err(map_call_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn record(seed: u8) -> AccountRecord {
        let pk = vec![seed; 32];
        let fp = PublicKeyFingerprint::from_public_key(&pk);
        AccountRecord {
            fingerprint: fp.to_base58(),
            ed25519_pk: pk,
            ml_dsa_pk: vec![seed; 64],
            created_at: 100,
        }
    }

    #[tokio::test]
    async fn sqlite_account_roundtrip_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("recrypt.db");
        let store = SqliteAccountStore::open(path.to_str().unwrap())
            .await
            .unwrap();

        let r = record(9);
        let fp = PublicKeyFingerprint::from_public_key(&r.ed25519_pk);

        assert!(!store.exists(&fp).await.unwrap());
        store.register(r.clone()).await.unwrap();
        assert!(store.exists(&fp).await.unwrap());
        let got = store.get(&fp).await.unwrap().unwrap();
        assert_eq!(got.fingerprint, r.fingerprint);
        assert_eq!(got.ed25519_pk, r.ed25519_pk);
        assert_eq!(got.ml_dsa_pk, r.ml_dsa_pk);
        assert_eq!(got.created_at, r.created_at);
    }
}
