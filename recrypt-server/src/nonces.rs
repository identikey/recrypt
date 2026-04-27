//! Nonce replay-prevention store trait and implementations.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::error::{ServerError, ServerResult};

/// Validate nonce format `{unix_ms}:{uuid}` and confirm it falls within
/// `window_secs` of now (with 1-minute future skew tolerance).
pub fn validate_format(nonce: &str, window_secs: u64) -> bool {
    let parts: Vec<&str> = nonce.split(':').collect();
    if parts.len() != 2 {
        return false;
    }
    let ts_ms: u64 = match parts[0].parse() {
        Ok(t) => t,
        Err(_) => return false,
    };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let window_ms = window_secs * 1000;
    if now_ms > ts_ms + window_ms {
        return false;
    }
    if ts_ms > now_ms + 60_000 {
        return false;
    }
    true
}

/// Extract the unix-second expiry encoded in the `{unix_ms}:{uuid}` nonce,
/// extended by `window_secs`. Returns 0 on parse failure.
pub fn nonce_expiry_secs(nonce: &str, window_secs: u64) -> u64 {
    nonce
        .split(':')
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .map(|ts_ms| ts_ms / 1000 + window_secs)
        .unwrap_or(0)
}

#[async_trait]
pub trait NonceStore: Send + Sync {
    /// Returns true if this is the first use, false if already seen (replay).
    async fn mark_used(&self, nonce: &str, expires_at: u64) -> ServerResult<bool>;
    /// Drop expired entries; returns the number removed.
    async fn gc_expired(&self) -> ServerResult<usize>;
}

/// In-memory nonce store. Entries are dropped lazily by `gc_expired`.
#[derive(Default)]
pub struct InMemoryNonceStore {
    inner: RwLock<HashMap<String, u64>>,
}

impl InMemoryNonceStore {
    pub fn new() -> Self {
        Self::default()
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[async_trait]
impl NonceStore for InMemoryNonceStore {
    async fn mark_used(&self, nonce: &str, expires_at: u64) -> ServerResult<bool> {
        let mut guard = self.inner.write().await;
        if guard.contains_key(nonce) {
            return Ok(false);
        }
        guard.insert(nonce.to_string(), expires_at);
        Ok(true)
    }

    async fn gc_expired(&self) -> ServerResult<usize> {
        let now = now_secs();
        let mut guard = self.inner.write().await;
        let before = guard.len();
        guard.retain(|_, expires| *expires >= now);
        Ok(before - guard.len())
    }
}

// ---------------------------------------------------------------------------
// SQLite implementation
// ---------------------------------------------------------------------------

pub struct SqliteNonceStore {
    conn: Arc<tokio_rusqlite::Connection>,
}

impl SqliteNonceStore {
    pub async fn new(conn: Arc<tokio_rusqlite::Connection>) -> ServerResult<Self> {
        conn.call(|c| {
            c.execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS nonces (
                    nonce      TEXT PRIMARY KEY,
                    expires_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_nonces_expires ON nonces(expires_at);
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

#[async_trait]
impl NonceStore for SqliteNonceStore {
    async fn mark_used(&self, nonce: &str, expires_at: u64) -> ServerResult<bool> {
        let nonce = nonce.to_string();
        self.conn
            .call(move |c| {
                // INSERT OR IGNORE is atomic at the statement level. changes()
                // returns 1 on first insert, 0 on a primary-key conflict (replay).
                c.execute(
                    "INSERT OR IGNORE INTO nonces (nonce, expires_at) VALUES (?, ?)",
                    rusqlite::params![nonce, expires_at as i64],
                )?;
                Ok::<_, rusqlite::Error>(c.changes() == 1)
            })
            .await
            .map_err(map_sqlite_err)
    }

    async fn gc_expired(&self) -> ServerResult<usize> {
        let now = now_secs() as i64;
        self.conn
            .call(move |c| {
                let n = c.execute("DELETE FROM nonces WHERE expires_at < ?", [now])?;
                Ok::<_, rusqlite::Error>(n)
            })
            .await
            .map_err(map_sqlite_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn inmem_replay_detected() {
        let s = InMemoryNonceStore::new();
        assert!(s.mark_used("n1", now_secs() + 60).await.unwrap());
        assert!(!s.mark_used("n1", now_secs() + 60).await.unwrap());
    }

    #[tokio::test]
    async fn sqlite_replay_detected_and_gc() {
        let conn = Arc::new(tokio_rusqlite::Connection::open_in_memory().await.unwrap());
        let s = SqliteNonceStore::new(conn).await.unwrap();

        let future = now_secs() + 600;
        assert!(s.mark_used("n1", future).await.unwrap());
        assert!(
            !s.mark_used("n1", future).await.unwrap(),
            "replay must return false"
        );

        // Insert an expired entry and gc it.
        assert!(s.mark_used("old", now_secs() - 10).await.unwrap());
        let removed = s.gc_expired().await.unwrap();
        assert!(removed >= 1);
        // Re-inserting "old" should work again because it was gc'd.
        assert!(s.mark_used("old", now_secs() + 60).await.unwrap());
    }
}
