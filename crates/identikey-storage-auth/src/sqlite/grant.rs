//! SQLite-backed [`GrantStore`] using `tokio_rusqlite`.

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;

use crate::error::{AuthError, AuthResult};
use crate::fingerprint::PublicKeyFingerprint;
use crate::grant::{AccessGrant, GrantId, GrantStore};
use crate::keyspace::Permission;

fn map_call_err(e: tokio_rusqlite::Error) -> AuthError {
    AuthError::Storage(format!("sqlite error: {e}"))
}

/// SQLite-backed grant store.
///
/// Holds an `Arc<tokio_rusqlite::Connection>` so that callers can share a
/// single connection (and therefore a single SQLite file) across multiple
/// stores. Schema is created via `init_schema`.
pub struct SqliteGrantStore {
    conn: Arc<tokio_rusqlite::Connection>,
}

impl SqliteGrantStore {
    /// Open or create a database file at `path` in WAL mode.
    pub async fn open(path: &str) -> AuthResult<Self> {
        let conn = tokio_rusqlite::Connection::open(path)
            .await
            .map_err(|e| AuthError::Storage(format!("sqlite error: {e}")))?;
        conn.call(|c| {
            c.pragma_update(None, "journal_mode", "WAL")?;
            Ok::<_, rusqlite::Error>(())
        })
        .await
        .map_err(map_call_err)?;
        conn.call(|c| {
            super::schema::init_schema(c)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
        })
        .await
        .map_err(map_call_err)?;
        Ok(Self {
            conn: Arc::new(conn),
        })
    }

    /// Wrap an existing shared connection. Caller is responsible for schema init.
    pub async fn new(conn: Arc<tokio_rusqlite::Connection>) -> AuthResult<Self> {
        Ok(Self { conn })
    }
}

/// Serialize a `BTreeSet<Permission>` to a comma-separated string.
fn caps_to_string(caps: &BTreeSet<Permission>) -> String {
    caps.iter()
        .map(|c| c.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

/// Deserialize a comma-separated capability string.
fn string_to_caps(s: &str) -> BTreeSet<Permission> {
    s.split(',')
        .filter(|t| !t.is_empty())
        .filter_map(Permission::parse)
        .collect()
}

/// Map a decode failure to a rusqlite conversion error.
///
/// We do NOT silently substitute zero bytes on decode failure: a corrupt
/// row containing `subject="not_base58"` must NOT become a grant whose
/// subject is the all-zeros fingerprint (which would act as a "wildcard"
/// identity against any `subject == expected_fp` check).
fn decode_err(field: &str, detail: impl std::fmt::Display) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        format!("grant.{field}: {detail}").into(),
    )
}

fn decode_fp_32(field: &str, s: &str) -> rusqlite::Result<[u8; 32]> {
    let bytes = bs58::decode(s)
        .into_vec()
        .map_err(|e| decode_err(field, e))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| decode_err(field, format!("expected 32 bytes, got {}", v.len())))
}

/// Build an `AccessGrant` from a rusqlite row.
///
/// Expected column order:
/// 0: grant_id, 1: keyspace_id, 2: keyspace_version, 3: subject,
/// 4: issuer, 5: permissions, 6: expires_at, 7: delegation_depth,
/// 8: parent_grant, 9: created_at, 10: doc_bytes
fn row_to_grant(row: &rusqlite::Row<'_>) -> rusqlite::Result<AccessGrant> {
    let keyspace_id_str: String = row.get(1)?;
    let keyspace_id = decode_fp_32("keyspace_id", &keyspace_id_str)?;

    let keyspace_version: i64 = row.get(2)?;
    let subject_str: String = row.get(3)?;
    let issuer_str: String = row.get(4)?;
    let caps_str: String = row.get(5)?;
    let expires_at: Option<i64> = row.get(6)?;
    let delegation_depth: i64 = row.get(7)?;
    let parent_grant_str: Option<String> = row.get(8)?;
    let created_at: i64 = row.get(9)?;

    let subject = PublicKeyFingerprint::from_base58(&subject_str)
        .ok_or_else(|| decode_err("subject", "invalid base58 fingerprint"))?;
    let issuer = PublicKeyFingerprint::from_base58(&issuer_str)
        .ok_or_else(|| decode_err("issuer", "invalid base58 fingerprint"))?;

    let parent_grant = match parent_grant_str {
        Some(s) => {
            let bytes = decode_fp_32("parent_grant", &s)?;
            Some(GrantId::from_bytes(bytes))
        }
        None => None,
    };

    Ok(AccessGrant {
        version: AccessGrant::VERSION,
        keyspace_id,
        keyspace_version: keyspace_version as u64,
        subject,
        issuer,
        permissions: string_to_caps(&caps_str),
        expires_at: expires_at.map(|t| t as u64),
        delegation_depth: delegation_depth as u8,
        parent_grant,
        created_at: created_at as u64,
        signature: None,
    })
}

#[async_trait]
impl GrantStore for SqliteGrantStore {
    async fn issue(&self, grant: AccessGrant) -> AuthResult<GrantId> {
        let id = GrantId::from_grant(&grant);
        let id_str = id.to_base58();
        let ks_id_str = bs58::encode(&grant.keyspace_id).into_string();
        let ks_version = grant.keyspace_version as i64;
        let subject_str = grant.subject.to_base58();
        let issuer_str = grant.issuer.to_base58();
        let caps_str = caps_to_string(&grant.permissions);
        let expires_at = grant.expires_at.map(|t| t as i64);
        let delegation_depth = grant.delegation_depth as i64;
        let parent_grant_str = grant.parent_grant.as_ref().map(|p| p.to_base58());
        let created_at = grant.created_at as i64;
        let doc_bytes = grant.canonical_bytes();

        let id_for_err = id_str.clone();
        self.conn
            .call(move |c| {
                let tx = c.transaction()?;
                tx.execute(
                    "INSERT INTO grants
                     (grant_id, keyspace_id, keyspace_version, subject, issuer,
                      permissions, expires_at, delegation_depth, parent_grant,
                      created_at, revoked, doc_bytes)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)",
                    rusqlite::params![
                        id_str,
                        ks_id_str,
                        ks_version,
                        subject_str,
                        issuer_str,
                        caps_str,
                        expires_at,
                        delegation_depth,
                        parent_grant_str,
                        created_at,
                        doc_bytes,
                    ],
                )?;
                tx.commit()?;
                Ok::<_, rusqlite::Error>(())
            })
            .await
            .map_err(|e| match &e {
                // PRIMARY KEY / UNIQUE violation on grant_id → AlreadyExists.
                tokio_rusqlite::Error::Error(rusqlite::Error::SqliteFailure(err, _))
                    if err.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    AuthError::AlreadyExists(format!("grant {id_for_err}"))
                }
                _ => map_call_err(e),
            })?;

        Ok(id)
    }

    async fn get(&self, id: &GrantId) -> AuthResult<Option<AccessGrant>> {
        let id_str = id.to_base58();
        self.conn
            .call(move |c| {
                let mut stmt = c.prepare(
                    "SELECT grant_id, keyspace_id, keyspace_version, subject, issuer,
                            permissions, expires_at, delegation_depth, parent_grant,
                            created_at, doc_bytes
                     FROM grants
                     WHERE grant_id = ? AND revoked = 0",
                )?;
                let mut rows = stmt.query([&id_str])?;
                if let Some(row) = rows.next()? {
                    Ok::<_, rusqlite::Error>(Some(row_to_grant(row)?))
                } else {
                    Ok(None)
                }
            })
            .await
            .map_err(map_call_err)
    }

    async fn revoke(&self, id: &GrantId) -> AuthResult<()> {
        let id_str = id.to_base58();
        self.conn
            .call(move |c| {
                c.execute(
                    "UPDATE grants SET revoked = 1 WHERE grant_id = ?",
                    [&id_str],
                )?;
                Ok::<_, rusqlite::Error>(())
            })
            .await
            .map_err(map_call_err)
    }

    async fn list_by_subject(
        &self,
        subject: &PublicKeyFingerprint,
    ) -> AuthResult<Vec<AccessGrant>> {
        let subject_str = subject.to_base58();
        self.conn
            .call(move |c| {
                let mut stmt = c.prepare(
                    "SELECT grant_id, keyspace_id, keyspace_version, subject, issuer,
                            permissions, expires_at, delegation_depth, parent_grant,
                            created_at, doc_bytes
                     FROM grants
                     WHERE subject = ? AND revoked = 0",
                )?;
                let grants = stmt
                    .query_map([&subject_str], |row| row_to_grant(row))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok::<_, rusqlite::Error>(grants)
            })
            .await
            .map_err(map_call_err)
    }

    async fn list_by_keyspace(&self, keyspace_id: &[u8; 32]) -> AuthResult<Vec<AccessGrant>> {
        let ks_id_str = bs58::encode(keyspace_id).into_string();
        self.conn
            .call(move |c| {
                let mut stmt = c.prepare(
                    "SELECT grant_id, keyspace_id, keyspace_version, subject, issuer,
                            permissions, expires_at, delegation_depth, parent_grant,
                            created_at, doc_bytes
                     FROM grants
                     WHERE keyspace_id = ? AND revoked = 0",
                )?;
                let grants = stmt
                    .query_map([&ks_id_str], |row| row_to_grant(row))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok::<_, rusqlite::Error>(grants)
            })
            .await
            .map_err(map_call_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn make_fp(seed: u8) -> PublicKeyFingerprint {
        PublicKeyFingerprint::from_bytes([seed; 32])
    }

    fn sample_grant(seed: u8) -> AccessGrant {
        AccessGrant {
            version: AccessGrant::VERSION,
            keyspace_id: [seed; 32],
            keyspace_version: 0,
            subject: make_fp(seed.wrapping_add(1)),
            issuer: make_fp(seed),
            permissions: BTreeSet::from([Permission::Read]),
            expires_at: None,
            delegation_depth: 0,
            parent_grant: None,
            created_at: 1000,
            signature: None,
        }
    }

    /// Return `(TempDir, Store)` so the test binding keeps the tempdir
    /// alive (and therefore cleans it up on drop). Leaking via
    /// `std::mem::forget` would accumulate on-disk garbage per test run.
    async fn open_store() -> (tempfile::TempDir, SqliteGrantStore) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db");
        let path_str = path.to_str().unwrap().to_string();
        let store = SqliteGrantStore::open(&path_str).await.unwrap();
        (dir, store)
    }

    #[tokio::test]
    async fn issue_get_revoke_roundtrip() {
        let (_dir, store) = open_store().await;
        let grant = sample_grant(1);
        let id = store.issue(grant.clone()).await.unwrap();

        let got = store.get(&id).await.unwrap().unwrap();
        assert_eq!(got.keyspace_id, grant.keyspace_id);
        assert_eq!(got.subject, grant.subject);
        assert_eq!(got.issuer, grant.issuer);

        store.revoke(&id).await.unwrap();
        assert!(store.get(&id).await.unwrap().is_none());

        // Idempotent revoke
        store.revoke(&id).await.unwrap();
    }

    #[tokio::test]
    async fn list_by_subject_filters_revoked() {
        let (_dir, store) = open_store().await;
        let g1 = sample_grant(1);
        let subject = g1.subject;
        let id1 = store.issue(g1).await.unwrap();

        let g2 = sample_grant(2);
        store.issue(g2).await.unwrap();

        let by_subject = store.list_by_subject(&subject).await.unwrap();
        assert_eq!(by_subject.len(), 1);

        store.revoke(&id1).await.unwrap();
        let by_subject = store.list_by_subject(&subject).await.unwrap();
        assert_eq!(by_subject.len(), 0);
    }

    #[tokio::test]
    async fn list_by_keyspace_filters_revoked() {
        let (_dir, store) = open_store().await;
        let g1 = sample_grant(1);
        let keyspace_id = g1.keyspace_id;
        let id1 = store.issue(g1).await.unwrap();

        let by_ks = store.list_by_keyspace(&keyspace_id).await.unwrap();
        assert_eq!(by_ks.len(), 1);
        assert_eq!(by_ks[0].keyspace_id, keyspace_id);

        store.revoke(&id1).await.unwrap();
        let by_ks = store.list_by_keyspace(&keyspace_id).await.unwrap();
        assert_eq!(by_ks.len(), 0);
    }
}
