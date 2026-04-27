//! SQLite-backed [`KeyspaceStore`] using `tokio_rusqlite`.

use std::sync::Arc;

use async_trait::async_trait;

use crate::error::{AuthError, AuthResult};
use crate::fingerprint::PublicKeyFingerprint;
use crate::keyspace::{
    DecryptionPolicy, KeyspaceDoc, KeyspaceDocHash, KeyspaceId, MemberCapability,
};
use crate::keyspace_store::{KeyspaceStore, validate_chain, warn_phase_c_placeholders};

fn map_call_err(e: tokio_rusqlite::Error) -> AuthError {
    AuthError::Storage(format!("sqlite error: {e}"))
}

/// SQLite-backed keyspace store.
///
/// Holds an `Arc<tokio_rusqlite::Connection>` so that callers can share a
/// single connection (and therefore a single SQLite file) across multiple
/// stores. Schema is created via `init_schema`.
pub struct SqliteKeyspaceStore {
    conn: Arc<tokio_rusqlite::Connection>,
}

impl SqliteKeyspaceStore {
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

/// Serialize a `BTreeSet<MemberCapability>` to a comma-separated string.
fn caps_to_string(caps: &std::collections::BTreeSet<MemberCapability>) -> String {
    caps.iter()
        .map(|c| c.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

/// Serialize `DecryptionPolicy` to a JSON string.
fn policy_to_string(p: &DecryptionPolicy) -> String {
    serde_json::to_string(p).expect("DecryptionPolicy must serialize")
}

#[async_trait]
impl KeyspaceStore for SqliteKeyspaceStore {
    async fn put(&self, doc: KeyspaceDoc) -> AuthResult<KeyspaceDocHash> {
        warn_phase_c_placeholders(&doc);
        // Read existing versions so we can enforce the version-chain invariant
        // before writing. Same rules the in-memory store enforces.
        let existing = self.list_versions(&doc.id).await?;
        validate_chain(Some(&existing), &doc)?;

        let hash = doc.doc_hash();
        let hash_str = hash.to_string();
        let id_str = doc.id.to_string();
        let version = doc.version as i64;
        let name = doc.name.clone();
        let doc_bytes = serde_json::to_vec(&doc)
            .map_err(|e| AuthError::Storage(format!("json serialize: {e}")))?;
        let created_at = doc.created_at as i64;

        // Collect member rows to insert.
        let member_rows: Vec<(String, i64, String, String, String)> = doc
            .members
            .iter()
            .map(|m| {
                (
                    id_str.clone(),
                    version,
                    m.fingerprint.to_base58(),
                    caps_to_string(&m.capabilities),
                    policy_to_string(&m.decryption_policy),
                )
            })
            .collect();

        self.conn
            .call(move |c| {
                let tx = c.transaction()?;

                // Upsert keyspaces summary row. Only advance current_version
                // when the incoming version is strictly greater — defense in
                // depth against any caller that bypasses `validate_chain`.
                tx.execute(
                    "INSERT INTO keyspaces (id, current_version, current_hash, name)
                     VALUES (?, ?, ?, ?)
                     ON CONFLICT(id) DO UPDATE SET
                         current_version = excluded.current_version,
                         current_hash = excluded.current_hash,
                         name = excluded.name
                     WHERE excluded.current_version > keyspaces.current_version",
                    rusqlite::params![id_str, version, hash_str, name],
                )?;

                // Insert doc blob. Content-addressed by hash; the chain check
                // above guarantees we only reach here for fresh versions.
                tx.execute(
                    "INSERT INTO keyspace_docs
                     (hash, keyspace_id, version, doc_bytes, created_at)
                     VALUES (?, ?, ?, ?, ?)",
                    rusqlite::params![hash_str, id_str, version, doc_bytes, created_at],
                )?;

                for (ks_id, ver, fp, caps, policy) in &member_rows {
                    tx.execute(
                        "INSERT OR REPLACE INTO keyspace_members
                         (keyspace_id, version, fingerprint, capabilities, decryption_policy)
                         VALUES (?, ?, ?, ?, ?)",
                        rusqlite::params![ks_id, ver, fp, caps, policy],
                    )?;
                }

                tx.commit()?;
                Ok::<_, rusqlite::Error>(())
            })
            .await
            .map_err(map_call_err)?;

        Ok(hash)
    }

    async fn get_latest(&self, id: &KeyspaceId) -> AuthResult<Option<KeyspaceDoc>> {
        let id_str = id.to_string();
        self.conn
            .call(move |c| {
                // Find current hash from keyspaces table.
                let hash_str: Option<String> = c
                    .query_row(
                        "SELECT current_hash FROM keyspaces WHERE id = ?",
                        [&id_str],
                        |row| row.get(0),
                    )
                    .ok();

                let hash_str = match hash_str {
                    Some(h) => h,
                    None => return Ok::<_, rusqlite::Error>(None),
                };

                let doc_bytes: Vec<u8> = c.query_row(
                    "SELECT doc_bytes FROM keyspace_docs WHERE hash = ?",
                    [&hash_str],
                    |row| row.get(0),
                )?;

                let doc: KeyspaceDoc = serde_json::from_slice(&doc_bytes)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
                Ok(Some(doc))
            })
            .await
            .map_err(map_call_err)
    }

    async fn get_by_hash(&self, hash: &KeyspaceDocHash) -> AuthResult<Option<KeyspaceDoc>> {
        let hash_str = hash.to_string();
        self.conn
            .call(move |c| {
                let doc_bytes: Option<Vec<u8>> = c
                    .query_row(
                        "SELECT doc_bytes FROM keyspace_docs WHERE hash = ?",
                        [&hash_str],
                        |row| row.get(0),
                    )
                    .ok();

                match doc_bytes {
                    Some(bytes) => {
                        let doc: KeyspaceDoc = serde_json::from_slice(&bytes)
                            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
                        Ok::<_, rusqlite::Error>(Some(doc))
                    }
                    None => Ok(None),
                }
            })
            .await
            .map_err(map_call_err)
    }

    async fn list_versions(&self, id: &KeyspaceId) -> AuthResult<Vec<KeyspaceDocHash>> {
        let id_str = id.to_string();
        self.conn
            .call(move |c| {
                let mut stmt = c.prepare(
                    "SELECT hash FROM keyspace_docs
                     WHERE keyspace_id = ?
                     ORDER BY version ASC",
                )?;
                let hashes = stmt
                    .query_map([&id_str], |row| {
                        let h: String = row.get(0)?;
                        Ok(h)
                    })?
                    .filter_map(|r| r.ok())
                    .filter_map(|s| s.parse::<KeyspaceDocHash>().ok())
                    .collect();
                Ok::<_, rusqlite::Error>(hashes)
            })
            .await
            .map_err(map_call_err)
    }

    async fn list_by_member(&self, fp: &PublicKeyFingerprint) -> AuthResult<Vec<KeyspaceId>> {
        let fp_str = fp.to_base58();
        self.conn
            .call(move |c| {
                // Join against `keyspaces.current_version` rather than
                // computing MAX(version) per keyspace — the summary row is
                // already maintained by `put`, and this turns a correlated
                // subquery into a simple index lookup.
                let mut stmt = c.prepare(
                    "SELECT km.keyspace_id
                     FROM keyspace_members km
                     JOIN keyspaces k ON k.id = km.keyspace_id
                     WHERE km.fingerprint = ?
                       AND km.version = k.current_version",
                )?;
                let ids: rusqlite::Result<Vec<KeyspaceId>> = stmt
                    .query_map([&fp_str], |row| {
                        let id: String = row.get(0)?;
                        id.parse::<KeyspaceId>().map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                0,
                                rusqlite::types::Type::Text,
                                format!("keyspace_members.keyspace_id: {e}").into(),
                            )
                        })
                    })?
                    .collect();
                ids
            })
            .await
            .map_err(map_call_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyspace::{DecryptionPolicy, Member, MemberCapability, RotationMode};
    use std::collections::BTreeSet;
    use tempfile::tempdir;

    fn make_id(seed: u8) -> KeyspaceId {
        KeyspaceId::from_bytes([seed; 32])
    }

    fn make_fp(seed: u8) -> PublicKeyFingerprint {
        PublicKeyFingerprint::from_bytes([seed; 32])
    }

    fn make_member(seed: u8) -> Member {
        Member {
            fingerprint: make_fp(seed),
            capabilities: BTreeSet::from([MemberCapability::Read]),
            decryption_policy: DecryptionPolicy::Standalone,
            added_at: 0,
            added_by: make_fp(0),
        }
    }

    fn v0(id: KeyspaceId, members: Vec<Member>) -> KeyspaceDoc {
        KeyspaceDoc {
            id,
            version: 0,
            parent: None,
            mode: RotationMode::Create,
            name: "test".to_string(),
            root_pk: vec![],
            epoch_pre_pk: [0u8; 32],
            epoch: 0,
            members,
            quorum: 1,
            signatures: vec![],
            created_at: 1000,
        }
    }

    fn v_next(prev: &KeyspaceDoc, new_members: Vec<Member>) -> KeyspaceDoc {
        KeyspaceDoc {
            id: prev.id,
            version: prev.version + 1,
            parent: Some(prev.doc_hash()),
            mode: RotationMode::Additive,
            name: prev.name.clone(),
            root_pk: prev.root_pk.clone(),
            epoch_pre_pk: prev.epoch_pre_pk,
            epoch: prev.epoch + 1,
            members: new_members,
            quorum: prev.quorum,
            signatures: vec![],
            created_at: 1000,
        }
    }

    /// Return `(TempDir, Store)` so the test binding keeps the tempdir
    /// alive (and therefore cleans it up on drop) instead of leaking via
    /// `std::mem::forget`.
    async fn open_store() -> (tempfile::TempDir, SqliteKeyspaceStore) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db");
        let path_str = path.to_str().unwrap().to_string();
        let store = SqliteKeyspaceStore::open(&path_str).await.unwrap();
        (dir, store)
    }

    #[tokio::test]
    async fn put_v0_get_latest_returns_it() {
        let (_dir, store) = open_store().await;
        let id = make_id(1);
        let doc = v0(id, vec![make_member(10)]);
        let hash = store.put(doc.clone()).await.unwrap();

        let latest = store.get_latest(&id).await.unwrap().unwrap();
        assert_eq!(latest.version, 0);
        assert_eq!(latest.doc_hash(), hash);
    }

    #[tokio::test]
    async fn put_v0_then_v1_get_latest_returns_v1() {
        let (_dir, store) = open_store().await;
        let id = make_id(2);
        let doc0 = v0(id, vec![make_member(10)]);
        store.put(doc0.clone()).await.unwrap();

        let doc1 = v_next(&doc0, vec![make_member(10), make_member(11)]);
        let hash1 = store.put(doc1).await.unwrap();

        let latest = store.get_latest(&id).await.unwrap().unwrap();
        assert_eq!(latest.version, 1);
        assert_eq!(latest.doc_hash(), hash1);
    }

    #[tokio::test]
    async fn list_versions_returns_ordered_hashes() {
        let (_dir, store) = open_store().await;
        let id = make_id(3);
        let doc0 = v0(id, vec![make_member(10)]);
        let h0 = store.put(doc0.clone()).await.unwrap();
        let doc1 = v_next(&doc0, vec![make_member(10), make_member(11)]);
        let h1 = store.put(doc1.clone()).await.unwrap();
        let doc2 = v_next(&doc1, vec![make_member(12)]);
        let h2 = store.put(doc2).await.unwrap();

        let versions = store.list_versions(&id).await.unwrap();
        assert_eq!(versions, vec![h0, h1, h2]);
    }

    #[tokio::test]
    async fn list_by_member_finds_current_members() {
        let (_dir, store) = open_store().await;
        let id = make_id(4);
        let fp_old = make_fp(50);
        let fp_new = make_fp(51);

        let doc0 = v0(
            id,
            vec![Member {
                fingerprint: fp_old,
                capabilities: BTreeSet::from([MemberCapability::Read]),
                decryption_policy: DecryptionPolicy::Standalone,
                added_at: 0,
                added_by: make_fp(0),
            }],
        );
        store.put(doc0.clone()).await.unwrap();
        assert_eq!(store.list_by_member(&fp_old).await.unwrap().len(), 1);
        assert_eq!(store.list_by_member(&fp_new).await.unwrap().len(), 0);

        // v1 replaces fp_old with fp_new
        let doc1 = v_next(
            &doc0,
            vec![Member {
                fingerprint: fp_new,
                capabilities: BTreeSet::from([MemberCapability::Write]),
                decryption_policy: DecryptionPolicy::Standalone,
                added_at: 0,
                added_by: make_fp(0),
            }],
        );
        store.put(doc1).await.unwrap();

        assert_eq!(store.list_by_member(&fp_old).await.unwrap().len(), 0);
        assert_eq!(store.list_by_member(&fp_new).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn put_v1_without_v0_fails() {
        let (_dir, store) = open_store().await;
        let id = make_id(99);
        let fake_parent = KeyspaceDocHash::from_bytes([99; 32]);
        let doc1 = KeyspaceDoc {
            id,
            version: 1,
            parent: Some(fake_parent),
            mode: RotationMode::Additive,
            name: "test".to_string(),
            root_pk: vec![],
            epoch_pre_pk: [0u8; 32],
            epoch: 1,
            members: vec![make_member(10)],
            quorum: 1,
            signatures: vec![],
            created_at: 0,
        };
        let err = store.put(doc1).await.unwrap_err();
        assert!(
            matches!(err, AuthError::Storage(_)),
            "expected Storage error, got {err:?}"
        );
    }

    #[tokio::test]
    async fn put_duplicate_v0_fails() {
        let (_dir, store) = open_store().await;
        let id = make_id(100);
        let doc = v0(id, vec![make_member(10)]);
        store.put(doc.clone()).await.unwrap();
        let err = store.put(doc).await.unwrap_err();
        assert!(
            matches!(err, AuthError::AlreadyExists(_)),
            "expected AlreadyExists, got {err:?}"
        );
    }

    #[tokio::test]
    async fn get_by_hash_roundtrip() {
        let (_dir, store) = open_store().await;
        let id = make_id(5);
        let doc = v0(id, vec![make_member(10)]);
        let hash = store.put(doc.clone()).await.unwrap();

        let got = store.get_by_hash(&hash).await.unwrap().unwrap();
        assert_eq!(got.version, 0);
        assert_eq!(got.name, "test");

        // Non-existent hash
        let missing = KeyspaceDocHash::from_bytes([99; 32]);
        assert!(store.get_by_hash(&missing).await.unwrap().is_none());
    }
}
