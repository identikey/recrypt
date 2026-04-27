//! Keyspace store: versioned storage for [`KeyspaceDoc`] with version-chain validation.

use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::error::{AuthError, AuthResult};
use crate::fingerprint::PublicKeyFingerprint;
use crate::keyspace::{KeyspaceDoc, KeyspaceDocHash, KeyspaceId};

// ---------------------------------------------------------------------------
// Phase-C placeholder diagnostics
// ---------------------------------------------------------------------------

/// Emit a tracing warning when a `KeyspaceDoc` is being stored with the
/// Phase-B-only placeholder fields in their default / empty state.
///
/// These fields (`root_pk`, `epoch_pre_pk`, `signatures`) will carry
/// meaningful crypto material once Phase C ships. Keyspaces persisted
/// today with empty values will require a migration at that point; we
/// log on every `put` so the operator sees the drift accumulating.
pub(crate) fn warn_phase_c_placeholders(doc: &KeyspaceDoc) {
    if doc.root_pk.is_empty() || doc.epoch_pre_pk == [0u8; 32] || doc.signatures.is_empty() {
        tracing::warn!(
            keyspace_id = %doc.id,
            version = doc.version,
            "storing keyspace with Phase-C placeholder fields (root_pk/epoch_pre_pk/signatures); \
             migration will be required once Phase C lands",
        );
    }
}

// ---------------------------------------------------------------------------
// Chain validation (shared across backends)
// ---------------------------------------------------------------------------

/// Validate a candidate `doc` against the existing version history.
///
/// Rules enforced:
/// - v0 must have no `parent` and the keyspace must not already have a v0.
/// - v>0 must declare a `parent` matching the last stored hash, and its
///   `version` must be exactly `previous_version + 1`.
///
/// All backends MUST call this before persisting a doc. Returns
/// `AuthError::AlreadyExists` for duplicate v0, `AuthError::Storage`
/// for any other chain violation.
pub fn validate_chain(
    existing_versions: Option<&[KeyspaceDocHash]>,
    doc: &KeyspaceDoc,
) -> AuthResult<()> {
    if doc.version == 0 {
        if doc.parent.is_some() {
            return Err(AuthError::Storage(
                "v0 document must not have a parent".to_string(),
            ));
        }
        if existing_versions.map(|v| !v.is_empty()).unwrap_or(false) {
            return Err(AuthError::AlreadyExists(format!(
                "keyspace {} v0 already exists",
                doc.id
            )));
        }
        return Ok(());
    }

    let versions = existing_versions.ok_or_else(|| {
        AuthError::Storage(format!(
            "broken chain: keyspace {} has no v0 but received v{}",
            doc.id, doc.version
        ))
    })?;

    let expected_version = versions.len() as u64;
    if doc.version != expected_version {
        return Err(AuthError::Storage(format!(
            "broken chain: expected v{} for keyspace {}, got v{}",
            expected_version, doc.id, doc.version
        )));
    }

    let prev_hash = versions.last().ok_or_else(|| {
        AuthError::Storage(format!(
            "broken chain: keyspace {} has no v0 but received v{}",
            doc.id, doc.version
        ))
    })?;

    let declared_parent = doc.parent.as_ref().ok_or_else(|| {
        AuthError::Storage(format!(
            "broken chain: v{} for keyspace {} is missing parent",
            doc.version, doc.id
        ))
    })?;

    if declared_parent != prev_hash {
        return Err(AuthError::Storage(format!(
            "broken chain: parent mismatch for keyspace {} v{}",
            doc.id, doc.version
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Async storage trait for versioned [`KeyspaceDoc`] records.
#[async_trait]
pub trait KeyspaceStore: Send + Sync {
    /// Store a new keyspace version. Validates version chain (parent must match).
    async fn put(&self, doc: KeyspaceDoc) -> AuthResult<KeyspaceDocHash>;

    /// Get the latest version of a keyspace.
    async fn get_latest(&self, id: &KeyspaceId) -> AuthResult<Option<KeyspaceDoc>>;

    /// Get a specific version by its document hash.
    async fn get_by_hash(&self, hash: &KeyspaceDocHash) -> AuthResult<Option<KeyspaceDoc>>;

    /// List all version hashes for a keyspace, ordered by version number.
    async fn list_versions(&self, id: &KeyspaceId) -> AuthResult<Vec<KeyspaceDocHash>>;

    /// Find all keyspaces where a fingerprint is a current member.
    async fn list_by_member(&self, fp: &PublicKeyFingerprint) -> AuthResult<Vec<KeyspaceId>>;
}

// ---------------------------------------------------------------------------
// In-memory implementation
// ---------------------------------------------------------------------------

#[derive(Default)]
struct KeyspaceStoreInner {
    /// All docs indexed by their content hash.
    by_hash: HashMap<KeyspaceDocHash, KeyspaceDoc>,
    /// The hash of the latest version for each keyspace.
    latest: HashMap<KeyspaceId, KeyspaceDocHash>,
    /// Ordered list of version hashes for each keyspace (index == version number).
    versions: HashMap<KeyspaceId, Vec<KeyspaceDocHash>>,
    /// Reverse index: fingerprint → set of keyspaces where it is a current member.
    member_index: HashMap<PublicKeyFingerprint, HashSet<KeyspaceId>>,
}

/// In-memory implementation of [`KeyspaceStore`].
#[derive(Default)]
pub struct InMemoryKeyspaceStore {
    inner: RwLock<KeyspaceStoreInner>,
}

impl InMemoryKeyspaceStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl KeyspaceStore for InMemoryKeyspaceStore {
    async fn put(&self, doc: KeyspaceDoc) -> AuthResult<KeyspaceDocHash> {
        warn_phase_c_placeholders(&doc);
        let mut guard = self.inner.write().await;

        let existing_versions = guard.versions.get(&doc.id).map(|v| v.as_slice());
        validate_chain(existing_versions, &doc)?;

        let hash = doc.doc_hash();

        // Rebuild the member_index entry for this keyspace from scratch using
        // the new latest document. This is O(members) and avoids any stale
        // entries from prior revoke/re-add cycles.
        let old_members: Vec<PublicKeyFingerprint> = guard
            .latest
            .get(&doc.id)
            .and_then(|h| guard.by_hash.get(h))
            .map(|old| old.members.iter().map(|m| m.fingerprint).collect())
            .unwrap_or_default();
        for fp in old_members {
            if let Some(set) = guard.member_index.get_mut(&fp) {
                set.remove(&doc.id);
            }
        }
        for m in &doc.members {
            guard
                .member_index
                .entry(m.fingerprint)
                .or_default()
                .insert(doc.id);
        }

        guard.latest.insert(doc.id, hash);
        guard.versions.entry(doc.id).or_default().push(hash);
        guard.by_hash.insert(hash, doc);

        Ok(hash)
    }

    async fn get_latest(&self, id: &KeyspaceId) -> AuthResult<Option<KeyspaceDoc>> {
        let guard = self.inner.read().await;
        let hash = match guard.latest.get(id) {
            Some(h) => *h,
            None => return Ok(None),
        };
        Ok(guard.by_hash.get(&hash).cloned())
    }

    async fn get_by_hash(&self, hash: &KeyspaceDocHash) -> AuthResult<Option<KeyspaceDoc>> {
        let guard = self.inner.read().await;
        Ok(guard.by_hash.get(hash).cloned())
    }

    async fn list_versions(&self, id: &KeyspaceId) -> AuthResult<Vec<KeyspaceDocHash>> {
        let guard = self.inner.read().await;
        Ok(guard.versions.get(id).cloned().unwrap_or_default())
    }

    async fn list_by_member(&self, fp: &PublicKeyFingerprint) -> AuthResult<Vec<KeyspaceId>> {
        let guard = self.inner.read().await;
        Ok(guard
            .member_index
            .get(fp)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyspace::{DecryptionPolicy, Member, MemberCapability, RotationMode};
    use std::collections::BTreeSet;

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
            created_at: 0,
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
            created_at: 0,
        }
    }

    #[tokio::test]
    async fn put_v0_get_latest_returns_it() {
        let store = InMemoryKeyspaceStore::new();
        let id = make_id(1);
        let doc = v0(id, vec![make_member(10)]);
        let hash = store.put(doc.clone()).await.unwrap();

        let latest = store.get_latest(&id).await.unwrap().unwrap();
        assert_eq!(latest.version, 0);
        assert_eq!(latest.doc_hash(), hash);
    }

    #[tokio::test]
    async fn put_v0_then_v1_get_latest_returns_v1() {
        let store = InMemoryKeyspaceStore::new();
        let id = make_id(2);
        let doc0 = v0(id, vec![make_member(10)]);
        store.put(doc0.clone()).await.unwrap();

        let doc1 = v_next(&doc0, vec![make_member(10), make_member(11)]);
        let hash1 = store.put(doc1.clone()).await.unwrap();

        let latest = store.get_latest(&id).await.unwrap().unwrap();
        assert_eq!(latest.version, 1);
        assert_eq!(latest.doc_hash(), hash1);
    }

    #[tokio::test]
    async fn put_v1_without_v0_fails() {
        let store = InMemoryKeyspaceStore::new();
        let id = make_id(3);
        // Craft a v1 doc without ever storing v0.
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
    async fn list_by_member_finds_right_keyspaces() {
        let store = InMemoryKeyspaceStore::new();
        let id_a = make_id(10);
        let id_b = make_id(11);
        let fp_shared = make_fp(20);
        let fp_exclusive = make_fp(21);

        let member_shared = Member {
            fingerprint: fp_shared,
            capabilities: BTreeSet::from([MemberCapability::Read]),
            decryption_policy: DecryptionPolicy::Standalone,
            added_at: 0,
            added_by: make_fp(0),
        };
        let member_exclusive = Member {
            fingerprint: fp_exclusive,
            capabilities: BTreeSet::from([MemberCapability::Write]),
            decryption_policy: DecryptionPolicy::Standalone,
            added_at: 0,
            added_by: make_fp(0),
        };

        store
            .put(v0(
                id_a,
                vec![member_shared.clone(), member_exclusive.clone()],
            ))
            .await
            .unwrap();
        store
            .put(v0(id_b, vec![member_shared.clone()]))
            .await
            .unwrap();

        let mut ks_shared = store.list_by_member(&fp_shared).await.unwrap();
        ks_shared.sort_by_key(|k| *k.as_bytes());
        assert_eq!(ks_shared.len(), 2);

        let ks_exclusive = store.list_by_member(&fp_exclusive).await.unwrap();
        assert_eq!(ks_exclusive.len(), 1);
        assert_eq!(ks_exclusive[0], id_a);
    }

    #[tokio::test]
    async fn list_versions_returns_ordered_hashes() {
        let store = InMemoryKeyspaceStore::new();
        let id = make_id(30);
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
    async fn member_index_handles_revoke_readd_cycle() {
        // v0 = {A, B}, v1 = {A} (B removed), v2 = {A, B} (B re-added).
        // list_by_member(B) at v2 must return the keyspace.
        let store = InMemoryKeyspaceStore::new();
        let id = make_id(60);
        let fp_a = make_fp(70);
        let fp_b = make_fp(71);

        let m_a = Member {
            fingerprint: fp_a,
            capabilities: BTreeSet::from([MemberCapability::Read]),
            decryption_policy: DecryptionPolicy::Standalone,
            added_at: 0,
            added_by: make_fp(0),
        };
        let m_b = Member {
            fingerprint: fp_b,
            capabilities: BTreeSet::from([MemberCapability::Read]),
            decryption_policy: DecryptionPolicy::Standalone,
            added_at: 0,
            added_by: make_fp(0),
        };

        let doc0 = v0(id, vec![m_a.clone(), m_b.clone()]);
        store.put(doc0.clone()).await.unwrap();
        let doc1 = v_next(&doc0, vec![m_a.clone()]);
        store.put(doc1.clone()).await.unwrap();
        // At v1, B is gone.
        assert_eq!(store.list_by_member(&fp_b).await.unwrap().len(), 0);

        let doc2 = v_next(&doc1, vec![m_a.clone(), m_b.clone()]);
        store.put(doc2).await.unwrap();

        // At v2, B must reappear.
        let ks = store.list_by_member(&fp_b).await.unwrap();
        assert_eq!(ks.len(), 1, "B should be a member again at v2");
        assert_eq!(ks[0], id);
    }

    #[tokio::test]
    async fn member_index_updated_on_version_change() {
        let store = InMemoryKeyspaceStore::new();
        let id = make_id(40);
        let fp_old = make_fp(50);
        let fp_new = make_fp(51);

        // v0 has fp_old only.
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

        // v1 replaces fp_old with fp_new.
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
}
