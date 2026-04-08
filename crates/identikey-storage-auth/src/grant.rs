//! Access grants: records of delegated access

use std::collections::HashMap;
use std::fmt;

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::capability::Operation;
use crate::error::{AuthError, AuthResult};
use crate::fingerprint::PublicKeyFingerprint;

/// Content-addressed identifier for an [`AccessGrant`].
///
/// Computed as a Blake3 hash over the grant's canonical byte encoding.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct GrantId([u8; 32]);

impl GrantId {
    /// Derive a `GrantId` by hashing the canonical byte encoding of `grant`.
    pub fn from_grant(grant: &AccessGrant) -> Self {
        Self(*blake3::hash(&grant.canonical_bytes()).as_bytes())
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(&self.0).into_string()
    }
}

impl fmt::Debug for GrantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GrantId({})", self.to_base58())
    }
}

/// A record of access granted from owner to grantee
#[derive(Clone, Debug)]
pub struct AccessGrant {
    /// File being shared
    pub file_hash: blake3::Hash,
    /// Who owns the file
    pub owner: PublicKeyFingerprint,
    /// Who has been granted access
    pub grantee: PublicKeyFingerprint,
    /// What operations are permitted
    pub operations: Vec<Operation>,
    /// When the grant expires (0 = never)
    pub expires_at: u64,
    /// When the grant was created (Unix timestamp)
    pub created_at: u64,
}

impl AccessGrant {
    pub fn new(
        file_hash: blake3::Hash,
        owner: PublicKeyFingerprint,
        grantee: PublicKeyFingerprint,
        operations: Vec<Operation>,
        expires_at: Option<u64>,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            file_hash,
            owner,
            grantee,
            operations,
            expires_at: expires_at.unwrap_or(0),
            created_at: now,
        }
    }

    /// Check if the grant has expired
    pub fn is_expired(&self) -> bool {
        if self.expires_at == 0 {
            return false;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now > self.expires_at
    }

    /// Check if a specific operation is permitted
    pub fn permits(&self, op: Operation) -> bool {
        self.operations.contains(&op)
    }

    /// Canonical byte encoding used for content-addressing.
    ///
    /// Note: `created_at` is intentionally included so that distinct issuances
    /// produce distinct IDs even if all other fields match.
    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend(self.file_hash.as_bytes());
        out.extend(self.owner.as_bytes());
        out.extend(self.grantee.as_bytes());
        let mut ops: Vec<&'static str> = self.operations.iter().map(|o| o.as_str()).collect();
        ops.sort();
        for op in ops {
            out.extend(op.as_bytes());
            out.push(0);
        }
        out.extend(self.expires_at.to_le_bytes());
        out.extend(self.created_at.to_le_bytes());
        out
    }
}

/// Async storage trait for [`AccessGrant`] records.
#[async_trait]
pub trait GrantStore: Send + Sync {
    /// Persist a new grant and return its content-addressed id.
    async fn issue(&self, grant: AccessGrant) -> AuthResult<GrantId>;

    /// Look up a grant by id.
    async fn get(&self, id: &GrantId) -> AuthResult<Option<AccessGrant>>;

    /// Revoke (delete) a grant by id. Idempotent: revoking a missing id is Ok.
    async fn revoke(&self, id: &GrantId) -> AuthResult<()>;

    /// List grants where `subject` is the grantee.
    async fn list_by_subject(
        &self,
        subject: &PublicKeyFingerprint,
    ) -> AuthResult<Vec<AccessGrant>>;

    /// List grants for a given resource (file) identified by its content hash.
    async fn list_by_resource(&self, resource_hash: &str) -> AuthResult<Vec<AccessGrant>>;
}

/// In-memory implementation of [`GrantStore`].
#[derive(Default)]
pub struct InMemoryGrantStore {
    inner: RwLock<HashMap<GrantId, AccessGrant>>,
}

impl InMemoryGrantStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl GrantStore for InMemoryGrantStore {
    async fn issue(&self, grant: AccessGrant) -> AuthResult<GrantId> {
        let id = GrantId::from_grant(&grant);
        let mut guard = self.inner.write().await;
        if guard.contains_key(&id) {
            return Err(AuthError::Storage(format!(
                "grant already exists: {}",
                id.to_base58()
            )));
        }
        guard.insert(id, grant);
        Ok(id)
    }

    async fn get(&self, id: &GrantId) -> AuthResult<Option<AccessGrant>> {
        let guard = self.inner.read().await;
        Ok(guard.get(id).cloned())
    }

    async fn revoke(&self, id: &GrantId) -> AuthResult<()> {
        let mut guard = self.inner.write().await;
        guard.remove(id);
        Ok(())
    }

    async fn list_by_subject(
        &self,
        subject: &PublicKeyFingerprint,
    ) -> AuthResult<Vec<AccessGrant>> {
        let guard = self.inner.read().await;
        Ok(guard
            .values()
            .filter(|g| &g.grantee == subject)
            .cloned()
            .collect())
    }

    async fn list_by_resource(&self, resource_hash: &str) -> AuthResult<Vec<AccessGrant>> {
        let guard = self.inner.read().await;
        Ok(guard
            .values()
            .filter(|g| g.file_hash.to_hex().to_string() == resource_hash)
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_grant(seed: u8) -> AccessGrant {
        AccessGrant::new(
            blake3::hash(&[seed; 4]),
            PublicKeyFingerprint::from_bytes([seed; 32]),
            PublicKeyFingerprint::from_bytes([seed.wrapping_add(1); 32]),
            vec![Operation::Read],
            None,
        )
    }

    #[tokio::test]
    async fn issue_get_revoke_roundtrip() {
        let store = InMemoryGrantStore::new();
        let grant = sample_grant(1);
        let id = store.issue(grant.clone()).await.unwrap();

        let got = store.get(&id).await.unwrap().unwrap();
        assert_eq!(got.file_hash, grant.file_hash);
        assert_eq!(got.grantee, grant.grantee);

        store.revoke(&id).await.unwrap();
        assert!(store.get(&id).await.unwrap().is_none());
        // Idempotent revoke
        store.revoke(&id).await.unwrap();
    }

    #[tokio::test]
    async fn list_by_subject_and_resource() {
        let store = InMemoryGrantStore::new();
        let g1 = sample_grant(1);
        let g2 = sample_grant(2);
        let subject = g1.grantee;
        let resource = g1.file_hash.to_hex().to_string();

        store.issue(g1.clone()).await.unwrap();
        store.issue(g2.clone()).await.unwrap();

        let by_subject = store.list_by_subject(&subject).await.unwrap();
        assert_eq!(by_subject.len(), 1);

        let by_resource = store.list_by_resource(&resource).await.unwrap();
        assert_eq!(by_resource.len(), 1);
        assert_eq!(by_resource[0].file_hash, g1.file_hash);
    }
}
