//! Access grants: records of delegated access within a keyspace

use std::collections::{BTreeSet, HashMap};
use std::fmt;

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::error::{AuthError, AuthResult};
use crate::fingerprint::PublicKeyFingerprint;
use crate::keyspace::MemberCapability;

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

/// A record of access granted within a keyspace.
///
/// Replaces the old file-hash-based AccessGrant. Grants are now scoped to a
/// keyspace and carry a set of `MemberCapability` values.
#[derive(Clone, Debug)]
pub struct AccessGrant {
    /// Format version
    pub version: u32,
    /// The keyspace this grant applies to
    pub keyspace_id: [u8; 32],
    /// Version of the keyspace document at time of issuance
    pub keyspace_version: u64,
    /// Who has been granted access
    pub subject: PublicKeyFingerprint,
    /// Who issued the grant
    pub issuer: PublicKeyFingerprint,
    /// What capabilities are permitted
    pub capabilities: BTreeSet<MemberCapability>,
    /// When the grant expires (None = never)
    pub expires_at: Option<u64>,
    /// Delegation depth (0 = non-delegable)
    pub delegation_depth: u8,
    /// Parent grant id for delegation chains
    pub parent_grant: Option<GrantId>,
    /// When the grant was created (Unix timestamp)
    pub created_at: u64,
    /// Signature placeholder (will be MultiSig)
    pub signature: Option<Vec<u8>>,
}

/// Length-prefixed encoding for a capability set.
///
/// Format: `u32 count || [u16 len || bytes]*` — iterated in BTreeSet order,
/// so encoding is deterministic and cannot alias across different sets
/// (e.g. `{"read"}` vs `{"read\0write"}`).
pub(crate) fn write_capabilities(out: &mut Vec<u8>, caps: &BTreeSet<MemberCapability>) {
    out.extend((caps.len() as u32).to_le_bytes());
    for cap in caps {
        let bytes = cap.as_str().as_bytes();
        // `as_str()` is a closed set of ASCII tags; a 16-bit length is plenty.
        out.extend((bytes.len() as u16).to_le_bytes());
        out.extend(bytes);
    }
}

impl AccessGrant {
    /// Current grant format version
    pub const VERSION: u32 = 2;

    pub fn new(
        keyspace_id: [u8; 32],
        keyspace_version: u64,
        subject: PublicKeyFingerprint,
        issuer: PublicKeyFingerprint,
        capabilities: BTreeSet<MemberCapability>,
        expires_at: Option<u64>,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            version: Self::VERSION,
            keyspace_id,
            keyspace_version,
            subject,
            issuer,
            capabilities,
            expires_at,
            delegation_depth: 0,
            parent_grant: None,
            created_at: now,
            signature: None,
        }
    }

    /// Check if the grant has expired
    pub fn is_expired(&self) -> bool {
        let expires = match self.expires_at {
            Some(ts) => ts,
            None => return false,
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now > expires
    }

    /// Check if a specific capability is permitted
    pub fn permits(&self, cap: MemberCapability) -> bool {
        self.capabilities.contains(&cap)
    }

    /// Domain-separation tag for `AccessGrant` canonical bytes.
    pub(crate) const DOMAIN_TAG: &'static [u8] = b"IdentikeyGrant\x01";

    /// Canonical byte encoding used for content-addressing.
    ///
    /// Layout is explicitly length-prefixed with a domain tag so that
    /// distinct field contents cannot alias under hashing. `created_at`
    /// is included so that distinct issuances produce distinct IDs even
    /// if all other fields match.
    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend(Self::DOMAIN_TAG);
        out.extend(self.version.to_le_bytes());
        out.extend(&self.keyspace_id);
        out.extend(self.keyspace_version.to_le_bytes());
        out.extend(self.subject.as_bytes());
        out.extend(self.issuer.as_bytes());
        write_capabilities(&mut out, &self.capabilities);
        out.extend(self.expires_at.unwrap_or(0).to_le_bytes());
        out.push(self.delegation_depth);
        if let Some(parent) = &self.parent_grant {
            out.push(1);
            out.extend(parent.as_bytes());
        } else {
            out.push(0);
        }
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

    /// List grants for a given keyspace.
    async fn list_by_keyspace(&self, keyspace_id: &[u8; 32]) -> AuthResult<Vec<AccessGrant>>;
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
            return Err(AuthError::AlreadyExists(format!(
                "grant {}",
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
            .filter(|g| &g.subject == subject)
            .cloned()
            .collect())
    }

    async fn list_by_keyspace(&self, keyspace_id: &[u8; 32]) -> AuthResult<Vec<AccessGrant>> {
        let guard = self.inner.read().await;
        Ok(guard
            .values()
            .filter(|g| &g.keyspace_id == keyspace_id)
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_grant(seed: u8) -> AccessGrant {
        AccessGrant::new(
            [seed; 32],
            0,
            PublicKeyFingerprint::from_bytes([seed.wrapping_add(1); 32]),
            PublicKeyFingerprint::from_bytes([seed; 32]),
            BTreeSet::from([MemberCapability::Read]),
            None,
        )
    }

    #[tokio::test]
    async fn issue_get_revoke_roundtrip() {
        let store = InMemoryGrantStore::new();
        let grant = sample_grant(1);
        let id = store.issue(grant.clone()).await.unwrap();

        let got = store.get(&id).await.unwrap().unwrap();
        assert_eq!(got.keyspace_id, grant.keyspace_id);
        assert_eq!(got.subject, grant.subject);

        store.revoke(&id).await.unwrap();
        assert!(store.get(&id).await.unwrap().is_none());
        // Idempotent revoke
        store.revoke(&id).await.unwrap();
    }

    #[tokio::test]
    async fn list_by_subject_and_keyspace() {
        let store = InMemoryGrantStore::new();
        let g1 = sample_grant(1);
        let g2 = sample_grant(2);
        let subject = g1.subject;
        let keyspace_id = g1.keyspace_id;

        store.issue(g1.clone()).await.unwrap();
        store.issue(g2.clone()).await.unwrap();

        let by_subject = store.list_by_subject(&subject).await.unwrap();
        assert_eq!(by_subject.len(), 1);

        let by_keyspace = store.list_by_keyspace(&keyspace_id).await.unwrap();
        assert_eq!(by_keyspace.len(), 1);
        assert_eq!(by_keyspace[0].keyspace_id, g1.keyspace_id);
    }
}
