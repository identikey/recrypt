//! Account storage: identity records keyed by public key fingerprint.

use std::collections::HashMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::error::AuthResult;
use crate::fingerprint::PublicKeyFingerprint;

/// Persistent identity record for a registered account.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountRecord {
    pub fingerprint: String,
    pub ed25519_pk: Vec<u8>,
    pub ml_dsa_pk: Vec<u8>,
    pub created_at: u64,
}

/// Trait describing storage for account identity records.
#[async_trait]
pub trait AccountStore: Send + Sync {
    /// Persist a new account record.
    async fn register(&self, record: AccountRecord) -> AuthResult<()>;

    /// Look up a record by fingerprint.
    async fn get(&self, fingerprint: &PublicKeyFingerprint) -> AuthResult<Option<AccountRecord>>;

    /// Check whether a record exists for `fingerprint`.
    async fn exists(&self, fingerprint: &PublicKeyFingerprint) -> AuthResult<bool>;
}

/// In-memory implementation of [`AccountStore`].
#[derive(Default)]
pub struct InMemoryAccountStore {
    inner: RwLock<HashMap<PublicKeyFingerprint, AccountRecord>>,
}

impl InMemoryAccountStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AccountStore for InMemoryAccountStore {
    async fn register(&self, record: AccountRecord) -> AuthResult<()> {
        let fp = PublicKeyFingerprint::from_public_key(&record.ed25519_pk);
        let mut guard = self.inner.write().await;
        guard.insert(fp, record);
        Ok(())
    }

    async fn get(&self, fingerprint: &PublicKeyFingerprint) -> AuthResult<Option<AccountRecord>> {
        let guard = self.inner.read().await;
        Ok(guard.get(fingerprint).cloned())
    }

    async fn exists(&self, fingerprint: &PublicKeyFingerprint) -> AuthResult<bool> {
        let guard = self.inner.read().await;
        Ok(guard.contains_key(fingerprint))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(seed: u8) -> AccountRecord {
        AccountRecord {
            fingerprint: format!("fp-{seed}"),
            ed25519_pk: vec![seed; 32],
            ml_dsa_pk: vec![seed; 64],
            created_at: 1,
        }
    }

    #[tokio::test]
    async fn register_and_get_roundtrip() {
        let store = InMemoryAccountStore::new();
        let record = sample_record(7);
        let fp = PublicKeyFingerprint::from_public_key(&record.ed25519_pk);

        store.register(record.clone()).await.unwrap();
        assert!(store.exists(&fp).await.unwrap());
        let got = store.get(&fp).await.unwrap().unwrap();
        assert_eq!(got.fingerprint, record.fingerprint);
        assert_eq!(got.ed25519_pk, record.ed25519_pk);
    }

    #[tokio::test]
    async fn missing_fingerprint_returns_none() {
        let store = InMemoryAccountStore::new();
        let fp = PublicKeyFingerprint::from_public_key(b"absent");
        assert!(!store.exists(&fp).await.unwrap());
        assert!(store.get(&fp).await.unwrap().is_none());
    }
}
