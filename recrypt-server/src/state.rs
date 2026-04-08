use crate::config::Config;
use identikey_storage_auth::{
    InMemoryOwnershipStore, InMemoryProviderIndex, OwnershipStore, ProviderIndex,
};
use recrypt_core::pre::{
    BackendId, PreBackend,
    backends::{LatticeBackend, MockBackend},
};
use recrypt_storage::{BlobStorage, InMemoryStorage, LocalFileStorage};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared application state
#[derive(Clone)]
#[allow(dead_code)] // Will be used by route handlers
pub struct AppState {
    pub storage: Arc<dyn BlobStorage>,
    pub ownership: Arc<dyn OwnershipStore>,
    pub providers: Arc<dyn ProviderIndex>,
    pub accounts: Arc<RwLock<AccountStore>>,
    pub shares: Arc<RwLock<ShareStore>>,
    pub nonces: Arc<RwLock<NonceStore>>,
    pub config: Arc<Config>,
    /// PRE backend for recryption ops (initialized once at startup, thread-safe after)
    pub pre_backend: Arc<dyn PreBackend + Send + Sync>,
}

/// In-memory account storage (Phase 5 MVP)
#[allow(dead_code)] // Will be used by route handlers
pub struct AccountStore {
    pub accounts: HashMap<String, Account>, // fingerprint -> account
}

#[derive(Clone, Debug)]
#[allow(dead_code)] // Will be used by route handlers
pub struct Account {
    pub fingerprint: String,
    pub ed25519_pk: Vec<u8>,
    pub ml_dsa_pk: Vec<u8>,
    pub pre_pk: Option<Vec<u8>>,
    pub created_at: u64,
}

/// Share policy storage
#[allow(dead_code)] // Will be used by route handlers
pub struct ShareStore {
    pub shares: HashMap<String, SharePolicy>, // share_id -> policy
}

#[derive(Clone, Debug)]
#[allow(dead_code)] // Will be used by route handlers
pub struct SharePolicy {
    pub id: String,
    pub from_fingerprint: String,
    pub to_fingerprint: String,
    pub file_hash: blake3::Hash,
    pub recrypt_key: Vec<u8>,
    pub backend_id: BackendId,
    pub created_at: u64,
}

/// Nonce tracking for replay prevention
#[allow(dead_code)] // Will be used by middleware
pub struct NonceStore {
    pub used: HashSet<String>,
    pub window_secs: u64,
}

impl Default for AccountStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AccountStore {
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
        }
    }
}

impl Default for ShareStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ShareStore {
    pub fn new() -> Self {
        Self {
            shares: HashMap::new(),
        }
    }
}

impl NonceStore {
    pub fn new(window_secs: u64) -> Self {
        Self {
            used: HashSet::new(),
            window_secs,
        }
    }

    /// Validate nonce format and freshness
    #[allow(dead_code)] // Will be used by middleware
    pub fn validate(&self, nonce: &str) -> bool {
        // Format: "{unix_ms}:{uuid}"
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

        // Check within window
        let window_ms = self.window_secs * 1000;
        if now_ms > ts_ms + window_ms {
            return false;
        } // Too old
        if ts_ms > now_ms + 60_000 {
            return false;
        } // Future (clock skew tolerance: 1 min)

        true
    }

    /// Check if nonce was already used
    #[allow(dead_code)] // Will be used by middleware
    pub fn is_used(&self, nonce: &str) -> bool {
        self.used.contains(nonce)
    }

    /// Mark nonce as used
    #[allow(dead_code)] // Will be used by middleware
    pub fn mark_used(&mut self, nonce: String) {
        self.used.insert(nonce);
    }
}

impl AppState {
    pub async fn new(config: &Config) -> anyhow::Result<Self> {
        // Build storage backend
        let storage: Arc<dyn BlobStorage> = match config.storage.backend.as_str() {
            "local" => {
                let path = config
                    .storage
                    .local_path
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("local storage requires local_path"))?;
                Arc::new(LocalFileStorage::new(path).await?)
            }
            _ => Arc::new(InMemoryStorage::new()),
        };

        // For MVP, use in-memory auth stores
        let ownership: Arc<dyn OwnershipStore> = Arc::new(InMemoryOwnershipStore::new());
        let providers: Arc<dyn ProviderIndex> = Arc::new(InMemoryProviderIndex::new());

        // Initialize PRE backend (slow for lattice, do once at startup)
        // SECURITY: Never silently downgrade - fail hard if requested backend unavailable
        let pre_backend: Arc<dyn PreBackend + Send + Sync> = match config
            .pre_backend
            .to_lowercase()
            .as_str()
        {
            "lattice" | "pq" | "post-quantum" => {
                if !LatticeBackend::is_available() {
                    anyhow::bail!(
                        "FATAL: Lattice backend requested but OpenFHE not available. \
                             Build with `--features openfhe` or use `pre_backend = \"mock\"` for testing."
                    );
                }
                tracing::info!("Initializing lattice PRE backend (this may take ~2 min)...");
                let start = std::time::Instant::now();
                let backend = LatticeBackend::new()
                    .map_err(|e| anyhow::anyhow!("Failed to init lattice backend: {e}"))?;
                tracing::info!("Lattice backend ready in {:?}", start.elapsed());
                Arc::new(backend)
            }
            "mock" | "test" => {
                tracing::warn!("Using mock PRE backend - NOT FOR PRODUCTION USE");
                Arc::new(MockBackend)
            }
            other => {
                anyhow::bail!(
                    "Unknown PRE backend '{}'. Valid options: 'lattice', 'mock'",
                    other
                );
            }
        };

        Ok(Self {
            storage,
            ownership,
            providers,
            accounts: Arc::new(RwLock::new(AccountStore::new())),
            shares: Arc::new(RwLock::new(ShareStore::new())),
            nonces: Arc::new(RwLock::new(NonceStore::new(config.nonce.window_secs))),
            config: Arc::new(config.clone()),
            pre_backend,
        })
    }
}
