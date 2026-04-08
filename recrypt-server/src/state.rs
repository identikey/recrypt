use crate::config::Config;
use crate::nonces::{InMemoryNonceStore, NonceStore, SqliteNonceStore};
use crate::shares::{InMemoryShareStore, ShareStore, SqliteShareStore};
use identikey_storage_auth::{
    AccountStore, InMemoryAccountStore, InMemoryOwnershipStore, OwnershipStore,
    SqliteAccountStore,
};
use recrypt_core::pre::{
    PreBackend,
    backends::{LatticeBackend, MockBackend},
};
use recrypt_storage::{
    BlobStorage, InMemoryProviderIndex, InMemoryStorage, LocalFileStorage, ProviderIndex,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

// Re-export so existing route handlers (`use crate::state::SharePolicy`) keep working.
pub use crate::shares::SharePolicy;

/// Shared application state.
#[derive(Clone)]
#[allow(dead_code)]
pub struct AppState {
    pub storage: Arc<dyn BlobStorage>,
    pub ownership: Arc<dyn OwnershipStore>,
    pub providers: Arc<dyn ProviderIndex>,
    pub accounts: Arc<dyn AccountStore>,
    pub shares: Arc<dyn ShareStore>,
    pub nonces: Arc<dyn NonceStore>,
    pub config: Arc<Config>,
    /// PRE backend (immutable after startup).
    pub pre_backend: Arc<dyn PreBackend + Send + Sync>,
    /// Background nonce-GC task handle. Wrapped in `Arc` so `AppState: Clone`.
    /// GC task lifecycle: tied to AppState; aborts on drop via JoinHandle.
    pub nonce_gc: Arc<NonceGcHandle>,
}

/// Drop guard that aborts the nonce-GC task when the last `AppState` clone is
/// dropped.
pub struct NonceGcHandle(JoinHandle<()>);

impl Drop for NonceGcHandle {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl AppState {
    /// Construct application state from a loaded config. Picks in-memory or
    /// SQLite-backed stores based on `config.persistence.backend`. Mock PRE
    /// backend always uses in-memory stores regardless of config (tests).
    pub async fn from_config(config: &Config) -> anyhow::Result<Self> {
        // ----- Storage backend (blobs) -----
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

        // ----- PRE backend -----
        let pre_backend_kind = config.pre_backend.to_lowercase();
        let pre_backend: Arc<dyn PreBackend + Send + Sync> = match pre_backend_kind.as_str() {
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
            other => anyhow::bail!(
                "Unknown PRE backend '{}'. Valid options: 'lattice', 'mock'",
                other
            ),
        };

        // ----- Persistence selection -----
        // Sqlite is selected whenever explicitly configured. Default ("memory")
        // keeps the in-memory stores regardless of PRE backend.
        let want_sqlite = config.persistence.backend == "sqlite";

        let (accounts, shares, nonces): (
            Arc<dyn AccountStore>,
            Arc<dyn ShareStore>,
            Arc<dyn NonceStore>,
        ) = if want_sqlite {
            // Single shared SQLite connection — Open Question 5.3: one unified recrypt.db.
            let path = config
                .persistence
                .sqlite_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("sqlite_path is not valid UTF-8"))?;
            tracing::info!("Opening SQLite persistence at {}", path);
            let conn = tokio_rusqlite::Connection::open(path)
                .await
                .map_err(|e| anyhow::anyhow!("failed to open sqlite db: {e}"))?;
            // WAL mode for concurrent readers.
            conn.call(|c| {
                c.pragma_update(None, "journal_mode", "WAL")?;
                Ok::<_, rusqlite::Error>(())
            })
            .await
            .map_err(|e| anyhow::anyhow!("failed to set WAL: {e}"))?;
            let conn = Arc::new(conn);

            let accounts = Arc::new(SqliteAccountStore::new(conn.clone()).await?);
            let shares = Arc::new(
                SqliteShareStore::new(conn.clone())
                    .await
                    .map_err(|e| anyhow::anyhow!("share store init: {e}"))?,
            );
            let nonces = Arc::new(
                SqliteNonceStore::new(conn)
                    .await
                    .map_err(|e| anyhow::anyhow!("nonce store init: {e}"))?,
            );
            (accounts, shares, nonces)
        } else {
            (
                Arc::new(InMemoryAccountStore::new()),
                Arc::new(InMemoryShareStore::new()),
                Arc::new(InMemoryNonceStore::new()),
            )
        };

        // Auth/storage bookkeeping that has no SQLite swap yet.
        let ownership: Arc<dyn OwnershipStore> = Arc::new(InMemoryOwnershipStore::new());
        let providers: Arc<dyn ProviderIndex> = Arc::new(InMemoryProviderIndex::new());

        // ----- Spawn background nonce GC -----
        // GC task lifecycle: tied to AppState; aborts on drop via JoinHandle.
        let gc_nonces = nonces.clone();
        let handle = tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            // First tick fires immediately; skip it.
            tick.tick().await;
            loop {
                tick.tick().await;
                match gc_nonces.gc_expired().await {
                    Ok(n) if n > 0 => tracing::debug!("nonce gc removed {n} expired entries"),
                    Ok(_) => {}
                    Err(e) => tracing::warn!("nonce gc error: {e}"),
                }
            }
        });

        Ok(Self {
            storage,
            ownership,
            providers,
            accounts,
            shares,
            nonces,
            config: Arc::new(config.clone()),
            pre_backend,
            nonce_gc: Arc::new(NonceGcHandle(handle)),
        })
    }

    /// Backwards-compatible alias for [`AppState::from_config`].
    pub async fn new(config: &Config) -> anyhow::Result<Self> {
        Self::from_config(config).await
    }
}
