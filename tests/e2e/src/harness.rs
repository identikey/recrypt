//! Test harness: spawns an in-process server, creates temp dirs, manages env isolation.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::net::TcpListener;

use recrypt_server::config::{
    Config, NonceConfig, PersistenceConfig, RateLimitConfig, StorageConfig,
};
use recrypt_server::state::AppState;

use crate::cli::CliRunner;

/// RAII guard that saves and restores environment variables on drop.
/// Prevents cross-test pollution under `--test-threads=1`.
pub struct TestEnv {
    saved: HashMap<String, Option<String>>,
}

impl TestEnv {
    pub fn new() -> Self {
        Self {
            saved: HashMap::new(),
        }
    }

    /// Set an env var, saving its previous value for restore on drop.
    ///
    /// # Safety
    /// Tests run with `--test-threads=1`, so no concurrent env mutation.
    pub fn set(&mut self, key: &str, value: &str) {
        if !self.saved.contains_key(key) {
            self.saved.insert(key.to_string(), std::env::var(key).ok());
        }
        unsafe { std::env::set_var(key, value) };
    }

    /// Remove an env var, saving its previous value for restore on drop.
    ///
    /// # Safety
    /// Tests run with `--test-threads=1`, so no concurrent env mutation.
    pub fn remove(&mut self, key: &str) {
        if !self.saved.contains_key(key) {
            self.saved.insert(key.to_string(), std::env::var(key).ok());
        }
        unsafe { std::env::remove_var(key) };
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        for (key, prev) in &self.saved {
            match prev {
                Some(val) => unsafe { std::env::set_var(key, val) },
                None => unsafe { std::env::remove_var(key) },
            }
        }
    }
}

/// Full test harness: in-process server + temp dirs + env isolation.
pub struct TestHarness {
    pub server_url: String,
    pub server_addr: SocketAddr,
    pub temp_dir: tempfile::TempDir,
    pub wallet_path: PathBuf,
    pub _env: TestEnv,
}

impl TestHarness {
    /// Start a test harness with mock backend, memory storage, and SQLite persistence.
    pub async fn new() -> Self {
        Self::with_config(StorageConfig::default()).await
    }

    /// Start with custom storage config (e.g. for S3 tests).
    pub async fn with_config(storage: StorageConfig) -> Self {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let wallet_path = temp_dir.path().join("test-wallet.recrypt");
        let sqlite_path = temp_dir.path().join("test.db");

        let config = Config {
            host: "127.0.0.1".into(),
            port: 0,
            storage,
            persistence: PersistenceConfig {
                backend: "sqlite".into(),
                sqlite_path,
            },
            nonce: NonceConfig { window_secs: 300 },
            pre_backend: "mock".into(),
            rate_limit: RateLimitConfig {
                per_ip_rps: 10_000,
                per_ip_burst: 10_000,
                per_fingerprint_rps: 10_000,
                per_fingerprint_burst: 10_000,
            },
        };

        let state = AppState::new(&config).await.expect("create app state");
        let app = recrypt_server::routes::router(state);

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("get local addr");

        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("server failed");
        });

        // Give server a moment to accept connections
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let server_url = format!("http://{addr}");

        // Set up env isolation — CLI reads these via flags, but some code paths
        // fall back to env vars, so we set them defensively.
        let mut env = TestEnv::new();
        env.set("RECRYPT_WALLET", wallet_path.to_str().unwrap());
        env.set("RECRYPT_SERVER", &server_url);
        env.set("RECRYPT_BACKEND", "mock");
        env.set("RECRYPT_WALLET_PASSWORD", "testpass123");
        // Clear any stale env that could leak between tests
        env.remove("RECRYPT_IDENTITY");
        env.remove("RECRYPT_WALLET_KEY");
        env.remove("RECRYPT_DEBUG");

        Self {
            server_url,
            server_addr: addr,
            temp_dir,
            wallet_path,
            _env: env,
        }
    }

    /// Get a CLI runner pointed at this harness.
    pub fn cli(&self) -> CliRunner {
        CliRunner::new(
            &self.server_url,
            &self.wallet_path,
            "mock",
            self.temp_dir.path(),
        )
    }

    /// Get an API test client for direct HTTP calls with signing.
    pub fn api(&self) -> crate::api::ApiTestClient {
        crate::api::ApiTestClient::new(&self.server_url)
    }

    /// Path to the temp directory for test files.
    pub fn tmp(&self) -> &std::path::Path {
        self.temp_dir.path()
    }
}
