use figment::{
    Figment,
    providers::{Env, Format, Toml},
};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,

    #[serde(default)]
    pub storage: StorageConfig,

    #[serde(default)]
    pub persistence: PersistenceConfig,

    #[serde(default)]
    pub nonce: NonceConfig,

    /// PRE backend: "mock" (default, fast) or "lattice" (post-quantum, slow init)
    #[serde(default = "default_pre_backend")]
    pub pre_backend: String,

    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    #[serde(default)]
    pub limits: MemoryLimitConfig,
}

fn default_pre_backend() -> String {
    "mock".into()
}

#[derive(Debug, Deserialize, Default, Clone)]
#[allow(dead_code)]
pub struct StorageConfig {
    #[serde(default = "default_backend")]
    pub backend: String, // "memory", "local", "s3"
    pub local_path: Option<String>,
    pub s3_bucket: Option<String>,
    pub s3_endpoint: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct PersistenceConfig {
    /// "memory" (default) or "sqlite"
    #[serde(default = "default_persistence_backend")]
    pub backend: String,
    /// Path to sqlite db file when backend = "sqlite"
    #[serde(default = "default_sqlite_path")]
    pub sqlite_path: PathBuf,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            backend: default_persistence_backend(),
            sqlite_path: default_sqlite_path(),
        }
    }
}

fn default_persistence_backend() -> String {
    "memory".into()
}
fn default_sqlite_path() -> PathBuf {
    PathBuf::from("recrypt-server.db")
}

#[derive(Debug, Deserialize, Clone)]
pub struct NonceConfig {
    #[serde(default = "default_nonce_window_secs")]
    pub window_secs: u64,
}

impl Default for NonceConfig {
    fn default() -> Self {
        Self {
            window_secs: default_nonce_window_secs(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct RateLimitConfig {
    #[serde(default = "default_per_ip_rps")]
    pub per_ip_rps: u32,
    #[serde(default = "default_per_ip_burst")]
    pub per_ip_burst: u32,
    #[serde(default = "default_per_fingerprint_rps")]
    pub per_fingerprint_rps: u32,
    #[serde(default = "default_per_fingerprint_burst")]
    pub per_fingerprint_burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            per_ip_rps: default_per_ip_rps(),
            per_ip_burst: default_per_ip_burst(),
            per_fingerprint_rps: default_per_fingerprint_rps(),
            per_fingerprint_burst: default_per_fingerprint_burst(),
        }
    }
}

fn default_per_ip_rps() -> u32 {
    50
}
fn default_per_ip_burst() -> u32 {
    100
}
fn default_per_fingerprint_rps() -> u32 {
    20
}
fn default_per_fingerprint_burst() -> u32 {
    40
}

/// Process memory limits. Malformed PRE material can drive OpenFHE/cereal
/// deserialization to attempt an arbitrarily large allocation from an
/// attacker-controlled length field (recrypt-hrq). A bounded address space
/// turns that runaway allocation into a catchable `std::bad_alloc` (surfaced
/// as an error by the FFI layer) instead of letting the allocator satisfy it
/// and the host OOM-kill the proxy.
#[derive(Debug, Deserialize, Clone)]
pub struct MemoryLimitConfig {
    /// Cap on virtual address space (RLIMIT_AS), in GiB. `0` disables the cap.
    /// Enforced on Linux; macOS ignores RLIMIT_AS, so production deployments
    /// should also set a container/cgroup memory limit. Tune upward for the
    /// lattice backend if large crypto contexts exhaust the default.
    #[serde(default = "default_address_space_gb")]
    pub address_space_gb: u64,
}

impl Default for MemoryLimitConfig {
    fn default() -> Self {
        Self {
            address_space_gb: default_address_space_gb(),
        }
    }
}

fn default_address_space_gb() -> u64 {
    16
}

fn default_host() -> String {
    "127.0.0.1".into()
}
fn default_port() -> u16 {
    7222
}
fn default_backend() -> String {
    "memory".into()
}
fn default_nonce_window_secs() -> u64 {
    300
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let config: Config = Figment::new()
            .merge(Toml::file("recrypt-server.toml"))
            .merge(Env::prefixed("RECRYPT_").split("__"))
            .extract()?;
        Ok(config)
    }
}
