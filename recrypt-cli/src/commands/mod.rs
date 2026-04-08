pub mod account;
pub mod config;
pub mod decrypt;
pub mod encrypt;
pub mod files;
pub mod helpers;
pub mod identity;
pub mod share;
pub mod wallet_cmd;

use recrypt_core::pre::backends::{LatticeBackend, MockBackend};
use recrypt_core::pre::{BackendId, PreBackend};

/// Global context passed to all commands
pub struct Context {
    pub json_output: bool,
    pub identity_override: Option<String>,
    pub server_override: Option<String>,
    pub wallet_override: Option<String>,
    pub backend_override: Option<String>,
    pub verbose: bool,
    pub debug: bool,
}

impl Context {
    /// Resolve which backend to use, with priority:
    /// 1. --backend CLI flag
    /// 2. Config file default_backend
    /// 3. Default to "lattice" if available, else "mock"
    pub fn resolve_backend_id(&self) -> anyhow::Result<BackendId> {
        use crate::config::Config;

        // 1. CLI override
        if let Some(ref backend_str) = self.backend_override {
            return backend_str.parse().map_err(|e| anyhow::anyhow!("{e}"));
        }

        // 2. Config file
        let config = Config::load()?;
        if let Some(ref backend_str) = config.default_backend {
            return backend_str.parse().map_err(|e| anyhow::anyhow!("{e}"));
        }

        // 3. Default: lattice if available, else mock
        if LatticeBackend::is_available() {
            Ok(BackendId::Lattice)
        } else {
            Ok(BackendId::Mock)
        }
    }

    /// Create a boxed backend from the resolved backend ID
    #[allow(dead_code)]
    pub fn create_backend(&self) -> anyhow::Result<Box<dyn PreBackend>> {
        let backend_id = self.resolve_backend_id()?;
        create_backend_from_id(backend_id)
    }
}

/// Create a boxed backend from a BackendId
pub fn create_backend_from_id(backend_id: BackendId) -> anyhow::Result<Box<dyn PreBackend>> {
    match backend_id {
        BackendId::Lattice => {
            let backend = LatticeBackend::new()
                .map_err(|e| anyhow::anyhow!("Failed to initialize lattice backend: {e}"))?;
            Ok(Box::new(backend))
        }
        BackendId::Mock => Ok(Box::new(MockBackend)),
        other => anyhow::bail!("Backend {other} is not yet implemented"),
    }
}
