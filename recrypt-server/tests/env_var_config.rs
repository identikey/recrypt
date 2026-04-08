//! Verifies that `Config::load()` honours `RECRYPT_*` environment variables
//! with double-underscore nesting, as documented in the production-readiness
//! plan.
//!
//! This test must run single-threaded (`--test-threads=1`) because it mutates
//! process-global env vars. The recrypt-server test suite already runs with
//! `--test-threads=1` due to OpenFHE constraints.

use recrypt_server::config::Config;
use tempfile::tempdir;

struct EnvGuard {
    keys: Vec<&'static str>,
}

impl EnvGuard {
    fn set(pairs: &[(&'static str, String)]) -> Self {
        let keys: Vec<&'static str> = pairs.iter().map(|(k, _)| *k).collect();
        for (k, v) in pairs {
            // Safety: tests are single-threaded and we restore on drop.
            unsafe { std::env::set_var(k, v) };
        }
        Self { keys }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for k in &self.keys {
            unsafe { std::env::remove_var(k) };
        }
    }
}

#[test]
fn env_vars_override_config() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("recrypt.db");
    let db_str = db_path.to_string_lossy().to_string();

    // Run from a directory with no recrypt-server.toml so the figment Toml
    // provider yields an empty source and env vars are the only input.
    let prev_cwd = std::env::current_dir().expect("cwd");
    std::env::set_current_dir(dir.path()).expect("chdir tmp");

    let _guard = EnvGuard::set(&[
        ("RECRYPT_PORT", "0".to_string()),
        ("RECRYPT_PERSISTENCE__BACKEND", "sqlite".to_string()),
        ("RECRYPT_PERSISTENCE__SQLITE_PATH", db_str.clone()),
        ("RECRYPT_PRE_BACKEND", "mock".to_string()),
    ]);

    let config = Config::load().expect("load config");

    // Restore cwd before any assertion failure can poison the test runner.
    std::env::set_current_dir(prev_cwd).expect("restore cwd");

    assert_eq!(config.port, 0);
    assert_eq!(config.persistence.backend, "sqlite");
    assert_eq!(
        config.persistence.sqlite_path.to_string_lossy(),
        db_str.as_str()
    );
    assert_eq!(config.pre_backend, "mock");
}
