//! CLI runner: wraps `tokio::process::Command` to invoke the `recrypt` binary with test flags.
//!
//! Uses async process spawning so the in-process server can serve requests
//! concurrently on the same tokio runtime.

use std::path::{Path, PathBuf};
use tokio::process::Command;

/// Result of a CLI invocation.
pub struct CommandResult {
    pub status: std::process::ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

impl CommandResult {
    /// Parse stdout as JSON. Panics if not valid JSON.
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| {
            panic!(
                "Failed to parse CLI stdout as JSON: {e}\nstdout: {}\nstderr: {}",
                self.stdout, self.stderr
            )
        })
    }

    /// Assert the command succeeded (exit code 0).
    pub fn expect_success(&self) -> &Self {
        assert!(
            self.status.success(),
            "CLI command failed (exit {}):\nstdout: {}\nstderr: {}",
            self.status,
            self.stdout,
            self.stderr,
        );
        self
    }

    /// Assert the command failed (non-zero exit code).
    pub fn expect_failure(&self) -> &Self {
        assert!(
            !self.status.success(),
            "CLI command unexpectedly succeeded:\nstdout: {}\nstderr: {}",
            self.stdout,
            self.stderr,
        );
        self
    }
}

/// Wrapper for the `recrypt` CLI binary.
///
/// Injects `--json`, `--wallet`, `--server`, `--backend` on every invocation.
pub struct CliRunner {
    server_url: String,
    wallet_path: PathBuf,
    backend: String,
    identity: Option<String>,
    config_dir: PathBuf,
}

impl CliRunner {
    pub fn new(server_url: &str, wallet_path: &Path, backend: &str, config_dir: &Path) -> Self {
        Self {
            server_url: server_url.to_string(),
            wallet_path: wallet_path.to_owned(),
            backend: backend.to_string(),
            identity: None,
            config_dir: config_dir.to_owned(),
        }
    }

    /// Set the default identity for all subsequent CLI calls.
    /// This overrides any `active_identity` in the global config file,
    /// preventing cross-test contamination under `--test-threads=1`.
    pub fn set_identity(&mut self, name: &str) {
        self.identity = Some(name.to_string());
    }

    /// Run a CLI command with the given arguments (async — won't block the runtime).
    /// `--json`, `--wallet`, `--server`, `--backend` are injected automatically.
    /// If an identity is set, `--identity` is also injected.
    pub async fn run(&self, args: &[&str]) -> CommandResult {
        #[allow(deprecated)]
        let bin = assert_cmd::cargo::cargo_bin("recrypt");
        let mut cmd = Command::new(bin);
        cmd.args(["--json", "--wallet", self.wallet_path.to_str().unwrap()])
            .args(["--server", &self.server_url])
            .args(["--backend", &self.backend]);
        if let Some(ref id) = self.identity {
            cmd.args(["--identity", id]);
        }
        let output = cmd
            .args(args)
            .env("RECRYPT_WALLET_PASSWORD", "testpass123")
            .env("RECRYPT_CONFIG_DIR", &self.config_dir)
            .env("RECRYPT_NO_KEYCHAIN", "1")
            .output()
            .await
            .expect("failed to execute recrypt CLI");

        CommandResult {
            status: output.status,
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        }
    }

    /// Run a CLI command and assert it succeeds, returning the result.
    pub async fn run_ok(&self, args: &[&str]) -> CommandResult {
        let result = self.run(args).await;
        result.expect_success();
        result
    }

    /// Run a CLI command and assert it fails, returning the result.
    pub async fn run_err(&self, args: &[&str]) -> CommandResult {
        let result = self.run(args).await;
        result.expect_failure();
        result
    }
}
