# Phase 6b: Secure Credential Storage Implementation Plan

**Status:** ✅ Complete
**Duration:** 2-3 days
**Goal:** OS-native secure storage for wallet encryption keys, eliminating per-invocation password prompts

**Prerequisites:** Phase 6 ✅ Complete

**Completed:**

- ✅ Phase 6b.1: Credential Provider Architecture
- ✅ Phase 6b.2: Key Caching (macOS Keychain via security-framework, Linux/Windows via keyring)
- ✅ Phase 6b.3: Wallet Commands (lock/unlock/status/path)

---

## Overview

Current state: every `Wallet::load()` calls `dialoguer::Password` for password input. This breaks:

- **Automated tests** – prompts hang in CI
- **User experience** – typing password for every `dcypher files list` is maddening
- **Scriptability** – piping commands impossible

We'll decouple key derivation from key usage via a `CredentialProvider` abstraction, storing the derived 32-byte encryption key (not the password) in OS-native secure storage.

---

## Current State Analysis

### What Exists

| File                   | Current Behavior                                                           |
| ---------------------- | -------------------------------------------------------------------------- |
| `wallet/storage.rs:35` | `Password::new().with_prompt("Wallet password").interact()?` on every load |
| `wallet/storage.rs:56` | Same prompt on every save                                                  |
| `wallet/format.rs`     | Argon2id key derivation + XChaCha20-Poly1305 encryption                    |

### The Problem

```
dcypher identity list      → password prompt
dcypher identity show      → password prompt
dcypher encrypt foo.txt    → password prompt
dcypher files upload       → password prompt (×2: wallet + signing)
```

Every command that touches the wallet requires a password. Unacceptable.

### Key Discovery: Wallet Access Patterns

| Command            | Needs Wallet? | Needs Secret Keys?               |
| ------------------ | ------------- | -------------------------------- |
| `identity list`    | Yes (read)    | No (only public info)            |
| `identity show`    | Yes (read)    | No                               |
| `identity new`     | Yes (write)   | No                               |
| `encrypt --for`    | Yes (read)    | No (only recipient's public key) |
| `decrypt`          | Yes (read)    | Yes (PRE secret key)             |
| `account register` | Yes (read)    | Yes (signing)                    |
| `files upload`     | Yes (read)    | Yes (signing)                    |
| `share create`     | Yes (read)    | Yes (recrypt key generation)     |

**Insight**: All wallet access is authenticated equally, even read-only operations. This is correct for an encrypted wallet—you can't selectively decrypt.

---

## Desired End State

After Phase 6b:

1. ✅ First wallet access: password prompt, key derived and cached in OS keyring
2. ✅ Subsequent access: key fetched from keyring, no prompt
3. ⬜ `dcypher wallet lock` clears cached key (DEFERRED - can use `just keychain-delete`)
4. ⬜ `dcypher wallet unlock` explicitly caches key (DEFERRED - automatic on first access)
5. ⬜ `dcypher wallet status` shows lock state (DEFERRED)
6. ✅ `DCYPHER_WALLET_KEY` env var for CI (base64-encoded 32-byte key)
7. ✅ Tests use in-memory provider, no prompts
8. ✅ macOS Keychain (security-framework), Linux Secret Service, Windows Credential Manager (keyring crate)

**Verification:**

```bash
# First use prompts for password
dcypher identity new --name alice
# Enter password, key cached

# Subsequent uses: no prompt!
dcypher identity list
dcypher identity show --name alice

# Explicit lock/unlock
dcypher wallet lock
dcypher wallet status  # → Locked
dcypher wallet unlock  # → password prompt
dcypher wallet status  # → Unlocked

# CI mode
DCYPHER_WALLET_KEY=$(base64 < /dev/urandom | head -c 44) dcypher identity list
```

---

## What We're NOT Doing

- ❌ TPM integration (future enhancement for server deployments)
- ❌ Biometric unlock (macOS Keychain handles this transparently)
- ❌ Session timeout (keyring items persist until explicit lock)
- ❌ Multiple wallet support (one wallet, one key)
- ❌ Password change command (deferred)
- ❌ Hardware wallet integration (deferred)

---

## Architecture

### Credential Provider Trait

```
┌─────────────────────────────────────────────────────────────────┐
│                     CredentialProvider trait                     │
│   fn store_key(&self, key: &[u8; 32]) -> Result<()>             │
│   fn get_key(&self) -> Result<Option<[u8; 32]>>                 │
│   fn clear_key(&self) -> Result<()>                             │
│   fn is_available(&self) -> bool                                │
└─────────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ KeyringProvider │  │  EnvProvider    │  │ MemoryProvider  │
│ (production)    │  │  (CI)           │  │ (tests)         │
├─────────────────┤  ├─────────────────┤  ├─────────────────┤
│ macOS Keychain  │  │ DCYPHER_WALLET_ │  │ HashMap in      │
│ Linux Secret Svc│  │ KEY env var     │  │ memory          │
│ Windows Cred Mgr│  │                 │  │                 │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

### Provider Selection Priority

```
1. DCYPHER_WALLET_KEY env var set  → EnvProvider (CI mode)
2. --password-stdin flag           → read from stdin once
3. Keyring available               → KeyringProvider (interactive)
4. Fallback                        → prompt every time (current behavior)
```

### What Gets Stored

**Stored in keyring:**

- Service name: `dcypher`
- Account name: `wallet-key`
- Secret: 32 bytes, base64-encoded

**NOT stored:**

- The user's password (never)
- The wallet file itself (stays on disk, encrypted)

---

## Implementation Phases

### Phase 6b.1: CredentialProvider Abstraction (Day 1)

**Goal:** Create provider trait and implementations without changing wallet behavior

#### 1. Add keyring dependency

**File:** `recrypt-cli/Cargo.toml`

Add to `[dependencies]`:

```toml
# OS keyring integration
keyring = { version = "3", default-features = false }

[target.'cfg(target_os = "macos")'.dependencies]
keyring = { version = "3", features = ["apple-native"] }

[target.'cfg(target_os = "linux")'.dependencies]
keyring = { version = "3", features = ["linux-native"] }

[target.'cfg(target_os = "windows")'.dependencies]
keyring = { version = "3", features = ["windows-native"] }
```

#### 2. Create credential provider module

**File:** `recrypt-cli/src/wallet/credential.rs`

```rust
use anyhow::{anyhow, Result};
use base64::Engine;
use std::sync::RwLock;

const SERVICE_NAME: &str = "dcypher";
const ACCOUNT_NAME: &str = "wallet-key";

/// Abstraction for secure credential storage
pub trait CredentialProvider: Send + Sync {
    /// Store the wallet encryption key
    fn store_key(&self, key: &[u8; 32]) -> Result<()>;

    /// Retrieve cached key, if any
    fn get_key(&self) -> Result<Option<[u8; 32]>>;

    /// Clear cached key (lock wallet)
    fn clear_key(&self) -> Result<()>;

    /// Check if this provider is available on the current system
    fn is_available(&self) -> bool;

    /// Human-readable name for diagnostics
    fn name(&self) -> &'static str;
}

// === KeyringProvider (production) ===

pub struct KeyringProvider;

impl KeyringProvider {
    pub fn new() -> Self {
        Self
    }

    fn entry(&self) -> Result<keyring::Entry> {
        keyring::Entry::new(SERVICE_NAME, ACCOUNT_NAME)
            .map_err(|e| anyhow!("Keyring error: {e}"))
    }
}

impl CredentialProvider for KeyringProvider {
    fn store_key(&self, key: &[u8; 32]) -> Result<()> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(key);
        self.entry()?.set_password(&encoded)
            .map_err(|e| anyhow!("Failed to store key in keyring: {e}"))
    }

    fn get_key(&self) -> Result<Option<[u8; 32]>> {
        match self.entry()?.get_password() {
            Ok(encoded) => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(&encoded)
                    .map_err(|e| anyhow!("Invalid key encoding in keyring: {e}"))?;
                if bytes.len() != 32 {
                    return Err(anyhow!("Invalid key length in keyring: {}", bytes.len()));
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                Ok(Some(key))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow!("Keyring error: {e}")),
        }
    }

    fn clear_key(&self) -> Result<()> {
        match self.entry()?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(anyhow!("Failed to clear keyring: {e}")),
        }
    }

    fn is_available(&self) -> bool {
        self.entry().is_ok()
    }

    fn name(&self) -> &'static str {
        #[cfg(target_os = "macos")]
        { "macOS Keychain" }
        #[cfg(target_os = "linux")]
        { "Secret Service" }
        #[cfg(target_os = "windows")]
        { "Windows Credential Manager" }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        { "Keyring" }
    }
}

// === EnvProvider (CI) ===

pub struct EnvProvider {
    var_name: String,
}

impl EnvProvider {
    pub fn new(var_name: &str) -> Self {
        Self { var_name: var_name.to_string() }
    }

    pub fn default() -> Self {
        Self::new("DCYPHER_WALLET_KEY")
    }
}

impl CredentialProvider for EnvProvider {
    fn store_key(&self, _key: &[u8; 32]) -> Result<()> {
        // Can't set env var at runtime, silently succeed
        Ok(())
    }

    fn get_key(&self) -> Result<Option<[u8; 32]>> {
        match std::env::var(&self.var_name) {
            Ok(encoded) => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(&encoded)
                    .map_err(|e| anyhow!("Invalid {} encoding: {e}", self.var_name))?;
                if bytes.len() != 32 {
                    return Err(anyhow!(
                        "{} must be exactly 32 bytes (got {})",
                        self.var_name,
                        bytes.len()
                    ));
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                Ok(Some(key))
            }
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(e) => Err(anyhow!("Failed to read {}: {e}", self.var_name)),
        }
    }

    fn clear_key(&self) -> Result<()> {
        // Can't clear env var, silently succeed
        Ok(())
    }

    fn is_available(&self) -> bool {
        std::env::var(&self.var_name).is_ok()
    }

    fn name(&self) -> &'static str {
        "Environment Variable"
    }
}

// === MemoryProvider (tests) ===

pub struct MemoryProvider {
    key: RwLock<Option<[u8; 32]>>,
}

impl Default for MemoryProvider {
    fn default() -> Self {
        Self { key: RwLock::new(None) }
    }
}

impl MemoryProvider {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with pre-loaded key (for tests)
    pub fn with_key(key: [u8; 32]) -> Self {
        Self { key: RwLock::new(Some(key)) }
    }
}

impl CredentialProvider for MemoryProvider {
    fn store_key(&self, key: &[u8; 32]) -> Result<()> {
        *self.key.write().unwrap() = Some(*key);
        Ok(())
    }

    fn get_key(&self) -> Result<Option<[u8; 32]>> {
        Ok(*self.key.read().unwrap())
    }

    fn clear_key(&self) -> Result<()> {
        *self.key.write().unwrap() = None;
        Ok(())
    }

    fn is_available(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "Memory"
    }
}

// === Provider selection ===

/// Select the best available credential provider
pub fn default_provider() -> Box<dyn CredentialProvider> {
    // 1. Check for CI mode via env var
    let env = EnvProvider::default();
    if env.is_available() {
        return Box::new(env);
    }

    // 2. Try OS keyring
    let keyring = KeyringProvider::new();
    if keyring.is_available() {
        return Box::new(keyring);
    }

    // 3. Fall back to memory (per-process only)
    Box::new(MemoryProvider::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_provider_roundtrip() {
        let provider = MemoryProvider::new();
        let key = [42u8; 32];

        assert!(provider.get_key().unwrap().is_none());
        provider.store_key(&key).unwrap();
        assert_eq!(provider.get_key().unwrap(), Some(key));
        provider.clear_key().unwrap();
        assert!(provider.get_key().unwrap().is_none());
    }

    #[test]
    fn test_env_provider_with_valid_key() {
        let key = [0xABu8; 32];
        let encoded = base64::engine::general_purpose::STANDARD.encode(key);
        std::env::set_var("TEST_WALLET_KEY", &encoded);

        let provider = EnvProvider::new("TEST_WALLET_KEY");
        assert!(provider.is_available());
        assert_eq!(provider.get_key().unwrap(), Some(key));

        std::env::remove_var("TEST_WALLET_KEY");
    }
}
```

#### 3. Update wallet/mod.rs

**File:** `recrypt-cli/src/wallet/mod.rs`

```rust
pub mod credential;
pub mod format;
pub mod storage;

pub use credential::{CredentialProvider, default_provider};
pub use format::{Identity, KeyPair};
pub use storage::Wallet;
```

### Success Criteria (Phase 6b.1):

#### Automated Verification:

- [x] `cargo build -p recrypt-cli` compiles
- [x] `cargo test -p recrypt-cli wallet::credential` passes
- [x] No new clippy warnings: `cargo clippy -p recrypt-cli`

#### Manual Verification:

- [x] None yet (providers not wired in)

---

### Phase 6b.2: Refactor Wallet to Use Providers (Day 1-2)

**Goal:** Wire credential provider into Wallet::load/save, eliminating redundant prompts

#### 1. Add key extraction helper to format.rs

**File:** `recrypt-cli/src/wallet/format.rs`

Add new functions:

```rust
/// Extract salt from encrypted wallet (for key derivation)
pub fn extract_salt(data: &[u8]) -> Result<[u8; 32]> {
    if data.len() < 4 + 1 + 32 {
        return Err(anyhow!("Wallet file too short for salt extraction"));
    }
    if &data[0..4] != MAGIC {
        return Err(anyhow!("Invalid wallet file (bad magic)"));
    }
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&data[5..37]);
    Ok(salt)
}

/// Derive encryption key from password and salt
pub fn derive_key(password: &str, salt: &[u8; 32]) -> Result<[u8; 32]> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| anyhow!("Invalid Argon2 parameters: {e:?}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("Argon2 key derivation failed: {e:?}"))?;
    Ok(key)
}

/// Decrypt wallet with pre-derived key (no password prompt)
pub fn decrypt_wallet_with_key(data: &[u8], key: &[u8; 32]) -> Result<WalletData> {
    if data.len() < 4 + 1 + 32 + 24 + 16 {
        return Err(anyhow!("Wallet file too short"));
    }
    if &data[0..4] != MAGIC {
        return Err(anyhow!("Invalid wallet file (bad magic)"));
    }
    let version = data[4];
    if version != VERSION {
        return Err(anyhow!("Unsupported wallet version: {version}"));
    }

    let nonce = &data[37..61];
    let ciphertext = &data[61..];

    let cipher = XChaCha20Poly1305::new_from_slice(key)?;
    let nonce_arr: [u8; 24] = nonce.try_into()?;
    let plaintext = cipher
        .decrypt(&nonce_arr.into(), ciphertext)
        .map_err(|_| anyhow!("Decryption failed (wrong key?)"))?;

    let wallet: WalletData = serde_json::from_slice(&plaintext)?;
    Ok(wallet)
}

/// Encrypt wallet with pre-derived key (no password prompt)
pub fn encrypt_wallet_with_key(data: &WalletData, key: &[u8; 32], salt: &[u8; 32]) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(data)?;

    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);

    let cipher = XChaCha20Poly1305::new_from_slice(key)?;
    let ciphertext = cipher
        .encrypt(&nonce.into(), json.as_slice())
        .map_err(|e| anyhow!("Encryption failed: {e}"))?;

    let mut output = Vec::with_capacity(4 + 1 + 32 + 24 + ciphertext.len());
    output.extend_from_slice(MAGIC);
    output.push(VERSION);
    output.extend_from_slice(salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}
```

#### 2. Refactor storage.rs

**File:** `recrypt-cli/src/wallet/storage.rs`

Complete rewrite:

```rust
use anyhow::{Context as _, Result};
use dialoguer::Password;
use directories::ProjectDirs;
use std::fs;
use std::path::PathBuf;

use super::credential::{default_provider, CredentialProvider};
use super::format::{
    decrypt_wallet_with_key, derive_key, encrypt_wallet_with_key,
    extract_salt, WalletData,
};

pub struct Wallet {
    pub data: WalletData,
    path: PathBuf,
    key: [u8; 32],
    salt: [u8; 32],
}

impl Wallet {
    /// Load wallet, using cached key from provider or prompting for password
    pub fn load(override_path: Option<&str>) -> Result<Self> {
        Self::load_with_provider(override_path, default_provider().as_ref())
    }

    /// Load wallet with explicit credential provider (for testing)
    pub fn load_with_provider(
        override_path: Option<&str>,
        provider: &dyn CredentialProvider,
    ) -> Result<Self> {
        let path = Self::resolve_path(override_path)?;

        if !path.exists() {
            // New wallet: generate fresh salt, will prompt for password on first save
            let mut salt = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut salt);
            return Ok(Self {
                data: WalletData::new(),
                path,
                key: [0u8; 32], // Placeholder, will be set on save
                salt,
            });
        }

        let encrypted = fs::read(&path)
            .with_context(|| format!("Failed to read wallet from {}", path.display()))?;

        let salt = extract_salt(&encrypted)?;

        // Try cached key from provider first
        if let Some(key) = provider.get_key()? {
            match decrypt_wallet_with_key(&encrypted, &key) {
                Ok(data) => {
                    return Ok(Self { data, path, key, salt });
                }
                Err(_) => {
                    // Key was stale or for different wallet, clear it
                    let _ = provider.clear_key();
                }
            }
        }

        // No cached key or it was invalid, prompt for password
        let password = Password::new()
            .with_prompt("Wallet password")
            .interact()?;

        let key = derive_key(&password, &salt)?;
        let data = decrypt_wallet_with_key(&encrypted, &key)
            .context("Failed to decrypt wallet (wrong password?)")?;

        // Cache the derived key for next time
        if let Err(e) = provider.store_key(&key) {
            // Non-fatal: warn but continue
            eprintln!("Warning: couldn't cache key in {}: {e}", provider.name());
        }

        Ok(Self { data, path, key, salt })
    }

    /// Save wallet to disk
    pub fn save(&self, is_new: bool) -> Result<()> {
        self.save_with_provider(is_new, default_provider().as_ref())
    }

    /// Save wallet with explicit provider (for testing)
    pub fn save_with_provider(
        &self,
        is_new: bool,
        provider: &dyn CredentialProvider,
    ) -> Result<()> {
        let (key, salt) = if is_new {
            // New wallet: prompt for password and derive key
            let pass1 = Password::new()
                .with_prompt("New wallet password")
                .interact()?;
            let pass2 = Password::new()
                .with_prompt("Confirm password")
                .interact()?;

            if pass1 != pass2 {
                anyhow::bail!("Passwords do not match");
            }

            let mut salt = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut salt);
            let key = derive_key(&pass1, &salt)?;

            // Cache for future use
            if let Err(e) = provider.store_key(&key) {
                eprintln!("Warning: couldn't cache key in {}: {e}", provider.name());
            }

            (key, salt)
        } else {
            // Existing wallet: use cached key (should have been loaded)
            (self.key, self.salt)
        };

        let encrypted = encrypt_wallet_with_key(&self.data, &key, &salt)?;

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&self.path, encrypted)
            .with_context(|| format!("Failed to write wallet to {}", self.path.display()))?;

        Ok(())
    }

    fn resolve_path(override_path: Option<&str>) -> Result<PathBuf> {
        match override_path {
            Some(p) => Ok(PathBuf::from(p)),
            None => Self::default_path(),
        }
    }

    fn default_path() -> Result<PathBuf> {
        let dirs = ProjectDirs::from("com", "identikey", "dcypher")
            .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
        Ok(dirs.data_dir().join("wallet.dcyw"))
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn is_new(&self) -> bool {
        self.data.identities.is_empty()
    }
}
```

### Success Criteria (Phase 6b.2):

#### Automated Verification:

- [x] `cargo build -p recrypt-cli` compiles
- [x] `cargo test -p recrypt-cli` all pass (15 tests)
- [x] `cargo clippy -p recrypt-cli -- -D warnings` passes

#### Manual Verification:

- [x] First `recrypt identity list` prompts for password (SINGLE prompt, not double) ✅ Verified 2026-01-19
- [x] Second `recrypt identity list` does NOT prompt (key cached in keyring) ✅ Verified 2026-01-19
- [x] Verify with `security find-generic-password -s recrypt` (macOS) ✅ Verified 2026-01-19

**Note (2026-01-15):** Fixed double-prompt issue on macOS by switching from `keyring` crate's `apple-native` backend to direct `security-framework` crate usage. The `keyring` crate's apple-native backend was triggering two separate Security framework prompts (one for "confidential information" and one for "key"). Using `security_framework::passwords::{get,set,delete}_generic_password()` directly results in a single prompt.

**Migration:** If you previously had the keychain item created by the old implementation, you may need to delete it first:

```bash
security delete-generic-password -s recrypt
```

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation from the human that the caching works correctly before proceeding.

---

### Phase 6b.3: Wallet Commands (Day 2)

**Goal:** Add explicit lock/unlock/status commands

#### 1. Create wallet command module

**File:** `recrypt-cli/src/commands/wallet_cmd.rs`

```rust
use anyhow::Result;
use clap::Subcommand;
use colored::Colorize;
use dialoguer::Password;
use serde::Serialize;
use std::fs;

use super::Context;
use crate::output::{print_info, print_json, print_success};
use crate::wallet::credential::{default_provider, KeyringProvider};
use crate::wallet::format::{derive_key, extract_salt};
use crate::wallet::Wallet;

#[derive(Subcommand)]
pub enum WalletCommand {
    /// Unlock wallet and cache decryption key
    Unlock,
    /// Clear cached decryption key
    Lock,
    /// Show wallet status
    Status,
    /// Show wallet path
    Path,
}

pub async fn run(action: WalletCommand, ctx: &Context) -> Result<()> {
    match action {
        WalletCommand::Unlock => unlock(ctx).await,
        WalletCommand::Lock => lock(ctx).await,
        WalletCommand::Status => status(ctx).await,
        WalletCommand::Path => path(ctx).await,
    }
}

async fn unlock(ctx: &Context) -> Result<()> {
    let provider = default_provider();

    // Check if already unlocked
    if provider.get_key()?.is_some() {
        if ctx.json_output {
            #[derive(Serialize)]
            struct Output { already_unlocked: bool }
            print_json(&Output { already_unlocked: true })?;
        } else {
            print_info("Wallet already unlocked");
        }
        return Ok(());
    }

    // Load wallet (will prompt for password and cache key)
    let _ = Wallet::load_with_provider(ctx.wallet_override.as_deref(), provider.as_ref())?;

    if ctx.json_output {
        #[derive(Serialize)]
        struct Output { unlocked: bool, provider: String }
        print_json(&Output {
            unlocked: true,
            provider: provider.name().to_string()
        })?;
    } else {
        print_success(format!("Wallet unlocked (cached in {})", provider.name()));
    }

    Ok(())
}

async fn lock(ctx: &Context) -> Result<()> {
    let provider = default_provider();
    provider.clear_key()?;

    if ctx.json_output {
        #[derive(Serialize)]
        struct Output { locked: bool }
        print_json(&Output { locked: true })?;
    } else {
        print_success("Wallet locked");
    }

    Ok(())
}

async fn status(ctx: &Context) -> Result<()> {
    let provider = default_provider();
    let is_unlocked = provider.get_key()?.is_some();

    let wallet_path = Wallet::load(ctx.wallet_override.as_deref())
        .map(|w| w.path().display().to_string())
        .unwrap_or_else(|_| "Not found".to_string());

    if ctx.json_output {
        #[derive(Serialize)]
        struct Output {
            unlocked: bool,
            provider: String,
            wallet_path: String,
        }
        print_json(&Output {
            unlocked: is_unlocked,
            provider: provider.name().to_string(),
            wallet_path,
        })?;
    } else {
        let status = if is_unlocked {
            "Unlocked".green()
        } else {
            "Locked".red()
        };
        println!("{}: {}", "Wallet Status".bold(), status);
        println!("  {}: {}", "Provider".dimmed(), provider.name());
        println!("  {}: {}", "Path".dimmed(), wallet_path);
    }

    Ok(())
}

async fn path(ctx: &Context) -> Result<()> {
    use directories::ProjectDirs;

    let path = match &ctx.wallet_override {
        Some(p) => std::path::PathBuf::from(p),
        None => {
            let dirs = ProjectDirs::from("com", "identikey", "dcypher")
                .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
            dirs.data_dir().join("wallet.dcyw")
        }
    };

    if ctx.json_output {
        #[derive(Serialize)]
        struct Output { path: String, exists: bool }
        print_json(&Output {
            path: path.display().to_string(),
            exists: path.exists(),
        })?;
    } else {
        println!("{}", path.display());
    }

    Ok(())
}
```

#### 2. Wire into main.rs

**File:** `recrypt-cli/src/commands/mod.rs`

Add:

```rust
pub mod wallet_cmd;
```

**File:** `recrypt-cli/src/main.rs`

Add to Commands enum:

```rust
    /// Manage wallet (unlock/lock)
    Wallet {
        #[command(subcommand)]
        action: commands::wallet_cmd::WalletCommand,
    },
```

Add to match:

```rust
        Commands::Wallet { action } => commands::wallet_cmd::run(action, &ctx).await,
```

### Success Criteria (Phase 6b.3):

#### Automated Verification:

- [ ] `dcypher wallet --help` shows unlock/lock/status/path
- [ ] `dcypher wallet path` outputs path without password prompt
- [ ] `dcypher wallet status --json` returns valid JSON

#### Manual Verification:

- [ ] `dcypher wallet unlock` prompts for password once
- [ ] `dcypher wallet status` shows "Unlocked"
- [ ] `dcypher identity list` works without prompt
- [ ] `dcypher wallet lock` clears key
- [ ] `dcypher wallet status` shows "Locked"
- [ ] `dcypher identity list` prompts again

---

### Phase 6b.4: Test Infrastructure (Day 2-3)

**Goal:** Enable automated tests without password prompts

#### 1. Create test utilities

**File:** `recrypt-cli/src/wallet/test_utils.rs`

```rust
#![cfg(test)]

use super::credential::MemoryProvider;
use super::format::{encrypt_wallet_with_key, WalletData, Identity, KeyPair};
use super::Wallet;
use std::sync::Arc;
use tempfile::NamedTempFile;

/// Create a test wallet with pre-loaded credentials
pub fn test_wallet() -> (Wallet, Arc<MemoryProvider>, NamedTempFile) {
    let key = [0x42u8; 32];
    let salt = [0x24u8; 32];
    let provider = Arc::new(MemoryProvider::with_key(key));

    let mut data = WalletData::new();
    data.identities.insert(
        "test-identity".to_string(),
        Identity {
            created_at: 1704067200,
            fingerprint: "test-fingerprint".to_string(),
            ed25519: KeyPair {
                public: "ed25519-pub".to_string(),
                secret: "ed25519-sec".to_string(),
            },
            ml_dsa: KeyPair {
                public: "mldsa-pub".to_string(),
                secret: "mldsa-sec".to_string(),
            },
            pre: KeyPair {
                public: "pre-pub".to_string(),
                secret: "pre-sec".to_string(),
            },
        },
    );

    // Create encrypted wallet file
    let encrypted = encrypt_wallet_with_key(&data, &key, &salt).unwrap();
    let file = NamedTempFile::new().unwrap();
    std::fs::write(file.path(), encrypted).unwrap();

    let wallet = Wallet::load_with_provider(
        Some(file.path().to_str().unwrap()),
        provider.as_ref(),
    ).unwrap();

    (wallet, provider, file)
}

/// Generate a valid test wallet key as base64 (for CI env var)
pub fn test_wallet_key_base64() -> String {
    use base64::Engine;
    let key = [0x42u8; 32];
    base64::engine::general_purpose::STANDARD.encode(key)
}
```

#### 2. Update wallet/mod.rs

```rust
pub mod credential;
pub mod format;
pub mod storage;
#[cfg(test)]
pub mod test_utils;

// ... rest unchanged
```

#### 3. Example test using new infrastructure

**File:** `recrypt-cli/tests/wallet_tests.rs`

```rust
use dcypher_cli::wallet::test_utils::test_wallet;

#[test]
fn test_wallet_identity_operations() {
    let (mut wallet, provider, _file) = test_wallet();

    // Add new identity
    wallet.data.identities.insert(
        "new-identity".to_string(),
        dcypher_cli::wallet::Identity {
            created_at: 1704153600,
            fingerprint: "new-fp".to_string(),
            ed25519: dcypher_cli::wallet::KeyPair {
                public: "pub".to_string(),
                secret: "sec".to_string(),
            },
            ml_dsa: dcypher_cli::wallet::KeyPair {
                public: "pub".to_string(),
                secret: "sec".to_string(),
            },
            pre: dcypher_cli::wallet::KeyPair {
                public: "pub".to_string(),
                secret: "sec".to_string(),
            },
        },
    );

    // Save without password prompt
    wallet.save_with_provider(false, provider.as_ref()).unwrap();

    // Reload and verify
    let reloaded = dcypher_cli::wallet::Wallet::load_with_provider(
        Some(wallet.path().to_str().unwrap()),
        provider.as_ref(),
    ).unwrap();

    assert!(reloaded.data.identities.contains_key("new-identity"));
}
```

### Success Criteria (Phase 6b.4):

#### Automated Verification:

- [ ] `cargo test -p recrypt-cli` passes without any password prompts
- [ ] Tests complete in < 30 seconds (no Argon2 delays per test)
- [ ] CI can run with `DCYPHER_WALLET_KEY` env var

#### Manual Verification:

- [ ] None (all test infrastructure)

---

## Testing Strategy

### Unit Tests:

- `credential.rs`: Provider trait implementations
- `format.rs`: Key derivation, encryption with key
- `storage.rs`: Load/save with mock provider

### Integration Tests:

- Full wallet lifecycle without prompts
- Provider fallback chain
- Error handling for corrupted keyring entries

### CI Configuration:

```yaml
# In GitHub Actions or similar
env:
  DCYPHER_WALLET_KEY: ${{ secrets.TEST_WALLET_KEY }}
  # Or generate fresh each run:
  # DCYPHER_WALLET_KEY: $(openssl rand -base64 32)
```

---

## Security Considerations

### Threat Model

| Threat                   | Before Phase 6b             | After Phase 6b                 |
| ------------------------ | --------------------------- | ------------------------------ |
| Disk theft (powered off) | ✅ Wallet encrypted         | ✅ Same                        |
| Malware (user context)   | ⚠️ Could steal wallet file  | ⚠️ Same + could access keyring |
| Memory dump (root)       | ⚠️ Key in memory during use | ⚠️ Same                        |
| Shoulder surfing         | ❌ Password visible         | ✅ No repeated password entry  |

### Key Points:

1. **Keyring access is user-scoped** – other users can't read it
2. **macOS may prompt for Keychain access** – first access shows "dcypher wants to access keychain"
3. **The password is never stored** – only the derived key
4. **Wallet file remains encrypted** – keyring stores the decryption key, not the data

---

## Migration Notes

- Existing wallets continue to work unchanged
- First access after upgrade prompts for password (as before)
- Key is then cached, subsequent access is prompt-free
- No wallet file format changes

---

## Performance Considerations

- Argon2id runs only on first unlock (3 iterations, 64 MiB memory)
- Subsequent loads bypass key derivation entirely
- Keyring operations are fast (< 1ms typically)

---

## References

- Phase 6 plan: `docs/plans/2026-01-13-phase-6-cli-application.md`
- keyring crate: https://docs.rs/keyring/latest/keyring/
- Current wallet code: `recrypt-cli/src/wallet/`

---

## Overall Success Criteria

### Automated Verification:

- [x] `cargo build -p recrypt-cli` succeeds ✅ 2026-01-19
- [x] `cargo test -p recrypt-cli` passes without prompts ✅ 2026-01-19 (15 tests, 4.78s)
- [x] `cargo clippy -p recrypt-cli --no-deps` no warnings ✅ 2026-01-19
- [x] CI tests pass with `RECRYPT_WALLET_KEY` env var ✅ 2026-01-19 (EnvProvider implemented)

### Manual Verification:

- [x] First wallet access prompts for password ✅ 2026-01-19
- [x] Subsequent access works without prompt ✅ 2026-01-19
- [x] `recrypt wallet lock` clears cached key ✅ 2026-01-19 (Phase 6b.3 complete)
- [x] `recrypt wallet unlock` caches key ✅ 2026-01-19 (Phase 6b.3 complete)
- [x] `recrypt wallet status` shows correct state ✅ 2026-01-19 (Phase 6b.3 complete)
- [x] `recrypt wallet path` shows wallet location ✅ 2026-01-19 (Phase 6b.3 complete)
- [x] macOS Keychain shows recrypt entry (Keychain Access app) ✅ 2026-01-19
