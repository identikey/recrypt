//! Secure credential storage abstraction for wallet encryption keys.
//!
//! Provides trait-based abstraction over OS-native keychains (macOS Keychain,
//! Linux Secret Service, Windows Credential Manager) with fallbacks for CI
//! environments and testing.

use anyhow::{anyhow, Result};
use base64::Engine;
use std::sync::RwLock;

const SERVICE_NAME: &str = "recrypt";

/// Derive a wallet-specific account name for the keychain.
/// Uses a truncated blake3 hash of the canonical wallet path so different
/// wallets get separate keychain entries and don't stomp each other.
pub fn account_name_for_wallet(wallet_path: &std::path::Path) -> String {
    let canonical = wallet_path
        .canonicalize()
        .unwrap_or_else(|_| wallet_path.to_path_buf());
    let hash = blake3::hash(canonical.to_string_lossy().as_bytes());
    format!("wallet-key-{}", &hash.to_hex()[..16])
}

/// Legacy account name for backward compat with existing keychain entries.
const LEGACY_ACCOUNT_NAME: &str = "wallet-key";

/// Abstraction for secure credential storage.
///
/// Implementations cache the 32-byte wallet encryption key (derived from
/// the user's password via Argon2id) so subsequent wallet access doesn't
/// require re-entering the password.
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

// === macOS: Direct Security Framework access (avoids double prompts) ===

#[cfg(target_os = "macos")]
pub struct MacOSKeychainProvider {
    account_name: String,
}

#[cfg(target_os = "macos")]
impl MacOSKeychainProvider {
    pub fn new(wallet_path: &std::path::Path) -> Self {
        Self {
            account_name: account_name_for_wallet(wallet_path),
        }
    }

    /// Create with the legacy singleton account name (for migration).
    pub fn legacy() -> Self {
        Self {
            account_name: LEGACY_ACCOUNT_NAME.to_string(),
        }
    }
}

#[cfg(target_os = "macos")]
impl CredentialProvider for MacOSKeychainProvider {
    fn store_key(&self, key: &[u8; 32]) -> Result<()> {
        use security_framework::passwords::{delete_generic_password, set_generic_password};

        let encoded = base64::engine::general_purpose::STANDARD.encode(key);

        // Delete existing entry first (set_generic_password fails if entry exists)
        let _ = delete_generic_password(SERVICE_NAME, &self.account_name);

        set_generic_password(SERVICE_NAME, &self.account_name, encoded.as_bytes())
            .map_err(|e| anyhow!("Failed to store key in Keychain: {e}"))
    }

    fn get_key(&self) -> Result<Option<[u8; 32]>> {
        use security_framework::passwords::get_generic_password;

        match get_generic_password(SERVICE_NAME, &self.account_name) {
            Ok(data) => {
                let encoded = String::from_utf8(data)
                    .map_err(|e| anyhow!("Invalid UTF-8 in keychain: {e}"))?;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(&encoded)
                    .map_err(|e| anyhow!("Invalid key encoding in keychain: {e}"))?;
                if bytes.len() != 32 {
                    return Err(anyhow!("Invalid key length in keychain: {}", bytes.len()));
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                Ok(Some(key))
            }
            Err(e) if e.code() == -25300 => Ok(None), // errSecItemNotFound
            Err(e) => Err(anyhow!("Keychain error: {e}")),
        }
    }

    fn clear_key(&self) -> Result<()> {
        use security_framework::passwords::delete_generic_password;

        match delete_generic_password(SERVICE_NAME, &self.account_name) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == -25300 => Ok(()), // errSecItemNotFound
            Err(e) => Err(anyhow!("Failed to clear keychain: {e}")),
        }
    }

    fn is_available(&self) -> bool {
        true // Keychain is always available on macOS
    }

    fn name(&self) -> &'static str {
        "macOS Keychain"
    }
}

// === KeyringProvider (Linux/Windows) ===

#[cfg(not(target_os = "macos"))]
pub struct KeyringProvider {
    account_name: String,
}

#[cfg(not(target_os = "macos"))]
impl KeyringProvider {
    pub fn new(wallet_path: &std::path::Path) -> Self {
        Self {
            account_name: account_name_for_wallet(wallet_path),
        }
    }

    /// Create with the legacy singleton account name (for migration).
    pub fn legacy() -> Self {
        Self {
            account_name: LEGACY_ACCOUNT_NAME.to_string(),
        }
    }

    fn entry(&self) -> Result<keyring::Entry> {
        keyring::Entry::new(SERVICE_NAME, &self.account_name)
            .map_err(|e| anyhow!("Keyring error: {e}"))
    }
}

#[cfg(not(target_os = "macos"))]
impl CredentialProvider for KeyringProvider {
    fn store_key(&self, key: &[u8; 32]) -> Result<()> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(key);
        self.entry()?
            .set_password(&encoded)
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
        #[cfg(target_os = "linux")]
        {
            "Secret Service"
        }
        #[cfg(target_os = "windows")]
        {
            "Windows Credential Manager"
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            "Keyring"
        }
    }
}

// === EnvProvider (CI) ===

/// Environment variable provider for CI/testing.
///
/// Reads `RECRYPT_WALLET_KEY` (or custom var) as base64-encoded 32-byte key.
/// Cannot store or clear keys (env vars are read-only at runtime).
pub struct EnvProvider {
    var_name: String,
}

impl EnvProvider {
    pub fn new(var_name: &str) -> Self {
        Self {
            var_name: var_name.to_string(),
        }
    }
}

impl Default for EnvProvider {
    fn default() -> Self {
        Self::new("RECRYPT_WALLET_KEY")
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

/// In-memory provider for tests.
///
/// Key lives only for process lifetime. Thread-safe via RwLock.
pub struct MemoryProvider {
    key: RwLock<Option<[u8; 32]>>,
}

impl Default for MemoryProvider {
    fn default() -> Self {
        Self {
            key: RwLock::new(None),
        }
    }
}

impl MemoryProvider {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with pre-loaded key (for tests)
    #[cfg(test)]
    pub fn with_key(key: [u8; 32]) -> Self {
        Self {
            key: RwLock::new(Some(key)),
        }
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

/// Select the best available credential provider for a given wallet path.
///
/// The keychain entry is keyed by the wallet path hash, so different wallets
/// get separate cached keys and don't stomp each other.
///
/// Priority:
/// 1. `RECRYPT_WALLET_KEY` env var (CI mode)
/// 2. OS keyring (interactive use, wallet-specific entry)
/// 3. Memory fallback (per-process only, for headless systems without keyring)
pub fn default_provider_for(wallet_path: &std::path::Path) -> Box<dyn CredentialProvider> {
    // 0. Check for no-keychain mode (testing/CI without keychain access)
    if std::env::var("RECRYPT_NO_KEYCHAIN").is_ok() {
        return Box::new(MemoryProvider::new());
    }

    // 1. Check for CI mode via env var
    let env = EnvProvider::default();
    if env.is_available() {
        return Box::new(env);
    }

    // 2. macOS: use security-framework directly (single prompt, not double)
    #[cfg(target_os = "macos")]
    {
        Box::new(MacOSKeychainProvider::new(wallet_path))
    }

    // 3. Windows: use keyring crate
    #[cfg(target_os = "windows")]
    {
        Box::new(KeyringProvider::new(wallet_path))
    }

    // 4. Linux: check if Secret Service is available; fall back to memory if not
    #[cfg(target_os = "linux")]
    {
        let keyring = KeyringProvider::new(wallet_path);
        if keyring.is_available() {
            Box::new(keyring)
        } else {
            Box::new(MemoryProvider::new())
        }
    }

    // 5. Other platforms: memory only
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = wallet_path;
        Box::new(MemoryProvider::new())
    }
}

/// Legacy provider selection (singleton keychain entry).
/// Used only for migration — tries the old "wallet-key" entry.
#[allow(dead_code)]
pub fn legacy_provider() -> Box<dyn CredentialProvider> {
    #[cfg(target_os = "macos")]
    {
        Box::new(MacOSKeychainProvider::legacy())
    }

    #[cfg(not(target_os = "macos"))]
    {
        Box::new(KeyringProvider::legacy())
    }
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
    fn test_memory_provider_with_preloaded_key() {
        let key = [0xDEu8; 32];
        let provider = MemoryProvider::with_key(key);
        assert_eq!(provider.get_key().unwrap(), Some(key));
    }

    #[test]
    fn test_env_provider_with_valid_key() {
        let key = [0xABu8; 32];
        let encoded = base64::engine::general_purpose::STANDARD.encode(key);
        // Use a unique var name to avoid test interference
        std::env::set_var("TEST_RECRYPT_WALLET_KEY_VALID", &encoded);

        let provider = EnvProvider::new("TEST_RECRYPT_WALLET_KEY_VALID");
        assert!(provider.is_available());
        assert_eq!(provider.get_key().unwrap(), Some(key));

        std::env::remove_var("TEST_RECRYPT_WALLET_KEY_VALID");
    }

    #[test]
    fn test_env_provider_missing_var() {
        let provider = EnvProvider::new("NONEXISTENT_VAR_12345");
        assert!(!provider.is_available());
        assert!(provider.get_key().unwrap().is_none());
    }

    #[test]
    fn test_env_provider_invalid_length() {
        let short_key = [0u8; 16]; // Only 16 bytes, should fail
        let encoded = base64::engine::general_purpose::STANDARD.encode(short_key);
        std::env::set_var("TEST_RECRYPT_WALLET_KEY_SHORT", &encoded);

        let provider = EnvProvider::new("TEST_RECRYPT_WALLET_KEY_SHORT");
        let result = provider.get_key();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32 bytes"));

        std::env::remove_var("TEST_RECRYPT_WALLET_KEY_SHORT");
    }
}
