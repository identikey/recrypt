use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAGIC: &[u8; 5] = b"IKEYW";
const VERSION: u8 = 1;

// Argon2 params (OWASP recommendations)
const ARGON2_M_COST: u32 = 65536; // 64 MiB
const ARGON2_T_COST: u32 = 3; // 3 iterations
const ARGON2_P_COST: u32 = 4; // 4 parallelism

#[derive(Serialize, Deserialize, Debug)]
pub struct WalletData {
    pub version: u8,
    pub identities: HashMap<String, Identity>,
    /// Active identity name — lives in the wallet, single source of truth.
    #[serde(default)]
    pub active_identity: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Identity {
    pub created_at: u64,
    /// Blake3(ed25519_public). Raw bytes; encode with bs58 for display/wire.
    pub fingerprint: [u8; 32],
    pub ed25519: KeyPair,
    pub ml_dsa: KeyPair,
    pub pre: KeyPair,
    /// PRE backend used for this identity (defaults to "mock" for backward compat)
    #[serde(default = "default_backend")]
    pub pre_backend: recrypt_core::pre::BackendId,
}

fn default_backend() -> recrypt_core::pre::BackendId {
    recrypt_core::pre::BackendId::Mock
}

#[derive(Serialize, Deserialize, Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct KeyPair {
    #[zeroize(skip)]
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

impl WalletData {
    pub fn new() -> Self {
        Self {
            version: 1,
            identities: HashMap::new(),
            active_identity: None,
        }
    }
}

impl Default for WalletData {
    fn default() -> Self {
        Self::new()
    }
}

/// Encrypt wallet with password (for tests and backward compat)
#[cfg(test)]
pub fn encrypt_wallet(data: &WalletData, password: &str) -> Result<Vec<u8>> {
    let json = zeroize::Zeroizing::new(serde_json::to_vec(data)?);

    // Generate salt and nonce
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);

    // Derive key with Argon2id
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| anyhow!("Invalid Argon2 parameters: {e:?}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| anyhow!("Argon2 key derivation failed: {e:?}"))?;

    // Encrypt with XChaCha20-Poly1305
    let cipher = XChaCha20Poly1305::new_from_slice(&key)?;
    let ciphertext = cipher
        .encrypt(&nonce.into(), json.as_slice())
        .map_err(|e| anyhow!("Encryption failed: {e}"))?;

    // Assemble: magic || version || salt || nonce || ciphertext (includes tag)
    let mut output = Vec::with_capacity(5 + 1 + 32 + 24 + ciphertext.len());
    output.extend_from_slice(MAGIC);
    output.push(VERSION);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Decrypt wallet with password (for tests and backward compat)
#[cfg(test)]
pub fn decrypt_wallet(data: &[u8], password: &str) -> Result<WalletData> {
    let salt = extract_salt(data)?;
    let key = derive_key(password, &salt)?;
    decrypt_wallet_with_key(data, &key)
}

/// Extract salt from encrypted wallet header (for key derivation)
pub fn extract_salt(data: &[u8]) -> Result<[u8; 32]> {
    if data.len() < 5 + 1 + 32 {
        return Err(anyhow!("Wallet file too short for salt extraction"));
    }
    if &data[0..5] != MAGIC {
        return Err(anyhow!("Invalid wallet file (bad magic)"));
    }
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&data[6..38]);
    Ok(salt)
}

/// Derive encryption key from password and salt using Argon2id
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

/// Decrypt wallet with pre-derived key (no password prompt needed)
pub fn decrypt_wallet_with_key(data: &[u8], key: &[u8; 32]) -> Result<WalletData> {
    if data.len() < 5 + 1 + 32 + 24 + 16 {
        return Err(anyhow!("Wallet file too short"));
    }
    if &data[0..5] != MAGIC {
        return Err(anyhow!("Invalid wallet file (bad magic)"));
    }
    let version = data[5];
    if version != VERSION {
        return Err(anyhow!("Unsupported wallet version: {version}"));
    }

    let nonce = &data[38..62];
    let ciphertext = &data[62..];

    let cipher = XChaCha20Poly1305::new_from_slice(key)?;
    let nonce_arr: [u8; 24] = nonce.try_into()?;
    let plaintext = zeroize::Zeroizing::new(
        cipher
            .decrypt(&nonce_arr.into(), ciphertext)
            .map_err(|_| anyhow!("Decryption failed (wrong key?)"))?,
    );

    let wallet: WalletData = serde_json::from_slice(&plaintext)?;
    Ok(wallet)
}

/// Encrypt wallet with pre-derived key and salt (no password prompt needed)
pub fn encrypt_wallet_with_key(
    data: &WalletData,
    key: &[u8; 32],
    salt: &[u8; 32],
) -> Result<Vec<u8>> {
    let json = zeroize::Zeroizing::new(serde_json::to_vec(data)?);

    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);

    let cipher = XChaCha20Poly1305::new_from_slice(key)?;
    let ciphertext = cipher
        .encrypt(&nonce.into(), json.as_slice())
        .map_err(|e| anyhow!("Encryption failed: {e}"))?;

    let mut output = Vec::with_capacity(5 + 1 + 32 + 24 + ciphertext.len());
    output.extend_from_slice(MAGIC);
    output.push(VERSION);
    output.extend_from_slice(salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_encryption_roundtrip() {
        let mut wallet = WalletData::new();
        wallet.identities.insert(
            "test".to_string(),
            Identity {
                created_at: 1704067200,
                fingerprint: [0u8; 32],
                ed25519: KeyPair {
                    public: b"test-pub".to_vec(),
                    secret: b"test-sec".to_vec(),
                },
                ml_dsa: KeyPair {
                    public: b"test-pub".to_vec(),
                    secret: b"test-sec".to_vec(),
                },
                pre: KeyPair {
                    public: b"test-pub".to_vec(),
                    secret: b"test-sec".to_vec(),
                },
                pre_backend: recrypt_core::pre::BackendId::Mock,
            },
        );

        let password = "test-password-123";
        let encrypted = encrypt_wallet(&wallet, password).unwrap();
        let decrypted = decrypt_wallet(&encrypted, password).unwrap();

        assert_eq!(wallet.version, decrypted.version);
        assert_eq!(wallet.identities.len(), decrypted.identities.len());
    }

    #[test]
    fn test_wrong_password_fails() {
        let wallet = WalletData::new();
        let encrypted = encrypt_wallet(&wallet, "correct-password").unwrap();
        let result = decrypt_wallet(&encrypted, "wrong-password");

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("wrong key"));
    }

    #[test]
    fn test_invalid_magic_fails() {
        let wallet = WalletData::new();
        let mut encrypted = encrypt_wallet(&wallet, "password").unwrap();
        encrypted[0] = b'X'; // Corrupt magic bytes

        let result = decrypt_wallet(&encrypted, "password");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("bad magic"));
    }

    #[test]
    fn test_extract_salt() {
        let wallet = WalletData::new();
        let encrypted = encrypt_wallet(&wallet, "password").unwrap();
        let salt = extract_salt(&encrypted).unwrap();
        assert_eq!(salt.len(), 32);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let salt = [0x42u8; 32];
        let key1 = derive_key("password", &salt).unwrap();
        let key2 = derive_key("password", &salt).unwrap();
        assert_eq!(key1, key2);

        let key3 = derive_key("different", &salt).unwrap();
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_encrypt_decrypt_with_key() {
        let mut wallet = WalletData::new();
        wallet.identities.insert(
            "test".to_string(),
            Identity {
                created_at: 1704067200,
                fingerprint: [0u8; 32],
                ed25519: KeyPair {
                    public: b"ed-pub".to_vec(),
                    secret: b"ed-sec".to_vec(),
                },
                ml_dsa: KeyPair {
                    public: b"ml-pub".to_vec(),
                    secret: b"ml-sec".to_vec(),
                },
                pre: KeyPair {
                    public: b"pre-pub".to_vec(),
                    secret: b"pre-sec".to_vec(),
                },
                pre_backend: recrypt_core::pre::BackendId::Mock,
            },
        );

        let key = [0xABu8; 32];
        let salt = [0xCDu8; 32];

        let encrypted = encrypt_wallet_with_key(&wallet, &key, &salt).unwrap();
        let decrypted = decrypt_wallet_with_key(&encrypted, &key).unwrap();

        assert_eq!(wallet.identities.len(), decrypted.identities.len());
        assert!(decrypted.identities.contains_key("test"));
    }
}
