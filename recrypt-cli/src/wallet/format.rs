use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use bc_envelope::Envelope;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305,
};
use rand::RngCore;
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::envelope;

const MAGIC: &[u8; 5] = b"IKEYW";
const VERSION: u8 = 2;

/// Error message for v1 wallets — exact string per wallet-envelope-format.md §7.
const V1_REJECTION_MSG: &str =
    "Wallet format v1 is no longer supported. Create a new wallet with `recrypt identity new`.";

// Argon2 params (OWASP recommendations)
const ARGON2_M_COST: u32 = 65536; // 64 MiB
const ARGON2_T_COST: u32 = 3; // 3 iterations
const ARGON2_P_COST: u32 = 4; // 4 parallelism

#[derive(Debug, ZeroizeOnDrop)]
pub struct WalletData {
    #[zeroize(skip)]
    pub identities: HashMap<String, Identity>,
    /// Active identity name — lives in the wallet, single source of truth.
    #[zeroize(skip)]
    pub active_identity: Option<String>,
    /// Wallet-level assertions whose predicates are not in `KNOWN_PREDICATES`.
    /// Preserved verbatim across decode/encode so additive spec extensions
    /// (§8 forward-compat) survive a load+save round-trip.
    #[zeroize(skip)]
    pub unknown_assertions: Vec<(Envelope, Envelope)>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, ZeroizeOnDrop)]
pub struct Identity {
    #[zeroize(skip)]
    pub created_at: u64,
    /// Blake3(ed25519_public). Raw bytes; encode with bs58 for display/wire.
    #[zeroize(skip)]
    pub fingerprint: [u8; 32],
    pub ed25519: KeyPair,
    pub ml_dsa: KeyPair,
    pub pre: KeyPair,
    #[zeroize(skip)]
    pub pre_backend: recrypt_core::pre::BackendId,
    /// Identity-level assertions not in the wire crate's `KNOWN_PREDICATES`.
    /// Round-tripped through `recrypt_wire::Identity::unknown_assertions` so
    /// additive spec extensions survive a wallet load+save (§8 forward-compat).
    #[serde(skip)]
    #[zeroize(skip)]
    pub unknown_assertions: Vec<(Envelope, Envelope)>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct KeyPair {
    #[zeroize(skip)]
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

impl WalletData {
    pub fn new() -> Self {
        Self {
            identities: HashMap::new(),
            active_identity: None,
            unknown_assertions: Vec::new(),
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
    let plaintext = zeroize::Zeroizing::new(envelope::to_envelope(data)?);

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
        .encrypt(&nonce.into(), plaintext.as_slice())
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

/// Extract salt from encrypted wallet header (for key derivation).
///
/// Also checks the magic and version bytes, returning the spec'd error
/// for v1 wallets so callers can avoid wasting an Argon2 derivation.
pub fn extract_salt(data: &[u8]) -> Result<[u8; 32]> {
    if data.len() < 5 + 1 + 32 {
        return Err(anyhow!("Wallet file too short for salt extraction"));
    }
    if &data[0..5] != MAGIC {
        return Err(anyhow!("Invalid wallet file (bad magic)"));
    }
    let version = data[5];
    if version == 1 {
        return Err(anyhow!(V1_REJECTION_MSG));
    }
    if version != VERSION {
        return Err(anyhow!("Unsupported wallet version: {version}"));
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
    if version == 1 {
        return Err(anyhow!(V1_REJECTION_MSG));
    }
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

    envelope::from_envelope(&plaintext)
}

/// Encrypt wallet with pre-derived key and salt (no password prompt needed)
pub fn encrypt_wallet_with_key(
    data: &WalletData,
    key: &[u8; 32],
    salt: &[u8; 32],
) -> Result<Vec<u8>> {
    let plaintext = zeroize::Zeroizing::new(envelope::to_envelope(data)?);

    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);

    let cipher = XChaCha20Poly1305::new_from_slice(key)?;
    let ciphertext = cipher
        .encrypt(&nonce.into(), plaintext.as_slice())
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
pub(crate) fn test_identity(seed: u8) -> Identity {
    let ed_public = vec![seed; 32];
    let fingerprint = *blake3::hash(&ed_public).as_bytes();
    Identity {
        created_at: 1_704_067_200,
        fingerprint,
        ed25519: KeyPair {
            public: ed_public,
            secret: vec![seed.wrapping_add(1); 32],
        },
        ml_dsa: KeyPair {
            public: vec![seed.wrapping_add(2); 16],
            secret: vec![seed.wrapping_add(3); 32],
        },
        pre: KeyPair {
            public: vec![seed.wrapping_add(4); 8],
            secret: vec![seed.wrapping_add(5); 16],
        },
        pre_backend: recrypt_core::pre::BackendId::Mock,
        unknown_assertions: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_encryption_roundtrip() {
        let mut wallet = WalletData::new();
        wallet
            .identities
            .insert("test".to_string(), test_identity(1));

        let password = "test-password-123";
        let encrypted = encrypt_wallet(&wallet, password).unwrap();
        let decrypted = decrypt_wallet(&encrypted, password).unwrap();

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
        wallet
            .identities
            .insert("test".to_string(), test_identity(7));

        let key = [0xABu8; 32];
        let salt = [0xCDu8; 32];

        let encrypted = encrypt_wallet_with_key(&wallet, &key, &salt).unwrap();
        let decrypted = decrypt_wallet_with_key(&encrypted, &key).unwrap();

        assert_eq!(wallet.identities.len(), decrypted.identities.len());
        assert!(decrypted.identities.contains_key("test"));
    }

    #[test]
    fn test_v1_wallet_rejected_with_spec_string() {
        // Build a v1-byte wallet header (magic + version=1 + zeroed salt/nonce/16B tag).
        let mut data = Vec::new();
        data.extend_from_slice(MAGIC);
        data.push(1u8);
        data.extend_from_slice(&[0u8; 32]); // salt
        data.extend_from_slice(&[0u8; 24]); // nonce
        data.extend_from_slice(&[0u8; 16]); // ciphertext (any 16+ bytes)

        let result = decrypt_wallet_with_key(&data, &[0u8; 32]);
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert_eq!(
            msg,
            "Wallet format v1 is no longer supported. Create a new wallet with `recrypt identity new`."
        );

        // Same check via the salt-extract pre-Argon2 fast path.
        let result = extract_salt(&data);
        let msg = result.unwrap_err().to_string();
        assert_eq!(
            msg,
            "Wallet format v1 is no longer supported. Create a new wallet with `recrypt identity new`."
        );
    }

    #[test]
    fn test_unknown_version_rejected() {
        let mut data = Vec::new();
        data.extend_from_slice(MAGIC);
        data.push(99u8);
        data.extend_from_slice(&[0u8; 32]);
        data.extend_from_slice(&[0u8; 24]);
        data.extend_from_slice(&[0u8; 16]);

        let err = decrypt_wallet_with_key(&data, &[0u8; 32]).unwrap_err();
        assert_eq!(err.to_string(), "Unsupported wallet version: 99");

        let err = extract_salt(&data).unwrap_err();
        assert_eq!(err.to_string(), "Unsupported wallet version: 99");
    }

    #[test]
    fn test_active_identity_preserved_through_aead() {
        let mut wallet = WalletData::new();
        wallet
            .identities
            .insert("alice".to_string(), test_identity(10));
        wallet
            .identities
            .insert("bob".to_string(), test_identity(20));
        wallet.active_identity = Some("bob".to_string());

        let key = [0x33u8; 32];
        let salt = [0x44u8; 32];
        let encrypted = encrypt_wallet_with_key(&wallet, &key, &salt).unwrap();
        let decrypted = decrypt_wallet_with_key(&encrypted, &key).unwrap();

        assert_eq!(decrypted.active_identity, Some("bob".to_string()));
        assert_eq!(decrypted.identities.len(), 2);
    }

    #[test]
    fn test_tampered_ciphertext_fails_aead() {
        let mut wallet = WalletData::new();
        wallet
            .identities
            .insert("alice".to_string(), test_identity(50));
        let key = [0x12u8; 32];
        let salt = [0x34u8; 32];
        let mut encrypted = encrypt_wallet_with_key(&wallet, &key, &salt).unwrap();
        // Flip a bit in the ciphertext (after header bytes 0..62).
        encrypted[80] ^= 0x01;
        let err = decrypt_wallet_with_key(&encrypted, &key).unwrap_err();
        assert!(err.to_string().contains("Decryption failed"));
    }
}
