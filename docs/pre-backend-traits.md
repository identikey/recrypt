> **Historical:** original design sketch. Code examples below show the
> pre-streaming `EncryptedFile` layout (with inline `bao_outboard`). As of
> the 2026-04-06 streaming sprint the outboard is a sibling storage object
> (`{hash}.obao`), not an envelope field. See
> [hybrid-encryption-architecture.md](hybrid-encryption-architecture.md)
> for the current layout and
> [plans/2026-04-06-bao-streaming-and-storage-simplification.md](plans/2026-04-06-bao-streaming-and-storage-simplification.md)
> for the migration rationale.

# PRE Backend Trait Hierarchy

**Status:** 📐 DESIGN SKETCH
**Purpose:** Pluggable backend system for proxy recryption

---

## Overview

The trait hierarchy allows swapping PRE backends without changing application logic. This is critical because:

1. Post-quantum standards are still evolving (NIST finalization ongoing)
2. Different use cases may prefer different trade-offs
3. Testing requires mockable backends

---

## Core Traits

### `PreBackend` — The Main Abstraction

```rust
//! recrypt-core/src/pre/traits.rs

use async_trait::async_trait;
use zeroize::Zeroizing;

/// Errors from PRE operations
#[derive(Debug, thiserror::Error)]
pub enum PreError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Recryption failed: {0}")]
    Recryption(String),

    #[error("Recrypt key generation failed: {0}")]
    RecryptKeyGeneration(String),

    #[error("Serialization failed: {0}")]
    Serialization(String),

    #[error("Deserialization failed: {0}")]
    Deserialization(String),

    #[error("Invalid key material: {0}")]
    InvalidKey(String),
}

pub type PreResult<T> = Result<T, PreError>;

/// Identifies which backend produced a ciphertext/key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BackendId {
    /// OpenFHE BFV/PRE (post-quantum, lattice-based)
    Lattice = 0,
    /// IronCore recrypt (classical, BN254 pairing)
    EcPairing = 1,
    /// NuCypher Umbral (classical, secp256k1)
    EcSecp256k1 = 2,
    /// Mock backend for testing
    Mock = 255,
}

/// A proxy recryption backend
///
/// This trait abstracts over different PRE schemes, allowing the system
/// to use lattice-based (post-quantum) or EC-based (classical) backends
/// interchangeably.
#[async_trait]
pub trait PreBackend: Send + Sync {
    /// Backend identifier for serialization format detection
    fn backend_id(&self) -> BackendId;

    /// Human-readable name
    fn name(&self) -> &'static str;

    /// Whether this backend is post-quantum secure
    fn is_post_quantum(&self) -> bool;

    /// Generate a new key pair
    fn generate_keypair(&self) -> PreResult<KeyPair>;

    /// Derive public key from secret key (if deterministic)
    fn public_key_from_secret(&self, secret: &SecretKey) -> PreResult<PublicKey>;

    /// Generate a recryption key from delegator to delegatee
    ///
    /// The recrypt key allows transforming ciphertexts encrypted for
    /// `from_secret`'s public key into ciphertexts decryptable by
    /// `to_public`'s corresponding secret key.
    fn generate_recrypt_key(
        &self,
        from_secret: &SecretKey,
        to_public: &PublicKey,
    ) -> PreResult<RecryptKey>;

    /// Encrypt data for a recipient
    ///
    /// For small payloads (symmetric keys), this encrypts directly.
    /// The maximum payload size is backend-dependent.
    fn encrypt(&self, recipient: &PublicKey, plaintext: &[u8]) -> PreResult<Ciphertext>;

    /// Decrypt data using secret key
    fn decrypt(&self, secret: &SecretKey, ciphertext: &Ciphertext) -> PreResult<Zeroizing<Vec<u8>>>;

    /// Transform a ciphertext for a new recipient
    ///
    /// Uses the recrypt key to transform a ciphertext encrypted for Alice
    /// into one decryptable by Bob, without revealing the plaintext.
    fn recrypt(&self, recrypt_key: &RecryptKey, ciphertext: &Ciphertext) -> PreResult<Ciphertext>;

    /// Maximum plaintext size this backend can encrypt directly
    ///
    /// For hybrid encryption, we only encrypt symmetric keys (32 bytes),
    /// so this is informational.
    fn max_plaintext_size(&self) -> usize;

    /// Approximate ciphertext size for a given plaintext size
    fn ciphertext_size_estimate(&self, plaintext_size: usize) -> usize;
}
```

### Key Types

```rust
//! recrypt-core/src/pre/keys.rs

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A PRE public key (backend-agnostic wrapper)
#[derive(Clone, Debug)]
pub struct PublicKey {
    pub(crate) backend: BackendId,
    pub(crate) bytes: Vec<u8>,
}

impl PublicKey {
    pub fn new(backend: BackendId, bytes: Vec<u8>) -> Self {
        Self { backend, bytes }
    }

    pub fn backend(&self) -> BackendId {
        self.backend
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.backend as u8];
        out.extend(&self.bytes);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> PreResult<Self> {
        if bytes.is_empty() {
            return Err(PreError::InvalidKey("Empty public key".into()));
        }
        let backend = BackendId::try_from(bytes[0])?;
        Ok(Self {
            backend,
            bytes: bytes[1..].to_vec(),
        })
    }
}

/// A PRE secret key (zeroized on drop)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    pub(crate) backend: BackendId,
    #[zeroize(skip)] // Backend ID doesn't need zeroizing
    pub(crate) bytes: Vec<u8>,
}

impl SecretKey {
    pub fn new(backend: BackendId, bytes: Vec<u8>) -> Self {
        Self { backend, bytes }
    }

    pub fn backend(&self) -> BackendId {
        self.backend
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A key pair (public + secret)
pub struct KeyPair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

/// A recryption key (transforms ciphertexts from one recipient to another)
#[derive(Clone)]
pub struct RecryptKey {
    pub(crate) backend: BackendId,
    pub(crate) from_public: PublicKey,  // For verification
    pub(crate) to_public: PublicKey,    // For verification
    pub(crate) bytes: Vec<u8>,
}

impl RecryptKey {
    pub fn backend(&self) -> BackendId {
        self.backend
    }

    /// The public key this recrypt key transforms FROM
    pub fn from_public(&self) -> &PublicKey {
        &self.from_public
    }

    /// The public key this recrypt key transforms TO
    pub fn to_public(&self) -> &PublicKey {
        &self.to_public
    }
}

/// A PRE ciphertext
#[derive(Clone, Debug)]
pub struct Ciphertext {
    pub(crate) backend: BackendId,
    pub(crate) level: u8,  // 0 = original, 1+ = recrypted
    pub(crate) bytes: Vec<u8>,
}

impl Ciphertext {
    pub fn backend(&self) -> BackendId {
        self.backend
    }

    /// Recryption level (0 = never recrypted, 1 = recrypted once, etc.)
    pub fn level(&self) -> u8 {
        self.level
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.backend as u8, self.level];
        out.extend(&self.bytes);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> PreResult<Self> {
        if bytes.len() < 2 {
            return Err(PreError::Deserialization("Ciphertext too short".into()));
        }
        let backend = BackendId::try_from(bytes[0])?;
        Ok(Self {
            backend,
            level: bytes[1],
            bytes: bytes[2..].to_vec(),
        })
    }
}
```

---

## Hybrid Encryption Layer

```rust
//! recrypt-core/src/hybrid.rs
//!
//! Hybrid encryption using XChaCha20 + Blake3/Bao for streaming verification.
//! No Poly1305—authenticity comes from signatures on the Bao root.
//! XChaCha20's 192-bit nonce eliminates birthday-bound concerns with random nonces.

use chacha20::XChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use rand::{RngCore, rngs::OsRng};
use zeroize::Zeroizing;

use crate::pre::{PreBackend, PublicKey, SecretKey, RecryptKey, Ciphertext, PreResult, PreError};

/// Symmetric key size (XChaCha20 uses 256-bit keys)
pub const SYMMETRIC_KEY_SIZE: usize = 32;

/// Nonce size for XChaCha20 (192-bit extended nonce)
pub const NONCE_SIZE: usize = 24;

/// Total key material size (key + nonce + plaintext_hash + size)
pub const KEY_MATERIAL_SIZE: usize = 32 + 24 + 32 + 8; // 96 bytes

/// Key material bundle (encrypted inside wrapped_key)
///
/// This is the plaintext that gets PRE-encrypted. The plaintext_hash
/// is included here (not in public metadata) to prevent confirmation
/// and dictionary attacks.
#[derive(Clone, Debug)]
pub struct KeyMaterial {
    /// XChaCha20 symmetric key
    pub symmetric_key: [u8; 32],
    /// XChaCha20 extended nonce (192-bit for birthday-safe random generation)
    pub nonce: [u8; 24],
    /// Blake3 hash of original plaintext (for post-decryption verification)
    pub plaintext_hash: [u8; 32],
    /// Original plaintext size in bytes
    pub plaintext_size: u64,
}

impl KeyMaterial {
    pub const SERIALIZED_SIZE: usize = 32 + 24 + 32 + 8; // 96 bytes

    pub fn to_bytes(&self) -> [u8; Self::SERIALIZED_SIZE] {
        let mut out = [0u8; Self::SERIALIZED_SIZE];
        out[0..32].copy_from_slice(&self.symmetric_key);
        out[32..56].copy_from_slice(&self.nonce);
        out[56..88].copy_from_slice(&self.plaintext_hash);
        out[88..96].copy_from_slice(&self.plaintext_size.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != Self::SERIALIZED_SIZE {
            return Err("Invalid key material size");
        }
        Ok(Self {
            symmetric_key: bytes[0..32].try_into().unwrap(),
            nonce: bytes[32..56].try_into().unwrap(),
            plaintext_hash: bytes[56..88].try_into().unwrap(),
            plaintext_size: u64::from_le_bytes(bytes[88..96].try_into().unwrap()),
        })
    }
}

/// An encrypted file with streaming-verifiable integrity
#[derive(Clone, Debug)]
pub struct EncryptedFile {
    /// The PRE-encrypted key bundle (contains key, nonce, plaintext_hash, size)
    pub wrapped_key: Ciphertext,

    /// Bao root hash of ciphertext (for streaming verification)
    /// This is the ONLY hash in public metadata—plaintext_hash is encrypted
    pub bao_hash: [u8; 32],

    /// Bao outboard data (verification tree, ~1% of ciphertext size)
    pub bao_outboard: Vec<u8>,

    /// XChaCha20-encrypted data (no auth tag—Bao provides integrity)
    pub ciphertext: Vec<u8>,
}

impl EncryptedFile {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let wrapped = self.wrapped_key.to_bytes();
        let mut out = Vec::new();

        // Version
        out.push(2u8);

        // Wrapped key (contains encrypted: key, nonce, plaintext_hash, size)
        out.extend((wrapped.len() as u32).to_le_bytes());
        out.extend(&wrapped);

        // Bao hash (only public hash—plaintext_hash is inside wrapped_key)
        out.extend(&self.bao_hash);
        out.extend((self.bao_outboard.len() as u64).to_le_bytes());
        out.extend(&self.bao_outboard);

        // Ciphertext
        out.extend((self.ciphertext.len() as u64).to_le_bytes());
        out.extend(&self.ciphertext);

        out
    }
}

/// Hybrid encryption using PRE for key wrapping + XChaCha20 + Bao
pub struct HybridEncryptor<B: PreBackend> {
    backend: B,
}

impl<B: PreBackend> HybridEncryptor<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Encrypt data for a recipient with streaming-verifiable integrity
    pub fn encrypt(&self, recipient: &PublicKey, plaintext: &[u8]) -> PreResult<EncryptedFile> {
        // Generate random symmetric key and nonce
        let mut sym_key = Zeroizing::new([0u8; SYMMETRIC_KEY_SIZE]);
        let mut nonce = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(sym_key.as_mut());
        OsRng.fill_bytes(&mut nonce);

        // Hash plaintext for post-decryption verification
        let plaintext_hash = blake3::hash(plaintext);
        let plaintext_size = plaintext.len() as u64;

        // Encrypt with XChaCha20 (pure stream cipher, no Poly1305)
        let mut ciphertext = plaintext.to_vec();
        let mut cipher = XChaCha20::new((&*sym_key).into(), (&nonce).into());
        cipher.apply_keystream(&mut ciphertext);

        // Compute Bao tree for streaming verification
        let (bao_hash, bao_outboard) = bao::encode::outboard(&ciphertext);

        // Bundle key material (includes plaintext_hash to protect it from leakage)
        let key_material = KeyMaterial {
            symmetric_key: *sym_key,
            nonce,
            plaintext_hash: *plaintext_hash.as_bytes(),
            plaintext_size,
        };

        // Wrap entire bundle with PRE (plaintext_hash now encrypted!)
        let wrapped_key = self.backend.encrypt(recipient, &key_material.to_bytes())?;

        Ok(EncryptedFile {
            wrapped_key,
            bao_hash: *bao_hash.as_bytes(),
            bao_outboard,
            ciphertext,
        })
    }

    /// Decrypt and verify integrity
    pub fn decrypt(&self, secret: &SecretKey, file: &EncryptedFile) -> PreResult<Vec<u8>> {
        // Verify ciphertext integrity via Bao
        // Note: Full Bao verification would use the outboard tree
        // This is simplified—real impl uses bao::decode::Decoder
        let computed_bao = blake3::Hasher::new()
            .update(&file.ciphertext)
            .finalize();
        if computed_bao.as_bytes() != &file.bao_hash {
            return Err(PreError::Decryption("Bao hash mismatch—ciphertext corrupted".into()));
        }

        // Unwrap key material bundle
        let key_material_bytes = self.backend.decrypt(secret, &file.wrapped_key)?;
        let key_material = KeyMaterial::from_bytes(&key_material_bytes)
            .map_err(|e| PreError::Decryption(e.to_string()))?;

        // Decrypt with XChaCha20
        let mut plaintext = file.ciphertext.clone();
        let mut cipher = XChaCha20::new(
            (&key_material.symmetric_key).into(),
            (&key_material.nonce).into(),
        );
        cipher.apply_keystream(&mut plaintext);

        // Verify plaintext size
        if plaintext.len() as u64 != key_material.plaintext_size {
            return Err(PreError::Decryption("Plaintext size mismatch".into()));
        }

        // Verify plaintext hash (now extracted from encrypted bundle)
        let computed_hash = blake3::hash(&plaintext);
        if computed_hash.as_bytes() != &key_material.plaintext_hash {
            return Err(PreError::Decryption(
                "Plaintext hash mismatch—decryption produced wrong data".into()
            ));
        }

        Ok(plaintext)
    }

    /// Recrypt for a new recipient
    ///
    /// Only transforms the wrapped key—ciphertext and Bao tree unchanged.
    /// The plaintext_hash travels inside the wrapped_key, so it's automatically
    /// re-encrypted for the new recipient.
    pub fn recrypt(&self, recrypt_key: &RecryptKey, file: &EncryptedFile) -> PreResult<EncryptedFile> {
        let new_wrapped = self.backend.recrypt(recrypt_key, &file.wrapped_key)?;

        Ok(EncryptedFile {
            wrapped_key: new_wrapped,
            bao_hash: file.bao_hash,
            bao_outboard: file.bao_outboard.clone(),
            ciphertext: file.ciphertext.clone(),
        })
    }

    /// Access the underlying PRE backend
    pub fn backend(&self) -> &B {
        &self.backend
    }
}
```

---

## Backend Implementations

### Mock Backend (for testing)

```rust
//! recrypt-core/src/pre/backends/mock.rs

use crate::pre::*;
use chacha20::XChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use rand::{RngCore, rngs::OsRng};
use zeroize::Zeroizing;

/// Mock PRE backend for testing
///
/// Uses simple symmetric encryption where the "public key" is actually
/// a shared secret. NOT SECURE - testing only!
pub struct MockBackend;

impl PreBackend for MockBackend {
    fn backend_id(&self) -> BackendId {
        BackendId::Mock
    }

    fn name(&self) -> &'static str {
        "Mock (TESTING ONLY)"
    }

    fn is_post_quantum(&self) -> bool {
        false
    }

    fn generate_keypair(&self) -> PreResult<KeyPair> {
        let mut secret_bytes = vec![0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);

        // "Public key" is just the secret (mock!)
        let public_bytes = secret_bytes.clone();

        Ok(KeyPair {
            public: PublicKey::new(BackendId::Mock, public_bytes),
            secret: SecretKey::new(BackendId::Mock, secret_bytes),
        })
    }

    fn public_key_from_secret(&self, secret: &SecretKey) -> PreResult<PublicKey> {
        Ok(PublicKey::new(BackendId::Mock, secret.bytes.clone()))
    }

    fn generate_recrypt_key(
        &self,
        from_secret: &SecretKey,
        to_public: &PublicKey,
    ) -> PreResult<RecryptKey> {
        // Mock: recrypt key = XOR of from_secret and to_public
        let mut rk_bytes = vec![0u8; 32];
        for i in 0..32 {
            rk_bytes[i] = from_secret.bytes[i] ^ to_public.bytes[i];
        }

        Ok(RecryptKey {
            backend: BackendId::Mock,
            from_public: self.public_key_from_secret(from_secret)?,
            to_public: to_public.clone(),
            bytes: rk_bytes,
        })
    }

    fn encrypt(&self, recipient: &PublicKey, plaintext: &[u8]) -> PreResult<Ciphertext> {
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);

        let mut ct = plaintext.to_vec();
        let mut cipher = XChaCha20::new(
            (&recipient.bytes[..32]).into(),
            (&nonce).into(),
        );
        cipher.apply_keystream(&mut ct);

        // Prepend nonce to ciphertext
        let mut bytes = nonce.to_vec();
        bytes.extend(ct);

        Ok(Ciphertext {
            backend: BackendId::Mock,
            level: 0,
            bytes,
        })
    }

    fn decrypt(&self, secret: &SecretKey, ciphertext: &Ciphertext) -> PreResult<Zeroizing<Vec<u8>>> {
        if ciphertext.bytes.len() < 24 {
            return Err(PreError::Decryption("Ciphertext too short".into()));
        }

        let nonce: [u8; 24] = ciphertext.bytes[..24].try_into().unwrap();
        let mut pt = ciphertext.bytes[24..].to_vec();

        let mut cipher = XChaCha20::new(
            (&secret.bytes[..32]).into(),
            (&nonce).into(),
        );
        cipher.apply_keystream(&mut pt);

        Ok(Zeroizing::new(pt))
    }

    fn recrypt(&self, recrypt_key: &RecryptKey, ciphertext: &Ciphertext) -> PreResult<Ciphertext> {
        // Mock: decrypt with XOR'd key, re-encrypt with to_public
        // This is NOT how real PRE works!

        let from_secret_approx: Vec<u8> = recrypt_key.bytes.iter()
            .zip(recrypt_key.to_public.bytes.iter())
            .map(|(a, b)| a ^ b)
            .collect();

        let temp_secret = SecretKey::new(BackendId::Mock, from_secret_approx);
        let plaintext = self.decrypt(&temp_secret, ciphertext)?;

        let mut new_ct = self.encrypt(&recrypt_key.to_public, &plaintext)?;
        new_ct.level = ciphertext.level + 1;

        Ok(new_ct)
    }

    fn max_plaintext_size(&self) -> usize {
        1024 * 1024 // 1 MB for mock
    }

    fn ciphertext_size_estimate(&self, plaintext_size: usize) -> usize {
        plaintext_size + 24 // Just nonce (24 bytes for XChaCha20), no auth tag (Bao provides integrity)
    }
}
```

### Lattice Backend (OpenFHE via FFI)

```rust
//! recrypt-core/src/pre/backends/lattice.rs
//!
//! OpenFHE BFV/PRE backend for post-quantum security

use crate::pre::*;

// FFI bindings would go here
// extern "C" { ... }

pub struct LatticeBackend {
    // OpenFHE crypto context (FFI pointer)
    // context: *mut openfhe_sys::CryptoContext,
}

impl LatticeBackend {
    pub fn new(security_level: u32) -> PreResult<Self> {
        // Initialize OpenFHE context
        todo!("OpenFHE FFI initialization")
    }
}

impl PreBackend for LatticeBackend {
    fn backend_id(&self) -> BackendId {
        BackendId::Lattice
    }

    fn name(&self) -> &'static str {
        "OpenFHE BFV/PRE (Post-Quantum)"
    }

    fn is_post_quantum(&self) -> bool {
        true
    }

    fn generate_keypair(&self) -> PreResult<KeyPair> {
        todo!("OpenFHE key generation")
    }

    fn public_key_from_secret(&self, _secret: &SecretKey) -> PreResult<PublicKey> {
        Err(PreError::KeyGeneration(
            "Lattice keys are not deterministically derivable".into()
        ))
    }

    fn generate_recrypt_key(
        &self,
        _from_secret: &SecretKey,
        _to_public: &PublicKey,
    ) -> PreResult<RecryptKey> {
        todo!("OpenFHE recrypt key generation")
    }

    fn encrypt(&self, _recipient: &PublicKey, _plaintext: &[u8]) -> PreResult<Ciphertext> {
        todo!("OpenFHE encryption")
    }

    fn decrypt(&self, _secret: &SecretKey, _ciphertext: &Ciphertext) -> PreResult<zeroize::Zeroizing<Vec<u8>>> {
        todo!("OpenFHE decryption")
    }

    fn recrypt(&self, _recrypt_key: &RecryptKey, _ciphertext: &Ciphertext) -> PreResult<Ciphertext> {
        todo!("OpenFHE recryption")
    }

    fn max_plaintext_size(&self) -> usize {
        // BFV slot capacity depends on ring dimension
        // At 128-bit security (n=4096), ~8KB per ciphertext
        // For KEM, we only need 32-64 bytes
        64
    }

    fn ciphertext_size_estimate(&self, _plaintext_size: usize) -> usize {
        // Roughly 1-10 KB for a single slot batch
        5 * 1024
    }
}
```

### EC Pairing Backend (recrypt crate)

```rust
//! recrypt-core/src/pre/backends/ec_pairing.rs
//!
//! IronCore recrypt backend (BN254 pairing-based)

use crate::pre::*;
use recrypt::api::{Recrypt, DefaultRng};

pub struct EcPairingBackend {
    recrypt: Recrypt<DefaultRng>,
}

impl EcPairingBackend {
    pub fn new() -> Self {
        Self {
            recrypt: Recrypt::new(),
        }
    }
}

impl PreBackend for EcPairingBackend {
    fn backend_id(&self) -> BackendId {
        BackendId::EcPairing
    }

    fn name(&self) -> &'static str {
        "recrypt (EC Pairing, BN254)"
    }

    fn is_post_quantum(&self) -> bool {
        false
    }

    fn generate_keypair(&self) -> PreResult<KeyPair> {
        let (secret, public) = self.recrypt.generate_key_pair()
            .map_err(|e| PreError::KeyGeneration(e.to_string()))?;

        Ok(KeyPair {
            public: PublicKey::new(BackendId::EcPairing, public.bytes().to_vec()),
            secret: SecretKey::new(BackendId::EcPairing, secret.bytes().to_vec()),
        })
    }

    fn public_key_from_secret(&self, secret: &SecretKey) -> PreResult<PublicKey> {
        let sk = recrypt::api::PrivateKey::new_from_slice(&secret.bytes)
            .map_err(|e| PreError::InvalidKey(e.to_string()))?;
        let pk = self.recrypt.compute_public_key(&sk)
            .map_err(|e| PreError::KeyGeneration(e.to_string()))?;

        Ok(PublicKey::new(BackendId::EcPairing, pk.bytes().to_vec()))
    }

    fn generate_recrypt_key(
        &self,
        from_secret: &SecretKey,
        to_public: &PublicKey,
    ) -> PreResult<RecryptKey> {
        let sk = recrypt::api::PrivateKey::new_from_slice(&from_secret.bytes)
            .map_err(|e| PreError::InvalidKey(e.to_string()))?;
        let pk = recrypt::api::PublicKey::new_from_slice(&to_public.bytes)
            .map_err(|e| PreError::InvalidKey(e.to_string()))?;

        let signing_kp = self.recrypt.generate_ed25519_key_pair();

        let rk = self.recrypt.generate_transform_key(&sk, &pk, &signing_kp)
            .map_err(|e| PreError::RecryptKeyGeneration(e.to_string()))?;

        Ok(RecryptKey {
            backend: BackendId::EcPairing,
            from_public: self.public_key_from_secret(from_secret)?,
            to_public: to_public.clone(),
            bytes: rk.bytes().to_vec(),
        })
    }

    fn encrypt(&self, recipient: &PublicKey, plaintext: &[u8]) -> PreResult<Ciphertext> {
        let pk = recrypt::api::PublicKey::new_from_slice(&recipient.bytes)
            .map_err(|e| PreError::InvalidKey(e.to_string()))?;

        // recrypt encrypts a Plaintext (fixed size), we need to handle variable size
        // For KEM, plaintext is always 32 bytes (symmetric key)
        if plaintext.len() > 384 {
            return Err(PreError::Encryption(
                format!("Plaintext too large: {} > 384 bytes", plaintext.len())
            ));
        }

        let pt = self.recrypt.gen_plaintext();
        // In reality, we'd encode plaintext bytes into the Fp12 element
        // This is a simplification

        let signing_kp = self.recrypt.generate_ed25519_key_pair();
        let encrypted = self.recrypt.encrypt(&pt, &pk, &signing_kp)
            .map_err(|e| PreError::Encryption(e.to_string()))?;

        Ok(Ciphertext {
            backend: BackendId::EcPairing,
            level: 0,
            bytes: encrypted.bytes().to_vec(),
        })
    }

    fn decrypt(&self, secret: &SecretKey, ciphertext: &Ciphertext) -> PreResult<zeroize::Zeroizing<Vec<u8>>> {
        let sk = recrypt::api::PrivateKey::new_from_slice(&secret.bytes)
            .map_err(|e| PreError::InvalidKey(e.to_string()))?;

        let encrypted = recrypt::api::EncryptedValue::new_from_slice(&ciphertext.bytes)
            .map_err(|e| PreError::Deserialization(e.to_string()))?;

        let decrypted = self.recrypt.decrypt(encrypted, &sk)
            .map_err(|e| PreError::Decryption(e.to_string()))?;

        Ok(zeroize::Zeroizing::new(decrypted.bytes().to_vec()))
    }

    fn recrypt(&self, recrypt_key: &RecryptKey, ciphertext: &Ciphertext) -> PreResult<Ciphertext> {
        let rk = recrypt::api::TransformKey::new_from_slice(&recrypt_key.bytes)
            .map_err(|e| PreError::InvalidKey(e.to_string()))?;

        let encrypted = recrypt::api::EncryptedValue::new_from_slice(&ciphertext.bytes)
            .map_err(|e| PreError::Deserialization(e.to_string()))?;

        let signing_kp = self.recrypt.generate_ed25519_key_pair();
        let transformed = self.recrypt.transform(encrypted, rk, &signing_kp)
            .map_err(|e| PreError::Recryption(e.to_string()))?;

        Ok(Ciphertext {
            backend: BackendId::EcPairing,
            level: ciphertext.level + 1,
            bytes: transformed.bytes().to_vec(),
        })
    }

    fn max_plaintext_size(&self) -> usize {
        384 // Fp12 element size
    }

    fn ciphertext_size_estimate(&self, _plaintext_size: usize) -> usize {
        480 // Level-0 ciphertext
    }
}
```

---

## Backend Registry

```rust
//! recrypt-core/src/pre/registry.rs

use std::sync::Arc;
use crate::pre::{PreBackend, BackendId, PreResult, PreError};

/// Registry of available PRE backends
pub struct BackendRegistry {
    backends: Vec<Arc<dyn PreBackend>>,
    default: BackendId,
}

impl BackendRegistry {
    pub fn new() -> Self {
        Self {
            backends: Vec::new(),
            default: BackendId::Lattice,
        }
    }

    /// Register a backend
    pub fn register(&mut self, backend: Arc<dyn PreBackend>) {
        self.backends.push(backend);
    }

    /// Set the default backend
    pub fn set_default(&mut self, id: BackendId) {
        self.default = id;
    }

    /// Get the default backend
    pub fn default_backend(&self) -> PreResult<Arc<dyn PreBackend>> {
        self.get(self.default)
    }

    /// Get a specific backend by ID
    pub fn get(&self, id: BackendId) -> PreResult<Arc<dyn PreBackend>> {
        self.backends
            .iter()
            .find(|b| b.backend_id() == id)
            .cloned()
            .ok_or_else(|| PreError::InvalidKey(format!("Backend {:?} not registered", id)))
    }

    /// List all registered backends
    pub fn list(&self) -> Vec<(BackendId, &'static str, bool)> {
        self.backends
            .iter()
            .map(|b| (b.backend_id(), b.name(), b.is_post_quantum()))
            .collect()
    }
}

/// Create default registry with available backends
pub fn default_registry() -> BackendRegistry {
    let mut registry = BackendRegistry::new();

    // Always register mock for testing
    #[cfg(test)]
    registry.register(Arc::new(crate::pre::backends::mock::MockBackend));

    // Register EC pairing if available
    #[cfg(feature = "ec-pairing")]
    registry.register(Arc::new(crate::pre::backends::ec_pairing::EcPairingBackend::new()));

    // Register lattice if available
    #[cfg(feature = "lattice")]
    if let Ok(backend) = crate::pre::backends::lattice::LatticeBackend::new(128) {
        registry.register(Arc::new(backend));
    }

    registry
}
```

---

## Module Structure

```
recrypt-core/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── hybrid.rs           # HybridEncryptor, EncryptedFile
    └── pre/
        ├── mod.rs          # Re-exports
        ├── traits.rs       # PreBackend trait
        ├── keys.rs         # Key types
        ├── error.rs        # PreError
        ├── registry.rs     # Backend registry
        └── backends/
            ├── mod.rs
            ├── mock.rs     # MockBackend (testing)
            ├── lattice.rs  # LatticeBackend (OpenFHE)
            └── ec_pairing.rs # EcPairingBackend (recrypt)
```

---

## Usage Example

```rust
use dcypher_core::{
    HybridEncryptor,
    pre::{BackendRegistry, BackendId},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get default backend (lattice/post-quantum)
    let registry = dcypher_core::pre::default_registry();
    let backend = registry.default_backend()?;

    println!("Using backend: {} (PQ: {})",
        backend.name(),
        backend.is_post_quantum());

    // Create encryptor
    let encryptor = HybridEncryptor::new(backend);

    // Generate keys for Alice and Bob
    let alice = encryptor.backend().generate_keypair()?;
    let bob = encryptor.backend().generate_keypair()?;

    // Alice encrypts a message
    let message = b"Hello, Bob!";
    let encrypted = encryptor.encrypt(&bob.public, message)?;

    // Bob decrypts
    let decrypted = encryptor.decrypt(&bob.secret, &encrypted)?;
    assert_eq!(decrypted.as_slice(), message);

    // Later: Alice wants to grant Carol access
    let carol = encryptor.backend().generate_keypair()?;

    // Generate recrypt key (requires Bob's secret key)
    let rk = encryptor.backend().generate_recrypt_key(&bob.secret, &carol.public)?;

    // Proxy transforms the ciphertext (no access to plaintext!)
    let for_carol = encryptor.recrypt(&rk, &encrypted)?;

    // Carol decrypts
    let decrypted_carol = encryptor.decrypt(&carol.secret, &for_carol)?;
    assert_eq!(decrypted_carol.as_slice(), message);

    Ok(())
}
```

---

## Cargo Features

```toml
[package]
name = "recrypt-core"
version = "0.1.0"
edition = "2021"

[features]
default = ["ec-pairing"]
ec-pairing = ["recrypt"]
ec-secp256k1 = ["umbral-pre"]
lattice = []  # Requires OpenFHE FFI setup

[dependencies]
async-trait = "0.1"
chacha20 = "0.9"           # XChaCha20 stream cipher (192-bit nonce, no Poly1305)
blake3 = "1.5"             # Hashing + Bao tree mode
bao = "0.12"               # Streaming verification trees
rand = "0.8"
thiserror = "1.0"
zeroize = { version = "1.7", features = ["derive"] }

# Optional backends
recrypt = { version = "0.14", optional = true }
umbral-pre = { version = "0.11", optional = true }

[dev-dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

**Note:** We use `chacha20::XChaCha20` (not `chacha20poly1305`) because:

- XChaCha20's 192-bit nonce eliminates birthday-bound concerns with random nonce generation
- Poly1305 provides all-or-nothing authentication (incompatible with streaming)
- Bao provides streaming verification via Blake3 tree hashing
- Signatures on Bao root provide authenticity (equivalent to Poly1305's key binding)
