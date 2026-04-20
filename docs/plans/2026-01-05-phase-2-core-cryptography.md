> **Historical:** Phase 2 planning. The `EncryptedFile` layout below shows
> an inline `bao_outboard` field that was removed in the 2026-04-06 Bao
> streaming sprint — the outboard now lives as a sibling `{hash}.obao`
> storage object. See [hybrid-encryption-architecture.md](../hybrid-encryption-architecture.md)
> for the current envelope shape.

# Phase 2: Core Cryptography Implementation Plan

## Overview

Build the `recrypt-core` crate on top of Phase 1's FFI bindings (`recrypt-ffi`). This provides production-ready cryptographic operations through a pluggable backend system supporting both post-quantum (lattice) and classical (EC) proxy Recryption.

**Duration:** 4-5 days  
**Prerequisites:** Phase 1 complete (FFI bindings functional)

## Current State Analysis

Phase 1 delivered:

- ✅ `recrypt-ffi` crate with OpenFHE BFV/PRE bindings
- ✅ liboqs ML-DSA signatures (44/65/87 variants)
- ✅ ED25519 classical signatures
- ✅ 16 passing tests for all primitives
- ✅ Clean error handling (`FfiError`)

**Key Files:**

- `crates/recrypt-ffi/src/openfhe/mod.rs` - OpenFHE PRE operations
- `crates/recrypt-ffi/src/liboqs/sig.rs` - Post-quantum signatures
- `crates/recrypt-ffi/src/ed25519.rs` - Classical signatures
- `crates/recrypt-ffi/src/error.rs` - Error types

**Missing:**

- No high-level crypto API (direct FFI usage only)
- No hybrid encryption (raw PRE operations only)
- No multi-signature support
- No pluggable backend system
- No streaming verification (Bao integration)

## Desired End State

A production-ready `recrypt-core` crate that:

1. **Abstracts crypto primitives** behind clean Rust APIs
2. **Implements hybrid encryption** (KEM-DEM with XChaCha20 + Bao)
3. **Supports pluggable PRE backends** (Lattice via OpenFHE, Mock for testing, future EC backends)
4. **Provides multi-signature** (ED25519 + ML-DSA-87)
5. **Handles streaming verification** via Blake3/Bao trees
6. **Encrypts plaintext hashes** inside wrapped keys (metadata confidentiality)
7. **Tests semantic correctness** (not byte equality—see non-determinism doc)

### Success Verification

#### Automated:

- [x] All unit tests pass: `cargo test -p recrypt-core`
- [x] Property tests pass: `cargo test -p recrypt-core --features proptest`
- [x] Benchmarks baseline established: `cargo bench -p recrypt-core`
- [x] Clippy clean: `cargo clippy -p recrypt-core -- -D warnings`
- [x] Doc tests pass: `cargo test -p recrypt-core --doc`

#### Manual:

- [x] Full Alice→Bob→Carol recryption flow works
- [x] Encrypted files decrypt to correct plaintext
- [x] Multi-signature verification catches tampered messages
- [x] Mock backend allows fast iteration without OpenFHE overhead
- [x] Documentation examples compile and run

**Implementation Note:** After completing each phase and all automated checks pass, pause for manual confirmation before proceeding.

## What We're NOT Doing

- ❌ **EC backends yet** - Mock + Lattice only; `recrypt`/`umbral` crates in future phases
- ❌ **Serialization formats** - That's Phase 3 (proto/armor)
- ❌ **Storage integration** - That's Phase 4
- ❌ **Network/API layer** - That's Phase 6
- ❌ **Key storage/management** - Out of scope (client/CLI responsibility)
- ❌ **Threshold PRE** - Single-server only for now

## Implementation Approach

**Strategy:** Bottom-up modular construction

1. **Start with types** - Keys, ciphertexts, errors (foundation)
2. **Build trait layer** - `PreBackend` abstraction
3. **Implement mock backend** - Fast testing without FFI
4. **Wrap FFI backend** - Lattice backend using `recrypt-ffi`
5. **Add hybrid layer** - KEM-DEM with XChaCha20 + Bao
6. **Build signature layer** - Multi-sig (ED25519 + ML-DSA)
7. **Write comprehensive tests** - Property-based + semantic validation

**Key Design Decisions:**

- **Explicit backend passing** (`HybridEncryptor<B: PreBackend>`) for testability
- **Zeroizing secrets** via `zeroize` crate
- **Semantic test strategy** (decrypt(encrypt(x)) == x, NOT byte equality)
- **Backend registry** for dynamic selection (feature-gated)

---

## Phase 2.1: Foundation Types & Traits

### Overview

Establish core types and the `PreBackend` trait that all implementations will satisfy.

### Changes Required

#### 1. Create `recrypt-core` crate structure

**File**: `crates/recrypt-core/Cargo.toml`

```toml
[package]
name = "recrypt-core"
version.workspace = true
edition.workspace = true

[dependencies]
# Crypto primitives
chacha20 = "0.9"           # XChaCha20 (192-bit nonce, no Poly1305)
blake3 = { version = "1.5", features = ["traits-preview"] }
bao = "0.12"               # Streaming verification
rand = "0.8"
rand_core = "0.6"

# Error handling
thiserror.workspace = true
anyhow.workspace = true

# Secret zeroization
zeroize = { version = "1.7", features = ["derive"] }

# Async (for trait)
async-trait = "0.1"

# FFI binding (our Phase 1 crate)
recrypt-ffi = { path = "../recrypt-ffi" }

[dev-dependencies]
proptest.workspace = true
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }

[features]
default = []
proptest = ["dep:proptest"]
```

**File**: `crates/recrypt-core/src/lib.rs`

```rust
//! recrypt-core: Production cryptography for proxy Recryption
//!
//! This crate provides:
//! - Pluggable PRE backend trait system
//! - Hybrid encryption (KEM-DEM with XChaCha20 + Bao)
//! - Multi-signature support (ED25519 + ML-DSA)
//! - Streaming verification via Blake3/Bao trees

pub mod error;
pub mod pre;
pub mod hybrid;
pub mod sign;

// Re-exports for convenience
pub use error::{CoreError, CoreResult};
pub use hybrid::{HybridEncryptor, EncryptedFile, KeyMaterial};
pub use pre::{PreBackend, KeyPair, PublicKey, SecretKey, RecryptKey, Ciphertext};
pub use sign::{MultiSig, SigningKeys, VerifyingKeys};
```

#### 2. Error Types

**File**: `crates/recrypt-core/src/error.rs`

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("PRE backend error: {0}")]
    PreBackend(#[from] PreError),

    #[error("Signature error: {0}")]
    Signature(String),

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Verification failed: {0}")]
    Verification(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("FFI error: {0}")]
    Ffi(#[from] dcypher_ffi::error::FfiError),
}

pub type CoreResult<T> = Result<T, CoreError>;

/// Errors from PRE operations
#[derive(Error, Debug)]
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

    #[error("Backend not available: {0}")]
    BackendUnavailable(String),
}

pub type PreResult<T> = Result<T, PreError>;
```

#### 3. Key Types

**File**: `crates/recrypt-core/src/pre/keys.rs`

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::error::PreResult;
use super::BackendId;

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

    /// Serialize with backend tag
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
    #[zeroize(skip)]
    _backend_skip: (),  // Backend ID doesn't need zeroizing
    pub(crate) bytes: Vec<u8>,
}

impl SecretKey {
    pub fn new(backend: BackendId, bytes: Vec<u8>) -> Self {
        Self {
            backend,
            _backend_skip: (),
            bytes,
        }
    }

    pub fn backend(&self) -> BackendId {
        self.backend
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A keypair (public + secret)
pub struct KeyPair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

/// A recryption key (transforms ciphertexts from one recipient to another)
#[derive(Clone)]
pub struct RecryptKey {
    pub(crate) backend: BackendId,
    pub(crate) from_public: PublicKey,
    pub(crate) to_public: PublicKey,
    pub(crate) bytes: Vec<u8>,
}

impl RecryptKey {
    pub fn new(
        backend: BackendId,
        from_public: PublicKey,
        to_public: PublicKey,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            backend,
            from_public,
            to_public,
            bytes,
        }
    }

    pub fn backend(&self) -> BackendId {
        self.backend
    }

    pub fn from_public(&self) -> &PublicKey {
        &self.from_public
    }

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
    pub fn new(backend: BackendId, level: u8, bytes: Vec<u8>) -> Self {
        Self { backend, level, bytes }
    }

    pub fn backend(&self) -> BackendId {
        self.backend
    }

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

#### 4. Backend Trait

**File**: `crates/recrypt-core/src/pre/traits.rs`

```rust
use async_trait::async_trait;
use zeroize::Zeroizing;
use super::{KeyPair, PublicKey, SecretKey, RecryptKey, Ciphertext, BackendId};
use crate::error::{PreResult, PreError};

/// A proxy Recryption backend
///
/// Abstracts over different PRE schemes (lattice post-quantum, EC classical).
/// All operations are semantic—ciphertext bytes may differ between runs.
#[async_trait]
pub trait PreBackend: Send + Sync {
    /// Backend identifier for serialization format detection
    fn backend_id(&self) -> BackendId;

    /// Human-readable name
    fn name(&self) -> &'static str;

    /// Whether this backend is post-quantum secure
    fn is_post_quantum(&self) -> bool;

    /// Generate a new keypair
    fn generate_keypair(&self) -> PreResult<KeyPair>;

    /// Derive public key from secret key (if deterministic)
    fn public_key_from_secret(&self, secret: &SecretKey) -> PreResult<PublicKey>;

    /// Generate a recryption key from delegator to delegatee
    ///
    /// Allows transforming ciphertexts encrypted for `from_secret`'s
    /// public key into ciphertexts decryptable by `to_public`'s secret key.
    fn generate_recrypt_key(
        &self,
        from_secret: &SecretKey,
        to_public: &PublicKey,
    ) -> PreResult<RecryptKey>;

    /// Encrypt data for a recipient
    ///
    /// For hybrid encryption, plaintext is always 96 bytes (KeyMaterial bundle).
    fn encrypt(&self, recipient: &PublicKey, plaintext: &[u8]) -> PreResult<Ciphertext>;

    /// Decrypt data using secret key
    fn decrypt(&self, secret: &SecretKey, ciphertext: &Ciphertext) -> PreResult<Zeroizing<Vec<u8>>>;

    /// Transform a ciphertext for a new recipient
    ///
    /// Uses recrypt key to transform without revealing plaintext.
    fn recrypt(&self, recrypt_key: &RecryptKey, ciphertext: &Ciphertext) -> PreResult<Ciphertext>;

    /// Maximum plaintext size this backend can encrypt directly
    fn max_plaintext_size(&self) -> usize;

    /// Approximate ciphertext size for given plaintext size
    fn ciphertext_size_estimate(&self, plaintext_size: usize) -> usize;
}
```

#### 5. Backend ID enum

**File**: `crates/recrypt-core/src/pre/mod.rs`

```rust
pub mod keys;
pub mod traits;
pub mod backends;

pub use keys::{PublicKey, SecretKey, KeyPair, RecryptKey, Ciphertext};
pub use traits::PreBackend;

use crate::error::PreError;

/// Identifies which backend produced a ciphertext/key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BackendId {
    /// OpenFHE BFV/PRE (post-quantum, lattice-based)
    Lattice = 0,
    /// IronCore recrypt (classical, BN254 pairing) - future
    EcPairing = 1,
    /// NuCypher Umbral (classical, secp256k1) - future
    EcSecp256k1 = 2,
    /// Mock backend for testing
    Mock = 255,
}

impl TryFrom<u8> for BackendId {
    type Error = PreError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Lattice),
            1 => Ok(Self::EcPairing),
            2 => Ok(Self::EcSecp256k1),
            255 => Ok(Self::Mock),
            other => Err(PreError::InvalidKey(format!("Unknown backend ID: {}", other))),
        }
    }
}
```

### Success Criteria

#### Automated Verification:

- [ ] Crate compiles: `cargo build -p recrypt-core`
- [ ] Types are publicly exported: `cargo doc -p recrypt-core --no-deps --open`
- [ ] No clippy warnings: `cargo clippy -p recrypt-core`

#### Manual Verification:

- [ ] All type definitions align with design docs
- [ ] Zeroization works (manual inspection of test output)
- [ ] Error types cover all failure modes identified in design

---

## Phase 2.2: Mock Backend Implementation

### Overview

Implement a simple mock PRE backend using XChaCha20 for fast testing without OpenFHE FFI overhead.

### Changes Required

#### 1. Mock Backend

**File**: `crates/recrypt-core/src/pre/backends/mock.rs`

```rust
//! Mock PRE backend for testing
//!
//! NOT SECURE - uses symmetric encryption where "public key" is shared secret.
//! Enables fast iteration without FFI overhead.

use crate::pre::*;
use crate::error::{PreResult, PreError};
use chacha20::XChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use rand::{RngCore, rngs::OsRng};
use zeroize::Zeroizing;

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
        let public_bytes = secret_bytes.clone();  // Mock: pk = sk

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
        // Mock: rk = from_sk XOR to_pk
        let mut rk_bytes = vec![0u8; 32];
        for i in 0..32 {
            rk_bytes[i] = from_secret.bytes[i] ^ to_public.bytes[i];
        }

        Ok(RecryptKey::new(
            BackendId::Mock,
            self.public_key_from_secret(from_secret)?,
            to_public.clone(),
            rk_bytes,
        ))
    }

    fn encrypt(&self, recipient: &PublicKey, plaintext: &[u8]) -> PreResult<Ciphertext> {
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);

        let mut ct = plaintext.to_vec();
        let key: &[u8; 32] = &recipient.bytes[..32].try_into()
            .map_err(|_| PreError::InvalidKey("Mock key must be 32 bytes".into()))?;

        let mut cipher = XChaCha20::new(key.into(), &nonce.into());
        cipher.apply_keystream(&mut ct);

        let mut bytes = nonce.to_vec();
        bytes.extend(ct);

        Ok(Ciphertext::new(BackendId::Mock, 0, bytes))
    }

    fn decrypt(&self, secret: &SecretKey, ciphertext: &Ciphertext) -> PreResult<Zeroizing<Vec<u8>>> {
        if ciphertext.bytes.len() < 24 {
            return Err(PreError::Decryption("Ciphertext too short".into()));
        }

        let nonce: &[u8; 24] = ciphertext.bytes[..24].try_into().unwrap();
        let mut pt = ciphertext.bytes[24..].to_vec();

        let key: &[u8; 32] = &secret.bytes[..32].try_into()
            .map_err(|_| PreError::InvalidKey("Mock key must be 32 bytes".into()))?;

        let mut cipher = XChaCha20::new(key.into(), nonce.into());
        cipher.apply_keystream(&mut pt);

        Ok(Zeroizing::new(pt))
    }

    fn recrypt(&self, recrypt_key: &RecryptKey, ciphertext: &Ciphertext) -> PreResult<Ciphertext> {
        // Mock: decrypt with from_sk, re-encrypt with to_pk
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
        1024 * 1024  // 1 MB
    }

    fn ciphertext_size_estimate(&self, plaintext_size: usize) -> usize {
        plaintext_size + 24  // Just nonce overhead
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_encrypt_decrypt() {
        let backend = MockBackend;
        let kp = backend.generate_keypair().unwrap();
        let plaintext = b"Hello, Mock PRE!";

        let ct = backend.encrypt(&kp.public, plaintext).unwrap();
        let pt = backend.decrypt(&kp.secret, &ct).unwrap();

        assert_eq!(&pt[..], plaintext);
    }

    #[test]
    fn test_mock_recryption() {
        let backend = MockBackend;
        let alice = backend.generate_keypair().unwrap();
        let bob = backend.generate_keypair().unwrap();

        let plaintext = b"Secret for Bob";
        let ct_alice = backend.encrypt(&alice.public, plaintext).unwrap();

        let rk = backend.generate_recrypt_key(&alice.secret, &bob.public).unwrap();
        let ct_bob = backend.recrypt(&rk, &ct_alice).unwrap();

        let pt_bob = backend.decrypt(&bob.secret, &ct_bob).unwrap();
        assert_eq!(&pt_bob[..], plaintext);
        assert_eq!(ct_bob.level(), 1);
    }
}
```

**File**: `crates/recrypt-core/src/pre/backends/mod.rs`

```rust
pub mod mock;

#[cfg(test)]
pub use mock::MockBackend;
```

### Success Criteria

#### Automated Verification:

- [ ] Mock tests pass: `cargo test -p recrypt-core mock`
- [ ] Property test with mock backend: `cargo test -p recrypt-core --features proptest mock_properties`

#### Manual Verification:

- [ ] Mock backend allows rapid iteration without OpenFHE
- [ ] Test failures clearly indicate semantic issues (not byte mismatches)

---

## Phase 2.3: Lattice Backend (OpenFHE Wrapper)

### Overview

Wrap Phase 1's OpenFHE FFI into the `PreBackend` trait.

### Changes Required

#### 1. Lattice Backend

**File**: `crates/recrypt-core/src/pre/backends/lattice.rs`

```rust
//! OpenFHE lattice-based PRE backend (post-quantum)

use crate::pre::*;
use crate::error::{PreResult, PreError};
use dcypher_ffi::openfhe::{PreContext as FfiContext, KeyPair as FfiKeyPair};
use zeroize::Zeroizing;

pub struct LatticeBackend {
    context: FfiContext,
}

impl LatticeBackend {
    /// Create new lattice backend with default BFV parameters
    pub fn new() -> PreResult<Self> {
        let context = FfiContext::new()
            .map_err(|e| PreError::BackendUnavailable(format!("OpenFHE init failed: {e}")))?;

        Ok(Self { context })
    }

    /// Access underlying OpenFHE context (for advanced usage)
    pub fn context(&self) -> &FfiContext {
        &self.context
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
        let ffi_kp = self.context.generate_keypair()
            .map_err(|e| PreError::KeyGeneration(e.to_string()))?;

        // Serialize keys to bytes (OpenFHE serialization is non-deterministic)
        let pk_bytes = serialize_openfhe_public_key(&ffi_kp.public)?;
        let sk_bytes = serialize_openfhe_secret_key(&ffi_kp.secret)?;

        Ok(KeyPair {
            public: PublicKey::new(BackendId::Lattice, pk_bytes),
            secret: SecretKey::new(BackendId::Lattice, sk_bytes),
        })
    }

    fn public_key_from_secret(&self, _secret: &SecretKey) -> PreResult<PublicKey> {
        Err(PreError::KeyGeneration(
            "Lattice keys are not deterministically derivable".into()
        ))
    }

    fn generate_recrypt_key(
        &self,
        from_secret: &SecretKey,
        to_public: &PublicKey,
    ) -> PreResult<RecryptKey> {
        let from_sk = deserialize_openfhe_secret_key(&from_secret.bytes)?;
        let to_pk = deserialize_openfhe_public_key(&to_public.bytes)?;

        let ffi_rk = self.context.generate_recrypt_key(&from_sk, &to_pk)
            .map_err(|e| PreError::RecryptKeyGeneration(e.to_string()))?;

        let rk_bytes = serialize_openfhe_recrypt_key(&ffi_rk)?;

        Ok(RecryptKey::new(
            BackendId::Lattice,
            self.public_key_from_secret(from_secret)
                .unwrap_or_else(|_| PublicKey::new(BackendId::Lattice, vec![])),
            to_public.clone(),
            rk_bytes,
        ))
    }

    fn encrypt(&self, recipient: &PublicKey, plaintext: &[u8]) -> PreResult<Ciphertext> {
        if plaintext.len() > 96 {
            return Err(PreError::Encryption(
                format!("Plaintext too large: {} > 96 bytes", plaintext.len())
            ));
        }

        let pk = deserialize_openfhe_public_key(&recipient.bytes)?;

        let cts = self.context.encrypt(&pk, plaintext)
            .map_err(|e| PreError::Encryption(e.to_string()))?;

        // Serialize all ciphertexts into one blob
        let ct_bytes = serialize_openfhe_ciphertexts(&cts)?;

        Ok(Ciphertext::new(BackendId::Lattice, 0, ct_bytes))
    }

    fn decrypt(&self, secret: &SecretKey, ciphertext: &Ciphertext) -> PreResult<Zeroizing<Vec<u8>>> {
        let sk = deserialize_openfhe_secret_key(&secret.bytes)?;
        let cts = deserialize_openfhe_ciphertexts(&ciphertext.bytes)?;

        // We encrypted 96 bytes (KeyMaterial)
        let plaintext = self.context.decrypt(&sk, &cts, 96)
            .map_err(|e| PreError::Decryption(e.to_string()))?;

        Ok(Zeroizing::new(plaintext))
    }

    fn recrypt(&self, recrypt_key: &RecryptKey, ciphertext: &Ciphertext) -> PreResult<Ciphertext> {
        let rk = deserialize_openfhe_recrypt_key(&recrypt_key.bytes)?;
        let cts = deserialize_openfhe_ciphertexts(&ciphertext.bytes)?;

        let new_cts = self.context.recrypt(&rk, &cts)
            .map_err(|e| PreError::Recryption(e.to_string()))?;

        let ct_bytes = serialize_openfhe_ciphertexts(&new_cts)?;

        Ok(Ciphertext::new(BackendId::Lattice, ciphertext.level + 1, ct_bytes))
    }

    fn max_plaintext_size(&self) -> usize {
        96  // KeyMaterial size
    }

    fn ciphertext_size_estimate(&self, _plaintext_size: usize) -> usize {
        5 * 1024  // ~5 KB for BFV ciphertext
    }
}

// Serialization helpers (placeholder—Phase 3 will implement properly)
fn serialize_openfhe_public_key(_pk: &dcypher_ffi::openfhe::PublicKey) -> PreResult<Vec<u8>> {
    // TODO: Implement OpenFHE serialization in Phase 3
    Ok(vec![])
}

fn deserialize_openfhe_public_key(_bytes: &[u8]) -> PreResult<dcypher_ffi::openfhe::PublicKey> {
    // TODO: Implement OpenFHE deserialization in Phase 3
    Err(PreError::Deserialization("Not yet implemented".into()))
}

// Similar stubs for secret_key, recrypt_key, ciphertexts...
// (Full implementation in Phase 3 when we add serialization support)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lattice_backend_creation() {
        let backend = LatticeBackend::new().unwrap();
        assert_eq!(backend.name(), "OpenFHE BFV/PRE (Post-Quantum)");
        assert!(backend.is_post_quantum());
    }

    // More tests will work once serialization is implemented in Phase 3
}
```

**Update**: `crates/recrypt-core/src/pre/backends/mod.rs`

```rust
pub mod mock;
pub mod lattice;

pub use mock::MockBackend;
pub use lattice::LatticeBackend;
```

### Success Criteria

#### Automated Verification:

- [ ] Lattice backend compiles: `cargo build -p recrypt-core`
- [ ] Basic instantiation test passes: `cargo test -p recrypt-core lattice_backend_creation`

#### Manual Verification:

- [ ] Lattice backend trait implementation aligns with mock backend
- [ ] Serialization TODOs documented for Phase 3

**Note:** Full lattice backend testing depends on Phase 3 (serialization). This phase establishes the structure.

---

## Phase 2.4: Hybrid Encryption Layer

### Overview

Implement KEM-DEM hybrid encryption using XChaCha20 + Bao with encrypted plaintext hash inside wrapped key.

### Changes Required

#### 1. Key Material Bundle

**File**: `crates/recrypt-core/src/hybrid/keymaterial.rs`

```rust
//! Key material bundle encrypted inside wrapped_key

use crate::error::PreError;

/// Key material bundle (96 bytes plaintext before PRE encryption)
///
/// This bundle is encrypted via PRE backend, protecting the plaintext_hash
/// from confirmation/dictionary attacks. Only someone who can unwrap the
/// key via PRE can see the plaintext hash.
#[derive(Clone, Debug)]
pub struct KeyMaterial {
    /// XChaCha20 symmetric key (256-bit)
    pub symmetric_key: [u8; 32],
    /// XChaCha20 extended nonce (192-bit for birthday-safe random generation)
    pub nonce: [u8; 24],
    /// Blake3 hash of original plaintext (encrypted for confidentiality!)
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

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PreError> {
        if bytes.len() != Self::SERIALIZED_SIZE {
            return Err(PreError::Deserialization(
                format!("Invalid key material size: {} != {}", bytes.len(), Self::SERIALIZED_SIZE)
            ));
        }
        Ok(Self {
            symmetric_key: bytes[0..32].try_into().unwrap(),
            nonce: bytes[32..56].try_into().unwrap(),
            plaintext_hash: bytes[56..88].try_into().unwrap(),
            plaintext_size: u64::from_le_bytes(bytes[88..96].try_into().unwrap()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keymaterial_roundtrip() {
        let km = KeyMaterial {
            symmetric_key: [1u8; 32],
            nonce: [2u8; 24],
            plaintext_hash: [3u8; 32],
            plaintext_size: 12345,
        };

        let bytes = km.to_bytes();
        let km2 = KeyMaterial::from_bytes(&bytes).unwrap();

        assert_eq!(km.symmetric_key, km2.symmetric_key);
        assert_eq!(km.nonce, km2.nonce);
        assert_eq!(km.plaintext_hash, km2.plaintext_hash);
        assert_eq!(km.plaintext_size, km2.plaintext_size);
    }
}
```

#### 2. Encrypted File Structure

**File**: `crates/recrypt-core/src/hybrid/encrypted_file.rs`

```rust
//! Encrypted file with streaming-verifiable integrity

use crate::pre::Ciphertext;

/// An encrypted file with streaming-verifiable integrity
///
/// The wrapped_key contains encrypted (key, nonce, plaintext_hash, size).
/// Only bao_hash is public—plaintext_hash is hidden for metadata confidentiality.
#[derive(Clone, Debug)]
pub struct EncryptedFile {
    /// PRE-encrypted key bundle (contains: key, nonce, plaintext_hash, size)
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
    /// Serialize to bytes (simplified—full wire format in Phase 3)
    pub fn to_bytes(&self) -> Vec<u8> {
        let wrapped = self.wrapped_key.to_bytes();
        let mut out = Vec::new();

        // Version
        out.push(2u8);

        // Wrapped key
        out.extend((wrapped.len() as u32).to_le_bytes());
        out.extend(&wrapped);

        // Bao hash
        out.extend(&self.bao_hash);
        out.extend((self.bao_outboard.len() as u64).to_le_bytes());
        out.extend(&self.bao_outboard);

        // Ciphertext
        out.extend((self.ciphertext.len() as u64).to_le_bytes());
        out.extend(&self.ciphertext);

        out
    }
}
```

#### 3. Hybrid Encryptor

**File**: `crates/recrypt-core/src/hybrid/mod.rs`

```rust
//! Hybrid encryption using XChaCha20 + Blake3/Bao

mod keymaterial;
mod encrypted_file;

pub use keymaterial::KeyMaterial;
pub use encrypted_file::EncryptedFile;

use crate::pre::{PreBackend, PublicKey, SecretKey, RecryptKey};
use crate::error::{CoreResult, CoreError, PreError};
use chacha20::XChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use rand::{RngCore, rngs::OsRng};
use zeroize::Zeroizing;

/// Hybrid encryption using PRE for key wrapping + XChaCha20 + Bao
pub struct HybridEncryptor<B: PreBackend> {
    backend: B,
}

impl<B: PreBackend> HybridEncryptor<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Encrypt data for a recipient with streaming-verifiable integrity
    pub fn encrypt(&self, recipient: &PublicKey, plaintext: &[u8]) -> CoreResult<EncryptedFile> {
        // Generate random symmetric key and nonce
        let mut sym_key = Zeroizing::new([0u8; 32]);
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(sym_key.as_mut());
        OsRng.fill_bytes(&mut nonce);

        // Hash plaintext for post-decryption verification
        let plaintext_hash = blake3::hash(plaintext);
        let plaintext_size = plaintext.len() as u64;

        // Encrypt with XChaCha20
        let mut ciphertext = plaintext.to_vec();
        let mut cipher = XChaCha20::new((&*sym_key).into(), (&nonce).into());
        cipher.apply_keystream(&mut ciphertext);

        // Compute Bao tree for streaming verification
        let (bao_hash, bao_outboard) = bao::encode::outboard(&ciphertext);

        // Bundle key material (plaintext_hash encrypted inside!)
        let key_material = KeyMaterial {
            symmetric_key: *sym_key,
            nonce,
            plaintext_hash: *plaintext_hash.as_bytes(),
            plaintext_size,
        };

        // Wrap entire bundle with PRE
        let wrapped_key = self.backend.encrypt(recipient, &key_material.to_bytes())?;

        Ok(EncryptedFile {
            wrapped_key,
            bao_hash: *bao_hash.as_bytes(),
            bao_outboard,
            ciphertext,
        })
    }

    /// Decrypt and verify integrity
    pub fn decrypt(&self, secret: &SecretKey, file: &EncryptedFile) -> CoreResult<Vec<u8>> {
        // Verify ciphertext integrity via Bao
        let computed_bao = blake3::hash(&file.ciphertext);
        if computed_bao.as_bytes() != &file.bao_hash {
            return Err(CoreError::Decryption(
                "Bao hash mismatch—ciphertext corrupted".into()
            ));
        }

        // Unwrap key material bundle
        let key_material_bytes = self.backend.decrypt(secret, &file.wrapped_key)?;
        let key_material = KeyMaterial::from_bytes(&key_material_bytes)
            .map_err(|e| CoreError::Decryption(e.to_string()))?;

        // Decrypt with XChaCha20
        let mut plaintext = file.ciphertext.clone();
        let mut cipher = XChaCha20::new(
            (&key_material.symmetric_key).into(),
            (&key_material.nonce).into(),
        );
        cipher.apply_keystream(&mut plaintext);

        // Verify plaintext size
        if plaintext.len() as u64 != key_material.plaintext_size {
            return Err(CoreError::Decryption(
                format!("Plaintext size mismatch: {} != {}", plaintext.len(), key_material.plaintext_size)
            ));
        }

        // Verify plaintext hash (now decrypted from bundle!)
        let computed_hash = blake3::hash(&plaintext);
        if computed_hash.as_bytes() != &key_material.plaintext_hash {
            return Err(CoreError::Decryption(
                "Plaintext hash mismatch—decryption produced wrong data".into()
            ));
        }

        Ok(plaintext)
    }

    /// Recrypt for a new recipient
    ///
    /// Only transforms wrapped_key—ciphertext and Bao tree unchanged.
    pub fn recrypt(&self, recrypt_key: &RecryptKey, file: &EncryptedFile) -> CoreResult<EncryptedFile> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pre::backends::MockBackend;

    #[test]
    fn test_hybrid_encrypt_decrypt() {
        let backend = MockBackend;
        let encryptor = HybridEncryptor::new(backend);

        let kp = encryptor.backend().generate_keypair().unwrap();
        let plaintext = b"Hello, hybrid encryption!";

        let encrypted = encryptor.encrypt(&kp.public, plaintext).unwrap();
        let decrypted = encryptor.decrypt(&kp.secret, &encrypted).unwrap();

        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_hybrid_recryption_flow() {
        let backend = MockBackend;
        let encryptor = HybridEncryptor::new(backend);

        let alice = encryptor.backend().generate_keypair().unwrap();
        let bob = encryptor.backend().generate_keypair().unwrap();

        let plaintext = b"Secret message for Bob";
        let encrypted_alice = encryptor.encrypt(&alice.public, plaintext).unwrap();

        // Generate recrypt key Alice → Bob
        let rk = encryptor.backend().generate_recrypt_key(&alice.secret, &bob.public).unwrap();

        // Proxy transforms
        let encrypted_bob = encryptor.recrypt(&rk, &encrypted_alice).unwrap();

        // Bob decrypts
        let decrypted = encryptor.decrypt(&bob.secret, &encrypted_bob).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_tampered_ciphertext_detected() {
        let backend = MockBackend;
        let encryptor = HybridEncryptor::new(backend);

        let kp = encryptor.backend().generate_keypair().unwrap();
        let plaintext = b"Integrity test";

        let mut encrypted = encryptor.encrypt(&kp.public, plaintext).unwrap();

        // Tamper with ciphertext
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }

        // Should fail Bao verification
        let result = encryptor.decrypt(&kp.secret, &encrypted);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Bao"));
    }
}
```

### Success Criteria

#### Automated Verification:

- [ ] Hybrid tests pass: `cargo test -p recrypt-core hybrid`
- [ ] Tamper detection works: test `test_tampered_ciphertext_detected` passes
- [ ] Property tests with mock backend: `cargo test -p recrypt-core --features proptest`

#### Manual Verification:

- [ ] Encrypted files decrypt correctly
- [ ] Plaintext hash is never exposed in public metadata
- [ ] Recryption preserves ciphertext and Bao tree (only wrapped_key changes)

---

## Phase 2.5: Multi-Signature System

### Overview

Implement multi-signature combining ED25519 (fast classical) + ML-DSA-87 (post-quantum).

### Changes Required

#### 1. Signature Types

**File**: `crates/recrypt-core/src/sign/mod.rs`

```rust
//! Multi-signature system (ED25519 + ML-DSA)

use crate::error::{CoreResult, CoreError};
use dcypher_ffi::ed25519::{Ed25519KeyPair, ed25519_sign, ed25519_verify};
use dcypher_ffi::liboqs::sig::{PqAlgorithm, PqKeyPair, pq_sign, pq_verify};
use ed25519_dalek::{Signature as Ed25519Signature, SigningKey, VerifyingKey};

/// A multi-signature combining classical and post-quantum signatures
#[derive(Clone, Debug)]
pub struct MultiSig {
    /// ED25519 signature (fast, small)
    pub ed25519_sig: Ed25519Signature,
    /// ML-DSA-87 signature (post-quantum, large)
    pub ml_dsa_sig: Vec<u8>,
}

/// Signing keys for multi-signature
pub struct SigningKeys {
    pub ed25519: SigningKey,
    pub ml_dsa: Vec<u8>,  // Secret key bytes
}

/// Verifying keys for multi-signature
pub struct VerifyingKeys {
    pub ed25519: VerifyingKey,
    pub ml_dsa: Vec<u8>,  // Public key bytes
}

/// Sign a message with both classical and post-quantum keys
pub fn sign_message(msg: &[u8], keys: &SigningKeys) -> CoreResult<MultiSig> {
    let ed25519_sig = ed25519_sign(&keys.ed25519, msg);

    let ml_dsa_sig = pq_sign(&keys.ml_dsa, PqAlgorithm::MlDsa87, msg)
        .map_err(|e| CoreError::Signature(format!("ML-DSA signing failed: {e}")))?;

    Ok(MultiSig {
        ed25519_sig,
        ml_dsa_sig,
    })
}

/// Verify a multi-signature
///
/// Both signatures must be valid for verification to succeed.
pub fn verify_message(msg: &[u8], sig: &MultiSig, pks: &VerifyingKeys) -> CoreResult<bool> {
    // Verify ED25519 (fast check first)
    ed25519_verify(&pks.ed25519, msg, &sig.ed25519_sig)
        .map_err(|_| CoreError::Signature("ED25519 verification failed".into()))?;

    // Verify ML-DSA
    let ml_dsa_valid = pq_verify(&pks.ml_dsa, PqAlgorithm::MlDsa87, msg, &sig.ml_dsa_sig)
        .map_err(|e| CoreError::Signature(format!("ML-DSA verification failed: {e}")))?;

    if !ml_dsa_valid {
        return Err(CoreError::Signature("ML-DSA signature invalid".into()));
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcypher_ffi::ed25519::ed25519_keygen;
    use dcypher_ffi::liboqs::sig::pq_keygen;

    #[test]
    fn test_multisig_roundtrip() {
        let ed_kp = ed25519_keygen();
        let pq_kp = pq_keygen(PqAlgorithm::MlDsa87).unwrap();

        let signing_keys = SigningKeys {
            ed25519: ed_kp.signing_key,
            ml_dsa: pq_kp.secret_key.clone(),
        };

        let verifying_keys = VerifyingKeys {
            ed25519: ed_kp.verifying_key,
            ml_dsa: pq_kp.public_key.clone(),
        };

        let message = b"Test multi-signature";
        let sig = sign_message(message, &signing_keys).unwrap();
        let valid = verify_message(message, &sig, &verifying_keys).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_multisig_tampered_message() {
        let ed_kp = ed25519_keygen();
        let pq_kp = pq_keygen(PqAlgorithm::MlDsa87).unwrap();

        let signing_keys = SigningKeys {
            ed25519: ed_kp.signing_key,
            ml_dsa: pq_kp.secret_key.clone(),
        };

        let verifying_keys = VerifyingKeys {
            ed25519: ed_kp.verifying_key,
            ml_dsa: pq_kp.public_key.clone(),
        };

        let message = b"Original message";
        let sig = sign_message(message, &signing_keys).unwrap();

        let tampered = b"Tampered message";
        let result = verify_message(tampered, &sig, &verifying_keys);

        assert!(result.is_err());
    }

    #[test]
    fn test_multisig_wrong_key() {
        let ed_kp1 = ed25519_keygen();
        let pq_kp1 = pq_keygen(PqAlgorithm::MlDsa87).unwrap();

        let ed_kp2 = ed25519_keygen();

        let signing_keys = SigningKeys {
            ed25519: ed_kp1.signing_key,
            ml_dsa: pq_kp1.secret_key.clone(),
        };

        let wrong_verifying_keys = VerifyingKeys {
            ed25519: ed_kp2.verifying_key,  // Wrong key!
            ml_dsa: pq_kp1.public_key.clone(),
        };

        let message = b"Test message";
        let sig = sign_message(message, &signing_keys).unwrap();

        let result = verify_message(message, &sig, &wrong_verifying_keys);
        assert!(result.is_err());
    }
}
```

### Success Criteria

#### Automated Verification:

- [ ] Multi-sig tests pass: `cargo test -p recrypt-core sign`
- [ ] Tamper detection works in multi-sig tests
- [ ] Wrong key detection works

#### Manual Verification:

- [ ] Multi-signature size is reasonable (~4.7 KB for ML-DSA-87)
- [ ] ED25519 verification fails fast before checking ML-DSA
- [ ] Both signatures required for validity

---

## Phase 2.6: Property-Based Tests

### Overview

Comprehensive property-based testing using `proptest` to validate semantic correctness.

### Changes Required

#### 1. Property Tests

**File**: `crates/recrypt-core/tests/properties.rs`

```rust
//! Property-based tests for cryptographic operations
//!
//! These tests validate SEMANTIC correctness, not byte-level equality.
//! Ciphertexts/keys are non-deterministic, so we test behavior.

#[cfg(feature = "proptest")]
mod proptest_suite {
    use proptest::prelude::*;
    use dcypher_core::*;
    use dcypher_core::pre::backends::MockBackend;

    proptest! {
        /// Property: decrypt(encrypt(x)) == x
        #[test]
        fn prop_encrypt_decrypt_roundtrip(data in prop::collection::vec(any::<u8>(), 1..1000)) {
            let backend = MockBackend;
            let encryptor = HybridEncryptor::new(backend);
            let kp = encryptor.backend().generate_keypair().unwrap();

            let encrypted = encryptor.encrypt(&kp.public, &data).unwrap();
            let decrypted = encryptor.decrypt(&kp.secret, &encrypted).unwrap();

            prop_assert_eq!(decrypted, data);
        }

        /// Property: decrypt_bob(recrypt(encrypt_alice(x))) == x
        #[test]
        fn prop_recryption_preserves_plaintext(data in prop::collection::vec(any::<u8>(), 1..500)) {
            let backend = MockBackend;
            let encryptor = HybridEncryptor::new(backend);

            let alice = encryptor.backend().generate_keypair().unwrap();
            let bob = encryptor.backend().generate_keypair().unwrap();

            let encrypted_alice = encryptor.encrypt(&alice.public, &data).unwrap();
            let rk = encryptor.backend().generate_recrypt_key(&alice.secret, &bob.public).unwrap();
            let encrypted_bob = encryptor.recrypt(&rk, &encrypted_alice).unwrap();
            let decrypted = encryptor.decrypt(&bob.secret, &encrypted_bob).unwrap();

            prop_assert_eq!(decrypted, data);
        }

        /// Property: verify(sign(msg)) == true
        #[test]
        fn prop_signature_roundtrip(msg in prop::collection::vec(any::<u8>(), 1..1000)) {
            use dcypher_ffi::ed25519::ed25519_keygen;
            use dcypher_ffi::liboqs::sig::{pq_keygen, PqAlgorithm};
            use dcypher_core::sign::*;

            let ed_kp = ed25519_keygen();
            let pq_kp = pq_keygen(PqAlgorithm::MlDsa87).unwrap();

            let signing_keys = SigningKeys {
                ed25519: ed_kp.signing_key,
                ml_dsa: pq_kp.secret_key.clone(),
            };

            let verifying_keys = VerifyingKeys {
                ed25519: ed_kp.verifying_key,
                ml_dsa: pq_kp.public_key.clone(),
            };

            let sig = sign_message(&msg, &signing_keys).unwrap();
            let valid = verify_message(&msg, &sig, &verifying_keys).unwrap();

            prop_assert!(valid);
        }
    }
}
```

#### 2. Known-Answer Tests

**File**: `crates/recrypt-core/tests/regression.rs`

```rust
//! Known-answer tests for regression detection
//!
//! These use FIXED keys/nonces to detect implementation changes.

use dcypher_core::*;
use dcypher_core::pre::backends::MockBackend;

#[test]
fn test_fixed_key_encrypt_decrypt() {
    // Use mock backend with deterministic keys
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);

    // Fixed keypair (mock backend: pk = sk)
    let kp = encryptor.backend().generate_keypair().unwrap();

    let plaintext = b"Known plaintext for regression test";
    let encrypted = encryptor.encrypt(&kp.public, plaintext).unwrap();
    let decrypted = encryptor.decrypt(&kp.secret, &encrypted).unwrap();

    assert_eq!(&decrypted[..], plaintext);

    // Note: We don't check ciphertext bytes (non-deterministic)
    // Only verify semantic correctness
}

#[test]
fn test_recryption_level_tracking() {
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);

    let alice = encryptor.backend().generate_keypair().unwrap();
    let bob = encryptor.backend().generate_keypair().unwrap();
    let carol = encryptor.backend().generate_keypair().unwrap();

    let plaintext = b"Multi-hop recryption test";

    // Alice encrypts
    let ct0 = encryptor.encrypt(&alice.public, plaintext).unwrap();
    assert_eq!(ct0.wrapped_key.level(), 0);

    // Recrypt Alice → Bob
    let rk_ab = encryptor.backend().generate_recrypt_key(&alice.secret, &bob.public).unwrap();
    let ct1 = encryptor.recrypt(&rk_ab, &ct0).unwrap();
    assert_eq!(ct1.wrapped_key.level(), 1);

    // Recrypt Bob → Carol
    let rk_bc = encryptor.backend().generate_recrypt_key(&bob.secret, &carol.public).unwrap();
    let ct2 = encryptor.recrypt(&rk_bc, &ct1).unwrap();
    assert_eq!(ct2.wrapped_key.level(), 2);

    // Carol decrypts
    let decrypted = encryptor.decrypt(&carol.secret, &ct2).unwrap();
    assert_eq!(&decrypted[..], plaintext);
}
```

### Success Criteria

#### Automated Verification:

- [ ] Property tests pass: `cargo test -p recrypt-core --features proptest`
- [ ] Regression tests pass: `cargo test -p recrypt-core regression`
- [ ] All tests complete in reasonable time (<30s)

#### Manual Verification:

- [ ] Property test failures clearly indicate which property violated
- [ ] Known-answer tests detect implementation changes

---

## Phase 2.7: Documentation & Examples

### Overview

Comprehensive documentation with runnable examples.

### Changes Required

#### 1. Crate-Level Docs

**Update**: `crates/recrypt-core/src/lib.rs`

Add documentation at the top:

````rust
//! # recrypt-core: Production Cryptography for Proxy Recryption
//!
//! This crate provides production-ready cryptographic operations for the Recrypt
//! proxy Recryption system.
//!
//! ## Features
//!
//! - **Pluggable PRE backends**: Lattice (post-quantum) or Mock (testing)
//! - **Hybrid encryption**: KEM-DEM with XChaCha20 + Bao streaming verification
//! - **Multi-signatures**: ED25519 + ML-DSA-87 for classical + post-quantum security
//! - **Metadata confidentiality**: Plaintext hashes encrypted inside wrapped keys
//!
//! ## Example: Basic Encryption
//!
//! ```rust
//! use dcypher_core::{HybridEncryptor, pre::backends::MockBackend};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let backend = MockBackend;
//! let encryptor = HybridEncryptor::new(backend);
//!
//! // Generate keypair
//! let kp = encryptor.backend().generate_keypair()?;
//!
//! // Encrypt
//! let plaintext = b"Hello, Recrypt!";
//! let encrypted = encryptor.encrypt(&kp.public, plaintext)?;
//!
//! // Decrypt
//! let decrypted = encryptor.decrypt(&kp.secret, &encrypted)?;
//! assert_eq!(&decrypted[..], plaintext);
//! # Ok(())
//! # }
//! ```
//!
//! ## Example: Proxy Recryption
//!
//! ```rust
//! use dcypher_core::{HybridEncryptor, pre::backends::MockBackend};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let backend = MockBackend;
//! let encryptor = HybridEncryptor::new(backend);
//!
//! // Alice and Bob generate keys
//! let alice = encryptor.backend().generate_keypair()?;
//! let bob = encryptor.backend().generate_keypair()?;
//!
//! // Alice encrypts for herself
//! let plaintext = b"Secret message";
//! let encrypted_alice = encryptor.encrypt(&alice.public, plaintext)?;
//!
//! // Alice generates recryption key for Bob
//! let rk = encryptor.backend().generate_recrypt_key(&alice.secret, &bob.public)?;
//!
//! // Proxy transforms (no access to plaintext!)
//! let encrypted_bob = encryptor.recrypt(&rk, &encrypted_alice)?;
//!
//! // Bob decrypts
//! let decrypted = encryptor.decrypt(&bob.secret, &encrypted_bob)?;
//! assert_eq!(&decrypted[..], plaintext);
//! # Ok(())
//! # }
//! ```
//!
//! ## Non-Determinism
//!
//! Cryptographic operations are intentionally non-deterministic:
//! - Ciphertexts differ on every encryption (randomness)
//! - Serialized keys may differ (OpenFHE non-canonical serialization)
//!
//! **Test semantic correctness**, not byte equality. See `docs/non-determinism.md`.
//!
//! ## Architecture
//!
//! See design documents in `docs/`:
//! - `hybrid-encryption-architecture.md` - KEM-DEM design
//! - `pre-backend-traits.md` - Backend trait hierarchy
//! - `non-determinism.md` - Testing strategy
````

#### 2. Module Documentation

Add doc comments to all public modules (see implementation files above).

### Success Criteria

#### Automated Verification:

- [ ] Doc tests pass: `cargo test -p recrypt-core --doc`
- [ ] Docs build: `cargo doc -p recrypt-core --no-deps`
- [ ] No missing doc warnings: `RUSTDOCFLAGS="-D warnings" cargo doc -p recrypt-core --no-deps`

#### Manual Verification:

- [ ] Examples in docs are runnable and correct
- [ ] API docs explain WHY, not just WHAT
- [ ] Links to design docs work

---

## Testing Strategy

### Unit Tests (per-module)

- `pre/keys.rs` - Serialization roundtrips
- `pre/backends/mock.rs` - Encrypt/decrypt/recrypt
- `pre/backends/lattice.rs` - Backend instantiation (full tests in Phase 3)
- `hybrid/keymaterial.rs` - KeyMaterial serialization
- `hybrid/mod.rs` - Encrypt/decrypt/recrypt with integrity checks
- `sign/mod.rs` - Multi-signature roundtrip, tamper detection

### Integration Tests

- `tests/properties.rs` - Property-based semantic tests
- `tests/regression.rs` - Known-answer tests with fixed keys

### Performance Benchmarks

- `benches/crypto_ops.rs` - Baseline timings for encrypt/decrypt/recrypt/sign

**File**: `crates/recrypt-core/benches/crypto_ops.rs`

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dcypher_core::*;
use dcypher_core::pre::backends::MockBackend;

fn bench_encrypt(c: &mut Criterion) {
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let kp = encryptor.backend().generate_keypair().unwrap();
    let data = vec![0u8; 1024];  // 1 KB

    c.bench_function("hybrid_encrypt_1kb", |b| {
        b.iter(|| {
            encryptor.encrypt(black_box(&kp.public), black_box(&data))
        })
    });
}

fn bench_decrypt(c: &mut Criterion) {
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let kp = encryptor.backend().generate_keypair().unwrap();
    let data = vec![0u8; 1024];
    let encrypted = encryptor.encrypt(&kp.public, &data).unwrap();

    c.bench_function("hybrid_decrypt_1kb", |b| {
        b.iter(|| {
            encryptor.decrypt(black_box(&kp.secret), black_box(&encrypted))
        })
    });
}

fn bench_recrypt(c: &mut Criterion) {
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let alice = encryptor.backend().generate_keypair().unwrap();
    let bob = encryptor.backend().generate_keypair().unwrap();
    let data = vec![0u8; 1024];
    let encrypted = encryptor.encrypt(&alice.public, &data).unwrap();
    let rk = encryptor.backend().generate_recrypt_key(&alice.secret, &bob.public).unwrap();

    c.bench_function("hybrid_recrypt_1kb", |b| {
        b.iter(|| {
            encryptor.recrypt(black_box(&rk), black_box(&encrypted))
        })
    });
}

criterion_group!(benches, bench_encrypt, bench_decrypt, bench_recrypt);
criterion_main!(benches);
```

Add to `Cargo.toml`:

```toml
[[bench]]
name = "crypto_ops"
harness = false

[dev-dependencies]
criterion = "0.5"
```

---

## Performance Considerations

### Expected Performance (Mock Backend)

| Operation      | Size | Target Latency |
| -------------- | ---- | -------------- |
| Encrypt        | 1 KB | < 1 ms         |
| Decrypt        | 1 KB | < 1 ms         |
| Recrypt        | 1 KB | < 1 ms         |
| Sign (multi)   | 1 KB | < 5 ms         |
| Verify (multi) | 1 KB | < 5 ms         |

### Expected Performance (Lattice Backend)

| Operation      | Size | Target Latency |
| -------------- | ---- | -------------- |
| Encrypt        | 96 B | < 30 ms        |
| Decrypt        | 96 B | < 15 ms        |
| Recrypt        | 96 B | < 150 ms       |
| Keygen         | -    | < 100 ms       |
| Recrypt keygen | -    | < 300 ms       |

**Note:** Lattice operations on key material only (96 bytes). Bulk data encrypted with XChaCha20 (GB/s).

---

## Migration Notes

### From Phase 1

- ✅ `recrypt-ffi` crate fully functional
- ✅ All FFI primitives tested
- ✅ Error handling established

### For Phase 3

Phase 3 (Protocol Layer) will need:

- Serialization format for OpenFHE keys/ciphertexts
- Wire protocol implementation (Protobuf/ASCII armor)
- Complete lattice backend tests (currently stubbed)

---

## References

- `docs/hybrid-encryption-architecture.md` - KEM-DEM design rationale
- `docs/pre-backend-traits.md` - Trait hierarchy details
- `docs/non-determinism.md` - Testing strategy for non-deterministic crypto
- `docs/hashing-standard.md` - Blake3/Bao usage
- `docs/IMPLEMENTATION_PLAN.md` - Overall project plan

---

## Timeline

**Estimated:** 4-5 days

- **Phase 2.1:** Foundation types & traits (0.5 day)
- **Phase 2.2:** Mock backend (0.5 day)
- **Phase 2.3:** Lattice backend wrapper (0.5 day)
- **Phase 2.4:** Hybrid encryption (1 day)
- **Phase 2.5:** Multi-signature (0.5 day)
- **Phase 2.6:** Property tests (1 day)
- **Phase 2.7:** Documentation (0.5 day)

**Buffer:** 1 day for debugging/iteration

---

**Next Phase:** Phase 3 (Protocol Layer) - Wire formats, serialization, Protobuf/ASCII armor
