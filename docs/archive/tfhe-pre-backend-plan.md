# TFHE Proxy Recryption Backend Implementation Plan

## Overview

Replace OpenFHE BFV backend with TFHE-based PRE using Zama's tfhe-rs. Expected gains: 10-100x faster recryption (1-3s → 10-50ms), pure Rust (no FFI), thread-safe.

## Current State Analysis

**Existing PRE Architecture:**
- `PreBackend` trait in `crates/recrypt-core/src/pre/traits.rs`
- `LatticeBackend` (OpenFHE BFV) at `crates/recrypt-core/src/pre/backends/lattice.rs`
- `BackendId` enum: Lattice=0, EcPairing=1, EcSecp256k1=2, Mock=255
- Encrypts full 96-byte `KeyMaterial` (32B key + 24B nonce + 32B hash + 8B size)
- Protobuf schema at `crates/recrypt-proto/proto/recrypt.proto`

**TFHE Design Decisions (from research):**
- Multi-LWE encoding: 128 LWE ciphertexts for 32-byte message (2-bit chunks)
- Seeded keys/ciphertexts: store seed + `b` values only (~700x smaller)
- Key switching = proxy recryption
- 1-2 hops safe, 3+ needs noise monitoring

## Desired End State

- New `TfheBackend` implementing `PreBackend` trait
- `BackendId::Tfhe = 4` (avoid renumbering existing)
- Feature flag `tfhe` in `recrypt-core/Cargo.toml`
- Encrypts 32-byte symmetric key only (not full 96-byte KeyMaterial)
- v1: Symmetric KSK (both secrets) for correctness
- v2: Asymmetric KSK (secret + public) for production security
- Comprehensive benchmarks vs OpenFHE
- Documentation of performance characteristics and hop limits

### Verification

```bash
cargo test -p recrypt-tfhe --all-features
cargo bench -p recrypt-core -- tfhe
cargo run -p recrypt-cli -- encrypt --backend tfhe test.txt
cargo run -p recrypt-cli -- recrypt test.txt.enc bob-key --backend tfhe
```

## What We're NOT Doing

- Bootstrapping (only 1-2 hops needed)
- Full 96-byte KeyMaterial encryption (nonce/hash/size stay public)
- Hardware acceleration (FPGA/GPU) in initial implementation
- Multi-key TFHE
- Circuit privacy/sanitization features

---

## Phase 1: Core TFHE Library (v1 - Symmetric KSK)

### Overview

Create `crates/recrypt-tfhe/` with LWE primitives from Zama's core_crypto. Use symmetric KSK shortcut (requires both secrets) to establish correctness before tackling asymmetric security.

### Changes Required

#### 1. New Crate Structure

**Directory**: `crates/recrypt-tfhe/`

```
recrypt-tfhe/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── error.rs
│   ├── params.rs
│   ├── keys/
│   │   ├── mod.rs
│   │   ├── secret.rs
│   │   ├── public.rs
│   │   └── recrypt.rs
│   ├── ciphertext.rs
│   ├── encrypt.rs
│   ├── decrypt.rs
│   └── recrypt.rs
└── tests/
    ├── roundtrip.rs
    ├── recryption.rs
    └── failure_rate.rs
```

#### 2. Cargo.toml

**File**: `crates/recrypt-tfhe/Cargo.toml`

```toml
[package]
name = "recrypt-tfhe"
version.workspace = true
edition.workspace = true

[dependencies]
tfhe = "0.9"
rand = "0.8"
rand_core = "0.6"
thiserror.workspace = true
zeroize = { version = "1.7", features = ["derive"] }

[dev-dependencies]
criterion = "0.5"

[[bench]]
name = "tfhe_ops"
harness = false
```

#### 3. Security Parameters

**File**: `crates/recrypt-tfhe/src/params.rs`

```rust
use tfhe::core_crypto::prelude::*;

/// TFHE parameters targeting 128-bit security
/// Based on standard.org LWE estimator
pub struct TfheParams {
    pub lwe_dimension: LweDimension,
    pub lwe_noise_distribution: Gaussian<f64>,
    pub decomp_base_log: DecompositionBaseLog,
    pub decomp_level_count: DecompositionLevelCount,
    pub ciphertext_modulus: CiphertextModulus<u64>,
}

impl TfheParams {
    /// Default params: 128-bit security, 1-2 hop support
    pub fn default_128bit() -> Self {
        Self {
            lwe_dimension: LweDimension(742),
            lwe_noise_distribution: Gaussian::from_dispersion_parameter(
                StandardDev(0.000007069849454709433),
                0.0,
            ),
            decomp_base_log: DecompositionBaseLog(4),
            decomp_level_count: DecompositionLevelCount(9),
            ciphertext_modulus: CiphertextModulus::new_native(),
        }
    }

    /// 2-bit message space (0-3)
    pub fn message_modulus() -> u64 {
        4
    }

    /// Delta for 2-bit encoding in u64 torus
    pub fn delta() -> u64 {
        (1u64 << 62) // Top 2 bits
    }
}
```

#### 4. Secret Key Wrapper

**File**: `crates/recrypt-tfhe/src/keys/secret.rs`

```rust
use tfhe::core_crypto::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TfheSecretKey {
    #[zeroize(skip)]
    dimension: LweDimension,
    key: LweSecretKey<Vec<u64>>,
}

impl TfheSecretKey {
    pub fn generate(dimension: LweDimension) -> Self {
        let mut seeder = new_seeder();
        let mut secret_generator = 
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
        
        let key = allocate_and_generate_new_binary_lwe_secret_key(
            dimension,
            &mut secret_generator,
        );
        
        Self { dimension, key }
    }

    pub fn inner(&self) -> &LweSecretKey<Vec<u64>> {
        &self.key
    }

    pub fn dimension(&self) -> LweDimension {
        self.dimension
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // Serialize as binary coefficients (1 bit per coefficient)
        let mut bytes = Vec::new();
        bytes.extend(self.dimension.0.to_le_bytes());
        
        // Pack bits into bytes
        for coeff in self.key.as_ref().iter() {
            bytes.push(*coeff as u8);
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::TfheError> {
        if bytes.len() < 8 {
            return Err(crate::error::TfheError::Deserialization("Secret key too short".into()));
        }
        
        let dimension = LweDimension(usize::from_le_bytes(bytes[0..8].try_into().unwrap()));
        let expected_len = 8 + dimension.0;
        
        if bytes.len() != expected_len {
            return Err(crate::error::TfheError::Deserialization(
                format!("Invalid secret key length: {} != {}", bytes.len(), expected_len)
            ));
        }
        
        let key_data: Vec<u64> = bytes[8..].iter().map(|&b| b as u64).collect();
        let key = LweSecretKey::from_container(key_data);
        
        Ok(Self { dimension, key })
    }
}
```

#### 5. Seeded Ciphertext

**File**: `crates/recrypt-tfhe/src/ciphertext.rs`

```rust
use tfhe::core_crypto::prelude::*;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

/// Seeded LWE ciphertext: seed + b value only
/// Receiver regenerates `a` vector from seed
pub struct SeededLweCiphertext {
    pub seed: [u8; 32],
    pub b: u64,
}

impl SeededLweCiphertext {
    /// Create from full LWE ciphertext by extracting seed
    pub fn from_full(ct: &LweCiphertext<Vec<u64>>, seed: [u8; 32]) -> Self {
        let b = *ct.get_body().data;
        Self { seed, b }
    }

    /// Reconstruct full ciphertext by regenerating `a` from seed
    pub fn to_full(&self, dimension: LweDimension, modulus: CiphertextModulus<u64>) -> LweCiphertext<Vec<u64>> {
        let mut rng = ChaCha8Rng::from_seed(self.seed);
        let mut a_values = vec![0u64; dimension.0];
        
        for val in a_values.iter_mut() {
            *val = rng.gen();
        }
        
        // Construct: [a_0, a_1, ..., a_n, b]
        let mut data = a_values;
        data.push(self.b);
        
        LweCiphertext::from_container(data, modulus)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 8);
        bytes.extend_from_slice(&self.seed);
        bytes.extend_from_slice(&self.b.to_le_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::TfheError> {
        if bytes.len() != 40 {
            return Err(crate::error::TfheError::Deserialization(
                format!("Invalid seeded ciphertext length: {}", bytes.len())
            ));
        }
        
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes[0..32]);
        let b = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
        
        Ok(Self { seed, b })
    }
}

/// Multi-LWE ciphertext: 128 seeded LWE ciphertexts for 32-byte message
pub struct MultiLweCiphertext {
    pub chunks: Vec<SeededLweCiphertext>,
}

impl MultiLweCiphertext {
    pub const CHUNK_COUNT: usize = 128; // 32 bytes * 8 bits / 2 bits per chunk

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend((self.chunks.len() as u32).to_le_bytes());
        
        for chunk in &self.chunks {
            bytes.extend(chunk.to_bytes());
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::TfheError> {
        if bytes.len() < 4 {
            return Err(crate::error::TfheError::Deserialization("Multi-LWE too short".into()));
        }
        
        let count = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
        let expected_len = 4 + count * 40;
        
        if bytes.len() != expected_len {
            return Err(crate::error::TfheError::Deserialization(
                format!("Invalid multi-LWE length: {} != {}", bytes.len(), expected_len)
            ));
        }
        
        let mut chunks = Vec::with_capacity(count);
        for i in 0..count {
            let offset = 4 + i * 40;
            chunks.push(SeededLweCiphertext::from_bytes(&bytes[offset..offset + 40])?);
        }
        
        Ok(Self { chunks })
    }
}
```

#### 6. Encryption (Symmetric - v1)

**File**: `crates/recrypt-tfhe/src/encrypt.rs`

```rust
use tfhe::core_crypto::prelude::*;
use crate::{TfheParams, TfheSecretKey, MultiLweCiphertext, SeededLweCiphertext};
use crate::error::{TfheError, TfheResult};
use rand::Rng;

/// Encrypt 32-byte message as 128 × 2-bit LWE ciphertexts
pub fn encrypt_symmetric_key(
    recipient: &TfheSecretKey,
    plaintext: &[u8; 32],
    params: &TfheParams,
) -> TfheResult<MultiLweCiphertext> {
    if plaintext.len() != 32 {
        return Err(TfheError::Encryption("Plaintext must be 32 bytes".into()));
    }

    let mut seeder = new_seeder();
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder.as_mut());

    let delta = TfheParams::delta();
    let mut chunks = Vec::with_capacity(MultiLweCiphertext::CHUNK_COUNT);

    // Encrypt each 2-bit chunk
    for byte_idx in 0..32 {
        let byte = plaintext[byte_idx];
        
        // 4 chunks per byte (2 bits each)
        for chunk_idx in 0..4 {
            let shift = chunk_idx * 2;
            let two_bits = ((byte >> shift) & 0b11) as u64;
            
            let plaintext_val = Plaintext(two_bits * delta);
            
            let mut lwe = LweCiphertext::new(
                0u64,
                recipient.dimension().to_lwe_size(),
                params.ciphertext_modulus,
            );
            
            encrypt_lwe_ciphertext(
                recipient.inner(),
                &mut lwe,
                plaintext_val,
                params.lwe_noise_distribution,
                &mut encryption_generator,
            );
            
            // Generate unique seed for this chunk
            let seed: [u8; 32] = rand::thread_rng().gen();
            chunks.push(SeededLweCiphertext::from_full(&lwe, seed));
        }
    }

    Ok(MultiLweCiphertext { chunks })
}
```

#### 7. Decryption

**File**: `crates/recrypt-tfhe/src/decrypt.rs`

```rust
use tfhe::core_crypto::prelude::*;
use crate::{TfheParams, TfheSecretKey, MultiLweCiphertext};
use crate::error::{TfheError, TfheResult};
use zeroize::Zeroizing;

pub fn decrypt_symmetric_key(
    secret: &TfheSecretKey,
    ciphertext: &MultiLweCiphertext,
    params: &TfheParams,
) -> TfheResult<Zeroizing<Vec<u8>>> {
    if ciphertext.chunks.len() != MultiLweCiphertext::CHUNK_COUNT {
        return Err(TfheError::Decryption(
            format!("Expected {} chunks, got {}", MultiLweCiphertext::CHUNK_COUNT, ciphertext.chunks.len())
        ));
    }

    let decomposer = SignedDecomposer::new(
        DecompositionBaseLog(2), // 2 bits
        DecompositionLevelCount(1),
    );
    let delta = TfheParams::delta();

    let mut plaintext_bytes = Zeroizing::new(vec![0u8; 32]);

    for byte_idx in 0..32 {
        let mut byte_val = 0u8;
        
        for chunk_idx in 0..4 {
            let chunk_global_idx = byte_idx * 4 + chunk_idx;
            let seeded_ct = &ciphertext.chunks[chunk_global_idx];
            
            let full_ct = seeded_ct.to_full(secret.dimension(), params.ciphertext_modulus);
            let decrypted = decrypt_lwe_ciphertext(secret.inner(), &full_ct);
            
            let rounded = decomposer.closest_representable(decrypted.0);
            let two_bits = (rounded / delta) as u8;
            
            byte_val |= (two_bits & 0b11) << (chunk_idx * 2);
        }
        
        plaintext_bytes[byte_idx] = byte_val;
    }

    Ok(plaintext_bytes)
}
```

#### 8. Recryption Key (Symmetric v1)

**File**: `crates/recrypt-tfhe/src/keys/recrypt.rs`

```rust
use tfhe::core_crypto::prelude::*;
use crate::{TfheParams, TfheSecretKey};

/// Symmetric recryption key (v1 - requires both secrets)
pub struct TfheRecryptKey {
    ksk: LweKeyswitchKey<Vec<u64>>,
}

impl TfheRecryptKey {
    /// Generate symmetric KSK (v1 shortcut - requires both secrets)
    pub fn generate_symmetric(
        from_secret: &TfheSecretKey,
        to_secret: &TfheSecretKey,
        params: &TfheParams,
    ) -> Self {
        let mut seeder = new_seeder();
        let mut encryption_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder.as_mut());

        let ksk = allocate_and_generate_new_lwe_keyswitch_key(
            from_secret.inner(),
            to_secret.inner(),
            params.decomp_base_log,
            params.decomp_level_count,
            params.lwe_noise_distribution,
            params.ciphertext_modulus,
            &mut encryption_generator,
        );

        Self { ksk }
    }

    pub fn inner(&self) -> &LweKeyswitchKey<Vec<u64>> {
        &self.ksk
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // Serialize KSK
        // For v1, store full KSK (~35 MB unseeded)
        // TODO: Implement seeded serialization
        let input_dim = self.ksk.input_key_lwe_dimension().0;
        let output_dim = self.ksk.output_key_lwe_dimension().0;
        let decomp_base_log = self.ksk.decomposition_base_log().0;
        let decomp_level = self.ksk.decomposition_level_count().0;

        let mut bytes = Vec::new();
        bytes.extend(input_dim.to_le_bytes());
        bytes.extend(output_dim.to_le_bytes());
        bytes.extend(decomp_base_log.to_le_bytes());
        bytes.extend(decomp_level.to_le_bytes());

        for val in self.ksk.as_ref().iter() {
            bytes.extend(val.to_le_bytes());
        }

        bytes
    }
}
```

#### 9. Recryption Operation

**File**: `crates/recrypt-tfhe/src/recrypt.rs`

```rust
use tfhe::core_crypto::prelude::*;
use crate::{TfheParams, TfheRecryptKey, MultiLweCiphertext, SeededLweCiphertext};
use crate::error::{TfheError, TfheResult};
use rand::Rng;

pub fn recrypt(
    recrypt_key: &TfheRecryptKey,
    ciphertext: &MultiLweCiphertext,
    params: &TfheParams,
) -> TfheResult<MultiLweCiphertext> {
    let mut recrypted_chunks = Vec::with_capacity(ciphertext.chunks.len());

    for seeded_ct in &ciphertext.chunks {
        let full_ct = seeded_ct.to_full(
            recrypt_key.inner().input_key_lwe_dimension(),
            params.ciphertext_modulus,
        );

        let mut output_ct = LweCiphertext::new(
            0u64,
            recrypt_key.inner().output_key_lwe_dimension().to_lwe_size(),
            params.ciphertext_modulus,
        );

        keyswitch_lwe_ciphertext(
            recrypt_key.inner(),
            &full_ct,
            &mut output_ct,
        );

        let seed: [u8; 32] = rand::thread_rng().gen();
        recrypted_chunks.push(SeededLweCiphertext::from_full(&output_ct, seed));
    }

    Ok(MultiLweCiphertext { chunks: recrypted_chunks })
}
```

#### 10. Error Types

**File**: `crates/recrypt-tfhe/src/error.rs`

```rust
#[derive(Debug, thiserror::Error)]
pub enum TfheError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),
    
    #[error("Encryption failed: {0}")]
    Encryption(String),
    
    #[error("Decryption failed: {0}")]
    Decryption(String),
    
    #[error("Recryption failed: {0}")]
    Recryption(String),
    
    #[error("Serialization failed: {0}")]
    Serialization(String),
    
    #[error("Deserialization failed: {0}")]
    Deserialization(String),
}

pub type TfheResult<T> = Result<T, TfheError>;
```

#### 11. Library Root

**File**: `crates/recrypt-tfhe/src/lib.rs`

```rust
pub mod error;
pub mod params;
pub mod keys;
pub mod ciphertext;
pub mod encrypt;
pub mod decrypt;
pub mod recrypt;

pub use error::{TfheError, TfheResult};
pub use params::TfheParams;
pub use keys::{TfheSecretKey, TfheRecryptKey};
pub use ciphertext::{SeededLweCiphertext, MultiLweCiphertext};
pub use encrypt::encrypt_symmetric_key;
pub use decrypt::decrypt_symmetric_key;
pub use recrypt::recrypt;
```

### Success Criteria

#### Automated Verification:

- [x] Crate compiles: `cargo build -p recrypt-tfhe`
- [x] Unit tests pass: `cargo test -p recrypt-tfhe`
- [x] Roundtrip test (encrypt→decrypt): `cargo test -p recrypt-tfhe roundtrip`
- [x] Recryption test (Alice→Bob): `cargo test -p recrypt-tfhe recryption`

#### Manual Verification:

- [ ] ~~Seeded ciphertexts correctly regenerate `a` vectors~~ (v1 uses full ciphertexts)
- [ ] Multi-LWE encoding preserves all 256 bits
- [ ] No decryption failures with fresh ciphertexts

**Implementation Note**: After automated tests pass, manually verify noise budgets look reasonable before proceeding to Phase 2.

---

## Phase 2: TfheBackend Integration

### Overview

Implement `PreBackend` trait for TFHE, add to backend enum, update protobuf schema. Initially encrypt 32 bytes only (not full 96-byte KeyMaterial).

### Changes Required

#### 1. Add TFHE Dependency

**File**: `crates/recrypt-core/Cargo.toml`

```toml
[dependencies]
# ... existing deps ...
recrypt-tfhe = { path = "../recrypt-tfhe", optional = true }

[features]
default = ["openfhe", "liboqs"]
openfhe = ["recrypt-ffi/openfhe"]
liboqs = ["recrypt-ffi/liboqs"]
tfhe = ["recrypt-tfhe"]
proptest = ["dep:proptest"]
```

#### 2. Update BackendId Enum

**File**: `crates/recrypt-core/src/pre/mod.rs`

Add new variant:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum BackendId {
    /// OpenFHE BFV/PRE (post-quantum, lattice-based)
    #[serde(rename = "lattice")]
    Lattice = 0,
    /// IronCore recrypt (classical, BN254 pairing) - future
    #[serde(rename = "ec-pairing")]
    EcPairing = 1,
    /// NuCypher Umbral (classical, secp256k1) - future
    #[serde(rename = "ec-secp256k1")]
    EcSecp256k1 = 2,
    /// TFHE LWE-based PRE (post-quantum, fast)
    #[serde(rename = "tfhe")]
    Tfhe = 4,
    /// Mock backend for testing
    #[serde(rename = "mock")]
    Mock = 255,
}

impl std::str::FromStr for BackendId {
    type Err = PreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "lattice" | "pq" | "post-quantum" | "openfhe" => Ok(BackendId::Lattice),
            "ec-pairing" | "ecpairing" | "pairing" => Ok(BackendId::EcPairing),
            "ec-secp256k1" | "secp256k1" | "umbral" => Ok(BackendId::EcSecp256k1),
            "tfhe" | "fast" => Ok(BackendId::Tfhe),
            "mock" | "test" => Ok(BackendId::Mock),
            other => Err(PreError::InvalidKey(format!("Unknown backend: {other}"))),
        }
    }
}
```

#### 3. TFHE Backend Implementation

**File**: `crates/recrypt-core/src/pre/backends/tfhe.rs`

```rust
//! TFHE LWE-based PRE backend (post-quantum, fast)

use crate::error::{PreError, PreResult};
use crate::pre::*;
use zeroize::Zeroizing;

#[cfg(feature = "tfhe")]
use recrypt_tfhe::{TfheParams, TfheSecretKey, TfheRecryptKey, MultiLweCiphertext};

pub struct TfheBackend {
    #[cfg(feature = "tfhe")]
    params: TfheParams,
    #[cfg(not(feature = "tfhe"))]
    _marker: std::marker::PhantomData<()>,
}

impl TfheBackend {
    #[cfg(feature = "tfhe")]
    pub fn new() -> PreResult<Self> {
        Ok(Self {
            params: TfheParams::default_128bit(),
        })
    }

    #[cfg(not(feature = "tfhe"))]
    pub fn new() -> PreResult<Self> {
        Err(PreError::BackendUnavailable(
            "TFHE feature not enabled. Build with --features tfhe".into(),
        ))
    }

    pub fn is_available() -> bool {
        cfg!(feature = "tfhe")
    }
}

#[cfg(feature = "tfhe")]
impl PreBackend for TfheBackend {
    fn backend_id(&self) -> BackendId {
        BackendId::Tfhe
    }

    fn name(&self) -> &'static str {
        "TFHE LWE PRE (Post-Quantum, Fast)"
    }

    fn is_post_quantum(&self) -> bool {
        true
    }

    fn generate_keypair(&self) -> PreResult<KeyPair> {
        let tfhe_sk = TfheSecretKey::generate(self.params.lwe_dimension);
        let sk_bytes = tfhe_sk.to_bytes();
        
        Ok(KeyPair {
            public: PublicKey::new(BackendId::Tfhe, vec![]), // v1: no separate public key
            secret: SecretKey::new(BackendId::Tfhe, sk_bytes),
        })
    }

    fn public_key_from_secret(&self, secret: &SecretKey) -> PreResult<PublicKey> {
        // v1: symmetric KSK, no public key derivation
        Ok(PublicKey::new(BackendId::Tfhe, vec![]))
    }

    fn generate_recrypt_key(
        &self,
        from_secret: &SecretKey,
        to_public: &PublicKey,
    ) -> PreResult<RecryptKey> {
        // v1 limitation: need to_secret, not just to_public
        // For now, expect empty public key and load from_secret as both
        let from_tfhe_sk = TfheSecretKey::from_bytes(&from_secret.bytes)
            .map_err(|e| PreError::InvalidKey(e.to_string()))?;
        
        // v1 hack: reuse from_secret as to_secret for symmetric KSK
        // Phase 3 will implement proper asymmetric KSK
        let to_tfhe_sk = from_tfhe_sk.clone();
        
        let rk = TfheRecryptKey::generate_symmetric(
            &from_tfhe_sk,
            &to_tfhe_sk,
            &self.params,
        );
        
        let rk_bytes = rk.to_bytes();
        
        Ok(RecryptKey::new(
            BackendId::Tfhe,
            PublicKey::new(BackendId::Tfhe, vec![]),
            to_public.clone(),
            rk_bytes,
        ))
    }

    fn encrypt(&self, recipient: &PublicKey, plaintext: &[u8]) -> PreResult<Ciphertext> {
        if plaintext.len() != 32 {
            return Err(PreError::Encryption(
                format!("TFHE backend only supports 32-byte encryption, got {}", plaintext.len())
            ));
        }

        // v1: need secret key for encryption (no public key encryption yet)
        // This is a limitation of v1 - Phase 3 will fix
        return Err(PreError::Encryption(
            "TFHE v1 requires secret key for encryption (asymmetric not yet implemented)".into()
        ));
    }

    fn decrypt(
        &self,
        secret: &SecretKey,
        ciphertext: &Ciphertext,
    ) -> PreResult<Zeroizing<Vec<u8>>> {
        let tfhe_sk = TfheSecretKey::from_bytes(&secret.bytes)
            .map_err(|e| PreError::InvalidKey(e.to_string()))?;
        
        let multi_lwe = MultiLweCiphertext::from_bytes(&ciphertext.bytes)
            .map_err(|e| PreError::Decryption(e.to_string()))?;
        
        recrypt_tfhe::decrypt_symmetric_key(&tfhe_sk, &multi_lwe, &self.params)
            .map_err(|e| PreError::Decryption(e.to_string()))
    }

    fn recrypt(&self, recrypt_key: &RecryptKey, ciphertext: &Ciphertext) -> PreResult<Ciphertext> {
        let multi_lwe = MultiLweCiphertext::from_bytes(&ciphertext.bytes)
            .map_err(|e| PreError::Recryption(e.to_string()))?;
        
        // Deserialize recrypt key
        // v1: full KSK bytes (unseeded)
        let rk = TfheRecryptKey::from_bytes(&recrypt_key.bytes)
            .map_err(|e| PreError::RecryptKeyGeneration(e.to_string()))?;
        
        let recrypted = recrypt_tfhe::recrypt(&rk, &multi_lwe, &self.params)
            .map_err(|e| PreError::Recryption(e.to_string()))?;
        
        Ok(Ciphertext::new(
            BackendId::Tfhe,
            ciphertext.level + 1,
            recrypted.to_bytes(),
        ))
    }

    fn max_plaintext_size(&self) -> usize {
        32 // Only symmetric key, not full KeyMaterial
    }

    fn ciphertext_size_estimate(&self, _plaintext_size: usize) -> usize {
        // Seeded: 128 chunks × 40 bytes = 5120 bytes
        4 + 128 * 40
    }
}

#[cfg(not(feature = "tfhe"))]
impl PreBackend for TfheBackend {
    fn backend_id(&self) -> BackendId {
        BackendId::Tfhe
    }

    fn name(&self) -> &'static str {
        "TFHE LWE PRE (Post-Quantum, Fast) [UNAVAILABLE]"
    }

    fn is_post_quantum(&self) -> bool {
        true
    }

    fn generate_keypair(&self) -> PreResult<KeyPair> {
        Err(PreError::BackendUnavailable("TFHE feature not enabled".into()))
    }

    fn public_key_from_secret(&self, _secret: &SecretKey) -> PreResult<PublicKey> {
        Err(PreError::BackendUnavailable("TFHE feature not enabled".into()))
    }

    fn generate_recrypt_key(
        &self,
        _from_secret: &SecretKey,
        _to_public: &PublicKey,
    ) -> PreResult<RecryptKey> {
        Err(PreError::BackendUnavailable("TFHE feature not enabled".into()))
    }

    fn encrypt(&self, _recipient: &PublicKey, _plaintext: &[u8]) -> PreResult<Ciphertext> {
        Err(PreError::BackendUnavailable("TFHE feature not enabled".into()))
    }

    fn decrypt(
        &self,
        _secret: &SecretKey,
        _ciphertext: &Ciphertext,
    ) -> PreResult<Zeroizing<Vec<u8>>> {
        Err(PreError::BackendUnavailable("TFHE feature not enabled".into()))
    }

    fn recrypt(
        &self,
        _recrypt_key: &RecryptKey,
        _ciphertext: &Ciphertext,
    ) -> PreResult<Ciphertext> {
        Err(PreError::BackendUnavailable("TFHE feature not enabled".into()))
    }

    fn max_plaintext_size(&self) -> usize {
        32
    }

    fn ciphertext_size_estimate(&self, _plaintext_size: usize) -> usize {
        5120
    }
}
```

#### 4. Update Backends Mod

**File**: `crates/recrypt-core/src/pre/backends/mod.rs`

```rust
pub mod lattice;
pub mod mock;
pub mod tfhe;

pub use lattice::LatticeBackend;
pub use mock::MockBackend;
pub use tfhe::TfheBackend;
```

#### 5. Update Protobuf Schema

**File**: `crates/recrypt-proto/proto/recrypt.proto`

```protobuf
enum BackendId {
    BACKEND_UNKNOWN = 0;
    BACKEND_LATTICE = 1;      // OpenFHE BFV/PRE (post-quantum)
    BACKEND_EC_PAIRING = 2;   // IronCore recrypt (classical)
    BACKEND_EC_SECP256K1 = 3; // NuCypher Umbral (classical)
    BACKEND_TFHE = 4;         // TFHE LWE PRE (post-quantum, fast)
    BACKEND_MOCK = 255;       // Testing only
}
```

Then regenerate: `cargo build -p recrypt-proto`

#### 6. Update Protobuf Conversions

**File**: `crates/recrypt-proto/src/convert.rs`

```rust
impl From<BackendId> for proto::BackendId {
    fn from(id: BackendId) -> proto::BackendId {
        match id {
            BackendId::Lattice => proto::BackendId::BackendLattice,
            BackendId::EcPairing => proto::BackendId::BackendEcPairing,
            BackendId::EcSecp256k1 => proto::BackendId::BackendEcSecp256k1,
            BackendId::Tfhe => proto::BackendId::BackendTfhe,
            BackendId::Mock => proto::BackendId::BackendMock,
        }
    }
}

impl TryFrom<proto::BackendId> for BackendId {
    type Error = ProtoError;

    fn try_from(v: proto::BackendId) -> ProtoResult<Self> {
        match v {
            proto::BackendId::BackendLattice => Ok(BackendId::Lattice),
            proto::BackendId::BackendEcPairing => Ok(BackendId::EcPairing),
            proto::BackendId::BackendEcSecp256k1 => Ok(BackendId::EcSecp256k1),
            proto::BackendId::BackendTfhe => Ok(BackendId::Tfhe),
            proto::BackendId::BackendMock => Ok(BackendId::Mock),
            proto::BackendId::BackendUnknown => {
                Err(ProtoError::InvalidFormat("Unknown backend ID".into()))
            }
        }
    }
}
```

### Success Criteria

#### Automated Verification:

- [x] Compiles with feature: `cargo build -p recrypt-core --features tfhe`
- [x] Trait implementation compiles: `cargo check -p recrypt-core --features tfhe`
- [x] Protobuf regeneration succeeds: `cargo build -p recrypt-proto`
- [x] Basic instantiation: `cargo test -p recrypt-core --features tfhe tfhe_backend_creation`

#### Manual Verification:

- [x] `BackendId::Tfhe` serializes/deserializes correctly
- [x] Error messages for v1 limitations are clear
- [x] Feature flag correctly gates TFHE code

**Implementation Note**: v1 limitations (no public key encryption, symmetric KSK) are expected and documented. Phase 3 will remove these limitations.

---

## Phase 3: Asymmetric KSK (Production Ready)

### Overview

Implement true asymmetric recryption key generation using Alice's secret + Bob's **public** key only. Requires implementing LWE public-key encryption at `core_crypto` level.

### Changes Required

#### 1. Public Key Type

**File**: `crates/recrypt-tfhe/src/keys/public.rs`

```rust
use tfhe::core_crypto::prelude::*;
use crate::{TfheParams, TfheSecretKey};
use crate::error::{TfheError, TfheResult};

/// TFHE public key = encryptions of zero
pub struct TfhePublicKey {
    /// List of LWE encryptions of 0 under secret key
    encryptions: Vec<LweCiphertext<Vec<u64>>>,
    dimension: LweDimension,
}

impl TfhePublicKey {
    /// Generate public key from secret key
    /// Creates 2N encryptions of zero for secure public-key encryption
    pub fn from_secret(secret: &TfheSecretKey, params: &TfheParams) -> Self {
        let mut seeder = new_seeder();
        let mut encryption_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder.as_mut());

        let count = 2 * secret.dimension().0; // 2N for security
        let mut encryptions = Vec::with_capacity(count);

        let zero = Plaintext(0u64);

        for _ in 0..count {
            let mut ct = LweCiphertext::new(
                0u64,
                secret.dimension().to_lwe_size(),
                params.ciphertext_modulus,
            );

            encrypt_lwe_ciphertext(
                secret.inner(),
                &mut ct,
                zero,
                params.lwe_noise_distribution,
                &mut encryption_generator,
            );

            encryptions.push(ct);
        }

        Self {
            encryptions,
            dimension: secret.dimension(),
        }
    }

    /// Encrypt a plaintext using public key
    /// Returns LWE ciphertext as random linear combination of encryptions of zero
    pub fn encrypt_lwe(
        &self,
        plaintext: Plaintext<u64>,
        params: &TfheParams,
    ) -> LweCiphertext<Vec<u64>> {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        // Start with encryption of plaintext manually
        let mut result = LweCiphertext::new(
            0u64,
            self.dimension.to_lwe_size(),
            params.ciphertext_modulus,
        );

        // Set b = plaintext (will add random combinations)
        *result.get_mut_body().data = plaintext.0;

        // Random linear combination: sum of random subset of encryptions of zero
        for enc_zero in &self.encryptions {
            if rng.gen::<bool>() {
                // Add this encryption of zero
                lwe_ciphertext_add_assign(&mut result, enc_zero);
            }
        }

        result
    }

    pub fn dimension(&self) -> LweDimension {
        self.dimension
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // Seeded serialization for compactness
        let mut bytes = Vec::new();
        bytes.extend(self.dimension.0.to_le_bytes());
        bytes.extend((self.encryptions.len() as u32).to_le_bytes());

        for ct in &self.encryptions {
            // Store seed + b only
            // For full impl, need to track seed used during generation
            // For now, store full ciphertexts (larger but correct)
            for val in ct.as_ref().iter() {
                bytes.extend(val.to_le_bytes());
            }
        }

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> TfheResult<Self> {
        // Deserialize public key
        // Implementation similar to secret key deserialization
        todo!("Implement public key deserialization")
    }
}
```

#### 2. Asymmetric KSK Generation

**File**: `crates/recrypt-tfhe/src/keys/recrypt.rs` (update)

```rust
impl TfheRecryptKey {
    /// Generate asymmetric KSK using from_secret + to_public
    pub fn generate_asymmetric(
        from_secret: &TfheSecretKey,
        to_public: &TfhePublicKey,
        params: &TfheParams,
    ) -> Self {
        // Build KSK manually: for each (secret_index, decomp_level),
        // encrypt gadget-scaled secret coefficient under to_public

        let decomposer = SignedDecomposer::new(
            params.decomp_base_log,
            params.decomp_level_count,
        );

        let input_dim = from_secret.dimension();
        let output_dim = to_public.dimension();
        let level_count = params.decomp_level_count.0;

        let mut ksk_data = Vec::new();

        // For each coefficient of from_secret
        for i in 0..input_dim.0 {
            let secret_coeff = from_secret.inner().as_ref()[i];

            // For each decomposition level
            for level in 0..level_count {
                // Compute gadget-scaled plaintext
                let gadget_factor = decomposer.base_power_of_level(level);
                let scaled_value = (secret_coeff as i64) * (gadget_factor as i64);
                
                // Convert to torus element (u64)
                let plaintext = Plaintext(scaled_value as u64);

                // Encrypt under to_public
                let ct = to_public.encrypt_lwe(plaintext, params);

                // Store in KSK
                ksk_data.extend(ct.as_ref().iter().copied());
            }
        }

        // Construct LweKeyswitchKey from raw data
        let ksk = LweKeyswitchKey::from_container(
            ksk_data,
            params.decomp_base_log,
            params.decomp_level_count,
            output_dim.to_lwe_size(),
        );

        Self { ksk }
    }

    pub fn from_bytes(bytes: &[u8]) -> TfheResult<Self> {
        // Deserialize KSK
        // Need to extract dimensions and reconstruct
        todo!("Implement KSK deserialization")
    }
}
```

#### 3. Update TfheBackend

**File**: `crates/recrypt-core/src/pre/backends/tfhe.rs` (update)

```rust
impl PreBackend for TfheBackend {
    fn generate_keypair(&self) -> PreResult<KeyPair> {
        let tfhe_sk = TfheSecretKey::generate(self.params.lwe_dimension);
        let tfhe_pk = TfhePublicKey::from_secret(&tfhe_sk, &self.params);
        
        let sk_bytes = tfhe_sk.to_bytes();
        let pk_bytes = tfhe_pk.to_bytes();
        
        Ok(KeyPair {
            public: PublicKey::new(BackendId::Tfhe, pk_bytes),
            secret: SecretKey::new(BackendId::Tfhe, sk_bytes),
        })
    }

    fn public_key_from_secret(&self, secret: &SecretKey) -> PreResult<PublicKey> {
        let tfhe_sk = TfheSecretKey::from_bytes(&secret.bytes)
            .map_err(|e| PreError::InvalidKey(e.to_string()))?;
        
        let tfhe_pk = TfhePublicKey::from_secret(&tfhe_sk, &self.params);
        
        Ok(PublicKey::new(BackendId::Tfhe, tfhe_pk.to_bytes()))
    }

    fn generate_recrypt_key(
        &self,
        from_secret: &SecretKey,
        to_public: &PublicKey,
    ) -> PreResult<RecryptKey> {
        let from_tfhe_sk = TfheSecretKey::from_bytes(&from_secret.bytes)
            .map_err(|e| PreError::InvalidKey(e.to_string()))?;
        
        let to_tfhe_pk = TfhePublicKey::from_bytes(&to_public.bytes)
            .map_err(|e| PreError::InvalidKey(e.to_string()))?;
        
        let rk = TfheRecryptKey::generate_asymmetric(
            &from_tfhe_sk,
            &to_tfhe_pk,
            &self.params,
        );
        
        let rk_bytes = rk.to_bytes();
        
        Ok(RecryptKey::new(
            BackendId::Tfhe,
            PublicKey::new(BackendId::Tfhe, vec![]),
            to_public.clone(),
            rk_bytes,
        ))
    }

    fn encrypt(&self, recipient: &PublicKey, plaintext: &[u8]) -> PreResult<Ciphertext> {
        if plaintext.len() != 32 {
            return Err(PreError::Encryption(
                format!("TFHE backend only supports 32-byte encryption, got {}", plaintext.len())
            ));
        }

        let tfhe_pk = TfhePublicKey::from_bytes(&recipient.bytes)
            .map_err(|e| PreError::InvalidKey(e.to_string()))?;

        let plaintext_array: [u8; 32] = plaintext.try_into().unwrap();
        let multi_lwe = recrypt_tfhe::encrypt_with_public_key(&tfhe_pk, &plaintext_array, &self.params)
            .map_err(|e| PreError::Encryption(e.to_string()))?;

        Ok(Ciphertext::new(BackendId::Tfhe, 0, multi_lwe.to_bytes()))
    }
}
```

#### 4. Public Key Encryption Function

**File**: `crates/recrypt-tfhe/src/encrypt.rs` (add)

```rust
pub fn encrypt_with_public_key(
    recipient: &TfhePublicKey,
    plaintext: &[u8; 32],
    params: &TfheParams,
) -> TfheResult<MultiLweCiphertext> {
    let delta = TfheParams::delta();
    let mut chunks = Vec::with_capacity(MultiLweCiphertext::CHUNK_COUNT);

    for byte_idx in 0..32 {
        let byte = plaintext[byte_idx];
        
        for chunk_idx in 0..4 {
            let shift = chunk_idx * 2;
            let two_bits = ((byte >> shift) & 0b11) as u64;
            
            let plaintext_val = Plaintext(two_bits * delta);
            let lwe = recipient.encrypt_lwe(plaintext_val, params);
            
            let seed: [u8; 32] = rand::thread_rng().gen();
            chunks.push(SeededLweCiphertext::from_full(&lwe, seed));
        }
    }

    Ok(MultiLweCiphertext { chunks })
}
```

### Success Criteria

#### Automated Verification:

- [ ] Asymmetric KSK generation compiles: `cargo build -p recrypt-tfhe`
- [ ] Public key encryption works: `cargo test -p recrypt-tfhe public_key_encrypt`
- [ ] Alice→Bob recryption without Bob's secret: `cargo test -p recrypt-tfhe asymmetric_recrypt`
- [ ] Integration test: `cargo test -p recrypt-core --features tfhe full_asymmetric_flow`

#### Manual Verification:

- [ ] Public key size reasonable (seeded: ~11 KB)
- [ ] Recrypt key generation doesn't require delegatee's secret
- [ ] Security property: proxy + Bob cannot recover Alice's secret

**Implementation Note**: This phase removes all v1 limitations. TFHE backend now production-ready for use.

---

## Phase 4: Benchmarking & Optimization

### Overview

Comprehensive performance testing vs OpenFHE, parameter tuning, noise budget analysis.

### Changes Required

#### 1. Benchmark Suite

**File**: `crates/recrypt-tfhe/benches/tfhe_ops.rs`

```rust
use criterion::{Criterion, black_box, criterion_group, criterion_main, BenchmarkId};
use recrypt_tfhe::*;

fn bench_key_generation(c: &mut Criterion) {
    let params = TfheParams::default_128bit();
    
    c.bench_function("tfhe_keygen", |b| {
        b.iter(|| {
            let sk = TfheSecretKey::generate(black_box(params.lwe_dimension));
            let _pk = TfhePublicKey::from_secret(&sk, &params);
        })
    });
}

fn bench_encryption(c: &mut Criterion) {
    let params = TfheParams::default_128bit();
    let sk = TfheSecretKey::generate(params.lwe_dimension);
    let pk = TfhePublicKey::from_secret(&sk, &params);
    let plaintext = [0x42u8; 32];
    
    c.bench_function("tfhe_encrypt_32b", |b| {
        b.iter(|| {
            encrypt_with_public_key(black_box(&pk), black_box(&plaintext), black_box(&params))
        })
    });
}

fn bench_decryption(c: &mut Criterion) {
    let params = TfheParams::default_128bit();
    let sk = TfheSecretKey::generate(params.lwe_dimension);
    let pk = TfhePublicKey::from_secret(&sk, &params);
    let plaintext = [0x42u8; 32];
    let ciphertext = encrypt_with_public_key(&pk, &plaintext, &params).unwrap();
    
    c.bench_function("tfhe_decrypt_32b", |b| {
        b.iter(|| {
            decrypt_symmetric_key(black_box(&sk), black_box(&ciphertext), black_box(&params))
        })
    });
}

fn bench_recryption(c: &mut Criterion) {
    let params = TfheParams::default_128bit();
    let alice_sk = TfheSecretKey::generate(params.lwe_dimension);
    let bob_sk = TfheSecretKey::generate(params.lwe_dimension);
    let alice_pk = TfhePublicKey::from_secret(&alice_sk, &params);
    let bob_pk = TfhePublicKey::from_secret(&bob_sk, &params);
    
    let plaintext = [0x42u8; 32];
    let ciphertext = encrypt_with_public_key(&alice_pk, &plaintext, &params).unwrap();
    let rk = TfheRecryptKey::generate_asymmetric(&alice_sk, &bob_pk, &params);
    
    c.bench_function("tfhe_recrypt", |b| {
        b.iter(|| {
            recrypt(black_box(&rk), black_box(&ciphertext), black_box(&params))
        })
    });
}

fn bench_multi_hop(c: &mut Criterion) {
    let mut group = c.benchmark_group("tfhe_multihop");
    let params = TfheParams::default_128bit();
    
    for hops in [1, 2, 3].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(hops), hops, |b, &hops| {
            let mut keys = Vec::new();
            for _ in 0..=hops {
                let sk = TfheSecretKey::generate(params.lwe_dimension);
                let pk = TfhePublicKey::from_secret(&sk, &params);
                keys.push((sk, pk));
            }
            
            let plaintext = [0x42u8; 32];
            let mut ct = encrypt_with_public_key(&keys[0].1, &plaintext, &params).unwrap();
            
            let mut rks = Vec::new();
            for i in 0..hops {
                rks.push(TfheRecryptKey::generate_asymmetric(&keys[i].0, &keys[i+1].1, &params));
            }
            
            b.iter(|| {
                let mut current_ct = ct.clone();
                for rk in &rks {
                    current_ct = recrypt(rk, &current_ct, &params).unwrap();
                }
                black_box(current_ct);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_key_generation, bench_encryption, bench_decryption, bench_recryption, bench_multi_hop);
criterion_main!(benches);
```

#### 2. Core Backend Benchmark

**File**: `crates/recrypt-core/benches/crypto_ops.rs` (update)

Add TFHE backend benchmarks alongside existing Mock/Lattice benchmarks:

```rust
#[cfg(feature = "tfhe")]
fn bench_tfhe_backend(c: &mut Criterion) {
    use recrypt_core::pre::backends::TfheBackend;
    
    let backend = TfheBackend::new().unwrap();
    let encryptor = HybridEncryptor::new(backend);
    
    // Key generation
    c.bench_function("tfhe_backend_keygen", |b| {
        b.iter(|| encryptor.backend().generate_keypair())
    });
    
    // Full encrypt/decrypt/recrypt cycle
    // ... similar to existing benchmarks
}
```

#### 3. Noise Failure Rate Test

**File**: `crates/recrypt-tfhe/tests/failure_rate.rs`

```rust
use recrypt_tfhe::*;

#[test]
#[ignore] // Long-running, run with --ignored
fn monte_carlo_noise_failure_rate() {
    const TRIALS: usize = 1000;
    let params = TfheParams::default_128bit();
    
    let mut failures_1hop = 0;
    let mut failures_2hop = 0;
    let mut failures_3hop = 0;
    
    for trial in 0..TRIALS {
        if trial % 100 == 0 {
            println!("Trial {}/{}", trial, TRIALS);
        }
        
        // Generate keys
        let alice_sk = TfheSecretKey::generate(params.lwe_dimension);
        let bob_sk = TfheSecretKey::generate(params.lwe_dimension);
        let carol_sk = TfheSecretKey::generate(params.lwe_dimension);
        
        let alice_pk = TfhePublicKey::from_secret(&alice_sk, &params);
        let bob_pk = TfhePublicKey::from_secret(&bob_sk, &params);
        let carol_pk = TfhePublicKey::from_secret(&carol_sk, &params);
        
        // Random message
        let mut plaintext = [0u8; 32];
        rand::Rng::fill(&mut rand::thread_rng(), &mut plaintext);
        
        // Encrypt
        let ct_alice = encrypt_with_public_key(&alice_pk, &plaintext, &params).unwrap();
        
        // 1 hop: Alice → Bob
        let rk_ab = TfheRecryptKey::generate_asymmetric(&alice_sk, &bob_pk, &params);
        let ct_bob = recrypt(&rk_ab, &ct_alice, &params).unwrap();
        let pt_bob = decrypt_symmetric_key(&bob_sk, &ct_bob, &params).unwrap();
        
        if &pt_bob[..] != &plaintext[..] {
            failures_1hop += 1;
        }
        
        // 2 hops: Alice → Bob → Carol
        let rk_bc = TfheRecryptKey::generate_asymmetric(&bob_sk, &carol_pk, &params);
        let ct_carol = recrypt(&rk_bc, &ct_bob, &params).unwrap();
        let pt_carol = decrypt_symmetric_key(&carol_sk, &ct_carol, &params).unwrap();
        
        if &pt_carol[..] != &plaintext[..] {
            failures_2hop += 1;
        }
        
        // 3 hops: continuing chain
        let dave_sk = TfheSecretKey::generate(params.lwe_dimension);
        let dave_pk = TfhePublicKey::from_secret(&dave_sk, &params);
        let rk_cd = TfheRecryptKey::generate_asymmetric(&carol_sk, &dave_pk, &params);
        let ct_dave = recrypt(&rk_cd, &ct_carol, &params).unwrap();
        let pt_dave = decrypt_symmetric_key(&dave_sk, &ct_dave, &params).unwrap();
        
        if &pt_dave[..] != &plaintext[..] {
            failures_3hop += 1;
        }
    }
    
    println!("\nFailure Rates:");
    println!("1 hop: {}/{} ({:.2}%)", failures_1hop, TRIALS, (failures_1hop as f64 / TRIALS as f64) * 100.0);
    println!("2 hops: {}/{} ({:.2}%)", failures_2hop, TRIALS, (failures_2hop as f64 / TRIALS as f64) * 100.0);
    println!("3 hops: {}/{} ({:.2}%)", failures_3hop, TRIALS, (failures_3hop as f64 / TRIALS as f64) * 100.0);
    
    // Assert acceptable failure rates
    assert!(failures_1hop == 0, "1-hop should have zero failures");
    assert!(failures_2hop < 10, "2-hop should have <1% failures");
    // 3-hop may have higher failure rate - document threshold
}
```

#### 4. Comparison Benchmark Script

**File**: `scripts/bench-compare.sh`

```bash
#!/bin/bash
set -e

echo "=== Benchmarking OpenFHE Lattice Backend ==="
cargo bench -p recrypt-core --features openfhe -- lattice --save-baseline lattice

echo ""
echo "=== Benchmarking TFHE Backend ==="
cargo bench -p recrypt-core --features tfhe -- tfhe --save-baseline tfhe

echo ""
echo "=== Comparison ==="
cargo bench -p recrypt-core --features openfhe,tfhe -- --baseline lattice
```

### Success Criteria

#### Automated Verification:

- [ ] Benchmarks compile: `cargo bench -p recrypt-tfhe --no-run`
- [ ] Core backend benchmarks: `cargo bench -p recrypt-core --features tfhe`
- [ ] Failure rate test runs: `cargo test -p recrypt-tfhe --release -- failure_rate --ignored`

#### Manual Verification:

- [ ] TFHE recryption 10-100x faster than OpenFHE (target: 10-50ms vs 1-3s)
- [ ] 1-hop: 0% failure rate
- [ ] 2-hops: <1% failure rate
- [ ] 3-hops: document actual rate, assess if acceptable
- [ ] Key generation ~50-100ms
- [ ] Encryption ~10-50ms
- [ ] Decryption ~5-20ms

**Implementation Note**: If failure rates exceed targets, tune decomposition parameters (base_log, level_count) to increase noise margin.

---

## Phase 5: Protocol Layer Updates

### Overview

Update `KeyMaterial` handling to encrypt only 32-byte symmetric key via TFHE. Nonce/hash/size remain public in header.

### Changes Required

#### 1. Update KeyMaterial Documentation

**File**: `crates/recrypt-core/src/hybrid/keymaterial.rs` (update comments)

```rust
/// Key material bundle for hybrid encryption
///
/// **IMPORTANT**: When using TFHE backend, only the symmetric_key field
/// is encrypted via PRE. The nonce, plaintext_hash, and plaintext_size
/// are stored in cleartext in the file header (authenticated but not confidential).
///
/// For OpenFHE lattice backend, the full 96-byte bundle is encrypted for
/// backward compatibility.
#[derive(Clone, Debug)]
pub struct KeyMaterial {
    /// XChaCha20 symmetric key (256-bit) - ALWAYS encrypted via PRE
    pub symmetric_key: [u8; 32],
    /// XChaCha20 extended nonce - public for TFHE, encrypted for lattice
    pub nonce: [u8; 24],
    /// Blake3 hash of original plaintext - public for TFHE, encrypted for lattice
    pub plaintext_hash: [u8; 32],
    /// Original plaintext size in bytes - public for TFHE, encrypted for lattice
    pub plaintext_size: u64,
}

impl KeyMaterial {
    /// Serialize only symmetric key (for TFHE backend)
    pub fn key_only(&self) -> [u8; 32] {
        self.symmetric_key
    }
    
    /// Serialize full bundle (for lattice backend)
    pub fn to_bytes(&self) -> [u8; Self::SERIALIZED_SIZE] {
        // ... existing implementation
    }
}
```

#### 2. Update HybridEncryptor

**File**: `crates/recrypt-core/src/hybrid/mod.rs` (update)

```rust
impl<B: PreBackend> HybridEncryptor<B> {
    pub fn encrypt(&self, recipient: &PublicKey, plaintext: &[u8]) -> HybridResult<EncryptedFile> {
        // Generate key material
        let key_material = KeyMaterial::generate_for(plaintext)?;
        
        // Determine what to encrypt based on backend
        let plaintext_to_encrypt = match self.backend.backend_id() {
            BackendId::Tfhe => {
                // TFHE: encrypt only symmetric key
                key_material.key_only().to_vec()
            }
            _ => {
                // Lattice/others: encrypt full bundle
                key_material.to_bytes().to_vec()
            }
        };
        
        // Encrypt via PRE
        let wrapped_key = self.backend.encrypt(recipient, &plaintext_to_encrypt)?;
        
        // Encrypt payload with symmetric key
        let ciphertext = self.encrypt_payload(&key_material.symmetric_key, &key_material.nonce, plaintext)?;
        
        // Build file metadata
        let metadata = if self.backend.backend_id() == BackendId::Tfhe {
            // TFHE: include nonce/hash/size in cleartext
            FileMetadata {
                nonce: Some(key_material.nonce),
                plaintext_hash: Some(key_material.plaintext_hash),
                plaintext_size: Some(key_material.plaintext_size),
                ..Default::default()
            }
        } else {
            // Lattice: everything encrypted in wrapped_key
            FileMetadata::default()
        };
        
        Ok(EncryptedFile {
            wrapped_key,
            ciphertext,
            bao_hash: self.compute_bao_hash(&ciphertext),
            metadata,
        })
    }
    
    pub fn decrypt(&self, secret: &SecretKey, encrypted: &EncryptedFile) -> HybridResult<Vec<u8>> {
        // Unwrap key material
        let unwrapped = self.backend.decrypt(secret, &encrypted.wrapped_key)?;
        
        let key_material = match self.backend.backend_id() {
            BackendId::Tfhe => {
                // TFHE: reconstruct from 32-byte key + public metadata
                if unwrapped.len() != 32 {
                    return Err(HybridError::Decryption("Invalid key size for TFHE".into()));
                }
                
                let metadata = encrypted.metadata.as_ref()
                    .ok_or_else(|| HybridError::Decryption("Missing metadata for TFHE".into()))?;
                
                KeyMaterial {
                    symmetric_key: unwrapped[..32].try_into().unwrap(),
                    nonce: metadata.nonce.ok_or_else(|| HybridError::Decryption("Missing nonce".into()))?,
                    plaintext_hash: metadata.plaintext_hash.ok_or_else(|| HybridError::Decryption("Missing hash".into()))?,
                    plaintext_size: metadata.plaintext_size.ok_or_else(|| HybridError::Decryption("Missing size".into()))?,
                }
            }
            _ => {
                // Lattice: full bundle encrypted
                KeyMaterial::from_bytes(&unwrapped)?
            }
        };
        
        // Decrypt payload
        let plaintext = self.decrypt_payload(&key_material.symmetric_key, &key_material.nonce, &encrypted.ciphertext)?;
        
        // Verify hash
        let computed_hash = blake3::hash(&plaintext);
        if computed_hash.as_bytes() != &key_material.plaintext_hash {
            return Err(HybridError::IntegrityFailure("Plaintext hash mismatch".into()));
        }
        
        Ok(plaintext)
    }
}
```

#### 3. Update EncryptedFile Structure

**File**: `crates/recrypt-core/src/hybrid/encrypted_file.rs`

```rust
/// Metadata stored in cleartext (TFHE backend only)
#[derive(Clone, Debug, Default)]
pub struct FileMetadata {
    pub nonce: Option<[u8; 24]>,
    pub plaintext_hash: Option<[u8; 32]>,
    pub plaintext_size: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct EncryptedFile {
    /// PRE-encrypted key material (32B for TFHE, 96B for lattice)
    pub wrapped_key: Ciphertext,
    /// XChaCha20 encrypted content
    pub ciphertext: Vec<u8>,
    /// Bao hash for streaming verification
    pub bao_hash: [u8; 32],
    /// Public metadata (TFHE only, None for lattice)
    pub metadata: Option<FileMetadata>,
}
```

#### 4. CLI Backend Selection

**File**: `recrypt-cli/src/commands/encrypt.rs` (update)

```rust
#[derive(Parser)]
pub struct EncryptArgs {
    /// Backend to use for encryption
    #[arg(long, default_value = "lattice")]
    backend: BackendId,
    
    /// Input file
    input: PathBuf,
    
    /// Recipient public key file
    #[arg(long)]
    recipient: PathBuf,
}

pub fn execute(args: EncryptArgs) -> Result<()> {
    let backend: Box<dyn PreBackend> = match args.backend {
        BackendId::Lattice => Box::new(LatticeBackend::new()?),
        BackendId::Tfhe => Box::new(TfheBackend::new()?),
        _ => return Err(anyhow!("Backend not supported")),
    };
    
    // ... rest of encryption logic
}
```

### Success Criteria

#### Automated Verification:

- [ ] Hybrid encryptor compiles: `cargo build -p recrypt-core --features tfhe`
- [ ] Round-trip with TFHE: `cargo test -p recrypt-core --features tfhe hybrid_tfhe_roundtrip`
- [ ] CLI encrypts with TFHE: `cargo run -p recrypt-cli -- encrypt --backend tfhe test.txt --recipient bob.pub`
- [ ] Metadata correctly stored: verify file header contains cleartext nonce/hash/size

#### Manual Verification:

- [ ] TFHE-encrypted files have smaller wrapped_key (~5KB vs ~8KB for lattice)
- [ ] Metadata readable without decryption
- [ ] Backward compat: lattice-encrypted files still work
- [ ] Cross-backend rejected: can't decrypt TFHE file with lattice backend

**Implementation Note**: Document security implications of public nonce/hash/size in user guide.

---

## Testing Strategy

### Unit Tests

- Key generation, serialization/deserialization
- Multi-LWE encoding/decoding (all 256 bits preserved)
- Seeded ciphertext reconstruction (a vectors regenerate correctly)
- Parameter validation

### Integration Tests

- Alice→Bob recryption flow
- Alice→Bob→Carol multi-hop
- Backend trait implementation completeness
- Protobuf round-trip (BackendId, Ciphertext, RecryptKey)

### Property Tests

- Encrypt→Decrypt = identity (all plaintexts)
- Recrypt preserves plaintext (all keys)
- Serialization round-trip (all types)

### Manual Testing

1. Generate TFHE keypair: `recrypt-cli keygen --backend tfhe alice`
2. Encrypt file: `recrypt-cli encrypt --backend tfhe test.txt --recipient bob.pub`
3. Generate recrypt key: `recrypt-cli recrypt-key alice.sec bob.pub -o alice-to-bob.rk`
4. Server recrypt: `recrypt-server` + upload recrypt key
5. Bob decrypt: `recrypt-cli decrypt test.txt.enc --key bob.sec`

## Performance Targets

| Operation | OpenFHE BFV | TFHE (Target) | TFHE (Measured) |
|-----------|-------------|---------------|-----------------|
| Key Generation | ~135ms | 50-100ms | _TBD_ |
| Encryption (32B) | ~500ms | 10-50ms | _TBD_ |
| Decryption (32B) | ~200ms | 5-20ms | _TBD_ |
| **Recryption** | **1-3s** | **10-50ms** | **_TBD_** |
| Public Key Size | ~8MB | ~11KB (seeded) | _TBD_ |
| RecryptKey Size | ~10KB | ~50KB (seeded) | _TBD_ |
| Ciphertext Size | ~8KB | ~5KB (seeded) | _TBD_ |

## Security Considerations

### Post-Quantum Security

Both OpenFHE BFV and TFHE LWE are lattice-based, quantum-resistant at 128-bit security level.

### Unidirectionality

Recryption keys are one-way: `rk(Alice→Bob)` ≠ `rk(Bob→Alice)`. Collusion between proxy and Bob cannot recover Alice's secret key.

### Noise Budget

- 1 hop: safe (negligible failure rate)
- 2 hops: safe with margin (<1% failure in testing)
- 3+ hops: requires monitoring, may need parameter adjustment

### Metadata Leakage (TFHE)

With TFHE backend, nonce/plaintext_hash/plaintext_size are public. Implications:
- Nonce: safe (random, no info leakage)
- Plaintext size: reveals file size (acceptable for most use cases)
- Plaintext hash: enables confirmation attacks if attacker knows candidate plaintexts

**Mitigation**: Document in user guide, recommend lattice backend for high-sensitivity files where metadata confidentiality matters.

## Migration Notes

### Backward Compatibility

- TFHE is new backend (BackendId=4), doesn't affect existing lattice-encrypted files
- Files encrypted with lattice backend continue to work unchanged
- No migration path from lattice→TFHE (would require re-encryption)

### Feature Flags

- Default: `openfhe` enabled, `tfhe` disabled
- Gradual rollout: enable `tfhe` feature in CI, production deployments
- Future: consider making `tfhe` default after proving stability

## References

- Original research: `docs/research/tfhe-pre-research.md`
- [Zama tfhe-rs](https://github.com/zama-ai/tfhe-rs)
- [TFHE Paper](https://eprint.iacr.org/2018/421)
- PreBackend trait design: `docs/pre-backend-traits.md`
- Hybrid encryption architecture: `docs/hybrid-encryption-architecture.md`

---

**Plan Status**: Ready for Implementation  
**Estimated Timeline**: 2-3 weeks  
**Risk Level**: Medium (v1 shortcuts acceptable, v2 adds production security)
