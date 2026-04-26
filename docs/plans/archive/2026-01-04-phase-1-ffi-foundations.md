# Phase 1: FFI Foundations Implementation Plan

> **Status: ✅ COMPLETE** (2026-01-05)
>
> All phases implemented and verified. 16 tests passing. Notable deviation: used `oqs` crate v0.11 instead of vendored liboqs.

> **Historical Note:** This plan originally referenced `vendor/openfhe-rs/` which has since been
> **deleted**. We created minimal custom bindings in `crates/recrypt-openfhe-sys/` instead.
> See `crates/recrypt-ffi/src/lib.rs` for the current architecture.

## Overview

Build the Rust FFI layer that wraps OpenFHE (lattice PRE) and liboqs (PQ signatures), plus ED25519 classical signatures. This is the critical path foundation—everything else depends on it.

## Current State Analysis

### What Exists

1. **OpenFHE Rust bindings** (`vendor/openfhe-rs/`)

   - Complete cxx-based FFI to OpenFHE
   - Already has `ReKeyGen` and `ReEncrypt` for PRE
   - Uses BFV/BGV/CKKS schemes
   - Well-structured C++ wrapper layer

2. **OpenFHE C++ library** (built in `vendor/openfhe-development/build/lib/`)

   - `libOPENFHEpke.dylib`, `libOPENFHEcore.dylib`, `libOPENFHEbinfhe.dylib`
   - Version 1.3.0

3. **liboqs C library** (built in `vendor/liboqs/build/`)

   - Shared library already compiled
   - Python prototype uses it via `oqs` Python package

4. **Python prototype PRE code** (`python-prototype/src/dcypher/lib/pre.py`)
   - Shows the API surface we need:
     - `create_crypto_context()` → BFVrns with PRE enabled
     - `generate_keys()` → KeyPair
     - `encrypt()` / `decrypt()` → chunked data
     - `generate_re_encryption_key()` → ReKeyGen
     - `re_encrypt()` → ReEncrypt (the recryption transform)

### Key Discoveries

- openfhe-rs line 663-668: `ReEncrypt` and `ReKeyGen` already bound
- openfhe-rs line 95-101: `ProxyReEncryptionMode` enum available (INDCPA, FIXED_NOISE_HRA, NOISE_FLOODING_HRA)
- openfhe-rs line 79-82: `PKESchemeFeature::PRE` available as feature flag
- Python pre.py line 72-73: PRE enabled via `cc.Enable(fhe.PRE)`

## Desired End State

A `recrypt-ffi` crate that provides:

```rust
// OpenFHE PRE operations
pub fn create_pre_context() -> PreContext;
pub fn generate_keypair(ctx: &PreContext) -> KeyPair;
pub fn encrypt(ctx: &PreContext, pk: &PublicKey, data: &[u8]) -> Ciphertext;
pub fn decrypt(ctx: &PreContext, sk: &SecretKey, ct: &Ciphertext) -> Vec<u8>;
pub fn generate_recrypt_key(ctx: &PreContext, from_sk: &SecretKey, to_pk: &PublicKey) -> RecryptKey;
pub fn recrypt(ctx: &PreContext, rk: &RecryptKey, ct: &Ciphertext) -> Ciphertext;

// liboqs PQ signatures (ML-DSA-87)
pub fn pq_keygen(alg: PqAlgorithm) -> PqKeyPair;
pub fn pq_sign(sk: &PqSecretKey, msg: &[u8]) -> PqSignature;
pub fn pq_verify(pk: &PqPublicKey, msg: &[u8], sig: &PqSignature) -> bool;

// ED25519 classical signatures
pub fn ed25519_keygen() -> Ed25519KeyPair;
pub fn ed25519_sign(sk: &Ed25519SecretKey, msg: &[u8]) -> Ed25519Signature;
pub fn ed25519_verify(pk: &Ed25519PublicKey, msg: &[u8], sig: &Ed25519Signature) -> bool;
```

### Verification

```bash
cargo test -p recrypt-ffi
# All smoke tests pass:
# - PRE encrypt/decrypt roundtrip
# - PRE recryption flow (Alice→Bob)
# - PQ sign/verify
# - ED25519 sign/verify
```

## What We're NOT Doing

- ❌ High-level `PreBackend` trait abstraction (that's Phase 2)
- ❌ Serialization/wire protocol (that's Phase 3)
- ❌ Hybrid KEM-DEM pattern (that's Phase 2)
- ❌ Any storage or server code
- ❌ HDprint (parallel track, separate crate)

## Implementation Approach

**Strategy:** Fork/adapt openfhe-rs, add liboqs bindings, wrap everything in a clean Rust API.

**Key Decision:** Use `openfhe-rs` as-is (it's already well-structured) rather than rewriting. We may need minor patches for serialization to bytes (currently file-based).

---

## Phase 1a: Workspace Scaffolding

### Overview

Create the Rust workspace structure and get a minimal build working.

### Changes Required

#### 1. Create Workspace Root

**File**: `Cargo.toml` (workspace root)

```toml
[workspace]
resolver = "2"
members = [
    "crates/recrypt-ffi",
    "crates/dcypher-hdprint",  # parallel track
]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "MIT OR Apache-2.0"
repository = "https://github.com/identikey/dcypher"

[workspace.dependencies]
# Crypto
cxx = "1.0"
ed25519-dalek = { version = "2.1", features = ["rand_core"] }
rand = "0.8"
rand_core = "0.6"

# Error handling
thiserror = "2"
anyhow = "1"

# Testing
proptest = "1"

[profile.release]
lto = true
codegen-units = 1
```

#### 2. Create recrypt-ffi Crate Structure

```
crates/recrypt-ffi/
├── Cargo.toml
├── build.rs
└── src/
    ├── lib.rs
    ├── openfhe/
    │   ├── mod.rs
    │   ├── bridge.rs      # cxx bridge definitions
    │   ├── context.rs     # CryptoContext wrapper
    │   ├── keys.rs        # Key types
    │   └── pre.rs         # PRE operations
    ├── liboqs/
    │   ├── mod.rs
    │   ├── sig.rs         # Signature operations
    │   └── bindings.rs    # Raw FFI bindings
    ├── ed25519.rs         # ed25519-dalek wrapper
    └── error.rs           # Error types
```

#### 3. Create Initial Cargo.toml

**File**: `crates/recrypt-ffi/Cargo.toml`

```toml
[package]
name = "recrypt-ffi"
version.workspace = true
edition.workspace = true

[dependencies]
cxx.workspace = true
ed25519-dalek.workspace = true
rand.workspace = true
rand_core.workspace = true
thiserror.workspace = true

[build-dependencies]
cxx-build = "1.0"
pkg-config = "0.3"

[dev-dependencies]
proptest.workspace = true

[features]
default = ["openfhe", "liboqs"]
openfhe = []
liboqs = []
```

### Success Criteria

#### Automated Verification

- [x] `cargo build -p recrypt-ffi` compiles (even with stub implementations)
- [x] Workspace structure matches spec: `ls crates/recrypt-ffi/src/`
- [x] `cargo clippy -p recrypt-ffi` passes

#### Manual Verification

- [x] Directory structure looks correct

**Implementation Note**: This phase is quick scaffolding. Proceed immediately to Phase 1b.

---

## Phase 1b: OpenFHE FFI Integration

### Overview

Create minimal OpenFHE bindings (`recrypt-openfhe-sys`) tailored for PRE operations.

### Decision: Minimal Custom Bindings

After analysis (see `docs/plans/openfhe-minimal-bindings-analysis.md`):

- The vendored `openfhe-rs` is ~1 year stale (adapted for OpenFHE v1.2.1)
- Our vendored OpenFHE is v1.3.0 (API changes in serialization, enums)
- We only need ~15% of the openfhe-rs API surface
- openfhe-rs is a git submodule—editing it directly is problematic

**Decision: Create `recrypt-openfhe-sys` with minimal bindings**

Benefits:

- ~80% less code to maintain
- Tailored for PRE use case
- Byte-based serialization (not file-based)
- Compatible with OpenFHE 1.3.0
- Option for static linking
- Better Rust ergonomics

### Required API (from Python prototype analysis)

```rust
// Context
fn create_bfv_context(params: &PreParams) -> Result<CryptoContext>;
fn get_ring_dimension(ctx: &CryptoContext) -> u32;

// Keys
fn keygen(ctx: &CryptoContext) -> Result<KeyPair>;

// Encryption
fn make_plaintext(ctx: &CryptoContext, coeffs: &[i64]) -> Plaintext;
fn encrypt(ctx: &CryptoContext, pk: &PublicKey, pt: &Plaintext) -> Ciphertext;
fn decrypt(ctx: &CryptoContext, sk: &SecretKey, ct: &Ciphertext) -> Plaintext;
fn get_packed_value(pt: &Plaintext) -> Vec<i64>;

// PRE (recryption)
fn generate_recrypt_key(ctx: &CryptoContext, from_sk: &SecretKey, to_pk: &PublicKey) -> RecryptKey;
fn recrypt(ctx: &CryptoContext, rk: &RecryptKey, ct: &Ciphertext) -> Ciphertext;

// Serialization (byte-based)
fn serialize_*() -> Vec<u8>;
fn deserialize_*() -> Result<T>;
```

### Build Strategy

1. Build OpenFHE from `vendor/openfhe-development/` to local prefix
2. Use `just setup-openfhe` for reproducible builds
3. Support both dynamic and static linking
4. No dependency on system-installed OpenFHE

### Changes Required

#### 1. Copy OpenFHE Bindings

```bash
cp -r vendor/openfhe-rs crates/recrypt-ffi/openfhe-sys
# Rename to internal crate
```

#### 2. Create PRE Wrapper

**File**: `crates/recrypt-ffi/src/openfhe/pre.rs`

```rust
//! Proxy recryption operations via OpenFHE BFV scheme

use crate::error::FfiError;
use crate::openfhe::bridge::ffi;

/// PRE-enabled crypto context
pub struct PreContext {
    inner: cxx::UniquePtr<ffi::CryptoContextDCRTPoly>,
}

impl PreContext {
    /// Create a new PRE context with default parameters
    ///
    /// Uses BFVrns with:
    /// - plaintext_modulus = 65537
    /// - PRE mode = INDCPA (or HRA for stronger security)
    pub fn new() -> Result<Self, FfiError> {
        let mut params = ffi::GenParamsBFVRNS();
        params.pin_mut().SetPlaintextModulus(65537);
        params.pin_mut().SetMultiplicativeDepth(2);

        let ctx = ffi::DCRTPolyGenCryptoContextByParamsBFVRNS(&params);
        ctx.EnableByFeature(ffi::PKESchemeFeature::PKE);
        ctx.EnableByFeature(ffi::PKESchemeFeature::KEYSWITCH);
        ctx.EnableByFeature(ffi::PKESchemeFeature::PRE);

        Ok(Self { inner: ctx })
    }

    /// Generate a new keypair
    pub fn generate_keypair(&self) -> Result<KeyPair, FfiError> {
        let kp = self.inner.KeyGen();
        Ok(KeyPair {
            public: PublicKey { inner: kp.GetPublicKey() },
            secret: SecretKey { inner: kp.GetPrivateKey() },
        })
    }

    /// Encrypt data for a recipient
    pub fn encrypt(&self, pk: &PublicKey, data: &[u8]) -> Result<Ciphertext, FfiError> {
        let coeffs = bytes_to_coefficients(data);
        let plaintext = self.make_packed_plaintext(&coeffs)?;
        let ct = self.inner.EncryptByPublicKey(&pk.inner, &plaintext);
        Ok(Ciphertext { inner: ct })
    }

    /// Decrypt ciphertext
    pub fn decrypt(&self, sk: &SecretKey, ct: &Ciphertext) -> Result<Vec<u8>, FfiError> {
        let mut plaintext = ffi::GenNullPlainText();
        self.inner.DecryptByPrivateKeyAndCiphertext(
            &sk.inner, &ct.inner, plaintext.pin_mut()
        );
        let coeffs = plaintext.GetPackedValue();
        Ok(coefficients_to_bytes(&coeffs))
    }

    /// Generate a recryption key from Alice to Bob
    pub fn generate_recrypt_key(
        &self,
        from_sk: &SecretKey,
        to_pk: &PublicKey,
    ) -> Result<RecryptKey, FfiError> {
        let rk = self.inner.ReKeyGen(&from_sk.inner, &to_pk.inner);
        Ok(RecryptKey { inner: rk })
    }

    /// Transform ciphertext from Alice to Bob
    pub fn recrypt(
        &self,
        rk: &RecryptKey,
        ct: &Ciphertext,
    ) -> Result<Ciphertext, FfiError> {
        let null_pk = ffi::DCRTPolyGenNullPublicKey();
        let new_ct = self.inner.ReEncrypt(&ct.inner, &rk.inner, &null_pk);
        Ok(Ciphertext { inner: new_ct })
    }
}

// Helper: convert bytes to BFV coefficients (16-bit unsigned)
fn bytes_to_coefficients(data: &[u8]) -> Vec<i64> {
    data.chunks(2)
        .map(|chunk| {
            let val = if chunk.len() == 2 {
                u16::from_le_bytes([chunk[0], chunk[1]])
            } else {
                chunk[0] as u16
            };
            val as i64
        })
        .collect()
}

// Helper: convert coefficients back to bytes
fn coefficients_to_bytes(coeffs: &[i64]) -> Vec<u8> {
    coeffs.iter()
        .flat_map(|&c| (c as u16).to_le_bytes())
        .collect()
}
```

#### 3. Update build.rs

**File**: `crates/recrypt-ffi/build.rs`

```rust
fn main() {
    // Build OpenFHE C++ bridge
    cxx_build::bridge("src/openfhe/bridge.rs")
        // Include openfhe-sys C++ files
        .files(glob::glob("openfhe-sys/src/*.cc").unwrap().filter_map(|p| p.ok()))
        // OpenFHE includes
        .include("/usr/local/include/openfhe")
        .include("/usr/local/include/openfhe/third-party/include")
        .include("/usr/local/include/openfhe/core")
        .include("/usr/local/include/openfhe/pke")
        .include("/usr/local/include/openfhe/binfhe")
        // Compiler flags
        .flag_if_supported("-std=c++17")
        .flag_if_supported("-O3")
        .compile("openfhe_bridge");

    // Link OpenFHE libraries
    println!("cargo::rustc-link-arg=-L/usr/local/lib");
    println!("cargo::rustc-link-arg=-lOPENFHEpke");
    println!("cargo::rustc-link-arg=-lOPENFHEcore");
    println!("cargo::rustc-link-arg=-lOPENFHEbinfhe");
    println!("cargo::rustc-link-arg=-Wl,-rpath,/usr/local/lib");
}
```

### Success Criteria

#### Automated Verification

- [x] `cargo build -p recrypt-ffi --features openfhe` compiles
- [x] OpenFHE smoke test passes:

```rust
#[test]
fn test_pre_roundtrip() {
    let ctx = PreContext::new().unwrap();
    let alice = ctx.generate_keypair().unwrap();
    let bob = ctx.generate_keypair().unwrap();

    let plaintext = b"Hello, PRE!";
    let ct = ctx.encrypt(&alice.public, plaintext).unwrap();

    // Direct decryption by Alice
    let decrypted = ctx.decrypt(&alice.secret, &ct).unwrap();
    assert_eq!(&decrypted[..plaintext.len()], plaintext);

    // Recryption flow: Alice → Bob
    let rk = ctx.generate_recrypt_key(&alice.secret, &bob.public).unwrap();
    let ct_for_bob = ctx.recrypt(&rk, &ct).unwrap();
    let decrypted_by_bob = ctx.decrypt(&bob.secret, &ct_for_bob).unwrap();
    assert_eq!(&decrypted_by_bob[..plaintext.len()], plaintext);
}
```

#### Manual Verification

- [x] Confirm OpenFHE dylibs are linked correctly: `otool -L target/debug/libdcypher_ffi.dylib`

---

## Phase 1c: liboqs PQ Signatures

### Overview

Bind liboqs for ML-DSA-87 (Dilithium) post-quantum signatures.

### Approach Options

1. **Use `oqs` crate from crates.io** — if it exists and is maintained
2. **Use `liboqs-sys` + manual safe wrapper** — more control
3. **Build our own bindings** — most work, most control

**Recommendation:** Check crates.io for `oqs` or `liboqs` first. If nothing suitable, use bindgen.

### Changes Required

#### 1. Investigate Existing Crates

```bash
cargo search oqs
cargo search liboqs
cargo search pqcrypto
```

Known options:

- `pqcrypto` — Pure Rust implementations, may not have ML-DSA-87
- `oqs-sys` — Low-level bindings if they exist

#### 2. Create liboqs Bindings (if needed)

**File**: `crates/recrypt-ffi/src/liboqs/bindings.rs`

```rust
//! Raw FFI bindings to liboqs
//! Generated via bindgen or manual extern "C" declarations

use std::ffi::c_char;
use std::os::raw::c_int;

#[repr(C)]
pub struct OQS_SIG {
    pub method_name: *const c_char,
    pub alg_version: *const c_char,
    pub length_public_key: usize,
    pub length_secret_key: usize,
    pub length_signature: usize,
    // ... other fields
}

extern "C" {
    pub fn OQS_SIG_new(method_name: *const c_char) -> *mut OQS_SIG;
    pub fn OQS_SIG_free(sig: *mut OQS_SIG);
    pub fn OQS_SIG_keypair(
        sig: *const OQS_SIG,
        public_key: *mut u8,
        secret_key: *mut u8,
    ) -> c_int;
    pub fn OQS_SIG_sign(
        sig: *const OQS_SIG,
        signature: *mut u8,
        signature_len: *mut usize,
        message: *const u8,
        message_len: usize,
        secret_key: *const u8,
    ) -> c_int;
    pub fn OQS_SIG_verify(
        sig: *const OQS_SIG,
        message: *const u8,
        message_len: usize,
        signature: *const u8,
        signature_len: usize,
        public_key: *const u8,
    ) -> c_int;
}
```

#### 3. Safe Wrapper

**File**: `crates/recrypt-ffi/src/liboqs/sig.rs`

```rust
//! Post-quantum signature operations

use crate::error::FfiError;
use std::ffi::CString;

#[derive(Debug, Clone, Copy)]
pub enum PqAlgorithm {
    MlDsa87,  // aka Dilithium5
    MlDsa65,  // aka Dilithium3
    MlDsa44,  // aka Dilithium2
}

impl PqAlgorithm {
    fn to_oqs_name(&self) -> &'static str {
        match self {
            Self::MlDsa87 => "ML-DSA-87",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa44 => "ML-DSA-44",
        }
    }
}

pub struct PqKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub algorithm: PqAlgorithm,
}

pub fn pq_keygen(alg: PqAlgorithm) -> Result<PqKeyPair, FfiError> {
    // Implementation using liboqs FFI
    todo!()
}

pub fn pq_sign(
    sk: &[u8],
    alg: PqAlgorithm,
    message: &[u8],
) -> Result<Vec<u8>, FfiError> {
    // Implementation using liboqs FFI
    todo!()
}

pub fn pq_verify(
    pk: &[u8],
    alg: PqAlgorithm,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, FfiError> {
    // Implementation using liboqs FFI
    todo!()
}
```

### Success Criteria

#### Automated Verification

- [x] `cargo build -p recrypt-ffi --features liboqs` compiles (via `oqs` crate v0.11)
- [x] PQ signature test passes:

```rust
#[test]
fn test_pq_signature_roundtrip() {
    let keypair = pq_keygen(PqAlgorithm::MlDsa87).unwrap();
    let message = b"Test message for PQ signature";

    let signature = pq_sign(&keypair.secret_key, PqAlgorithm::MlDsa87, message).unwrap();
    let valid = pq_verify(&keypair.public_key, PqAlgorithm::MlDsa87, message, &signature).unwrap();

    assert!(valid);

    // Tampered message should fail
    let mut bad_message = message.to_vec();
    bad_message[0] ^= 0xFF;
    let invalid = pq_verify(&keypair.public_key, PqAlgorithm::MlDsa87, &bad_message, &signature).unwrap();
    assert!(!invalid);
}
```

---

## Phase 1d: ED25519 Classical Signatures

### Overview

Integrate `ed25519-dalek` for classical signature fallback.

### Changes Required

**File**: `crates/recrypt-ffi/src/ed25519.rs`

```rust
//! ED25519 classical signatures via ed25519-dalek

use ed25519_dalek::{
    Signer, SigningKey, Verifier, VerifyingKey,
    Signature, SignatureError,
};
use rand::rngs::OsRng;

use crate::error::FfiError;

pub struct Ed25519KeyPair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

pub fn ed25519_keygen() -> Ed25519KeyPair {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    Ed25519KeyPair { signing_key, verifying_key }
}

pub fn ed25519_sign(sk: &SigningKey, message: &[u8]) -> Signature {
    sk.sign(message)
}

pub fn ed25519_verify(
    pk: &VerifyingKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), SignatureError> {
    pk.verify(message, signature)
}
```

### Success Criteria

#### Automated Verification

- [x] ED25519 test passes:

```rust
#[test]
fn test_ed25519_roundtrip() {
    let kp = ed25519_keygen();
    let message = b"Hello ED25519";
    let sig = ed25519_sign(&kp.signing_key, message);
    assert!(ed25519_verify(&kp.verifying_key, message, &sig).is_ok());
}
```

---

## Phase 1e: Integration & Smoke Tests

### Overview

Final integration testing of all three crypto subsystems.

### Changes Required

**File**: `crates/recrypt-ffi/tests/integration.rs`

```rust
//! Integration tests for recrypt-ffi

use dcypher_ffi::openfhe::PreContext;
use dcypher_ffi::liboqs::{pq_keygen, pq_sign, pq_verify, PqAlgorithm};
use dcypher_ffi::ed25519::{ed25519_keygen, ed25519_sign, ed25519_verify};

#[test]
fn test_full_pre_flow() {
    // Alice encrypts for herself
    let ctx = PreContext::new().unwrap();
    let alice = ctx.generate_keypair().unwrap();
    let bob = ctx.generate_keypair().unwrap();

    let data = b"Sensitive document for proxy recryption";
    let ct_alice = ctx.encrypt(&alice.public, data).unwrap();

    // Proxy transforms for Bob (without seeing plaintext)
    let recrypt_key = ctx.generate_recrypt_key(&alice.secret, &bob.public).unwrap();
    let ct_bob = ctx.recrypt(&recrypt_key, &ct_alice).unwrap();

    // Bob decrypts
    let recovered = ctx.decrypt(&bob.secret, &ct_bob).unwrap();
    assert_eq!(&recovered[..data.len()], data);
}

#[test]
fn test_dual_signature_flow() {
    let message = b"Dual-signed authentication request";

    // Classical signature
    let ed_kp = ed25519_keygen();
    let ed_sig = ed25519_sign(&ed_kp.signing_key, message);

    // Post-quantum signature
    let pq_kp = pq_keygen(PqAlgorithm::MlDsa87).unwrap();
    let pq_sig = pq_sign(&pq_kp.secret_key, PqAlgorithm::MlDsa87, message).unwrap();

    // Both verify
    assert!(ed25519_verify(&ed_kp.verifying_key, message, &ed_sig).is_ok());
    assert!(pq_verify(&pq_kp.public_key, PqAlgorithm::MlDsa87, message, &pq_sig).unwrap());
}
```

### Success Criteria

#### Automated Verification

- [x] All tests pass: `cargo test -p recrypt-ffi` — 16 tests passing
- [x] No clippy warnings: `cargo clippy -p recrypt-ffi -- -D warnings`
- [x] Documentation builds: `cargo doc -p recrypt-ffi`

#### Manual Verification

- [x] Libraries link correctly on macOS (dylib)
- [ ] Libraries link correctly on Linux (if CI available)
- [x] Performance is acceptable (PRE ~10-100ms, signatures ~1ms)

---

## Testing Strategy

### Unit Tests

- Each module has inline tests for basic functionality
- `PreContext` creation and parameter validation
- Coefficient conversion (bytes ↔ BFV integers)
- Signature roundtrips

### Integration Tests

- Full PRE flow: encrypt → recrypt → decrypt
- Dual-signature creation and verification
- Error cases: wrong keys, corrupted data

### Property-Based Tests (proptest)

```rust
proptest! {
    #[test]
    fn pre_roundtrip_arbitrary_data(data in prop::collection::vec(any::<u8>(), 1..1000)) {
        let ctx = PreContext::new().unwrap();
        let kp = ctx.generate_keypair().unwrap();
        let ct = ctx.encrypt(&kp.public, &data).unwrap();
        let recovered = ctx.decrypt(&kp.secret, &ct).unwrap();
        prop_assert_eq!(&recovered[..data.len()], &data[..]);
    }
}
```

## Performance Considerations

- OpenFHE context creation is expensive (~100ms); cache contexts
- BFV encryption/decryption: ~10-50ms per chunk
- Recryption: ~10ms (transforms only the key material)
- ED25519: ~0.1ms sign/verify
- ML-DSA-87: ~1ms sign, ~0.5ms verify

## Known Risks & Mitigations

| Risk                                          | Mitigation                                          |
| --------------------------------------------- | --------------------------------------------------- |
| OpenFHE linking issues on different platforms | Document required env vars; consider static linking |
| liboqs algorithm name changes                 | Use feature detection; fallback names               |
| Non-deterministic serialization               | Test semantic equality only                         |
| Large ciphertext sizes (~10KB)                | Document in API; optimize later                     |

## References

- Implementation plan: `docs/IMPLEMENTATION_PLAN.md`
- OpenFHE Rust bindings: `vendor/openfhe-rs/`
- Python prototype PRE: `python-prototype/src/dcypher/lib/pre.py`
- Hybrid encryption design: `docs/hybrid-encryption-architecture.md`
- PRE backend traits: `docs/pre-backend-traits.md`

---

## Appendix: Dependency Investigation Notes

### liboqs Rust Options

1. **`oqs` crate** — Check if available and maintained
2. **`pqcrypto-dilithium`** — Part of pqcrypto suite, pure Rust
3. **`liboqs-sys`** — Raw bindings if available
4. **Manual bindgen** — Last resort

### ED25519 Crate

Using `ed25519-dalek` v2.1:

- Well-maintained, audited
- Supports `SigningKey`/`VerifyingKey` API
- No additional dependencies needed
