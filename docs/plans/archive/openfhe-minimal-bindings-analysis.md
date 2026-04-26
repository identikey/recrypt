# OpenFHE Minimal Bindings Analysis

> **Historical Note:** This analysis led to the decision to create custom minimal bindings
> in `crates/recrypt-openfhe-sys/` instead of using `vendor/openfhe-rs/`. The openfhe-rs
> directory has since been **deleted**. This document is preserved for reference.

## Summary

Based on the Python prototype's `pre.py`, we need a very small subset of OpenFHE.
The original `openfhe-rs` bindings were ~1500 lines of Rust + ~2000 lines of C++ wrapper code,
but we only need ~15% of that functionality.

## Required API Surface

### From Python Prototype Analysis

| Category | Python API | OpenFHE C++ API | Status in openfhe-rs |
|----------|-----------|-----------------|---------------------|
| **Params** | `CCParamsBFVRNS()` | `CCParams<CryptoContextBFVRNS>` | ✅ `GenParamsBFVRNS()` |
| | `params.SetPlaintextModulus()` | `SetPlaintextModulus()` | ✅ |
| | `params.SetScalingModSize()` | `SetScalingModSize()` | ✅ |
| **Context** | `GenCryptoContext(params)` | `GenCryptoContext()` | ✅ `DCRTPolyGenCryptoContextByParamsBFVRNS()` |
| | `cc.Enable(PKE)` | `Enable(PKESchemeFeature)` | ✅ `EnableByFeature()` |
| | `cc.Enable(KEYSWITCH)` | | ✅ |
| | `cc.Enable(LEVELEDSHE)` | | ✅ |
| | `cc.Enable(PRE)` | | ✅ |
| | `cc.GetRingDimension()` | `GetRingDimension()` | ✅ |
| | `cc.GetPlaintextModulus()` | N/A on context | ❌ Need to add or track from params |
| **Keys** | `cc.KeyGen()` | `KeyGen()` | ✅ |
| | `keypair.publicKey` | `GetPublicKey()` | ✅ |
| | `keypair.secretKey` | `GetPrivateKey()` | ✅ |
| **Plaintext** | `cc.MakePackedPlaintext(coeffs)` | `MakePackedPlaintext()` | ✅ |
| | `pt.GetPackedValue()` | `GetPackedValue()` | ✅ |
| **Encrypt/Decrypt** | `cc.Encrypt(pk, pt)` | `Encrypt()` | ✅ `EncryptByPublicKey()` |
| | `cc.Decrypt(sk, ct)` | `Decrypt()` | ✅ `DecryptByPrivateKeyAndCiphertext()` |
| **PRE** | `cc.ReKeyGen(sk, pk)` | `ReKeyGen()` | ✅ |
| | `cc.ReEncrypt(ct, rk)` | `ReEncrypt()` | ✅ |
| **Serialization** | `SerializeToFile()` | `Serial::SerializeToFile()` | ❌ API changed in 1.3.0 |
| | `DeserializeCryptoContext()` | `Serial::DeserializeFromFile()` | ❌ API changed in 1.3.0 |
| | `DeserializePublicKey()` | | ❌ |
| | `DeserializePrivateKey()` | | ❌ |
| | `DeserializeCiphertext()` | | ❌ |
| | `DeserializeEvalKey()` | | ❌ |

## What We DON'T Need (can delete)

From the current openfhe-rs, we can remove:

### Schemes (keep only BFV)
- ❌ `ParamsCKKSRNS` - CKKS scheme for approximate arithmetic
- ❌ `ParamsBGVRNS` - BGV scheme
- ❌ `MakeCKKSPackedPlaintext*` - CKKS plaintext encoding
- ❌ `MakeCoefPackedPlaintext` - Coefficient packing
- ❌ `MakeStringPlaintext` - String encoding

### Homomorphic Operations (we only need PRE, not computation)
- ❌ `EvalAdd*` - Homomorphic addition (15+ variants)
- ❌ `EvalSub*` - Homomorphic subtraction (15+ variants)
- ❌ `EvalMult*` - Homomorphic multiplication (20+ variants)
- ❌ `EvalNegate*` - Negation
- ❌ `EvalPoly*` - Polynomial evaluation
- ❌ `EvalRotate*` - Rotation operations
- ❌ `EvalSum*` - Summation
- ❌ `EvalBootstrap*` - Bootstrapping
- ❌ `EvalChebyshev*` - Chebyshev polynomial evaluation
- ❌ `EvalLogistic` - Logistic function
- ❌ `EvalDivide` - Division
- ❌ `EvalSin/Cos` - Trigonometric functions
- ❌ `EvalInnerProduct*` - Inner products

### Multiparty (we use PRE, not threshold)
- ❌ `Multiparty*` - All multiparty operations
- ❌ `ShareKeys` / `RecoverSharedKey`
- ❌ `IntMPBoot*` - Interactive multiparty bootstrapping

### FHEW/LWE (binary gate FHE)
- ❌ `LWEPrivateKey`
- ❌ `EvalCKKStoFHEW*`
- ❌ `EvalFHEWtoCKKS*`
- ❌ `VectorOfLWECiphertexts`

### Scheme Switching
- ❌ `EvalSchemeSwitching*`
- ❌ `EvalCompare*`
- ❌ `EvalMax/MinSchemeSwitching*`

### Advanced Features
- ❌ `Trapdoor*` - Trapdoor sampling
- ❌ `ModReduce*` - Modulus reduction
- ❌ `LevelReduce*` - Level reduction
- ❌ `Rescale*` - CKKS rescaling
- ❌ `Relinearize*` - Relinearization
- ❌ `Compress` - Ciphertext compression

## Minimal Binding Specification

### Types Needed

```rust
// Opaque FFI types
type CryptoContext;      // CryptoContextImpl<DCRTPoly>
type KeyPair;            // KeyPair<DCRTPoly>
type PublicKey;          // PublicKey<DCRTPoly>
type SecretKey;          // PrivateKey<DCRTPoly>
type Ciphertext;         // Ciphertext<DCRTPoly>
type RecryptKey;         // EvalKey<DCRTPoly>
type Plaintext;          // Plaintext

// Rust-side types
struct PreParams {
    plaintext_modulus: u64,
    scaling_mod_size: u32,
    security_level: SecurityLevel,
}
```

### Functions Needed

```rust
// Context creation
fn create_bfv_context(params: &PreParams) -> Result<CryptoContext>;

// Key generation
fn keygen(ctx: &CryptoContext) -> Result<KeyPair>;
fn get_public_key(kp: &KeyPair) -> PublicKey;
fn get_secret_key(kp: &KeyPair) -> SecretKey;

// Encryption
fn make_plaintext(ctx: &CryptoContext, coeffs: &[i64]) -> Result<Plaintext>;
fn encrypt(ctx: &CryptoContext, pk: &PublicKey, pt: &Plaintext) -> Result<Ciphertext>;
fn decrypt(ctx: &CryptoContext, sk: &SecretKey, ct: &Ciphertext) -> Result<Plaintext>;
fn get_packed_value(pt: &Plaintext) -> Vec<i64>;

// PRE operations
fn generate_recrypt_key(ctx: &CryptoContext, from_sk: &SecretKey, to_pk: &PublicKey) -> Result<RecryptKey>;
fn recrypt(ctx: &CryptoContext, rk: &RecryptKey, ct: &Ciphertext) -> Result<Ciphertext>;

// Serialization (byte-based, not file-based)
fn serialize_context(ctx: &CryptoContext) -> Result<Vec<u8>>;
fn deserialize_context(bytes: &[u8]) -> Result<CryptoContext>;
fn serialize_public_key(pk: &PublicKey) -> Result<Vec<u8>>;
fn deserialize_public_key(ctx: &CryptoContext, bytes: &[u8]) -> Result<PublicKey>;
fn serialize_secret_key(sk: &SecretKey) -> Result<Vec<u8>>;
fn deserialize_secret_key(ctx: &CryptoContext, bytes: &[u8]) -> Result<SecretKey>;
fn serialize_ciphertext(ct: &Ciphertext) -> Result<Vec<u8>>;
fn deserialize_ciphertext(ctx: &CryptoContext, bytes: &[u8]) -> Result<Ciphertext>;
fn serialize_recrypt_key(rk: &RecryptKey) -> Result<Vec<u8>>;
fn deserialize_recrypt_key(ctx: &CryptoContext, bytes: &[u8]) -> Result<RecryptKey>;

// Utility
fn get_ring_dimension(ctx: &CryptoContext) -> u32;
fn get_plaintext_modulus(ctx: &CryptoContext) -> u64;
```

### Estimated Size

| Component | openfhe-rs | Minimal | Reduction |
|-----------|-----------|---------|-----------|
| Rust FFI declarations | ~1200 lines | ~150 lines | 87% |
| C++ wrapper code | ~2000 lines | ~400 lines | 80% |
| Build time | ~30s | ~8s | 73% |
| Binary size | ~5MB | ~1MB | 80% |

## Implementation Approach

### Option A: Fork and Strip (Recommended)

1. Fork openfhe-rs to `recrypt-openfhe-sys`
2. Delete all unused bindings
3. Update remaining bindings for OpenFHE 1.3.0
4. Add byte-based serialization (using stringstream instead of file)
5. Add proper error handling
6. Consider static linking option

### Option B: Fresh Implementation

1. Start from scratch with minimal cxx bridge
2. Only implement what we need
3. Design API for Rust ergonomics from the start
4. More work upfront, cleaner result

### Recommendation

**Option A (Fork and Strip)** because:
- The core bindings (encrypt/decrypt/PRE) work
- We only need to fix serialization
- Faster to ship
- Can iterate toward Option B over time

## Static Linking Considerations

OpenFHE supports static builds:

```bash
cmake .. -DBUILD_STATIC=ON -DWITH_OPENMP=OFF
```

Benefits:
- No runtime library path issues
- Single binary deployment
- Simpler cross-compilation

Drawbacks:
- Larger binary (~50MB)
- Longer build times
- May need to resolve symbol conflicts

For production, static linking is strongly recommended.

## Next Steps

1. [ ] Create `crates/recrypt-openfhe-sys/` 
2. [ ] Copy minimal subset from openfhe-rs
3. [ ] Update for OpenFHE 1.3.0 compatibility
4. [ ] Implement byte-based serialization
5. [ ] Add static linking option
6. [ ] Write smoke tests
7. [ ] Update recrypt-ffi to use new bindings

## References

- Python prototype: `python-prototype/src/dcypher/lib/pre.py`
- openfhe-rs: `vendor/openfhe-rs/`
- OpenFHE source: `vendor/openfhe-development/`
- OpenFHE docs: https://openfhe-development.readthedocs.io/

