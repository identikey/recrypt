# TFHE Proxy Recryption Research Report

**Date:** 2026-01-20  
**Status:** Research Complete, Awaiting Implementation  
**Purpose:** Replace OpenFHE BFV with faster TFHE-based proxy recryption

---

## Executive Summary

We will replace the current OpenFHE BFV-based PRE backend with TFHE using [Zama's tfhe-rs](https://github.com/zama-ai/tfhe-rs). TFHE's key switching mechanism implements proxy recryption by transforming an LWE ciphertext encrypted under key A into one decryptable by key B, without decryption.

**Key decisions:**
- **Multi-LWE encoding:** Encrypt each 2-bit chunk separately (simpler, same security)
- **32-byte payload only:** PRE just the symmetric key, not the full 96-byte KeyMaterial
- **Seeded keys:** Store seed + `b` values only, regenerate `a` vectors (shrinks keys ~100x)
- **Zama primitives:** Use `core_crypto` types, implement custom asymmetric KSK generation

**Expected gains:**
- Recryption: ~1-3s → ~10-50ms (10-100x faster)
- Pure Rust (no C++ FFI nightmare)
- Thread-safe (no global state)

---

## 1. How TFHE PRE Works

### 1.1 LWE Ciphertext Structure

```
ct = (a, b) where b = <a, s> + message + noise
      ↑              ↑           ↑
   random vector   secret key   small error term
```

### 1.2 Why Hops Add Noise

Key switching involves adding ciphertexts together. Each has its own noise term:
- Fresh ciphertext: noise ≈ α
- After 1 recryption: noise ≈ α + β  
- After 2 recryptions: noise ≈ α + 2β
- Eventually: noise > message → decryption fails

With good parameters, **1-2 hops is fine**. Beyond that requires bootstrapping.

### 1.3 Key Switching = PRE

The recryption key is a **key switching key (KSK)** containing encryptions of Alice's secret key material under Bob's key. The proxy applies this to transform ciphertext domains.

---

## 2. Implementation Decisions

### 2.1 Multi-LWE Encoding ✓

LWE encrypts **one scalar** (2-4 bits typically). For 32 bytes:
- 32 bytes = 256 bits
- With 2-bit message space: 128 LWE ciphertexts
- With 4-bit message space: 64 LWE ciphertexts

**Why multi-LWE over packed RLWE:**
- Simpler—just "do LWE N times"
- Same security per ciphertext
- No polynomial ring complexity
- Key switching applies directly

**Ciphertext size:** ~128 × 5.6 KB ≈ **700 KB** per encrypted 32-byte key (unseeded)

### 2.2 32-Byte Payload Only ✓

Current `KeyMaterial` structure:
```rust
pub struct KeyMaterial {
    pub key: [u8; 32],    // ← PRE THIS (symmetric key)
    pub nonce: [u8; 24],  // Public (random IV)
    pub hash: [u8; 32],   // Public (content hash)
    pub size: u64,        // Public
}
```

**Only the 32-byte symmetric key needs encryption.** The rest can be authenticated but stored in the clear. 256-bit symmetric key = AES-256 level security.

### 2.3 Seeded Keys ✓

LWE ciphertext = `(a, b)` where `a` is a large random vector (~5 KB for n=700).

**Unseeded storage:**
- Store full `a` vector for each ciphertext
- RecryptKey: ~35 MB (6,300 ciphertexts × 5.6 KB each)

**Seeded storage:**
- Store 32-byte seed + only the `b` values
- Receiver regenerates `a` vectors from CSPRNG
- RecryptKey: ~50 KB (6,300 × 8 bytes + 32 byte seed)

**Same security**—`a` is pseudorandom either way. ~700x smaller.

---

## 3. Architecture: Extend Zama's core_crypto

### 3.1 Approach

Use Zama's `core_crypto` primitives but implement custom asymmetric KSK generation:

```rust
use tfhe::core_crypto::prelude::*;

/// Custom: asymmetric KSK generation using Bob's PUBLIC key
fn generate_asymmetric_ksk(
    from_sk: &LweSecretKey,
    to_pk: &TfhePublicKey,  // NOT to_sk!
    decomp_params: DecompositionParameters,
) -> LweKeyswitchKey {
    // For each i in 0..n and each decomposition level:
    // - compute gadget-scaled plaintext of s_from[i] (INTEGER torus arithmetic)
    // - encrypt under to_pk (public key encryption)
}
```

### 3.2 Why Not Fork rs-tfhe?

rs-tfhe has working PRE, but:
- Uses 32-bit torus (u32), Zama uses 64-bit (u64)
- Uses **floats** in key generation (correctness/security footgun)
- Less maintained than Zama

Better to use Zama's decomposition + keyswitch machinery and only customize the KSK generation.

### 3.3 Critical: No Floats

rs-tfhe does this (bad):
```rust
let p = ((k as u32 * key_val) as f64) / ((1 << ...) as f64);  // WRONG
```

We must use **integer torus arithmetic** only:
```rust
// Use Zama's SignedDecomposer and Plaintext<Torus>
let decomposer = SignedDecomposer::new(base_log, level_count);
let scaled = decomposer.closest_representable(secret_bit * gadget_factor);
```

---

## 4. Key Size Analysis (Corrected)

### 4.1 Recryption Key Size

Standard KSK stores one ciphertext per (secret_index, decomposition_level):

| Component | Count | Size Each | Total |
|-----------|-------|-----------|-------|
| Secret indices (n) | 700 | - | - |
| Decomposition levels (L) | 9 | - | - |
| Ciphertexts | 6,300 | 5.6 KB | **35 MB** |

**With seeding:**
| Component | Size |
|-----------|------|
| Seed | 32 bytes |
| `b` values only | 6,300 × 8 = 50 KB |
| **Total** | **~50 KB** |

### 4.2 Public Key Size

Public key = encryptions of zero (for public-key encryption):

| Unseeded | Seeded |
|----------|--------|
| 2N × 5.6 KB ≈ **8 MB** | 2N × 8 + 32 ≈ **11 KB** |

### 4.3 Ciphertext Size (32-byte message)

| Encoding | Chunks | Unseeded | Seeded |
|----------|--------|----------|--------|
| 2-bit | 128 | ~700 KB | ~1 KB |
| 4-bit | 64 | ~350 KB | ~0.5 KB |

---

## 5. Security Model

### 5.1 Post-Quantum

TFHE is lattice-based (LWE hardness). At 128-bit security parameters, it's quantum-resistant—same as BFV.

### 5.2 Unidirectionality

Recryption keys are one-way:
- `rk(Alice→Bob)` ≠ `rk(Bob→Alice)`
- Collusion between proxy and Bob doesn't reveal Alice's secret key

### 5.3 CPA Security (Malleable)

Basic LWE PRE is malleable—attacker can perturb ciphertexts. But our hybrid architecture (AEAD for payload) provides integrity. PRE only transports the symmetric key.

### 5.4 Noise Budget

With conservative parameters:
- 1 recryption: ✓ safe
- 2 recryptions: ✓ safe with margin
- 3+ recryptions: ⚠️ measure failure rates

---

## 6. Performance Estimates

| Operation | OpenFHE BFV | TFHE (Expected) |
|-----------|-------------|-----------------|
| Key Generation | ~135ms | ~50-100ms |
| Encryption (32B) | ~500ms | ~10-50ms |
| Decryption | ~200ms | ~5-20ms |
| **Recryption** | **~1-3s** | **~10-50ms** |

---

## 7. Implementation Plan

### Phase 1: Core Library (Week 1)

Create `crates/recrypt-tfhe/`:

```
recrypt-tfhe/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── error.rs
│   ├── params.rs         # 128-bit security parameters
│   ├── keys/
│   │   ├── mod.rs
│   │   ├── secret.rs     # LweSecretKey wrapper
│   │   ├── public.rs     # Seeded encryptions of zero
│   │   └── recrypt.rs    # Seeded asymmetric KSK
│   ├── ciphertext.rs     # Multi-LWE, seeded
│   ├── encrypt.rs        # Public-key LWE encryption
│   ├── decrypt.rs
│   └── recrypt.rs        # Key switching operation
└── tests/
    ├── roundtrip.rs
    ├── recryption.rs
    └── failure_rate.rs   # Monte Carlo noise tests
```

**v1 shortcut:** Use Zama's `KeySwitchingKey` which requires both secrets. Get correctness first.

**v2:** Implement true asymmetric KSK generation (Alice's secret + Bob's public only).

### Phase 2: PreBackend Integration (Week 2)

```rust
// crates/recrypt-core/src/pre/backends/tfhe.rs

pub struct TfheBackend {
    params: TfheParams,
}

impl PreBackend for TfheBackend {
    fn backend_id(&self) -> BackendId { BackendId::Tfhe }
    fn is_post_quantum(&self) -> bool { true }
    // ... implement trait methods
}
```

Add `BackendId::Tfhe = 2` to existing enum.

### Phase 3: Testing & Benchmarks (Week 2)

- Roundtrip encryption tests
- Recryption chain tests (Alice→Bob, Alice→Bob→Carol)
- **Failure rate Monte Carlo:** random keys/messages, count decrypt failures
- Benchmark vs OpenFHE backend

---

## 8. Open Questions

1. **Seeding implementation:** Does Zama expose seeded LWE ciphertext types in `core_crypto`? May need to implement ourselves.

2. **Public-key encryption:** Zama's high-level API uses `ClientKey` for encryption. For asymmetric PRE, we need proper LWE public-key encryption. Check if `core_crypto` exposes this or if we implement it (encryptions of zero + random linear combinations).

3. **Decomposition parameters:** What `base_log` and `level_count` for good noise/size tradeoff? Start with Zama's defaults, tune based on failure rate tests.

---

## 9. References

1. [Zama tfhe-rs](https://github.com/zama-ai/tfhe-rs) — Production Rust TFHE
2. [rs-tfhe proxy_reenc.rs](https://github.com/thedonutfactory/rs-tfhe/blob/main/src/proxy_reenc.rs) — Reference PRE implementation
3. [TFHE Paper](https://eprint.iacr.org/2018/421) — Original TFHE construction
4. [HElium](http://arxiv.org/abs/2312.14250) — FHE compiler with PRE support
5. [HPRE](http://arxiv.org/abs/1706.01756) — Homomorphic Proxy Re-Encryption theory

---

## Appendix A: Comparison Summary

| Aspect | OpenFHE BFV (current) | TFHE (proposed) |
|--------|----------------------|-----------------|
| Recrypt speed | ~1-3s | ~10-50ms |
| Language | C++ via FFI | Pure Rust |
| Thread safety | Global state issues | Thread-safe |
| RecryptKey size | ~10 KB | ~50 KB (seeded) |
| Ciphertext size | ~5-10 KB | ~1 KB (seeded, 32B msg) |
| Post-quantum | ✓ | ✓ |
| Maintenance | Complex C++ build | Cargo dependency |

## Appendix B: Why Only 32 Bytes

The hybrid encryption architecture already separates concerns:

```
┌─────────────────────────────────────────────────────────┐
│  Encrypted File                                          │
├─────────────────────────────────────────────────────────┤
│  Header:                                                 │
│    - PRE-encrypted symmetric key (32 bytes) ← RECRYPT   │
│    - Nonce (24 bytes, public)                           │
│    - Content hash (32 bytes, public)                    │
│    - Size (8 bytes, public)                             │
├─────────────────────────────────────────────────────────┤
│  Payload:                                                │
│    - XChaCha20-Poly1305 encrypted content               │
│    - Authenticated, integrity-protected                  │
└─────────────────────────────────────────────────────────┘
```

PRE only transforms the 32-byte key. Everything else is either public metadata or symmetrically encrypted with the key we're protecting.
