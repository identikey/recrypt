# Hybrid Encryption Architecture

**Status:** ✅ DECIDED  
**Default:** Post-quantum hybrid (Lattice-KEM + XChaCha20 + Bao)  
**Fallback:** Classical hybrid (EC-KEM + XChaCha20 + Bao)

---

## Executive Summary

Recrypt uses **hybrid encryption** for all file/message encryption:

1. **KEM (Key Encapsulation):** PRE-encrypt a random symmetric key
2. **DEM (Data Encapsulation):** Symmetric-encrypt the payload with that key

This architecture is mandatory for lattice-based PRE (due to ciphertext expansion) and recommended for EC-based PRE (for consistency and performance).

---

## Security Model

### Threat Model

| Threat                                   | Mitigation                                                                |
| ---------------------------------------- | ------------------------------------------------------------------------- |
| **Passive adversary (storage provider)** | Never sees plaintext or keys; only wrapped keys + symmetric ciphertext    |
| **Active adversary (network)**           | Signatures on all messages; content-addressing prevents substitution      |
| **Compromised proxy**                    | Proxy has recrypt keys, but these don't reveal plaintexts or private keys |
| **Key compromise (user)**                | Forward secrecy via per-file random symmetric keys                        |
| **Quantum adversary**                    | Lattice-based KEM provides post-quantum security                          |

### Security Properties

| Property                 | Hybrid (Lattice) | Hybrid (EC)      | Pure Lattice | Pure EC |
| ------------------------ | ---------------- | ---------------- | ------------ | ------- |
| **Post-quantum**         | ✅               | ❌               | ✅           | ❌      |
| **IND-CPA (KEM)**        | ✅               | ✅               | ✅           | ✅      |
| **AE (DEM)**             | ✅               | ✅               | N/A          | N/A     |
| **Forward secrecy**      | ✅ Per-file keys | ✅ Per-file keys | ❌           | ❌      |
| **Proxy learns nothing** | ✅               | ✅               | ✅           | ✅      |

### IND-CPA vs IND-CCA Acceptability

PRE schemes typically provide IND-CPA (chosen-plaintext) security, not IND-CCA (chosen-ciphertext). This is acceptable for Recrypt because:

1. **Content-addressing:** Ciphertext hash = storage key. Tampering → different hash → not found
2. **Signatures:** All messages are signed. Forged/modified ciphertexts fail verification
3. **No decryption oracle:** Users don't decrypt arbitrary attacker-supplied ciphertexts

### Metadata Confidentiality: Encrypted Plaintext Hash

A subtle but critical security property: **the plaintext hash is encrypted**.

| Approach                     | Plaintext Hash      | Attack Surface                                |
| ---------------------------- | ------------------- | --------------------------------------------- |
| **Public metadata**          | Visible to all      | Confirmation, dictionary, correlation attacks |
| **Encrypted in wrapped_key** | Requires PRE access | None—same as full decryption                  |

By including `plaintext_hash` and `plaintext_size` inside the PRE-encrypted key material rather than public metadata, we prevent:

1. **Confirmation attacks:** "Is this the file I suspect?" requires unwrapping the key
2. **Dictionary attacks:** Pre-computing hashes of known files is useless without key access
3. **Correlation attacks:** Same plaintext encrypted by different users produces different ciphertext AND different wrapped keys (due to randomness)

This is a defense-in-depth measure. Even if an attacker has:

- Full ciphertext (encrypted data)
- Bao tree hash (ciphertext integrity)
- Wrapped key (PRE-encrypted)

They learn **nothing** about the plaintext content without the corresponding private key or a valid recryption path.

**Tradeoff:** The recipient must unwrap the key to verify plaintext integrity, but this is the correct order of operations anyway—you can't verify plaintext until after decryption.

---

## Practical Security: Leak Friction Analysis

### The Insider Threat

An authorized user with legitimate access can always leak content. No cryptography prevents this. However, different architectures impose different **friction** on leaking:

| Architecture         | Leak Payload                | Payload Size      | Friction Level |
| -------------------- | --------------------------- | ----------------- | -------------- |
| **Hybrid (any)**     | `file_hash + symmetric_key` | 64 bytes          | 🔴 Minimal     |
| **Pure EC-PRE**      | Full ciphertext             | 5-15x file size   | 🟡 Moderate    |
| **Pure Lattice-PRE** | Full ciphertext             | 50-100x file size | 🟢 High        |
| **Plaintext exfil**  | Raw content                 | 1x file size      | 🟡 Moderate    |

### Interpretation

- **Hybrid leak (64 bytes):** Fits in a QR code, SMS, or sticky note. Trivial to exfiltrate.
- **Ciphertext leak:** Requires bandwidth proportional to (expanded) file size. Detectable.
- **Plaintext leak:** Same bandwidth as original file. Always possible for authorized users.

**Conclusion:** Friction-based leak prevention is not a primary security goal. Rely on:

- Access control (authorization)
- Audit logging
- DRM/watermarking (if required)
- Legal/contractual controls

---

## Ciphertext Expansion Comparison

### KEM Ciphertext (Wrapped Symmetric Key)

| Backend                   | Input    | Output     | Expansion |
| ------------------------- | -------- | ---------- | --------- |
| **Lattice (OpenFHE BFV)** | 32 bytes | 1-10 KB    | ~30-300x  |
| **EC Pairing (recrypt)**  | 32 bytes | ~480 bytes | ~15x      |
| **EC secp256k1 (umbral)** | 32 bytes | ~200 bytes | ~6x       |

### DEM Ciphertext (Symmetric Encryption)

| Cipher                | Input   | Output   | Expansion |
| --------------------- | ------- | -------- | --------- | --- |
| **XChaCha20 + Bao**   | N bytes | N bytes  | ~0%       |
| **ChaCha20-Poly1305** | N bytes | N + 16 B | ~0%       |     |
| **AES-256-GCM**       | N bytes | N + 16 B | ~0%       |

**Note:** We use XChaCha20 (pure stream cipher with 192-bit nonce) + Bao tree hashing, not AEAD. The Bao tree (~1% overhead) is stored separately as outboard data. XChaCha20's extended nonce eliminates birthday-bound concerns with random nonce generation.

### Total Overhead (Hybrid)

For a 1 MB file:

| Backend          | Symmetric CT | Wrapped Key | Total      | Overhead |
| ---------------- | ------------ | ----------- | ---------- | -------- |
| **Lattice**      | 1,000,016 B  | ~5 KB       | ~1.005 MB  | ~0.5%    |
| **EC Pairing**   | 1,000,016 B  | ~500 B      | ~1.0005 MB | ~0.05%   |
| **EC secp256k1** | 1,000,016 B  | ~200 B      | ~1.0002 MB | ~0.02%   |

**Conclusion:** With hybrid encryption, the PRE backend choice has negligible impact on storage overhead.

---

## Computational Overhead

### Single Operations (Wrapping 32-byte Key)

| Operation                | Lattice (128-bit) | EC Pairing | EC secp256k1 | Ratio (L:EC) |
| ------------------------ | ----------------- | ---------- | ------------ | ------------ |
| **Key generation**       | 50-100 ms         | ~760 μs    | ~500 μs      | ~100x        |
| **Generate recrypt key** | 100-300 ms        | ~15 ms     | ~10 ms       | ~10-20x      |
| **Encrypt (wrap)**       | 10-30 ms          | ~7 ms      | ~5 ms        | ~2-5x        |
| **Recrypt**              | 50-150 ms         | ~18 ms     | ~12 ms       | ~3-10x       |
| **Decrypt (unwrap)**     | 5-15 ms           | ~6.5 ms    | ~4 ms        | ~1-3x        |

### Symmetric Operations (XChaCha20 + Bao)

| File Size | Encrypt + Hash | Decrypt + Verify |
| --------- | -------------- | ---------------- |
| 1 KB      | ~0.5 μs        | ~0.5 μs          |
| 1 MB      | ~0.5 ms        | ~0.5 ms          |
| 100 MB    | ~50 ms         | ~50 ms           |
| 1 GB      | ~500 ms        | ~500 ms          |

**Note:** Slightly slower than pure XChaCha20 due to Bao tree hashing, but enables streaming verification.

### End-to-End Latency (Hybrid, 1 MB File)

| Operation                 | Lattice         | EC Pairing       | EC secp256k1   |
| ------------------------- | --------------- | ---------------- | -------------- |
| **Encrypt file**          | ~20 ms + 0.3 ms | ~7 ms + 0.3 ms   | ~5 ms + 0.3 ms |
| **Recrypt for recipient** | ~100 ms         | ~18 ms           | ~12 ms         |
| **Decrypt file**          | ~10 ms + 0.3 ms | ~6.5 ms + 0.3 ms | ~4 ms + 0.3 ms |

### Energy Consumption (Approximate)

| Backend     | Energy per Encrypt | Energy per Recrypt |
| ----------- | ------------------ | ------------------ |
| **Lattice** | ~100-500 mJ        | ~200-800 mJ        |
| **EC**      | ~10-50 mJ          | ~20-100 mJ         |

**Conclusion:** EC is ~10x more energy-efficient. Matters for mobile/embedded.

---

## Memory and Key Material Sizes

| Item               | Lattice (128-bit) | EC Pairing | EC secp256k1 |
| ------------------ | ----------------- | ---------- | ------------ |
| **Public key**     | ~200 KB           | ~64 bytes  | ~33 bytes    |
| **Secret key**     | ~100-200 KB       | ~32 bytes  | ~32 bytes    |
| **Recrypt key**    | ~1-2 MB           | ~200 bytes | ~100 bytes   |
| **Crypto context** | ~10-50 MB         | N/A        | N/A          |

**Conclusion:** Lattice requires orders of magnitude more memory. Problematic for:

- Mobile apps
- WebAssembly (memory limits)
- High-concurrency servers (per-user contexts)

---

## Backend Selection Guidance

### Default: Lattice (Post-Quantum Hybrid)

Use when:

- Long-term data protection required (>10 years)
- Adversary may have future quantum capabilities
- Compliance requires post-quantum algorithms
- Memory/energy constraints are acceptable

### Alternative: EC (Classical Hybrid)

Use when:

- Immediate performance is critical
- Resource-constrained environment (mobile, embedded, WASM)
- Post-quantum not required by threat model
- Simpler deployment (pure Rust, no FFI)

### Future: Hybrid Hybrid (Belt + Suspenders)

```
wrapped_key = EC_PRE(Lattice_PRE(symmetric_key))
```

Defense in depth: if either primitive breaks, the other protects. Cost: 2x KEM overhead (still negligible vs file size).

---

## MPC/Threshold Extension

Both lattice and EC-based PRE can be extended to threshold/MPC schemes:

| Scheme                | Threshold Support  | Maturity   | Notes                             |
| --------------------- | ------------------ | ---------- | --------------------------------- |
| **Umbral (EC)**       | ✅ Native (t-of-n) | Production | NuCypher network uses this        |
| **recrypt (EC)**      | ❌ Not built-in    | —          | Would require custom impl         |
| **Lattice (OpenFHE)** | ✅ Research impls  | Academic   | Threshold BFV exists but immature |

### Threshold PRE Benefits

- No single proxy has full recryption capability
- Collusion threshold required to recrypt
- Decentralized trust model

### Implementation Priority

1. **Phase 1:** Single-server PRE (current scope)
2. **Phase 2:** Threshold EC-PRE via Umbral
3. **Phase 3:** Threshold Lattice-PRE (when mature)

---

## Wire Format

### Encrypted File Structure

```
┌─────────────────────────────────────────────────────────────┐
│ EncryptedFile (envelope, v3 — Gordian Envelope / dCBOR)     │
├─────────────────────────────────────────────────────────────┤
│ wrapped_key: Ciphertext        // PRE-encrypted key bundle  │
│ bao_hash:    [u8; 32]          // Blake3 root of ciphertext │
│ ciphertext:  [u8]              // XChaCha20 encrypted data  │
│ signature:   Option<MultiSig>  // ED25519 + ML-DSA-87       │
└─────────────────────────────────────────────────────────────┘

Stored alongside (never inside the envelope):
  {bao_hash}.obao  — bao-tree outboard, sibling storage object.
                     Absent for files ≤ 16 KiB (single chunk group).
```

**Notes:**

- No Poly1305 auth tag — Bao root + signature provides equivalent security
- `plaintext_hash` and `plaintext_size` are INSIDE `wrapped_key` (encrypted)
- The bao outboard is **not** an envelope field; it lives as a sibling storage
  object keyed `{base58(bao_hash)}.obao` and is fetched independently by the
  streaming decrypt path. Field 4 (`bao_outboard`) is retired in the wire
  schema.
- Ciphertext is pure XChaCha20 (seekable, no per-chunk overhead)

### Wrapped Key Bundle (PRE-Encrypted)

The key material bundle is encrypted by the PRE backend:

```
┌─────────────────────────────────────────────────────────────┐
│ KeyMaterial (96 bytes, plaintext before PRE encryption)     │
├─────────────────────────────────────────────────────────────┤
│ symmetric_key: [u8; 32]        // XChaCha20 key             │
│ nonce: [u8; 24]                // XChaCha20 extended nonce  │
│ plaintext_hash: [u8; 32]       // Blake3 of plaintext       │
│ plaintext_size: u64            // Original size (LE bytes)  │
└─────────────────────────────────────────────────────────────┘
```

This protects the plaintext hash from confirmation/dictionary attacks—only
someone who can unwrap the key via PRE can see the plaintext hash.

### Backend-Specific Serialization

```
// Lattice (OpenFHE serialized ciphertext)
wrapped_key = openfhe_serialize(bfv_encrypt(key_material))

// EC Pairing (recrypt)
wrapped_key = ephemeral_pk || encrypted_payload || auth_hash

// EC secp256k1 (umbral)
wrapped_key = capsule || encrypted_payload
```

### Signed Metadata

The `wrapped_key` and `bao_hash` MUST be covered by the sender's signature:

```
signature_payload = concat(
    wrapped_key,    // Contains encrypted (key, nonce, plaintext_hash, size)
    bao_hash,       // Ciphertext integrity root
)
signature = Sign(sender_sk, signature_payload)
```

This binding provides:

- **Authenticity:** These values came from the sender
- **Integrity:** Tampering is detectable
- **Confidentiality:** `plaintext_hash` hidden inside `wrapped_key`

---

## Symmetric Encryption: XChaCha20 + Bao (No Poly1305)

### Decision

Use **XChaCha20** (pure stream cipher with 192-bit nonce) with **Blake3/Bao** for integrity, rather than ChaCha20-Poly1305 AEAD.

### Why XChaCha20 over ChaCha20?

XChaCha20 extends the nonce from 96 bits to 192 bits via an HChaCha20 key derivation step. Benefits:

1. **Nonce safety:** With 192-bit random nonces, birthday collision probability is negligible (~2^-96 after 2^48 encryptions vs ~2^-32 for 96-bit nonces)
2. **Simpler key management:** Safe to use random nonces per-file forever without tracking state
3. **Same security:** Underlying ChaCha20 security properties unchanged
4. **Negligible overhead:** One extra HChaCha20 call (~nanoseconds) per encryption

### Rationale

Poly1305's authentication tag is computed over the entire ciphertext—no partial verification is possible. This conflicts with our streaming verification requirement. Bao (Blake3's tree mode) provides:

- Incremental verification during streaming download
- ~1% overhead (tree structure) vs 16 bytes × chunks for per-chunk AEAD
- Native to Blake3, which we already use everywhere

### Why This Provides AEAD-Equivalent Security

Traditional AEAD (Authenticated Encryption with Associated Data) bundles:

- **Confidentiality** (encryption)
- **Integrity** (tamper detection)
- **Authenticity** (proof of origin)

Our construction achieves the same properties through composition:

| Property            | AEAD (Poly1305)      | Our Construction      |
| ------------------- | -------------------- | --------------------- |
| **Confidentiality** | ChaCha20             | XChaCha20             |
| **Integrity**       | Poly1305 MAC         | Blake3/Bao tree hash  |
| **Authenticity**    | Poly1305 key binding | Signature on Bao root |

The key insight: **Poly1305's authenticity comes from the secret key**. In our case, the Bao root hash is **signed** by the sender's key, providing equivalent authenticity:

```
AEAD:        Auth = Poly1305(key, ciphertext)
Our scheme:  Auth = Sign(sender_sk, bao_root)
```

Both prove "this ciphertext came from someone who knows the secret." The signature is actually _stronger_ because it's non-repudiable.

### Security Proof Sketch

1. **Confidentiality:** XChaCha20 with random key/nonce is IND-CPA secure
2. **Integrity:** Blake3 is collision-resistant; finding `ct'` where `Bao(ct') = Bao(ct)` requires ~2^128 work
3. **Authenticity:** Signature on `(wrapped_key, bao_root)` binds:
   - The symmetric key (via `wrapped_key`)
   - The exact ciphertext (via `bao_root`)
   - The sender's identity (via signature)

An attacker cannot:

- Modify ciphertext without changing Bao root (integrity)
- Forge a signature on a different Bao root (authenticity)
- Decrypt without the symmetric key (confidentiality)

### Content-Addressing Bonus

In Recrypt, files are stored by `bao_root` hash. This means:

- Tampered ciphertext → different hash → file not found at original address
- Additional layer of integrity beyond cryptographic verification

---

## Dual Integrity Hashes

### Problem

The current Python prototype only stores the Merkle root of **ciphertext chunks**. After decryption, there's no way to verify "I got the correct plaintext" without trusting the entire decrypt pipeline.

### Security Concern: Plaintext Hash Leakage

Storing `plaintext_hash` in public metadata enables attacks:

| Attack           | Description                                             |
| ---------------- | ------------------------------------------------------- |
| **Confirmation** | "Is this the file I suspect?" → compute hash, compare   |
| **Dictionary**   | Pre-compute hashes of known files, match against stored |
| **Correlation**  | Same plaintext → same hash → linkable across users      |

This leaks information about plaintext content, defeating confidentiality.

### Solution: Encrypt Plaintext Hash in Wrapped Key

The `plaintext_hash` is included in the PRE-encrypted key material, not public metadata:

```rust
/// Key material bundle (encrypted by PRE backend)
struct KeyMaterial {
    /// XChaCha20 symmetric key
    pub symmetric_key: [u8; 32],

    /// XChaCha20 extended nonce (192-bit for birthday-safe random generation)
    pub nonce: [u8; 24],

    /// Blake3 hash of original plaintext (for post-decrypt verification)
    pub plaintext_hash: [u8; 32],

    /// Original plaintext size in bytes
    pub plaintext_size: u64,
}
// Total: 96 bytes — fits in one PRE ciphertext slot
```

Only someone who can unwrap the key can see the plaintext hash.

### What's Public vs Encrypted

| Field            | Location                     | Visible Without Decryption?                |
| ---------------- | ---------------------------- | ------------------------------------------ |
| `bao_hash`       | Public metadata              | ✅ Yes — needed for streaming verification |
| `{hash}.obao`    | Sibling storage object       | ✅ Yes — bao-tree outboard (absent for files ≤ 16 KiB) |
| `ciphertext`     | Public                       | ✅ Yes — encrypted data                    |
| `symmetric_key`  | Inside wrapped_key           | ❌ No — PRE encrypted                      |
| `nonce`          | Inside wrapped_key           | ❌ No — PRE encrypted                      |
| `plaintext_hash` | Inside wrapped_key           | ❌ No — PRE encrypted                      |
| `plaintext_size` | Inside wrapped_key           | ❌ No — PRE encrypted                      |

### Verification Flow

```
DOWNLOAD & STREAMING VERIFY (no decryption needed):
  1. Receive ciphertext chunks
  2. Verify each chunk against Bao tree
  3. After full download: computed bao_root matches stored bao_hash ✓

DECRYPT & FINAL VERIFY (requires unwrapping):
  4. Unwrap key material via PRE → get (key, nonce, plaintext_hash, size)
  5. Decrypt ciphertext with XChaCha20(key, nonce)
  6. Verify: len(plaintext) == size ✓
  7. Verify: blake3(plaintext) == plaintext_hash ✓
```

### Why Both Hashes Are Needed

| Hash                      | Verifies               | When          | Requires Key Unwrap? |
| ------------------------- | ---------------------- | ------------- | -------------------- |
| **Bao root (ciphertext)** | Download integrity     | Streaming     | ❌ No                |
| **Blake3 (plaintext)**    | Decryption correctness | After decrypt | ✅ Yes               |

The plaintext hash catches:

- Bugs in decryption code
- Wrong symmetric key used
- Corrupted key material
- Implementation mismatches between sender/receiver

And because it's encrypted, it reveals **nothing** to observers.

---

## Nonce Strategy

### Recommendation: Random Nonce, Stored with Wrapped Key

```rust
struct WrappedKeyBundle {
    wrapped_key: Vec<u8>,     // PRE-encrypted symmetric key
    nonce: [u8; 24],          // Random 192-bit nonce for XChaCha20
}
```

### Alternatives Considered

| Strategy                   | Pros           | Cons                                  |
| -------------------------- | -------------- | ------------------------------------- |
| **Random (chosen)**        | Simple, secure | Must store with wrapped key           |
| **Derived from file hash** | Deterministic  | Risk if same file encrypted twice     |
| **Counter-based**          | No storage     | Requires state management             |
| **ChaCha20 (96-bit)**      | RFC 8439       | Birthday bound at ~2^48 random nonces |

XChaCha20's 192-bit nonce means random generation is safe indefinitely—no birthday concerns even at planetary scale.

### No Per-Chunk Nonces Needed

Since we use XChaCha20 as a pure stream cipher (not per-chunk AEAD), we only need a single nonce per file. XChaCha20 is seekable—we can decrypt any byte offset without processing preceding bytes.

---

## References

- [KEM-DEM Paradigm](https://en.wikipedia.org/wiki/Hybrid_cryptosystem)
- [ChaCha20 Stream Cipher](https://cr.yp.to/chacha.html)
- [XChaCha20 (IETF Draft)](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha)
- [Blake3 Hash Function](https://github.com/BLAKE3-team/BLAKE3)
- [Bao: Blake3 Tree Hashing](https://github.com/oconnor663/bao) — streaming verification
- [BFV Encryption Scheme](https://eprint.iacr.org/2012/144)
- [recrypt-rs (IronCore)](https://github.com/IronCoreLabs/recrypt-rs)
- [umbral-pre (NuCypher)](https://github.com/nucypher/rust-umbral)
- [OpenFHE](https://www.openfhe.org/)
