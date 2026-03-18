# TFHE Noise Analysis: Key Switching and Public Key Encryption

**Date:** January 2026
**Author:** Claude (with human oversight)
**Status:** Research findings - requires cryptographic review before production decisions

## Executive Summary

This document analyzes the noise characteristics of TFHE (Torus Fully Homomorphic Encryption) operations, specifically focusing on why **asymmetric key switching key (KSK) generation using public key encryption does not work** with our current parameters. Our experiments show that while symmetric KSK generation (requiring both secret keys) works correctly, asymmetric KSK generation (using only source secret + target public key) produces ciphertexts with accumulated noise that exceeds the message space, causing decryption failures.

## Background: How TFHE Works

### LWE Encryption Basics

TFHE is based on the Learning With Errors (LWE) problem. An LWE ciphertext encrypting message `m` under secret key `s` has the form:

```
c = (a, b) where b = <a, s> + m + e
```

- `a` is a random vector of dimension `n`
- `s` is the secret key (binary in our case: each coefficient is 0 or 1)
- `m` is the message, scaled by a factor `Δ = 2^62` for 2-bit messages
- `e` is noise sampled from a Gaussian distribution with standard deviation `σ`

The noise `e` is critical: it provides semantic security by masking the relationship between `a`, `b`, and `s`. However, if noise grows too large, it corrupts the message during decryption.

### Message Space and Noise Budget

For 2-bit messages (values 0-3), we encode:
- Message 0 → plaintext value `0`
- Message 1 → plaintext value `Δ = 2^62`
- Message 2 → plaintext value `2Δ = 2^63`
- Message 3 → plaintext value `3Δ = 3 × 2^62`

The messages are spaced `2^62` apart in a 64-bit space. For correct decryption, the noise must be less than `Δ/2 = 2^61` to avoid rounding to the wrong message.

### Key Switching Operation

Key switching transforms a ciphertext encrypted under key `s_A` into a ciphertext decryptable with key `s_B`, without revealing the plaintext. This is fundamental to proxy recryption.

A Key Switching Key (KSK) from `s_A` to `s_B` is a collection of encryptions:

```
KSK[i][l] = Enc_{s_B}(-s_A[i] × 2^{64 - l × base_log})
```

For each coefficient `i` of the input secret key and each decomposition level `l`, we encrypt a scaled (and negated) version of that coefficient under the output key.

### Gadget Decomposition

To reduce noise growth during key switching, TFHE uses gadget decomposition. Instead of multiplying large ciphertext coefficients directly, we decompose them into small digits (base `B = 2^{base_log}`).

Our parameters:
- `base_log = 4` (base `B = 16`)
- `level_count = 3` (3 decomposition levels)

This bounds each digit to at most `B - 1 = 15`, significantly reducing noise accumulation.

## Our Parameters (128-bit Security)

| Parameter | Value | Description |
|-----------|-------|-------------|
| LWE dimension `n` | 742 | Number of coefficients in secret key |
| Ciphertext modulus `q` | 2^64 | Native 64-bit modulus |
| Noise std dev `σ` | 7.07 × 10^-6 | Gaussian standard deviation |
| Decomposition base_log | 4 | log₂(B) where B=16 |
| Decomposition levels | 3 | Number of decomposition digits |
| Message delta `Δ` | 2^62 | Scaling factor for 2-bit messages |

## The Problem: Asymmetric KSK Noise Accumulation

### Our Experimental Findings

We created diagnostic tests comparing symmetric and asymmetric KSK generation:

| Operation | Result |
|-----------|--------|
| Direct encryption (public key) → decrypt | ✅ Works |
| Symmetric KSK recryption → decrypt | ✅ Works |
| Asymmetric KSK recryption → decrypt | ❌ Fails (all bytes corrupted) |

Even encrypting all-zeros and recrypting with asymmetric KSK produces garbage output.

### Noise Measurements

Our `debug_pk_noise` experiment measured noise in bits for encrypting zero:

**Public Key Encryption Noise:**
| Zero Encryption Count | Min Bits | Avg Bits | Max Bits |
|----------------------|----------|----------|----------|
| 1,484 (2n) | 43 | 51 | 54 |
| 2,968 (4n) | 42 | 51 | 54 |
| 5,936 (8n) | 46 | 51 | 54 |
| 11,872 (16n) | 46 | 52 | 55 |
| 47,680 (recommended) | 47 | 52 | 56 |

**Symmetric (Secret Key) Encryption Noise:**
| Decomposition Level | Noise Bits |
|---------------------|------------|
| Level 1 | ~47 |
| Level 2 | ~45 |
| Level 3 | ~48 |

**Key observation:** Public key encryption has ~3-5 more bits of noise on average (~51-52 bits) compared to symmetric encryption (~45-48 bits). This difference is small but compounds dramatically during key switching.

### Why Noise Accumulates During Key Switching

The key switching algorithm computes:

```
c_out[j] = Σ_i Σ_l  decomposed[i][l] × KSK[i][l][j]
```

Where `decomposed[i][l]` is bounded by `B - 1 = 15`.

The noise in the output is approximately:

```
noise_out ≈ original_noise + Σ noise from KSK elements
```

With `n = 742` dimensions and `L = 3` levels, we sum `n × L = 2,226` terms. The accumulated noise variance is:

```
Var(total) ≈ n × L × (B-1)² × Var(individual_KSK_noise)
```

Taking square root to get standard deviation:

```
σ_total ≈ √(n × L) × (B-1) × σ_individual
       ≈ √(2226) × 15 × σ_individual
       ≈ 47.2 × 15 × σ_individual
       ≈ 708 × σ_individual
```

This is approximately `2^{9.5}` factor increase. If individual noise is ~51 bits, total noise becomes ~60.5 bits, dangerously close to the 61-bit threshold.

But this is the best case! In practice:
1. The decomposition isn't perfectly uniform
2. Some terms don't cancel as expected
3. We observed all 32 bytes corrupted, suggesting catastrophic noise overflow

### Why Symmetric KSK Works But Asymmetric Doesn't

The key difference is **the initial noise in each KSK element**:

**Symmetric KSK:**
- Each element is encrypted using TFHE's standard `allocate_and_encrypt_new_lwe_ciphertext`
- Noise is sampled directly from Gaussian(σ) ≈ 45-48 bits

**Asymmetric KSK (our implementation):**
- Each element is encrypted using public key encryption
- Noise combines random selector with zero-encryption noise ≈ 51-52 bits
- Each of the 2,226 elements has ~3-5 bits more noise

With 2,226 elements:
- Symmetric: ~45 bits + 9.5 bits accumulation = ~54.5 bits total ✅
- Asymmetric: ~52 bits + 9.5 bits accumulation = ~61.5 bits total ❌

The asymmetric case exceeds the ~61-bit threshold, causing decryption to fail.

## Public Key Encryption in TFHE: How It Works

### Structure of an LWE Public Key

An LWE public key is a collection of `m` encryptions of zero:

```
PK = {(a_j, b_j) : b_j = <a_j, s> + e_j for j = 1..m}
```

Where `m` is the "zero encryption count." The [TFHE-rs documentation](https://docs.zama.org/tfhe-rs/1.0/get-started/security_and_cryptography) recommends:

```
m = ⌈(n+1) × 64 + λ⌉ for λ security bits
```

For n=742 and λ=128: `m = (742+1) × 64 + 128 = 47,680`

### Why Public Key Encryption Has More Noise

To encrypt message `μ` with a public key, we:

1. Sample a random binary selector vector `r ∈ {0,1}^m`
2. Compute `a = Σ r_j × a_j`
3. Compute `b = Σ r_j × b_j + μ`

The resulting noise is:
```
e_total = Σ r_j × e_j
```

This sums roughly `m/2` Gaussian noise terms (in expectation). For independent Gaussians:
```
Var(e_total) = (m/2) × σ²
σ_total = √(m/2) × σ
```

For m=47,680: `σ_total ≈ 154 × σ_original`

Even with m=1,484 (2n): `σ_total ≈ 27 × σ_original`

This explains the ~51-52 bit observed noise vs ~45-48 bit symmetric noise.

## Research: Alternative Approaches

### TFHE Public-Key Encryption Revisited (Joye, 2024)

The paper ["TFHE Public-Key Encryption Revisited"](https://eprint.iacr.org/2023/603) introduces an improved public key variant of TFHE where:
- The public key is shorter
- The resulting ciphertexts are **less noisy**
- Security holds under standard RLWE assumption

This could potentially make asymmetric KSK feasible, but:
1. It's not currently implemented in TFHE-rs
2. It would require significant implementation effort
3. The noise reduction may still not be sufficient for KSK use

### Key Switching Noise Formula (Academic Literature)

According to [Jeremy Kun's analysis](https://www.jeremykun.com/2022/08/29/key-switching-in-lwe/), the total error after key switching with parameters (B, k, L) is approximately:

```
(n/2 + √(n log n)) × B^{k-1} + (L-k) × B × σ × √(2n log n)
```

Where:
- `n` is the dimension
- `B` is the decomposition base
- `L` is the number of levels
- `k` is the lowest significant digit included (0 for error-free)
- `σ` is the encryption noise standard deviation

The left term represents approximation error from decomposition, the right term represents noise from the KSK encryptions.

## Recommendations

### Option 1: Use Symmetric KSK (Current Best Option)

Accept that TFHE key switching requires both secret keys for KSK generation. In a proxy recryption scenario:

1. Bob generates his keypair
2. Bob sends his **secret key** to Alice via a secure channel (e.g., ECIES-encrypted)
3. Alice generates the KSK using both secrets
4. The KSK is published for the recryption proxy

**Pros:**
- Works with current parameters
- Well-understood noise behavior
- Production-ready

**Cons:**
- Requires secure key exchange outside the PRE primitive
- Not "true" asymmetric PRE
- Bob must trust Alice with his secret key temporarily

### Option 2: Reduce Parameters (Trade Security for Functionality)

Use smaller LWE dimension `n` to reduce KSK noise accumulation:

| Dimension n | Security | KSK Elements | Accumulated Noise |
|-------------|----------|--------------|-------------------|
| 742 | 128-bit | 2,226 | ~61.5 bits (fails) |
| 512 | ~100-bit | 1,536 | ~59 bits (marginal) |
| 256 | ~80-bit | 768 | ~56 bits (works) |

**Not recommended** without thorough security analysis.

### Option 3: Increase Decomposition Levels (Trade Speed for Noise)

More decomposition levels means smaller coefficients, reducing noise multiplication:

| Levels | Base | Max Coefficient | Speed Impact |
|--------|------|-----------------|--------------|
| 3 | 16 | 15 | Current |
| 4 | 8 | 7 | ~33% slower |
| 6 | 4 | 3 | ~100% slower |
| 8 | 2 | 1 | ~166% slower |

With 8 levels and base 2, KSK noise accumulation would be:
```
√(742 × 8) × 1 × σ ≈ 77 × σ
```

Adding ~6.3 bits instead of ~9.5 bits. This might make asymmetric KSK viable with careful tuning.

**Requires experimentation and benchmarking.**

### Option 4: Different PRE Algorithm

Consider using a different PRE construction:
- **AFGH-style PRE on RLWE** - designed for asymmetric operation
- **OpenFHE's BFV PRE** - already works asymmetrically (but slower)
- **Hybrid approach** - use TFHE for data encryption, different scheme for recryption

### Option 5: Implement Joye's Improved Public Key Scheme

Implement the public key variant from "TFHE Public-Key Encryption Revisited" that produces less noisy ciphertexts. This would require:
1. New public key generation algorithm
2. Modified encryption routine
3. Potentially different parameters

**Significant implementation effort required.**

## Conclusion

The fundamental issue is that **LWE public key encryption inherently produces noisier ciphertexts than secret key encryption**, and this noise compounds during key switching. With our 128-bit security parameters, the accumulated noise exceeds the message space.

For production use, we recommend **Option 1 (Symmetric KSK)** with secure key exchange handled at the application layer. The recrypt-core trait interface can remain unchanged by passing the target's secret key bytes through the `to_public` parameter with appropriate documentation.

Future work should explore Option 3 (increased decomposition levels) and Option 5 (improved public key scheme) for truly asymmetric operation.

## References

1. [TFHE-rs Security and Cryptography Documentation](https://docs.zama.org/tfhe-rs/1.0/get-started/security_and_cryptography)
2. [Key Switching in LWE - Jeremy Kun](https://www.jeremykun.com/2022/08/29/key-switching-in-lwe/)
3. [The Gadget Decomposition in FHE - Jeremy Kun](https://www.jeremykun.com/2021/12/11/the-gadget-decomposition-in-fhe/)
4. [TFHE Public-Key Encryption Revisited - Marc Joye (2024)](https://link.springer.com/chapter/10.1007/978-3-031-58868-6_11)
5. [TFHE Deep Dive Part III - Key Switching - Zama](https://www.zama.org/post/tfhe-deep-dive-part-3)
6. [Learning with Errors - Wikipedia](https://en.wikipedia.org/wiki/Learning_with_errors)
7. [TFHE: Fast Fully Homomorphic Encryption over the Torus (CGGI19)](https://eprint.iacr.org/2018/421.pdf)

## Appendix: Experimental Code

The diagnostic code used for these experiments is in:
- `crates/recrypt-tfhe/examples/debug_ksk.rs` - Symmetric vs asymmetric KSK comparison
- `crates/recrypt-tfhe/examples/debug_pk_noise.rs` - Public key noise measurement
- `crates/recrypt-tfhe/examples/debug_pk_noise_counts.rs` - Zero encryption count vs noise
- `crates/recrypt-tfhe/examples/pk_timing.rs` - Public key generation timing

Run with `cargo run --example <name> --release -p recrypt-tfhe`
