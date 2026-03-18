# TFHE PRE Backend Spike: Takeaways & Learnings

**Date:** January 2026
**Status:** Spike complete — TFHE removed as a PRE backend option
**Conclusion:** TFHE key switching cannot serve as asymmetric proxy recryption at 128-bit security with current techniques

---

## What We Explored

We investigated replacing OpenFHE BFV with TFHE (via Zama's `tfhe-rs`) as the PRE backend. The hypothesis was that TFHE's key switching primitive — which transforms a ciphertext under key A into one under key B — could serve as proxy recryption with significant advantages:

- **10-100x faster recryption** (~10-50ms vs ~1-3s with OpenFHE BFV)
- **Pure Rust** (no C++ FFI, no complex build system)
- **Thread-safe** (no OpenFHE global state issues)
- **Post-quantum** (LWE-based, same security class as BFV)

The approach used multi-LWE encoding (128 LWE ciphertexts for a 32-byte symmetric key, 2-bit chunks each) with seeded keys for compact storage (~50KB recrypt keys vs ~35MB unseeded).

## What Worked

1. **Symmetric key switching works correctly.** When both Alice's and Bob's secret keys are available, KSK generation produces valid recryption keys. Encrypt-recrypt-decrypt roundtrips succeed, including multi-hop (Alice -> Bob -> Carol).

2. **The `PreBackend` trait integration was clean.** TFHE slotted into the existing pluggable backend architecture without friction.

3. **Performance estimates were confirmed.** Key generation and encryption operations were significantly faster than OpenFHE.

## What Failed: The Asymmetric KSK Problem

True proxy recryption requires generating a recryption key from Alice's **secret** key and Bob's **public** key only (asymmetric KSK). This is where TFHE breaks down.

### Root Cause: Noise Accumulation

LWE public-key encryption is inherently noisier than secret-key encryption. A public key is a collection of encryptions of zero; to encrypt, you sum a random subset, accumulating their noise terms:

| Encryption Method | Noise (bits) |
|-------------------|-------------|
| Secret-key (symmetric) | ~45-48 |
| Public-key (asymmetric) | ~51-52 |

This ~5-bit difference seems small, but it compounds catastrophically during key switching. A KSK contains `n × L = 742 × 3 = 2,226` encrypted elements. The noise accumulation factor is `√(n × L) × (B-1) ≈ 708×`:

| KSK Type | Per-element noise | + Accumulation (~9.5 bits) | vs. 61-bit threshold |
|----------|-------------------|---------------------------|---------------------|
| Symmetric | ~45-48 bits | ~54.5-57.5 bits | Safe |
| Asymmetric | ~51-52 bits | ~60.5-61.5 bits | Fails |

The asymmetric case exceeds or is right at the decryption threshold. In practice, all 32 bytes were corrupted in every test.

### Mitigations Considered (All Insufficient)

1. **Increase decomposition levels** (more levels = smaller coefficients = less noise multiplication): Helps but makes recryption slower, partially negating TFHE's speed advantage. May still not be enough.

2. **Reduce LWE dimension** (fewer KSK elements = less accumulation): Weakens security below 128-bit. Not acceptable.

3. **More zero encryptions in public key**: Tested 2n through 64n. No effect on noise magnitude — count affects security, not noise.

4. **Joye's improved public key scheme (2024 paper)**: Theoretically produces less noisy ciphertexts, but not implemented in `tfhe-rs` and would require significant custom cryptographic engineering with uncertain outcome.

5. **Accept symmetric KSK** (require Bob's secret key for recrypt key generation): Works cryptographically, but defeats the purpose of PRE. The whole point is that Alice shouldn't need Bob's secret key.

## Key Learnings

### 1. TFHE ≠ PRE

TFHE is designed for **homomorphic computation** (arbitrary programs on encrypted data). Key switching is an internal primitive used for bootstrapping, not a first-class PRE operation. Using it for PRE is using a side effect of the design, not the design itself.

OpenFHE's BFV scheme has **native PRE support** — the `ReEncrypt` operation is a designed, analyzed, documented feature of the scheme. This matters for both correctness and for future security analysis.

### 2. "Pure Rust" Isn't Worth Broken Cryptography

The biggest TFHE selling point was eliminating the C++ FFI. But a pure-Rust implementation that can't actually perform asymmetric recryption at target security levels is worse than a C++ FFI that works correctly. The OpenFHE build complexity is a one-time cost; broken crypto is forever.

### 3. Noise Budgets Are Unforgiving

In lattice-based crypto, noise is the fundamental constraint. Small differences in per-operation noise (5 bits here) can compound into catastrophic failure when operations are composed. This is not a bug to be fixed — it's a fundamental property of the construction.

### 4. Spike Methodology Worked Well

The phased approach (Phase 1: symmetric correctness, Phase 2: core integration, Phase 3: asymmetric KSK) caught the problem at exactly the right time. We had a working symmetric implementation to validate the approach before investing in the harder asymmetric case, and the noise analysis diagnostics (`debug_ksk.rs`, `debug_pk_noise.rs`) gave us clear quantitative evidence.

## Decision

**OpenFHE BFV remains the production PRE backend.** Its disadvantages (C++ FFI, global state, ~1-3s recryption) are real but manageable. Its advantage — native, analyzed, working asymmetric PRE — is fundamental.

If a pure-Rust post-quantum PRE backend becomes available in the future (e.g., if `tfhe-rs` adds native PRE support, or if an RLWE-based PRE crate emerges), it would be worth revisiting. The `PreBackend` trait makes swapping backends straightforward.

## Archived Materials

The following research documents from this spike are preserved in `docs/archive/`:
- `tfhe-pre-spike-takeaways.md` — this document
- `tfhe-pre-research.md` — original research report (multi-LWE encoding, seeded keys, security model)
- `tfhe-noise-analysis.md` — detailed noise measurements and mathematical analysis
- `tfhe-pre-backend-plan.md` — implementation plan (3 phases)

## References

1. [Zama tfhe-rs](https://github.com/zama-ai/tfhe-rs) — Production Rust TFHE
2. [rs-tfhe proxy_reenc.rs](https://github.com/thedonutfactory/rs-tfhe/blob/main/src/proxy_reenc.rs) — Reference PRE implementation (uses floats, not production-safe)
3. [TFHE Public-Key Encryption Revisited (Joye, 2024)](https://link.springer.com/chapter/10.1007/978-3-031-58868-6_11) — Improved public key variant (not implemented)
4. [Key Switching in LWE - Jeremy Kun](https://www.jeremykun.com/2022/08/29/key-switching-in-lwe/) — Noise analysis reference
5. [TFHE Deep Dive Part III - Key Switching - Zama](https://www.zama.org/post/tfhe-deep-dive-part-3)
