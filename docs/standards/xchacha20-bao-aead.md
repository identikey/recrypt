# XChaCha20-Bao: A Streaming AEAD Construction

**Status:** Draft v0
**Date:** 2026-04-08
**Authors:** Duke Jones (recrypt project)
**Reviewers needed:** RWOT / Blockchain Commons cryptography reviewers
**Related:** [verification architecture](../verification-architecture.md), [wire protocol](../wire-protocol.md)

## Abstract

This document specifies **XChaCha20-Bao**, an authenticated encryption
construction that pairs the XChaCha20 stream cipher (RFC 7539 / draft-irtf-cfrg-xchacha)
with Bao tree-mode hashing (Blake3 with verified-streaming structure).
It is positioned as a sibling to the well-known XChaCha20-Poly1305
AEAD, offering equivalent confidentiality and integrity guarantees with
the additional property of **incremental verification**: a recipient
can verify and consume the ciphertext in chunks without first holding
the entire blob, and a sender can produce the ciphertext as a stream
without buffering the whole plaintext for tag computation.

The construction is *not* a new cryptographic primitive. It is a
documented composition of standardized primitives (XChaCha20, Blake3,
Bao) using a long-known and -trusted pattern (encrypt-then-MAC, where
"MAC" is replaced by a signed Merkle root over the ciphertext). This
document exists because the composition is useful enough to be worth
naming, and the security argument is short enough to be worth writing
down once so implementers don't have to rederive it.

## Status of this document

Draft v0. This is the initial write-up from the [recrypt](https://github.com/identikey/recrypt) project where the construction
is in production use as the bulk-encryption layer underneath
post-quantum proxy recryption. We intend to circulate this document
for review through Rebooting Web of Trust and Blockchain Commons
channels before considering it stable. **Do not adopt this construction
on the basis of this draft alone** without independent review.

The recrypt implementation lives in [`crates/recrypt-core/src/hybrid/mod.rs`](../crates/recrypt-core/src/hybrid/mod.rs)
and serves as the reference implementation pending wider review.

## 1. Motivation

### 1.1 What XChaCha20-Poly1305 gives us

`XChaCha20-Poly1305` (RFC 8439 §2.8 / RFC 7905) is the de-facto modern
AEAD: 256-bit key, 192-bit nonce (large enough for safe random
generation without coordination), 128-bit Poly1305 tag, very fast on
all common hardware. It's the right choice for messages that fit in
memory and are produced and consumed atomically.

### 1.2 What it doesn't give us

XChaCha20-Poly1305 is **single-shot**. The Poly1305 tag is computed
over the entire ciphertext, and the receiver cannot validate any byte
of plaintext until they have received and processed the final tag
byte. This has three concrete consequences for systems handling
non-trivial blobs:

1. **No incremental verification.** A 10 GB encrypted file cannot be
   streamed to disk while verifying — you either buffer the whole
   thing in RAM (untenable), write unverified plaintext and hope
   (unsafe), or build an ad hoc chunking layer on top.

2. **No random access verification.** Reading byte 9 GB of a 10 GB
   blob requires reading all 10 GB to verify the tag.

3. **No proof-of-content for slices.** A storage proxy cannot prove
   to a client "here is byte range [N, M)" without the client
   downloading the entire blob to verify.

The standard workarounds (CBC of small AEAD chunks; Tink's
streaming AEAD; Nonce-misuse-resistant constructions like AES-GCM-SIV
chunked) all reinvent the same wheel: **a Merkle hash over chunks of
ciphertext, plus per-chunk authenticated decryption**. They work,
but each is slightly different, and most of them weren't designed
with verified streaming as the central feature.

### 1.3 What Bao gives us, for free

[Bao](https://github.com/oconnor663/bao) is a standardized verified
streaming format built on top of [Blake3](https://github.com/BLAKE3-team/BLAKE3-specs).
Blake3 is internally a Merkle tree over 1 KiB chunks; Bao formalizes
this so that:

- A producer can hash a stream once and emit a 32-byte root hash
  plus an "outboard" Merkle tree (~1/128 of the data size).
- A consumer with the root hash and the outboard can stream the
  data and verify each chunk against the tree before consuming it.
- A consumer can request and verify any byte range using a slice
  proof (logarithmic in the data size).
- The Blake3/Bao construction is approximately as fast as
  unauthenticated reads on modern hardware (SIMD-vectorized).

Bao is a hash construction, not an AEAD. It provides integrity over
*public* data — exactly the role Poly1305 plays in
ChaCha20-Poly1305, but with a tree structure instead of a single
tag.

### 1.4 The composition

If we encrypt with XChaCha20 (a stream cipher with no built-in
authentication) and then hash the resulting ciphertext with Bao (a
keyless integrity construction), and then sign the Bao root with the
producer's signing key, we get:

- Confidentiality from XChaCha20 (equivalent to XChaCha20-Poly1305).
- Integrity from `Sign(BaoRoot(ciphertext))` — equivalent in strength
  to Poly1305's tag, but covering the entire ciphertext via a Merkle
  tree.
- **Streaming verification, random access, and slice proofs**, all
  at the chunk-group granularity (16 KiB in the recrypt
  implementation; tunable).

This is the encrypt-then-MAC paradigm, with the MAC replaced by a
"hash-then-sign" structure. It is not novel, but it deserves to be
named so people stop reinventing it.

We call this construction **XChaCha20-Bao**.

## 2. Specification

### 2.1 Notation

- `||` denotes concatenation.
- `len(x)` is the length of `x` in bytes.
- `KeyGen()` produces a random 32-byte symmetric key.
- `NonceGen()` produces a random 24-byte XChaCha20 nonce.
- `Sign(sk, m)` is a digital signature over message `m` under
  signing key `sk`.
- `Verify(pk, m, σ)` returns true iff `σ` is a valid signature on
  `m` under verification key `pk`.

### 2.2 Inputs

- A 256-bit symmetric key `K`.
- A 192-bit nonce `N` (24 bytes), unique per message under a given
  key (the standard XChaCha20 nonce uniqueness requirement).
- Plaintext `P` of length 0 ≤ |P| < 2^40 bytes (recrypt enforces a
  1 TiB limit; the construction itself has the XChaCha20 stream
  limit of 2^64 - 1 bytes).
- A signing keypair `(sk, pk)` from any signature scheme. recrypt
  uses Ed25519 + ML-DSA-87 hybrid; this construction is agnostic.

### 2.3 Encryption

```
function XChaCha20Bao_Encrypt(K, N, P, sk):
    1. C ← XChaCha20(K, N, P)               // bulk cipher, no auth tag
    2. (root, outboard) ← BaoTree(C)        // Blake3-tree-mode over C
    3. σ ← Sign(sk, root)                   // sign the root
    4. return (C, root, outboard, σ)
```

`BaoTree(C)` is the Bao "outboard mode" hash function, parameterized
by a chunk group size. recrypt uses 16 KiB chunk groups
(`BlockSize::from_chunk_log(4)` in `bao-tree` 0.16). The exact chunk
size is tunable; it affects the size of the outboard
(approximately `len(C) / 128` for the default 1 KiB chunks; smaller
for larger chunk groups) and the granularity of partial verification.

The outputs are:

- `C` — the encrypted bytes, same length as `P`.
- `root` — 32-byte Blake3/Bao root hash. This is the "tag."
- `outboard` — the Merkle tree of inner Blake3 hashes (excluding
  the root, which is `root`). Size is ~1/128 of `len(C)` for
  default chunks; ~1/2048 for 16 KiB chunk groups.
- `σ` — the signature over `root`.

For files smaller than a single chunk group (16 KiB in recrypt's
configuration), the outboard is empty and `root = blake3(C)`. This
is a valid optimization because there are no parent nodes — the
tree degenerates to a single leaf.

### 2.4 Decryption / verification

```
function XChaCha20Bao_Decrypt(K, N, C, root, outboard, σ, pk):
    1. if not Verify(pk, root, σ): return AuthFailure
    2. if not BaoVerify(C, root, outboard): return IntegrityFailure
    3. P ← XChaCha20(K, N, C)               // stream cipher decrypt
    4. return P
```

`BaoVerify` walks the chunk groups of `C` against the outboard tree,
recomputing each leaf's Blake3 hash and parent nodes upward, and
asserts that the recomputed root equals the trusted `root`. This can
be done in a streaming fashion: each chunk group is verified
**before** its plaintext is exposed to downstream consumers.

The verification ordering is critical: **verify the signature on the
root before doing any work with the outboard or ciphertext.** This
prevents an attacker from feeding crafted outboards to a verifier
that hasn't yet authenticated the root.

### 2.5 Streaming verification

The advantage of this construction is that step 2 of decryption can
be interleaved with step 3:

```
function XChaCha20Bao_DecryptStream(K, N, C_stream, root, outboard, σ, pk):
    1. if not Verify(pk, root, σ): return AuthFailure
    2. for each chunk_group cg in C_stream:
        a. if not BaoVerifyChunkGroup(cg, outboard, root):
             return IntegrityFailure
        b. P_cg ← XChaCha20(K, N, cg, offset=cg.offset)
        c. yield P_cg
```

Each chunk group is verified before its plaintext is yielded. A
tampered byte is detected within the chunk group containing it
(at most 16 KiB of unverified work) before any plaintext from a
subsequent chunk group is exposed. No plaintext is *ever* yielded
from a chunk group whose hash doesn't match the tree.

XChaCha20's stream cipher property means we can decrypt at any
offset using `XChaCha20(K, N, ·, offset)` without touching prior
bytes. This is what makes random access work.

### 2.6 Slice proofs

Bao's slice format (specified in the [Bao spec](https://github.com/oconnor663/bao/blob/master/docs/spec.md))
allows a producer or holder of the ciphertext to emit a proof for
a contiguous byte range `[lo, hi)` consisting of:

- The ciphertext bytes for the range.
- A logarithmic number of intermediate Blake3 nodes that, combined
  with the chunk hashes, recompute to the root.

A verifier with the trusted `root` and `σ` can verify the slice
proof and decrypt the slice independently. This is the property
that lets a storage proxy serve byte ranges with cryptographic
proof of correctness, without holding the producer's signing key
and without forwarding the entire blob.

## 3. Security argument

### 3.1 Threat model

We consider an adversary who:

- Sees the ciphertext `C`, the root `root`, the outboard, and
  the signature `σ`.
- Controls the storage and transport of all of the above (can
  modify, reorder, replace).
- Does not have the symmetric key `K`, the signing key `sk`, nor
  the ability to query an encryption oracle for chosen plaintexts
  under `K`.

We claim:

1. **Confidentiality** of `P` against this adversary, equivalent to
   the IND-CPA security of XChaCha20.
2. **Integrity** of `(P, root)` against this adversary, equivalent
   to the EUF-CMA security of the underlying signature scheme,
   conditional on the collision resistance of Blake3.

### 3.2 Confidentiality

XChaCha20 is a stream cipher with a 256-bit key and a 192-bit nonce.
Its IND-CPA security reduces to the indistinguishability of the
ChaCha20 keystream from random under random key, which is the
standard assumption for ChaCha20 and is preserved by the XChaCha20
HChaCha20-based key/nonce derivation. The 192-bit nonce length means
random nonce generation is birthday-safe up to ~2^96 messages under
the same key, which is far beyond any practical workload.

The adversary sees `C = P ⊕ Stream(K, N)`. Without `K`, this
ciphertext is computationally indistinguishable from random, hence
reveals no information about `P` beyond its length. The other
emitted values (`root`, `outboard`, `σ`) are deterministic
functions of `C`, so they are also computationally independent of
`P` given `K`.

This is the same confidentiality argument as for
ChaCha20-Poly1305; the AEAD's authentication tag is replaced here
with a signed Merkle root, but neither construction's
confidentiality argument depends on the integrity layer.

### 3.3 Integrity

We argue that any PPT adversary's probability of producing a tuple
`(C', root', outboard', σ')` distinct from a legitimate
`(C, root, outboard, σ)` such that
`XChaCha20Bao_Decrypt(K, N, C', root', outboard', σ', pk)` succeeds
is bounded by `EUF-CMA-Adv(SigScheme) + Coll-Adv(Blake3)`.

**Case 1: `root' = root`.** Then the signature `σ'` must verify on
`root'` under `pk`, so either `σ' = σ` (in which case the only way
to vary the tuple is to vary `C'` or `outboard'`) or the adversary
has produced a new valid signature on the same message (a forgery
of strength EUF-CMA).

If `σ' = σ` and `root' = root`, then for `BaoVerify(C', root', outboard')`
to accept, the recomputed Blake3 root over `C'` walked against
`outboard'` must equal `root`. Since `root` is the Blake3/Bao hash
of the *original* `C`, this requires the adversary to find a
different `(C', outboard')` that hashes to the same root — a
collision in Blake3. Coll-Adv(Blake3) bounds this term.

**Case 2: `root' ≠ root`.** Then `σ'` must be a valid signature on
`root'`, a fresh message, under `pk`. The adversary has not
queried a signing oracle on `root'` (we assume the producer signs
each unique root at most once and never signs adversary-chosen
values), so this is a chosen-message-attack forgery.
EUF-CMA-Adv(SigScheme) bounds this term.

Sum of the two cases gives the total integrity bound. ∎

The above is informal but tracks the standard encrypt-then-MAC
argument with `MAC = Sign∘BaoRoot`. A formal treatment would model
Bao as a collision-resistant hash function (which Blake3 is
believed to be at the 128-bit collision security level for its
256-bit output) and the signature scheme as EUF-CMA-secure.

For recrypt's hybrid Ed25519+ML-DSA-87 multi-signature, the
EUF-CMA bound is the **minimum** of the two scheme bounds (an
adversary need only forge one to win — but recrypt's
all-must-verify rule means they need to forge both). Actually,
since recrypt requires both signatures to verify, the bound is the
**product** of the two, which is much smaller than either alone.

### 3.4 Comparison to XChaCha20-Poly1305

The security argument above is structurally identical to the
encrypt-then-MAC analysis of XChaCha20-Poly1305, with the
following substitutions:

| Role            | XChaCha20-Poly1305          | XChaCha20-Bao                 |
|---              |---                          |---                            |
| Confidentiality | XChaCha20                   | XChaCha20                     |
| Integrity tag   | Poly1305(K_mac, C)          | Sign(sk, BaoRoot(C))          |
| Tag derivation  | Subkey from K via XChaCha20 | Producer's signing key (any scheme) |
| Tag size        | 16 bytes                    | 32 bytes (root) + sig size    |
| Streaming verify | No                         | Yes (chunk-group granularity) |
| Random access   | No                          | Yes                           |
| Slice proofs    | No                          | Yes (Bao slice format)        |

The integrity story is **stronger**, not weaker, because the
signing key need not be derived from the symmetric key — it can
be a long-term identity key. This means a compromise of the
symmetric key does not let an attacker forge new ciphertexts
that verify under the producer's identity. In recrypt this matters
a lot: the symmetric key is recoverable by any recipient who is
granted access, but the originator's signature continues to bind
the ciphertext to its origin.

### 3.5 Non-malleability and the role of the signature

It is important to be precise: in this construction, the
authenticator is a **signature**, not a MAC. Two consequences:

1. **Public verifiability.** Anyone with the producer's public
   key can verify the integrity of the ciphertext, not only the
   recipient who holds the symmetric key. This is sometimes a
   feature (audit trails, third-party verification, gossip-based
   replication) and sometimes irrelevant.

2. **The encryption is not "deniable" in the way Poly1305-based
   AEADs are.** If the producer signs a ciphertext, a third party
   can prove the producer did so. For a system like recrypt where
   non-repudiation is wanted, this is the right behavior. For
   systems wanting deniable authentication, replace `Sign` with
   a designated-verifier MAC (e.g., HMAC with a key known to both
   parties) and the analysis goes through unchanged with EUF-CMA
   replaced by SUF-CMA of the MAC.

The construction is parameterized over the authenticator. We
specify `Sign` as the default because it matches recrypt's
threat model.

## 4. Concrete parameters

### 4.1 Recrypt's choices

| Parameter         | Value                      | Rationale                            |
|---                |---                         |---                                    |
| Cipher            | XChaCha20                   | Standard, fast, 192-bit nonce safe for random gen |
| Key length        | 256 bits                    | Standard                              |
| Nonce length      | 192 bits                    | XChaCha20 native; birthday-safe random |
| Hash              | Blake3 (Bao tree mode)      | Fast, standardized, tree-friendly     |
| Root size         | 256 bits                    | Blake3 default                        |
| Chunk group size  | 16 KiB (`chunk_log = 4`)    | Balances outboard size vs verification granularity |
| Signature scheme  | Ed25519 + ML-DSA-87 hybrid  | Recrypt's multi-sig invariant         |

The 16 KiB chunk group size is a recrypt choice, not a property of
the construction. Larger chunk groups produce smaller outboards and
faster Bao computation but coarser verification granularity (a
tampered byte poisons up to 16 KiB of plaintext that has been
verified-as-a-group but cannot be partially yielded). 16 KiB is
small enough to fit in L1 cache on modern CPUs and large enough that
the outboard is ~1/2048 of the ciphertext.

### 4.2 Sizing

For a plaintext of size *N* bytes:

- Ciphertext: *N* bytes (no expansion).
- Bao outboard: ≈ *N* / 2048 bytes for 16 KiB chunk groups (zero
  for *N* ≤ 16 KiB).
- Bao root: 32 bytes.
- Signature: depends on scheme. Ed25519 = 64 bytes. ML-DSA-87 = 4627
  bytes. Recrypt's hybrid = ~4691 bytes total.

Compared to XChaCha20-Poly1305 with the same plaintext: the AEAD has
*N* + 16 bytes of ciphertext+tag. XChaCha20-Bao has *N* + 32 bytes
(root) + sig + outboard. For a 1 MB file with the recrypt hybrid
sig: ~1 MB + 32 + 4691 + 512 ≈ 1 MB + 5.2 KB. The overhead is
< 1% for files larger than 1 MB and dominated by the post-quantum
signature, not the Bao structure.

For files smaller than 16 KiB, the outboard is empty and the
overhead is exactly the root (32 bytes) plus the signature.

### 4.3 Reference implementation

The recrypt project's reference implementation lives in
[`crates/recrypt-core/src/hybrid/mod.rs`](../crates/recrypt-core/src/hybrid/mod.rs). It uses:

- [`chacha20`](https://crates.io/crates/chacha20) crate for XChaCha20 (`XChaCha20::new(key, nonce)` + `apply_keystream`)
- [`bao-tree`](https://crates.io/crates/bao-tree) 0.16 for Bao
  (`outboard_post_order`, `BaoTree::new`, `ResponseDecoder` for
  streaming verification)
- [`blake3`](https://crates.io/crates/blake3) directly for the
  small-file optimization (`blake3::hash` is `BaoRoot` for files
  smaller than one chunk group)

The streaming encrypt path uses `bao_tree::io::fsm::outboard_post_order`
which is async and avoids `spawn_blocking`. The streaming decrypt
path uses `PostOrderMemOutboard` reconstructed from the trusted root
and the producer's outboard, walked chunk-by-chunk via
`ResponseDecoder`, which yields verified plaintext to the consumer.

## 5. Test vectors

**TODO before stable.** The vectors below are placeholders showing the
shape; they need to be generated against the reference implementation
and confirmed reproducible by an independent implementer before this
document leaves draft.

### Vector 1: Empty plaintext

```
key:        0000000000000000000000000000000000000000000000000000000000000000
nonce:      000000000000000000000000000000000000000000000000
plaintext:  (empty)

ciphertext: (empty)
bao_root:   af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262   ; blake3("")
outboard:   (empty)
```

### Vector 2: One-byte plaintext

```
key:        0000000000000000000000000000000000000000000000000000000000000000
nonce:      000000000000000000000000000000000000000000000000
plaintext:  61                                                                   ; "a"

ciphertext: TODO
bao_root:   TODO
outboard:   (empty)
```

### Vector 3: 16 KiB + 1 byte plaintext (forces a multi-chunk-group outboard)

```
key:        TODO
nonce:      TODO
plaintext:  TODO (16385 bytes)

ciphertext: TODO
bao_root:   TODO
outboard:   TODO (non-empty)
```

### Vector 4: 1 MB plaintext (typical file)

```
key:        TODO
nonce:      TODO
plaintext:  TODO

ciphertext: TODO
bao_root:   TODO
outboard:   TODO (~512 bytes)
```

### Vector 5: Slice proof for byte range [16384, 32768) of vector 4

```
slice_lo:   16384
slice_hi:   32768
proof:      TODO
```

A reproducer script in the recrypt repo's test suite generates and
asserts these vectors. Implementers should be able to run an
independent script and produce byte-identical outputs from the
specified inputs.

## 6. Comparison to alternatives

### 6.1 vs. AES-GCM-streaming / Tink Streaming AEAD

Tink's streaming AEAD wraps AES-GCM in a chunked construction with a
per-chunk header carrying segment number and final-segment flag. It
provides streaming verification at chunk granularity. Differences
from XChaCha20-Bao:

- Tink streaming AEAD does not produce a single short authenticator
  for the whole stream — verification requires walking all chunks.
  XChaCha20-Bao's signed root is a constant-size authenticator
  regardless of file size.
- Tink streaming AEAD does not support efficient random access — to
  verify byte N you must verify all chunks before it. Bao supports
  logarithmic-size slice proofs.
- Tink streaming AEAD uses AES; XChaCha20-Bao uses ChaCha20.
  Performance comparison is hardware-dependent; ChaCha20 wins on
  most non-AES-NI hardware.

### 6.2 vs. age / minisign

age's encryption format is a chunked ChaCha20-Poly1305 with a header.
It provides streaming decryption but not random access or slice
proofs, and the integrity authenticator is a series of per-chunk
Poly1305 tags rather than a Merkle tree.

minisign signs files; it does not encrypt them.

Neither directly supports the proxy-storage use case where a third
party serves verified byte ranges without holding any decryption
material.

### 6.3 vs. building Merkle-of-AEAD-chunks yourself

You can construct an "AEAD chunks under a Merkle tree of tags"
scheme by hand. Many systems do. The disadvantages are:

- Each implementation reinvents the wheel slightly differently and
  the wire formats don't interop.
- The MAC keys for each chunk must be derived from the master key
  in a way that prevents reuse and replay — easy to get wrong.
- The Merkle tree structure is usually ad hoc, not standardized,
  and lacks the slice-proof format Bao gives you.

XChaCha20-Bao reuses standardized building blocks (XChaCha20,
Blake3, Bao tree mode) and inherits their properties.

## 7. Open questions and known limitations

1. **No formal proof.** The integrity argument in §3.3 is informal.
   A formal proof in the standard model would strengthen the case
   for adoption. Independent cryptographic review is the highest
   priority for this document.

2. **Nonce uniqueness still required.** Despite the streaming
   property, XChaCha20 still requires nonces to be unique under a
   given key. The 192-bit nonce means random generation is
   birthday-safe past any practical threshold, but implementers
   must still draw fresh nonces per message and not reuse them.

3. **Signature scheme is a parameter, not a fixed choice.** Recrypt
   uses Ed25519 + ML-DSA-87 because of its specific threat model
   (defense in depth + Ed25519 as identity primitive). Other
   adopters may want different schemes. The construction is
   agnostic; the security bound depends on the chosen scheme's
   EUF-CMA security.

4. **Non-deniability.** As noted in §3.5, the use of a signature
   rather than a MAC means producers cannot deny having produced
   a given ciphertext. Designated-verifier or MAC-based variants
   are easy to specify if deniability is wanted; we have not done
   so here because recrypt does not need it.

5. **Outboard size for very large files.** A 1 TiB file with 16 KiB
   chunk groups produces a ~512 MB outboard. For files this large,
   the outboard should be stored in chunks alongside the
   ciphertext rather than held in memory. The recrypt
   implementation uses an in-memory outboard and documents a 1 TiB
   limit accordingly. A streaming-outboard variant is implementable
   but not specified here.

6. **Chunk group size as a wire-format parameter.** This document
   uses 16 KiB as the recrypt default but does not mandate it. If
   XChaCha20-Bao becomes a standardized format, the chunk group
   size needs to be either fixed or carried explicitly in any
   wire format that pairs ciphertext with outboard. Recrypt
   carries it implicitly (the bao-tree library encodes it in
   the outboard structure).

## 8. Naming

We propose **XChaCha20-Bao** as the canonical name. Variants:

- **XChaCha20-Bao-Sign** when the authenticator is a signature
  (the default; what recrypt uses).
- **XChaCha20-Bao-MAC** when the authenticator is a MAC keyed by a
  key shared between sender and receiver.
- **ChaCha20-Bao** if the underlying cipher is ChaCha20 (96-bit
  nonce) instead of XChaCha20. Same construction; nonce-uniqueness
  story is harder.

## 9. References

- RFC 8439: ChaCha20 and Poly1305 for IETF Protocols
- draft-irtf-cfrg-xchacha: XChaCha20 and XChaCha20-Poly1305
- [BLAKE3 specification](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf)
- [Bao specification](https://github.com/oconnor663/bao/blob/master/docs/spec.md)
- [`bao-tree`](https://docs.rs/bao-tree/) Rust crate documentation
- [Recrypt project](../../README.md) — reference implementation context
- [Recrypt verification architecture](../verification-architecture.md)

## Appendix A: Why not just sign the plaintext?

A reader familiar with signed-document systems might ask: "Why not
hash and sign the plaintext directly, then encrypt the plaintext for
confidentiality?" That gives confidentiality + integrity + non-
repudiation in three lines.

Answer: it gives those properties, but loses streaming verification
and slice proofs. To verify a byte range, you'd need to either:
(a) decrypt the entire file to reach the plaintext bytes the
signature covers, or (b) sign chunks individually and walk a Merkle
tree of chunk hashes — at which point you're inventing this
construction badly.

XChaCha20-Bao signs the *ciphertext root*, not the plaintext. This
lets the producer's outboard tree be walked over the ciphertext as
it streams in, with no decryption needed for verification. The
plaintext hash, if needed for a separate purpose (recrypt carries
one inside its `KeyMaterial` bundle, encrypted by the PRE layer),
is a separate concern.

## Appendix B: Why post-order outboard?

Bao supports two outboard layouts: pre-order and post-order. Recrypt
uses post-order because:

1. Post-order can be computed in a single forward pass over the
   ciphertext, with the writer of the outboard not needing to seek
   backward. This matches the streaming-encryption use case.
2. Post-order is the format `bao-tree` produces by default with
   `outboard_post_order`.
3. Post-order is what `ResponseDecoder` consumes for streaming
   verification.

Pre-order has slightly nicer properties for random-access *reads*
of the outboard (you walk down the tree in order), but for
recrypt's workload — produce once, verify often, stream the
ciphertext — post-order is the better fit.

---

*This document is a draft. Comments, corrections, and reviews welcome.
Send to: TODO contact info, or open an issue against the recrypt
repository when public.*
