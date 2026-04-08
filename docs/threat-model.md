# Recrypt Threat Model (Stub)

> **Status:** Stub. This document exists to capture the shape of the threat
> model so a disciplined pass can be done before the Phase 9 security audit.
> Sections marked **TODO** need to be filled in. Sections marked **DRAFT** are
> reasoned first passes that still need adversarial review.

---

## 0. Product framing

Recrypt's distinguishing product is **fine-grained, revocable group sharing
without a trusted server** — "Signal meets Dropbox". The threat model has
to make sense in that context, so a quick framing:

- A user encrypts a file once to their own public key.
- Sharing with another user means generating a recrypt key (client-side,
  using the sharer's secret key and the recipient's public key) and
  uploading it to the recryption proxy. The recrypt key is a
  transformation key, not a decryption key — see Adv-P in §4 for details.
- The proxy transforms the ~1 KB `wrapped_key` on demand when the
  recipient requests the file. The ~1 GB ciphertext passes through
  byte-for-byte and is verified client-side against a signed BLAKE3
  Merkle tree root.
- **Revocation is a DELETE** at the proxy. The recrypt key goes away; the
  proxy can no longer produce a wrapped key the revoked user can decrypt.
  No bulk re-encryption required. This is the central operational
  property that proxy recryption gives us over every "encrypt once per
  recipient" scheme.
- Groups scale as O(1) in bulk data (one ciphertext, one outboard,
  independent of group size) and O(N) only in small recrypt keys stored
  at the proxy.

This framing is the *reason* each of the adversary models below matters
the way it does. A compromised proxy is a big deal because the proxy is
what group sharing runs through. An untrusted storage provider is
expected because the design target is "no trusted cloud".

## 1. System-in-scope

Recrypt is a quantum-resistant proxy recryption system for secure, revocable
file sharing with untrusted storage providers. The components in scope for
this threat model are:

- **`recrypt-cli`** — local key management, encryption, decryption, HTTP client
- **`recrypt-server`** — recryption proxy, HTTP API, share policy storage
- **`recrypt-storage`** — content-addressed blob storage backends (S3, local)
- **`identikey-storage-auth`** — ownership and capability tracking
- **`recrypt-core` / `recrypt-proto` / `recrypt-ffi`** — crypto primitives and
  wire format used by the above

Explicitly **out of scope**:

- The physical security of the user's device
- The security of the OS keyring implementation on each platform
- Side-channel attacks against OpenFHE / liboqs / ed25519-dalek (we inherit
  their posture)
- Network-level DoS against the proxy (mitigated at deploy time via reverse
  proxy / WAF, not in application code)

---

## 2. Assets (DRAFT)

| ID   | Asset                              | Where it lives                                  | Confidentiality | Integrity | Availability |
| ---- | ---------------------------------- | ------------------------------------------------ | :-------------: | :-------: | :----------: |
| A1   | User plaintext                     | CLI process memory during ops; encrypted at rest |       ●         |     ●     |      ○       |
| A2   | User PRE secret key                | Wallet file + OS keyring cache                   |       ●         |     ●     |      ●       |
| A3   | User ED25519 secret key            | Wallet file + OS keyring cache                   |       ●         |     ●     |      ●       |
| A4   | User ML-DSA-87 secret key          | Wallet file + OS keyring cache                   |       ●         |     ●     |      ●       |
| A5   | Recryption keys `rk(Alice→Bob)`    | Server in-memory store                          |       ○         |     ●     |      ●       |
| A6   | File ciphertexts (`EncryptedFile`) | `ChunkStorage` (S3/local), server pass-through  |       ○         |     ●     |      ●       |
| A7   | Ownership records                  | `OwnershipStore` (SQLite or in-memory)          |       ○         |     ●     |      ●       |
| A8   | Share policies                     | Server in-memory store                          |       ◐         |     ●     |      ●       |
| A9   | Wallet password                    | User memory / env var `RECRYPT_WALLET_PASSWORD` |       ●         |     ●     |      ○       |
| A10  | Nonces / replay window             | Server in-memory `NonceStore`                   |       ○         |     ●     |      ●       |

Legend: ● high, ◐ medium, ○ low.

**Note on A5 classification:** recryption keys are **low confidentiality**.
A recrypt key `rk(Alice → Bob)` leaks nothing about plaintext, nothing
about Alice's or Bob's secret keys (unidirectionality property of BFV PRE),
and nothing about the contents of any ciphertext Alice has encrypted. It
does grant, for its lifetime, the ability to transform Alice's ciphertexts
into ones Bob can decrypt — but only if both the source ciphertext and a
way to deliver the output to Bob exist, both of which are already covered
by other controls (access control on `/files/{hash}`, signed download
requests at `/recryption/share/{id}/file`). Losing a recrypt key to an
attacker who cannot also breach those controls gains them nothing.

---

## 3. Trust boundaries (DRAFT)

```
   ┌──────────────────────── Client device (fully trusted) ──────────────────────┐
   │                                                                             │
   │    recrypt-cli ──────── wallet ──── OS keyring                              │
   │         │                                                                   │
   └─────────┼──────────── TLS (reverse proxy) ────────────────────────────────── ┘
             │
   ┌─────────┼──────── Recryption proxy (semi-trusted) ─────────────────────────┐
   │         ▼                                                                   │
   │    recrypt-server ─── identikey-storage-auth ─── SQLite                    │
   │         │                                                                   │
   │         ▼                                                                   │
   │    recrypt-storage (trait) ───────────────────────────────────────────────  │
   └──────────┼─────────────────────────────────────────────────────────────────┘
              │
   ┌──────────▼──────── Storage backend (untrusted) ─────────────────────────────┐
   │    S3 / Minio / local fs                                                    │
   └─────────────────────────────────────────────────────────────────────────────┘
```

### Boundary 1: Client ↔ Server
- **Transport:** HTTPS (TLS terminated at reverse proxy, out of recrypt's scope)
- **Authentication:** multi-signature (ED25519 + ML-DSA-87) over canonical
  action messages + nonce
- **What crosses:** public keys, recryption keys, ciphertexts, share metadata,
  multi-signatures. **Never:** secret keys, plaintext, wallet password.

### Boundary 2: Server ↔ Storage backend
- **Transport:** S3 protocol over TLS, or local filesystem
- **Authentication:** whatever the backend provides (IAM, static keys, fs
  permissions) — **not** enforced by recrypt itself
- **What crosses:** Blake3-hashed blobs. Every read is re-hashed (defense in
  depth).

### Boundary 3: User ↔ wallet / keyring
- **Transport:** local syscalls (file I/O, OS keyring API)
- **Authentication:** wallet password (Argon2id) on first unlock; cached
  derived key in OS keyring thereafter
- **What crosses:** user-typed password, derived key, key material

---

## 4. Adversary models (DRAFT)

### Adv-S: Malicious storage provider
**Capabilities:** read, modify, delete, reorder, return arbitrary content for
any blob; observe access patterns.

**Assumed unable to:** compromise the recryption proxy or the client; observe
TLS-encrypted traffic between proxy and itself beyond the S3 request/response
structure.

**Recrypt's defense:**
- Content addressing + Blake3 hash verification on every read (tamper detection)
- Semantic-security of XChaCha20 + PRE-wrapped KEM (confidentiality)
- Bao-hash signature inside `EncryptedFile.signature_payload` (integrity under
  authenticator's signing key)

**Residual risk:** storage provider can **delete** or **refuse to serve**
content (DoS / censorship). This is inherent to untrusted storage and not
cryptographically solvable.

**TODO:** Does the Bao outboard in `EncryptedFile` actually get verified during
download? Trace it end-to-end.

---

### Adv-P: Malicious / compromised recryption proxy

**What the proxy holds:**
- Recryption keys `rk(Alice → Bob)` for every active share. **These are
  transformation keys, not decryption keys.** A recrypt key enables the
  proxy to transform `Enc(pk_Alice, m)` into `Enc(pk_Bob, m)` without
  learning `m`, and without holding either party's secret key.
- Share policies (who shares what with whom, expiry, operations).
- Public keys and Blake3 file hashes.
- Access patterns and request metadata.

**What the proxy *cannot* do, cryptographically:**
- Decrypt `Enc(pk_Alice, m)` to recover `m`. No secret key, no decryption
  capability.
- Decrypt `Enc(pk_Bob, m)` either.
- Derive `sk_Alice` or `sk_Bob` from any recrypt key. Recrypt keys are
  one-way constructions from the delegator's secret key and the
  recipient's public key.
- Forge a new `rk(X → Y)` for pairs it doesn't have keys for — recrypt
  key generation requires `sk_X`, which lives only on the delegator's
  client.
- Collude with Bob to recover `sk_Alice`. This is the **unidirectionality
  property** of BFV proxy recryption: `rk(Alice → Bob)` gives Bob+proxy
  the ability to transform Alice's ciphertexts, but provably not to
  extract `sk_Alice`. (Transitivity in the other direction — can the
  collusion transform *arbitrary* Alice-encrypted ciphertexts Bob
  acquires? — is a known PRE limitation and is accepted in our model.)

**What the proxy *can* do (residual risks):**
- **Refuse service.** Availability attack. Unavoidable — the proxy is
  the one doing the transform.
- **Misdirect a recrypted output.** The cryptographic recrypt transform
  doesn't bind the recipient identity; the application layer does,
  via the `DOWNLOAD:{requester_fingerprint}:{share_id}:{nonce}` signed
  request that the proxy is trusted to verify before serving. A
  malicious proxy could serve a recrypted ciphertext to anyone who
  asks. **This is the policy-enforcement trust assumption.**
- **Leak metadata.** Who shares what with whom, when, and how often.
- **Selectively censor.** Refuse to serve specific requests.

**What "semi-trusted" means for the recryption proxy** (formal
statement):

> *The proxy is trusted to correctly enforce share access policies. It
> is not trusted with plaintext confidentiality: plaintext is
> cryptographically out of reach of the proxy, regardless of its
> behavior.*

Equivalently: the proxy's honesty affects *access control*, not
*confidentiality*. A fully malicious proxy can withhold access or
misdirect it, but cannot read user data.

**Path to a fully untrusted proxy (future work):** it is possible in
principle to make the recrypt transform bind to a live, signed request
from the intended recipient, such that the proxy's output is only
usable by that specific signer. This eliminates the misdirection risk
and leaves only availability and metadata as residual proxy
capabilities. Out of scope today; tracked as Phase 10+ research in
[plans/2026-04-06-bao-streaming-and-storage-simplification.md §11.5](plans/2026-04-06-bao-streaming-and-storage-simplification.md).

---

### Adv-N: Network adversary
**Capabilities:** passive + active on the network between client and proxy,
and between proxy and storage.

**Defense:** TLS at both legs (deploy concern), plus the application-level
multi-signature + nonce scheme, which does **not** depend on TLS for
authentication or replay protection.

**Residual risk:** traffic analysis is out of scope.

---

### Adv-C: Malicious client (authenticated user)
**Capabilities:** has a valid account, can mint valid multi-signatures, can
upload arbitrary content.

**Defense:**
- Cannot forge signatures for other users (ED25519 + ML-DSA unforgeability)
- Cannot read other users' files (ownership check on delete; download is
  currently public — **see TODO**)
- Cannot revoke other users' shares (`from_fingerprint` check)

**Residual risk / TODO:**
- Unauthenticated download endpoint (`GET /files/{hash}`) means any client
  who knows a file hash can download the ciphertext. This is safe if
  confidentiality is provided by the encryption itself, but leaks metadata
  (existence, size, access pattern) to anyone who guesses a hash.
- Storage quota / spam uploads — no rate limiting currently implemented.

---

### Adv-Q: Future quantum adversary
**Capabilities:** can break ED25519 and classical DH; cannot break ML-DSA-87
or the BFV lattice scheme.

**Defense:** dual-stack signatures (ED25519 **AND** ML-DSA-87 required) and
lattice-based PRE (post-quantum by design).

**Residual risk:** if the ML-DSA-87 assumption is ever broken, the ED25519
half buys us nothing against a quantum adversary — we rely entirely on the
post-quantum layer. This is a standard hybrid-signature assumption.

---

## 5. Cryptographic assumptions (DRAFT, TO VERIFY)

- **BFV semantic security** under the Ring-LWE assumption with OpenFHE's
  default parameters
- **Proxy recryption unidirectionality** (in BFV): a recryption key from A→B
  does not allow B→A
- **Collusion resistance** — TODO: what is the collusion model? Does
  Alice+proxy colluding reveal anything about Bob's secret key? (For BFV PRE
  the answer is "no" in the honest-but-curious proxy setting; we should
  state this explicitly.)
- **Blake3 collision resistance** (256-bit)
- **XChaCha20 IND-CPA** (we do not rely on Poly1305 for the DEM; integrity
  comes from Bao + the MultiSig)
- **ED25519 EUF-CMA** (classical)
- **ML-DSA-87 EUF-CMA** (post-quantum, NIST Level 5)
- **Argon2id** for password KDF with OWASP-recommended parameters

**TODO:** Each of these needs a line saying *how recrypt relies on it* —
what breaks if the assumption is broken.

---

## 5.5 Dependencies

Two additional cryptographic assumptions introduced in Phase 8:

1. **`bao-tree` integrity assumption** (new) — the `bao-tree` crate (v0.16)
   implements BLAKE3 Merkle tree construction with 16 KiB chunk groups per
   `BlockSize::from_chunk_log(4)`. Maintained by `n0-computer` (the iroh team),
   used in production by iroh-blobs. Cryptographic security rests on BLAKE3
   collision resistance (well-studied, widely deployed). The novelty is layout
   and chunk alignment, not the underlying construction. Should be in scope for
   Phase 9 security audit as a third-party-dependency review item.

2. **Outboard sibling tampering** (architectural) — if the storage provider
   corrupts the `.obao` sibling object, every verification fails. This is a
   denial-of-service, not a confidentiality or integrity break — the client
   cannot be fooled into accepting bad ciphertext, only into rejecting good
   ciphertext. File availability is impacted, but confidentiality is preserved.

3. **Outboard substitution across files** (architectural) — a malicious storage
   provider could serve file B's outboard in response to a request for file A's
   outboard. The decoder will fail verification because the signed `bao_hash`
   from the metadata envelope won't match what bao-tree reconstructs from the
   wrong outboard + ciphertext. This is caught by the existing multi-signature;
   no new mitigation needed.

---

## 6. Known limitations and open questions

- **Share-policy enforcement is a trust-in-proxy assumption**, not a
  cryptographic guarantee. See Adv-P.
- **Signature payload is `wrapped_key || bao_hash`** — does this bind to the
  recipient? If not, a malicious proxy could re-use a signed `EncryptedFile`
  across multiple share recipients without detection. *Needs analysis.*
- **Nonce store is in-memory** and not persisted — restarting the server
  resets the replay window. *Needs design decision before production.*
- **No rate limiting** anywhere in the server. See Adv-C and the Phase 5
  plan's unimplemented tower rate-limit layer.
- **File download is unauthenticated.** Confidential data stays confidential
  (it's encrypted) but metadata leaks.
- **Revocation is eventually consistent** — between a client's `DELETE
  /recryption/share/{id}` and the server actually removing the in-memory
  entry, a concurrent download may still succeed. For production this should
  be tightened or explicitly acknowledged.

---

## 7. TODO before security audit

- [ ] Fill in every **TODO** in this document
- [ ] Upgrade Adv-P analysis with a formal unforgeability argument
- [ ] Cross-reference each claim against `hybrid-encryption-architecture.md`
      and `verification-architecture.md`
- [ ] Add a section on key rotation and key-loss recovery
- [ ] Add a section on multi-device / key-sync use cases (or explicitly rule
      them out)
- [ ] Confirm Bao outboard verification is wired up end-to-end
- [ ] Confirm the canonical signature-message strings bind enough context
      (recipient, action, file hash, nonce) to prevent cross-protocol reuse
