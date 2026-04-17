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
- **`recrypt-core` / `recrypt-wire` / `recrypt-ffi`** — crypto primitives and
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
| A6   | File ciphertexts (`EncryptedFile`) | `BlobStorage` (S3/local), server pass-through  |       ○         |     ●     |      ●       |
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
- ~~**Signature payload is `wrapped_key || bao_hash`** — does this bind to the
  recipient? If not, a malicious proxy could re-use a signed `EncryptedFile`
  across multiple share recipients without detection. *Needs analysis.*~~
  **Resolved by the wire-format migration**, see §8.4.
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

## 8. Wire-format and signature design (added 2026-04-08)

This section documents threat-model commitments introduced by the
[protobuf → Gordian Envelope migration](plans/2026-04-08-gordian-envelope-migration.md).
It supersedes the original §4 / §6 references to "the protobuf
signature payload" wherever they conflict.

### 8.1 Hybrid signature: Ed25519 + ML-DSA-87

Every signed recrypt envelope carries **exactly two** `'signed'`
assertions: one Ed25519, one ML-DSA-87. This is enforced as a
recrypt application-layer invariant — a verifier MUST reject any
envelope that does not have both.

#### 8.1.1 Why both

The pairing exists for three reasons, in order of how load-bearing
they are:

1. **Ed25519 as the identity primitive.** Ed25519 produces a
   32-byte deterministic public key from a 32-byte seed. Recrypt's
   `PublicKeyFingerprint` type is `Blake3(ed25519_pubkey)`, and
   that fingerprint is the routing key threaded through every
   layer of the system: storage auth, capability granting,
   recryption-key delegation, every database table that mentions
   "an account." ML-DSA-87 public keys are ~2.6 KB, far too large
   to serve this role. Removing Ed25519 from recrypt would mean
   redesigning the identity layer, not just the signature layer.

2. **Defense in depth against PQ implementation bugs.** ML-DSA was
   only finalized as FIPS 204 in August 2024. Field implementations
   are new, and the known cryptographic-engineering history
   suggests we should expect implementation-level bugs in any
   newly-deployed scheme for several years. Pairing ML-DSA with a
   well-understood classical scheme means a single-implementation
   bug in our liboqs ML-DSA path doesn't silently break our
   security — the Ed25519 layer continues to authenticate.

3. **Audit and compliance posture.** "We trust Ed25519 for today's
   adversaries and ML-DSA-87 for tomorrow's quantum adversary"
   reads cleanly to an auditor or compliance reviewer. "We bet
   everything on a 2024-finalized lattice scheme" is a harder
   conversation to have.

#### 8.1.2 Acknowledged security-level asymmetry

Ed25519 provides ~128-bit classical security. ML-DSA-87 provides
~256-bit (Category 5). The standards-track composite signature
draft `draft-ietf-jose-pq-composite-sigs` deliberately pairs
ML-DSA-87 with **Ed448**, not Ed25519, to avoid this asymmetry.

Recrypt accepts the asymmetry knowingly. Reasoning:

- **Against a classical adversary**, the security is
  `min(Ed25519, ML-DSA-87)` ≈ 128 bits. This matches Ed25519
  alone, which is the de-facto standard for non-PQ signed
  systems. The hybrid does not improve classical security; it
  matches it.
- **Against a quantum adversary**, the security is whatever
  ML-DSA-87 provides on its own (~256 bits classical-equivalent
  resistance to quantum attacks). Ed25519 contributes nothing
  here — quantum adversaries break Ed25519. The hybrid does not
  improve quantum security beyond the ML-DSA layer.
- **The hybrid's actual benefit is implementation-bug
  resistance**, not security-level addition. An adversary needs
  to break *both* schemes to forge a recrypt signature, and a
  bug in either scheme's implementation does not by itself break
  recrypt.

If recrypt ever needs Cat-5 classical resistance, the right move
is to add Ed448 as a third assertion (becoming a true "all three
must verify" scheme), not to drop Ed25519. We don't do this today
because Ed25519 is the deployed identity primitive.

#### 8.1.3 The "all must verify" rule

Recrypt verifiers MUST reject an envelope unless **both** the
Ed25519 and ML-DSA-87 signatures are present and verify under the
expected verification keys. This is a recrypt application-layer
invariant; the Gordian Envelope standard does not enforce it. A
generic Envelope verifier with no recrypt knowledge would accept
an envelope with only one of the two signatures.

The rule is load-bearing and must be tested explicitly:

- An envelope with only an Ed25519 signature MUST be rejected,
  even if the Ed25519 signature is valid.
- An envelope with only an ML-DSA-87 signature MUST be rejected,
  even if the ML-DSA-87 signature is valid.
- An envelope with both signatures, where one fails to verify,
  MUST be rejected.
- An envelope with both signatures, where both verify, is
  accepted.

See FR-3 in the [migration plan](plans/2026-04-08-gordian-envelope-migration.md#functional-requirements)
for the corresponding test gate.

### 8.2 Wrapped-key envelopes are unsigned

Recrypt's `recrypt.pre-wrapped-key` envelopes ship without
`'signed'` assertions. This is a deliberate design choice with a
specific integrity argument.

#### 8.2.1 The integrity model

A wrapped-key envelope's integrity is established by **successful
PRE decryption followed by a plaintext-hash check**, not by a
signature on the envelope.

The decryption flow:

1. Recipient PRE-decrypts the wrapped-key's `ciphertext` field
   with their PRE secret key. Output: a 96-byte `KeyMaterial`
   bundle.
2. Recipient parses the `KeyMaterial` bundle (see
   [docs/standards/recrypt-key-material-v1.md](standards/recrypt-key-material-v1.md))
   to extract `symmetric_key`, `nonce`, `plaintext_hash`, and
   `plaintext_size`.
3. Recipient fetches the file ciphertext and XChaCha20-decrypts
   it.
4. Recipient computes `Blake3(recovered_plaintext)` and compares
   to `plaintext_hash`.
5. If the comparison fails, decryption is rejected.

The `plaintext_hash` lives **inside the PRE encryption envelope**,
where an attacker without the recipient's PRE secret key cannot
modify it without invalidating PRE decryption.

#### 8.2.2 What this defeats

- **Wrapped-key substitution.** Attacker swaps in a wrapped-key
  from a different file. The recipient PRE-decrypts and gets
  KeyMaterial whose `symmetric_key` doesn't decrypt the file
  ciphertext correctly; the resulting "plaintext" hashes to
  something different from the embedded `plaintext_hash`; the
  check fails.
- **Wrapped-key tampering.** Attacker modifies the PRE ciphertext
  bytes. Either PRE decryption rejects (most likely) or produces
  garbage KeyMaterial that fails downstream.
- **Truncation attacks on the file.** The KeyMaterial's
  `plaintext_size` field provides a fast-fail check before the
  full hash computation.

#### 8.2.3 Why this is sufficient

A signature on the wrapped-key envelope would add **redundant
integrity, not new integrity**. The cryptographic anchor that
authenticates "this wrapped-key is valid for this recipient and
this file" is the PRE-decryption + plaintext-hash check. A
signature would let a third party verify the wrapped-key without
attempting decryption, but recrypt has no use case where a
non-decrypter needs to verify a wrapped-key.

The operational consequence is **the recryption proxy needs no
signing key**. This is a real security win: the proxy is a
high-value attack target precisely because it sits in the
recryption critical path. Every signing key the proxy holds is a
key that could be stolen and used to forge attestations. Holding
none simplifies the threat surface.

#### 8.2.4 Future provenance signatures

Recrypt may later add `'signed'` assertions to wrapped-key
envelopes as a **provenance signal, not an integrity gate** — to
let auditors trace which proxy performed which recryption. The
addition is bound by an explicit forward-compatibility rule:

> **Future signatures must not change the verification model.**
> A verifier that ignores the new `'signed'` assertions MUST
> continue to get the same answer about whether the wrapped-key
> is valid.

This rule keeps the integrity model stable across the change. A
malicious proxy that strips its provenance signature does not
gain the ability to forge a wrapped-key — it only gains
deniability about which proxy did the recryption.

### 8.3 Elision and salting

Recrypt envelopes use Gordian Envelope's elision feature to let
holders strip metadata without invalidating signatures. Elision
replaces an assertion with its 32-byte Blake3 digest; signatures
continue to verify because the signed digest was already the
assertion's digest.

#### 8.3.1 The brute-force attack on naive elision

For any elidable assertion whose object has fewer than ~80 bits
of effective entropy, an attacker who knows the predicate can
brute-force the value:

1. Enumerate all possible objects (e.g., all subsets of a 4-value
   enum).
2. Encode each candidate as canonical dCBOR.
3. Hash with Blake3.
4. Compare to the visible elided digest.

For a 4-value enum like `Operation { Read, Write, Delete, Share }`,
this completes in microseconds.

#### 8.3.2 Salted assertions

Recrypt addresses this by using `bc-envelope`'s salted assertions
for any elidable field whose object has low entropy or where
unlinkability matters. A salted assertion's digest covers
`(salt, predicate, object)` where `salt` is a fresh CSPRNG nonce.
On elision the salt is stripped along with the value, leaving
only the digest of the salted triple — which is infeasible to
brute-force.

The full per-field policy is in
[wire-protocol.md §6](wire-protocol.md) and the
[envelope sketch spike](spikes/2026-04-08-envelope-sketch.md).

#### 8.3.3 Salt freshness invariant

Salts MUST be drawn fresh per assertion. They MUST NOT be:

- Derived from the assertion value (defeats the purpose).
- Reused across assertions within an envelope.
- Reused across envelopes for the same value (an attacker who
  learns the value once for any one envelope can confirm it for
  all of them).

`bc-envelope`'s `add_assertion_salted` API does the right thing
by default. Any code path that constructs salted assertions by
any other route MUST independently verify these properties.

#### 8.3.4 What salting does not protect against

Salting prevents brute-force reversal of an *individual* elided
assertion's value. It does **not** protect against:

- **Traffic analysis.** An observer who sees which wrapped-key
  is fetched for which recipient learns the access graph, even
  if every wrapped-key's contents are fully elided.
- **Timing correlation.** Create-time gaps, access patterns, and
  similar side channels are out of scope for the wire format and
  must be handled at higher layers.
- **Cross-envelope value correlation for low-cardinality fields.**
  If a recipient knows the file size of a few specific files,
  they can confirm those sizes appear in elided `plaintext-size`
  assertions across many envelopes — the salt prevents recovering
  the value from a single envelope, but does not prevent
  confirming a hypothesis. This is why the
  [KeyMaterial v1 spec](standards/recrypt-key-material-v1.md)
  treats `plaintext-size` as low-entropy even though it's a u56:
  most files cluster in narrow size ranges that correlate with
  content type.
- **Known-plaintext forgery.** Salted elision is about privacy,
  not integrity. Integrity comes from signatures (for file
  envelopes) and the plaintext-hash check (for wrapped-keys).

### 8.4 Resolved: signature payload binding

The original §6 contains this open question:

> **Signature payload is `wrapped_key || bao_hash`** — does this
> bind to the recipient? If not, a malicious proxy could re-use a
> signed `EncryptedFile` across multiple share recipients without
> detection. *Needs analysis.*

**Resolved by the envelope migration design.** The new wire format
separates concerns:

- The **file envelope's** signature payload is the envelope
  subject digest plus the digests of all non-elided assertions
  at signing time. The subject contains `bao-hash` (the file
  identity) and `format-version`. The signature explicitly does
  **not** bind to any recipient — file envelopes are
  recipient-independent and the same envelope is served to every
  recipient.
- **Recipient binding lives in the wrapped-key**, not the file
  envelope. The `for-recipient` field in the wrapped-key
  envelope's subject identifies who this wrapped-key is for, and
  the auth service routes wrapped-keys to recipients via its
  index.
- The "malicious proxy re-uses across recipients" attack is
  prevented because:
  1. Each recipient has their own wrapped-key (PRE-encrypted
     under their key).
  2. A wrapped-key for the wrong recipient fails PRE decryption.
  3. Even if PRE decryption succeeded somehow, the
     plaintext-hash check would catch any actual ciphertext
     mismatch.

The new model is cleaner: file envelopes are signed once per file,
wrapped-keys are minted per recipient per file, and the binding
between them is enforced by the auth service routing layer plus
the cryptographic decrypt-and-verify gate.

---

## 9. TODO before security audit

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
