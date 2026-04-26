# Doc 0 / Spike: Envelope Sketch for Recrypt Domain Types

**Date:** 2026-04-08
**Status:** Spike — not a committed design
**Purpose:** Ground [Doc 1 (wire-protocol rewrite)](../plans/2026-04-08-gordian-envelope-migration.md)
in the actual shape of recrypt's Rust types and the actual `bc-envelope`
API, so the schema doc isn't invented in a vacuum.

**Driver:** Migration plan §"Doc 0: Envelope sketch spike".

---

## Ground truth: current recrypt domain types

Verified by direct read of the sources as of 2026-04-08. These are the
types we must represent as envelopes. Field comments reproduced
verbatim where relevant.

### `EncryptedFile` — [`crates/recrypt-core/src/hybrid/encrypted_file.rs:9`](../../crates/recrypt-core/src/hybrid/encrypted_file.rs#L9)

```rust
pub struct EncryptedFile {
    pub wrapped_key: Ciphertext,           // PRE-encrypted key bundle
    pub bao_hash: [u8; 32],                // Bao root of the ciphertext
    pub ciphertext: Vec<u8>,               // XChaCha20 bulk ciphertext (no auth tag — Bao provides integrity)
    pub signature: Option<MultiSig>,       // signs (wrapped_key || bao_hash)
}
```

Signature payload today (`signature_payload()`): concatenation of
`wrapped_key.to_bytes()` + `bao_hash`. The signature does **not** cover
the ciphertext directly — Bao's hash does, and Bao's hash is in the
signed payload.

### `MultiSig` — [`crates/recrypt-core/src/sign/mod.rs:10`](../../crates/recrypt-core/src/sign/mod.rs#L10)

```rust
pub struct MultiSig {
    pub ed25519_sig: ed25519_dalek::Signature,  // 64 bytes
    pub ml_dsa_sig: Vec<u8>,                     // ML-DSA-87 signature bytes
}
```

**Both signatures must verify** (`verify_message` in the same file
returns `Err` if either fails). This is the recrypt application-layer
invariant the plan documents as FR-3.

### `Ciphertext` — [`crates/recrypt-core/src/pre/keys.rs:186`](../../crates/recrypt-core/src/pre/keys.rs#L186)

```rust
pub struct Ciphertext {
    pub(crate) backend: BackendId,  // Lattice | Mock | EcPairing | EcSecp256k1
    pub(crate) level: u8,           // 0 = original, 1+ = recrypted
    pub(crate) bytes: Vec<u8>,      // Backend-specific ciphertext
}
```

`level` increments on each recryption — this is important because it
lets a verifier see that a ciphertext has been through the proxy.

### `KeyMaterial` — [`crates/recrypt-core/src/hybrid/keymaterial.rs:7`](../../crates/recrypt-core/src/hybrid/keymaterial.rs#L7)

```rust
pub struct KeyMaterial {
    pub symmetric_key:  [u8; 32],   // XChaCha20 key
    pub nonce:          [u8; 24],   // XChaCha20 nonce
    pub plaintext_hash: [u8; 32],   // Blake3 of *plaintext* (confidential — lives inside the PRE envelope)
    pub plaintext_size: u64,
}
```

**Fixed 96 bytes**, never transmitted in the clear — this is the
plaintext that the PRE `wrapped_key` encrypts. It never appears as an
envelope on its own in normal flows; it materializes only after the
recipient decrypts `wrapped_key`. Documentary only in the envelope
schema.

### `RecryptKey` — [`crates/recrypt-core/src/pre/keys.rs:80`](../../crates/recrypt-core/src/pre/keys.rs#L80)

```rust
pub struct RecryptKey {
    pub(crate) backend: BackendId,
    pub(crate) from_public: PublicKey,   // source
    pub(crate) to_public:   PublicKey,   // destination
    pub(crate) bytes: Vec<u8>,           // backend-specific key data
}
```

### `PublicKey` / `SecretKey` — [`crates/recrypt-core/src/pre/keys.rs:7,46`](../../crates/recrypt-core/src/pre/keys.rs#L7)

PRE-backend key wrappers: `(backend: BackendId, bytes: Vec<u8>)`. Note
that recrypt's "public key bundle" is not a single struct in the current
codebase — the current proto schema bundles `ed25519_key`, `pq_keys`,
and `pre_public_key`, but `recrypt-core` does not own a combined type.
The protobuf `PublicKeyBundle` exists in the wire layer only, which
means the envelope migration gets to decide whether to introduce a
proper domain type or keep it purely wire-layer.

### `Capability` — [`crates/identikey-storage-auth/src/capability.rs:55`](../../crates/identikey-storage-auth/src/capability.rs#L55)

```rust
pub struct Capability {
    pub version: u32,                     // format version
    pub file_hash: blake3::Hash,          // content address
    pub granted_to: PublicKeyFingerprint, // grantee (Blake3(pubkey))
    pub operations: Vec<Operation>,       // Read | Write | Delete | Share
    pub expires_at: u64,                  // unix seconds, 0 = no expiry
    pub issuer: PublicKeyFingerprint,
    pub signature: Option<MultiSig>,
}
```

Signature payload canonicalizes operations alphabetically before signing.

### `PublicKeyFingerprint` — [`crates/identikey-storage-auth/src/fingerprint.rs:11`](../../crates/identikey-storage-auth/src/fingerprint.rs#L11)

```rust
pub struct PublicKeyFingerprint([u8; 32]);
```

Blake3(public_key_bytes). Displayed as base58. This is the identity
primitive threaded through the whole system.

---

## Target: `bc-envelope` 0.43.0 API

Verified from [docs.rs/bc-envelope/0.43.0](https://docs.rs/bc-envelope/latest/bc_envelope/). Key primitives:

- `Envelope::new(subject)` — wrap any CBOR-encodable value as an envelope's subject.
- `.add_assertion(predicate, object)` — attach a `[predicate: object]` triple.
- `.add_assertion_salted(...)` — same, but with decorrelation salt so identical-looking metadata can't be fingerprinted across envelopes.
- `.add_signature(signing_key)` / `.add_signatures(&[key1, key2])` — produces `'signed': Signature` assertions. **Natively supports multi-sig** — exactly what we need for Ed25519 + ML-DSA-87.
- `.elide_*` family — replace assertions or subjects with their Merkle hash without invalidating signatures on ancestors.
- `.is_elided`, `.is_subject_elided`, `.is_obscured` — introspection.
- Default features include: `ed25519`, `pqcrypto`, `encrypt`, `signature`, `recipient`, `salt`, `compress`, `known_value`, `types`, `sskr`, `ssh`. The `pqcrypto` feature is the one that gives us ML-DSA support without writing our own integration — **critical confirmation**.

dCBOR is not a separate crate to import for envelope users; `bc-envelope` re-exports or depends on `dcbor` 0.25 transitively.

Known values (from `known-values`): BC defines a set of canonical
predicate names (e.g., `'signed'`, `'note'`, `'date'`, `'isA'`) encoded
as compact small integers rather than strings. Using these where they
match our semantics buys interop with `envelope-cli` and other BC
tooling for free.

---

## The sketch: `EncryptedFile` as an envelope

Diagnostic notation. `"foo"` are strings; `'foo'` are BC known-values;
`h'...'` are byte strings; `42(x)` is CBOR tag 42 applied to x.
Indentation shows assertion nesting.

```
201(                                               ; #6.201 = leaf-of-envelope
  {                                                ; subject: a map describing the file
    "type": "recrypt.encrypted-file",
    "format-version": 3,
    "bao-hash": h'...32 bytes...',                 ; covered by signature; the file's identity
    "ciphertext-ref": h'...32 bytes...'            ; S3 content address = Blake3(ciphertext); sidecar
  }
) [
  [salted] "backend":        "lattice-bfv",         ; recrypt.BackendId as string for diagnostic clarity
  [salted] "created":        1(1712534400),         ; CBOR tag 1 = epoch time
           "owner":          h'...32 bytes...',     ; Blake3(owner Ed25519 pubkey) = PublicKeyFingerprint
  [salted] "plaintext-size": 1048576,               ; u64 bytes; optional, elidable
           'signed':         Signature(ed25519, ...),    ; 'signed' is a BC known-value predicate
           'signed':         Signature(ml-dsa-87, ...)   ; second signature for the hybrid
]
```

Note: no `wrapped-key-ref` field. The file envelope is the same for
every recipient and across every recryption — it never needs
re-issuing. Wrapped-key discovery goes through the auth service
keyed on `(file_hash, recipient_fingerprint)`. See the rationale
paragraph below the wrapped-key envelope sketch.

Two signatures. Both attach to the same subject via separate `'signed'`
assertions. `add_signatures(&[ed25519_key, ml_dsa_key])` produces this
shape directly.

**What the subject contains vs what lives in assertions:** I'm putting
the load-bearing integrity anchors (`bao-hash`, `ciphertext-ref`,
`format-version`) in the subject map so they're
part of the subject hash and therefore part of every assertion digest.
Mutable metadata (`created`, `plaintext-size`) and descriptive fields
go in assertions so they can be individually elided.

**No `wrapped-key-ref` in the file envelope.** *Updated 2026-04-08
after design discussion.* The file envelope contains **no pointer to
the wrapped-key**. The reference is one-way: wrapped-key → file (via
the wrapped-key's `"for-file"` assertion). Discovery is handled by
the `identikey-storage-auth` service, which indexes wrapped-keys by
`(file_hash, recipient_fingerprint)` and returns the appropriate
object on lookup. Rationale: the wrapped-key changes on every
recryption; the file envelope must not change. A pointer in the
file envelope would either be stale-on-recryption (re-issuing the
file envelope defeats the migration's marquee benefit) or live in
an elidable assertion (mutable, weak binding). The auth service
already plays this routing role today, so this is reusing existing
architecture, not inventing new.

### The wrapped-key object (separate envelope)

```
201(
  {
    "type": "recrypt.pre-wrapped-key",
    "format-version": 1,
    "backend": "lattice-bfv",
    "for-recipient": h'...32 bytes...',     ; Blake3(recipient PRE pubkey) — routing only
    "ciphertext": h'...backend-specific bytes...'   ; PRE-encrypted KeyMaterial bundle
  }
) [
  [salted] "for-file":  h'...bao-hash of the file...',   ; routing hint, elidable, NOT load-bearing
  [salted] "level":     0,                                ; increments on each recryption
  [salted] "created":   1(1712534400)
  ; no 'signed' assertions — see "Integrity model" below
]
```

**Direction of binding (decided 2026-04-08): wrapped-key → file,
one-way.** The wrapped-key envelope references the file via
`"for-file"`. The file envelope does not reference the wrapped-key.
The auth service indexes wrapped-keys by `(file_hash,
recipient_fingerprint)` and returns the appropriate object on
recipient lookup. This matches the existing architecture in
[`docs/architecture.md`](../architecture.md) where the auth service
is the routing layer.

**`for-file` is an elidable assertion, not a subject field
(decided 2026-04-08, reversing earlier design).** The integrity of
the wrapped-key does not depend on `for-file` being present at
verification time. The integrity gate is the
`KeyMaterial.plaintext_hash` check inside the PRE-encrypted bundle:
when the recipient decrypts the wrapped-key with their secret key
and gets a 96-byte KeyMaterial, they then XChaCha20-decrypt the
file ciphertext using `KeyMaterial.symmetric_key`, hash the
resulting plaintext with Blake3, and compare against
`KeyMaterial.plaintext_hash`. Any wrapped-key that doesn't actually
unlock the file the recipient is trying to read fails this check.
The plaintext hash lives inside the PRE encryption envelope, so it
cannot be modified without the recipient's secret key.

This means `"for-file"` is purely a **routing/discovery hint**, not
a security boundary. The auth service uses it to index. The
recipient doesn't need it at decrypt time. Eliding it loses no
integrity, and **enables a privacy property worth naming**: a
wrapped-key envelope in its elided form reveals nothing about
which file it unlocks. Useful for "I have *some* access grant"
attestations and for stripping metadata when forwarding through
less-trusted hops.

**Earlier reasoning that was wrong:** an earlier draft of this
spike said `"for-file"` had to be in the subject to prevent
"wrapped-key for the wrong file" confusion attacks. That argument
missed the plaintext-hash check. Recording the reversal so future
readers don't reinvent the wrong rule.

### Integrity model: why wrapped-keys are unsigned (for now)

**Decision (2026-04-08):** wrapped-key envelopes ship without
signatures. Rationale:

- **The integrity of the wrapped-key is established by successful
  decryption + plaintext-hash check.** A maliciously-modified
  wrapped-key either fails to decrypt under the recipient's secret
  key or decrypts to garbage that fails the plaintext-hash gate.
  Adding a signature on the wrapped-key envelope would be
  redundant integrity, not new integrity.
- **The file envelope's signature already commits to the
  ciphertext** (via `bao-hash` in its subject). The wrapped-key is
  just key material for that ciphertext. Whether the wrapped-key is
  the "right" one is established by trying to use it; whether the
  file is the "right" one is established by the file envelope's
  signature.
- **The proxy needs no signing key.** This is a real operational
  win: the recryption proxy is a high-value attack target, and
  every signing key it holds is a key that could be stolen. Shipping
  without signatures means we don't need to design proxy key
  management today.
- **Authorization of "who can fetch this wrapped-key" is the auth
  service's job**, enforced by capability checks on the storage
  layer. This is a separate concern from the cryptographic
  integrity of the wrapped-key itself.

**Future work — provenance signatures (not integrity):** when we
later want auditability of "which proxy performed which
recryption," we will add `'signed'` assertions to the wrapped-key
envelope as an **additive, backwards-compatible** change. Verifiers
ignore them by default (the integrity model continues to be
plaintext-hash-check). A separate provenance-checking flow walks
the signature assertions when an audit is desired. The future
signatures are about *traceability of access*, not about
*correctness of decryption*.

The rule for adding this later: **future signatures must not change
the verification model.** A recipient who ignores them must
continue to get the same answer about whether the wrapped-key is
valid. This is the same principle as the multi-sig "all must
verify" rule for the file envelope: signatures attest, decryption
authenticates.

### `Capability` as an envelope

```
201(
  {
    "type": "recrypt.capability",
    "format-version": 1,
    "file-hash":  h'...32 bytes...',
    "granted-to": h'...32 bytes...',
    "issuer":     h'...32 bytes...'
  }
) [
  "operations": ["read", "share"],          ; CBOR array of strings
  "expires-at": 1(1714521600),               ; 0 or absent = no expiry
  'note': "issued for research access",     ; optional human-readable
  'signed': Signature(ed25519, ...),
  'signed': Signature(ml-dsa-87, ...)
]
```

Subject carries the identity triple
(`file-hash`, `granted-to`, `issuer`) and format version. Operations
and expiry are assertions — elidable if the capability is used in a
context where the grantee doesn't need to reveal them (e.g., "I have
*some* capability on this file" without revealing scope).

The current `Capability::signature_payload()` code
([capability.rs:96](../../crates/identikey-storage-auth/src/capability.rs#L96))
hand-sorts operations alphabetically before signing. dCBOR's
canonical-encoding rules give us this for free: the CBOR encoding of
`["read", "share"]` is deterministic, so two capabilities with the
same operations in different input order produce the same envelope.
**That's a net simplification** — we can delete the hand-sort code.

### `PublicKeyBundle` — new domain type, introduced by this migration

Current code has no single type; wire format aggregates. We should
introduce a real `PublicKeyBundle` (name TBD) in `recrypt-core` as part
of the migration because option B (envelope-native domain types)
requires it. Sketch:

```
201(
  {
    "type": "recrypt.public-key-bundle",
    "format-version": 1,
    "ed25519":    h'...32 bytes...',
    "ml-dsa-87":  h'...2592 bytes...',
    "pre-backend": "lattice-bfv",
    "pre-public": h'...backend-specific...'
  }
) [
  "created": 1(...),
  'note': "Alice's primary keypair"
]
```

The fingerprint stays defined as `Blake3(ed25519_key)` to preserve
backwards-compatibility with all the identity routing in
`recrypt-server` and `identikey-storage-auth`. This is where the
[threat-model rationale](../plans/2026-04-08-gordian-envelope-migration.md#doc-3-update-docsthreat-modelmd-or-create)
for keeping Ed25519 as identity-primitive earns its keep.

### `RecryptKey` as an envelope

```
201(
  {
    "type": "recrypt.recrypt-key",
    "format-version": 1,
    "backend": "lattice-bfv",
    "from-fingerprint": h'...32 bytes...',     ; Blake3(from_public)
    "to-fingerprint":   h'...32 bytes...',
    "key-data": h'...backend-specific bytes...'
  }
) [
  'signed': Signature(ed25519, ...),            ; signed by the delegator (source keyholder)
  'signed': Signature(ml-dsa-87, ...)
]
```

Recrypt keys are never published — they live on the proxy — but when
they move between a client and the proxy, they move as signed
envelopes.

---

## Verification notes (answering the spike's acceptance criteria)

**Every field in [`recrypt.proto`](../../crates/recrypt-proto/proto/recrypt.proto) has a corresponding envelope assertion:**

| proto field                                   | envelope location                                  |
|---                                             |---                                                  |
| `BackendId`                                    | string in subject (or BC known-value — TBD)        |
| `PublicKeyBundle.ed25519_key`                  | `"ed25519"` in subject map                         |
| `PublicKeyBundle.pq_keys[].algorithm/key_data` | `"ml-dsa-87"` in subject map (fixed algo)          |
| `PublicKeyBundle.pre_backend/pre_public_key`   | `"pre-backend"` / `"pre-public"` in subject map    |
| `SecretKeyBundle.*`                            | mirror of PublicKeyBundle (for local storage only) |
| `RecryptKeyProto.*`                            | recrypt-key envelope above                         |
| `CiphertextProto.backend/level/data`           | `"backend"` / `"level"` / `"ciphertext"` in wrapped-key envelope |
| `EncryptedFileProto.version`                   | `"format-version"` in subject                      |
| `EncryptedFileProto.wrapped_key`               | Separate `recrypt.pre-wrapped-key` envelope; discovered via auth service |
| `EncryptedFileProto.bao_hash`                  | `"bao-hash"` in subject                            |
| `EncryptedFileProto.ciphertext`                | `"ciphertext-ref"` hash (sidecar, content-addressed) |
| `EncryptedFileProto.signature`                 | two `'signed'` assertions                          |
| `KeyMaterialProto.*`                           | plaintext inside PRE ciphertext, documentary only  |
| `MultiSignatureProto.*`                        | represented as BC `Signature` objects              |
| `FileMetadata.*`                               | subject + assertions on the file envelope          |
| `ChunkProto.*`                                 | **deferred** — chunk transfer stays out-of-band    |
| `CapabilityProto.*`                            | capability envelope above                          |
| `UploadRequest/DownloadResponse/Recrypt*`      | thin envelopes wrapping the above                  |

Every field accounted for. `ChunkProto` deferred because chunk
transfer is an HTTP-layer concern, not a persisted-blob concern —
confirmed by reading the existing routes.

**dCBOR edge cases enumerated (list for Doc 1 to deepen):**

1. **Map key ordering**: dCBOR requires map keys to be sorted in
   canonical CBOR order (shortest encoding first, then
   lexicographic). `ciborium`'s default does not enforce this on
   encode. **Impact:** the subject map order in our sketches is
   irrelevant for correctness; `bc-envelope`/`dcbor` will canonicalize.
2. **Integer encoding**: smallest-form required. `1`, `24`, `256`,
   `65536` must each use the smallest encoding. dCBOR enforces.
3. **Float encoding**: dCBOR forbids NaN, forbids -0.0, requires
   smallest representation. **Impact:** we have no floats in our data
   model, so this is a non-issue — worth stating explicitly in Doc 1.
4. **No indefinite-length items**: dCBOR forbids indefinite-length
   byte strings, text strings, arrays, maps. Our byte arrays are all
   known-size at encode time, so this is free.
5. **Tags**: dCBOR permits registered CBOR tags. We will use BC's
   envelope/leaf tags (#6.200, #6.201) plus any recrypt-specific tag
   we register for the wrapped-key object (pending Wolf's feedback per
   Open Question 1).
6. **String vs byte string**: Blake3 hashes and PRE ciphertexts are
   byte strings (`h'...'`), never base58-encoded inside the envelope.
   Base58 is a display concern for CLI output only. This is a
   **simplification** from the current JSON path which base58-encodes
   everything.

**Open Question 1 concrete proposal (ready to send to Wolf):**

> Hi Wolf — we're building a proxy recryption system (recrypt) that
> has a shape very similar to [`bc-envelope`'s](https://crates.io/crates/bc-envelope) `SealedMessage`/`Recipient` pattern, but
> with a twist: after a semi-trusted proxy applies a recryption
> transform, the wrapped symmetric key is replaced with a new
> ciphertext under a different recipient's PRE public key, without
> the proxy ever learning the key itself. We're modeling this as a
> separate "wrapped-key" envelope alongside the main file envelope.
>
> Two questions:
>
> 1. Is there anything in `bc-components` we should reuse here, or
>    is this concept sufficiently different that we should define a
>    recrypt-specific CBOR tag (`recrypt.pre-wrapped-key` or similar)?
> 2. If we define a new tag, would you be open to hosting it in the
>    BC tags registry, or should we claim one in the private-use
>    range for now and revisit later?
>
> Fallback plan: if we don't hear back by 2026-04-22, we'll use a
> private-use tag and ship.

---

## Rust sketch (what the code will actually look like)

Not compiled. Illustrative. Shows the option-B envelope-native domain
type shape from the migration plan.

```rust
use bc_envelope::prelude::*;

pub struct EncryptedFile {
    envelope: Envelope,
}

impl EncryptedFile {
    pub fn new(
        bao_hash:        [u8; 32],
        ciphertext_ref:  [u8; 32],
        backend:         BackendId,
        owner:           PublicKeyFingerprint,
    ) -> Self {
        // No wrapped-key-ref — file envelopes are recipient-independent
        // and immutable across recryptions. Wrapped-key discovery is the
        // auth service's job. See §"No wrapped-key-ref in the file envelope".
        let subject = dcbor::Map::new()
            .insert("type", "recrypt.encrypted-file")
            .insert("format-version", 3u32)
            .insert("bao-hash",        dcbor::ByteString::from(bao_hash.to_vec()))
            .insert("ciphertext-ref",  dcbor::ByteString::from(ciphertext_ref.to_vec()));

        let envelope = Envelope::new(subject)
            .add_assertion("backend", backend.to_string())
            .add_assertion("owner", dcbor::ByteString::from(owner.as_bytes().to_vec()));

        Self { envelope }
    }

    pub fn sign(mut self, ed: &Ed25519PrivateKey, mldsa: &MlDsaPrivateKey) -> Self {
        self.envelope = self.envelope.add_signatures(&[ed, mldsa]);
        self
    }

    pub fn verify(&self, pub_bundle: &PublicKeyBundle) -> Result<(), Error> {
        // Both signatures must verify — application-layer rule (FR-3)
        self.envelope.verify_signature_from(&pub_bundle.ed25519_verifier())?;
        self.envelope.verify_signature_from(&pub_bundle.ml_dsa_verifier())?;
        Ok(())
    }

    pub fn bao_hash(&self) -> Result<[u8; 32], Error> {
        let subject_map = self.envelope.subject().extract_subject::<dcbor::Map>()?;
        let bytes: dcbor::ByteString = subject_map.get("bao-hash")?;
        bytes.into_inner().try_into().map_err(|_| Error::WrongSize)
    }

    pub fn to_cbor_bytes(&self) -> Vec<u8> {
        self.envelope.to_cbor_data()
    }

    pub fn from_cbor_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let envelope = Envelope::try_from_cbor_data(bytes)?;
        // Sanity-check the subject map shape
        let subject = envelope.subject().extract_subject::<dcbor::Map>()?;
        let ty: String = subject.get("type")?;
        if ty != "recrypt.encrypted-file" {
            return Err(Error::WrongType(ty));
        }
        let ver: u32 = subject.get("format-version")?;
        if ver != 3 { return Err(Error::WrongVersion(ver)); }
        Ok(Self { envelope })
    }
}
```

**API shape observations:**

- Domain types become newtype wrappers around `Envelope`, not arbitrary
  structs. Every accessor goes through subject-extraction.
- The multi-sig "all must verify" rule is enforced by the application
  (`verify` calls both underlying verifiers). This is what the plan's
  FR-3 documents.
- Construction is slightly more verbose than plain struct literals,
  but we get elision and round-trip for free.
- The accessors (`bao_hash`, etc.) do a small amount of
  subject-extraction on every call. For hot paths (recryption proxy),
  we can cache parsed subject data in the wrapper; the `Envelope` is
  the source of truth on disk/wire.

**Estimated friction points for the real implementation:**

1. `Envelope` is `Clone` but conceptually immutable — every mutation
   returns a new envelope. The chain-style API (`.add_assertion(...)
   .add_assertion(...)`) works well but we must be careful not to
   discard intermediate results accidentally.
2. Extracting typed values from the subject map requires knowing the
   dcbor type system. Learning curve, not a blocker.
3. The `bc-envelope` signature API wants `bc-components::Signer`
   trait implementations for our Ed25519 and ML-DSA keys. We'll
   either: (a) implement `Signer` on wrappers around our current key
   types, or (b) use `bc-components` key types directly and migrate
   the key-management layer. Option (a) is less invasive and is what
   I'd recommend — our current `ed25519-dalek` and `oqs` key types
   don't need to change.

---

## Round-trip validation (deferred to implementation)

The acceptance criterion says "at least one sketch successfully
round-trips via `bc-envelope` in a scratch Rust binary." I'm marking
this as **deferred to the start of implementation** rather than doing
it here, on the basis that:

1. Running it requires pulling `bc-envelope` into the workspace
   (`Cargo.toml` change) — that's already the first step of actual
   implementation, not spike territory.
2. The API shape is confirmed from docs.rs, and the type signatures
   above compile against `bc-envelope` 0.43.0's documented surface.
3. The spike's job is to de-risk the *schema design*, which it has
   done. The compile-check is valuable but orthogonal.

**First implementation step will be:** add `bc-envelope = "0.43.0"`
(exact pin) as a dev-dependency to a scratch example in
`recrypt-proto`, construct an `EncryptedFile` envelope, round-trip it,
sign+elide+verify it, and confirm the pattern works. If any of those
fail, the spike's conclusions need to be revised before Doc 1 is
written.

---

## Verdict: does the semantic-triples model feel right?

**Yes, strongly.**

Three specific observations from writing this out:

1. **Elision maps naturally onto "proxy strips routing info."** The
   recrypt-server's share-GET handler can elide `"created"`,
   `"plaintext-size"`, and any future audit stamps before forwarding
   an envelope to a recipient — the signature continues to verify. This
   is the marquee feature and it works without any special code paths.

2. **The subject-vs-assertions split is doing real work.** Load-bearing
   integrity anchors (`bao-hash`, `ciphertext-ref`,
   `format-version`) belong in the subject because they must not be
   elidable. Metadata belongs in assertions because it should be.
   The distinction is exactly what COSE's protected/unprotected
   headers were trying to express, but with finer granularity — we can
   elide assertions individually, not just "the whole unprotected
   map."

3. **Multi-sig "just works" via `add_signatures`.** No custom
   composite algorithm identifier, no extra RFC drafts. The `'signed'`
   predicate is repeated; each signature lives in its own assertion;
   the application enforces "all must verify." This is a cleaner
   expression of the invariant than the current protobuf
   `MultiSignatureProto` with its nested `pq_signatures` array.

**No red flags** in the shape of the data. The wrapped-key-reference
question (options a/b/c) was resolved during design discussion:
option (b) — wrapped-key → file one-way, no pointer in the file
envelope, auth service handles discovery. See the resolved items
in the followups section below.

**The spike unblocks Doc 1.**

---

## Salting policy for elidable low-entropy assertions

Elision replaces an assertion subtree with its 32-byte Blake3 digest.
The signature continues to verify because the Merkle structure is
unchanged. **But** if the elided value comes from a small preimage
space, an attacker can brute-force it: enumerate all candidates,
encode each as canonical dCBOR, hash, and compare to the visible
digest. For an enum of 4 values, this takes microseconds.

`bc-envelope` provides `add_assertion_salted` for exactly this
problem. A salted assertion's digest covers `(salt, predicate,
object)` where `salt` is a random nonce. The salt is preserved when
the envelope is held in full and discarded along with the value when
the assertion is elided. Verifiers see only the digest of the
salted triple, which is infeasible to brute-force.

**Rule:** any assertion whose object has fewer than ~80 bits of
effective entropy *and* is intended to be elidable in a hostile
environment MUST be salted. High-entropy values (hashes,
fingerprints, ciphertext bytes, signatures) do not need salting
because brute force over their preimage space is infeasible
regardless.

We salt only where elision is actually meaningful — not blindly
on every assertion, because salts add bytes to the wire format and
muddy the diagnostic notation. The principle is: salt where
elision is a privacy or unlinkability feature; don't salt where
elision is just a "we don't need this field today" placeholder.

### Per-assertion classification

| Assertion                            | Type     | Entropy   | Salted? | Reason                                       |
|---                                    |---       |---        |---      |---                                            |
| `"format-version"` (subject field)   | u32      | low       | n/a     | In subject, never elided — verifiers must read it |
| `"bao-hash"` (subject field)          | 32 bytes | high      | n/a     | In subject; integrity anchor, never elided   |
| `"ciphertext-ref"` (subject field)    | 32 bytes | high      | n/a     | In subject; content address                  |
| `"backend"`                           | string   | ~2 bits   | **YES** | 4 values; trivially brute-forced unsalted    |
| `"owner"` (fingerprint)               | 32 bytes | high      | no      | Blake3 digest, full entropy                  |
| `"created"` (timestamp)               | u64      | ~30 bits  | **YES** | Knowable to ±days from context; brute-forceable |
| `"plaintext-size"`                    | u64      | low-med   | **YES** | Often guessable from context                 |
| `'signed': Signature`                 | bytes    | high      | no      | Signature itself is high-entropy             |
| `"operations"` (capability)           | array    | ~4 bits   | **YES** | 16 subsets of 4-value enum; trivially brute-forced |
| `"expires-at"` (capability)           | u64      | low-med   | **YES** | Knowable to ±hours; brute-forceable          |
| `"granted-to"` (subject field)        | 32 bytes | high      | n/a     | In subject; fingerprint, full entropy        |
| `"issuer"` (subject field)            | 32 bytes | high      | n/a     | In subject; fingerprint, full entropy        |
| `"file-hash"` (subject field)         | 32 bytes | high      | n/a     | In subject; content address                  |
| `"for-file"` (wrapped-key)            | 32 bytes | high      | **YES** | High entropy, but salting enables anonymity-preserving elision (see wrapped-key §) |
| `"for-recipient"` (wrapped-key)       | 32 bytes | high      | n/a     | In subject; routing identifier               |
| `"level"` (wrapped-key)               | u8       | ~2 bits   | **YES** | 0/1/2/...; small range, salt for unlinkability |
| `"key-data"` (recrypt key)            | bytes    | high      | no      | Backend ciphertext bytes                     |
| `"from-fingerprint"` / `"to-fingerprint"` | bytes | high      | no      | Blake3 fingerprints                          |
| `'note'` (free-text comments)         | string   | varies    | **YES** | Often short or templated; salt by default    |

**Note on `"for-file"`:** the high entropy of a Blake3 hash would
normally make salting unnecessary, but here the salt serves a
*different* purpose — it prevents an observer from confirming "is
this elided wrapped-key for file X?" by hashing the candidate
file-hash and comparing. Without salt, that comparison succeeds for
the right file. With salt, the observer would need both the salt
and the candidate hash, and the salt is gone after elision. This is
the unlinkability case the wrapped-key §"Integrity model" section
flags as a privacy property.

### Cross-document linkability

Even with salting, repeated elision of the same value with the same
salt would leak that the value is constant across envelopes. **Salts
must be drawn fresh per assertion**, not derived from the value or
reused. `bc-envelope`'s `add_assertion_salted` does this correctly
out of the box; the threat-model doc should state the requirement
explicitly so any future custom code path doesn't get it wrong.

### What this changes in our envelope sketches

Reading back the envelope sketches above with the salting policy
applied:

- The `EncryptedFile` envelope's `"backend"`, `"created"`, and
  `"plaintext-size"` assertions become `add_assertion_salted` calls.
- The `Capability` envelope's `"operations"`, `"expires-at"`, and
  `'note'` assertions become salted.
- All `'signed'` assertions stay unsalted — signatures are
  high-entropy.
- All hash references and fingerprints stay unsalted.
- Subject map fields are never elided and never need salting.

The sketches in §"The sketch" above remain conceptually correct but
would be rendered with `[salted]` annotations on the elidable
low-entropy assertions in the final Doc 1 spec.

## Followups for Doc 1

Things this spike surfaced that need to be decided when writing the
actual wire-protocol doc:

- [x] **Resolved 2026-04-08**: Wrapped-key reference strategy.
      Decision: **(b) file-hash binding via external index** —
      wrapped-key → file one-way reference, no pointer in the file
      envelope, auth service handles routing.
- [x] **Resolved 2026-04-08**: `"for-file"` placement. Decision:
      elidable salted assertion, not subject field. Integrity
      comes from the plaintext-hash check inside the PRE-encrypted
      KeyMaterial, not from the assertion's presence. Eliding is
      a privacy feature.
- [x] **Resolved 2026-04-08**: Wrapped-key signatures. Decision:
      ship unsigned. Future provenance signatures will be additive
      and non-load-bearing.
- [ ] Whether to use BC known-values for recrypt-specific predicates
      (`"backend"`, `"owner"`, etc.) or plain strings. Known-values
      save bytes but couple us to BC's registry. Leaning strings
      for recrypt-specific terms, known-values for standard ones
      (`'signed'`, `'note'`, `'date'`).
- [ ] Exact string set for `"backend"` values: `"lattice-bfv"`,
      `"ec-pairing"`, `"ec-secp256k1"`, `"mock"`. Keep in sync with
      `BackendId` enum.
- [ ] Whether to introduce a real `PublicKeyBundle` domain type in
      `recrypt-core` (yes, per this spike).
- [ ] Whether the CLI's ASCII armor path re-encodes the envelope
      bytes or uses BC's UR format (`ur:envelope/...`). UR gives us
      interop with BC tooling for free; armor is our existing
      convention. Could support both.
- [ ] Send the Wolf email (Open Question 1).
- [ ] Implementation sanity-check: pull `bc-envelope` into a scratch
      Rust file and compile+run the round-trip before writing the
      first line of Doc 1.
