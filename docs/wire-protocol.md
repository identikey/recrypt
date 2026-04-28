# Wire Protocol: Gordian Envelope Format

**Status:** ✅ Stable.
**Authoritative reference:** this document.
**Implementation:** [`crates/recrypt-wire`](../crates/recrypt-wire/).

For the HTTP endpoints that consume these messages, see
[http-api-reference.md](http-api-reference.md). For the broader architectural
role of the wire crate, see [architecture.md §3](architecture.md#3-per-crate-responsibilities).
For the bulk-encryption construction used underneath this envelope, see
[xchacha20-bao-aead.md](standards/xchacha20-bao-aead.md).

---

## 1. Overview

Recrypt's wire format is a thin layering over [Gordian Envelope](https://developer.blockchaincommons.com/envelope/)
from Blockchain Commons. Envelope is a CBOR-based "smart document"
format with:

- **Deterministic CBOR (dCBOR)** encoding, so signature
  canonicalization is solved at the library level.
- A **Merkle-like digest tree** over every assertion, allowing
  individual assertions to be **elided** (replaced with their hash)
  without invalidating signatures on ancestors.
- **Semantic triples** (`subject [predicate: object]`) as the
  internal structure, giving us first-class extensible metadata.
- **Salted assertions** for redaction-resistant privacy, so
  low-entropy fields can be elided without being brute-forceable
  from their digest.
- **Native multi-signature support** via repeated `'signed'`
  assertions — exactly what recrypt's hybrid Ed25519+ML-DSA-87
  scheme needs.
- An **IETF draft** (`draft-mcnally-envelope`) and the media type
  `application/envelope+cbor`.

We carry recrypt-specific semantics as CBOR-tagged subject types and
named assertion predicates. Everything outside of PRE (which Envelope
doesn't speak natively) maps onto Envelope primitives directly.

### 1.1 Supported formats

| Format       | Primary use              | Content-Type                | Status   |
| ------------ | ------------------------ | --------------------------- | -------- |
| Envelope     | Wire protocol, storage   | `application/envelope+cbor` | ✅ Stable |
| ASCII armor  | Human export, key backup | `text/plain`                | ✅ Stable |
| UR           | QR codes, sneakernet     | `text/plain`                | 🔜 Later |

The Envelope bytes are the authoritative representation. Armor and
UR are wrappings of the same underlying bytes.

### 1.2 Why Envelope?

Envelope was chosen over protobuf for four reasons that matter for
recrypt's specific shape (long-lived archival blobs, opaque crypto
payloads, third-party extension, and proxy-side metadata stripping):

- **Self-describing.** A blob carries its own structure; no
  out-of-band `.proto` schema is required to read archival data.
- **Opaque payloads are first-class.** Every meaningful recrypt
  field is `bytes` anyway, so protobuf's schema-driven type safety
  bought us nothing.
- **Extension is graceful.** New assertion predicates are additive;
  there is no `google.protobuf.Any` escape hatch.
- **Elision is built in.** A proxy can strip metadata from a
  forwarded blob without invalidating signatures over the parent.

The historical migration retrospective is preserved in
[`plans/archive/2026-04-08-gordian-envelope-migration.md`](plans/archive/2026-04-08-gordian-envelope-migration.md).

---

## 2. Primitives and conventions

### 2.1 dCBOR

All recrypt envelope bytes are **dCBOR**, Blockchain Commons'
deterministic CBOR profile. dCBOR is stricter than RFC 8949's
canonical encoding, guaranteeing that re-serializing any parsed
value produces byte-identical output.

The rules that affect recrypt specifically:

- **Map keys sorted** in canonical CBOR order (shortest encoding
  first, then lexicographic). Applies automatically via
  `bc-dcbor`.
- **Integers use the smallest encoding.** `1`, `24`, `256`, `65536`
  each use the smallest form; non-canonical encodings are invalid.
- **No indefinite-length items.** All byte strings, text strings,
  arrays, and maps must have a known length at encode time.
- **No floats.** Recrypt has no floating-point values in any domain
  type. If we ever need one, dCBOR's rules (no NaN, no -0.0,
  smallest representation) apply.
- **Tagged major types** are permitted and we use them for the
  envelope/leaf tags and for timestamps.

### 2.2 Envelope and leaf tags

| CBOR tag | Role                         | Owner                        |
|---       |---                           |---                           |
| `#6.200` | Envelope                     | Blockchain Commons           |
| `#6.201` | Leaf (dCBOR-encoded subject) | Blockchain Commons           |
| `#6.1`   | Epoch time (RFC 8949)        | IETF                         |
| `#6.???` | `recrypt.pre-wrapped-key`    | TBD — private-use until BC feedback ([migration plan OQ1](plans/archive/2026-04-08-gordian-envelope-migration.md#open-questions)) |

Every recrypt envelope is a `#6.200`-tagged value. The subject of
every recrypt envelope is a `#6.201`-tagged dCBOR map containing a
`"type"` field that names the recrypt domain object.

### 2.3 Named predicates

Recrypt uses plain-string assertion predicates for all
recrypt-specific metadata. We use Blockchain Commons' Known Values
(BCR-2023-002, small integers) only for predicates that already
have a BC-standardized meaning:

| Predicate     | Known Value | Source                          |
|---            |---          |---                              |
| `'signed'`    | yes         | BC standard, signature assertion |
| `'note'`      | yes         | BC standard, human-readable comment |
| `'date'`      | yes         | BC standard, timestamp          |
| `'isA'`       | yes         | BC standard, type assertion     |

Everything else — `"backend"`, `"owner"`, `"for-file"`,
`"operations"`, etc. — is a plain UTF-8 string. This is a
deliberate trade-off: BC known values save a few bytes per
assertion but couple our wire format to BC's registry. Plain
strings are more verbose but keep our vocabulary independent.

### 2.4 Subject vs assertions: the design rule

Every recrypt envelope follows a strict rule:

> **Load-bearing integrity anchors live in the subject map.
> Mutable, descriptive, and elidable metadata lives in assertions.**

"Load-bearing" means: the field is required for correctness and
cannot be removed without changing the envelope's meaning.
"Elidable" means: the field can be stripped without breaking
verification, usually for privacy or size.

Subject fields:

- Identify the envelope's **type** (`"type"` field).
- Carry the **format version** so parsers can reject unsupported
  versions before doing work.
- Hold any **content-address / cryptographic anchor** that
  downstream operations depend on (`bao-hash`, `ciphertext-ref`,
  `file-hash`, etc.).

Assertions:

- Carry metadata (`"created"`, `"plaintext-size"`, `"owner"`,
  `"backend"`).
- Carry relationships (`"for-file"`, `"for-recipient"`).
- Carry signatures (`'signed': Signature`).

Any field an attacker might care about reversing — like a 4-value
enum — must be **salted** if it lives in an assertion and is
intended to be elidable in a hostile environment. See §6.

### 2.5 Multi-signature rule

Every signed recrypt envelope carries **two** `'signed'` assertions:
one Ed25519, one ML-DSA-87. The recrypt application-layer invariant
is **"all attached `'signed'` assertions must verify"** — a verifier
that sees only one signature MUST reject the envelope.

This is a recrypt rule, not an Envelope rule. The Envelope standard
allows multiple `'signed'` assertions without mandating any
verification policy across them; the policy is the application's
job. See [threat-model.md](threat-model.md) for the rationale
(defense-in-depth, Ed25519 as identity primitive, acknowledged
security-level asymmetry).

---

## 3. Domain types

The following envelope types are defined. Each is shown in CBOR
diagnostic notation with elidable salted assertions marked
`[salted]`.

### 3.0 Implementation status

| Type                          | Status        | Where implemented                                        |
|-------------------------------|---------------|----------------------------------------------------------|
| `recrypt.encrypted-file`      | ✅ Implemented | `crates/recrypt-wire/src/convert.rs::encrypted_file_to_envelope` |
| `recrypt.identity`            | ✅ Implemented | `crates/recrypt-wire/src/identity.rs`                    |
| `recrypt.pre-wrapped-key`     | 📝 Spec-only  | Carried as a `wrapped-key` assertion on `recrypt.encrypted-file` today; standalone envelope not yet implemented |
| `recrypt.public-key-bundle`   | 📝 Spec-only  | `POST /accounts` body uses ad-hoc JSON; envelope variant not yet implemented |
| `recrypt.capability`          | 📝 Spec-only  | `crates/identikey-storage-auth/src/capability.rs` still uses domain-tagged TLV; envelope migration tracked under recrypt-6aj follow-ups |
| `recrypt.recrypt-key`         | 🚧 Speculative | Held only on the proxy; never crosses an envelope boundary today. Drop from spec unless a concrete export use case appears. |
| `recrypt.secret-key-bundle`   | 🚧 Redundant  | Subsumed by `recrypt.identity` (which already carries secrets when present). Drop from spec. |
| `recrypt.key-material`        | 📝 Documentary| Not an envelope — a 96-byte fixed plaintext layout (see §3.3) |

### 3.1 `recrypt.encrypted-file`

The primary wire payload — represents an encrypted file's metadata,
signatures, and content-address. The actual ciphertext bytes live
in a sidecar S3 object (content-addressed by `bao-hash`). The
wrapped key material lives in a separate envelope (§3.2), discovered
via the auth service on the recipient's behalf.

```
200(                                            ; envelope
  201(                                          ; leaf subject
    {
      "type":           "recrypt.encrypted-file",
      "format-version": 3,
      "bao-hash":       h'...32 bytes...',      ; Bao root of ciphertext
      "ciphertext-ref": h'...32 bytes...'       ; = bao-hash; S3 content address
    }
  )
) [
  [salted] "backend":        "lattice-bfv",
  [salted] "created":        1(1712534400),     ; CBOR tag 1 = epoch time
           "owner":          h'...32 bytes...', ; Blake3(owner Ed25519 pubkey)
  [salted] "plaintext-size": 1048576,
           'signed':         Signature(ed25519, ...),
           'signed':         Signature(ml-dsa-87, ...)
]
```

**Subject fields:**

| Field            | Type     | Meaning                                   |
|---               |---       |---                                        |
| `type`           | string   | Always `"recrypt.encrypted-file"`         |
| `format-version` | u32      | Currently 3; bumped on breaking changes   |
| `bao-hash`       | 32 bytes | Blake3/Bao root hash of the ciphertext    |
| `ciphertext-ref` | 32 bytes | S3 content address (equal to `bao-hash`)  |

`bao-hash` and `ciphertext-ref` are equal in the current design but
kept as separate fields for future-proofing — a future version may
address ciphertext by a different key (e.g., for storage-provider
sharding).

**Assertions:**

| Predicate        | Salted? | Meaning                                                    |
|---               |---      |---                                                          |
| `"backend"`      | YES     | PRE backend: `"lattice-bfv"`, `"ec-pairing"`, `"ec-secp256k1"`, `"mock"` |
| `"created"`      | YES, optional | Epoch time of encryption, CBOR tag 1. Pure UX — the auth service and HTTP layer also know "when did this arrive". Encoders MAY emit; decoders MUST tolerate absence. |
| `"owner"`        | no      | Blake3(owner's Ed25519 pubkey) — the file originator fingerprint |
| `"plaintext-size"` | YES, optional | Original plaintext byte count, for display only. The load-bearing copy lives inside the AEAD-protected `KeyMaterial` (§3.3). Encoders MAY emit; decoders MUST tolerate absence. |
| `'signed'`       | no      | Ed25519 signature over the subject + non-elided assertions  |
| `'signed'`       | no      | ML-DSA-87 signature, same coverage                          |

**What is signed:** the envelope's subject digest plus the digest
of every non-elided assertion at signing time, per Envelope's
signature semantics. Eliding an assertion after signing does not
invalidate the signature because elision replaces the assertion
with its own digest, which is already what the signature committed
to.

**No wrapped-key reference.** The file envelope does **not** contain
a pointer to the wrapped-key envelope. The file envelope is the same
for every recipient and across every recryption, so it never needs
re-issuing. Wrapped-key discovery is the auth service's job; see §5.

### 3.2 `recrypt.pre-wrapped-key`

A PRE-encrypted symmetric-key bundle. One file may have many of
these — one per recipient, and potentially multiple per recipient
(e.g., after key rotation). Wrapped-keys are the thing that *change*
when the recryption proxy does its job.

```
200(
  201(
    {
      "type":           "recrypt.pre-wrapped-key",
      "format-version": 1,
      "backend":        "lattice-bfv",
      "for-recipient":  h'...32 bytes...',      ; Blake3(recipient's PRE pubkey)
      "ciphertext":     h'...backend-specific bytes...'
    }
  )
) [
  [salted] "for-file": h'...32 bytes...',       ; bao-hash of the file this unlocks
  [salted] "level":    0,                        ; 0 = original, 1+ = recrypted
  [salted] "created":  1(1712534400)
  ; NO 'signed' assertions — see §3.2.1
]
```

**Subject fields:**

| Field            | Type     | Meaning                                              |
|---               |---       |---                                                    |
| `type`           | string   | Always `"recrypt.pre-wrapped-key"`                   |
| `format-version` | u32      | Currently 1                                          |
| `backend`        | string   | PRE backend; must match the file envelope's backend  |
| `for-recipient`  | 32 bytes | Blake3(recipient PRE pubkey) — who can decrypt this  |
| `ciphertext`     | bytes    | Backend-specific PRE ciphertext; opaque              |

`backend` lives in the subject here (not an elidable assertion)
because the PRE decryption routine needs to know which backend to
dispatch to — eliding it would break decryption. Contrast with the
file envelope, where `backend` is metadata and is elidable.

**The `ciphertext` field** contains the opaque PRE ciphertext that,
when decrypted by the recipient's PRE secret key, yields a 96-byte
`KeyMaterial` bundle (see §3.3).

**Assertions:**

| Predicate    | Salted? | Meaning                                                  |
|---           |---      |---                                                        |
| `"for-file"` | YES     | Blake3 hash of the file this wrapped-key unlocks          |
| `"level"`    | YES     | 0 for originals, incremented by each recryption           |
| `"created"`  | YES     | Epoch time of wrapping, CBOR tag 1                        |

#### 3.2.1 Why wrapped-keys are unsigned

**Integrity of the wrapped-key is established by successful
decryption and the plaintext-hash check inside the decrypted
KeyMaterial bundle**, not by a signature on the envelope.

The decryption flow is:

1. Recipient fetches the wrapped-key envelope (via auth service
   lookup; §5).
2. Recipient PRE-decrypts `subject.ciphertext` with their PRE
   secret key → 96-byte `KeyMaterial`.
3. Recipient fetches the file's ciphertext bytes from S3 at
   `file.ciphertext-ref`.
4. Recipient XChaCha20-decrypts the ciphertext with
   `KeyMaterial.symmetric_key` and `KeyMaterial.nonce`.
5. Recipient computes `Blake3(plaintext)` and compares to
   `KeyMaterial.plaintext_hash`.

If the wrapped-key has been tampered with or swapped, step 2 either
fails (PRE decryption rejects) or produces garbage KeyMaterial whose
symmetric key doesn't decrypt the file correctly, which step 5 then
catches. The `plaintext_hash` field is **inside the PRE encryption
envelope**, so it cannot be modified by an attacker who does not
hold the recipient's PRE secret key.

This means signing the wrapped-key envelope would add **redundant
integrity, not new integrity**. It would also require the proxy to
hold a signing key — creating a high-value target where none needs
to exist.

**Future work:** we may add `'signed'` assertions to wrapped-key
envelopes later as a **provenance signal, not an integrity
gate** — letting an auditor trace which proxy performed which
recryption. Such signatures would be additive and
backwards-compatible: verifiers that ignore them MUST continue to
get the same answer about whether the wrapped-key is valid. This
rule protects the integrity model from silently shifting.

#### 3.2.2 Why `for-file` is an elidable assertion, not a subject field

An earlier draft of this spec put `"for-file"` in the subject, on
the theory that binding the wrapped-key to its file needed to be
load-bearing. That was wrong: the plaintext-hash check inside the
decrypted KeyMaterial already defeats any "wrong file" confusion
attack (see the decryption flow above).

Making `"for-file"` an elidable salted assertion gives us a
**privacy property**: a wrapped-key envelope in its fully-elided
form reveals nothing about which file it unlocks or when it was
issued. This is useful for:

- Stripping metadata when forwarding a wrapped-key through a
  less-trusted hop.
- "I have *some* access grant" attestations that don't reveal the
  grant's scope.
- Sensitive deployments where the association between a recipient
  and a file-hash is itself confidential.

The salt on `"for-file"` is load-bearing even though the value is
high-entropy: without salt, an observer who suspects the file hash
is `H` can hash `H` and compare to the elided assertion digest.
With salt, they'd need both the salt and `H`, and the salt is gone.

### 3.3 `recrypt.key-material` (documentary only)

Never transmitted on the wire as an envelope. This is the plaintext
structure *inside* the PRE-encrypted `ciphertext` field of a
`recrypt.pre-wrapped-key`. Documented here so the format is
complete.

#### v1 layout (96 bytes total)

```
[0]      version          = 1   (u8)
[1..33]  symmetric_key    = XChaCha20 256-bit key (32 bytes)
[33..57] nonce            = XChaCha20 192-bit nonce (24 bytes)
[57..89] plaintext_hash   = Blake3 of original plaintext (32 bytes)
[89..96] plaintext_size   = u56 little-endian (7 bytes)
```

The 96-byte size is fixed to match
`LatticeBackend::max_plaintext_size()` in the OpenFHE BFV backend.
Other PRE backends MAY have different plaintext capacities; the
KeyMaterial encoding is the same 96 bytes regardless, and PRE
backends with larger plaintext capacity simply use a smaller
fraction of their slot.

#### Why a version byte instead of dCBOR

The first byte is a **version discriminator**. The remaining 95
bytes are interpreted per version. Unknown versions MUST be
rejected with a clear error. This is the entire forward-
compatibility story for KeyMaterial.

We considered dCBOR. Even with the most aggressive encoding
(integer map keys, no `type` field, no version field), the framing
overhead pushes the smallest CBOR encoding past 96 bytes once the
three 32-byte fields are accounted for. The version-byte approach
is ~15 bytes more efficient than CBOR while preserving the only
property we wanted from CBOR (extensibility), and parsing is one
byte then a match statement.

Rest of the recrypt wire format is dCBOR; KeyMaterial is the one
exception. The exception is justified because KeyMaterial:

- Lives inside a fixed-size cryptographic plaintext slot.
- Has no third-party extension story (we control all encoders and
  decoders).
- Is never inspected without first PRE-decrypting it, so
  self-description is irrelevant — the recipient knows it's
  KeyMaterial because that's what the wrapped-key envelope's
  `type` says.

#### Why u56 for `plaintext_size`

Squeezing the version byte requires giving up one byte somewhere.
We took it from `plaintext_size`, dropping it from u64 to u56.
The maximum representable value becomes 2^56 − 1 ≈ 72 PB, which is
wildly larger than [`MAX_ENCRYPT_FILE_SIZE`](../crates/recrypt-core/src/hybrid/mod.rs)
(currently 1 TiB). Encoders MUST reject any plaintext size that
does not fit in u56; in practice this is unreachable because the
streaming encrypt path enforces a much smaller limit.

#### Why `plaintext_size` lives both here and on the file envelope

The file envelope carries `plaintext-size` as a salted, elidable
assertion (§3.1). That copy is for UX and **may be elided for
privacy** — see the privacy note below.

The KeyMaterial copy is **inside the PRE encryption** and is never
exposed to anyone except the recipient who can decrypt the wrapped
key. It exists so the decryption code path can sanity-check the
plaintext size after XChaCha20 decryption without depending on any
envelope assertion that a malicious proxy might have stripped or
tampered with. The `plaintext_hash` already covers integrity (a
truncated plaintext would fail the hash check), but the size check
is a faster failure mode for truncation attacks and it costs us
nothing because the bytes are already inside the PRE envelope.

**Privacy note on the file envelope's `plaintext-size`:** the
salted, elidable assertion is by default elidable so producers can
publish file envelopes that reveal nothing about file size to
observers. This matters because **small `plaintext_size` values are
low-entropy even when salted across many envelopes** — an attacker
who learns a single value can confirm "this file is exactly N
bytes" everywhere it appears, and small files cluster in narrow
ranges that correlate with content type (a thumbnail vs a document
vs a video). Eliding by default gives the producer maximum public
mystery; the recipient still has the size from KeyMaterial after
decryption.

#### Version evolution

To define v2:

1. Choose a new layout for bytes [1..96].
2. Add the version constant to the parser dispatch.
3. Bump the `format-version` of the `recrypt.encrypted-file`
   envelope and document which KeyMaterial versions are valid for
   which envelope versions.

Old encryptors continue producing v1; old decryptors continue
parsing v1; v2 is opt-in for new files. There is no in-place
migration. This is intentional — KeyMaterial is the most
performance-sensitive byte layout in the system and a flag day is
preferable to runtime version negotiation inside the hot path.

### 3.4 `recrypt.public-key-bundle`

A recipient's public keys, bundled for transport. Used during
account registration and when looking up a recipient's keys.

```
200(
  201(
    {
      "type":           "recrypt.public-key-bundle",
      "format-version": 1,
      "ed25519":        h'...32 bytes...',
      "ml-dsa-87":      h'...2592 bytes...',
      "pre-backend":    "lattice-bfv",
      "pre-public":     h'...backend-specific...'
    }
  )
) [
  [salted] "created": 1(1712534400),
           "fingerprint": h'...32 bytes...',   ; Blake3(ed25519) for convenience
  [salted] 'note':    "Alice's primary keypair"
]
```

**Subject fields:**

| Field            | Type     | Meaning                                     |
|---               |---       |---                                           |
| `type`           | string   | Always `"recrypt.public-key-bundle"`        |
| `format-version` | u32      | Currently 1                                  |
| `ed25519`         | 32 bytes | Ed25519 verification key (raw)              |
| `ml-dsa-87`       | bytes    | ML-DSA-87 verification key (~2592 bytes)    |
| `pre-backend`    | string   | PRE backend identifier                       |
| `pre-public`     | bytes    | PRE public key bytes (backend-specific)     |

**Why these fields are in the subject:** all four keys are
load-bearing for verification — you cannot verify a signature
without the corresponding verification key, and you cannot PRE-wrap
a key for a recipient without their PRE public key. Eliding any of
them would produce a bundle that can't do its job.

**`"fingerprint"`** in the assertions is `Blake3(ed25519)` and is
redundant with the subject (a verifier can compute it). It exists
only as a lookup key and UX affordance.

### 3.5 `recrypt.secret-key-bundle`

Same shape as `recrypt.public-key-bundle` with the corresponding
secret keys. **Never transmitted on the wire.** Used only for local
at-rest storage, always wrapped in a password-encrypted envelope
(not specified here — see
[phase-6b-secure-credential-storage.md](plans/2026-01-14-phase-6b-secure-credential-storage.md)).

### 3.6 `recrypt.recrypt-key`

A PRE recryption key — held by the proxy, transported between the
delegator and the proxy when a new sharing relationship is
established. Never published.

```
200(
  201(
    {
      "type":             "recrypt.recrypt-key",
      "format-version":   1,
      "backend":          "lattice-bfv",
      "from-fingerprint": h'...32 bytes...',  ; Blake3(delegator PRE pubkey)
      "to-fingerprint":   h'...32 bytes...',  ; Blake3(delegatee PRE pubkey)
      "key-data":         h'...backend-specific bytes...'
    }
  )
) [
  [salted] "created": 1(1712534400),
           'signed':  Signature(ed25519, ...),   ; signed by the delegator
           'signed':  Signature(ml-dsa-87, ...)
]
```

All subject fields are load-bearing: the proxy needs every one of
them to apply the recryption. The signature is **required** — a
recryption key is a powerful delegation and the proxy MUST verify
the delegator authorized it.

### 3.7 `recrypt.capability`

> **Status (2026-04, epic recrypt-nj1).** Envelope-native rebuild
> landed under recrypt-91h. The legacy domain-tagged TLV signature
> payload is gone; signatures cover the wrapped envelope's subject
> digest. Delegation chain (`parent`) is present in the wire format
> but **chain verification is not yet implemented** — verifying a
> capability with `parent` set checks only the immediate signature.
> Tracked as a follow-up.

A signed, time-limited bearer token granting permissions on a resource.
Issued by a resource's owner (or by a delegating holder), presented by a
grantee to any verifier holding the issuer's public keys. The subject is
intentionally generic — the same envelope shape covers files, keyspaces,
accounts, and any future resource type.

```
200(
  201(
    {
      "type":           "recrypt.capability",
      "format-version": 1,
      "subject":        h'...32 bytes...',     ; resource address
      "subject-kind":   "file"|"keyspace"|"account",
      "granted-to":     h'...32 bytes...',     ; Blake3(grantee Ed25519 pubkey)
      "issuer":         h'...32 bytes...'      ; Blake3(issuer Ed25519 pubkey)
    }
  )
) [
  [salted] "permissions":      ["read", "write"],   ; subset of {read, write, delegate, admin, sign_rotation}
  [salted] "expires-at":       1(1714521600),       ; CBOR tag 1 epoch seconds; absent = no expiry
  [salted] "note":             "research access",
           "parent":           h'...32 bytes...',   ; optional; digest of parent capability's wrap subject
           "ed25519-signature": h'<64 bytes>',
           "mldsa-signature":   h'<~4.6 KB>'        ; optional (PqOptional clients may omit)
]
```

**Subject fields** form the identity triple: which resource, to whom,
from whom (plus the resource kind). These cannot be elided — a
capability without them is meaningless.

**Salted/elidable assertions:**

- `"permissions"` — closed enum is trivially brute-forceable unsalted.
- `"expires-at"` — timestamps are often guessable from context.
- `"note"` — human-readable comments are often short and templated.

**Non-salted assertions:**

- `"parent"` — verifiers walking the delegation chain need the link
  visible; eliding it would defeat chain verification.
- `"ed25519-signature"` / `"mldsa-signature"` — raw-bytes assertions
  rather than bc-envelope's native `'signed'` form, mirroring the
  hybrid pattern used by `Identity::sign_self_hybrid` (bc-envelope's
  `Signature` cannot model ML-DSA). A future migration to native
  `'signed'` for the ed25519 half is straightforward.

Both signature assertions cover the same payload: the wrap envelope's
subject digest, which transitively commits to the inner subject and
all non-elided assertions. dCBOR canonical encoding makes the
payload byte-identical for any equivalent input ordering.

Construction and verification API: see
[`crates/identikey-storage-auth/src/capability.rs`](../crates/identikey-storage-auth/src/capability.rs).
HTTP verification surface: `POST /capabilities/verify` (see
[http-api-reference.md §2.6](http-api-reference.md#26-capabilities)).

### 3.8 HTTP request/response wrappers

The recrypt HTTP API sends and receives bare envelopes as the
request/response body with `Content-Type: application/envelope+cbor`.
Requests that need additional framing (e.g., uploading a file with
its metadata envelope *plus* the ciphertext bytes) use multipart
form encoding with the envelope as one part and the ciphertext as
another. See [http-api-reference.md](http-api-reference.md) for the
endpoint specification.

---

## 4. Signature model

### 4.1 Producer flow

To sign an envelope:

1. Construct the envelope with its subject and all non-signature
   assertions.
2. Call `envelope.add_signatures(&[ed25519_signer, mldsa_signer])`.
3. The Envelope library computes the digest of the subject plus
   all current assertions, signs that digest with each signer,
   and adds one `'signed'` assertion per signature.

The Envelope library handles the digest computation and the
canonical encoding of the signature input. Implementations MUST use
the library's high-level API, not hand-computed signature inputs,
to avoid drift from the canonical form.

### 4.2 Verifier flow

To verify an envelope:

1. Check `subject.type` and `subject.format-version` — reject
   unknown or unsupported values early.
2. Count `'signed'` assertions. If fewer than 2, reject with
   "missing required signature."
3. For each `'signed'` assertion, identify the signature algorithm
   from its content and verify it against the appropriate
   verification key.
4. If any signature fails, reject the entire envelope.
5. If exactly one of {Ed25519, ML-DSA-87} is present and the other
   is missing, reject — both are required.
6. If verification succeeds, the envelope is trusted.

The "all attached signatures must verify + both Ed25519 and
ML-DSA-87 must be present" policy is recrypt-specific. A pure
Envelope verifier with no recrypt knowledge would accept an
envelope with only an Ed25519 signature; recrypt verifiers must
apply the stricter rule.

### 4.3 Elision and signatures

Elision replaces an assertion (or a subject subtree) with its
32-byte Blake3 digest. The signature continues to verify because
the signed digest was already the assertion's digest.

**Elision rules for recrypt envelopes:**

- The **subject** may never be elided. Subject fields are
  load-bearing for correctness.
- Any assertion marked `[salted]` in §3 MAY be elided by any
  holder of the envelope without invalidating signatures.
- An assertion NOT marked `[salted]` MUST NOT be elided — it's
  either a signature (whose elision would destroy verification) or
  a high-entropy field whose elision is meaningful and already
  covered by the dCBOR digest.
- A verifier receiving a partially-elided envelope MUST verify it
  exactly as it would a non-elided envelope. Elision is invisible
  to the verification routine.

See §6 for the salting / brute-force analysis.

---

## 5. The auth service and wrapped-key discovery

The `identikey-storage-auth` crate indexes wrapped-key envelopes
and answers the question "which wrapped-key should this recipient
fetch for this file?" It does not mint wrapped-keys itself; the
proxy does that.

The index is keyed on `(file_hash, recipient_fingerprint) →
wrapped_key_location`. When a recipient wants to decrypt a file:

1. Recipient fetches the file envelope from storage (content-
   addressed by `file_hash`).
2. Recipient verifies the file envelope's signatures (§4.2).
3. Recipient queries the auth service:
   `lookup(file_hash, my_fingerprint) → wrapped_key_location`.
4. Recipient fetches the wrapped-key envelope from the returned
   location.
5. Recipient proceeds with the decryption flow in §3.2.1.

If the lookup fails (no wrapped-key exists for this recipient), the
auth service returns an error and the recipient has no access. If
the lookup returns a wrapped-key for a *different* file, the
recipient's decryption will fail at the plaintext-hash check,
preventing confusion attacks regardless of whether the auth service
is honest.

**The auth service is trusted for availability, not for
confidentiality.** A malicious auth service can deny access but
cannot grant it (the wrapped-key still needs to PRE-decrypt under
the recipient's secret key) and cannot tamper with file contents
(the file envelope's signature covers the bao-hash). This is the
separation of concerns that the migration plan's architectural
commitment preserves.

---

## 6. Salting policy

Elision alone is not sufficient privacy for low-entropy fields. An
attacker who sees the digest of an elided assertion and knows the
predicate can enumerate the preimage space, encode each candidate
as canonical dCBOR, hash, and compare. For a 4-value enum, this
takes microseconds.

Recrypt addresses this by **salting** any elidable assertion whose
object has fewer than ~80 bits of effective entropy OR where
unsalted elision would leak unlinkability.

### 6.1 Which assertions are salted

See the per-type tables in §3. The rule is:

| Entropy / Use Case                  | Salted? |
|---                                   |---      |
| Enum with < 2^20 values              | YES     |
| Timestamp                            | YES     |
| Byte-count or size (often guessable) | YES     |
| Human-readable text (templated)      | YES     |
| Hash or fingerprint (high entropy)   | no, unless unlinkability matters |
| Signature bytes                      | no      |
| Subject field                        | n/a — never elided |

The one unusual case is `"for-file"` on wrapped-key envelopes: the
value is a 32-byte hash (high entropy), but salt is still used
because the unlinkability property matters (see §3.2.2).

### 6.2 Salt generation

Salts MUST be drawn freshly from a CSPRNG per assertion. They MUST
NOT be:

- Derived from the assertion value (defeats the purpose).
- Reused across assertions within a single envelope.
- Reused across envelopes for the "same" value (would let an
  attacker who learns the value once confirm it for all others).

`bc-envelope`'s `add_assertion_salted` API does the right thing by
default. Implementations that construct salted assertions by any
other path MUST independently verify these properties.

### 6.3 What salting does not protect against

Salting prevents brute-force reversal of an *individual* elided
assertion's value. It does not protect against:

- **Traffic analysis.** An observer who sees which wrapped-key is
  fetched for which recipient learns the access graph, even if
  the wrapped-key's contents are fully elided.
- **Timing correlation.** Create-time gaps, access patterns, and
  similar side channels are out of scope for the wire format and
  must be handled at higher layers if they matter.
- **Known-plaintext forgery.** Salted elision is about privacy,
  not integrity. Integrity comes from signatures and (for
  wrapped-keys) the plaintext-hash check.

---

## 7. Benchmarks and sizing

Measured 2026-04-09 against `recrypt-wire` 0.1.0 with
`bc-envelope` 0.43.0.

### 7.1 Envelope size (NFR-2)

| Scenario                 | Payload  | Envelope | Overhead | Overhead % |
|---                       |---       |---       |---       |---         |
| Metadata-only (server)   | 0 B      | 155 B    | 155 B    | n/a        |
| 1 KB ct + 128 B wk       | 1,152 B  | 1,329 B  | 177 B    | 15.4%      |
| 64 KB ct + 4 KB wk       | 69,632 B | 69,816 B | 184 B    | 0.3%       |
| 1 MB ct + 4 KB wk        | ~1 MB    | ~1 MB    | 181 B    | 0.02%      |

**NFR-2 verdict: PASS.** Metadata-only envelope is 155 bytes
(threshold: < 2 KB). Overhead for 1 MB+ files is 0.02%
(threshold: < 5%). Framing overhead is essentially constant at
~155–184 bytes regardless of payload size.

### 7.2 Dependency surface (NFR-3)

| Metric                           | Count |
|---                               |---    |
| `recrypt-wire` direct deps       | 10    |
| `bc-envelope` transitive tree    | 428   |

`bc-envelope` pulls a large transitive tree (crypto primitives,
CBOR, UR, SSH key support, SSKR), but many transitive deps are
shared with our existing crypto stack (ed25519-dalek, blake3, rand,
etc.), so the net new count is lower than 428 suggests. The 10
direct deps are reasonable.

### 7.3 Build and test time (NFR-4, NFR-5)

| Metric                                | Time     |
|---                                    |---       |
| `cargo build -p recrypt-wire --release` | 40s    |
| `cargo test -p recrypt-wire`           | 1.1s    |

The build time is dominated by `oqs-sys` (liboqs C library)
compilation. The test time (1.1s) includes 21 tests across 5 test
files.

### 7.4 Recryption hot path (NFR-1)

The recryption proxy hot path (parse envelope → PRE transform →
re-serialize) adds ~155 bytes of CBOR framing work on top of the
PRE transform itself, which is negligible compared to the PRE
transform's millisecond-scale latency. The
`crates/recrypt-core/benches/crypto_ops.rs` benchmarks measure the
PRE transform; dedicated criterion benchmarks for envelope
parse/serialize remain a follow-up.

---

## 8. ASCII armor

ASCII armor is a PGP-style wrapper around envelope bytes for
human-touchable workflows (copy-paste, email, printed backups).

```
----- BEGIN RECRYPT ENVELOPE -----
Type: recrypt.public-key-bundle
Version: 1
Format: envelope+cbor

<base64-encoded envelope bytes>
----- END RECRYPT ENVELOPE -----
```

The armor types currently defined:

| Armor type           | Envelope type inside                |
|---                   |---                                   |
| `RECRYPT ENVELOPE`   | Any — the inner `type` disambiguates |
| `RECRYPT PUBLIC KEY` | `recrypt.public-key-bundle`         |
| `RECRYPT SECRET KEY` | `recrypt.secret-key-bundle` (password-wrapped) |
| `RECRYPT CAPABILITY` | `recrypt.capability`                 |

Implementations MAY use the generic `RECRYPT ENVELOPE` banner for
everything; the type-specific banners exist for UX clarity in
workflows where users see the armor directly.

---

## 9. UR (Uniform Resources)

Deferred. [Blockchain Commons UR](https://developer.blockchaincommons.com/ur/)
is a text encoding for CBOR that plays well with QR codes and
sneakernet workflows. Because Envelope is CBOR, every recrypt
envelope can be serialized as a UR:

```
ur:envelope/<bytewords-encoded envelope bytes>
```

We do not support UR in the initial migration. A follow-up pass
will add it once the core migration is shipped. The Envelope
library already handles UR encoding — adoption is mostly plumbing.

---

## 10. Versioning and evolution

### 10.1 The `format-version` field

Every recrypt envelope carries a `format-version` integer in its
subject. Current values:

| Envelope type                  | Current version |
|---                             |---               |
| `recrypt.encrypted-file`       | 3               |
| `recrypt.pre-wrapped-key`      | 1               |
| `recrypt.public-key-bundle`    | 1               |
| `recrypt.secret-key-bundle`    | 1               |
| `recrypt.recrypt-key`          | 1               |
| `recrypt.capability`           | 1               |

Parsers MUST check the version before any other field access and
reject unsupported versions with a specific error.

### 10.2 Adding fields

- **New assertions** are additive. Old parsers ignore unknown
  predicates. No version bump required.
- **New subject fields** require a version bump because old
  parsers may reject unknown subject keys (and should, for
  safety). Bump the version integer and document the change.
- **Renaming or removing** a subject field is a breaking change.
  Bump to a new major version integer and retain the old parser
  for a migration window.

### 10.3 Adding domain types

Introduce a new `type` string in the subject. Register it in this
document's §3. No version interaction with existing types — new
types are orthogonal.

### 10.4 Signature scheme changes

Adding a new signature algorithm (e.g., Falcon or SLH-DSA as a
third hybrid component) would require updating the "two signatures
required" rule in §4.2. That's a verifier change, not a format
change per se — the envelope structure already accommodates
multiple `'signed'` assertions. Treat it as a version bump on
every signed type.

---

## 11. References

- [Gordian Envelope Developer Resources](https://developer.blockchaincommons.com/envelope/)
- [`draft-mcnally-envelope`](https://blockchaincommons.github.io/WIPs-IETF-draft-envelope/draft-mcnally-envelope.html) — IETF draft specification
- [BCR-2023-013: Gordian Envelope Cryptography](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2023-013-envelope-crypto.md)
- [BCR-2023-002: Known Values](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2023-002-known-value.md)
- [BCR-2025-003: Post-Quantum CBOR Tags](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2025-003-post-quantum.md)
- [dCBOR / CBOR Deterministic Encoding](https://cborbook.com/part_2/cbor_cde_dcbor.html)
- [RFC 8949: CBOR](https://datatracker.ietf.org/doc/html/rfc8949)
- [RFC 8610: CDDL](https://datatracker.ietf.org/doc/html/rfc8610)
- [Bao specification](https://github.com/oconnor663/bao/blob/master/docs/spec.md)
- [XChaCha20+Bao AEAD spec (this repo)](standards/xchacha20-bao-aead.md)
- [Envelope sketch spike](plans/archive/2026-04-08-envelope-sketch.md)
- [Threat model](threat-model.md)
- [Encoding conventions](standards/encoding-conventions.md) — when to use raw bytes vs base58 vs base64
