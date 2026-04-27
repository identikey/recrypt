# Wallet Serialization: Gordian Envelope Format

**Status:** ✅ Stable
**Date:** 2026-04-09 (proposal); stabilized 2026-04-27
**Implementation:** `recrypt-cli/src/wallet/envelope.rs` (encode/decode), `recrypt-cli/src/wallet/format.rs` (outer encryption shell)
**Supersedes:** The JSON-in-XChaCha20-Poly1305 wallet format in `recrypt-cli/src/wallet/format.rs`
**Follows:** [wire-protocol.md](../wire-protocol.md) conventions (subject/assertion rule, salting policy, multi-sig)

---

## 1. Overview

The wallet stores a user's identity material: signing keys, PRE key pairs, and operational state (active identity, preferences). It lives on the user's local filesystem, encrypted at rest.

The new format is a Gordian Envelope wrapped in an **outer encryption shell**. The envelope carries structured identity data as assertions; the shell provides password-based authenticated encryption.

```
File on disk:
  MAGIC ("IKEYW") || version (2) || salt (32B) || nonce (24B)
  || XChaCha20-Poly1305(
       Gordian Envelope bytes (dCBOR)
     )
```

The outer shell uses the same Argon2id parameters and same AEAD as v1; the magic ("IKEYW", short for Identikey Wallet) and version byte both change to make v1→v2 wallets unambiguously distinct on sight, and the plaintext payload changes from JSON to a Gordian Envelope.

---

## 2. Why Envelope inside the encryption shell

The wallet is always encrypted at rest. Why not just use a flat CBOR map?

1. **Consistency with the wire format.** Every other recrypt domain type is an envelope. The wallet should speak the same language.
2. **Selective disclosure.** A future "wallet summary" feature can elide secret keys and share the envelope (e.g., for backup verification: "yes, this wallet contains 3 identities" without exposing key material).
3. **Signable.** The wallet can carry a self-signature — the owner signs the wallet state to detect tampering after decryption.
4. **Extensible.** Adding new fields (keyspace memberships, delegated capabilities, preferences) is just adding assertions. No schema migration, no version bump needed for additive changes.

---

## 3. Envelope structure

Shown in CBOR diagnostic notation, following [wire-protocol.md](../wire-protocol.md) conventions.

### 3.1 Top-level wallet envelope

```
200(                                              ; envelope
  201(                                            ; leaf subject
    {
      "type":           "recrypt.wallet",
      "format-version": 2
    }
  )
) [
  "active-identity": "alice",                     ; name of the active identity (or elided)
  "identity":        <recrypt.identity envelope>,  ; one per identity
  "identity":        <recrypt.identity envelope>,  ; repeated
  'signed':          Signature(ed25519, ...),      ; optional: self-integrity check
  'signed':          Signature(ml-dsa-87, ...)     ; optional: self-integrity check
]
```

**Subject fields:**

| Field            | Type   | Meaning                           |
|------------------|--------|-----------------------------------|
| `type`           | string | Always `"recrypt.wallet"`         |
| `format-version` | u32    | `2` for this format               |

**Assertions:**

| Predicate           | Salted? | Type            | Meaning                                    |
|----------------------|---------|-----------------|--------------------------------------------|
| `"active-identity"`  | no      | string          | Name of the currently active identity      |
| `"identity"`         | no      | nested envelope | One `recrypt.identity` envelope per identity |
| `'signed'`           | no      | Signature       | Optional self-integrity signature (Ed25519) |
| `'signed'`           | no      | Signature       | Optional self-integrity signature (ML-DSA)  |

**Notes:**
- Multiple `"identity"` assertions are expected (one per identity in the wallet).
- Salting is unnecessary — the wallet is encrypted at rest. The envelope is never shared in elided form in normal operation.
- Self-signatures are optional. When present, they use the active identity's signing keys. This detects corruption after decryption (bitrot, truncated write) but is not a security boundary — the attacker who can modify the encrypted wallet file can also re-encrypt a modified version.

### 3.2 Identity envelope

Each identity is a nested envelope:

```
200(
  201(
    {
      "type":           "recrypt.identity",
      "format-version": 1,
      "fingerprint":    h'...32 bytes...'          ; Blake3(ed25519 pubkey)
    }
  )
) [
  "name":             "alice",
  "created":          1(1712534400),               ; CBOR tag 1 = epoch time

  ; === Signing keys ===
  "ed25519-public":   h'...32 bytes...',
  "ed25519-secret":   h'...32 bytes...',
  "ml-dsa-public":    h'...2592 bytes...',         ; ML-DSA-87 public key
  "ml-dsa-secret":    h'...4896 bytes...',         ; ML-DSA-87 secret key

  ; === PRE keys ===
  "pre-backend":      "mock",                      ; or "lattice-bfv"
  "pre-public":       h'...backend-specific...',
  "pre-secret":       h'...backend-specific...',
]
```

**Subject fields:**

| Field            | Type     | Meaning                                       |
|------------------|----------|-----------------------------------------------|
| `type`           | string   | Always `"recrypt.identity"`                   |
| `format-version` | u32      | `1` for this format                           |
| `fingerprint`    | 32 bytes | Blake3(ed25519 public key) — content address  |

The fingerprint is in the subject because it's the identity's content address — the immutable anchor that other systems reference. It MUST match `Blake3(ed25519-public)`.

**Assertions:**

| Predicate          | Type     | Meaning                                              |
|--------------------|----------|------------------------------------------------------|
| `"name"`           | string   | Human-readable name ("alice", "work-laptop")         |
| `"created"`        | tagged   | CBOR tag 1 epoch time                                |
| `"ed25519-public"` | bytes    | Ed25519 verifying key (32 bytes)                     |
| `"ed25519-secret"` | bytes    | Ed25519 signing key (32 bytes)                       |
| `"ml-dsa-public"`  | bytes    | ML-DSA-87 public key (raw bytes)                     |
| `"ml-dsa-secret"`  | bytes    | ML-DSA-87 secret key (raw bytes)                     |
| `"pre-backend"`    | string   | PRE backend identifier (`"mock"`, `"lattice-bfv"`)   |
| `"pre-public"`     | bytes    | PRE public key (backend-specific, raw bytes)         |
| `"pre-secret"`     | bytes    | PRE secret key (backend-specific, raw bytes)         |

---

## 4. Key encoding: raw bytes, not base58/base64

All keys are stored as **raw byte strings** (CBOR major type 2). No base58. No base64. The wallet is encrypted at rest — there is no need for a human-readable encoding of the key material inside it.

This eliminates the encoding inconsistency in the v1 format (ed25519/ml-dsa in base58, PRE in base64) and removes a class of bugs entirely.

Base58 and base64 remain the right choice for:
- **Display/export** (`identity show`, ASCII armor, QR codes)
- **Wire protocol** (HTTP headers, JSON API responses)
- **Fingerprints** in user-facing contexts

But inside the encrypted wallet, raw bytes are correct.

### 4.1 Large key encoding performance

ML-DSA-87 keys are large (~2.5 KB public, ~4.9 KB secret). OpenFHE lattice PRE keys can be larger. Base58 encoding of multi-KB values is computationally expensive (O(n^2) with bignum arithmetic). Raw bytes in CBOR are O(n) — a length prefix followed by the bytes.

---

## 5. Outer encryption shell

The file-on-disk format wraps the envelope in an authenticated encryption shell:

```
Offset  Size  Field
0       5     Magic bytes: "IKEYW"
5       1     Shell version: 2
6       32    Salt (random, for Argon2id)
38      24    Nonce (random, for XChaCha20-Poly1305)
62      var   Ciphertext + Poly1305 tag (16 bytes)
```

**Shell version 2** signals that the plaintext is a Gordian Envelope (dCBOR), not JSON. Parsers that see version 1 know the payload is JSON; version 2 is dCBOR.

**KDF:** Argon2id with OWASP-recommended parameters:
- Memory: 64 MiB (`m = 65536`)
- Iterations: 3 (`t = 3`)
- Parallelism: 4 (`p = 4`)
- Output: 32 bytes

**AEAD:** XChaCha20-Poly1305 (same as v1).

**Key caching:** The derived 32-byte key is cached in the OS keychain (macOS Keychain, Linux Secret Service, Windows Credential Manager) keyed by `wallet-key-{blake3(wallet_path)[..16]}`. See [credential.rs](../recrypt-cli/src/wallet/credential.rs) for the `CredentialProvider` trait.

---

## 6. Determinism and round-trip guarantee

The wallet envelope MUST produce byte-identical output when re-serialized without modification. This is guaranteed by dCBOR's deterministic encoding rules (see [wire-protocol.md §2.1](../wire-protocol.md#21-dcbor)).

However, a **save-after-load without changes** will NOT produce an identical *file* because the outer shell uses a fresh random nonce on every write. The envelope bytes inside the ciphertext are identical; the ciphertext itself differs. This is by design — nonce reuse in XChaCha20-Poly1305 is catastrophic.

---

## 7. Migration from v1

No migration needed per project policy — there are no deployed wallets worth preserving. The v1 format is retired entirely.

For robustness during development:
- `Wallet::load()` checks the shell version byte.
- Version 1: reject with a clear error: "Wallet format v1 is no longer supported. Create a new wallet with `recrypt identity new`."
- Version 2: deserialize envelope.
- Unknown versions: reject with "Unsupported wallet version: N".

---

## 8. Extension points

These assertions can be added later without a format-version bump (additive changes):

| Future assertion       | Type            | Purpose                                                |
|------------------------|-----------------|--------------------------------------------------------|
| `"keyspace-membership"` | nested envelope | Track which keyspaces this identity belongs to         |
| `"delegated-capability"` | nested envelope | Cached capability tokens for offline use              |
| `"preference"`          | string/map      | UI preferences (default server, output format)        |
| `"backup-metadata"`     | map             | Last backup time, backup provider, verification hash  |
| `"recovery-share"`      | bytes           | SSS share for key recovery                            |

A wallet created by a newer client must remain readable AND writable by an older client without losing the newer assertions. The wire/wallet decoder collects any wallet-level or identity-level assertion whose predicate is not in its `KNOWN_PREDICATES` list into an `unknown_assertions` field, and re-emits it verbatim on encode. This means an older client can `load → save` a newer wallet and the additive assertions survive. (Implementations that simply "ignore" unknown assertions on parse — without preserving them on re-encode — silently break forward-compat on the next save.) This is the forward-compatibility property that protobuf and JSON both struggle with for encrypted payloads.

---

## 9. Size estimates

| Component                     | Approximate size |
|-------------------------------|-----------------|
| Wallet envelope overhead      | ~50 bytes       |
| Identity envelope (mock PRE)  | ~250 bytes      |
| Identity envelope (lattice PRE) | ~10 KB (dominated by OpenFHE key size) |
| Typical wallet (3 identities, mock) | ~850 bytes  |
| Typical wallet (1 lattice identity) | ~10.5 KB    |
| Outer shell overhead          | 61 bytes fixed  |

All well within the "instant load" performance envelope. No lazy loading or streaming needed.

---

## 10. Implementation

The encode/decode lives in `recrypt-cli/src/wallet/envelope.rs` as two free
functions (the wallet stays free of `recrypt-wire` dependencies — see epic
design notes). The outer encryption shell in `recrypt-cli/src/wallet/format.rs`
dispatches into them in place of the previous `serde_json::{to_vec, from_slice}`
calls.

```rust
// recrypt-cli/src/wallet/envelope.rs

pub fn to_envelope(wallet: &WalletData) -> Result<Vec<u8>>;
pub fn from_envelope(bytes: &[u8]) -> Result<WalletData>;

fn wallet_to_envelope(wallet: &WalletData) -> Result<Envelope> {
    let mut subject = Map::new();
    subject.insert("type", "recrypt.wallet");
    subject.insert("format-version", 2_u32);

    let mut envelope = Envelope::new(CBOR::from(subject));

    if let Some(ref active) = wallet.active_identity {
        envelope = envelope.add_assertion("active-identity", active.as_str());
    }

    // Identities iterated in name-sorted order so the encoded bytes are stable
    // across runs even though HashMap iteration order isn't.
    let mut names: Vec<&String> = wallet.identities.keys().collect();
    names.sort();
    for name in names {
        let id_envelope = identity_to_envelope(name, &wallet.identities[name])?;
        envelope = envelope.add_assertion("identity", id_envelope);
    }

    Ok(envelope)
}

fn identity_to_envelope(name: &str, id: &Identity) -> Result<Envelope> {
    // The fingerprint MUST equal Blake3(ed25519-public). We verify on both
    // encode (catch construction errors) and decode (catch tampering).
    let expected = blake3::hash(&id.ed25519.public);
    if id.fingerprint != *expected.as_bytes() {
        return Err(anyhow!("fingerprint does not match Blake3(ed25519-public)"));
    }

    let mut subject = Map::new();
    subject.insert("type", "recrypt.identity");
    subject.insert("format-version", 1_u32);
    subject.insert("fingerprint", ByteString::from(id.fingerprint.to_vec()));

    Ok(Envelope::new(CBOR::from(subject))
        .add_assertion("name", name)
        .add_assertion("created", CBOR::to_tagged_value(Tag::with_value(1), id.created_at))
        .add_assertion("ed25519-public", ByteString::from(id.ed25519.public.clone()))
        .add_assertion("ed25519-secret", ByteString::from(id.ed25519.secret.clone()))
        .add_assertion("ml-dsa-public",  ByteString::from(id.ml_dsa.public.clone()))
        .add_assertion("ml-dsa-secret",  ByteString::from(id.ml_dsa.secret.clone()))
        .add_assertion("pre-backend",    id.pre_backend.to_string())
        .add_assertion("pre-public",     ByteString::from(id.pre.public.clone()))
        .add_assertion("pre-secret",     ByteString::from(id.pre.secret.clone())))
}
```

The outer shell (encryption/decryption) in `wallet/format.rs` reads the
version byte before deriving the Argon2 key, returning the §7 v1 rejection
string immediately if `version == 1` to avoid wasting a 64-MiB derivation
on a definitely-incompatible file.

---

## See also

- [Wire Protocol](../wire-protocol.md) — conventions this format follows
- [dCBOR Determinism](dcbor-determinism.md) — interop contract for identity envelope serialization
- [Encoding Conventions](encoding-conventions.md) — normative rules for raw bytes / base58 / base64 / hex
- [Security Tiers](../security-tiers.md) — keyspace membership and capability extensions
- [Identity Self-Signature](identity-self-signature.md) — spec for `sign_self_ed25519` / `verify_self_signature_ed25519`
