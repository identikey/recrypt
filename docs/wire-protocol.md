# Wire Protocol: Multiple Serialization Formats

**Status:** ✅ IMPLEMENTED (Protobuf + Armor full; JSON for `EncryptedFile` only)
**Authoritative schema:** [`crates/recrypt-proto/proto/recrypt.proto`](../crates/recrypt-proto/proto/recrypt.proto) — this
document is derived from the proto and must be kept in sync with it.

For the HTTP endpoints that consume these messages, see
[http-api-reference.md](http-api-reference.md). For the broader architectural
role of `recrypt-proto`, see [architecture.md §3](architecture.md#3-per-crate-responsibilities).

---

## 1. Supported formats

| Format       | Primary use              | Content-Type             | Status              |
| ------------ | ------------------------ | ------------------------ | ------------------- |
| Protobuf     | Wire protocol, storage   | `application/x-protobuf` | ✅ Full              |
| ASCII armor  | Human export, key backup | `text/plain`             | ✅ Full              |
| JSON         | API responses, debugging | `application/json`       | ✅ `EncryptedFile`   |

Selection rationale:

- **Protobuf** — compact, schema-driven, forward-compatible via field numbers.
  Default for client ↔ server and blob storage.
- **ASCII armor** — PGP-style, copy-pasteable. Used for key export/import and
  manual backup workflows.
- **JSON** — universal tooling, debuggable. Currently only
  `EncryptedFile` has a full JSON implementation. Other types that need JSON
  transport fall back to base58/base64-wrapped protobuf.

---

## 2. Protobuf schema

The authoritative schema is `crates/recrypt-proto/proto/recrypt.proto`. The
generated Rust types live at `crates/recrypt-proto/src/generated/recrypt.v1.rs`
and are re-exported as `recrypt_proto::proto`.

Package: **`recrypt.v1`** (any future breaking changes will use `v2`, etc.)

### 2.1 Enums

```protobuf
enum BackendId {
    BACKEND_UNKNOWN      = 0;
    BACKEND_LATTICE      = 1;   // OpenFHE BFV, post-quantum (default)
    BACKEND_EC_PAIRING   = 2;   // classical, reserved
    BACKEND_EC_SECP256K1 = 3;   // classical, reserved
    BACKEND_MOCK         = 255; // testing only, NOT secure
}
```

### 2.2 Core crypto types

```protobuf
message PublicKeyBundle {
    uint32 version              = 1;
    bytes  ed25519_key          = 2;   // 32 bytes
    repeated PqPublicKey pq_keys = 3;   // typically one ML-DSA-87 entry
    BackendId pre_backend       = 4;
    bytes  pre_public_key       = 5;   // backend-specific serialization
}

message PqPublicKey {
    string algorithm = 1;   // e.g. "ML-DSA-87"
    bytes  key_data  = 2;
}

message SecretKeyBundle {
    uint32 version              = 1;
    bytes  ed25519_key          = 2;
    repeated PqSecretKey pq_keys = 3;
    BackendId pre_backend       = 4;
    bytes  pre_secret_key       = 5;
}

message PqSecretKey {
    string algorithm = 1;
    bytes  key_data  = 2;
}

message RecryptKeyProto {
    uint32    version                  = 1;
    BackendId backend                  = 2;
    bytes     from_pubkey_fingerprint  = 3;   // Blake3 of delegator pubkey
    bytes     to_pubkey_fingerprint    = 4;   // Blake3 of recipient pubkey
    bytes     key_data                 = 5;   // backend-specific serialization
}

message CiphertextProto {
    BackendId backend = 1;
    uint32    level   = 2;   // 0 = original, 1+ = recrypted
    bytes     data    = 3;   // backend-specific ciphertext
}
```

### 2.3 Encrypted file — the primary wire payload

```protobuf
message EncryptedFileProto {
    uint32              version      = 1;   // format version (currently 3)
    CiphertextProto     wrapped_key  = 2;   // PRE-encrypted KeyMaterial
    bytes               bao_hash     = 3;   // 32-byte Bao root over ciphertext
    bytes               ciphertext   = 4;   // XChaCha20-encrypted data
    MultiSignatureProto signature    = 5;   // signs (wrapped_key || bao_hash)
}
```

**Version 3 change:** The outboard has moved out of the envelope. For files
> 16 KiB, it is stored as a sibling object in S3-compatible storage (key
suffix `.obao`), fetched separately, and kept out-of-band during verification.
Files ≤ 16 KiB contain no outboard (single Bao chunk group = root). This is
a breaking wire-format change from v2; no stored v2 data exists anywhere, so
field numbers were renumbered rather than reserved.

See §4 for the role of `bao_hash` and the verification architecture.

### 2.4 Key material — documentary only (never transmitted)

```protobuf
// NOT serialized on the wire. This message documents what lives inside
// wrapped_key after PRE decryption. Layout is fixed at 96 bytes to match
// LatticeBackend::max_plaintext_size().
message KeyMaterialProto {
    bytes  symmetric_key  = 1;   // 32 bytes — XChaCha20 key
    bytes  nonce          = 2;   // 24 bytes — XChaCha20 nonce
    bytes  plaintext_hash = 3;   // 32 bytes — Blake3(plaintext)
    uint64 plaintext_size = 4;   //  8 bytes — original file size
}
```

`plaintext_hash` is carried *inside* `wrapped_key` specifically so that
possessing a ciphertext does not reveal anything about the plaintext.
A recipient verifies it only after decrypting both the wrapped key and
the ciphertext.

### 2.5 Signatures

```protobuf
message MultiSignatureProto {
    bytes ed25519_signature                = 1;   // 64 bytes
    repeated PqSignatureProto pq_signatures = 2;   // typically one ML-DSA-87 entry
}

message PqSignatureProto {
    string algorithm = 1;   // "ML-DSA-87"
    bytes  signature = 2;
}
```

Both signatures must verify for a multi-sig to be accepted. See
[http-api-reference.md §1](http-api-reference.md) for the dual-stack
rationale and the canonical message strings that are signed.

### 2.6 File metadata and chunks

```protobuf
message FileMetadata {
    uint32    version           = 1;
    bytes     file_hash         = 2;   // Blake3 of ciphertext (content address)
    uint64    total_size        = 3;
    uint64    created_at        = 4;   // unix seconds
    bytes     owner_fingerprint = 5;   // Blake3(owner_ed25519_pk)
    BackendId backend           = 6;   // PRE backend used
}

message ChunkProto {
    uint32 index     = 1;
    bytes  data      = 2;   // encrypted chunk bytes
    bytes  bao_proof = 3;   // optional Bao slice proof (see §4)
}
```

### 2.7 Capabilities

```protobuf
message CapabilityProto {
    uint32              version            = 1;
    bytes               file_hash          = 2;
    bytes               granted_to         = 3;   // recipient fingerprint
    repeated string     operations         = 4;   // "read" | "write" | "delete" | "share"
    uint64              expires_at         = 5;   // unix seconds (0 = never)
    bytes               issuer_fingerprint = 6;   // who granted this
    MultiSignatureProto signature          = 7;   // over all fields above
}
```

### 2.8 API request/response wrappers

```protobuf
message UploadRequest {
    FileMetadata metadata         = 1;
    repeated ChunkProto chunks    = 2;
}

message DownloadResponse {
    FileMetadata metadata         = 1;
    repeated string chunk_urls    = 2;
}

message RecryptRequest {
    bytes file_hash      = 1;
    bytes recrypt_key_id = 2;
}

message RecryptResponse {
    CiphertextProto new_wrapped_key = 1;
}
```

---

## 3. The `MultiFormat` trait

`recrypt-proto` exposes a single trait for all supported serialization formats:

```rust
pub trait MultiFormat: Sized {
    fn proto_name() -> &'static str;

    fn to_protobuf(&self) -> ProtoResult<Vec<u8>>;
    fn from_protobuf(bytes: &[u8]) -> ProtoResult<Self>;

    fn to_json(&self) -> ProtoResult<String>;
    fn from_json(s: &str) -> ProtoResult<Self>;

    fn to_armor(&self, armor_type: ArmorType) -> ProtoResult<String>;
    fn from_armor(s: &str) -> ProtoResult<Self>;

    /// Auto-detect format and deserialize.
    fn from_any(data: &[u8]) -> ProtoResult<Self>;
}
```

### 3.1 Format auto-detection

```rust
pub fn detect_format(data: &[u8]) -> Format {
    if data.starts_with(b"----- BEGIN RECRYPT") {
        Format::Armor
    } else if data.first() == Some(&b'{') {
        Format::Json
    } else {
        Format::Protobuf
    }
}
```

This is a heuristic, not a guarantee — malicious input could be ambiguous.
It exists for convenience on input paths that want to accept "whatever the
user pasted". Security-sensitive code paths should pin the expected format.

### 3.2 Current implementation coverage

| Type                 | Protobuf | JSON | Armor | Notes                                              |
| -------------------- | :------: | :--: | :---: | -------------------------------------------------- |
| `EncryptedFile`      | ✅        | ✅   | ✅    | Fully implemented in `impls.rs`                    |
| `PublicKeyBundle`    | ✅        | —    | ✅    | JSON would wrap base64'd proto                     |
| `SecretKeyBundle`    | ✅        | —    | ✅    | JSON would wrap base64'd proto                     |
| `RecryptKeyProto`    | ✅        | —    | ✅    | JSON would wrap base64'd proto                     |
| `CapabilityProto`    | ✅        | —    | ✅    | JSON would wrap base64'd proto                     |
| `FileMetadata`       | ✅        | —    | —    | Proto only                                         |
| `ChunkProto`         | ✅        | —    | —    | Proto only                                         |

Broader JSON and `MultiFormat` coverage for the other types is a planned
follow-up; today, the primary wire format is Protobuf across the board.

---

## 4. Integrity verification: Blake3 + Bao

### 4.1 What's in `EncryptedFile`

Every `EncryptedFile` carries two integrity-related fields that are computed
together at encryption time:

```rust
let (bao_outboard, bao_hash) = bao::encode::outboard(&ciphertext);
```

- **`bao_hash`** is the 32-byte root of the Bao tree over the ciphertext. For
  Bao, this root is **identical** to `blake3::hash(ciphertext)` — the tree is
  designed so the root equals plain Blake3 over the full data. That's what
  makes `blake3::hash(ciphertext) == bao_hash` a valid full-file integrity
  check.

- **`bao_outboard`** is the Bao verification tree. It is ~1% the size of the
  ciphertext and is what makes **streaming** and **slice** verification
  possible: given the root `bao_hash` and the outboard, a verifier can check
  a chunk or byte range **as it arrives**, without buffering the whole
  ciphertext and without trusting the rest of the data.

Both fields are signed together as part of `signature_payload =
wrapped_key_bytes || bao_hash`, so a tampered `bao_hash` invalidates the
multi-signature. The outboard itself is not directly signed, but because it
is checked *against* the signed root, any tampering with it causes
verification to fail.

**Important nuance on what the "MAC" actually is.** Raw BLAKE3 and raw Bao
are unkeyed hashes — by themselves they provide integrity only against a
passive observer. An active attacker who tampers with the ciphertext can
trivially recompute both `bao_hash` and `bao_outboard` over the tampered
bytes and the decoder will happily verify the result. What makes this
construction a real authenticator is the **MultiSig over `wrapped_key ||
bao_hash`**: the signature is the key, and once the signature is verified
against the sender's public key, the whole downstream Bao tree
verification inherits that authentication.

There is a second, independent integrity mechanism that catches failures
in the first: `plaintext_hash` inside `KeyMaterial` (§2.4) is a BLAKE3
hash of the plaintext, carried inside `wrapped_key`. After decryption the
recipient checks `blake3(decrypted) == plaintext_hash`. This field is
itself unforgeable because it lives inside the PRE-encrypted `wrapped_key`;
tampering with it requires breaking the PRE scheme. It's a post-decryption
backstop, not a pre-decryption authenticator, but it catches failure modes
where signature verification is somehow bypassed.

**Critical operational rule:** always verify the signature *before*
decryption. If decryption happens before (or without) signature
verification, an active attacker can feed chosen ciphertext into XChaCha20
and the raw cipher has no way to reject it. `plaintext_hash` will
eventually catch it, but only after the bad bytes have flowed through. See
[plans/2026-04-06-bao-streaming-and-storage-simplification.md §12](plans/2026-04-06-bao-streaming-and-storage-simplification.md#12-integrity-chain-whats-the-mac-exactly)
for a full walkthrough of the integrity chain.

### 4.2 Current implementation status

| Capability                                                    | Status     |
| ------------------------------------------------------------- | ---------- |
| Full-file integrity check on `HybridEncryptor::decrypt`       | ✅ Done     |
| Signature over `wrapped_key \|\| bao_hash`                    | ✅ Done     |
| **Streaming verification** using the `bao_outboard`           | 🚧 Planned |
| **Slice verification** (random access to verified byte range) | 🚧 Planned |

The full-file check is correct today because `bao_hash == blake3(ciphertext)`.
It guarantees that if a receiver holds the complete ciphertext, they can
detect any tampering before decryption. What it does **not** yet give us is
the ability to detect tampering *before the whole ciphertext is buffered*,
or on an arbitrary byte range, which is what `bao_outboard` was shipped for.

**Next work:** wire the real `bao::decode::Decoder::new_outboard` into
`HybridEncryptor::decrypt` and add a `SliceDecoder`-backed API for
random-access reads. See [verification-architecture.md §Current status](verification-architecture.md#current-status)
for the implementation plan.

**Audit note:** the old `recrypt-proto::bao_stream` scaffolding that partially
attempted this was removed. It compared the stored `expected_hash` against
`blake3::hash(data)` (which happened to match the Bao root but was presented
as if it were tree verification) and only size-checked the outboard. The
replacement will use the `bao` crate's streaming decoder directly, so the
outboard is actually walked during verification.

---

## 5. ASCII armor

### 5.1 Structure

```
----- BEGIN RECRYPT {TYPE} -----
{Header}: {value}
{Header}: {value}
...

{base64-encoded protobuf payload}
----- END RECRYPT {TYPE} -----
```

Six armor types are supported:

- `RECRYPT PUBLIC KEY` — `PublicKeyBundle`
- `RECRYPT SECRET KEY` — `SecretKeyBundle`
- `RECRYPT RECRYPT KEY` — `RecryptKeyProto`
- `RECRYPT CAPABILITY` — `CapabilityProto`
- `RECRYPT ENCRYPTED FILE` — `EncryptedFileProto`
- `RECRYPT MESSAGE` — generic envelope, reserved

### 5.2 Example — public key export

```
----- BEGIN RECRYPT PUBLIC KEY -----
Version: 1
Algorithm: ED25519+ML-DSA-87
Created: 2026-04-06T12:00:00Z

eyJlZDI1NTE5IjoiTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FF...
----- END RECRYPT PUBLIC KEY -----
```

---

## 6. JSON format (EncryptedFile only)

`EncryptedFile` serializes to a self-describing JSON form where every
binary field is base58-encoded:

```json
{
  "version": 2,
  "wrapped_key": {
    "backend": "Lattice",
    "level": 0,
    "data": "base58..."
  },
  "bao_hash": "base58...",
  "bao_outboard": "base58...",
  "ciphertext": "base58..."
}
```

The signature, if present, follows the same pattern:

```json
"signature": {
  "ed25519_signature": "base58...",
  "pq_signatures": [
    { "algorithm": "ML-DSA-87", "signature": "base58..." }
  ]
}
```

JSON is intended for debug output, inspection, and interop with tools that
can't easily consume protobuf. On the wire, prefer protobuf.

---

## 7. Content negotiation

HTTP endpoints that return `EncryptedFile` honor `Accept`:

```http
Accept: application/x-protobuf   → protobuf (default, recommended)
Accept: application/json         → JSON (EncryptedFile only)
Accept: text/plain               → ASCII armor
```

---

## 8. Size comparison (rough, 1 MiB file)

| Format       | Metadata overhead | Ciphertext encoding | Bao outboard | Total overhead |
| ------------ | ----------------- | ------------------- | ------------ | -------------- |
| Protobuf     | ~200 B            | 0%                  | ~10 KB (~1%) | ~1%            |
| JSON         | ~1 KB             | ~37% (base58)       | ~14 KB       | ~37%           |
| ASCII armor  | ~300 B            | ~33% (base64)       | ~13 KB       | ~34%           |

Recommendation: Protobuf for wire and storage. Armor for human-touchable
export. JSON strictly for debug.

---

## 9. Version evolution

### Protobuf

Add new fields with new field numbers. Old clients ignore unknown fields.
Never reuse a retired field number.

```protobuf
message EncryptedFileProto {
    // ... existing fields ...
    optional bytes encryption_algorithm = 7;   // new in v3
    optional uint32 compression_level   = 8;
}
```

### JSON

Add fields. Old parsers ignore unknown keys. Include a top-level `version`.

### ASCII armor

Add new headers. Old parsers ignore unknown headers. The armor type string
itself is part of the format contract — a new payload type gets a new type
name.

---

## 10. Dependencies

```toml
[dependencies]
prost       = "0.13"
prost-types = "0.13"
serde       = { version = "1", features = ["derive"] }
serde_json  = "1"
base64      = "0.22"
bs58        = "0.5"
bao         = "0.12"
blake3      = "1"

[build-dependencies]
prost-build = "0.13"
```

---

## 11. References

- [Protocol Buffers](https://protobuf.dev/)
- [`prost` crate docs](https://docs.rs/prost)
- [Bao specification](https://github.com/oconnor663/bao/blob/master/docs/spec.md)
- [Blake3 paper](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf)
- [OpenPGP ASCII Armor (RFC 4880 §6)](https://datatracker.ietf.org/doc/html/rfc4880#section-6)
