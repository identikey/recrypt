# Recrypt Architecture Overview

This document is the map of the recrypt codebase: what each crate owns, what it
explicitly does **not** own, and how the pieces compose. It is the entry point
for understanding the system before diving into per-topic design docs.

For phase history and roadmap, see [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).
For deep dives on specific subsystems, see the "Deeper references" sections below.

---

## 1. Elevator pitch

Recrypt is a **quantum-resistant proxy recryption system** that enables secure,
revocable file sharing with untrusted storage providers. Alice encrypts a file
once, uploads the ciphertext, and later shares access with Bob without
re-encrypting the bulk data and without exposing her private key or the
plaintext to any intermediary. A semi-trusted proxy transforms a small wrapped
key (KEM) from Alice's encryption to Bob's, leaving the bulk ciphertext (DEM)
untouched.

The cryptographic core is **lattice-based (OpenFHE BFV)** for post-quantum
security, authenticated with **ED25519 + ML-DSA-87** dual signatures, and
integrity-verified with **Blake3 + Bao** streaming hashes.

---

## 2. Crate dependency graph

```
                      ┌──────────────────┐
                      │  recrypt-cli     │  user workflows, wallet, HTTP client
                      └────────┬─────────┘
                               │
                               ├─── reqwest (HTTP)
                               ▼
                      ┌──────────────────┐
                      │  recrypt-server  │  Axum proxy, auth middleware, routes
                      └────────┬─────────┘
                               │
          ┌────────────────────┼──────────────────┐
          ▼                    ▼                  ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────────────┐
│  recrypt-core    │ │  recrypt-proto   │ │  recrypt-storage         │
│  crypto objects  │ │  wire format     │ │  content-addressed blobs │
│  & operations    │ │  (pb/json/armor) │ │  + chunking              │
└────────┬─────────┘ └────────┬─────────┘ └──────────────────────────┘
         │                    │
         │                    └── (converts core ↔ proto)
         ▼
┌──────────────────┐           ┌──────────────────────────┐
│  recrypt-ffi     │           │  identikey-storage-auth  │
│  safe Rust for   │           │  capabilities, ownership,│
│  OpenFHE + liboqs│           │  provider index          │
│  + ed25519       │           └──────────────────────────┘
└────────┬─────────┘
         │
         ▼
┌────────────────────┐
│ recrypt-openfhe-sys│  raw CXX bridge to OpenFHE C++
└────────────────────┘
```

**Rule of thumb:** dependencies flow downward. `recrypt-core` never imports
`recrypt-proto` or `recrypt-storage`. Application crates (`-cli`, `-server`)
compose lower crates; they never implement crypto themselves.

---

## 3. Per-crate responsibilities

### `recrypt-openfhe-sys` — raw C++ FFI

**Owns:** CXX bridge to the OpenFHE C++ library. Opaque wrappers for
`CryptoContext`, `KeyPair`, `PublicKey`, `PrivateKey`, `Plaintext`, `Ciphertext`,
`RecryptKey`, and ~15 FFI functions for BFV context setup, keygen,
encrypt/decrypt primitives, recryption key generation, the recryption
transform, and byte-based serialization.

**Does NOT own:** any safe abstraction, error handling beyond FFI propagation,
threading model (documented externally), or key material layout.

**Depends on:** `cxx`, vendored OpenFHE at `vendor/openfhe-install/`.

---

### `recrypt-ffi` — safe FFI wrappers

**Owns:**
- `openfhe::PreContext` — thread-safe `Arc<UniquePtr<CryptoContext>>` wrapper
  providing higher-level encrypt/decrypt with slot chunking, byte-based
  (de)serialization, and coefficient conversion utilities.
- `ed25519` module — keygen/sign/verify via `ed25519-dalek`.
- `liboqs` module — post-quantum signatures (ML-DSA-44/65/87) via the `oqs` crate.
- `error::FfiError` enum.

**Does NOT own:** the `PreBackend` trait (that's in `recrypt-core`), hybrid
encryption, signature composition (`MultiSig`), or wire format.

**Depends on:** `recrypt-openfhe-sys` (optional, `openfhe` feature), `oqs`
(optional, `liboqs` feature), `ed25519-dalek`.

**Downstream:** `recrypt-core` consumes all three modules.

---

### `recrypt-core` — the cryptographic engine

This is the crate that defines the crypto objects and operations. Everything
above it composes these; everything below it is an implementation detail.

**Owns:**

- **`pre/` — Pluggable PRE backends**
  - `traits::PreBackend` — 9-method trait (keygen, encrypt, decrypt, recrypt,
    recrypt-key generation, max-plaintext-size, etc.).
  - `backends::LatticeBackend` — OpenFHE/BFV, post-quantum, production default.
  - `backends::MockBackend` — XChaCha20-based stand-in for fast testing.
  - `backends::BackendId` — enum tag (`Lattice=0`, `EcPairing=1`, `EcSecp256k1=2`,
    `Mock=255`) used to select backend at runtime.
  - `keys::{PublicKey, SecretKey, KeyPair, Ciphertext, RecryptKey}` —
    backend-agnostic wrappers with byte (de)serialization.

- **`hybrid/` — KEM-DEM construction**
  - `HybridEncryptor<B: PreBackend>` — orchestrates: generate random symmetric
    key → PRE-encrypt it (KEM) → XChaCha20-encrypt plaintext (DEM) → Bao-hash
    the ciphertext for streaming integrity.
  - `KeyMaterial` — fixed 96-byte bundle `(symmetric_key[32] || nonce[24] ||
    plaintext_hash[32] || plaintext_size[8])`, always encrypted inside
    `wrapped_key`, never transmitted in the clear.
  - `EncryptedFile` — in-memory struct `{ wrapped_key, bao_hash, bao_outboard,
    ciphertext, signature }`. Provides `sign()` / `verify_signature()` over a
    canonical `signature_payload = wrapped_key.to_bytes() || bao_hash`.
    **Wire serialization lives in `recrypt-proto`, not here.**

- **`sign/` — Dual-stack signatures**
  - `MultiSig = ED25519 + ML-DSA-87`. `sign_message` / `verify_message` require
    **both** algorithms to succeed — classical + post-quantum hybrid security.
  - `SigningKeys` / `VerifyingKeys` bundles.

- **`error/`** — `CoreError`, `CoreResult`, `PreError`, `PreResult`.

**Does NOT own:** wire format of any kind (that's `recrypt-proto`), storage,
networking, FFI specifics, or the chunking of large files.

**Depends on:** `recrypt-ffi` (with both `openfhe` and `liboqs` features),
`chacha20`, `blake3`, `bao`, `zeroize`, `ed25519-dalek`.

**Public API re-exports:** `HybridEncryptor`, `PreBackend`, `MockBackend`,
`LatticeBackend`, `{PublicKey, SecretKey, KeyPair, Ciphertext, RecryptKey}`,
`EncryptedFile`, `KeyMaterial`, `MultiSig`, `SigningKeys`, `VerifyingKeys`,
`CoreError`, `CoreResult`.

---

### `recrypt-proto` — wire format

**Owns:**

- **`proto/recrypt.proto`** — the protobuf schema, package `recrypt.v1`. Covers
  16 message types: `PublicKeyBundle`, `SecretKeyBundle`, `PqPublicKey`,
  `PqSecretKey`, `RecryptKeyProto`, `CiphertextProto`, `EncryptedFileProto`,
  `KeyMaterialProto` (documentary — never transmitted standalone),
  `MultiSignatureProto`, `PqSignatureProto`, `FileMetadata`, `ChunkProto`,
  `CapabilityProto`, `UploadRequest`, `DownloadResponse`, `RecryptRequest`,
  `RecryptResponse`; plus the `BackendId` enum.

- **`MultiFormat` trait** — the single entry point for serialization:
  ```rust
  fn to_protobuf/from_protobuf(...) -> ProtoResult<...>;
  fn to_json/from_json(...) -> ProtoResult<...>;
  fn to_armor/from_armor(...) -> ProtoResult<...>;
  fn from_any(data: &[u8]) -> ProtoResult<Self>;  // auto-detect
  ```
  Currently fully implemented for `EncryptedFile`.

- **`format::detect_format`** — byte-prefix heuristic
  (`"----- BEGIN RECRYPT" → Armor`, `b'{' → Json`, else `Protobuf`).

- **`armor::ArmorType`** — 6 ASCII-armor variants (PublicKey, SecretKey, Message,
  Capability, RecryptKey, EncryptedFile) with PGP-style headers and
  base64-wrapped payloads.

- **`convert.rs`** — `From` / `TryFrom` bridges between `recrypt-core` types and
  generated proto types.

- **`bao_stream`** — Blake3/Bao tree verification helpers: `BaoEncoder`,
  `BaoDecoder`, `SliceVerifier` (outboard mode).

**Does NOT own:** any crypto operations, key generation, HTTP routing, or FFI.

**Depends on:** `prost` (v0.13), `prost-build`, `serde`, `serde_json`, `base64`,
`bs58`, `blake3`, `bao`, `recrypt-core`, `ed25519-dalek`.

**Downstream consumers:** `recrypt-server`, `recrypt-cli`, `identikey-storage-auth`.

---

### `recrypt-storage` — content-addressed blob storage

**Owns:**

- **`ChunkStorage` trait** — async, content-addressed by Blake3 hash, with
  defense-in-depth hash verification on both `put` and `get`.
  `put / get / exists / delete / list`.
- **Backends:** `InMemoryStorage` (tests), `LocalFileStorage` (filesystem,
  `{root}/chunks/b3/{hash_base58}`), `S3Storage` (feature-gated `s3`, supports
  S3 / Minio / Backblaze).
- **`chunking` module:** `Chunk`, `ChunkManifest`, `split()`, `join()`,
  `store_chunked()`, `retrieve_chunked()`. `ChunkManifest` now derives
  `Serialize`/`Deserialize` with Blake3 hashes encoded as base58 via custom
  serde helpers.
- **Hash utilities:** `hash_to_base58`, `hash_from_base58`.
- **`StorageError`** enum.

**Does NOT own:** authorization, file metadata (ownership, timestamps), provider
location tracking, or the HTTP API.

**Trust model:** storage backends are **untrusted**. Every read re-verifies the
Blake3 hash. Content addressing makes blobs immutable by construction.

**Depends on:** `blake3`, `bs58`, `tokio`, `async-trait`, `serde`,
`aws-sdk-s3` (optional).

**Downstream:** `recrypt-server` (via `Arc<dyn ChunkStorage>` in `AppState`),
`identikey-storage-auth` (dev-dep for integration tests).

---

### `identikey-storage-auth` — capability-based auth service

**Owns:**

- **Traits:**
  - `OwnershipStore` — `register`, `is_owner`, `list_owned`, `transfer`,
    `grant_access`, `revoke_access`, `has_access`, `list_grants`,
    `list_shared_with`, `unregister`.
  - `ProviderIndex` — file location registry across multiple providers
    (`register`, `lookup`, `update_location`, `remove_location`, `exists`,
    `list_at_provider`).

- **Implementations:** `InMemory*` (always available), `Sqlite*` (feature-gated
  `sqlite`, prepared statements, schema versioning).

- **Core types:**
  - `Capability` — signed, time-limited access token. Fields: `version`,
    `file_hash`, `granted_to` (fingerprint), `operations`, `expires_at`,
    `issuer`, optional `MultiSig`. Methods: `new_signed`, `sign`,
    `verify_signature`, `is_expired`, `permits`, `verify` (full check).
  - `Operation` — `Read | Write | Delete | Share`.
  - `AccessGrant` — record of delegated access.
  - `PublicKeyFingerprint` — `blake3(public_key) → [u8; 32]`, base58-encodable.

- **`AuthError`** enum, **SQLite schema v1** (`ownership`, `access_grants`,
  `provider_locations`, `schema_version`).

**Does NOT own:** HTTP routing (consumer's job), signature generation
(delegates to `recrypt-core`), actual chunk storage, or Postgres backend
(trait-ready but not implemented).

**Trust model:** the auth service holds **ground truth** for ownership and
grants. It is **trusted**. Capabilities are forgery-resistant via multi-sig.

**Depends on:** `recrypt-core`, `recrypt-proto`, `blake3`, `bs58`, `rusqlite`
(optional).

**Downstream:** `recrypt-server` (holds `Arc<dyn OwnershipStore>` and
`Arc<dyn ProviderIndex>` in `AppState`).

---

### `recrypt-server` — the recryption proxy

**Owns:** the HTTP API surface (Axum) and the recryption orchestration.

- **Routes:**
  - **Accounts** — `POST /accounts` (register ED25519 + ML-DSA + PRE public
    keys), `GET /accounts/{fp}`, `GET /accounts/{fp}/files`.
  - **Files** — `POST /files` (upload, server computes Blake3, registers
    ownership), `GET /files/{hash}` (public download),
    `DELETE /files/{hash}` (signed + ownership-checked).
  - **Recryption** — `POST /recryption/share` (store share policy containing
    recrypt key + from/to fingerprints), `GET /recryption/share/{id}/file`
    (**the core proxy operation**: deserialize `EncryptedFile` via protobuf,
    apply `HybridEncryptor::recrypt()` to `wrapped_key` only, re-serialize,
    return to the authenticated recipient), `DELETE /recryption/share/{id}`
    (owner-only revoke), `GET /accounts/{fp}/shares`.
  - **Health** — `GET /health`.

- **Middleware:**
  - Multi-signature verification (ED25519 + ML-DSA over canonical action
    messages).
  - Nonce-based replay prevention — timestamp + UUID, 5-minute replay window
    (configurable).

- **State:** `AppState` composing `Arc<dyn ChunkStorage>`, `Arc<dyn
  OwnershipStore>`, `Arc<dyn ProviderIndex>`, `AccountStore`, `ShareStore`,
  `NonceStore`, and the configured `PreBackend`.

**Does NOT own:** key generation, encryption/decryption of plaintext (it never
sees plaintext), user secret keys, or persistent databases (in-memory for MVP,
trait-ready for SQL backends).

**Trust posture:** the server is **semi-trusted**. It holds:
- recrypt keys (client-generated, uploaded by delegator);
- file ciphertexts (content-addressed blobs);
- share policies (metadata).

It does **not** hold:
- any secret keys;
- any plaintext (never computed);
- possession of a revoked recrypt key (deletion is atomic).

**Depends on:** `recrypt-core`, `recrypt-proto`, `recrypt-storage`,
`identikey-storage-auth`, `recrypt-ffi` (indirect), `axum`, `tower`.

---

### `recrypt-cli` — the user-facing tool

**Owns:** identity, wallet, local encryption/decryption, and the HTTP client
that talks to `recrypt-server`.

- **Identity & wallet** (`commands/identity.rs`, `wallet/`) —
  generate/list/show/delete/export/import identities. Multiple identities per
  wallet. Wallet file at e.g. `~/.local/share/recrypt/wallet.recrypt`, encrypted
  with **Argon2id (64 MiB, 3 iters, parallelism 4) + XChaCha20-Poly1305**.
  32-byte derived key cached in the **OS keyring** (macOS Keychain, Linux
  Secret Service, Windows Credential Manager) via the `CredentialProvider`
  abstraction. Password via interactive prompt or `RECRYPT_WALLET_PASSWORD`.

- **Local crypto** (`commands/encrypt.rs`, `commands/decrypt.rs`) — `encrypt`
  and `decrypt` are **fully offline**: `HybridEncryptor::encrypt` /
  `HybridEncryptor::decrypt` serialized via `MultiFormat::to_protobuf` /
  `from_protobuf`.

- **HTTP client** (`client/api.rs`, `client/auth.rs`) — account registration,
  nonce fetch, request signing (ED25519 + ML-DSA over action message), file
  upload/download/list/delete, share create/list/revoke/download.

- **Commands** (`commands/*.rs`) — `account`, `files`, `share`, `config`,
  `identity`, `encrypt`, `decrypt`.

- **UX** (`output.rs`) — colored text, optional JSON via `--json`, progress
  bars for encrypt/decrypt/upload.

**Does NOT own:** cryptographic primitives, file storage, share policy
enforcement, TUI/GUI (deferred), or hardware-wallet integration (deferred).

**Trust posture:** the CLI is **fully trusted locally**. It holds all secret
keys (encrypted at rest) and all plaintext (in process memory during operations).
It trusts the server's enforcement of share policies but independently verifies
multi-signatures on anything it receives.

**Depends on:** `recrypt-core`, `recrypt-proto`, `recrypt-ffi`, `reqwest`,
`clap`, `argon2`, `chacha20poly1305`, `keyring`.

---

## 4. Canonical data flow: encrypt → share → decrypt

```
                          ALICE                                                     BOB
                      ┌─────────┐                                               ┌─────────┐
                      │ recrypt │                                               │ recrypt │
                      │   cli   │                                               │   cli   │
                      └────┬────┘                                               └────┬────┘
                           │                                                         │
  1. identity new          │  genkeys: ED25519 + ML-DSA + PRE                        │
                           │  ─ wallet (Argon2id + XChaCha20-Poly1305) ─┐            │
                           │                                            ▼            │
                           │                                    [wallet.recrypt]     │
                           │                                                         │
  2. encrypt file.txt      │  HybridEncryptor::encrypt(alice_pre_pk, pt)             │
                           │   ├─ random sym_key + nonce                             │
                           │   ├─ PRE-encrypt KeyMaterial → wrapped_key (KEM)        │
                           │   ├─ XChaCha20(pt, sym_key)  → ciphertext (DEM)         │
                           │   └─ Bao(ciphertext)         → bao_hash + outboard      │
                           │  EncryptedFile → protobuf bytes                         │
                           │                                                         │
  3. account register      │  POST /accounts  (multi-sig + nonce) ──────────┐        │
                           │                                                ▼        │
                           │                                      ┌──────────────┐   │
  4. files upload          │  POST /files    (body = ciphertext, ─▶│ recrypt-server│  │
                           │                   multi-sig + nonce) │              │   │
                           │                                      │ ChunkStorage │   │
                           │                                      │ OwnershipStore│  │
                           │                                      └──────┬───────┘   │
                           │                                             │           │
  5. share create          │  backend.generate_recrypt_key(alice_sk,bob_pk)          │
                           │  POST /recryption/share ─────────────▶ SharePolicy{     │
                           │                                         rk, from, to,  │
                           │                                         file_hash }    │
                           │                                                        │
                           │                                                        │
  6.                                                  share download ◀──────────────┤
                                                     │                              │
                                                     ▼                              │
                                              ┌────────────┐                        │
                                              │  server    │                        │
                                              │  recrypt() │  wrapped_key(KEM)      │
                                              │  transform │  only — ciphertext(DEM)│
                                              └─────┬──────┘  untouched             │
                                                    │                               │
                                                    └────── recrypted bytes ───────▶│
                                                                                    │
  7. decrypt                                                        HybridEncryptor::│
                                                                    decrypt(bob_sk, ·)
                                                                                    │
                                                                          [plaintext]
```

**Invariants enforced by the architecture:**

1. **The server never sees plaintext.** It only transforms `wrapped_key`. The
   DEM ciphertext passes through byte-identical.
2. **The server never holds a secret key.** Only public keys, recrypt keys, and
   ciphertexts.
3. **Integrity is verified without a secret.** Bao-hash-root is signed with the
   `wrapped_key` as the canonical signature payload, so any tampering with
   either the wrapped key or the bulk ciphertext is detectable.
4. **Revocation is atomic.** Deleting a `SharePolicy` deletes the recrypt key.
5. **Storage is untrusted.** Every blob is re-hashed on read.

---

## 5. Deeper references per topic

| Topic                    | Doc                                                     |
| ------------------------ | ------------------------------------------------------- |
| Hybrid KEM-DEM design    | [hybrid-encryption-architecture.md](hybrid-encryption-architecture.md) |
| PRE backend trait design | [pre-backend-traits.md](pre-backend-traits.md)          |
| Non-determinism & tests  | [non-determinism.md](non-determinism.md)                |
| Wire format              | [wire-protocol.md](wire-protocol.md)                    |
| HTTP API reference       | [http-api-reference.md](http-api-reference.md)          |
| Storage + chunking       | [storage-design.md](storage-design.md)                  |
| Blake3/Bao verification  | [verification-architecture.md](verification-architecture.md) |
| Hashing conventions      | [hashing-standard.md](hashing-standard.md)              |
| OpenFHE threading        | [openfhe-threading-model.md](openfhe-threading-model.md) |
| Threat model (stub)      | [threat-model.md](threat-model.md)                      |
| Phase roadmap            | [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md)        |
| Phase plans              | [plans/](plans/)                                        |

---

## 6. Known gaps in the deeper per-topic docs

Surfaced while compiling this overview. Items marked ✅ were addressed
during this doc pass; items marked 🚧 are follow-ups for Phase 8/9.

### Resolved during this doc pass
- ✅ [wire-protocol.md](wire-protocol.md) rewritten from the current proto
  schema — `RecryptKeyProto`, `CapabilityProto.issuer_fingerprint`,
  `FileMetadata.backend`, `KeyMaterialProto` layout, and the status of
  streaming verification are all now documented correctly.
- ✅ [http-api-reference.md](http-api-reference.md) created. It includes the
  exact canonical signature-message strings (`CREATE:`, `UPLOAD:`, `DELETE:`,
  `SHARE:`, `DOWNLOAD:`, `REVOKE:`, `LIST_SHARES:`) with the encoding of every
  substituted field. All 7 strings were verified to match between
  `recrypt-cli/src/client/auth.rs` and the corresponding server-side verifier
  in `recrypt-server/src/routes/*` and `middleware/auth.rs`.
- ✅ [threat-model.md](threat-model.md) stub created with assets, trust
  boundaries, adversary models (Adv-S/P/N/C/Q), and open questions. Needs a
  disciplined adversarial pass before the Phase 9 security audit.
- ✅ [storage-design.md](storage-design.md) updated to document
  `ChunkManifest`'s new serde derivation and base58 blake3 helpers, and to
  flag the chunking/Bao convergence question.
- ✅ [verification-architecture.md](verification-architecture.md) now has a
  "Current status" section stating plainly what's wired in
  (`blake3(ciphertext) == bao_hash` full-file check — correct because the Bao
  root equals plain Blake3 over the data) and what's not yet wired in
  (streaming decoder against the `bao_outboard`, slice verification).
- ✅ Removed the stale `#[allow(dead_code)] // Used in Phase 2.3+` comment on
  `RecryptKey::bytes` in `recrypt-core/src/pre/keys.rs`.
- ✅ Added `hash_algorithm` validation in
  `recrypt-storage::chunking::join()` — manifests declaring a non-Blake3
  algorithm are now rejected rather than silently re-verified with Blake3.
- ✅ Removed the dead `recrypt-proto::bao_stream` module. It was never called
  outside its own tests; its `verify()` happened to work (the Bao root equals
  plain Blake3 over the data) but was presented as if it were walking the
  outboard tree, which it wasn't. Fresh streaming implementation will use the
  `bao` crate's real API directly — see follow-ups below.

### Streaming verification — planned next work 🚧
This is the main outstanding correctness-adjacent item. Today the
`bao_outboard` field is computed at encryption time, stored in every
`EncryptedFile`, and signed transitively via `bao_hash`, but is **not
consumed** during decryption. Full-file integrity is still guaranteed by
the `blake3(ciphertext) == bao_hash` check, but we get none of the
streaming / slice benefits that motivated carrying the outboard in the
first place.

The plan is:

1. Wire `bao::decode::Decoder::new_outboard` into
   `HybridEncryptor::decrypt` so decryption *reads* the ciphertext
   through the Bao decoder with the stored outboard, catching tampering
   mid-stream rather than after buffering.
2. Expose a `bao::decode::SliceDecoder`-backed API for random-access,
   range-verified reads. The proto already carries a `ChunkProto.bao_proof`
   field for this.
3. Once (1) and (2) exist, collapse the integrity role of
   `recrypt-storage::chunking::ChunkManifest` into Bao. The storage
   chunking should remain as a 4 MiB storage-layout concern (S3
   multipart alignment, dedup) but should not re-verify what Bao
   already verifies. `ChunkManifest.file_hash` is bit-identical to
   `EncryptedFile.bao_hash` today — one authoritative root is enough.

See [verification-architecture.md §Current status](verification-architecture.md#current-status)
for the implementation notes.

### `docs/hybrid-encryption-architecture.md` & `recrypt-core/src/lib.rs` 🚧
- The lib.rs rustdoc does not mention why `KeyMaterial` is always 96 bytes
  (fixed to match `LatticeBackend::max_plaintext_size()`).
- No explanation of **why `plaintext_hash` is encrypted inside `wrapped_key`**
  (metadata confidentiality).
- `non-determinism.md` is referenced but not prominent in the rustdoc.

### `docs/wire-protocol.md` — follow-ups 🚧
- `MultiFormat` is only fully implemented for `EncryptedFile`.
  `PublicKeyBundle`, `SecretKeyBundle`, `RecryptKeyProto`, and
  `CapabilityProto` would all benefit from full JSON implementations, not
  just proto + armor.

### `docs/plans/2026-01-06-phase-4b-storage-auth.md` 🚧
- Phase 4b plan describes Postgres as "future scale"; the implementation only
  ships SQLite. The trait design is Postgres-ready but this deferral is not
  recorded anywhere.
- "Metadata storage" was listed TBD in the plan and is still unresolved in
  code — there is no explicit home for file metadata beyond `FileMetadata`
  fields carried inside uploads.
- SQLite schema (`schema.rs`) is commented but has no design doc counterpart.

### `docs/plans/2026-01-07-phase-5-recryption-proxy.md` 🚧
- Plan calls for **tower rate limiting**; not implemented. Either implement
  it or record it as an explicit deferral.
- TLS termination is out of scope (expected — nginx/reverse proxy), but the
  deployment doc should say this explicitly once it exists.
- The canonical signature-message strings *are* now documented in
  [http-api-reference.md §1.3](http-api-reference.md#13-canonical-signature-message-format),
  so this item is resolved; just make sure future route changes update that
  table.

### `docs/plans/2026-01-14-phase-6b-secure-credential-storage.md` 🚧
- Wallet `lock` / `unlock` commands are marked as deferred. Infrastructure
  exists (`CredentialProvider`). Track as a known follow-up.

### Still missing 🚧
- **Deployment guide** (Phase 8). Not started. Should cover:
  `brew install libomp`, Minio/S3 setup, running the server, TLS termination
  via reverse proxy, backend selection, operational concerns (recrypt key
  storage, nonce store GC).
