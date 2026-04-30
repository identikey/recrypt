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
│  recrypt-core    │ │  recrypt-wire    │ │  recrypt-storage         │
│  crypto objects  │ │  wire format     │ │  content-addressed blobs │
│  & operations    │ │  (envelope/armor)│ │  + chunking              │
└────────┬─────────┘ └────────┬─────────┘ └──────────────────────────┘
         │                    │
         │                    └── (converts core ↔ envelope)
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
`recrypt-wire` or `recrypt-storage`. Application crates (`-cli`, `-server`)
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
  - `EncryptedFile` — in-memory struct `{ wrapped_key, bao_hash, ciphertext,
    signature }`. Provides `sign()` / `verify_signature()` over a canonical
    `signature_payload = wrapped_key.to_bytes() || bao_hash`. The bao outboard
    is **not** an envelope field; it lives as a sibling storage object
    (`{hash}.obao`) and is produced/consumed via the streaming API.
    **Wire serialization lives in `recrypt-wire` (Gordian Envelope), not here.**

- **`sign/` — Dual-stack signatures**
  - `MultiSig = ED25519 + ML-DSA-87`. `sign_message` / `verify_message` require
    **both** algorithms to succeed — classical + post-quantum hybrid security.
  - `SigningKeys` / `VerifyingKeys` bundles.

- **`error/`** — `CoreError`, `CoreResult`, `PreError`, `PreResult`.

**Does NOT own:** wire format of any kind (that's `recrypt-wire`), storage,
networking, FFI specifics, or the chunking of large files.

**Depends on:** `recrypt-ffi` (with both `openfhe` and `liboqs` features),
`chacha20`, `blake3`, `bao`, `zeroize`, `ed25519-dalek`.

**Public API re-exports:** `HybridEncryptor`, `PreBackend`, `MockBackend`,
`LatticeBackend`, `{PublicKey, SecretKey, KeyPair, Ciphertext, RecryptKey}`,
`EncryptedFile`, `KeyMaterial`, `MultiSig`, `SigningKeys`, `VerifyingKeys`,
`CoreError`, `CoreResult`.

---

### `recrypt-wire` — wire format

The wire format is [Gordian Envelope](https://developer.blockchaincommons.com/envelope/)
(dCBOR). See [wire-protocol.md](wire-protocol.md) for the full spec.

**Owns:**

- **Envelope construction and parsing** for all recrypt domain types:
  `EncryptedFile`, `PreWrappedKey`, `PublicKeyBundle`, `SecretKeyBundle`,
  `RecryptKey`, `Capability`, `FileMetadata`. Each domain type wraps or
  is a Gordian `Envelope` (option B — envelope-native domain types).

- **Recrypt-specific CBOR tags** — the tag for `recrypt.pre-wrapped-key`
  is currently a private-use tag, pending Blockchain Commons assignment.

- **`armor.rs`** — ASCII-armor variants (PublicKey, SecretKey, Capability,
  RecryptKey, EncryptedFile) with PGP-style headers and base64-wrapped
  envelope payloads.

- **Multi-signature helpers** — Ed25519 + ML-DSA-87 hybrid signing via
  `Envelope::add_signatures`, and the "all must verify" verifier.

- **Salted assertion helpers** — constructors that apply the
  [salting policy](wire-protocol.md) for low-entropy elidable fields.

**Does NOT own:** any crypto operations, key generation, HTTP routing, or FFI.

**Depends on:** `bc-envelope`, `bc-dcbor`, `bc-components`, `blake3`,
`bs58`, `recrypt-core`, `ed25519-dalek`.

**Downstream consumers:** `recrypt-server`, `recrypt-cli`, `identikey-storage-auth`.

---

### `recrypt-storage` — content-addressed blob storage

**Owns:**

- **`BlobStorage` trait** — async, content-addressed by Blake3 hash, with
  defense-in-depth hash verification on both `put` and `get`.
  `put / get / exists / delete / list`.
- **Backends:** `InMemoryStorage` (tests), `LocalFileStorage` (filesystem,
  `{root}/blob/b3/{hash_base58}`), `S3Storage` (feature-gated `s3`, supports
  S3 / Minio / Backblaze).
- **Two-object storage API:** `put_with_outboard` / `get_with_outboard` for
  ciphertext + sibling `.obao` (bao-tree outboard). Small files (≤ 16 KiB)
  skip the `.obao` PUT. Replaces the retired `chunking` module
  (`ChunkManifest` was fully subsumed by Bao and deleted in the 2026-04-06
  streaming sprint).
- **Hash utilities:** `hash_to_base58`, `hash_from_base58`.
- **`StorageError`** enum.

**Does NOT own:** authorization, file metadata (ownership, timestamps), provider
location tracking, or the HTTP API.

**Trust model:** storage backends are **untrusted**. Every read re-verifies the
Blake3 hash. Content addressing makes blobs immutable by construction.

**Depends on:** `blake3`, `bs58`, `tokio`, `async-trait`, `serde`,
`aws-sdk-s3` (optional).

**Downstream:** `recrypt-server` (via `Arc<dyn BlobStorage>` in `AppState`),
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

**Depends on:** `recrypt-core`, `recrypt-wire`, `blake3`, `bs58`, `rusqlite`
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
    (**the core proxy operation**: deserialize `EncryptedFile` via Gordian Envelope,
    apply `HybridEncryptor::recrypt()` to `wrapped_key` only, re-serialize,
    return to the authenticated recipient), `DELETE /recryption/share/{id}`
    (owner-only revoke), `GET /accounts/{fp}/shares`.
  - **Health** — `GET /health`.

- **Middleware:**
  - Multi-signature verification (ED25519 + ML-DSA over canonical action
    messages).
  - Nonce-based replay prevention — timestamp + UUID, 5-minute replay window
    (configurable).
  - Rate limiting via `tower-governor` — per-IP (30 req/s, burst 60) and
    per-fingerprint (100 req/s, burst 200) limiting. `GET /health` exempt.

- **Persistent state:** Four trait-backed stores with in-memory and SQLite
  implementations:
  - `AccountStore` — account registration and lookup (from
    `identikey-storage-auth`).
  - `ShareStore` — share policy creation/deletion/listing (local to
    `recrypt-server`).
  - `NonceStore` — replay prevention with periodic GC (local to
    `recrypt-server`).
  - `ProviderIndex` — file location registry (from `recrypt-storage`).

  At startup, `AppState::from_config(&config).await` selects in-memory or
  SQLite backends based on `config.persistence.backend`. SQLite uses
  `tokio-rusqlite` in WAL mode with a single unified `recrypt.db` shared
  across crates.

- **Configuration:** Layered via `figment`: defaults → `recrypt-server.toml`
  → `RECRYPT_*` env vars (double-underscore for nesting) → CLI flags.

- **State:** `AppState` composing `Arc<dyn AccountStore>`, `Arc<dyn
  ShareStore>`, `Arc<dyn NonceStore>`, `Arc<dyn BlobStorage>`, `Arc<dyn
  OwnershipStore>`, `Arc<dyn ProviderIndex>`, and the configured `PreBackend`.

**Does NOT own:** key generation, encryption/decryption of plaintext (it never
sees plaintext), user secret keys, or authorization policy (delegated to
`OwnershipStore`).

**Trust posture:** the server is **semi-trusted**. It holds:
- recrypt keys (client-generated, uploaded by delegator);
- file ciphertexts (content-addressed blobs);
- share policies (metadata).

It does **not** hold:
- any secret keys;
- any plaintext (never computed);
- possession of a revoked recrypt key (deletion is atomic).

**Depends on:** `recrypt-core`, `recrypt-wire`, `recrypt-storage`,
`identikey-storage-auth`, `recrypt-ffi` (indirect), `axum`, `tower`.

---

### `recrypt-cli` — the user-facing tool

**Owns:** identity, wallet, local encryption/decryption, and the HTTP client
that talks to `recrypt-server`.

- **Identity & wallet** (`commands/identity.rs`, `wallet/`) —
  generate/list/show/delete/export/import identities. Multiple identities per
  wallet. Wallet file at e.g. `~/.local/share/recrypt/wallet.ikeyw`, encrypted
  with **Argon2id (64 MiB, 3 iters, parallelism 4) + XChaCha20-Poly1305**.
  32-byte derived key cached in the **OS keyring** (macOS Keychain, Linux
  Secret Service, Windows Credential Manager) via the `CredentialProvider`
  abstraction. Password via interactive prompt or `RECRYPT_WALLET_PASSWORD`.

- **Local crypto** (`commands/encrypt.rs`, `commands/decrypt.rs`) — `encrypt`
  and `decrypt` are **fully offline**: `HybridEncryptor::encrypt` /
  `HybridEncryptor::decrypt` serialized via Gordian Envelope (see
  [wire-protocol.md](wire-protocol.md)).

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

**Depends on:** `recrypt-core`, `recrypt-wire`, `recrypt-ffi`, `reqwest`,
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
                           │                                    [wallet.ikeyw]       │
                           │                                                         │
  2. encrypt file.txt      │  HybridEncryptor::encrypt(alice_pre_pk, pt)             │
                           │   ├─ random sym_key + nonce                             │
                           │   ├─ PRE-encrypt KeyMaterial → wrapped_key (KEM)        │
                           │   ├─ XChaCha20(pt, sym_key)  → ciphertext (DEM)         │
                           │   └─ Bao(ciphertext)         → bao_hash + outboard      │
                           │  EncryptedFile → envelope bytes                         │
                           │                                                         │
  3. account register      │  POST /accounts  (multi-sig + nonce) ──────────┐        │
                           │                                                ▼        │
                           │                                      ┌──────────────┐   │
  4. files upload          │  POST /files    (body = ciphertext, ─▶│ recrypt-server│  │
                           │                   multi-sig + nonce) │              │   │
                           │                                      │ BlobStorage │   │
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
| Hashing conventions      | [standards/hashing-standard.md](standards/hashing-standard.md) |
| OpenFHE threading        | [openfhe-threading-model.md](openfhe-threading-model.md) |
| Threat model (stub)      | [threat-model.md](threat-model.md)                      |
| Phase roadmap (archived) | [plans/archive/](plans/archive/)                        |
| Phase plans              | [plans/](plans/)                                        |

---

## 6. Completed and active plans

### Recently completed (Phase 8)

1. **[2026-04-06 — Bao streaming + storage simplification](plans/2026-04-06-bao-streaming-and-storage-simplification.md)** ✅
   Replaced bare `bao` with `bao-tree` at 16 KiB chunk groups. Moved the
   Bao outboard out of `EncryptedFileProto` into a sibling S3 object.
   Implemented `HybridEncryptor::{encrypt_streaming, decrypt_streaming,
   decrypt_range}`. Deleted `recrypt-storage::chunking::ChunkManifest`
   (zero dedup benefit, fully subsumed by Bao). Split the
   recryption proxy's control plane from its data plane so group-member
   downloads don't funnel bulk bytes through the proxy.

### Critical path (Phase 9+)

Outstanding work is tracked in dedicated plan
docs under [plans/](plans/). Two sprints are queued, in order:

2. **[2026-04-07 — Production readiness](plans/archive/2026-04-07-production-readiness.md)**
   Trait-backed state stores with SQLite-default / in-memory-for-tests
   implementations via `tokio-rusqlite` + WAL. Boundary refactor:
   `AccountStore` moves to `identikey-storage-auth`, `ProviderIndex`
   moves to `recrypt-storage`. Env-var config via `figment`. Drop-in
   `tower-governor` rate limiting. This is the "make it real" sprint —
   turns the prototype into something you can actually run.

3. **[2026-04-07 — Group sharing](plans/2026-04-07-group-sharing.md)**
   The "Signal meets Dropbox" value-prop sprint. `Group` abstraction
   with batch add/remove of members and files, canonical `GROUP_*`
   signature messages with `files_digest` / `members_digest` binding,
   per-group mutex for atomicity, CLI commands. Depends on the
   persistence layer from sprint 2.

Sprints 1 and 2 are independent and can land in either order (or
concurrently). Sprint 3 depends on sprint 2 for trait-backed
persistence.

### Deferred work

Everything not in one of the three sprints above is tracked in the
backlog:

**[2026-04-07 — Next steps backlog](plans/2026-04-07-next-steps-backlog.md)**

Major items:

- **Discoverability, sync, and indexes** — per-user file index,
  group-level feeds, notifications, watched folders, background sync
  client. The "feels like Dropbox" polish layer.
- **Plaintext layer** — client-side plaintext content addressing,
  folder/path metadata, search.
- **Multi-device + account recovery** — delegated to the identikey
  codebase, which specializes in key recovery systems. Recrypt will
  consume its APIs rather than build its own.
- **Deployment guide + Mjolnir integration** — operational
  documentation and deployment orchestration, picked up after
  production-readiness lands.
- **Threat-model adversarial pass** — deferred until Phase 9 security
  audit kickoff, when it will be done as one focused pass.
- **XChaCha20-Poly1305 vs raw XChaCha20** — defense-in-depth decision
  before Phase 9 audit. See
  [2026-04-06 §8.6](plans/2026-04-06-bao-streaming-and-storage-simplification.md).
- **Non-transferable proxy recryption** — make the proxy
  cryptographically unable to misdirect recrypted output. Research
  direction for Phase 10+. See
  [2026-04-06 §11.5](plans/2026-04-06-bao-streaming-and-storage-simplification.md).
- **Group sharing v2** — admin roles, read/write membership, invite
  flow, nested groups, group-owned files. Deferred from the MVP group
  plan.
- **API stability, `MultiFormat` JSON coverage, contributing guide,
  rustdoc polish** — small doc and API-hygiene items.

See the backlog doc for full context on each entry.
