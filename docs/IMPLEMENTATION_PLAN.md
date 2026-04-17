> **Note:** This document was the original implementation plan from Phase 0 (Jan 2026).
> For current project status and architecture, see [architecture.md](docs/architecture.md)
> and the Phase 8+ plans in [docs/plans/](docs/plans/).

# Recrypt Implementation Plan

**Status:** 🚀 Implementation Phase (Phase 0 Complete)  
**Target:** Production-ready quantum-resistant proxy recryption system  
**Compatibility:** Clean slate—no Python prototype compatibility required

---

## Executive Summary

Production Rust implementation of Recrypt, a quantum-resistant proxy recryption system. Architecturally sound, performant, and production-ready with proper separation of concerns.

**Core Innovation:** Proxy recryption enables untrusted storage where files stay encrypted end-to-end but can be shared/revoked via cryptographic transformation rather than key sharing.

---

## Design Philosophy Changes

### What We're Keeping

- ✅ Proxy recryption via OpenFHE lattice crypto
- ✅ Post-quantum signatures (ML-DSA-87, etc via liboqs)
- ✅ Dual classical keys (ED25519 only, **dropping ECDSA/SECP256k1**)
- ✅ Multi-signature authorization pattern
- ✅ Nonce-based replay prevention
- ✅ Chunked streaming architecture

### What We're Changing

- ❌ **No ECDSA/SECP256k1** - Unnecessary complexity, ED25519 sufficient for classical fallback
- ❌ **No naive file storage** - Moving to S3-compatible API (Minio for dev)
- ❌ **No IDK ASCII armor as primary format** - More efficient wire protocol needed
- ✅ **Hybrid encryption** - KEM-DEM with pluggable PRE backends (lattice for PQ, EC for classical)
- ✅ **Blake3 everywhere** - Standardized hashing (faster, Bao integration)
- ✅ **Blake3/Bao tree mode** - Streaming chunk verification

### What We're Building New

- 🆕 **S3-compatible storage layer** - Authenticated access via file hash lookup
- 🆕 **Efficient wire protocol** - Binary serialization for performance
- 🆕 **Minimal rad TUI** - Inherit spirit, lose bloat
- 🆕 **Proper Rust architecture** - Workspace with focused crates

---

## Critical Design Questions — DECISIONS

### 1. Encryption Architecture ✅ DECIDED: Hybrid with Pluggable PRE Backends

**Decision:** Use **hybrid encryption** (KEM-DEM) with pluggable PRE backends.

**Architecture:**

1. **KEM (Key Encapsulation):** PRE-encrypt a random 256-bit symmetric key
2. **DEM (Data Encapsulation):** XChaCha20 + Bao tree hashing for bulk data encryption
3. **Recryption:** Only transforms the wrapped key (~KB), not the file

**PRE Backends (pluggable):**

| Backend                   | Security       | Ciphertext Size | Status      |
| ------------------------- | -------------- | --------------- | ----------- |
| **OpenFHE BFV/PRE**       | Post-quantum   | ~1-10 KB        | Default     |
| **recrypt (IronCore)**    | Classical (EC) | ~480 bytes      | Alternative |
| **umbral-pre (NuCypher)** | Classical (EC) | ~200 bytes      | Alternative |

**Rationale:**

- Lattice PRE has 50-100x ciphertext expansion; hybrid makes this negligible
- Symmetric encryption (XChaCha20) is ~GB/s; PRE operations are ms-scale
- Pluggable backends allow post-quantum or classical choice per use case
- EC backends are pure Rust (no FFI), better for mobile/WASM

**Documents:**

- `docs/hybrid-encryption-architecture.md` — Full trade-off analysis
- `docs/pre-backend-traits.md` — Trait hierarchy for pluggable backends

---

### 2. Hashing Standardization ✅ DECIDED: Blake3 Everywhere

**Decision:** Standardize on **Blake3** for all hashing operations.

**Rationale:**

- 4-8x faster than Blake2b
- Built-in tree mode (Bao) for streaming verification
- Native parallelism
- Excellent Rust crate (`blake3`)
- 256-bit security margin

**Migration from Python:**

- Blake2b (Merkle, chunks) → Blake3

**Document in:** `docs/hashing-standard.md`

---

### 3. Hierarchical Verification ✅ DECIDED: Blake3/Bao Tree Mode

**Decision:** Use **Blake3's built-in Bao tree mode** for streaming verification.

**Benefits:**

- Native streaming verification (chunks verified as they arrive)
- No manual Merkle tree construction
- Root hash sufficient for full file integrity
- Parallel hashing built-in
- Implicit auth paths in encoding (no per-chunk overhead)

**Implementation:**

```rust
use bao::{encode::Encoder, decode::Decoder};

// Encoding
let (encoded, root) = bao::encode::encode(data);

// Streaming verification
let mut decoder = Decoder::new(&root);
decoder.write_all(&chunk)?;  // verifies incrementally
```

**Document in:** `docs/verification-architecture.md`

---

### 5. Non-Deterministic Operations ✅ DECIDED: Semantic Testing

**Decision:** Test **semantic correctness**, not byte equality.

**Sources of Non-Determinism:**
| Source | Cause | Test Strategy |
|--------|-------|---------------|
| OpenFHE serialization | Internal state ordering | Roundtrip semantic equality |
| OpenFHE ciphertext | Encryption randomness | decrypt(encrypt(x)) == x |
| PQ signatures | Randomized signing | verify(sign(m)) == true |

**Content Addressing:** Hash **plaintext** (or deterministic canonical form), never ciphertext.

**Document in:** `docs/non-determinism.md`

---

### 6. S3-Compatible Storage ✅ DECIDED: Content-Addressed + Auth Service

**Decision:** Content-addressed storage (IPFS-style) with separate **Authentication Service** layer.

**Architecture:**

```
┌─────────────────────────────────────────────────────────────────┐
│                     AUTHENTICATION SERVICE                       │
│  - Manages file ownership (pubkey → file hashes)                │
│  - Issues access capabilities (signed tokens)                   │
│  - Maintains storage provider index (hash → provider URLs)      │
│  - Handles hosting agility (files movable between providers)    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     S3-COMPATIBLE STORAGE                        │
│  - Single bucket for all users                                  │
│  - Objects keyed by Blake3 hash (content-addressed)             │
│  - Automatic deduplication                                      │
│  - Any provider: Minio (dev), AWS S3, Backblaze, etc.          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     RECRYPTION PROXY (separate)                  │
│  - Lean, special-purpose                                        │
│  - Holds recryption keys only                                   │
│  - Semi-trusted (users can self-host for security)             │
└─────────────────────────────────────────────────────────────────┘
```

**Key Design Points:**

- Files referenced by hash (hosting-agnostic, like IPFS)
- Auth service (`identikey-storage-auth`) returns capabilities for accessing specific hashes
- Recryption proxy (`recrypt-server`) is the main service—streams KEM ciphertext, holds recrypt keys
- Auth service is part of Identikey suite; implementing in this repo for now, will split later

**Document in:** `docs/storage-design.md`

---

### 7. Wire Protocol ✅ DECIDED: Multiple Formats

**Decision:** Support **multiple serialization formats**; maintenance overhead minimal.

**Supported Formats:**

1. **Protobuf (primary)** — Compact, typed, fast
2. **ASCII Armor (export)** — Human-readable, debugging, key backup
3. **JSON (debug/API)** — Easy inspection, API responses

**Format Selection:**

- Wire protocol: Protobuf (default)
- File export/import: ASCII armor
- REST API responses: JSON or Protobuf (content negotiation)

**Document in:** `docs/wire-protocol.md`

---

## Public Key Fingerprints

Public key fingerprints use **plain Blake3 hashing** with Base58 encoding:

```rust
let fingerprint = blake3::hash(pubkey_bytes);
let display = bs58::encode(fingerprint.as_bytes()).into_string();
```

**Rationale:** HDprint (a self-correcting hierarchical identifier system with BCH error correction and HMAC chains) was considered but deemed over-engineered for our use cases. Modern UX patterns (QR codes, copy-paste, deep links) make manual transcription rare, and the complexity cost wasn't justified. Plain Blake3 → Base58 provides 256-bit collision resistance with zero implementation overhead.

**Archived:** See `docs/archive/hdprint-specification.md` for the original spec.

---

## Implementation Phases

### Phase 0: Planning & Specification (Current)

**Duration:** 2-3 days  
**Deliverables:**

- ✅ This master plan
- ✅ Answer all 6 design questions above
- ✅ Architecture decision records for each question
- ✅ Rust workspace structure defined
- ✅ Dependency analysis (crates needed)

**Design Docs Written:**

1. ✅ `docs/hybrid-encryption-architecture.md` - Encryption architecture (KEM-DEM + pluggable PRE)
2. ✅ `docs/pre-backend-traits.md` - Trait hierarchy for pluggable backends
3. ✅ `docs/hashing-standard.md` - Blake3 standardization
4. ✅ `docs/verification-architecture.md` - Streaming chunk verification via Bao
5. ✅ `docs/non-determinism.md` - Testing strategy for non-deterministic crypto
6. ✅ `docs/storage-design.md` - S3 integration architecture
7. ✅ `docs/wire-protocol.md` - Binary protocol specification

---

### Phase 1: Rust Workspace Setup & FFI Foundations

**Duration:** 3-5 days  
**Goal:** Get OpenFHE and liboqs working in Rust

**Tasks:**

1. Create workspace structure:

   ```
   dcypher-rust/
   ├── Cargo.toml (workspace)
   ├── crates/
   │   ├── recrypt-ffi/      # START HERE
   │   ├── recrypt-core/
   │   ├── recrypt-proto/
   │   └── recrypt-storage/
   ├── recrypt-cli/
   ├── recrypt-server/
   └── docs/
   ```

2. **recrypt-ffi crate:**

   - OpenFHE bindings via cxx
   - OpenFHE bindings: `crates/recrypt-openfhe-sys/` (custom minimal wrapper)
   - liboqs bindings (check crates.io first, may exist)
   - ED25519 via libsodium or RustCrypto
   - Build system: `build.rs` with cxx-build
   - Basic smoke tests: encrypt/decrypt roundtrip

3. **Validation:**
   - Can create crypto context in Rust
   - Can generate keypairs
   - Can encrypt/decrypt small message
   - Can generate recryption key
   - Can perform recryption transformation
   - Decrypt after recryption succeeds

**Non-Determinism Note:**

- Write tests that validate cryptographic properties (plaintext recovered)
- NOT byte-level comparison of ciphertexts/serialized keys

**Dependencies to evaluate:**

- `cxx` for OpenFHE bindings
- `oqs-sys` or `pqcrypto` for liboqs (check which is maintained)
- `ed25519-dalek` for ED25519 signatures
- `blake3` crate for hashing (assuming we standardize on Blake3)

---

### Phase 2: Core Cryptography (recrypt-core)

**Duration:** 4-5 days  
**Goal:** Production-ready crypto operations library

**Architecture:**

```rust
recrypt-core/
├── src/
│   ├── lib.rs
│   ├── hybrid.rs           // HybridEncryptor (KEM-DEM pattern)
│   ├── sign.rs             // ED25519 + PQ signatures, MultiSig
│   └── pre/
│       ├── mod.rs          // Re-exports
│       ├── traits.rs       // PreBackend trait
│       ├── keys.rs         // PublicKey, SecretKey, RecryptKey, Ciphertext
│       ├── error.rs        // PreError
│       ├── registry.rs     // Backend registry (feature-gated)
│       └── backends/
│           ├── mod.rs
│           ├── mock.rs     // MockBackend (testing)
│           ├── lattice.rs  // LatticeBackend (OpenFHE FFI)
│           └── ec_pairing.rs // EcPairingBackend (recrypt crate)
└── tests/
    ├── roundtrip.rs        // Basic encrypt/decrypt via HybridEncryptor
    ├── recryption.rs       // Full Alice->Bob flow
    └── signatures.rs       // Multi-sig verification
```

**Key Design Decisions:**

- **Encryption approach:** Hybrid KEM-DEM with pluggable PRE backends (see `docs/hybrid-encryption-architecture.md`)
- **Context management:** Explicit backend passing via `HybridEncryptor<B: PreBackend>` for testability
- **Error handling:** Custom error types with `thiserror` (see `PreError` enum)
- **Async or sync:** Start sync, async can wrap later if needed

**API Sketch:**

```rust
//! PRE Backend Trait (pluggable: lattice, EC-pairing, EC-secp256k1)
pub trait PreBackend: Send + Sync {
    fn generate_keypair(&self) -> PreResult<KeyPair>;
    fn generate_recrypt_key(&self, from_sk: &SecretKey, to_pk: &PublicKey) -> PreResult<RecryptKey>;
    fn encrypt(&self, recipient: &PublicKey, plaintext: &[u8]) -> PreResult<Ciphertext>;
    fn decrypt(&self, secret: &SecretKey, ciphertext: &Ciphertext) -> PreResult<Vec<u8>>;
    fn recrypt(&self, recrypt_key: &RecryptKey, ciphertext: &Ciphertext) -> PreResult<Ciphertext>;
}

//! Hybrid Encryption (KEM-DEM pattern)
pub struct HybridEncryptor<B: PreBackend> { backend: B }

impl<B: PreBackend> HybridEncryptor<B> {
    /// Encrypt: generates random symmetric key, PRE-wraps it, XChaCha20 encrypts data
    pub fn encrypt(&self, recipient: &PublicKey, plaintext: &[u8]) -> PreResult<EncryptedFile>;

    /// Decrypt: unwraps key via PRE, XChaCha20 decrypts, verifies plaintext hash
    pub fn decrypt(&self, secret: &SecretKey, file: &EncryptedFile) -> PreResult<Vec<u8>>;

    /// Recrypt: transforms wrapped_key only (ciphertext unchanged)
    pub fn recrypt(&self, recrypt_key: &RecryptKey, file: &EncryptedFile) -> PreResult<EncryptedFile>;
}

//! Multi-signature (ED25519 + PQ)
pub struct MultiSig { ed25519_sig: Signature, pq_sigs: Vec<PqSignature> }
pub fn sign_message(msg: &[u8], keys: &SigningKeys) -> Result<MultiSig>;
pub fn verify_message(msg: &[u8], sig: &MultiSig, pks: &VerifyingKeys) -> Result<bool>;
```

See `docs/pre-backend-traits.md` for full trait hierarchy and backend implementations.

**Testing Strategy:**

- Property-based tests with `proptest`:
  - encrypt(decrypt(x)) == x
  - decrypt_bob(recrypt(encrypt_alice(x))) == x
  - verify(sign(msg)) == true
- Known-answer tests with fixed keys (for regression)
- Performance benchmarks with `criterion`

**Critical:** Document non-determinism in tests

- Ciphertext bytes will differ each run (randomness)
- Serialized keys may differ (OpenFHE non-canonical)
- Test semantic equivalence, not byte equality

---

### Phase 3: Protocol Layer (recrypt-proto)

**Duration:** 3-4 days  
**Goal:** Wire protocol for serialization/deserialization

**Architecture:**

```rust
recrypt-proto/
├── src/
│   ├── lib.rs
│   ├── wire.rs         // Protobuf serialization
│   ├── armor.rs        // ASCII armor format (export/debugging)
│   ├── bao.rs          // Blake3/Bao tree verification helpers
│   └── message.rs      // High-level message construction
└── tests/
    ├── serialization.rs
    └── verification.rs
```

**Key Decisions (from Phase 0):**

- Wire format: Protobuf (primary), ASCII armor (export), JSON (debug)
- Blake3/Bao tree mode for streaming verification
- Header fields defined in `docs/wire-protocol.md`

**Message Types:**

```rust
/// Encrypted file (from hybrid-encryption-architecture.md)
pub struct EncryptedFile {
    pub version: u8,                    // Format version (2)
    pub wrapped_key: Ciphertext,        // PRE-encrypted KeyMaterial
    pub bao_hash: [u8; 32],             // Ciphertext integrity root
    pub bao_outboard: Vec<u8>,          // Bao verification tree
    pub ciphertext: Vec<u8>,            // XChaCha20 encrypted data
}

/// KeyMaterial (encrypted INSIDE wrapped_key—protects plaintext_hash)
pub struct KeyMaterial {
    pub symmetric_key: [u8; 32],        // XChaCha20 key
    pub nonce: [u8; 24],                // XChaCha20 extended nonce
    pub plaintext_hash: [u8; 32],       // Blake3 of plaintext (encrypted!)
    pub plaintext_size: u64,            // Original size
}
// Total: 96 bytes (32 key + 24 nonce + 32 hash + 8 size)
```

**Verification Flow:**

1. Stream download: verify chunks against Bao tree
2. After full download: verify `computed_bao_root == stored_bao_hash`
3. Unwrap key via PRE → get `(key, nonce, plaintext_hash, size)`
4. Decrypt with XChaCha20, verify plaintext hash and size

**Testing:**

- Round-trip serialization
- Merkle tree proofs for various tree sizes
- Signature verification
- Malformed message handling

---

### Phase 4: Storage Layer (recrypt-storage)

**Duration:** 3-4 days  
**Goal:** S3-compatible storage abstraction

**Architecture:**

```rust
recrypt-storage/
├── src/
│   ├── lib.rs
│   ├── traits.rs       // Storage trait abstraction
│   ├── s3.rs           // S3/Minio implementation
│   ├── local.rs        // Local filesystem (testing)
│   └── chunking.rs     // Chunk management logic
└── tests/
    ├── s3_integration.rs    // Requires Minio running
    └── local_storage.rs
```

**Storage Trait:**

```rust
#[async_trait]
pub trait ChunkStorage {
    async fn put_chunk(&self, hash: &Hash, data: &[u8]) -> Result<()>;
    async fn get_chunk(&self, hash: &Hash) -> Result<Vec<u8>>;
    async fn exists(&self, hash: &Hash) -> Result<bool>;
    async fn delete_chunk(&self, hash: &Hash) -> Result<()>;
    async fn list_chunks(&self, prefix: &str) -> Result<Vec<ChunkMetadata>>;
}
```

**Integration with Phase 3:**

Phase 4 will use the protocol types from `recrypt-proto`:

- `ChunkProto` for streaming uploads (already defined in protobuf schema)
- `FileMetadata` for file listings (ready to use)
- `EncryptedFileProto` for complete file serialization
- Content-addressing via `bao_hash` from `EncryptedFile`

**Implementations:**

1. **MinioStorage** - Development environment

   - Uses `rusoto_s3` or `aws-sdk-rust`
   - Docker compose for local Minio
   - Configuration via env vars

2. **S3Storage** - Production

   - Same interface, different endpoint
   - Supports any S3-compatible service

3. **LocalFileStorage** - Testing
   - Simple filesystem backend
   - No external dependencies
   - Fast for unit tests

**Key Design (from Phase 0):**

- Authenticated access model
- Bucket/object naming scheme
- Metadata handling strategy

**Testing:**

- Unit tests with LocalFileStorage
- Integration tests with Minio (Docker)
- Error handling: network failures, permission errors
- Concurrent access patterns

**Docker Compose for Dev:**

```yaml
version: "3"
services:
  minio:
    image: minio/minio
    ports:
      - "9000:9000"
      - "9001:9001"
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    command: server /data --console-address ":9001"
```

---

### Phase 4b: Storage Auth Service (identikey-storage-auth)

**Duration:** 3-4 days  
**Goal:** Authenticated access to content-addressed storage

**Why S3 Isn't Enough:**

S3 ACLs are bucket/prefix-based. We need:

- Access control based on cryptographic identity (pubkeys)
- Per-hash authorization (not per-prefix)
- Hash → storage provider mapping (hosting agility)

**Architecture:**

```rust
identikey-storage-auth/
├── src/
│   ├── lib.rs
│   ├── ownership.rs    // pubkey → hash ownership index
│   ├── capability.rs   // Signed access tokens
│   ├── index.rs        // hash → provider URL mapping
│   └── api.rs          // HTTP endpoints
└── tests/
    ├── capability_test.rs
    └── integration_test.rs
```

**Core Functions:**

```rust
/// Ownership registry
pub trait OwnershipStore {
    /// Register file ownership
    async fn register(&self, owner: &PublicKey, hash: &Hash, provider_url: &str) -> Result<()>;

    /// Check if pubkey owns hash
    async fn is_owner(&self, owner: &PublicKey, hash: &Hash) -> Result<bool>;

    /// List files owned by pubkey
    async fn list_owned(&self, owner: &PublicKey) -> Result<Vec<Hash>>;
}

/// Capability issuance
pub struct Capability {
    pub hash: Hash,
    pub grantee: PublicKey,
    pub expires: Option<DateTime>,
    pub permissions: Permissions,  // Read, Write, Share
    pub signature: Signature,      // Signed by auth service
}

/// Hash → provider mapping (hosting agility)
pub trait ProviderIndex {
    /// Where is this hash stored?
    async fn lookup(&self, hash: &Hash) -> Result<Vec<ProviderUrl>>;

    /// Update location (file moved between providers)
    async fn update_location(&self, hash: &Hash, old: &ProviderUrl, new: &ProviderUrl) -> Result<()>;
}
```

**API Endpoints:**

```
POST   /auth/register          - Register file ownership (after upload)
GET    /auth/capability/{hash} - Request access capability (if authorized)
POST   /auth/grant             - Grant access to another pubkey
DELETE /auth/revoke            - Revoke access
GET    /auth/locate/{hash}     - Resolve hash to storage URL(s)
```

**Note:** This is part of the Identikey suite. Will eventually move to separate repo, but building here for now since we need it.

---

### Phase 5: Recryption Proxy Server (recrypt-server)

**Duration:** 4-5 days  
**Goal:** Production recryption proxy with REST API (Axum)

**What recrypt-server IS:**

- The internet-connected recryption proxy
- Holds recrypt keys (semi-trusted—users can self-host)
- Streams KEM ciphertext through itself (wrapped key transforms)
- Does NOT hold user secret keys
- Does NOT see plaintext (only transforms encrypted key material)

**Architecture:**

```rust
recrypt-server/
├── src/
│   ├── main.rs
│   ├── routes/
│   │   ├── accounts.rs
│   │   ├── files.rs
│   │   ├── recryption.rs   // NOTE: "recryption" terminology
│   │   └── health.rs
│   ├── auth.rs             // Nonce + signature verification
│   ├── state.rs            // Application state
│   └── error.rs            // Error responses
└── tests/
    └── integration/
        ├── accounts_test.rs
        ├── recryption_test.rs
        └── e2e_test.rs
```

**Framework:** Axum (modern, fast, well-integrated with Tower)

**Dependencies:** Uses `recrypt-core` (crypto), `recrypt-proto` (serialization), `recrypt-storage` (S3 client), `identikey-storage-auth` (access control)

**Integration with Phase 3:**

Phase 5 will leverage protocol types from `recrypt-proto`:

- Content negotiation via `detect_format()` (protobuf/JSON/armor)
- Request/response serialization using `MultiFormat` trait
- `CapabilityProto` for access tokens (already defined)
- `RecryptRequest`/`RecryptResponse` for transformation API
- Streaming protobuf responses for efficient wire transfer

**API Routes:**

```
POST   /accounts                    - Create account (ED25519 + PQ keys)
GET    /accounts/{pubkey}           - Get account info
POST   /accounts/{pubkey}/keys      - Add/remove PQ keys
GET    /accounts/{pubkey}/files     - List files

POST   /files/{hash}/register       - Start file upload
POST   /files/{hash}/chunks         - Upload chunk
GET    /files/{hash}/chunks/{n}     - Download chunk
GET    /files/{hash}                - Download complete file

POST   /recryption/share            - Create share policy
GET    /recryption/shares/{pubkey}  - List shares
GET    /recryption/share/{id}       - Download shared file (with recryption)
DELETE /recryption/share/{id}       - Revoke share

GET    /health                      - Health check
```

**Key Features:**

- Multi-signature verification middleware
- Nonce-based replay prevention
- Rate limiting (Tower middleware)
- Structured logging with `tracing`
- Metrics with `metrics` crate
- Graceful shutdown

**Configuration:**

```rust
pub struct Config {
    pub host: String,
    pub port: u16,
    pub storage_backend: StorageConfig,
    pub crypto_params: CryptoParams,
    pub nonce_window: Duration,
}
```

**Testing:**

- Unit tests for each route handler
- Integration tests with test client
- E2E tests: full Alice->Bob sharing flow
- Load testing with `drill` or similar

---

### Phase 6: CLI Application (recrypt-cli)

**Duration:** 3-4 days  
**Goal:** User-friendly command-line interface

**Architecture:**

```rust
recrypt-cli/
├── src/
│   ├── main.rs
│   ├── commands/
│   │   ├── identity.rs   // Key management
│   │   ├── encrypt.rs
│   │   ├── decrypt.rs
│   │   ├── share.rs
│   │   └── files.rs
│   ├── client.rs         // HTTP client for server
│   └── config.rs         // CLI config management
└── tests/
    └── cli_tests.rs
```

**CLI Framework:** `clap` v4 with derive macros

**Command Structure:**

```
dcypher identity new [--output identity.json]
dcypher identity show <identity-file>

dcypher keys generate
dcypher keys inspect <pubkey>

dcypher encrypt <file> --for <pubkey> --output <file.enc>
dcypher decrypt <file.enc> --with <identity> --output <file>

dcypher share create <file-hash> --to <pubkey>
dcypher share list
dcypher share revoke <share-id>

dcypher files upload <file> [--server http://localhost:8000]
dcypher files download <file-hash> --output <file>
dcypher files list

dcypher server start [--config server.toml]
```

**Key Features:**

- Interactive prompts with `dialoguer` for sensitive operations
- Progress bars with `indicatif` for uploads/downloads
- Colored output with `colored`
- Config file support (TOML)
- Shell completions generation

**Identity File Format:**

```json
{
  "version": "1.0",
  "public_key": {
    "ed25519": "...",
    "pq_keys": [{ "alg": "ML-DSA-87", "key": "..." }],
    "pre_key": "..."
  },
  "secret_key": {
    "ed25519": "...",
    "pq_keys": [{ "alg": "ML-DSA-87", "key": "..." }],
    "pre_key": "..."
  },
  "crypto_context": "..." // Serialized context
}
```

**Testing:**

- Command parsing tests
- Integration tests with mock server
- E2E tests with real server

---

### Phase 7: Minimal Rad TUI (dcypher-tui) — ⏸️ DEFERRED

**Status:** Deferred until after production deployment  
**Duration:** 2-3 days (when resumed)  
**Goal:** Inherit spirit, lose bloat

**Rationale for deferral:** CLI provides full functionality. TUI is a nice-to-have enhancement for power users, not a launch blocker.

**Framework:** `ratatui` (formerly tui-rs) - lightweight, no heavy deps

**Screens (Minimal Set):**

1. **Dashboard** - System status, active operations
2. **Files** - Browse, upload, download
3. **Sharing** - Create/revoke shares
4. **Keys** - Identity management

---

### Phase 8: Documentation & Deployment

**Duration:** 2-3 days  
**Goal:** Production-ready documentation and deployment guides

**Deliverables:**

1. **User Guide** (`docs/user-guide.md`)

   - CLI command reference
   - Common workflows (encrypt, share, revoke)
   - Wallet management
   - Configuration options

2. **API Documentation** (`docs/api-reference.md`)

   - Server endpoints
   - Authentication flow
   - Request/response formats
   - Error codes

3. **Deployment Guide** (`docs/deployment.md`)

   - Docker deployment
   - Systemd service setup
   - Cloud deployment (AWS, GCP, etc.)
   - Configuration reference
   - Backup and recovery

4. **Operations Guide** (`docs/operations.md`)
   - Monitoring and logging
   - Troubleshooting
   - Performance tuning

---

### Phase 9: E2E Testing & Security Audit Prep

**Duration:** 1-2 days  
**Goal:** Validate full system and prepare for security review

**E2E Test Scenarios:**

1. Alice creates identity, registers on server
2. Alice encrypts file locally
3. Alice uploads encrypted file to server
4. Alice shares file with Bob (creates recryption key)
5. Bob downloads and decrypts file via recryption
6. Alice revokes Bob's access
7. Bob can no longer access file

**Security Audit Prep:**

1. **Threat Model** (`docs/security/threat-model.md`)

   - Assets and trust boundaries
   - Attack vectors
   - Mitigations

2. **Cryptographic Design Review** (`docs/security/crypto-review.md`)

   - Algorithm choices and rationale
   - Key management
   - Known limitations

3. **Audit Checklist** (`docs/security/audit-checklist.md`)
   - Code areas requiring review
   - Dependencies with crypto
   - FFI boundary considerations

---

## Workspace Structure (Final)

```
dcypher/
├── README.md
├── Cargo.toml                      # Workspace root
├── Cargo.lock
│
├── crates/
│   ├── recrypt-ffi/                # OpenFHE + liboqs FFI bindings
│   │   ├── Cargo.toml
│   │   ├── build.rs                # cxx-build integration
│   │   └── src/
│   │
│   ├── recrypt-core/               # Core crypto operations
│   │   ├── Cargo.toml
│   │   └── src/
│   │
│   ├── recrypt-proto/              # Wire protocol + serialization
│   │   ├── Cargo.toml
│   │   └── src/
│   │
│   └── recrypt-storage/            # S3-compatible storage layer
│       ├── Cargo.toml
│       └── src/
│
├── recrypt-cli/                    # CLI binary
│   ├── Cargo.toml
│   └── src/
│
├── recrypt-server/                 # Recryption proxy + HTTP API (streams KEM ciphertext)
│   ├── Cargo.toml
│   └── src/
│
├── identikey-storage-auth/         # Auth service for S3 (future: separate Identikey repo)
│   ├── Cargo.toml
│   └── src/
│
├── dcypher-tui/                    # TUI binary
│   ├── Cargo.toml
│   └── src/
│
├── docs/                           # Design documents
│   ├── hybrid-encryption-architecture.md
│   ├── pre-backend-traits.md
│   ├── hashing-standard.md
│   ├── verification-architecture.md
│   ├── non-determinism.md
│   ├── storage-design.md
│   ├── wire-protocol.md
│   └── archive/                    # Archived specs (HDprint, HMAC analysis)
│
├── python-prototype/               # ARCHIVED: Original Python implementation
│   └── [all existing Python code]
│
└── docker/
    ├── docker-compose.dev.yml      # Minio + services for development
    └── Dockerfile                  # Production build
```

---

## Key Dependencies (Preliminary)

### Cryptography

- `cxx` - C++/Rust FFI for OpenFHE bindings
- `oqs` v0.11 - Post-quantum signatures (ML-DSA) via liboqs
- `ed25519-dalek` - ED25519 signatures
- `blake3` - Hashing (standardized)
- `rand` + `rand_core` - Cryptographic RNG

### Serialization

- `serde` + `serde_json` - Config files, identity files
- `prost` or `capnp` or `flatbuffers` - Wire protocol (TBD)
- `base64` - ASCII armor encoding
- `hex` - Hex encoding for debugging

### Storage

- `aws-sdk-rust` or `rusoto_s3` - S3 API client
- `tokio` - Async runtime
- `tower` + `tower-http` - HTTP middleware

### Server

- `axum` - HTTP framework
- `tracing` + `tracing-subscriber` - Structured logging
- `metrics` + `metrics-exporter-prometheus` - Observability
- `tower-http` - CORS, compression, rate limiting

### CLI/TUI

- `clap` - CLI argument parsing
- `ratatui` - TUI framework
- `dialoguer` - Interactive prompts
- `indicatif` - Progress bars
- `colored` - Terminal colors

### Development

- `thiserror` - Error handling
- `anyhow` - Error propagation in binaries
- `proptest` - Property-based testing
- `criterion` - Benchmarking
- `mockall` - Mocking for tests

---

## Migration Notes from Python Prototype

### Files to Reference (Now Archived)

```
python-prototype/
├── src/dcypher/lib/pre.py          # Core crypto operations
├── src/dcypher/lib/idk_message.py  # Message format (needs revision)
├── src/dcypher/routers/            # API endpoint logic
└── docs/spec.md                    # Original IDK spec (update for Rust)
```

### What NOT to Port

- ❌ `dcypher/lib/auth.py` - ECDSA verification (dropping SECP256k1)
- ❌ `dcypher/routers/storage.py` - Naive file storage (moving to S3)
- ❌ `dcypher/tui/widgets/` - Heavy widgets (minimal TUI instead)
- ❌ `dcypher/lib/profiling.py` - Profiling infrastructure (use Rust tooling)
- ❌ Test harness for Python-Rust compatibility (not needed)

### Terminology Migration

- `re_encrypt` → `recrypt`
- `re_encryption_key` → `recrypt_key`
- `rekey` → `recrypt_key` (consistent naming)
- Everything else: `recryption` (already correct)

### No Compatibility Requirements

- ✅ Can't decrypt Python ciphertexts with Rust (different serialization)
- ✅ Can't verify Python signatures with Rust (different key formats)
- ✅ Can't parse Python IDK messages with Rust (format changing)
- ✅ Fresh start = clean design

**This is a feature, not a bug.**

---

## Success Criteria

### Phase 0 Complete When:

- [x] All 7 design questions answered with documented decisions
- [x] Architecture docs written and reviewed
- [x] Rust workspace structure defined
- [x] Dependency list finalized

### Phase 1 Complete When:

- [x] Can encrypt/decrypt in Rust using OpenFHE
- [x] Can generate/verify ED25519 signatures
- [x] Can generate/verify PQ signatures (ML-DSA-87) — via `oqs` crate v0.11
- [x] Can generate recryption keys
- [x] Can perform recryption transformation
- [x] All FFI smoke tests passing — 16 tests

### Phase 2 Complete When:

- [x] Core crypto API stable and documented
- [x] Property-based tests passing
- [x] Known-answer tests for regression
- [x] Benchmarks baseline established
- [x] Documentation with examples

### Phase 3 Complete When:

- [x] Wire protocol defined and implemented (Protobuf + ASCII armor + JSON)
- [x] Blake3/Bao tree verification working
- [x] Message serialization round-trips (all formats)
- [x] Signature verification integrated (wrapped_key || bao_hash)
- [x] Streaming verification functional
- [x] MultiFormat trait for polymorphic serialization
- [x] 29 tests passing, 0 failures
- [ ] Lattice backend serialization (DEFERRED - exists in openfhe-sys, wiring when activated)

### Phase 4 Complete When:

- [x] Local file storage working
- [x] Minio integration functional
- [x] S3 integration tested
- [x] Docker compose dev environment
- [x] Concurrent access patterns validated (thread-safe via RwLock, async throughout)

### Phase 4b Complete When:

- [x] `OwnershipStore` trait with `InMemoryOwnershipStore` and `SqliteOwnershipStore`
- [x] `ProviderIndex` trait with `InMemoryProviderIndex` and `SqliteProviderIndex`
- [x] `Capability` domain type with signing and verification
- [x] `AccessGrant` for tracking delegated access
- [x] Ownership registration, transfer, and revocation working
- [x] Capability issuance, expiry checking, and verification working
- [x] Hash → provider URL lookup and migration working
- [x] Access grant/revoke flow working
- [x] Integration tests with recrypt-storage validated
- [x] SQLite persistence layer functional

**Plan:** `docs/plans/2026-01-06-phase-4b-storage-auth.md`

### Phase 5 Complete When:

- [x] All API routes functional
- [x] Multi-sig verification working
- [x] Nonce replay prevention validated
- [x] E2E Alice->Bob sharing flow works (automated tests validate)
- [x] Load testing baseline established (deferred to Phase 5b)

**Plan:** `docs/plans/2026-01-07-phase-5-recryption-proxy.md` ✅ COMPLETE

### Phase 6 Complete When:

- [x] Identity management (new, list, show, use, delete, export, import)
- [x] Password-encrypted wallet functional
- [x] Local encrypt/decrypt working
- [x] HTTP client for server API
- [x] Account register/show working
- [x] Files upload/download/list/delete working
- [x] Share create/list/download/revoke working
- [x] Server list endpoints added
- [x] Pretty and JSON output modes
- [x] Config file management working

**Plan:** `docs/plans/2026-01-13-phase-6-cli-application.md` ✅ COMPLETE

### Phase 6b Complete When:

- [x] CredentialProvider trait abstraction
- [x] macOS Keychain integration (via security-framework crate)
- [x] Linux Secret Service integration (via keyring crate)
- [x] Windows Credential Manager integration (via keyring crate)
- [x] EnvProvider for CI (`DCYPHER_WALLET_KEY`)
- [x] MemoryProvider for tests
- [x] Key caching works (no password prompt on subsequent runs)
- [x] Wallet lock/unlock/status/path commands

**Plan:** `docs/plans/2026-01-14-phase-6b-secure-credential-storage.md` ✅ COMPLETE

### Phase 7: TUI — ⏸️ DEFERRED

TUI development deferred until after production deployment. CLI provides full functionality.

### Phase 8 Complete When:

- [x] User guide (CLI usage, common workflows) — `docs/user-guide.md`
- [ ] API documentation (server endpoints)
- [ ] Deployment guide (Docker, systemd, cloud)
- [ ] Configuration reference

### Phase 9 Complete When:

- [ ] Full Alice→Bob E2E flow tested CLI-to-CLI via server
- [ ] Security audit prep document ready
- [ ] Threat model documented
- [ ] Key management best practices documented

### Overall Complete When:

- [ ] Full Alice->Bob E2E flow works CLI-to-CLI via server
- [ ] Documentation complete (user guide + API docs)
- [ ] Deployment guide written
- [ ] Security audit prep document ready

---

## Timeline Estimate

**Phase 0:** 2-3 days (design decisions) ✅ COMPLETE  
**Phase 1:** 3-5 days (FFI bindings) ✅ COMPLETE  
**Phase 2:** 4-5 days (core crypto) ✅ COMPLETE  
**Phase 3:** 3-4 days (protocol) ✅ COMPLETE  
**Phase 4:** 3-4 days (storage client) ✅ COMPLETE  
**Phase 4b:** 3-4 days (auth service) ✅ COMPLETE  
**Phase 5:** 4-5 days (recryption proxy server) ✅ COMPLETE  
**Phase 6:** 4-5 days (CLI) ✅ COMPLETE  
**Phase 6b:** 2-3 days (secure credential storage) ✅ COMPLETE  
**Phase 7:** ⏸️ DEFERRED (TUI)  
**Phase 8:** 2-3 days (documentation & deployment)  
**Phase 9:** 1-2 days (E2E testing & security audit prep)

**Total:** ~30 days to production-ready (excluding TUI)

---

## Next Steps

1. **Now:** Complete Phase 8 — Documentation & Deployment Guide
2. **Then:** Phase 9 — Full E2E testing & Security Audit Prep
3. **Future:** Phase 7 TUI (post-launch enhancement)

---

## Notes for Future Maintainers

- **Non-determinism is normal:** Don't expect byte-level equality in tests
- **Context is precious:** Keep crypto context alive for related operations
- **Recryption not re-encryption:** Consistent terminology throughout
- **S3 is flexible:** Easy to swap storage backends via trait
- **Blake3 fingerprints are simple:** `blake3(pubkey) → base58` — no fancy error correction needed
- **Security over performance:** But both are achievable with good design

---

**This document is the source of truth for Recrypt implementation. Update as progress is made.**
