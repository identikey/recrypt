# Storage Design: Content-Addressed + Authentication Service

**Status:** ✅ DECIDED  
**Decision:** Content-addressed storage (IPFS-style) with separate Authentication Service layer

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLIENTS                                         │
│  CLI, TUI, Web App, Mobile, etc.                                            │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
┌───────────────────────┐ ┌─────────────────┐ ┌─────────────────────────────┐
│  AUTHENTICATION       │ │  RECRYPTION     │ │  S3-COMPATIBLE STORAGE      │
│  SERVICE              │ │  PROXY          │ │  (Minio/AWS/Backblaze)      │
│                       │ │                 │ │                             │
│  - Ownership index    │ │  - Recrypt keys │ │  - Single shared bucket     │
│  - Access capabilities│ │  - Transform CT │ │  - Objects keyed by hash    │
│  - Provider registry  │ │  - Lean & mean  │ │  - Automatic dedup          │
│  - Metadata (TBD)     │ │  - Self-hostable│ │  - Any S3-compatible        │
└───────────────────────┘ └─────────────────┘ └─────────────────────────────┘
```

---

## Core Principles

### 1. Content-Addressed Storage (IPFS-style)

Files are referenced by their **Blake3 hash**, not by path or user namespace:

```
GET /storage/{blake3_hash}
```

**Benefits:**

- **Hosting agility:** Move files between providers; hash stays the same
- **Deduplication:** Identical content stored once
- **Integrity:** Hash proves content authenticity
- **Cacheability:** Immutable by hash → infinite cache TTL

### 2. Separation of Concerns

| Service          | Responsibility                    | Trust Level                  |
| ---------------- | --------------------------------- | ---------------------------- |
| Auth Service     | Identity, ownership, capabilities | Trusted                      |
| Recryption Proxy | Key transformation                | Semi-trusted (self-hostable) |
| S3 Storage       | Blob storage                      | Untrusted (just bytes)       |

### 3. Hosting Agility

Files can migrate between storage providers without breaking references:

```
Auth Service maintains:
  hash → [provider1_url, provider2_url, ...]

Client requests file by hash, gets list of locations
```

---

## Authentication Service

### Responsibilities

1. **Ownership Index:** Maps `pubkey → [owned_file_hashes]`
2. **Access Capabilities:** Issues signed tokens for file access
3. **Provider Registry:** Maps `hash → [storage_provider_urls]`
4. **Metadata Storage:** (TBD: inline in S3 vs in auth service)

### API

```
# Register file ownership
POST /auth/files
Authorization: <ED25519 + PQ multi-sig>
Body: { file_hash, metadata_hash }

# Request access capability
GET /auth/files/{hash}/capability
Authorization: <signature proving identity>
Response: { capability_token, expires_at, storage_urls }

# Lookup file locations
GET /auth/files/{hash}/locations
Response: { storage_urls: ["https://s3-1.example.com/...", ...] }

# Transfer ownership (for sharing)
POST /auth/files/{hash}/share
Authorization: <owner signature>
Body: { recipient_pubkey, access_level }
```

### Capability Token

A capability is a signed, time-limited authorization:

```rust
struct Capability {
    file_hash: [u8; 32],
    granted_to: PublicKey,      // Who can use this
    operations: Vec<Operation>, // read, write, delete
    expires_at: u64,            // Unix timestamp
    issuer_signature: Signature,
}

enum Operation {
    Read,
    Write,
    Delete,
}
```

Client presents capability to storage layer:

```
GET /storage/{hash}
Authorization: Bearer <base64(capability)>
```

Storage layer verifies:

1. Capability signature valid (from trusted auth service)
2. Not expired
3. Operation permitted
4. Hash matches

---

## S3 Storage Layer

### Bucket Structure

Single bucket, content-addressed by algorithm-prefixed hash:

```
s3://recrypt-storage/
  ├── chunks/
  │   └── b3/                              # Blake3 algorithm prefix
  │       ├── 2DrjgbLkLvvE6wvQyYCe9XN2Xm9L8dT3FJgKr2HJvAP1
  │       ├── 4Qn8kYr5pW3mVxN7tZ9aB2cD6eF8gH1jK4lM0nPqR3sU
  │       └── ...
  └── metadata/  (if storing metadata in S3)
      └── b3/
          ├── {file_hash_base58}.meta
          └── ...
```

### Object Naming

```
chunks/{algorithm}/{hash_base58}

Example:
chunks/b3/2DrjgbLkLvvE6wvQyYCe9XN2Xm9L8dT3FJgKr2HJvAP1
```

**Format rationale:**

- `b3` prefix = Blake3 (enables future hash algorithm agility)
- Base58 encoding = ~31% shorter than hex, still human-readable
- No ambiguous characters (0/O, 1/l excluded)

### Storage Trait

```rust
#[async_trait]
pub trait ChunkStorage: Send + Sync {
    /// Store chunk by its hash
    async fn put(&self, hash: &blake3::Hash, data: &[u8]) -> Result<()>;

    /// Retrieve chunk by hash
    async fn get(&self, hash: &blake3::Hash) -> Result<Vec<u8>>;

    /// Check if chunk exists
    async fn exists(&self, hash: &blake3::Hash) -> Result<bool>;

    /// Delete chunk
    async fn delete(&self, hash: &blake3::Hash) -> Result<()>;
}
```

### ChunkManifest

`crates/recrypt-storage/src/chunking.rs` provides a flat manifest for files
that have been split into content-addressed 4 MiB (default) chunks:

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChunkManifest {
    pub hash_algorithm: String,          // "blake3", validated on join()
    #[serde(with = "blake3_base58")]
    pub file_hash: Hash,                 // Blake3 of the full file
    pub total_size: u64,
    #[serde(with = "vec_blake3_base58")]
    pub chunk_hashes: Vec<Hash>,         // one hash per 4 MiB chunk
    pub chunk_size: usize,
}
```

The manifest is JSON-serializable (Blake3 hashes serialize as base58
strings via custom `serde` helpers). `join()` validates that
`manifest.hash_algorithm == "blake3"` before attempting verification —
a manifest claiming a different algorithm is rejected rather than
silently re-verified with Blake3.

**Note — chunking vs Bao (convergence pending).** The per-chunk Blake3
hashes in the manifest provide integrity on top of the storage layer,
but once streaming Bao verification lands in `recrypt-core` (see
[verification-architecture.md](verification-architecture.md)), the
manifest's integrity role becomes redundant: Bao's outboard gives
finer-grained leaves (1024 B), O(log n) proofs, and random access over
the same ciphertext. The likely endgame is that `ChunkManifest` shrinks
to a pure storage-layout concern (split into 4 MiB blobs for S3
multipart/dedup), with all integrity delegated to Bao. Until then the
two layers coexist; `manifest.file_hash` and `EncryptedFile.bao_hash`
compute the same 32-byte value over the same bytes.

### Implementations

```rust
// Development
pub struct MinioStorage { /* ... */ }

// Production
pub struct S3Storage { /* ... */ }

// Testing
pub struct InMemoryStorage { /* ... */ }
pub struct LocalFileStorage { /* ... */ }
```

---

## Recryption Proxy

### Design Principles

1. **Lean:** Only handles recryption operations
2. **Special-purpose:** No storage, no metadata, just crypto
3. **Self-hostable:** Users with security requirements run their own
4. **Semi-trusted:** Holds recryption keys, never plaintext

### API

```
# Register recryption key
POST /proxy/keys
Authorization: <owner signature>
Body: { from_pubkey, to_pubkey, recrypt_key }

# Request recryption
POST /proxy/recrypt
Authorization: <owner or delegate signature>
Body: { file_hash, ciphertext_chunks }
Response: { recrypted_chunks }

# Revoke recryption key
DELETE /proxy/keys/{key_id}
Authorization: <owner signature>
```

### Security Model

The proxy:

- ✅ Can transform ciphertexts (Alice→Bob)
- ❌ Cannot decrypt (no secret keys)
- ❌ Cannot forge ciphertexts (no signing keys)
- ⚠️ Could refuse to recrypt (availability attack)
- ⚠️ Could log access patterns (metadata leakage)

**Mitigation:** Users self-host for sensitive data.

---

## Metadata Storage: Open Question

### Option A: Inline in S3

```
s3://recrypt-storage/
  └── metadata/{file_hash}.meta
```

**Pros:**

- Metadata lives with data
- Single storage layer
- Easy backup/migration

**Cons:**

- Auth service must query S3 for lookups
- S3 not optimized for small objects
- Harder to index/search

### Option B: In Auth Service Database

```sql
CREATE TABLE file_metadata (
    file_hash BYTEA PRIMARY KEY,
    owner_pubkey BYTEA NOT NULL,
    wrapped_key BYTEA NOT NULL,
    bao_root BYTEA NOT NULL,
    chunk_hashes BYTEA[] NOT NULL,
    created_at TIMESTAMP NOT NULL,
    -- ... other fields
);
```

**Pros:**

- Fast lookups and queries
- Auth service already manages ownership
- Indexing for search

**Cons:**

- Data split across systems
- Database scaling considerations
- Migration complexity

### Recommendation

**Analyze further.** Consider:

- Query patterns (how often is metadata accessed?)
- Size of metadata (affects S3 small-object overhead)
- Consistency requirements (eventual vs strong)

---

## File Upload Flow

```
┌────────┐     ┌────────────┐     ┌─────────┐
│ Client │     │ Auth Svc   │     │ Storage │
└───┬────┘     └─────┬──────┘     └────┬────┘
    │                │                  │
    │ 1. Request upload capability      │
    ├───────────────►│                  │
    │                │                  │
    │ 2. Capability token               │
    │◄───────────────┤                  │
    │                │                  │
    │ 3. Upload chunks with capability  │
    ├──────────────────────────────────►│
    │                │                  │
    │ 4. Chunk stored                   │
    │◄──────────────────────────────────┤
    │                │                  │
    │ 5. Register file with metadata    │
    ├───────────────►│                  │
    │                │                  │
    │ 6. File registered                │
    │◄───────────────┤                  │
    │                │                  │
```

## File Download Flow

```
┌────────┐     ┌────────────┐     ┌─────────┐
│ Client │     │ Auth Svc   │     │ Storage │
└───┬────┘     └─────┬──────┘     └────┬────┘
    │                │                  │
    │ 1. Request file by hash           │
    ├───────────────►│                  │
    │                │                  │
    │ 2. Verify access, return:         │
    │    - Capability token             │
    │    - Storage URLs                 │
    │    - Metadata (wrapped key, etc)  │
    │◄───────────────┤                  │
    │                │                  │
    │ 3. Download chunks with capability│
    ├──────────────────────────────────►│
    │                │                  │
    │ 4. Chunks (verified via Bao)      │
    │◄──────────────────────────────────┤
    │                │                  │
```

---

## Development Environment

### Docker Compose

```yaml
version: "3.8"
services:
  minio:
    image: minio/minio
    ports:
      - "9000:9000" # S3 API
      - "9001:9001" # Console
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    command: server /data --console-address ":9001"
    volumes:
      - minio_data:/data

  auth-service:
    build: ./recrypt-server
    ports:
      - "8080:8080"
    environment:
      STORAGE_ENDPOINT: http://minio:9000
      DATABASE_URL: postgres://...
    depends_on:
      - minio
      - postgres

  recryption-proxy:
    build: ./dcypher-proxy
    ports:
      - "8081:8081"
    environment:
      AUTH_SERVICE_URL: http://auth-service:8080

  postgres:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD: postgres
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  minio_data:
  postgres_data:
```

---

## Dependencies

```toml
[dependencies]
aws-sdk-s3 = "1"
tokio = { version = "1", features = ["full"] }
```

---

## Open Questions

1. **Metadata location:** S3 vs Auth Service database?
2. **Capability format:** JWT vs custom signed struct?
3. **Multi-provider redundancy:** How to handle same file on multiple providers?
4. **Garbage collection:** How to clean up orphaned chunks?
5. **Rate limiting:** Per-user limits on storage/bandwidth?

---

## References

- [IPFS Content Addressing](https://docs.ipfs.io/concepts/content-addressing/)
- [Capability-based Security](https://en.wikipedia.org/wiki/Capability-based_security)
- [AWS S3 SDK for Rust](https://docs.rs/aws-sdk-s3)
