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

Files are referenced by their **BLAKE3 hash**, not by path or user namespace:

```
GET /storage/{blake3_hash}
```

**Benefits (in order of importance for recrypt):**

- **Backend agility (the real reason).** The blob's identity equals its
  content hash. Migrating from S3 to Backblaze to local disk to an
  iroh-blobs peer network requires no rename, no metadata rewrite, and
  no re-signing: the blob is byte-identical on every backend, so its
  identifier is identical on every backend. Any component holding the
  hash can fetch from any provider without a lookup step. `ProviderIndex`
  in `identikey-storage-auth` maps `file_hash → [provider_urls]` for
  exactly this reason.
- **Cacheability.** Immutable by hash → infinite cache TTL, cheap
  deduplication at CDN / browser / client levels.
- **Retry idempotency.** An interrupted upload retries to the same S3
  key; the second PUT is a no-op.
- **iroh interop.** The 32-byte BLAKE3 root we use as a storage key is
  bit-identical to the blob ID iroh-blobs uses for the same bytes. If we
  later want to serve or fetch files through an iroh peer network, the
  content addresses are already compatible.
- **Signed integrity is cheap to verify.** Combined with a signature
  over `wrapped_key || bao_hash`, the storage key *is* the signed root.
  A recipient knows which bytes they expect before fetching.

**Non-benefit (historical):** Cross-user or same-user deduplication.
Every `HybridEncryptor::encrypt` call generates fresh random XChaCha20
material, so identical plaintexts never produce identical ciphertexts.
Chunk-level dedup finds zero collisions in practice. This was an
inherited assumption from IPFS-style designs and does not apply to
recrypt; it should not be cited as a motivation.

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

Single bucket, content-addressed by BLAKE3 hash. Two objects per
encrypted file: the ciphertext blob and (for blobs > 16 KiB) a sibling
Bao outboard for streaming verification.

```
s3://recrypt-storage/blob/b3/
  ├── 2DrjgbLkLvvE6wvQyYCe9XN2Xm9L8dT3FJgKr2HJvAP1          # ciphertext
  ├── 2DrjgbLkLvvE6wvQyYCe9XN2Xm9L8dT3FJgKr2HJvAP1.obao    # bao-tree outboard
  ├── 4Qn8kYr5pW3mVxN7tZ9aB2cD6eF8gH1jK4lM0nPqR3sU
  ├── 4Qn8kYr5pW3mVxN7tZ9aB2cD6eF8gH1jK4lM0nPqR3sU.obao
  └── ...
```

### Object Naming

```
blob/b3/{base58(blake3(ciphertext))}           # ciphertext blob
blob/b3/{base58(blake3(ciphertext))}.obao      # bao-tree outboard sibling (files > 16 KiB)
```

**Format rationale:**

- **Flat namespace under `blob/b3/`.** The BLAKE3 hash is the full identifier.
  The prefix enables future object-lifecycle rules (e.g., abort incomplete
  multipart uploads in this prefix).
- **Base58 encoding** — ~31% shorter than hex, still human-readable, no
  ambiguous characters (0/O, 1/l excluded).
- **`.obao` suffix** matches the iroh-blobs convention for sibling
  outboard objects. Interop-friendly.
- **Small files (≤ 16 KiB) skip the outboard entirely.** A single
  Bao chunk group (16 KiB) = the BLAKE3 root, so no verification tree is needed.
  A `GET` for the `.obao` sibling returns 404, and the client treats this as
  "no outboard needed".

### Storage Trait: Two-Object API

```rust
#[async_trait]
pub trait BlobStorage: Send + Sync {
    /// Store ciphertext and outboard
    async fn put_with_outboard(
        &self,
        hash: &blake3::Hash,
        ciphertext: impl AsyncRead + Unpin,
        outboard: &[u8],  // empty for files ≤ 16 KiB
    ) -> Result<()>;

    /// Retrieve ciphertext and outboard separately
    async fn get_with_outboard(
        &self,
        hash: &blake3::Hash,
    ) -> Result<(
        Box<dyn AsyncRead + Unpin>,     // ciphertext
        Box<dyn AsyncRead + AsyncSeek + Unpin>, // outboard or empty
    )>;

    /// Delete both ciphertext and outboard
    async fn delete_with_outboard(&self, hash: &blake3::Hash) -> Result<()>;
}
```

**Key design:**

- **Outboard is optional.** `put_with_outboard` accepts an empty outboard
  byte slice for files ≤ 16 KiB; it skips the `.obao` PUT entirely in
  that case.
- **No per-chunk dedup.** Every call to `encrypt_streaming` uses fresh random
  symmetric key material, so identical plaintexts never produce identical
  ciphertexts. Per-call random keys eliminate any chunk-level dedup benefit.
  The storage layer stores full files identified by their ciphertext hash.

### Orphan Garbage Collection

S3 buckets have a lifecycle rule to abort incomplete multipart uploads after
24 hours (see the deployment guide). Application-level GC for fully-uploaded
orphaned objects (those with no metadata record) is a planned follow-up; it
requires a real metadata service client before it can safely delete data.

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
