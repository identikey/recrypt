# Bao Streaming Verification + Storage Simplification

**Date:** 2026-04-06
**Status:** ✅ Substantially complete (2026-04-19). Retained as the
design reference, including the explicitly-deferred §8.6
(XChaCha20-Poly1305 belt-and-suspenders) and §11.5 (non-transferable
PRE). Implementation history lives in `git log`.
**Phase:** 8 (Documentation & Deployment)
**Authors:** Duke Jones, Claude

> **TL;DR** Replace the bare `bao` crate with `bao-tree` (the n0-computer
> fork, same team as iroh) at a 16 KiB chunk group size. Store the outboard
> as a sibling S3 object `{hash}.obao` and always fetch it whole — at 16 KiB
> groups the outboard is tiny (~1.3 MiB even for a 10 GiB file). Add
> `decrypt_streaming` / `decrypt_range` to `HybridEncryptor` so callers pass
> in readers and receive verified plaintext without ever touching a Merkle
> proof directly. Delete `recrypt-storage::chunking::ChunkManifest` — with
> per-encryption random keys it provides zero dedup value and Bao fully
> supersedes its integrity role. Clean slate; no existing streaming code to
> migrate.

---

## 1. Motivation

### 1.1 What's broken today

The current state, as of the doc pass that preceded this plan:

- **`EncryptedFile.bao_outboard` is computed and stored but never consumed.**
  `HybridEncryptor::decrypt` verifies integrity with
  `blake3::hash(ciphertext) == bao_hash`. That's a valid check (the Bao root
  equals plain BLAKE3 over the data, so both produce the same 32-byte
  value), but it requires the *whole ciphertext in memory* and gives us no
  streaming or random-access benefit.
- **The entire client path is buffer-everything.** `recrypt-cli decrypt`
  reads the full file into a `Vec<u8>` before calling `decrypt()`. Same on
  the server recryption path. Nothing streams.
- **`recrypt-storage::chunking::ChunkManifest` provides zero dedup
  benefit.** Every `HybridEncryptor::encrypt` call generates a fresh random
  XChaCha20 key + nonce, so two encryptions of the same plaintext produce
  entirely different ciphertexts. Chunk-level dedup cannot find collisions.
  The only thing `ChunkManifest` actually does is add a second, weaker
  integrity layer on top of `bao_hash` — computing `blake3(full_file)` and a
  flat list of per-chunk hashes. Bao's outboard subsumes both.
- **We pay real S3 request cost for chunking.** Splitting a 1 GiB file into
  256 × 4 MiB chunks is 256 PUTs and 256 GETs. Monolithic object + HTTP
  Range GETs is the standard S3 pattern and is 10–100× cheaper in request
  fees (see §7 for numbers).
- **The removed `recrypt-proto::bao_stream` module** (deleted during the
  doc pass) had the right intent — a `BaoEncoder`/`BaoDecoder`/`SliceVerifier`
  API — but its `verify()` actually just compared `blake3::hash(data)`
  against the root, presented as if it were tree verification. It was dead
  code and was removed.

### 1.2 What we want

1. **Streaming verification.** Read ciphertext bytes from the network; have
   tampering caught mid-stream, not after a full buffer.
2. **Random-access decryption.** "Give me the plaintext from byte 500 MB to
   byte 600 MB" should require fetching only ~100 MB of ciphertext from
   S3, not the whole file. This is the feature that justifies carrying a
   verification tree at all.
3. **No application-layer chunking.** One S3 object per ciphertext. Storage
   chunking is S3's multipart upload concern, not ours.
4. **No proof protocol.** Clients don't exchange Merkle proofs with
   servers. The verification tree is a local-only data structure that the
   client fetches whole (it's small enough) and uses to validate a stream.
5. **Interop with iroh's content addressing** so that the other repos using
   iroh can recognize our content hashes.

---

## 2. Decision

### 2.1 Primitive: `bao-tree` at 16 KiB chunk groups

We use the [`bao-tree`](https://crates.io/crates/bao-tree) crate, version
0.5 or later, maintained by `n0-computer` (the iroh team). Chunk group size:
**16 KiB** (block_size_log = 4), matching iroh-blobs' production default.

Why not the alternatives:

| Option | Why not |
|---|---|
| bare `bao` 0.12 / 0.13 | Sync-only API; fixed 1 KiB leaves → unshippable outboard sizes (~600 MiB for 10 GiB); less active maintenance |
| `iroh-blobs` | Tightly couples us to iroh's QUIC stack and blob store; we use S3+HTTP, not peer-to-peer; 5–10 MiB of dependency weight for features we don't use |
| **`bao-tree`** ✅ | Async-native; configurable chunk groups; wire-format compatible with iroh-blobs; maintained by the same team; same 32-byte BLAKE3 root as every other option |

**Iroh interop comes for free.** The 32-byte BLAKE3 root hash we compute
with `bao-tree` is bit-identical to the content identifier iroh-blobs uses
for the same bytes. If we later want to serve files peer-to-peer via iroh, or
fetch a file that an iroh-blobs peer has, the hashes match and the wire
format of any Bao-encoded range is compatible.

### 2.2 Chunk group size: why 16 KiB

At 16 KiB groups (vs 1 KiB for bare `bao`), the outboard shrinks by ~16×.
Concretely, the outboard size at 16 KiB groups is ~0.013% of the blob size:

| Blob size | Outboard size @ 16 KiB groups | Slice proof size |
|-----------|-------------------------------|------------------|
| ≤16 KiB   | **0 bytes** (single chunk group; root hash alone suffices) | n/a |
| 1 MiB     | ~4 KiB                        | ~192 B |
| 100 MiB   | ~400 KiB                      | ~416 B |
| 1 GiB     | ~4 MiB                        | ~512 B |
| 10 GiB    | ~1.3 MiB                      | ~640 B |
| 100 GiB   | ~13 MiB                       | ~768 B |

At these sizes, **we never need a per-slice Merkle proof protocol**. Clients
fetch the full outboard once per file (one S3 GET, a few hundred KiB to a
couple MiB), keep it in memory, and use it to verify any range of the
ciphertext for free. We only lose the ability to verify ranges smaller than
16 KiB — for streaming plaintext, that's not a meaningful constraint.

Files at or below 16 KiB fit entirely in a single chunk group and need no
outboard at all; the BLAKE3 root hash is the whole verification. We follow
iroh-blobs' convention and store no sibling object for these.

### 2.3 Storage layout: monolithic object + sibling outboard

```
s3://recrypt-store/
  chunks/
    b3/
      <base58(bao_hash)>           <- ciphertext blob, single object
      <base58(bao_hash)>.obao      <- bao-tree outboard (only if file > 16 KiB)
```

- **One ciphertext object per encrypted file.** Supports HTTP Range GET for
  streaming and resume.
- **Sibling outboard object** with `.obao` suffix, small enough to always
  fetch whole on first access. Skipped entirely for files ≤ 16 KiB.
- **S3 key = base58(bao_hash) = base58(blake3(ciphertext))** — one
  authoritative content identifier across the whole system. Same value
  that appears in `EncryptedFileProto.bao_hash`, same value used by
  `recrypt-storage-auth` as a content address, same value iroh-blobs
  would use as a blob ID for the same bytes.

The `.obao` suffix matches iroh-blobs' naming (`{hash}.obao4` where `4` is
the chunk group log — we'll use the same suffix so tooling is compatible).

### 2.4 Wire format change: `EncryptedFileProto` v3

`EncryptedFileProto` drops `bao_outboard`:

```protobuf
message EncryptedFileProto {
    uint32              version      = 1;   // bump to 3
    CiphertextProto     wrapped_key  = 2;
    bytes               bao_hash     = 3;   // unchanged: 32-byte root
    // bytes            bao_outboard = 4;   // REMOVED
    bytes               ciphertext   = 5;
    MultiSignatureProto signature    = 6;   // signs (wrapped_key || bao_hash), unchanged
}
```

Protobuf field numbers are not reused (`bao_outboard = 4` stays retired
forever). The signature payload is **unchanged** — it was always
`wrapped_key_bytes || bao_hash`, never including the outboard, so dropping
the outboard field does not require re-signing anything that already
exists.

The outboard moves out of the envelope entirely. It is no longer part of
"the encrypted file"; it's a verification artifact that lives next to the
ciphertext in storage.

### 2.5 API shape: the caller never sees a Merkle proof

The whole point of this design: **no consumer of `recrypt-core` ever
touches a proof node, a tree level, or an outboard byte directly.** They
pass in readers and get verified bytes out.

**Async-native from day one.** The entire downstream stack — Axum,
`reqwest`, `aws-sdk-s3`, the recryption proxy — is tokio-based. A sync
API would force `spawn_blocking` at every call site or a duplicate async
variant later. `bao-tree` exposes async types directly, so we use them.
The public surface uses `tokio::io::{AsyncRead, AsyncWrite, AsyncSeek}`.

```rust
// recrypt-core/src/hybrid/mod.rs — new surface

use tokio::io::{AsyncRead, AsyncWrite, AsyncSeek};

impl<B: PreBackend> HybridEncryptor<B> {
    /// Full-file streaming encrypt.
    ///
    /// Reads plaintext, writes XChaCha20 ciphertext to `ciphertext_out`,
    /// and accumulates the bao-tree outboard in memory (bounded by
    /// `max_outboard_bytes`, see §2.5.1). Returns the 32-byte BLAKE3 root,
    /// the `wrapped_key` needed to reconstruct an `EncryptedFile`
    /// envelope, and the buffered outboard bytes for the caller to upload.
    pub async fn encrypt_streaming<R, W>(
        &self,
        recipient: &PublicKey,
        plaintext: R,
        ciphertext_out: W,
    ) -> CoreResult<StreamingEncryptResult>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    { ... }

    /// Full-file streaming decrypt with verification.
    ///
    /// Wraps `ciphertext_in` in a bao-tree decoder backed by `outboard_in`
    /// and the stored `bao_hash`. Any tampering surfaces as an `Err` on the
    /// next poll. Verified ciphertext bytes are then decrypted with
    /// XChaCha20 and written to `plaintext_out`.
    pub async fn decrypt_streaming<C, O, W>(
        &self,
        secret: &SecretKey,
        wrapped_key: &Ciphertext,
        bao_hash: &[u8; 32],
        ciphertext_in: C,
        outboard_in: O,
        plaintext_out: W,
    ) -> CoreResult<()>
    where
        C: AsyncRead + Unpin,
        O: AsyncRead + AsyncSeek + Unpin,
        W: AsyncWrite + Unpin,
    { ... }

    /// Range-verified decrypt.
    ///
    /// Decrypts plaintext bytes in `range` without processing any bytes
    /// outside the range. The caller provides a seekable ciphertext source
    /// (typically wrapping an S3 Range GET reader the caller pre-positioned)
    /// and the full outboard. `range` is in **plaintext coordinates**;
    /// XChaCha20 is 1:1 so the translation is the identity.
    pub async fn decrypt_range<C, O, W>(
        &self,
        secret: &SecretKey,
        wrapped_key: &Ciphertext,
        bao_hash: &[u8; 32],
        ciphertext_in: C,
        outboard_in: O,
        range: Range<u64>,
        plaintext_out: W,
    ) -> CoreResult<()>
    where
        C: AsyncRead + AsyncSeek + Unpin,
        O: AsyncRead + AsyncSeek + Unpin,
        W: AsyncWrite + Unpin,
    { ... }
}

/// Return type of encrypt_streaming — everything the caller needs to
/// persist to storage and build an EncryptedFile envelope.
pub struct StreamingEncryptResult {
    pub bao_hash: [u8; 32],
    pub wrapped_key: Ciphertext,
    pub ciphertext_size: u64,
    /// Buffered outboard bytes (empty for files ≤ 16 KiB).
    /// The caller writes these to the sibling `.obao` storage object.
    pub outboard: Vec<u8>,
}
```

#### 2.5.1 Outboard buffering policy

The outboard is **always buffered in memory** during streaming encrypt
— never spilled to a tempfile. Rationale: the outboard is tiny relative
to the blob (~0.013% at 16 KiB chunk groups, see §2.2). Even at the
file-size ceiling we accept, the buffer fits comfortably in RAM, and a
single in-memory path is much easier to reason about for upload retry
and partial-failure cleanup than a sometimes-file/sometimes-buffer hybrid.

**Hard ceiling:** `MAX_ENCRYPT_FILE_SIZE = 1 TiB`. At 16 KiB chunk
groups this caps the outboard at ~130 MiB, which is the largest we're
willing to hold in process memory during an encrypt. `encrypt_streaming`
returns `CoreError::FileTooLarge` if the plaintext stream exceeds this
limit before EOF. Files larger than 1 TiB are out of scope for this
sprint and would need a tempfile-backed outboard path (deferred).

Note what is **not** in this API:

- No `Outboard`, `SliceProof`, `MerkleNode`, or similar type crosses the
  public surface.
- No method takes or returns a "proof".
- No method asks the caller to choose a chunk size, walk a tree, or check
  a hash.
- No custom wire protocol for proofs. None.

The caller says "here's the ciphertext, here's the outboard, here's the
root; give me verified plaintext" and the implementation does everything
else.

For callers that want verified **ciphertext** without decryption (e.g. a
storage GC that just wants to check an object is intact), we expose a
thin helper:

```rust
/// Wrap a ciphertext reader in a bao-tree verifier. The returned reader
/// yields the same bytes as `ciphertext_in` on success, or errors
/// mid-stream on tamper detection.
pub fn verified_reader<C, O>(
    ciphertext_in: C,
    outboard_in: O,
    bao_hash: &[u8; 32],
) -> impl Read
where
    C: Read,
    O: Read + Seek,
{ ... }
```

This lives in `recrypt-core`. We're not splitting it into a separate
`recrypt-verify` crate — speculative crate splits are slop, and a
single-file move later is cheap if we ever need it.

### 2.6 Remove `recrypt-storage::chunking`

`ChunkManifest`, `split()`, `join()`, `store_chunked()`, and
`retrieve_chunked()` are removed. The `chunking.rs` module is deleted
entirely.

Reasoning, from the dedup analysis:

- **No dedup benefit.** Per-call random XChaCha20 keys mean no two
  encryptions of the same plaintext share a single byte. Chunk-level
  dedup finds zero collisions in practice.
- **Bao subsumes the integrity role.** `ChunkManifest.file_hash` is
  bit-identical to `EncryptedFile.bao_hash`. The per-chunk hashes are a
  flat Merkle-ish structure that bao-tree replaces with a real tree
  supporting O(log n) proofs and random access.
- **Storage chunking is an S3 multipart upload concern**, not an
  application-layer concept. The AWS SDK handles multipart transparently;
  we don't need to expose it.

Storage becomes: one ciphertext object per file, one sibling outboard
object, both addressed by the BLAKE3 root. The `ChunkStorage` trait stays
as-is (`put` / `get` / `exists` / `delete` on hash-keyed blobs) and
becomes the sole storage abstraction.

### 2.7 Orphan GC for partial uploads

The atomic commit point is the metadata POST to the auth/metadata
service. Anything in storage without a corresponding metadata record is
an orphan from a crashed upload, and we need a way to clean it up.

**Two layers, both implemented in this sprint:**

1. **S3 lifecycle rule (set-and-forget).** Configure the bucket so
   incomplete multipart uploads are aborted after 24 hours. This is a
   single bucket-policy line and handles the most common failure mode
   (crash before `CompleteMultipartUpload`) without any code we have to
   maintain. Documented in `docs/deployment.md` as part of bucket setup.

2. **Application-level sweep callable on demand.** A function on
   `recrypt-storage` that lists ciphertext objects in `chunks/b3/`,
   cross-references them against the metadata service, and deletes
   anything older than `max_upload_lifetime` with no metadata record
   pointing at it. Both ciphertext and `.obao` siblings are eligible.

```rust
// recrypt-storage/src/gc.rs
pub struct GcOptions {
    /// Orphans younger than this are kept (lets in-flight uploads finish).
    pub max_upload_lifetime: Duration,
    /// Dry-run prints what would be deleted without acting.
    pub dry_run: bool,
}

pub struct GcReport {
    pub scanned: u64,
    pub orphans_found: u64,
    pub bytes_reclaimed: u64,
    pub deleted_keys: Vec<String>,
}

impl S3Storage {
    /// Sweep orphaned ciphertext + outboard objects.
    pub async fn gc_orphans(
        &self,
        metadata: &dyn MetadataIndex,
        opts: GcOptions,
    ) -> StorageResult<GcReport>;
}
```

The CLI exposes this as `recrypt-cli admin gc [--dry-run]
[--max-age=24h]` so an operator can run it manually or wire it into
cron. The function is the same code path either way — no separate
"production GC daemon" to maintain.

**Default `max_upload_lifetime`:** 24 hours. Configurable via
`RecryptServerConfig`. Lower for testing, higher for slow upload paths.

---

## 3. End-to-end flows

### 3.1 Encrypt + upload (new path)

```
Client                                    S3
─────                                     ──
plaintext_reader
    │
    ▼
HybridEncryptor::encrypt_streaming
    │
    ├── XChaCha20 ─▶ ciphertext_writer ────▶ multipart PUT parts
    │                                        (accumulate into
    │                                         s3://chunks/b3/{hash})
    │
    ├── bao-tree Encoder ─▶ outboard_writer (in-memory or tempfile)
    │
    └── on finalize():
            bao_hash, wrapped_key returned
                    │
                    ▼
     PUT s3://chunks/b3/{base58(bao_hash)}.obao
     (outboard, only if file > 16 KiB)
                    │
                    ▼
     sign (wrapped_key || bao_hash)
                    │
                    ▼
     POST /files metadata
     (EncryptedFileProto with wrapped_key,
      bao_hash, signature — NO ciphertext,
      NO outboard)
```

Key points:

- Ciphertext and outboard are computed **in parallel** during streaming
  encryption. Each plaintext byte flows through XChaCha20 (to ciphertext)
  and through the bao-tree encoder (to outboard). Two independent sinks.
- Ciphertext streams directly into an S3 multipart upload without a full
  buffer; the upload can start before encryption finishes.
- Outboard size is known only after `finalize()`, but it's tiny — buffered
  in memory or spilled to a tempfile.
- The `EncryptedFileProto` envelope is built *last*, after both S3 objects
  have committed, so it can reference concrete content.

### 3.2 Decrypt + download (new path) — control plane / data plane split

The recryption proxy is now strictly a **control plane**: it returns
the recrypted `wrapped_key` plus storage URLs and never touches the
bulk ciphertext. The client fetches ciphertext and outboard directly
from the storage backend (or from a thin metadata-fetch endpoint that
proxies S3 — interchangeable, since metadata is small).

See §8.7 for the cost rationale; the short version is that without
this split, a 1000-member group sharing a 10 GiB file costs the proxy
10 TiB of bandwidth per download cycle for crypto that only needs the
~1 KB `wrapped_key`.

```
Client                                    recrypt-server / S3
──────                                    ────────────────────
GET /recryption/share/{id}         ─────▶ recrypt-server
                                          - recrypts wrapped_key (~1 KB)
                                          - returns metadata + URLs
                                    ◀──── { wrapped_key_for_recipient,
                                            bao_hash, signature,
                                            ciphertext_url,
                                            outboard_url }
    │
    ▼
verify_signature(wrapped_key || bao_hash)
    │
    ▼
GET {outboard_url}                 ─────▶ S3 (direct)
                                    ◀──── outboard bytes (small, one GET)
    │
    ▼
GET {ciphertext_url}               ─────▶ S3 (direct)
(or HTTP Range if user asked for
 a range)                           ◀────
    │
    ▼
HybridEncryptor::decrypt_streaming(
    secret, wrapped_key, bao_hash,
    ciphertext_stream, outboard_reader,
    plaintext_sink
)
    │
    ▼  (bao-tree decoder verifies each
    │   chunk group as it flows through)
    │
    ▼
plaintext bytes to caller
```

Tampering detection: if any chunk group of ciphertext fails verification,
the next `read()` on the plaintext stream returns an `Err` and the caller
sees the failure before the tampered bytes are ever handed off. The ~16
KiB chunk group window bounds how much "wrong" data can be buffered before
the mismatch surfaces.

### 3.3 Range decrypt

For "decrypt plaintext bytes [start, end)":

1. XChaCha20 is a stream cipher; ciphertext byte `i` corresponds to
   plaintext byte `i`. No offset translation needed.
2. Issue an HTTP Range GET for the same byte range on the ciphertext S3
   object.
3. The range might not be chunk-group-aligned; bao-tree's slice decoder
   handles the alignment internally. We fetch a slightly larger range
   covering the requested bytes, verify the whole slice, then trim.
4. The outboard is already local (fetched once per file). bao-tree's
   `SliceDecoder` walks only the tree nodes relevant to the slice.
5. Verified ciphertext bytes → XChaCha20 seek + decrypt → plaintext bytes.

Cost: one outboard GET (first use, then cached) plus one Range GET per
range requested. No proof exchange. No per-range metadata on the wire.

### 3.4 Upload resume / continuation

S3 multipart upload is the transactional backbone:

1. Client begins a multipart upload (`CreateMultipartUpload`), gets an
   upload ID.
2. Client streams encrypt; each finalized multipart part is uploaded with
   `UploadPart`. Outboard is accumulated in parallel in memory/tempfile.
3. On successful encryption end: client calls
   `CompleteMultipartUpload` to atomically publish the ciphertext object.
4. Client uploads the outboard sibling.
5. Client signs and POSTs the `EncryptedFileProto` metadata envelope.

On failure / resume:

- **Crash before `CompleteMultipartUpload`**: the multipart upload is
  abandoned. S3 lifecycle rules (or a periodic sweep) clean up orphaned
  parts. No metadata record exists, so the file is simply "not uploaded".
  The client can retry from scratch.
- **Crash after `CompleteMultipartUpload` but before outboard upload**:
  ciphertext exists in S3 but is unreferenced (no metadata). A periodic
  GC sweep looks for ciphertext objects older than `max_upload_lifetime`
  with no metadata pointing at them and deletes them. The client retries
  from scratch.
- **Crash after outboard upload but before metadata POST**: same as
  above — GC handles the orphan.
- **The metadata record is the atomic commit point.** Its presence means
  "ciphertext and outboard are both in S3 and verified against the
  signature"; its absence means "nothing was committed, clean up any
  orphans".

Partial-download resume on the client side uses HTTP Range GETs and
bao-tree's slice verification to resume from any chunk-group boundary
without re-fetching already-verified bytes. The outboard is already in
hand, so no state other than "which chunk groups do I have?" needs to be
tracked.

---

## 4. Migration

**Clean slate. No migration needed.** Nothing in this repo currently
produces or consumes an `EncryptedFile` in a streaming way. All existing
code buffers the whole file. All existing encrypted files in any test
environment can be re-encrypted rather than migrated. Phase 8 is still the
doc & cleanup phase; there are no production users.

If we later find we do have stored encrypted files with
`EncryptedFileProto` v2 (with `bao_outboard` in the envelope), a one-shot
migration is trivial: read v2, hoist the `bao_outboard` field out into a
sibling S3 object, rewrite the metadata record with `version = 3`. Since
the signature payload was always `wrapped_key || bao_hash` (never included
the outboard), **no re-signing is needed**.

---

## 5. Threat model delta

Things that change:

- **Verification is now walked through the Bao tree**, not just a plain
  BLAKE3 compare over a full buffer. This makes tamper detection
  *mid-stream* (within one 16 KiB chunk group of the corrupted byte)
  rather than *post-buffer*. Stronger real-time property, same ultimate
  guarantee.
- **Outboard integrity is still bound to the signed `bao_hash`.** The
  outboard itself is not directly signed, but any tampering with the
  outboard causes verification against the signed root to fail. Same
  property bao-tree has by construction.
- **Ciphertext object is now publicly addressable by content hash** and is
  fetchable via unauthenticated `GET /files/{hash}` (unchanged from
  current design). The outboard sibling object is equally public. Neither
  reveals plaintext; both are integrity-bearing only.

Things that don't change:

- Signature payload remains `wrapped_key_bytes || bao_hash`.
- Trust posture of each component (client = fully trusted, proxy =
  semi-trusted, storage = untrusted) is identical.
- Proxy still only recrypts `wrapped_key`; `ciphertext` and `bao_hash`
  pass through byte-for-byte, so no re-computation of the outboard is
  needed during recryption. The recryption proxy never touches the
  outboard at all.

New entries for the threat model document:

- **`bao-tree` is unaudited.** It is maintained by `n0-computer`, used in
  production by iroh, and implements a standard BLAKE3 Merkle tree with
  configurable chunk group size. The cryptographic construction is not
  novel; the novelty is layout and chunk alignment. Security rests on
  BLAKE3's collision resistance (well-studied, widely deployed). We
  should note this in the Phase 9 security audit scope as a
  third-party-dependency review item: no formal audit exists, but the
  construction is simple and inspectable.
- **Outboard tampering by storage**: if the storage provider corrupts the
  outboard sibling object, every verification fails. This is a DoS, not a
  confidentiality or integrity break — the client cannot be fooled into
  accepting bad ciphertext, only into rejecting good ciphertext. Same
  property as any dependent-on-storage-availability system.
- **Outboard substitution across files**: a malicious storage provider
  could serve the outboard for file B in response to a request for file
  A's outboard. The decoder will fail verification because the root
  hash from the signed metadata envelope won't match bao-tree's
  reconstruction from the wrong outboard + ciphertext. This is caught by
  the existing signature, no new mitigation needed.

---

## 6. Implementation plan

### 6.1 Phase order

1. **Add `bao-tree` dependency and sketch the `verified_reader` helper.**
   Single-file proof of concept: wrap a `Cursor<Vec<u8>>` ciphertext and a
   `Cursor<Vec<u8>>` outboard in a bao-tree decoder, read bytes out, fail
   on tamper. Get confidence with the real API.

2. **`HybridEncryptor::encrypt_streaming`** producing both ciphertext and
   outboard in lockstep from a single plaintext reader. Unit test: verify
   the resulting `(ciphertext, outboard, bao_hash)` roundtrips through
   bare bao-tree decode.

3. **`HybridEncryptor::decrypt_streaming`** taking readers and producing a
   verified plaintext stream. Unit test: round trip with
   `encrypt_streaming`, plus a tamper test that flips a byte in the
   ciphertext and asserts `decrypt_streaming` errors.

4. **`HybridEncryptor::decrypt_range`** for random-access reads. Unit
   tests: various ranges, aligned and unaligned to chunk groups, tamper
   tests for ranges inside and outside the corrupted area.

5. **Wire format bump to `EncryptedFileProto` v3**: remove `bao_outboard`
   field (keep field number retired), bump `version = 3`. Update
   `recrypt-proto::impls` JSON/armor roundtrips. Ensure signatures still
   verify over `wrapped_key || bao_hash` unchanged.

6. **`recrypt-storage` two-object layout**: `put_with_outboard(hash,
   ciphertext, outboard)` and `get_with_outboard(hash) → (ciphertext_reader,
   outboard_reader)`. Implement for `InMemoryStorage`, `LocalFileStorage`,
   `S3Storage`. Unit tests for all three.

7. **Update `recrypt-server::routes::files` and `recrypt-cli` encrypt/decrypt
   commands** to use the streaming APIs in the same pass, then delete
   `recrypt-storage::chunking` and all references. (Folded together so
   the tree is never in a half-broken state — `chunking` is removed only
   after every caller has migrated.) Integration test: encrypt a
   multi-MiB file, round-trip through a local `InMemoryStorage`, decrypt,
   confirm plaintext matches.

8. **Update `recrypt-server::routes::recryption`** to the control/data
   plane split: recrypt only the `wrapped_key`, return metadata + storage
   URLs, never touch the bulk ciphertext (see §3.2 and §8.7).

9. **Implement orphan GC** (`recrypt-storage::gc::gc_orphans` +
   `recrypt-cli admin gc`, see §2.7). Document the S3 lifecycle rule
   for incomplete multipart uploads in `docs/deployment.md`.

10. **Benchmarks** (criterion or a small bench bin): see §6.4 for
    targets. Establish numbers before docs lock in claims.

11. **Update all docs** to match the new implementation: wire-protocol.md
    removes `bao_outboard` from the proto schema section, storage-design.md
    drops ChunkManifest, verification-architecture.md gains a "how it
    actually works now" section replacing its "planned" markers,
    architecture.md gaps section crosses off the streaming verification
    item.

12. **Threat model update**: add the `bao-tree` unaudited-dependency note
    and the outboard-tampering analysis.

### 6.2 What can be parallelized

Steps 1 and 5 can run in parallel (dependency setup and proto format
change are independent). Steps 2, 3, 4 are a single dependency chain on
the core crypto side. Steps 6–9 can be parallelized across crates once
the core (step 3) is in place. Step 10 is last (docs follow
implementation, not the other way around).

### 6.3 Benchmark targets

Concrete acceptance bars so we know the design pays off:

| Scenario | Target |
|---|---|
| `encrypt_streaming` of a 1 GiB plaintext, in-memory sink | ≤ 2× the wall-clock of `XChaCha20`-only over the same bytes (overhead = bao-tree encoder) |
| `decrypt_streaming` of a 1 GiB ciphertext from local storage | ≤ 2× XChaCha20-only baseline; constant memory (no full-file buffer) |
| `decrypt_range` of a 100 MiB plaintext window from a 10 GiB ciphertext on local file storage | ≤ 3 storage GETs total (1 outboard, 1 ciphertext range, optional 1 metadata); ≤ 105 MiB of bytes read; wall-clock dominated by the range fetch, not by tree walking |
| Outboard fetch for a 10 GiB file | < 2 MiB transferred, single GET |
| Proxy CPU + bandwidth per recryption download (control/data split) | bounded by `O(wrapped_key_size)`, independent of file size — verified by benching a 100 MiB file vs a 10 GiB file and seeing flat proxy cost |

These run in CI on every PR touching `recrypt-core` or `recrypt-storage`,
with regression gates on the streaming overhead ratios.

### 6.4 Rollback

Each step is a single-crate change and can be reverted in isolation. Until
step 10 lands, the old buffer-everything path still exists alongside the
new streaming path and can be swapped back as a one-line change.

---

## 7. Cost comparison (from S3 research)

For a 1 GiB file, AWS S3 standard pricing:

| Approach | PUTs | GETs | Request cost per GB |
|---|---|---|---|
| Old: 256 × 4 MiB chunks + manifest | 257 | 257 | ~$2.43 (at Class A rates) |
| New: 1 ciphertext + 1 outboard | 2 | 2 | negligible (~$0.02) |

At scale this difference is substantial. On Cloudflare R2 (free egress) or
Wasabi (no per-request pricing), the monolithic approach is also
simpler, cheaper, or both. No provider currently dedupes at the chunk
level, so we lose nothing on the storage side either.

---

## 8. Open questions

### 8.1 Where does the outboard physically live?

Three options, in rough order of preference:

1. **Sibling S3 object `{hash}.obao`** (proposed above). Pros: dead
   simple, one content-addressed object per artifact, S3 handles
   caching. Cons: adds one extra GET per download for the outboard.
2. **Inside the `EncryptedFileProto` envelope for small files only.**
   Keeps small files to a single metadata fetch. Cons: special-case
   branching, envelope size varies.
3. **In the auth service / metadata database.** Pros: co-located with
   other file metadata. Cons: auth service becomes a data path, not just
   a control path.

Option 1 is the default. Option 2 is a latency optimization we can add
later if outboard fetches become a hot path. Option 3 is probably wrong
for the trust model (we don't want the auth service in the bulk data
path).

### 8.2 `decrypt_range` takes plaintext range — RESOLVED

Plaintext range. XChaCha20 is 1:1 so translation is the identity, and
plaintext coordinates are what callers think in. Locked into the API in
§2.5.

### 8.3 Async surface: async-native from day one — RESOLVED

The whole stack downstream of `recrypt-core` (Axum, `reqwest`,
`aws-sdk-s3`, recryption proxy) is tokio-based. `bao-tree` exposes
async types directly. Sync-first would force `spawn_blocking` at every
call site or a duplicate API later. The public surface uses
`tokio::io::{AsyncRead, AsyncWrite, AsyncSeek}` from the start (§2.5).

### 8.4 `recrypt-verify` crate — RESOLVED: no

`verified_reader` lives in `recrypt-core`. A speculative crate split
for one helper is slop; moving the file later if a real consumer
appears costs about ten minutes.

### 8.5 Bao-tree version pin

Current `bao-tree` is 0.5. We should pin to a specific minor and keep an
eye on iroh's version bumps, since the two co-evolve.

### 8.6 Belt-and-suspenders XChaCha20-Poly1305?

Today we use raw XChaCha20 (stream cipher, no AEAD) and rely on the
Bao tree + signature over `wrapped_key || bao_hash` as our integrity
layer. This is correct as long as the signature is verified *before*
decryption. But if anything in the client path ever decrypts before
verifying the signature (a subtle bug away), the attacker's window
opens: XChaCha20 will cheerfully decrypt tampered ciphertext into
controlled-garbage plaintext.

Switching to XChaCha20-Poly1305 (the AEAD variant) would give us an
**independent 16-byte authenticator** over the ciphertext that the
decryption function itself refuses to proceed without verifying.
Defense in depth: even if the signature check is somehow bypassed,
Poly1305 catches tampering. The Poly1305 tag would live inside the
`wrapped_key` envelope alongside the symmetric key, so it's
transmitted and encrypted with the key material.

The tradeoff is that Poly1305 is a linear MAC: you need the whole
ciphertext to verify the tag. This complicates the streaming/range
story — you can't range-decrypt a 100 MB slice without also computing
Poly1305 over the whole file. One approach is to use Poly1305 as a
*final* integrity check after streaming and rely on Bao for
mid-stream tamper detection; another is to accept that random-access
reads only get Bao-level integrity (which is still signed-tree-level,
not nothing).

Worth a design discussion before Phase 9 security audit. For now, the
plan sticks with raw XChaCha20 + Bao + signature, with a clear rule:
**always verify the signature before touching the decrypted stream.**

### 8.7 Control plane / data plane split for recryption downloads — RESOLVED

**Decision:** adopt the split. The proxy is a control plane only;
clients fetch ciphertext + outboard directly from storage. Wired into
§3.2 and step 8 of §6.1.

**Previous design (rejected):** `GET /recryption/share/{id}/file` reads
the full ciphertext from storage, runs `HybridEncryptor::recrypt()` on
the whole `EncryptedFile`, and returns the recrypted bytes.

**Problem:** this forces every group-member download through the
recryption proxy. For a 1000-member group sharing a 10 GiB file, the
proxy is serving 10 TiB of recrypted bulk data per full-group
download cycle. The proxy becomes the bottleneck for a workload the
cryptography itself doesn't require it for.

**The cryptographic truth:** recryption transforms the `wrapped_key`
(~1 KB). The `ciphertext` (the bulk) passes through byte-for-byte.
The proxy does not need to touch the bulk data at all.

**Proposed split:** change the endpoint shape so the proxy only
returns the **recrypted metadata** — the new `wrapped_key`, the
`bao_hash`, the signature — plus a storage URL (or pre-signed S3
URL, or direct hash) the client uses to fetch the ciphertext and
outboard directly from storage.

```
GET /recryption/share/{id}
→ {
    "wrapped_key_for_recipient": "<base58 recrypted CiphertextProto>",
    "bao_hash": "<base58>",
    "signature": { ... },
    "ciphertext_url": "s3://.../{bao_hash}",
    "outboard_url":   "s3://.../{bao_hash}.obao"
  }
```

The client then:
1. Verifies the signature.
2. Fetches ciphertext + outboard directly from S3 (Range GETs,
   streaming, bao-tree verification — all the features from this
   plan).
3. Decrypts with its own secret key + the recrypted wrapped_key.

**Scale:** proxy work per download is now ~1 KB of crypto
(recrypting the wrapped_key) + ~300 bytes of JSON serialization.
1000 members downloading a 10 GiB file costs the proxy 1000 × ~1 KB,
not 1000 × 10 GiB.

Needs a spec revision and threat-model update (does exposing a
storage URL to a legitimate recipient leak anything? — probably
not, but worth thinking through). See §11 for how this pairs with
group sharing.

---

## 9. Success criteria

- [ ] `bao-tree` dependency added at pinned version
- [ ] `HybridEncryptor::encrypt_streaming` + `decrypt_streaming` +
      `decrypt_range` implemented with unit tests covering: happy path,
      tamper detection in every position, cross-chunk-group ranges,
      sub-chunk-group ranges, files smaller than one chunk group
- [ ] `EncryptedFileProto` v3 in use; field 4 (`bao_outboard`) retired;
      signatures still verify unchanged
- [ ] Storage layer exposes `{hash}` + `{hash}.obao` two-object layout
      via the existing `ChunkStorage` trait or a thin wrapper over it
- [ ] `recrypt-storage::chunking` module and all references deleted
- [ ] `recrypt-cli encrypt` / `decrypt` commands use the streaming path
- [ ] `recrypt-server` recryption handler implements the control/data
      plane split: returns recrypted `wrapped_key` + storage URLs, never
      touches bulk ciphertext (§3.2, §8.7)
- [ ] Orphan GC: `recrypt-storage::gc::gc_orphans` implemented and
      exposed via `recrypt-cli admin gc [--dry-run]`; S3 lifecycle rule
      for incomplete multipart uploads documented in deployment guide
- [ ] Benchmarks from §6.3 land in CI with regression gates
- [ ] End-to-end test: Alice encrypts a 100 MiB file with streaming,
      uploads it, shares with Bob, Bob downloads and decrypts with
      streaming verification, plaintext matches
- [ ] Tamper test: flip a byte in the stored ciphertext, confirm Bob's
      decrypt errors mid-stream before any tampered plaintext is handed
      off
- [ ] Range test: Bob requests plaintext bytes [50 MiB, 51 MiB), only
      ~1 MiB of ciphertext is fetched from storage, decryption succeeds,
      plaintext matches
- [ ] Docs updated: wire-protocol.md, storage-design.md,
      verification-architecture.md, architecture.md gaps, threat-model.md
      `bao-tree` note

---

## 11. Group sharing: the real reason all this matters

Recrypt's distinguishing product feature — the thing that makes it "Signal
meets Dropbox" instead of "yet another encrypted file service" — is
**fine-grained, revocable group sharing without a trusted server**. Proxy
recryption is the cryptographic primitive that makes this possible, and
the streaming/verification design in this plan is what makes it usable at
realistic file sizes.

### 11.1 What the cryptography lets us do

For a group of N members sharing a file:

| Operation           | Cost                                             |
| ------------------- | ------------------------------------------------ |
| Alice encrypts once | 1 encryption, 1 ciphertext, 1 outboard           |
| Alice adds member M | 1 recrypt key generation (~KB), 1 POST to proxy  |
| Member M reads      | 1 wrapped_key recryption (~KB) + streaming read  |
| Alice revokes M     | 1 DELETE at proxy — **no bulk re-encryption**    |
| Group of 1000       | 1 ciphertext + 1 outboard + 1000 recrypt keys    |

Compare to the naive alternative ("encrypt to each recipient separately"):

| Operation                        | Naive cost                                  |
| -------------------------------- | ------------------------------------------- |
| Share with M new members         | M re-encryptions of the entire file         |
| Revoke one member                | Re-encrypt the whole file + re-distribute   |
| Group of 1000                    | 1000 × (ciphertext + metadata)              |

Proxy recryption collapses the bulk-data cost from `O(N × filesize)` to
`O(filesize)`, with per-member cost living entirely in a few KB of
recrypt-key material at the proxy. This is why PRE exists as a research
field and why recrypt is built on it.

### 11.2 How the Bao streaming design amplifies this

Every design choice in this plan compounds the group-sharing benefit:

- **One ciphertext object per file**, content-addressed by `bao_hash`.
  All N members pull from the *same* storage object. Storage cost scales
  O(1) in group size, not O(N). Storage dedup is irrelevant because
  there's only ever one copy.
- **One outboard object per file.** Same story. A group of 1000 doesn't
  generate 1000 copies of the verification tree.
- **Streaming + range decryption.** Members can seek into the file
  without pulling the whole thing. Video-in-a-shared-folder works.
- **Member-side verification against a signed root.** Every member
  independently verifies the same signed `bao_hash`. The proxy doesn't
  have to be trusted to serve correct bytes — it can't, because
  tampering is detected locally.

### 11.3 Revocation is a single DELETE

This is worth dwelling on because it's the feature that most
distinguishes recrypt from every "encrypted cloud storage" product that
exists today:

1. Alice shares file F with Bob. Proxy stores `rk(Alice → Bob)`.
2. Bob downloads F, reads it.
3. Alice decides to revoke Bob. She calls `DELETE /recryption/share/{id}`.
4. Proxy deletes `rk(Alice → Bob)`.
5. Bob tries to download F again. Proxy cannot produce a wrapped_key Bob
   can decrypt — the transformation key is gone.

**What Bob could keep:** whatever he already downloaded and decrypted
before the revocation (Alice cannot un-read a file someone has already
read). **What Bob loses:** any future access to F, including new
versions or ranges he hasn't fetched yet.

What this is *not*: a cryptographic guarantee that Bob destroys the
bytes he already has. No system can give you that. What it *is*: a
guarantee that from the moment of revocation, the cloud infrastructure
cannot be used to deliver F's plaintext to Bob again, **without
re-encrypting F or touching any other member's access**.

Compare to "encrypt once per recipient": revoking Bob means
re-encrypting F and re-distributing to everyone else. Compare to
"trusted cloud with ACLs": revoking Bob means trusting the cloud to
actually enforce the revocation. Recrypt gives you the operational
convenience of the first and the trust model of neither.

### 11.4 The proxy's trust posture in more detail

The proxy is often described as "semi-trusted", which is imprecise.
More carefully:

**What the proxy holds and can do:**
- `rk(Alice → Bob)` for every active share. This is a **transformation
  key**, not a decryption key. It enables the proxy to transform
  `Enc(pk_Alice, m)` into `Enc(pk_Bob, m)` without learning `m`.
- The proxy can *refuse* to recrypt (availability attack).
- The proxy can *leak metadata* — who is sharing what with whom,
  access patterns, file hashes.
- The proxy can, in principle, *misdirect* a recrypted output to the
  wrong recipient — the cryptographic transform doesn't bind the
  recipient identity, it's the application-layer authentication that
  does. This is the policy-enforcement trust assumption.

**What the proxy *cannot* do, cryptographically:**
- Decrypt `Enc(pk_Alice, m)` to recover `m`. No secret key, no
  decryption capability.
- Decrypt `Enc(pk_Bob, m)` either.
- Derive `sk_Alice` or `sk_Bob` from any recrypt key.
- Forge a new `rk(X → Y)` for pairs it doesn't have keys for.
- Collude with Bob to recover `sk_Alice` — this is the unidirectionality
  property of BFV proxy recryption: `rk(Alice → Bob)` gives Bob+proxy
  the ability to transform Alice's ciphertexts, but not to extract her
  secret key.

**The word "semi-trusted" in our docs specifically means "trusted for
policy enforcement, untrusted for confidentiality".** Plaintext is
cryptographically out of reach of the proxy. Access control is an
application-layer concern that the proxy is currently trusted to
enforce correctly.

### 11.5 Path to a truly untrusted proxy (future work)

A natural question: can we make the proxy cryptographically unable to
deliver a recrypted ciphertext to the wrong recipient? Yes, in
principle, through techniques sometimes labeled "non-transferable" or
"obliviously delegatable" proxy recryption. The idea: bind the
recrypt transformation to a live, signed request from the intended
recipient, such that the proxy's output is only usable by that specific
signer.

This is out of scope for the current sprint but is a natural extension
once the streaming + group-sharing foundations are in place. Worth
tracking as **Phase 10+ research: non-transferable recryption**.

### 11.6 Success criteria for group sharing (added to §9)

- [ ] End-to-end test of a 3-member group share: Alice encrypts F,
      shares with Bob and Carol, both can stream-decrypt independently,
      Alice revokes Bob, Bob's subsequent requests fail, Carol still
      works.
- [ ] Storage cost verification: the above test produces exactly 1
      ciphertext object and 1 outboard object in the backing store,
      regardless of the number of members.
- [ ] Proxy work per member download is bounded by O(wrapped_key_size),
      not O(file_size). Benchmark with a 100 MiB file and 10 members.

---

## 12. Integrity chain: what's the MAC, exactly?

A subtle question came up during design and deserves to be written
down explicitly, because the answer isn't obvious from the code.

### 12.1 XChaCha20 has no integrity

Raw XChaCha20 is a stream cipher: one plaintext bit in, one ciphertext
bit out, with no authentication. Flipping one ciphertext bit flips
exactly one plaintext bit, and **the decryptor has no way to detect
the change** from the cipher operation alone. This is why the
standard construction in most systems is **XChaCha20-Poly1305**, which
adds a 16-byte authenticator tag.

We chose to use raw XChaCha20 and build our own integrity layer. This
is a valid choice — it gives us properties Poly1305 can't (range
verification, streaming) — but it means **we have to be careful about
where the authentication actually lives** in the construction.

### 12.2 Three things that look like integrity but aren't MACs

1. **`bao_hash` by itself** is an unkeyed BLAKE3 hash over the
   ciphertext. It is *not* a MAC. An attacker who tampers with the
   ciphertext can trivially recompute `bao_hash` over the tampered
   bytes. Without a key, there's nothing to forge.

2. **The Bao outboard** is a BLAKE3 Merkle tree over the ciphertext.
   It is *not* a MAC. An attacker who tampers with the ciphertext can
   recompute the outboard against their tampered ciphertext and it
   will self-consistently verify. Without a key, there's nothing to
   forge.

3. **`plaintext_hash` inside `KeyMaterial`** is a BLAKE3 hash of the
   plaintext, carried inside the PRE-wrapped `wrapped_key`. This is
   *closer* to a MAC: the recipient can decrypt the wrapped key, get
   the plaintext_hash, decrypt the ciphertext, and check that
   `blake3(decrypted) == plaintext_hash`. If an attacker tampered
   with the ciphertext, this check fails, because plaintext_hash is
   encrypted under the recipient's PRE key and the attacker can't
   substitute a new one without breaking PRE. **But it's a
   post-decryption check, not a pre-decryption authenticator.**

### 12.3 Where integrity actually comes from

Two independent mechanisms, working together:

**Mechanism A (pre-decryption, range-friendly): signed `bao_hash`.**
The `MultiSig` in `EncryptedFile.signature` covers `wrapped_key_bytes
|| bao_hash`. Anyone verifying the signature against the sender's
public keys commits to these specific bytes. Because `bao_hash` is a
BLAKE3 tree root over the ciphertext, and the Bao decoder verifies
incoming ciphertext chunks against this root as they stream, **a
signed `bao_hash` turns the otherwise-unkeyed Bao tree into a
signed authenticator**. The signature is the key. Without the
signature, the whole Bao construction provides integrity against a
passive observer but not against an active attacker.

**Mechanism B (post-decryption, final check): encrypted
`plaintext_hash`.** Even if Mechanism A is somehow bypassed (signature
check forgotten, wrong signer trusted, bug in the verification code),
the recipient still checks `blake3(decrypted_plaintext) ==
plaintext_hash` after decryption. `plaintext_hash` is itself
unforgeable because it lives inside `wrapped_key`, which is PRE-encrypted
to the recipient; substituting it requires breaking the PRE scheme.

**Mechanism A is what we rely on for streaming and range reads.**
It lets the decoder refuse tampered ciphertext bytes before they ever
flow into the cipher. Mechanism B is a backstop that catches certain
failure modes of Mechanism A.

### 12.4 Critical rule

**Always verify the signature before decrypting.** If the code path
ever decrypts without first checking the signature, the whole
integrity story for streaming collapses — you'd be feeding
unauthenticated ciphertext into XChaCha20 and trusting the output.
Mechanism B would still catch the failure *eventually*, but only at
end-of-stream, and only if you bother to check `plaintext_hash` after
buffering the whole plaintext.

This rule is currently enforced by `HybridEncryptor::decrypt_and_verify`
(which verifies before calling `decrypt`) but **not** by
`HybridEncryptor::decrypt` alone, which is happy to decrypt without a
signature check. The streaming API we're designing in this plan should
either:

- Require signature verification at its entry point (so there's no
  "decrypt without verify" path), or
- Make unsigned decryption an explicit, named, loudly-marked operation
  that's clearly opt-out of integrity.

Leaning toward the first.

### 12.5 Does XChaCha20 support range decryption?

Yes, trivially. XChaCha20 is a stream cipher whose keystream at byte
offset `N` depends only on `(key, nonce, N)` — specifically, it
derives `keystream_byte[N] = XChaCha20_block_function(key, nonce, N /
64)[N % 64]`. There's no chaining: byte `N`'s ciphertext depends only
on byte `N`'s plaintext and the keystream at that offset.

To decrypt plaintext bytes `[start, end)`:
1. Fetch ciphertext bytes `[start, end)` (via HTTP Range GET).
2. Compute the XChaCha20 keystream starting at offset `start`.
3. XOR.

Done. No need to touch bytes outside the range. The symmetric key and
nonce come from `wrapped_key` (one decryption of ~1 KB, not the whole
file), so the total work for a range decrypt is
`O(range_size + wrapped_key_size)`.

This is the property that makes range decryption *possible* at all.
If we were using AES-CBC we'd need the preceding block; if we were
using XChaCha20-Poly1305 we'd need the whole ciphertext to verify the
tag (see §8.6). Raw XChaCha20 is uniquely friendly to streaming and
range workloads, which is a big part of why we chose it.

---

## 13. References

- [bao-tree on crates.io](https://crates.io/crates/bao-tree)
- [bao-tree on GitHub (n0-computer)](https://github.com/n0-computer/bao-tree)
- [iroh blob store design challenges](https://www.iroh.computer/blog/blob-store-design-challenges)
- [iroh blobs protocol](https://docs.iroh.computer/protocols/blobs)
- [Bao specification](https://github.com/oconnor663/bao/blob/master/docs/spec.md)
- [BLAKE3 paper](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf)
- This repo:
  - [architecture.md](../architecture.md) — how this plan fits into the
    broader crate layout
  - [verification-architecture.md](../verification-architecture.md) —
    current status and target design
  - [wire-protocol.md](../wire-protocol.md) — current proto schema with
    `bao_outboard` still in the envelope (will change in step 5)
  - [threat-model.md](../threat-model.md) — security posture affected by
    this change
