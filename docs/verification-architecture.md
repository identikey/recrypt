# Verification Architecture: Blake3/Bao Tree Mode

**Status:** ✅ DECIDED  
**Decision:** Use Blake3's built-in Bao tree mode for streaming verification

---

## Summary

File integrity verification uses Blake3's Bao (Blake3 Authenticated Output) tree mode, enabling:

- Streaming chunk verification as data arrives
- Parallel hashing and verification
- No manual Merkle tree construction
- Implicit auth paths (no per-chunk overhead)

---

## Why Bao?

### Comparison with Manual Merkle Tree

| Aspect                 | Manual Merkle (Python) | Bao Tree (Rust)      |
| ---------------------- | ---------------------- | -------------------- |
| Implementation         | Custom code            | Library handles it   |
| Auth path transmission | O(log n) per chunk     | Implicit in encoding |
| Parallelism            | Manual threading       | Built-in             |
| Streaming verification | Complex                | Native support       |
| Battle-tested          | Our code               | Blake3 authors' code |

### Key Benefits

1. **Streaming verification:** Verify chunks as they arrive, no need to buffer entire file
2. **Parallel hashing:** Automatically uses all CPU cores
3. **Implicit proofs:** Auth paths encoded in the Bao format itself
4. **Single root hash:** File identity = 32-byte Blake3 hash

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         FILE DATA                                │
│  [chunk 0] [chunk 1] [chunk 2] ... [chunk n]                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      BAO ENCODER                                 │
│  - Computes Blake3 tree over chunks                             │
│  - Produces root hash (file identity)                           │
│  - Optionally produces "outboard" tree (for streaming)          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      OUTPUT                                      │
│  - root_hash: [u8; 32]     (file identity, stored in metadata)  │
│  - encoded_data: Vec<u8>   (interleaved data + tree nodes)      │
│  - OR outboard: Vec<u8>    (tree nodes only, data separate)     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Implementation

### Encoding (Sender)

```rust
use bao::encode;

// Simple: encode entire file
fn encode_file(data: &[u8]) -> (bao::Hash, Vec<u8>) {
    let (encoded, hash) = encode::encode(data);
    (hash, encoded)
}

// Streaming: encode chunk by chunk
fn encode_streaming(chunks: impl Iterator<Item = Vec<u8>>) -> (bao::Hash, Vec<u8>) {
    let mut encoder = encode::Encoder::new(Vec::new());
    for chunk in chunks {
        encoder.write_all(&chunk).unwrap();
    }
    let (output, hash) = encoder.finalize();
    (hash, output)
}

// Outboard mode: keep data separate from tree
fn encode_outboard(data: &[u8]) -> (bao::Hash, Vec<u8>) {
    let mut outboard = Vec::new();
    let hash = encode::outboard(data, &mut outboard);
    (hash, outboard)
}
```

### Decoding/Verification (Receiver)

```rust
use bao::decode;

// Simple: verify and decode entire file
fn verify_file(encoded: &[u8], expected_hash: &bao::Hash) -> Result<Vec<u8>, Error> {
    decode::decode(encoded, expected_hash)
}

// Streaming: verify chunks as they arrive
fn verify_streaming(
    encoded_stream: impl Read,
    expected_hash: &bao::Hash,
) -> Result<Vec<u8>, Error> {
    let mut decoder = decode::Decoder::new(encoded_stream, expected_hash);
    let mut output = Vec::new();
    decoder.read_to_end(&mut output)?;  // Fails immediately on tampered chunk
    Ok(output)
}

// Outboard mode: verify with separate tree
fn verify_outboard(
    data: &[u8],
    outboard: &[u8],
    expected_hash: &bao::Hash,
) -> Result<(), Error> {
    decode::decode_outboard(data, outboard, expected_hash)?;
    Ok(())
}
```

### Slice Extraction (Random Access)

Bao supports extracting verified slices without downloading entire file:

```rust
use bao::encode::SliceExtractor;

// Extract verified slice from encoded data
fn extract_slice(
    encoded: &[u8],
    start: u64,
    len: u64,
) -> Vec<u8> {
    let mut extractor = SliceExtractor::new(
        std::io::Cursor::new(encoded),
        start,
        len,
    );
    let mut slice = Vec::new();
    extractor.read_to_end(&mut slice).unwrap();
    slice
}

// Verify extracted slice
fn verify_slice(
    slice: &[u8],
    expected_hash: &bao::Hash,
    start: u64,
    len: u64,
) -> Result<Vec<u8>, Error> {
    let mut decoder = decode::SliceDecoder::new(
        std::io::Cursor::new(slice),
        expected_hash,
        start,
        len,
    );
    let mut output = Vec::new();
    decoder.read_to_end(&mut output)?;
    Ok(output)
}
```

---

## Storage Modes

### Combined Mode (Interleaved)

Data and tree nodes interleaved in single blob:

```
[header][node][data][node][data]...
```

**Pros:** Single file, streaming verification works
**Cons:** ~6% size overhead, must re-encode to modify

### Outboard Mode

Tree stored separately from data:

```
data.bin   → original file (unchanged)
data.obao  → tree nodes only
```

**Pros:** Original file unmodified, tree is small (~0.01% of file)
**Cons:** Two files to manage, need both for verification

### Recommendation

Use **outboard mode** for storage:

- Original encrypted chunks stored as-is in S3
- Bao tree stored in metadata or alongside
- Enables verification without re-encoding

---

## Wire Protocol Integration

### File Upload

1. Client computes Bao hash while uploading chunks
2. Final root hash sent as file identity
3. Server can verify chunks incrementally

### File Download

1. Client requests file by root hash
2. Server streams chunks with Bao encoding
3. Client verifies each chunk as it arrives
4. Immediate rejection of tampered data

### Chunk Format

```
FileChunk (conceptual — not a wire-format envelope):
  index:     u32         chunk sequence number
  data:      bytes       encrypted chunk data
  bao_proof: bytes       Bao slice proof for this chunk (optional)
```

---

## Security Properties

1. **Integrity** — against an active attacker, *only when the root hash
   is signed*. Bare BLAKE3 / Bao over ciphertext is an unkeyed hash;
   without a signature binding the root to an authenticated sender,
   integrity holds against passive observers only. In recrypt, the
   `MultiSig` over `wrapped_key || bao_hash` is what turns the Bao tree
   into a real authenticator. Always verify the signature *before*
   decryption. See
   [plans/2026-04-06-bao-streaming-and-storage-simplification.md §12](plans/2026-04-06-bao-streaming-and-storage-simplification.md#12-integrity-chain-whats-the-mac-exactly)
   for a careful walkthrough of the integrity chain.
2. **Streaming** — don't need full file to verify partial content.
3. **Random access** — can verify arbitrary slices via the outboard
   tree; proof size is O(log n) per range.
4. **Collision resistance** — 128-bit security against BLAKE3 collisions
   (256-bit hash, birthday bound).
5. **Deterministic** — same bytes always produce the same root hash.
   This is what enables content addressing across storage backends.

---

## Dependencies

```toml
[dependencies]
blake3 = "1"
bao = "0.12"
```

---

## Current status

This document describes the streaming verification architecture now in place:

| Capability                                                             | Status     | Where                                              |
| ---------------------------------------------------------------------- | ---------- | -------------------------------------------------- |
| Bao outboard generated at encryption time                              | ✅ Done     | `recrypt-core/src/hybrid/mod.rs` — `bao::encode::outboard` |
| Root hash stored in `EncryptedFile.bao_hash`                           | ✅ Done     | same                                               |
| Root hash signed together with `wrapped_key` in the multi-signature    | ✅ Done     | `EncryptedFile::signature_payload`                 |
| **Full-file integrity check on decrypt**                               | ✅ Done     | `HybridEncryptor::decrypt` — validates ciphertext against signed `bao_hash` |
| **Streaming verification** via async API                               | ✅ Done     | `HybridEncryptor::encrypt_streaming`, `decrypt_streaming`, backed by `bao-tree` |
| **Slice / random-access verification**                                 | ✅ Done     | `HybridEncryptor::decrypt_range` for plaintext-coordinate ranges                |
| Bao outboard stored separately from envelope                           | ✅ Done     | Sibling `.obao` object in S3; not embedded in `EncryptedFileProto` v3             |

### Implementation overview

**`bao-tree` dependency:** pinned to `0.16`, provides:
- 16 KiB chunk groups (`BlockSize::from_chunk_log(4)`)
- Merkle tree construction and verification
- O(log n) proof size for range queries

**Outboard size and fetch:** ~0.013% of ciphertext (e.g., ~130 MiB for 1 TiB file).
Small enough to fetch in a single request; never streamed incrementally.

**Public API:**

```rust
pub async fn encrypt_streaming<R: AsyncRead + Unpin>(
    &self,
    key: &PublicKey,
    plaintext: R,
) -> CoreResult<StreamingEncryptResult>;

pub async fn decrypt_streaming<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    &self,
    key: &SecretKey,
    ciphertext: R,
    outboard: R,  // 404 returns empty, client treats as no outboard
    plaintext_out: W,
) -> CoreResult<()>;

pub async fn decrypt_range<R: AsyncRead + AsyncSeek + Unpin>(
    &self,
    key: &SecretKey,
    ciphertext: R,
    outboard: R,
    plaintext_range: Range<u64>,
) -> CoreResult<Vec<u8>>;
```

### Known limitations (current)

**Internal buffering:** The current implementation buffers the entire ciphertext
in memory and uses a "recompute the bao root and compare" verification path
rather than walking the Merkle tree incrementally. The async public API surface
is future-proof; a future implementation can walk the tree incrementally without
breaking callers. This buffering is acceptable for the CLI (predictable resource
availability) but should be revisited for server-side streaming in future phases.

**No streaming outboard fetch:** The outboard is fetched in a single request
before decryption begins, not streamed alongside ciphertext chunks. This is a
reasonable tradeoff for outboards < 200 MiB.

### Historical note

An earlier `recrypt-wire::bao_stream` module partially attempted
streaming verification. Its `BaoDecoder::verify()` compared the stored
root against `blake3::hash(data)` (which happened to match the Bao root but
was presented as if it were tree verification) and then only size-checked
the outboard. The module was never called in production and was removed
to avoid giving the false impression that the outboard was being
walked.

---

## References

- [Bao specification](https://github.com/oconnor663/bao/blob/master/docs/spec.md)
- [bao crate documentation](https://docs.rs/bao)
- [Blake3 paper](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf)
