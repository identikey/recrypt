# Hashing Standard: Blake3 Everywhere

**Status:** ✅ DECIDED  
**Decision:** Standardize on Blake3 for all hashing operations

---

## Summary

All hashing uses **Blake3** exclusively.

---

## Rationale

### Performance

| Algorithm | Speed (single-threaded) | Speed (multi-threaded)        |
| --------- | ----------------------- | ----------------------------- |
| Blake2b   | ~1 GB/s                 | ~1 GB/s (no parallelism)      |
| Blake3    | ~1.5 GB/s               | ~10+ GB/s (scales with cores) |

Blake3 is 4-8x faster in parallel workloads, which matters for:

- Large file hashing
- Bao tree construction
- Chunk verification

### Built-in Tree Mode (Bao)

Blake3 includes a verified tree mode designed for streaming verification:

```rust
use bao::{encode, decode};

// Hash with tree structure
let (encoded, hash) = encode::encode(data);

// Verify chunks as they stream
let mut decoder = decode::Decoder::new(&hash);
decoder.write_all(&chunk)?;  // Fails if tampered
```

This eliminates the need for manual Merkle tree construction.

### Security

Both Blake2b and Blake3 provide ≥256-bit security against:

- Collision attacks
- Preimage attacks
- Second preimage attacks

Blake3 uses the Bao tree construction which has been formally analyzed.

### Rust Ecosystem

The `blake3` crate is:

- Maintained by the Blake3 authors
- SIMD-optimized (AVX2, AVX-512, NEON)
- No-std compatible
- Well-documented

---

## Migration from Python Prototype

| Python Usage                     | Rust Replacement                |
| -------------------------------- | ------------------------------- |
| `hashlib.blake2b(data).digest()` | `blake3::hash(data)`            |
| `MerkleTree` (manual)            | `bao::encode::Encoder`          |
| Chunk hashes                     | `blake3::hash(chunk)`           |
| Content addressing               | `blake3::hash(plaintext)`       |
| Public key fingerprints          | `blake3::hash(pubkey)` → Base58 |

---

## Usage Guidelines

### Content Addressing

Files and chunks are identified by their Blake3 hash of the **plaintext**:

```rust
// File identity (never hash ciphertext!)
let file_hash = blake3::hash(&plaintext_data);

// Use as content address
let storage_key = format!("chunks/{}", file_hash.to_hex());
```

### Chunk Hashing

For individual chunk verification:

```rust
let chunk_hash = blake3::hash(&chunk_data);
```

### Wire Protocol Integrity

For message authentication (non-keyed):

```rust
let message_hash = blake3::hash(&serialized_message);
```

### Keyed Hashing (when needed)

Blake3 supports keyed mode for MAC-like operations:

```rust
let key: [u8; 32] = /* ... */;
let mac = blake3::keyed_hash(&key, data);
```

---

## Dependencies

```toml
[dependencies]
blake3 = "1"
bao = "0.12"  # For tree mode / streaming verification
```

---

## Security Considerations

1. **Content addressing:** Always hash plaintext, never ciphertext (ciphertext is non-deterministic)
2. **Length extension:** Blake3 is immune to length extension attacks
3. **Collision resistance:** 256-bit output provides 128-bit collision resistance (birthday bound)

---

## References

- [Blake3 specification](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf)
- [Bao specification](https://github.com/oconnor663/bao/blob/master/docs/spec.md)
- [blake3 crate](https://docs.rs/blake3)
- [bao crate](https://docs.rs/bao)
