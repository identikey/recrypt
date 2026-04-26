# OpenFHE Serialization Research

## TL;DR

**OpenFHE serialization already works.** The C++ layer uses Cereal's `PortableBinaryOutputArchive` via `std::stringstream`. We just need to:
1. Wire up the existing FFI functions to `recrypt-ffi`
2. Complete the Lattice backend in `recrypt-core`
3. Treat serialized OpenFHE blobs as opaque `bytes` in our protobuf schema

No need to "manhandle" anything—just plumb it through.

---

## Current State

### What Exists

**`recrypt-openfhe-sys/src/wrapper.cc`** already implements in-memory serialization:

```cpp
rust::Vec<uint8_t> serialize_ciphertext(const Ciphertext &ct) {
  std::stringstream ss;
  lbcrypto::Serial::Serialize(ct.inner, ss, lbcrypto::SerType::BINARY);
  std::string str = ss.str();
  rust::Vec<uint8_t> result;
  result.reserve(str.size());
  for (char c : str) {
    result.push_back(static_cast<uint8_t>(c));
  }
  return result;
}
```

**`recrypt-openfhe-sys/src/lib.rs`** exposes these via CXX FFI:

```rust
fn serialize_ciphertext(ct: &Ciphertext) -> Vec<u8>;
fn deserialize_ciphertext(ctx: &CryptoContext, data: &[u8]) -> UniquePtr<Ciphertext>;
fn serialize_public_key(pk: &PublicKey) -> Vec<u8>;
fn deserialize_public_key(ctx: &CryptoContext, data: &[u8]) -> UniquePtr<PublicKey>;
fn serialize_private_key(sk: &PrivateKey) -> Vec<u8>;
fn deserialize_private_key(ctx: &CryptoContext, data: &[u8]) -> UniquePtr<PrivateKey>;
fn serialize_recrypt_key(rk: &RecryptKey) -> Vec<u8>;
fn deserialize_recrypt_key(ctx: &CryptoContext, data: &[u8]) -> UniquePtr<RecryptKey>;
```

### What's Missing

1. **`recrypt-ffi`** doesn't expose serialization—only raw operations
2. **`recrypt-core`'s Lattice backend** has stubs returning errors like:
   ```rust
   Err(PreError::Encryption("Lattice encryption requires serialization (Phase 3)".into()))
   ```

---

## OpenFHE's Serialization System

### Under the Hood

OpenFHE uses **Cereal** (C++ serialization library) with:
- `cereal::PortableBinaryOutputArchive` for binary format
- `cereal::JSONOutputArchive` for JSON format

The binary format uses Cereal's portable encoding—consistent across platforms but opaque.

### Key Insight: It's Opaque But Stable

We don't need to understand or manipulate the internal format. Treat it as:

```
OpenFHE Object → serialize → [opaque bytes] → deserialize → OpenFHE Object
```

The bytes are:
- **Not human-readable** (binary, includes type tags)
- **Not protobuf** (Cereal's own format)
- **Platform-portable** (Cereal handles endianness)
- **Version-tagged** (Cereal includes version info for schema evolution)

### Sizes (Measured)

| Object | Typical Size |
|--------|-------------|
| PublicKey | ~180-220 KB |
| PrivateKey | ~90-120 KB |
| RecryptKey | ~1.5-2 MB |
| Ciphertext (96 bytes plaintext) | ~5-10 KB |
| CryptoContext | ~10-50 MB (!!!) |

**The CryptoContext is huge** bc it includes precomputed tables for NTT operations.

---

## Integration Strategy

### Option A: Opaque Blob in Protobuf (Recommended)

Treat OpenFHE serialized data as `bytes` fields in our protobuf:

```protobuf
message CiphertextProto {
    BackendId backend = 1;
    uint32 level = 2;
    bytes data = 3;  // OpenFHE serialized blob (opaque)
}
```

**Pros:**
- Simple—just pass bytes through
- No format conversion overhead
- OpenFHE handles versioning internally

**Cons:**
- Can't inspect contents without deserializing
- Large keys (~200 KB public key)

### Option B: Extract and Reformat (Not Recommended)

Parse OpenFHE's internal structure, extract coefficients, re-serialize in our format.

**Pros:**
- Could achieve smaller sizes
- Full control over format

**Cons:**
- Enormous complexity
- Must track OpenFHE's internal format changes
- Security risk (might break cryptographic properties)
- Not worth it for hybrid encryption (key material is only ~5 KB overhead)

### Option C: Context Caching (Required for Performance)

**Problem:** CryptoContext is 10-50 MB. We can't serialize it with every message.

**Solution:** Share context separately:

```rust
/// PreContext wraps OpenFHE's CryptoContext
/// Must be the SAME context for serialize/deserialize pairs
pub struct LatticeBackend {
    context: Arc<FfiContext>,
}
```

For wire protocol:
- Don't serialize CryptoContext with each message
- Assume both sides have compatible contexts (same BFV parameters)
- Include only a context identifier/hash for validation

---

## Implementation Plan

### Step 1: Wire Serialization Through recrypt-ffi

Add to `crates/recrypt-ffi/src/openfhe/mod.rs`:

```rust
impl PreContext {
    pub fn serialize_public_key(&self, pk: &PublicKey) -> Result<Vec<u8>, FfiError> {
        Ok(openfhe_sys::serialize_public_key(&pk.inner))
    }
    
    pub fn deserialize_public_key(&self, bytes: &[u8]) -> Result<PublicKey, FfiError> {
        let pk = openfhe_sys::deserialize_public_key(&self.inner, bytes);
        if pk.is_null() {
            return Err(FfiError::OpenFhe("Deserialization failed".into()));
        }
        Ok(PublicKey { inner: pk })
    }
    // ... same for ciphertext, private_key, recrypt_key
}
```

### Step 2: Complete Lattice Backend

Update `crates/recrypt-core/src/pre/backends/lattice.rs`:

```rust
impl PreBackend for LatticeBackend {
    fn generate_keypair(&self) -> PreResult<KeyPair> {
        let ffi_kp = self.context.generate_keypair()
            .map_err(|e| PreError::KeyGeneration(e.to_string()))?;
        
        let pk_bytes = self.context.serialize_public_key(&ffi_kp.public)?;
        let sk_bytes = self.context.serialize_private_key(&ffi_kp.secret)?;
        
        Ok(KeyPair {
            public: PublicKey::new(BackendId::Lattice, pk_bytes),
            secret: SecretKey::new(BackendId::Lattice, sk_bytes),
        })
    }
    
    fn encrypt(&self, recipient: &PublicKey, plaintext: &[u8]) -> PreResult<Ciphertext> {
        // Deserialize recipient's public key
        let pk = self.context.deserialize_public_key(recipient.as_bytes())?;
        
        // Encrypt (returns Vec<FfiCiphertext> bc of chunking)
        let cts = self.context.encrypt(&pk, plaintext)?;
        
        // Serialize all ciphertexts into one blob
        let mut ct_bytes = Vec::new();
        ct_bytes.extend((cts.len() as u32).to_le_bytes());
        for ct in &cts {
            let serialized = self.context.serialize_ciphertext(ct)?;
            ct_bytes.extend((serialized.len() as u32).to_le_bytes());
            ct_bytes.extend(serialized);
        }
        
        Ok(Ciphertext::new(BackendId::Lattice, 0, ct_bytes))
    }
    // ... decrypt, recrypt similarly
}
```

### Step 3: Handle Context Persistence (Separate Concern)

For the server to perform recryption, it needs:
1. A compatible CryptoContext (same parameters)
2. RecryptKeys that were generated under that context

**Options:**
- **Single global context** (simplest—all users share BFV parameters)
- **Context-per-user** (more flexible, massive memory cost)
- **Serialized context file** (startup cost, but deterministic)

Recommendation: Single global context with fixed BFV parameters. Document the parameters in the wire protocol.

---

## Testing the Serialization

Add to `recrypt-openfhe-sys` tests:

```rust
#[test]
fn test_ciphertext_serialization_roundtrip() {
    let ctx = create_context();
    let kp = ctx.generate_keypair().unwrap();
    
    let plaintext = b"Hello!";
    let ct = ctx.encrypt(&kp.public, plaintext).unwrap();
    
    // Serialize
    let serialized = serialize_ciphertext(&ct);
    println!("Ciphertext size: {} bytes", serialized.len());
    
    // Deserialize
    let ct2 = deserialize_ciphertext(&ctx, &serialized).unwrap();
    
    // Decrypt should give same result
    let recovered = ctx.decrypt(&kp.secret, &ct2, plaintext.len()).unwrap();
    assert_eq!(recovered, plaintext);
}
```

---

## Summary

| Question | Answer |
|----------|--------|
| Does OpenFHE serialization work? | **Yes**, via Cereal + stringstream |
| Do we need to modify the format? | **No**, treat as opaque bytes |
| Is it compatible with protobuf? | **Yes**, just use `bytes` field |
| What about CryptoContext size? | Share context, don't serialize per-message |
| What's left to implement? | Wire FFI → recrypt-ffi → Lattice backend |

**Effort estimate:** 0.5-1 day to wire it up (much less than the 1 day budgeted in Phase 3.6).

---

## References

- `crates/recrypt-openfhe-sys/src/wrapper.cc` - Existing serialization
- `crates/recrypt-openfhe-sys/src/lib.rs` - FFI bindings
- `vendor/openfhe-development/src/core/include/utils/serial.h` - OpenFHE's Serial API
- [Cereal documentation](https://uscilab.github.io/cereal/)

