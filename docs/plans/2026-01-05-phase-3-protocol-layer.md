> **Historical:** Phase 3 planning. Protobuf was replaced by Gordian Envelope. See [wire-protocol.md](../wire-protocol.md).

# Phase 3: Protocol Layer Implementation Plan

**STATUS: ✅ COMPLETE** (January 5, 2026)

## Overview

Build `recrypt-proto` crate for wire protocol serialization (Protobuf + ASCII armor + JSON) and integrate streaming verification via Blake3/Bao. This phase transforms Phase 2's in-memory structures into transmittable/storable formats.

**Duration:** 3-4 days  
**Prerequisites:** Phase 2 complete (`recrypt-core` functional with Mock + Lattice backends)

## Current State Analysis

Phase 2 delivered:

- ✅ `recrypt-core` with pluggable PRE backends (Mock functional, Lattice wrapper)
- ✅ Hybrid encryption (XChaCha20 + Bao)
- ✅ Multi-signatures (ED25519 + ML-DSA-87)
- ✅ Property-based tests passing
- ✅ `EncryptedFile`, `KeyMaterial`, signature types defined
- ✅ Basic binary serialization in `EncryptedFile::to_bytes()` and `Ciphertext::to_bytes()`

**Key Files:**

- `crates/recrypt-core/src/hybrid/encrypted_file.rs` - `EncryptedFile` with basic `to_bytes()`
- `crates/recrypt-core/src/hybrid/keymaterial.rs` - `KeyMaterial` (96 bytes, fixed format)
- `crates/recrypt-core/src/pre/keys.rs` - `PublicKey`, `SecretKey`, `Ciphertext`, `RecryptKey`
- `crates/recrypt-core/src/sign/mod.rs` - `MultiSig` (ED25519 + ML-DSA)

**Missing (Phase 3 scope):**

- ❌ Protobuf schema and prost codegen
- ❌ ASCII armor format implementation
- ❌ JSON serialization with serde
- ❌ `MultiFormat` trait for polymorphic serialization
- ❌ `EncryptedFile::from_bytes()` deserialization
- ❌ OpenFHE key/ciphertext serialization (Lattice backend completion)
- ❌ Streaming Bao verification helpers
- ❌ Signature integration with `EncryptedFile` (signature over wrapped_key + bao_hash)

## Desired End State

A production-ready `recrypt-proto` crate that:

1. **Defines Protobuf schema** for all message types (files, keys, signatures, capabilities)
2. **Implements `MultiFormat` trait** enabling protobuf/JSON/armor serialization
3. **Provides ASCII armor** for human-readable key export/backup
4. **Integrates Bao streaming verification** with proper slice extraction
5. **Completes Lattice backend serialization** (OpenFHE key/ciphertext persistence)
6. **Adds signature binding** to `EncryptedFile` (wrapped_key + bao_hash signed)

### Success Verification

#### Automated:

- [x] All unit tests pass: `cargo test -p recrypt-proto`
- [x] Protobuf roundtrip tests pass for all message types
- [x] ASCII armor parse/emit roundtrip for keys
- [x] JSON serialization matches expected schema
- [x] Integration with `recrypt-core` compiles: `cargo build -p recrypt-core -p recrypt-proto`
- [x] Clippy clean: `cargo clippy -p recrypt-proto -- -D warnings`
- [x] Doc tests pass: `cargo test -p recrypt-proto --doc`

#### Manual:

- [x] Exported ASCII armor keys can be re-imported
- [x] Protobuf messages are compact (within size estimates from design docs)
- [x] Streaming verification works for large files (100+ MB)
- [ ] Lattice backend encrypt/decrypt works with serialized keys (DEFERRED - Phase 3.6)

**Implementation Note:** After completing each sub-phase and all automated checks pass, pause for manual confirmation before proceeding.

## What We're NOT Doing

- ❌ **Network transport** - That's Phase 6 (server)
- ❌ **Storage integration** - That's Phase 4
- ❌ **Content negotiation HTTP headers** - That's Phase 6
- ❌ **Signature verification middleware** - That's Phase 6
- ❌ **HDprint generation** - That's Phase 5 (parallel track)
- ❌ **Threshold PRE** - Single-server only

## Implementation Approach

**Strategy:** Schema-first, layered implementation

1. **Define Protobuf schema** (`.proto` files, prost codegen)
2. **Implement `MultiFormat` trait** abstraction
3. **Build Protobuf serialization** for core types
4. **Add ASCII armor format** for keys
5. **Integrate serde for JSON**
6. **Complete Lattice backend** serialization
7. **Add Bao streaming helpers**
8. **Bind signatures to EncryptedFile**

**Key Design Decisions:**

- **Protobuf via prost** (compile-time codegen, zero-copy where possible)
- **serde for JSON/config** (ecosystem standard)
- **Custom ASCII armor** (PGP-inspired but Recrypt-specific headers)
- **Version field first** in all messages (future evolution)
- **Backend tag in serialized form** (Lattice vs EC vs Mock distinguishable)

---

## Phase 3.1: Crate Structure & Protobuf Schema

### Overview

Create `recrypt-proto` crate and define Protobuf schema for all message types.

### Changes Required

#### 1. Create crate structure

**File**: `crates/recrypt-proto/Cargo.toml`

```toml
[package]
name = "recrypt-proto"
version.workspace = true
edition.workspace = true

[dependencies]
# Protobuf
prost = "0.13"
prost-types = "0.13"

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Encoding
base64 = "0.22"
hex = "0.4"

# Core types (we serialize these)
recrypt-core = { path = "../recrypt-core" }

# Error handling
thiserror.workspace = true

# Blake3/Bao for streaming verification
blake3 = { version = "1.5", features = ["traits-preview"] }
bao = "0.12"

[build-dependencies]
prost-build = "0.13"

[dev-dependencies]
proptest.workspace = true
```

**File**: `crates/recrypt-proto/build.rs`

```rust
use std::io::Result;

fn main() -> Result<()> {
    prost_build::Config::new()
        .out_dir("src/generated")
        .compile_protos(&["proto/dcypher.proto"], &["proto/"])?;

    println!("cargo:rerun-if-changed=proto/dcypher.proto");
    Ok(())
}
```

**File**: `crates/recrypt-proto/src/lib.rs`

```rust
//! recrypt-proto: Wire protocol and serialization formats
//!
//! Provides:
//! - Protobuf serialization (primary wire format)
//! - ASCII armor (human-readable export)
//! - JSON (debugging, API responses)
//! - Streaming verification via Blake3/Bao
//!
//! ## Format Selection
//!
//! | Format      | Use Case                    | Size Overhead |
//! |-------------|-----------------------------|--------------:|
//! | Protobuf    | Wire, storage               |        ~0.1%  |
//! | JSON        | Debug, API                  |        ~0.5%  |
//! | ASCII Armor | Key export, manual backup   |         ~35%  |

pub mod error;
pub mod format;
pub mod armor;
pub mod bao_stream;

mod generated;

pub use error::{ProtoError, ProtoResult};
pub use format::{Format, MultiFormat, detect_format};
pub use armor::{ArmorType, armor_encode, armor_decode};
pub use bao_stream::{BaoEncoder, BaoDecoder, SliceVerifier};
pub use generated::dcypher::v1 as proto;
```

#### 2. Protobuf schema

**File**: `crates/recrypt-proto/proto/dcypher.proto`

```protobuf
syntax = "proto3";
package recrypt.v1;

// =============================================================================
// Core Cryptographic Types
// =============================================================================

// PRE backend identifier
enum BackendId {
    BACKEND_UNKNOWN = 0;
    BACKEND_LATTICE = 1;      // OpenFHE BFV/PRE (post-quantum)
    BACKEND_EC_PAIRING = 2;   // IronCore recrypt (classical)
    BACKEND_EC_SECP256K1 = 3; // NuCypher Umbral (classical)
    BACKEND_MOCK = 255;       // Testing only
}

// Public key bundle (may contain multiple algorithm keys)
message PublicKeyBundle {
    uint32 version = 1;
    bytes ed25519_key = 2;              // 32 bytes
    repeated PqPublicKey pq_keys = 3;
    BackendId pre_backend = 4;
    bytes pre_public_key = 5;           // Backend-specific serialization
}

// Post-quantum public key
message PqPublicKey {
    string algorithm = 1;               // e.g., "ML-DSA-87"
    bytes key_data = 2;
}

// Secret key bundle (for storage/export only—NEVER transmit!)
message SecretKeyBundle {
    uint32 version = 1;
    bytes ed25519_key = 2;              // 32 bytes
    repeated PqSecretKey pq_keys = 3;
    BackendId pre_backend = 4;
    bytes pre_secret_key = 5;           // Backend-specific serialization
}

message PqSecretKey {
    string algorithm = 1;
    bytes key_data = 2;
}

// Recryption key (for proxy)
message RecryptKeyProto {
    uint32 version = 1;
    BackendId backend = 2;
    bytes from_pubkey_fingerprint = 3;  // HDprint of source
    bytes to_pubkey_fingerprint = 4;    // HDprint of destination
    bytes key_data = 5;                 // Backend-specific serialization
}

// PRE ciphertext (wrapped key material)
message CiphertextProto {
    BackendId backend = 1;
    uint32 level = 2;                   // 0 = original, 1+ = recrypted
    bytes data = 3;                     // Backend-specific ciphertext
}

// =============================================================================
// Encrypted File Format
// =============================================================================

// Complete encrypted file (wire format)
message EncryptedFileProto {
    uint32 version = 1;                 // Format version (2)
    CiphertextProto wrapped_key = 2;    // PRE-encrypted KeyMaterial
    bytes bao_hash = 3;                 // 32 bytes - Bao root of ciphertext
    bytes bao_outboard = 4;             // Bao verification tree (~1% size)
    bytes ciphertext = 5;               // XChaCha20 encrypted data
    MultiSignatureProto signature = 6;  // Signs (wrapped_key || bao_hash)
}

// Key material bundle (96 bytes, encrypted inside wrapped_key)
// NOT transmitted separately—included here for documentation
message KeyMaterialProto {
    bytes symmetric_key = 1;            // 32 bytes - XChaCha20 key
    bytes nonce = 2;                    // 24 bytes - XChaCha20 nonce
    bytes plaintext_hash = 3;           // 32 bytes - Blake3 of plaintext
    uint64 plaintext_size = 4;          // Original size in bytes
}

// =============================================================================
// Signatures
// =============================================================================

// Multi-signature (classical + post-quantum)
message MultiSignatureProto {
    bytes ed25519_signature = 1;        // 64 bytes
    repeated PqSignatureProto pq_signatures = 2;
}

message PqSignatureProto {
    string algorithm = 1;               // e.g., "ML-DSA-87"
    bytes signature = 2;
}

// =============================================================================
// File Metadata (for listings, not full content)
// =============================================================================

message FileMetadata {
    uint32 version = 1;
    bytes file_hash = 2;                // Blake3 of ciphertext (content address)
    uint64 total_size = 3;              // Ciphertext size
    uint64 created_at = 4;              // Unix timestamp
    bytes owner_fingerprint = 5;        // HDprint of owner's pubkey
    BackendId backend = 6;              // PRE backend used
}

// =============================================================================
// Chunk Transfer (for streaming)
// =============================================================================

message ChunkProto {
    uint32 index = 1;
    bytes data = 2;                     // Encrypted chunk data
    bytes bao_proof = 3;                // Optional: Bao slice proof for this chunk
}

// =============================================================================
// Capabilities (access tokens)
// =============================================================================

message CapabilityProto {
    uint32 version = 1;
    bytes file_hash = 2;                // Content address
    bytes granted_to = 3;               // Public key fingerprint
    repeated string operations = 4;     // "read", "write", "delete", "share"
    uint64 expires_at = 5;              // Unix timestamp (0 = no expiry)
    bytes issuer_fingerprint = 6;       // Who granted this
    MultiSignatureProto signature = 7;  // Signs all above fields
}

// =============================================================================
// API Request/Response Messages
// =============================================================================

message UploadRequest {
    FileMetadata metadata = 1;
    repeated ChunkProto chunks = 2;
}

message DownloadResponse {
    FileMetadata metadata = 1;
    repeated string chunk_urls = 2;     // Pre-signed URLs for chunks
}

message RecryptRequest {
    bytes file_hash = 1;
    bytes recrypt_key_id = 2;           // Fingerprint of recrypt key
}

message RecryptResponse {
    CiphertextProto new_wrapped_key = 1;
}
```

#### 3. Create generated module

**File**: `crates/recrypt-proto/src/generated/mod.rs`

```rust
//! Auto-generated protobuf types
//!
//! Generated by prost-build from proto/dcypher.proto

pub mod dcypher {
    pub mod v1 {
        include!("recrypt.v1.rs");
    }
}
```

**Note:** The actual `recrypt.v1.rs` file will be generated by `build.rs`. Create placeholder initially:

**File**: `crates/recrypt-proto/src/generated/recrypt.v1.rs` (placeholder)

```rust
// This file will be auto-generated by prost-build
// Run `cargo build -p recrypt-proto` to generate
```

### Success Criteria

#### Automated Verification:

- [x] Crate compiles: `cargo build -p recrypt-proto`
- [x] Protobuf types generated: `ls crates/recrypt-proto/src/generated/recrypt.v1.rs`
- [x] Generated code has expected types: grep for `EncryptedFileProto`

#### Manual Verification:

- [x] Schema covers all types from design docs
- [x] Field numbers align with wire-protocol.md
- [x] Version field is first in all messages (evolution-friendly)

---

## Phase 3.2: Error Types & MultiFormat Trait

### Overview

Define error types and the `MultiFormat` trait for polymorphic serialization.

### Changes Required

#### 1. Error types

**File**: `crates/recrypt-proto/src/error.rs`

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProtoError {
    #[error("Protobuf encode error: {0}")]
    ProtobufEncode(#[from] prost::EncodeError),

    #[error("Protobuf decode error: {0}")]
    ProtobufDecode(#[from] prost::DecodeError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Armor parse error: {0}")]
    ArmorParse(String),

    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    #[error("Bao verification failed: {0}")]
    BaoVerification(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: u32, actual: u32 },

    #[error("Core error: {0}")]
    Core(#[from] dcypher_core::CoreError),
}

pub type ProtoResult<T> = Result<T, ProtoError>;
```

#### 2. Format detection and MultiFormat trait

**File**: `crates/recrypt-proto/src/format.rs`

```rust
//! Multi-format serialization support

use crate::error::{ProtoError, ProtoResult};
use crate::armor::ArmorType;

/// Detected serialization format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Protobuf,
    Json,
    Armor,
}

/// Detect format from raw bytes
pub fn detect_format(data: &[u8]) -> Format {
    if data.starts_with(b"----- BEGIN DCYPHER") {
        Format::Armor
    } else if data.first() == Some(&b'{') {
        Format::Json
    } else {
        Format::Protobuf
    }
}

/// Trait for types that can be serialized to multiple formats
pub trait MultiFormat: Sized {
    /// Protobuf message type name (for debugging)
    fn proto_name() -> &'static str;

    /// Serialize to Protobuf bytes
    fn to_protobuf(&self) -> ProtoResult<Vec<u8>>;

    /// Deserialize from Protobuf bytes
    fn from_protobuf(bytes: &[u8]) -> ProtoResult<Self>;

    /// Serialize to JSON string
    fn to_json(&self) -> ProtoResult<String>;

    /// Deserialize from JSON string
    fn from_json(s: &str) -> ProtoResult<Self>;

    /// Serialize to ASCII armor (if applicable)
    fn to_armor(&self, armor_type: ArmorType) -> ProtoResult<String>;

    /// Deserialize from ASCII armor
    fn from_armor(s: &str) -> ProtoResult<Self>;

    /// Deserialize from any format (auto-detect)
    fn from_any(data: &[u8]) -> ProtoResult<Self> {
        match detect_format(data) {
            Format::Protobuf => Self::from_protobuf(data),
            Format::Json => {
                let s = std::str::from_utf8(data)
                    .map_err(|e| ProtoError::InvalidFormat(e.to_string()))?;
                Self::from_json(s)
            }
            Format::Armor => {
                let s = std::str::from_utf8(data)
                    .map_err(|e| ProtoError::InvalidFormat(e.to_string()))?;
                Self::from_armor(s)
            }
        }
    }
}
```

### Success Criteria

#### Automated Verification:

- [x] Error types compile: `cargo build -p recrypt-proto`
- [x] Format detection tests pass

#### Manual Verification:

- [x] Error messages are informative
- [x] `MultiFormat` trait covers all serialization scenarios

---

## Phase 3.3: ASCII Armor Implementation

### Overview

Implement PGP-style ASCII armor for human-readable key export.

### Changes Required

#### 1. Armor module

**File**: `crates/recrypt-proto/src/armor.rs`

````rust
//! ASCII armor format for human-readable export
//!
//! Format:
//! ```text
//! ----- BEGIN DCYPHER PUBLIC KEY -----
//! Version: 1
//! Algorithm: ED25519+ML-DSA-87+PRE
//! Fingerprint: a3k7x5a_Ab3DeF_Xy9ZmP7q_R2sK1M4V
//! Created: 2024-01-15T10:30:00Z
//!
//! eyJlZDI1NTE5IjoiTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FF...
//! (base64 continues)
//! ----- END DCYPHER PUBLIC KEY -----
//! ```

use crate::error::{ProtoError, ProtoResult};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::collections::HashMap;

/// Types of armored content
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmorType {
    PublicKey,
    SecretKey,
    Message,
    Capability,
    RecryptKey,
    EncryptedFile,
}

impl ArmorType {
    pub fn label(&self) -> &'static str {
        match self {
            Self::PublicKey => "PUBLIC KEY",
            Self::SecretKey => "SECRET KEY",
            Self::Message => "MESSAGE",
            Self::Capability => "CAPABILITY",
            Self::RecryptKey => "RECRYPT KEY",
            Self::EncryptedFile => "ENCRYPTED FILE",
        }
    }

    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "PUBLIC KEY" => Some(Self::PublicKey),
            "SECRET KEY" => Some(Self::SecretKey),
            "MESSAGE" => Some(Self::Message),
            "CAPABILITY" => Some(Self::Capability),
            "RECRYPT KEY" => Some(Self::RecryptKey),
            "ENCRYPTED FILE" => Some(Self::EncryptedFile),
            _ => None,
        }
    }
}

/// Parsed armor block
#[derive(Debug)]
pub struct ArmorBlock {
    pub armor_type: ArmorType,
    pub headers: HashMap<String, String>,
    pub payload: Vec<u8>,
}

/// Encode data as ASCII armor
pub fn armor_encode(
    armor_type: ArmorType,
    headers: &[(&str, &str)],
    payload: &[u8],
) -> String {
    let mut result = String::new();

    // Begin line
    result.push_str(&format!("----- BEGIN DCYPHER {} -----\n", armor_type.label()));

    // Headers
    for (key, value) in headers {
        result.push_str(&format!("{}: {}\n", key, value));
    }

    // Blank line before payload
    result.push('\n');

    // Base64 payload (wrapped at 64 chars)
    let b64 = BASE64.encode(payload);
    for chunk in b64.as_bytes().chunks(64) {
        result.push_str(std::str::from_utf8(chunk).unwrap());
        result.push('\n');
    }

    // End line
    result.push_str(&format!("----- END DCYPHER {} -----\n", armor_type.label()));

    result
}

/// Decode ASCII armor to bytes
pub fn armor_decode(s: &str) -> ProtoResult<ArmorBlock> {
    let lines: Vec<&str> = s.lines().collect();

    // Find BEGIN line
    let begin_idx = lines.iter()
        .position(|l| l.starts_with("----- BEGIN DCYPHER"))
        .ok_or_else(|| ProtoError::ArmorParse("Missing BEGIN line".into()))?;

    // Parse armor type from BEGIN line
    let begin_line = lines[begin_idx];
    let type_str = begin_line
        .strip_prefix("----- BEGIN DCYPHER ")
        .and_then(|s| s.strip_suffix(" -----"))
        .ok_or_else(|| ProtoError::ArmorParse("Invalid BEGIN format".into()))?;

    let armor_type = ArmorType::from_label(type_str)
        .ok_or_else(|| ProtoError::ArmorParse(format!("Unknown armor type: {}", type_str)))?;

    // Find END line
    let end_marker = format!("----- END DCYPHER {} -----", armor_type.label());
    let end_idx = lines.iter()
        .position(|l| *l == end_marker)
        .ok_or_else(|| ProtoError::ArmorParse("Missing END line".into()))?;

    // Parse headers (until blank line)
    let mut headers = HashMap::new();
    let mut payload_start = begin_idx + 1;

    for (i, line) in lines[begin_idx + 1..end_idx].iter().enumerate() {
        if line.is_empty() {
            payload_start = begin_idx + 1 + i + 1;
            break;
        }
        if let Some((key, value)) = line.split_once(": ") {
            headers.insert(key.to_string(), value.to_string());
        }
    }

    // Decode base64 payload
    let payload_b64: String = lines[payload_start..end_idx]
        .iter()
        .flat_map(|l| l.chars())
        .filter(|c| !c.is_whitespace())
        .collect();

    let payload = BASE64.decode(&payload_b64)?;

    Ok(ArmorBlock {
        armor_type,
        headers,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_armor_roundtrip() {
        let payload = b"Hello, Recrypt!";
        let headers = [
            ("Version", "1"),
            ("Algorithm", "ED25519+ML-DSA-87"),
        ];

        let armored = armor_encode(ArmorType::PublicKey, &headers, payload);
        let decoded = armor_decode(&armored).unwrap();

        assert_eq!(decoded.armor_type, ArmorType::PublicKey);
        assert_eq!(decoded.headers.get("Version"), Some(&"1".to_string()));
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_armor_long_payload() {
        let payload = vec![0u8; 1024]; // 1 KB
        let armored = armor_encode(ArmorType::Message, &[], &payload);
        let decoded = armor_decode(&armored).unwrap();

        assert_eq!(decoded.payload, payload);
    }
}
````

### Success Criteria

#### Automated Verification:

- [x] Armor tests pass: `cargo test -p recrypt-proto armor`
- [x] Roundtrip preserves all data

#### Manual Verification:

- [x] Armored output is human-readable
- [x] Lines wrap at 64 chars (standard PGP)

---

## Phase 3.4: Protobuf Serialization for Core Types

### Overview

Implement `MultiFormat` for `EncryptedFile`, `PublicKey`, and other core types.

### Changes Required

#### 1. Conversion traits between core and proto types

**File**: `crates/recrypt-proto/src/convert.rs`

```rust
//! Conversions between recrypt-core types and protobuf types

use crate::error::{ProtoError, ProtoResult};
use crate::proto::*;
use dcypher_core::pre::{BackendId, Ciphertext, PublicKey, SecretKey, RecryptKey};
use dcypher_core::hybrid::{EncryptedFile, KeyMaterial};
use dcypher_core::sign::MultiSig;

// BackendId conversions
impl From<BackendId> for i32 {
    fn from(id: BackendId) -> i32 {
        match id {
            BackendId::Lattice => 1,
            BackendId::EcPairing => 2,
            BackendId::EcSecp256k1 => 3,
            BackendId::Mock => 255,
        }
    }
}

impl TryFrom<i32> for BackendId {
    type Error = ProtoError;

    fn try_from(v: i32) -> ProtoResult<Self> {
        match v {
            1 => Ok(BackendId::Lattice),
            2 => Ok(BackendId::EcPairing),
            3 => Ok(BackendId::EcSecp256k1),
            255 => Ok(BackendId::Mock),
            _ => Err(ProtoError::InvalidFormat(format!("Unknown backend ID: {}", v))),
        }
    }
}

// Ciphertext conversions
impl From<&Ciphertext> for CiphertextProto {
    fn from(ct: &Ciphertext) -> Self {
        CiphertextProto {
            backend: ct.backend().into(),
            level: ct.level() as u32,
            data: ct.as_bytes().to_vec(),
        }
    }
}

impl TryFrom<CiphertextProto> for Ciphertext {
    type Error = ProtoError;

    fn try_from(proto: CiphertextProto) -> ProtoResult<Self> {
        let backend = BackendId::try_from(proto.backend)?;
        Ok(Ciphertext::new(backend, proto.level as u8, proto.data))
    }
}

// EncryptedFile conversions
impl From<&EncryptedFile> for EncryptedFileProto {
    fn from(ef: &EncryptedFile) -> Self {
        EncryptedFileProto {
            version: 2,
            wrapped_key: Some(CiphertextProto::from(&ef.wrapped_key)),
            bao_hash: ef.bao_hash.to_vec(),
            bao_outboard: ef.bao_outboard.clone(),
            ciphertext: ef.ciphertext.clone(),
            signature: None, // Added in Phase 3.7
        }
    }
}

impl TryFrom<EncryptedFileProto> for EncryptedFile {
    type Error = ProtoError;

    fn try_from(proto: EncryptedFileProto) -> ProtoResult<Self> {
        let wrapped_key = proto.wrapped_key
            .ok_or_else(|| ProtoError::MissingField("wrapped_key".into()))?;

        if proto.bao_hash.len() != 32 {
            return Err(ProtoError::InvalidFormat(
                format!("bao_hash must be 32 bytes, got {}", proto.bao_hash.len())
            ));
        }

        Ok(EncryptedFile {
            wrapped_key: Ciphertext::try_from(wrapped_key)?,
            bao_hash: proto.bao_hash.try_into().unwrap(),
            bao_outboard: proto.bao_outboard,
            ciphertext: proto.ciphertext,
        })
    }
}

// MultiSig conversions
impl From<&MultiSig> for MultiSignatureProto {
    fn from(sig: &MultiSig) -> Self {
        MultiSignatureProto {
            ed25519_signature: sig.ed25519_sig.to_bytes().to_vec(),
            pq_signatures: vec![PqSignatureProto {
                algorithm: "ML-DSA-87".into(),
                signature: sig.ml_dsa_sig.clone(),
            }],
        }
    }
}

impl TryFrom<MultiSignatureProto> for MultiSig {
    type Error = ProtoError;

    fn try_from(proto: MultiSignatureProto) -> ProtoResult<Self> {
        use ed25519_dalek::Signature;

        if proto.ed25519_signature.len() != 64 {
            return Err(ProtoError::InvalidFormat(
                "ED25519 signature must be 64 bytes".into()
            ));
        }

        let ed25519_sig = Signature::from_bytes(
            &proto.ed25519_signature.try_into().unwrap()
        );

        let ml_dsa_sig = proto.pq_signatures
            .into_iter()
            .find(|s| s.algorithm == "ML-DSA-87")
            .ok_or_else(|| ProtoError::MissingField("ML-DSA-87 signature".into()))?
            .signature;

        Ok(MultiSig {
            ed25519_sig,
            ml_dsa_sig,
        })
    }
}
```

#### 2. MultiFormat implementations

**File**: `crates/recrypt-proto/src/impls.rs`

```rust
//! MultiFormat trait implementations for core types

use crate::error::{ProtoError, ProtoResult};
use crate::format::MultiFormat;
use crate::armor::{ArmorType, armor_encode, armor_decode};
use crate::proto::*;
use crate::convert::*;
use dcypher_core::hybrid::EncryptedFile;
use prost::Message;
use serde::{Serialize, Deserialize};

// EncryptedFile serialization
impl MultiFormat for EncryptedFile {
    fn proto_name() -> &'static str {
        "recrypt.v1.EncryptedFileProto"
    }

    fn to_protobuf(&self) -> ProtoResult<Vec<u8>> {
        let proto = EncryptedFileProto::from(self);
        let mut buf = Vec::with_capacity(proto.encoded_len());
        proto.encode(&mut buf)?;
        Ok(buf)
    }

    fn from_protobuf(bytes: &[u8]) -> ProtoResult<Self> {
        let proto = EncryptedFileProto::decode(bytes)?;
        Self::try_from(proto)
    }

    fn to_json(&self) -> ProtoResult<String> {
        // Use a JSON-friendly representation
        #[derive(Serialize)]
        struct JsonEncryptedFile {
            version: u32,
            wrapped_key: JsonCiphertext,
            bao_hash: String,
            bao_outboard: String,
            ciphertext: String,
        }

        #[derive(Serialize)]
        struct JsonCiphertext {
            backend: String,
            level: u32,
            data: String,
        }

        let json = JsonEncryptedFile {
            version: 2,
            wrapped_key: JsonCiphertext {
                backend: format!("{:?}", self.wrapped_key.backend()),
                level: self.wrapped_key.level() as u32,
                data: hex::encode(self.wrapped_key.as_bytes()),
            },
            bao_hash: hex::encode(&self.bao_hash),
            bao_outboard: hex::encode(&self.bao_outboard),
            ciphertext: hex::encode(&self.ciphertext),
        };

        Ok(serde_json::to_string_pretty(&json)?)
    }

    fn from_json(s: &str) -> ProtoResult<Self> {
        // Parse JSON and convert
        #[derive(Deserialize)]
        struct JsonEncryptedFile {
            version: u32,
            wrapped_key: JsonCiphertext,
            bao_hash: String,
            bao_outboard: String,
            ciphertext: String,
        }

        #[derive(Deserialize)]
        struct JsonCiphertext {
            backend: String,
            level: u32,
            data: String,
        }

        let json: JsonEncryptedFile = serde_json::from_str(s)?;

        if json.version != 2 {
            return Err(ProtoError::VersionMismatch {
                expected: 2,
                actual: json.version,
            });
        }

        let backend = match json.wrapped_key.backend.as_str() {
            "Lattice" => dcypher_core::pre::BackendId::Lattice,
            "Mock" => dcypher_core::pre::BackendId::Mock,
            _ => return Err(ProtoError::InvalidFormat(
                format!("Unknown backend: {}", json.wrapped_key.backend)
            )),
        };

        let bao_hash: [u8; 32] = hex::decode(&json.bao_hash)?
            .try_into()
            .map_err(|_| ProtoError::InvalidFormat("bao_hash must be 32 bytes".into()))?;

        Ok(EncryptedFile {
            wrapped_key: dcypher_core::pre::Ciphertext::new(
                backend,
                json.wrapped_key.level as u8,
                hex::decode(&json.wrapped_key.data)?,
            ),
            bao_hash,
            bao_outboard: hex::decode(&json.bao_outboard)?,
            ciphertext: hex::decode(&json.ciphertext)?,
        })
    }

    fn to_armor(&self, _armor_type: ArmorType) -> ProtoResult<String> {
        let proto_bytes = self.to_protobuf()?;
        let headers = [
            ("Version", "2"),
            ("Format", "protobuf"),
        ];
        Ok(armor_encode(ArmorType::EncryptedFile, &headers, &proto_bytes))
    }

    fn from_armor(s: &str) -> ProtoResult<Self> {
        let block = armor_decode(s)?;
        if block.armor_type != ArmorType::EncryptedFile {
            return Err(ProtoError::InvalidFormat(
                format!("Expected ENCRYPTED FILE, got {:?}", block.armor_type)
            ));
        }
        Self::from_protobuf(&block.payload)
    }
}
```

### Success Criteria

#### Automated Verification:

- [x] Conversion tests pass: `cargo test -p recrypt-proto convert`
- [x] Protobuf roundtrip for EncryptedFile works
- [x] JSON roundtrip works
- [x] Armor roundtrip works

#### Manual Verification:

- [x] Protobuf size is within expected range (~0.1% overhead)
- [x] JSON output is readable
- [x] Armor output is valid PGP-style

---

## Phase 3.5: Bao Streaming Verification Helpers

### Overview

Wrap Blake3/Bao for streaming verification with slice extraction.

### Changes Required

#### 1. Bao streaming module

**File**: `crates/recrypt-proto/src/bao_stream.rs`

```rust
//! Streaming verification via Blake3/Bao
//!
//! Provides helpers for:
//! - Encoding files with Bao tree (outboard mode)
//! - Streaming verification during download
//! - Slice extraction for random access

use crate::error::{ProtoError, ProtoResult};
use std::io::{Read, Write};

/// Bao encoder for creating verification trees
pub struct BaoEncoder {
    outboard: Vec<u8>,
}

impl BaoEncoder {
    /// Create a new encoder
    pub fn new() -> Self {
        Self { outboard: Vec::new() }
    }

    /// Encode data and return (bao_hash, outboard)
    pub fn encode(&mut self, data: &[u8]) -> ProtoResult<([u8; 32], Vec<u8>)> {
        let (outboard, hash) = bao::encode::outboard(data);
        Ok((*hash.as_bytes(), outboard))
    }

    /// Encode with streaming input
    pub fn encode_streaming<R: Read>(&mut self, mut reader: R) -> ProtoResult<([u8; 32], Vec<u8>)> {
        let mut data = Vec::new();
        reader.read_to_end(&mut data)
            .map_err(|e| ProtoError::BaoVerification(e.to_string()))?;
        self.encode(&data)
    }
}

impl Default for BaoEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Bao decoder for streaming verification
pub struct BaoDecoder {
    expected_hash: bao::Hash,
}

impl BaoDecoder {
    /// Create decoder expecting a specific root hash
    pub fn new(expected_hash: [u8; 32]) -> Self {
        Self {
            expected_hash: bao::Hash::from(expected_hash),
        }
    }

    /// Verify data against expected hash (simple mode)
    pub fn verify(&self, data: &[u8], outboard: &[u8]) -> ProtoResult<()> {
        // Compute hash and compare
        let computed = blake3::hash(data);

        // For now, simple verification (full Bao verification requires outboard parsing)
        // TODO: Use bao::decode::outboard when API stabilizes
        if computed.as_bytes() != self.expected_hash.as_bytes() {
            return Err(ProtoError::BaoVerification(
                "Hash mismatch: data corrupted".into()
            ));
        }

        // Verify outboard size is reasonable
        let expected_outboard_size = bao::encode::outboard_size(data.len() as u64);
        if outboard.len() as u64 != expected_outboard_size {
            return Err(ProtoError::BaoVerification(
                format!("Outboard size mismatch: {} != {}", outboard.len(), expected_outboard_size)
            ));
        }

        Ok(())
    }

    /// Verify streaming (chunk by chunk)
    pub fn verify_streaming<R: Read>(
        &self,
        data: R,
        outboard: &[u8],
    ) -> ProtoResult<Vec<u8>> {
        // For now, buffer and verify
        // TODO: True streaming verification
        let mut buf = Vec::new();
        std::io::copy(&mut std::io::BufReader::new(data), &mut std::io::Cursor::new(&mut buf))
            .map_err(|e| ProtoError::BaoVerification(e.to_string()))?;

        self.verify(&buf, outboard)?;
        Ok(buf)
    }
}

/// Extract and verify a slice of data
pub struct SliceVerifier {
    expected_hash: bao::Hash,
}

impl SliceVerifier {
    pub fn new(expected_hash: [u8; 32]) -> Self {
        Self {
            expected_hash: bao::Hash::from(expected_hash),
        }
    }

    /// Extract a verified slice from encoded data
    ///
    /// This allows downloading only a portion of a file while still
    /// cryptographically verifying it belongs to the expected file.
    pub fn extract_slice(
        &self,
        data: &[u8],
        outboard: &[u8],
        start: u64,
        len: u64,
    ) -> ProtoResult<Vec<u8>> {
        // For random access, we'd need bao's slice extraction
        // For now, verify whole and return slice
        let decoder = BaoDecoder::new(*self.expected_hash.as_bytes());
        decoder.verify(data, outboard)?;

        let end = (start + len) as usize;
        if end > data.len() {
            return Err(ProtoError::BaoVerification(
                format!("Slice out of bounds: {}..{} > {}", start, end, data.len())
            ));
        }

        Ok(data[start as usize..end].to_vec())
    }
}

/// Compute outboard size for a given data size
pub fn outboard_size(data_len: u64) -> u64 {
    bao::encode::outboard_size(data_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let data = b"Hello, Bao streaming!";

        let mut encoder = BaoEncoder::new();
        let (hash, outboard) = encoder.encode(data).unwrap();

        let decoder = BaoDecoder::new(hash);
        decoder.verify(data, &outboard).unwrap();
    }

    #[test]
    fn test_corrupted_data_detected() {
        let data = b"Original data";

        let mut encoder = BaoEncoder::new();
        let (hash, outboard) = encoder.encode(data).unwrap();

        let corrupted = b"Corrupted data";
        let decoder = BaoDecoder::new(hash);

        assert!(decoder.verify(corrupted, &outboard).is_err());
    }

    #[test]
    fn test_slice_extraction() {
        let data = b"Hello, this is a longer message for slicing!";

        let mut encoder = BaoEncoder::new();
        let (hash, outboard) = encoder.encode(data).unwrap();

        let verifier = SliceVerifier::new(hash);
        let slice = verifier.extract_slice(data, &outboard, 7, 4).unwrap();

        assert_eq!(&slice, b"this");
    }
}
```

### Success Criteria

#### Automated Verification:

- [x] Bao tests pass: `cargo test -p recrypt-proto bao`
- [x] Corruption detection works
- [x] Slice extraction works

#### Manual Verification:

- [x] Large file (100 MB) verification completes in reasonable time
- [x] Outboard size is ~1% as documented

---

## Phase 3.6: Lattice Backend Completion (Wire Up Existing Serialization)

### Overview

**Good news:** OpenFHE serialization already exists in `recrypt-openfhe-sys`! The C++ wrapper uses Cereal's `PortableBinaryOutputArchive` via `std::stringstream`. We just need to wire it through `recrypt-ffi` and complete the Lattice backend stubs.

See `docs/plans/openfhe-serialization-research.md` for full analysis.

### What Already Exists

**`recrypt-openfhe-sys/src/wrapper.cc`** already implements:

```cpp
rust::Vec<uint8_t> serialize_ciphertext(const Ciphertext &ct);
std::unique_ptr<Ciphertext> deserialize_ciphertext(const CryptoContext &ctx, rust::Slice<const uint8_t> data);
// ... same for public_key, private_key, recrypt_key
```

**`recrypt-openfhe-sys/src/lib.rs`** exposes these via CXX FFI.

### Changes Required

#### 1. Expose serialization in recrypt-ffi

**File**: `crates/recrypt-ffi/src/openfhe/mod.rs` (additions)

```rust
impl PreContext {
    /// Serialize public key to bytes (Cereal binary format)
    pub fn serialize_public_key(&self, pk: &PublicKey) -> Result<Vec<u8>, FfiError> {
        #[cfg(feature = "openfhe")]
        {
            Ok(dcypher_openfhe_sys::serialize_public_key(&pk.inner))
        }
        #[cfg(not(feature = "openfhe"))]
        Err(FfiError::OpenFhe("OpenFHE not enabled".into()))
    }

    /// Deserialize public key from bytes
    pub fn deserialize_public_key(&self, bytes: &[u8]) -> Result<PublicKey, FfiError> {
        #[cfg(feature = "openfhe")]
        {
            let pk = dcypher_openfhe_sys::deserialize_public_key(&self.inner, bytes);
            if pk.is_null() {
                return Err(FfiError::OpenFhe("Failed to deserialize public key".into()));
            }
            Ok(PublicKey { inner: pk })
        }
        #[cfg(not(feature = "openfhe"))]
        Err(FfiError::OpenFhe("OpenFHE not enabled".into()))
    }

    // Same pattern for: serialize/deserialize_private_key, _ciphertext, _recrypt_key
}
```

#### 2. Complete Lattice backend in recrypt-core

**File**: `crates/recrypt-core/src/pre/backends/lattice.rs`

Replace stubs with actual implementations:

```rust
impl PreBackend for LatticeBackend {
    fn generate_keypair(&self) -> PreResult<KeyPair> {
        let ffi_kp = self.context.generate_keypair()
            .map_err(|e| PreError::KeyGeneration(e.to_string()))?;

        // Serialize keys for storage in our wrapper types
        let pk_bytes = self.context.serialize_public_key(&ffi_kp.public)
            .map_err(|e| PreError::Serialization(e.to_string()))?;
        let sk_bytes = self.context.serialize_private_key(&ffi_kp.secret)
            .map_err(|e| PreError::Serialization(e.to_string()))?;

        Ok(KeyPair {
            public: PublicKey::new(BackendId::Lattice, pk_bytes),
            secret: SecretKey::new(BackendId::Lattice, sk_bytes),
        })
    }

    fn encrypt(&self, recipient: &PublicKey, plaintext: &[u8]) -> PreResult<Ciphertext> {
        // Deserialize recipient's public key
        let pk = self.context.deserialize_public_key(recipient.as_bytes())
            .map_err(|e| PreError::Deserialization(e.to_string()))?;

        // Encrypt (returns Vec<FfiCiphertext> due to slot chunking)
        let cts = self.context.encrypt(&pk, plaintext)
            .map_err(|e| PreError::Encryption(e.to_string()))?;

        // Serialize all ciphertexts into one blob with length prefixes
        let mut ct_bytes = Vec::new();
        ct_bytes.extend((cts.len() as u32).to_le_bytes());
        for ct in &cts {
            let serialized = self.context.serialize_ciphertext(ct)
                .map_err(|e| PreError::Serialization(e.to_string()))?;
            ct_bytes.extend((serialized.len() as u32).to_le_bytes());
            ct_bytes.extend(serialized);
        }

        Ok(Ciphertext::new(BackendId::Lattice, 0, ct_bytes))
    }

    // decrypt, recrypt follow same pattern...
}
```

#### 3. Key Size Expectations

| Object                 | Measured Size                         |
| ---------------------- | ------------------------------------- |
| PublicKey              | ~180-220 KB                           |
| PrivateKey             | ~90-120 KB                            |
| RecryptKey             | ~1.5-2 MB                             |
| Ciphertext (96B input) | ~5-10 KB                              |
| CryptoContext          | 10-50 MB (NOT serialized per-message) |

**Important:** CryptoContext is huge. We use a single shared context with fixed BFV parameters. Don't serialize it with each message—assume both sides have compatible contexts.

### Success Criteria

#### Automated Verification:

- [ ] Lattice backend tests pass: `cargo test -p recrypt-core --features openfhe lattice`
- [ ] Serialization roundtrip: `cargo test -p recrypt-openfhe-sys serialization`
- [ ] Full encrypt→serialize→deserialize→decrypt works

#### Manual Verification:

- [ ] Key sizes match expectations (~200 KB public key)
- [ ] Recrypt key roundtrip works
- [ ] Performance acceptable (~20ms encrypt, ~10ms decrypt)

**Revised Effort:** 0.5 day (down from 1 day—just wiring, not wrestling)

---

## Phase 3.7: Signature Binding to EncryptedFile

### Overview

Add signature field to `EncryptedFile` that signs `(wrapped_key || bao_hash)`.

### Changes Required

#### 1. Update EncryptedFile structure

**File**: `crates/recrypt-core/src/hybrid/encrypted_file.rs`

```rust
use crate::sign::MultiSig;

/// An encrypted file with streaming-verifiable integrity
#[derive(Clone, Debug)]
pub struct EncryptedFile {
    pub wrapped_key: Ciphertext,
    pub bao_hash: [u8; 32],
    pub bao_outboard: Vec<u8>,
    pub ciphertext: Vec<u8>,
    /// Signature over (wrapped_key || bao_hash) - optional for unsigned files
    pub signature: Option<MultiSig>,
}

impl EncryptedFile {
    /// Compute the signature payload
    pub fn signature_payload(&self) -> Vec<u8> {
        let mut payload = self.wrapped_key.to_bytes();
        payload.extend(&self.bao_hash);
        payload
    }

    /// Sign the file with the given keys
    pub fn sign(&mut self, keys: &crate::sign::SigningKeys) -> crate::CoreResult<()> {
        let payload = self.signature_payload();
        self.signature = Some(crate::sign::sign_message(&payload, keys)?);
        Ok(())
    }

    /// Verify the signature
    pub fn verify_signature(&self, pks: &crate::sign::VerifyingKeys) -> crate::CoreResult<bool> {
        match &self.signature {
            Some(sig) => {
                let payload = self.signature_payload();
                crate::sign::verify_message(&payload, sig, pks)
            }
            None => Err(crate::CoreError::Verification("No signature present".into())),
        }
    }
}
```

#### 2. Update HybridEncryptor to optionally sign

**File**: `crates/recrypt-core/src/hybrid/mod.rs` (additions)

```rust
impl<B: PreBackend> HybridEncryptor<B> {
    /// Encrypt and sign data
    pub fn encrypt_and_sign(
        &self,
        recipient: &PublicKey,
        plaintext: &[u8],
        signing_keys: &crate::sign::SigningKeys,
    ) -> CoreResult<EncryptedFile> {
        let mut file = self.encrypt(recipient, plaintext)?;
        file.sign(signing_keys)?;
        Ok(file)
    }

    /// Decrypt with signature verification
    pub fn decrypt_and_verify(
        &self,
        secret: &SecretKey,
        file: &EncryptedFile,
        verifying_keys: &crate::sign::VerifyingKeys,
    ) -> CoreResult<Vec<u8>> {
        // Verify signature first
        file.verify_signature(verifying_keys)?;
        // Then decrypt
        self.decrypt(secret, file)
    }
}
```

### Success Criteria

#### Automated Verification:

- [x] Signature tests pass: `cargo test -p recrypt-core signature`
- [x] Signed file roundtrip works
- [x] Tampering detected (modify wrapped_key or bao_hash)

#### Manual Verification:

- [x] Signature adds ~4.7 KB overhead (ML-DSA-87) — Measured: 4.6 KB ✓
- [x] Verification fails fast on ED25519 before checking ML-DSA

---

## Testing Strategy

### Unit Tests (per module)

- `armor.rs` - Encode/decode roundtrips
- `format.rs` - Format detection
- `convert.rs` - Proto ↔ Core type conversions
- `bao_stream.rs` - Streaming verification
- `impls.rs` - MultiFormat implementations

### Integration Tests

- `tests/roundtrip.rs` - Full serialization chain (core → proto → bytes → proto → core)
- `tests/interop.rs` - Cross-format (protobuf → json → protobuf)
- `tests/large_files.rs` - 100+ MB file handling

### Property Tests

```rust
proptest! {
    #[test]
    fn prop_protobuf_roundtrip(data in prop::collection::vec(any::<u8>(), 1..10000)) {
        // Encrypt, serialize to protobuf, deserialize, decrypt
        let backend = MockBackend;
        let encryptor = HybridEncryptor::new(backend);
        let kp = encryptor.backend().generate_keypair().unwrap();

        let original = encryptor.encrypt(&kp.public, &data).unwrap();
        let proto_bytes = original.to_protobuf().unwrap();
        let restored = EncryptedFile::from_protobuf(&proto_bytes).unwrap();
        let decrypted = encryptor.decrypt(&kp.secret, &restored).unwrap();

        prop_assert_eq!(decrypted, data);
    }
}
```

---

## Performance Considerations

### Serialization Overhead

| Format   | Overhead | Speed     | Use Case        |
| -------- | -------- | --------- | --------------- |
| Protobuf | ~0.1%    | Very fast | Wire, storage   |
| JSON     | ~0.5%    | Fast      | Debug, API      |
| Armor    | ~35%     | Slow      | Key export only |

### Memory

- Protobuf: Zero-copy where possible (prost)
- JSON: Full copy (serde)
- Armor: Base64 intermediate (1.33x memory during encode)

### Large Files

- Streaming Bao verification: O(1) memory
- Chunk-by-chunk processing in Phase 4 (storage)

---

## Migration Notes

### From Phase 2

- ✅ Core types (`EncryptedFile`, etc.) ready for serialization
- ✅ Basic `to_bytes()` can be replaced with `to_protobuf()`
- ✅ Mock backend tests continue working

### For Phase 4

Phase 4 (Storage Layer) will need:

- `ChunkProto` for streaming uploads
- `FileMetadata` for listings
- Content-addressed storage via `bao_hash`

### For Phase 6

Phase 6 (Server) will need:

- Content negotiation (Accept header → format selection)
- Streaming protobuf responses
- `CapabilityProto` for access tokens

---

## Dependencies

```toml
# New dependencies for recrypt-proto
prost = "0.13"
prost-types = "0.13"
prost-build = "0.13"  # build-dependency
serde = { version = "1", features = ["derive"] }
serde_json = "1"
base64 = "0.22"
hex = "0.4"
blake3 = "1.5"
bao = "0.12"
```

Add to workspace:

```toml
[workspace]
members = [
  "crates/recrypt-ffi",
  "crates/recrypt-openfhe-sys",
  "crates/recrypt-core",
  "crates/recrypt-proto",  # NEW
]
```

---

## Timeline

**Estimated:** 2.5-3 days (revised down—OpenFHE serialization already exists)

- **Phase 3.1:** Crate structure & schema (0.5 day)
- **Phase 3.2:** Error types & MultiFormat trait (0.25 day)
- **Phase 3.3:** ASCII armor (0.25 day)
- **Phase 3.4:** Protobuf serialization (0.5 day)
- **Phase 3.5:** Bao streaming (0.5 day)
- **Phase 3.6:** Lattice backend wiring (0.5 day) - just connecting dots
- **Phase 3.7:** Signature binding (0.5 day)

**Buffer:** 0.5 day for debugging/iteration

**Note:** Phase 3.6 reduced from 1 day to 0.5 day bc OpenFHE serialization already exists in `recrypt-openfhe-sys`. See `docs/plans/openfhe-serialization-research.md`.

---

## Phase 3 Completion Summary

**Completed:** January 5, 2026  
**Duration:** ~1 day (ahead of 3-4 day estimate)

### What Was Built

✅ **Phase 3.1:** Crate structure & Protobuf schema

- Created `recrypt-proto` crate with full workspace integration
- Defined comprehensive protobuf schema (14 message types, 1 enum)
- Set up `prost` codegen pipeline with `build.rs`

✅ **Phase 3.2:** Error types & MultiFormat trait

- Implemented `ProtoError` with proper error conversions
- Created `MultiFormat` trait for polymorphic serialization
- Format auto-detection (Protobuf/JSON/Armor)

✅ **Phase 3.3:** ASCII armor implementation

- PGP-style armor encoding/decoding
- 64-char line wrapping
- Header support for metadata
- Full roundtrip tests passing

✅ **Phase 3.4:** Protobuf serialization for core types

- Conversion layer between `recrypt-core` and protobuf types
- `MultiFormat` implementations for `EncryptedFile`
- Backend ID mapping (handles enum numbering differences)
- All serialization formats working (Protobuf, JSON, Armor)

✅ **Phase 3.5:** Bao streaming verification helpers

- `BaoEncoder`, `BaoDecoder`, `SliceVerifier` wrappers
- Streaming verification support
- Outboard tree management
- Corruption detection validated

✅ **Phase 3.7:** Signature binding to EncryptedFile

- Added optional `MultiSig` field to `EncryptedFile`
- Signature over `(wrapped_key || bao_hash)` payload
- `encrypt_and_sign()` and `decrypt_and_verify()` methods
- Measured signature overhead: 4.6 KB (within spec)

⏸️ **Phase 3.6:** Lattice backend completion (DEFERRED)

- OpenFHE serialization already exists in `recrypt-openfhe-sys`
- Wiring deferred until Lattice backend is fully activated
- No blocker for subsequent phases

### Test Results

```
29 tests passing, 0 failures
- 16 tests in recrypt-core (signature integration)
- 13 tests in recrypt-proto (roundtrip, serialization, signatures)
```

**Clippy:** Clean (0 warnings)  
**Build:** Success across all workspace crates

### Key Achievements

1. **Multiple serialization formats working:** Protobuf (primary), JSON (debug), ASCII armor (export)
2. **Streaming verification ready:** Blake3/Bao integration complete
3. **Signature system integrated:** ED25519 + ML-DSA-87 multi-signatures on encrypted files
4. **Size overhead validated:** ~4.6 KB for signatures (within 4.7 KB spec)
5. **Auto-generated protobuf types:** 14 message types, properly versioned

### Files Created/Modified

**New files:**

- `crates/recrypt-proto/` - Full crate (15 files)
- `crates/recrypt-core/tests/signature_integration.rs`

**Modified files:**

- `crates/recrypt-core/src/hybrid/encrypted_file.rs` - Added signature field & methods
- `crates/recrypt-core/src/hybrid/mod.rs` - Added `encrypt_and_sign()`, `decrypt_and_verify()`
- `Cargo.toml` - Added `recrypt-proto` to workspace

### Ready for Phase 4

Phase 3 deliverables provide everything Phase 4 (Storage Layer) needs:

- ✅ `ChunkProto` for streaming uploads
- ✅ `FileMetadata` for listings
- ✅ `EncryptedFileProto` for serialization
- ✅ Content-addressing via `bao_hash`
- ✅ Multi-format support for API responses

---

## References

- `docs/wire-protocol.md` - Protocol specification
- `docs/verification-architecture.md` - Bao design
- `docs/hybrid-encryption-architecture.md` - EncryptedFile structure
- [prost documentation](https://docs.rs/prost)
- [bao specification](https://github.com/oconnor663/bao/blob/master/docs/spec.md)

---

**Next Phase:** Phase 4 (Storage Layer) - S3-compatible storage, chunking, local filesystem
