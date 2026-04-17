> **Historical:** Phase 4b planning. Protobuf references superseded by Gordian Envelope.

# Phase 4b: Storage Auth Service Implementation Plan

**Status:** ✅ **COMPLETE** (2026-01-06)  
**Duration:** 1 day (planned 3-4 days)  
**Goal:** Core auth logic for content-addressed storage — ownership, capabilities, provider index

**Prerequisites:** Phase 4 (recrypt-storage) ✅ Complete

---

## Overview

Build `identikey-storage-auth` crate: core authorization logic for content-addressed storage. **No HTTP API** — that comes in Phase 6. This phase focuses on:

1. **Ownership tracking** — Who owns which file hashes
2. **Capability issuance** — Signed, time-limited access tokens
3. **Provider index** — Where files are stored (hosting agility)

The crate provides traits with pluggable backends (in-memory for tests, SQLite for single-node, Postgres-ready design for future scale).

---

## Current State Analysis

### What Exists

- **recrypt-storage**: `ChunkStorage` trait with working backends
- **recrypt-proto**: `CapabilityProto` already defined with all fields
- **recrypt-core**: Multi-signature (`sign_message`, `verify_message`)
- **Pattern**: Proto ↔ domain type conversions in `recrypt-proto/src/convert.rs`

### What's Missing

- `identikey-storage-auth` crate
- `OwnershipStore` trait + implementations
- `ProviderIndex` trait + implementations
- `Capability` domain type with verification
- SQLite persistence layer

### Key Design Decisions

| Decision           | Choice                 | Rationale                                                  |
| ------------------ | ---------------------- | ---------------------------------------------------------- |
| Fingerprint format | Blake3 hash (32 bytes) | Simple, collision-resistant, no fancy error correction     |
| Capability scope   | File-level             | Chunk-level is unnecessary complexity                      |
| Persistence        | In-memory + SQLite     | SQLite for single-node; trait design allows Postgres later |
| HTTP API           | Deferred to Phase 6    | Separation of concerns                                     |

---

## Desired End State

After Phase 4b:

1. ✅ `OwnershipStore` trait with `InMemoryOwnershipStore` and `SqliteOwnershipStore`
2. ✅ `ProviderIndex` trait with `InMemoryProviderIndex` and `SqliteProviderIndex`
3. ✅ `Capability` domain type with signing and verification
4. ✅ `AccessGrant` for tracking delegated access
5. ✅ Integration tests with `recrypt-storage`
6. ✅ SQLite schema and migrations

**Verification:**

```bash
cargo test -p identikey-storage-auth                    # In-memory tests
cargo test -p identikey-storage-auth --features sqlite  # SQLite tests
```

---

## What We're NOT Doing

- ❌ HTTP API endpoints (Phase 6)
- ❌ Postgres backend (future enhancement)
- ❌ Rate limiting (Phase 5)
- ❌ Distributed consensus (future enhancement)

---

## Architecture

```
identikey-storage-auth/
├── Cargo.toml
├── src/
│   ├── lib.rs              # Re-exports
│   ├── error.rs            # AuthError
│   ├── fingerprint.rs      # PublicKeyFingerprint (Blake3 hash)
│   ├── capability.rs       # Capability domain type + verification
│   ├── ownership.rs        # OwnershipStore trait
│   ├── provider.rs         # ProviderIndex trait
│   ├── grant.rs            # AccessGrant type
│   ├── memory/             # In-memory implementations
│   │   ├── mod.rs
│   │   ├── ownership.rs
│   │   └── provider.rs
│   └── sqlite/             # SQLite implementations (feature-gated)
│       ├── mod.rs
│       ├── schema.rs
│       ├── ownership.rs
│       └── provider.rs
└── tests/
    ├── ownership_tests.rs
    ├── capability_tests.rs
    └── integration_tests.rs
```

---

## Phase 4b.1: Crate Scaffolding

### Overview

Create `identikey-storage-auth` crate with trait definitions and error types.

### Changes Required

#### 1. Workspace Cargo.toml

**File**: `Cargo.toml`

Add to workspace members and dependencies:

```toml
[workspace]
members = [
  "crates/recrypt-ffi",
  "crates/recrypt-openfhe-sys",
  "crates/recrypt-core",
  "crates/recrypt-proto",
  "crates/recrypt-storage",
  "crates/identikey-storage-auth",  # NEW
]

[workspace.dependencies]
# ... existing deps ...

# Auth service (Phase 4b)
rusqlite = { version = "0.32", features = ["bundled"] }
```

#### 2. Crate Cargo.toml

**File**: `crates/identikey-storage-auth/Cargo.toml`

```toml
[package]
name = "identikey-storage-auth"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "Authorization layer for content-addressed storage"

[features]
default = []
sqlite = ["rusqlite"]

[dependencies]
# Workspace
recrypt-core.path = "../recrypt-core"
recrypt-proto.path = "../recrypt-proto"
thiserror.workspace = true
async-trait.workspace = true
tokio.workspace = true

# Hashing
blake3 = "1"

# SQLite (optional)
rusqlite = { workspace = true, optional = true }

[dev-dependencies]
tokio = { workspace = true, features = ["rt-multi-thread", "macros"] }
tempfile = "3"
```

#### 3. Error Types

**File**: `crates/identikey-storage-auth/src/error.rs`

```rust
//! Auth service error types

use thiserror::Error;

pub type AuthResult<T> = Result<T, AuthError>;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Not authorized: {0}")]
    NotAuthorized(String),

    #[error("Capability expired")]
    CapabilityExpired,

    #[error("Capability signature invalid")]
    InvalidSignature,

    #[error("Operation not permitted: {0}")]
    OperationNotPermitted(String),

    #[error("Already exists: {0}")]
    AlreadyExists(String),

    #[error("Invalid fingerprint: {0}")]
    InvalidFingerprint(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Signature error: {0}")]
    Signature(#[from] dcypher_core::error::CoreError),

    #[cfg(feature = "sqlite")]
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
}
```

#### 4. Library Root

**File**: `crates/identikey-storage-auth/src/lib.rs`

````rust
//! identikey-storage-auth: Authorization for content-addressed storage
//!
//! Provides ownership tracking, capability issuance, and provider indexing
//! for the Recrypt storage layer.
//!
//! ## Features
//!
//! | Feature  | Description                    |
//! |----------|--------------------------------|
//! | (none)   | In-memory backends only        |
//! | `sqlite` | SQLite persistence             |
//!
//! ## Example
//!
//! ```rust,ignore
//! use identikey_storage_auth::{
//!     InMemoryOwnershipStore, InMemoryProviderIndex,
//!     OwnershipStore, ProviderIndex, Capability, Operation,
//! };
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let ownership = InMemoryOwnershipStore::new();
//!     let providers = InMemoryProviderIndex::new();
//!
//!     // Register file ownership
//!     let file_hash = blake3::hash(b"encrypted content");
//!     ownership.register(&owner_fingerprint, &file_hash).await?;
//!
//!     // Issue capability
//!     let cap = Capability::new(
//!         file_hash,
//!         grantee_fingerprint,
//!         vec![Operation::Read],
//!         Some(expires_at),
//!     );
//!     let signed_cap = cap.sign(&signing_keys)?;
//!
//!     Ok(())
//! }
//! ```

mod error;
mod fingerprint;
mod capability;
mod ownership;
mod provider;
mod grant;

pub mod memory;

#[cfg(feature = "sqlite")]
pub mod sqlite;

// Re-exports
pub use error::{AuthError, AuthResult};
pub use fingerprint::PublicKeyFingerprint;
pub use capability::{Capability, Operation};
pub use ownership::OwnershipStore;
pub use provider::ProviderIndex;
pub use grant::AccessGrant;

pub use memory::{InMemoryOwnershipStore, InMemoryProviderIndex};

#[cfg(feature = "sqlite")]
pub use sqlite::{SqliteOwnershipStore, SqliteProviderIndex};
````

### Success Criteria

#### Automated Verification:

- [x] `cargo check -p identikey-storage-auth` compiles
- [x] `cargo check -p identikey-storage-auth --features sqlite` compiles
- [x] `cargo doc -p identikey-storage-auth` generates docs

---

## Phase 4b.2: Core Domain Types

### Overview

Define `PublicKeyFingerprint`, `Operation`, `Capability`, and `AccessGrant`.

### Changes Required

#### 1. PublicKeyFingerprint

**File**: `crates/identikey-storage-auth/src/fingerprint.rs`

```rust
//! Public key fingerprint type
//!
//! Uses Blake3 hash of public key bytes for compact, collision-resistant identification.

use std::fmt;

/// A fingerprint uniquely identifying a public key
///
/// Blake3 hash provides 256-bit collision resistance, Base58 encoding for readability.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKeyFingerprint([u8; 32]);

impl PublicKeyFingerprint {
    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create from a public key (Blake3 hash)
    pub fn from_public_key(pubkey_bytes: &[u8]) -> Self {
        let hash = blake3::hash(pubkey_bytes);
        Self(*hash.as_bytes())
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Encode as base58 (compact, readable)
    pub fn to_base58(&self) -> String {
        bs58::encode(&self.0).into_string()
    }

    /// Decode from base58
    pub fn from_base58(s: &str) -> Option<Self> {
        let bytes = bs58::decode(s).into_vec().ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let arr: [u8; 32] = bytes.try_into().ok()?;
        Some(Self(arr))
    }
}

impl fmt::Debug for PublicKeyFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", &self.to_base58()[..8])
    }
}

impl fmt::Display for PublicKeyFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl From<[u8; 32]> for PublicKeyFingerprint {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for PublicKeyFingerprint {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_roundtrip() {
        let bytes = [42u8; 32];
        let fp = PublicKeyFingerprint::from_bytes(bytes);

        let b58 = fp.to_base58();
        let recovered = PublicKeyFingerprint::from_base58(&b58).unwrap();

        assert_eq!(fp, recovered);
    }

    #[test]
    fn test_from_public_key() {
        let pubkey = b"test public key bytes";
        let fp = PublicKeyFingerprint::from_public_key(pubkey);

        // Same input should produce same fingerprint
        let fp2 = PublicKeyFingerprint::from_public_key(pubkey);
        assert_eq!(fp, fp2);

        // Different input should produce different fingerprint
        let fp3 = PublicKeyFingerprint::from_public_key(b"different key");
        assert_ne!(fp, fp3);
    }
}
```

#### 2. Operation Enum

**File**: `crates/identikey-storage-auth/src/capability.rs` (first part)

```rust
//! Capability: signed, time-limited access token

use crate::error::{AuthError, AuthResult};
use crate::fingerprint::PublicKeyFingerprint;
use dcypher_core::sign::{MultiSig, SigningKeys, VerifyingKeys, sign_message, verify_message};

/// Operations that can be granted via capability
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Operation {
    /// Read file content
    Read,
    /// Write/update file (re-upload)
    Write,
    /// Delete file
    Delete,
    /// Share file with others (issue sub-capabilities)
    Share,
}

impl Operation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Operation::Read => "read",
            Operation::Write => "write",
            Operation::Delete => "delete",
            Operation::Share => "share",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "read" => Some(Operation::Read),
            "write" => Some(Operation::Write),
            "delete" => Some(Operation::Delete),
            "share" => Some(Operation::Share),
            _ => None,
        }
    }
}

/// All operations for convenience
pub const ALL_OPERATIONS: &[Operation] = &[
    Operation::Read,
    Operation::Write,
    Operation::Delete,
    Operation::Share,
];
```

#### 3. Capability Type

**File**: `crates/identikey-storage-auth/src/capability.rs` (continued)

```rust
/// A capability granting access to a file
///
/// Capabilities are signed by the issuer and can be verified by anyone
/// with the issuer's public key.
#[derive(Clone, Debug)]
pub struct Capability {
    /// Format version
    pub version: u32,
    /// Content address of the file
    pub file_hash: blake3::Hash,
    /// Who this capability is granted to
    pub granted_to: PublicKeyFingerprint,
    /// Permitted operations
    pub operations: Vec<Operation>,
    /// Expiration timestamp (Unix seconds, 0 = no expiry)
    pub expires_at: u64,
    /// Who issued this capability
    pub issuer: PublicKeyFingerprint,
    /// Signature over capability fields (None if unsigned)
    pub signature: Option<MultiSig>,
}

impl Capability {
    /// Current capability format version
    pub const VERSION: u32 = 1;

    /// Create a new unsigned capability
    pub fn new(
        file_hash: blake3::Hash,
        granted_to: PublicKeyFingerprint,
        operations: Vec<Operation>,
        expires_at: Option<u64>,
        issuer: PublicKeyFingerprint,
    ) -> Self {
        Self {
            version: Self::VERSION,
            file_hash,
            granted_to,
            operations,
            expires_at: expires_at.unwrap_or(0),
            issuer,
            signature: None,
        }
    }

    /// Compute the bytes to be signed
    fn signature_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();

        // Version (4 bytes)
        payload.extend(self.version.to_le_bytes());

        // File hash (32 bytes)
        payload.extend(self.file_hash.as_bytes());

        // Granted to (32 bytes)
        payload.extend(self.granted_to.as_bytes());

        // Operations (variable, but deterministic)
        let mut ops: Vec<_> = self.operations.iter().map(|o| o.as_str()).collect();
        ops.sort(); // Canonical order
        for op in ops {
            payload.extend(op.as_bytes());
            payload.push(0); // Separator
        }

        // Expires at (8 bytes)
        payload.extend(self.expires_at.to_le_bytes());

        // Issuer (32 bytes)
        payload.extend(self.issuer.as_bytes());

        payload
    }

    /// Sign the capability
    pub fn sign(&mut self, keys: &SigningKeys) -> AuthResult<()> {
        let payload = self.signature_payload();
        self.signature = Some(sign_message(&payload, keys)?);
        Ok(())
    }

    /// Create a signed capability in one step
    pub fn new_signed(
        file_hash: blake3::Hash,
        granted_to: PublicKeyFingerprint,
        operations: Vec<Operation>,
        expires_at: Option<u64>,
        issuer: PublicKeyFingerprint,
        keys: &SigningKeys,
    ) -> AuthResult<Self> {
        let mut cap = Self::new(file_hash, granted_to, operations, expires_at, issuer);
        cap.sign(keys)?;
        Ok(cap)
    }

    /// Verify the capability signature
    pub fn verify_signature(&self, issuer_keys: &VerifyingKeys) -> AuthResult<()> {
        let sig = self.signature.as_ref()
            .ok_or(AuthError::InvalidSignature)?;

        let payload = self.signature_payload();
        verify_message(&payload, sig, issuer_keys)?;
        Ok(())
    }

    /// Check if capability has expired
    pub fn is_expired(&self) -> bool {
        if self.expires_at == 0 {
            return false; // No expiry
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now > self.expires_at
    }

    /// Check if a specific operation is permitted
    pub fn permits(&self, op: Operation) -> bool {
        self.operations.contains(&op)
    }

    /// Full verification: signature + expiry + operation
    pub fn verify(
        &self,
        issuer_keys: &VerifyingKeys,
        required_op: Operation,
    ) -> AuthResult<()> {
        // Check signature
        self.verify_signature(issuer_keys)?;

        // Check expiry
        if self.is_expired() {
            return Err(AuthError::CapabilityExpired);
        }

        // Check operation
        if !self.permits(required_op) {
            return Err(AuthError::OperationNotPermitted(required_op.as_str().into()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcypher_ffi::ed25519::ed25519_keygen;
    use dcypher_ffi::liboqs::{PqAlgorithm, pq_keygen};

    fn test_keys() -> (SigningKeys, VerifyingKeys) {
        let ed_kp = ed25519_keygen();
        let pq_kp = pq_keygen(PqAlgorithm::MlDsa87).unwrap();

        let signing = SigningKeys {
            ed25519: ed_kp.signing_key,
            ml_dsa: pq_kp.secret_key.clone(),
        };

        let verifying = VerifyingKeys {
            ed25519: ed_kp.verifying_key,
            ml_dsa: pq_kp.public_key.clone(),
        };

        (signing, verifying)
    }

    #[test]
    fn test_capability_sign_verify() {
        let (signing, verifying) = test_keys();

        let file_hash = blake3::hash(b"test file");
        let grantee = PublicKeyFingerprint::from_bytes([1u8; 32]);
        let issuer = PublicKeyFingerprint::from_bytes([2u8; 32]);

        let cap = Capability::new_signed(
            file_hash,
            grantee,
            vec![Operation::Read],
            None,
            issuer,
            &signing,
        ).unwrap();

        assert!(cap.verify_signature(&verifying).is_ok());
    }

    #[test]
    fn test_capability_expiry() {
        let file_hash = blake3::hash(b"test");
        let fp = PublicKeyFingerprint::from_bytes([0u8; 32]);

        // No expiry
        let cap = Capability::new(file_hash, fp, vec![Operation::Read], None, fp);
        assert!(!cap.is_expired());

        // Expired
        let cap = Capability::new(file_hash, fp, vec![Operation::Read], Some(1), fp);
        assert!(cap.is_expired());

        // Future expiry
        let future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + 3600;
        let cap = Capability::new(file_hash, fp, vec![Operation::Read], Some(future), fp);
        assert!(!cap.is_expired());
    }

    #[test]
    fn test_capability_operations() {
        let file_hash = blake3::hash(b"test");
        let fp = PublicKeyFingerprint::from_bytes([0u8; 32]);

        let cap = Capability::new(
            file_hash, fp,
            vec![Operation::Read, Operation::Write],
            None, fp,
        );

        assert!(cap.permits(Operation::Read));
        assert!(cap.permits(Operation::Write));
        assert!(!cap.permits(Operation::Delete));
        assert!(!cap.permits(Operation::Share));
    }
}
```

#### 4. AccessGrant Type

**File**: `crates/identikey-storage-auth/src/grant.rs`

```rust
//! Access grants: records of delegated access

use crate::capability::Operation;
use crate::fingerprint::PublicKeyFingerprint;

/// A record of access granted from owner to grantee
#[derive(Clone, Debug)]
pub struct AccessGrant {
    /// File being shared
    pub file_hash: blake3::Hash,
    /// Who owns the file
    pub owner: PublicKeyFingerprint,
    /// Who has been granted access
    pub grantee: PublicKeyFingerprint,
    /// What operations are permitted
    pub operations: Vec<Operation>,
    /// When the grant expires (0 = never)
    pub expires_at: u64,
    /// When the grant was created (Unix timestamp)
    pub created_at: u64,
}

impl AccessGrant {
    pub fn new(
        file_hash: blake3::Hash,
        owner: PublicKeyFingerprint,
        grantee: PublicKeyFingerprint,
        operations: Vec<Operation>,
        expires_at: Option<u64>,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            file_hash,
            owner,
            grantee,
            operations,
            expires_at: expires_at.unwrap_or(0),
            created_at: now,
        }
    }

    /// Check if the grant has expired
    pub fn is_expired(&self) -> bool {
        if self.expires_at == 0 {
            return false;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now > self.expires_at
    }

    /// Check if a specific operation is permitted
    pub fn permits(&self, op: Operation) -> bool {
        self.operations.contains(&op)
    }
}
```

### Success Criteria

#### Automated Verification:

- [x] `cargo test -p identikey-storage-auth fingerprint` passes
- [x] `cargo test -p identikey-storage-auth capability` passes

---

## Phase 4b.3: OwnershipStore Trait + InMemory Implementation

### Overview

Define the `OwnershipStore` trait and implement `InMemoryOwnershipStore`.

### Changes Required

#### 1. OwnershipStore Trait

**File**: `crates/identikey-storage-auth/src/ownership.rs`

```rust
//! Ownership tracking: who owns which files

use async_trait::async_trait;
use blake3::Hash;

use crate::error::AuthResult;
use crate::fingerprint::PublicKeyFingerprint;
use crate::grant::AccessGrant;
use crate::capability::Operation;

/// Tracks file ownership and access grants
#[async_trait]
pub trait OwnershipStore: Send + Sync {
    /// Register a new file as owned by a public key
    ///
    /// Returns error if file is already registered to a different owner.
    async fn register(
        &self,
        owner: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<()>;

    /// Check if a public key owns a file
    async fn is_owner(
        &self,
        owner: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<bool>;

    /// List all files owned by a public key
    async fn list_owned(
        &self,
        owner: &PublicKeyFingerprint,
    ) -> AuthResult<Vec<Hash>>;

    /// Transfer ownership to another public key
    ///
    /// Only the current owner can transfer.
    async fn transfer(
        &self,
        from: &PublicKeyFingerprint,
        to: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<()>;

    /// Grant access to another public key
    async fn grant_access(
        &self,
        grant: AccessGrant,
    ) -> AuthResult<()>;

    /// Revoke access from a grantee
    async fn revoke_access(
        &self,
        owner: &PublicKeyFingerprint,
        grantee: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<()>;

    /// Check if a public key has access (owner or grantee)
    async fn has_access(
        &self,
        pubkey: &PublicKeyFingerprint,
        file_hash: &Hash,
        operation: Operation,
    ) -> AuthResult<bool>;

    /// List all grants for a file (owner only)
    async fn list_grants(
        &self,
        owner: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<Vec<AccessGrant>>;

    /// List files shared with a public key (as grantee)
    async fn list_shared_with(
        &self,
        grantee: &PublicKeyFingerprint,
    ) -> AuthResult<Vec<Hash>>;

    /// Remove file record entirely (for cleanup)
    async fn unregister(
        &self,
        owner: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<()>;
}
```

#### 2. InMemoryOwnershipStore

**File**: `crates/identikey-storage-auth/src/memory/ownership.rs`

```rust
//! In-memory ownership store

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use async_trait::async_trait;
use blake3::Hash;

use crate::error::{AuthError, AuthResult};
use crate::fingerprint::PublicKeyFingerprint;
use crate::grant::AccessGrant;
use crate::capability::Operation;
use crate::ownership::OwnershipStore;

/// In-memory ownership store for testing
#[derive(Default)]
pub struct InMemoryOwnershipStore {
    /// file_hash -> owner
    owners: RwLock<HashMap<Hash, PublicKeyFingerprint>>,
    /// (file_hash, grantee) -> AccessGrant
    grants: RwLock<HashMap<(Hash, PublicKeyFingerprint), AccessGrant>>,
}

impl InMemoryOwnershipStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of registered files
    pub fn file_count(&self) -> usize {
        self.owners.read().unwrap().len()
    }

    /// Number of active grants
    pub fn grant_count(&self) -> usize {
        self.grants.read().unwrap().len()
    }

    /// Clear all data
    pub fn clear(&self) {
        self.owners.write().unwrap().clear();
        self.grants.write().unwrap().clear();
    }
}

#[async_trait]
impl OwnershipStore for InMemoryOwnershipStore {
    async fn register(
        &self,
        owner: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<()> {
        let mut owners = self.owners.write().unwrap();

        if let Some(existing) = owners.get(file_hash) {
            if existing != owner {
                return Err(AuthError::AlreadyExists(format!(
                    "File {} already owned by different key",
                    file_hash
                )));
            }
            // Already registered to same owner — idempotent
            return Ok(());
        }

        owners.insert(*file_hash, *owner);
        Ok(())
    }

    async fn is_owner(
        &self,
        owner: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<bool> {
        let owners = self.owners.read().unwrap();
        Ok(owners.get(file_hash) == Some(owner))
    }

    async fn list_owned(
        &self,
        owner: &PublicKeyFingerprint,
    ) -> AuthResult<Vec<Hash>> {
        let owners = self.owners.read().unwrap();
        Ok(owners
            .iter()
            .filter(|(_, o)| *o == owner)
            .map(|(h, _)| *h)
            .collect())
    }

    async fn transfer(
        &self,
        from: &PublicKeyFingerprint,
        to: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<()> {
        let mut owners = self.owners.write().unwrap();

        match owners.get(file_hash) {
            Some(current) if current == from => {
                owners.insert(*file_hash, *to);
                Ok(())
            }
            Some(_) => Err(AuthError::NotAuthorized(
                "Only owner can transfer".into()
            )),
            None => Err(AuthError::FileNotFound(file_hash.to_string())),
        }
    }

    async fn grant_access(
        &self,
        grant: AccessGrant,
    ) -> AuthResult<()> {
        // Verify the granter owns the file
        let owners = self.owners.read().unwrap();
        match owners.get(&grant.file_hash) {
            Some(owner) if *owner == grant.owner => {}
            Some(_) => return Err(AuthError::NotAuthorized(
                "Only owner can grant access".into()
            )),
            None => return Err(AuthError::FileNotFound(grant.file_hash.to_string())),
        }
        drop(owners);

        let key = (grant.file_hash, grant.grantee);
        self.grants.write().unwrap().insert(key, grant);
        Ok(())
    }

    async fn revoke_access(
        &self,
        owner: &PublicKeyFingerprint,
        grantee: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<()> {
        // Verify ownership
        if !self.is_owner(owner, file_hash).await? {
            return Err(AuthError::NotAuthorized("Only owner can revoke".into()));
        }

        let key = (*file_hash, *grantee);
        self.grants.write().unwrap().remove(&key);
        Ok(())
    }

    async fn has_access(
        &self,
        pubkey: &PublicKeyFingerprint,
        file_hash: &Hash,
        operation: Operation,
    ) -> AuthResult<bool> {
        // Owner has all access
        if self.is_owner(pubkey, file_hash).await? {
            return Ok(true);
        }

        // Check grants
        let grants = self.grants.read().unwrap();
        let key = (*file_hash, *pubkey);

        match grants.get(&key) {
            Some(grant) => {
                if grant.is_expired() {
                    Ok(false)
                } else {
                    Ok(grant.permits(operation))
                }
            }
            None => Ok(false),
        }
    }

    async fn list_grants(
        &self,
        owner: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<Vec<AccessGrant>> {
        // Verify ownership
        if !self.is_owner(owner, file_hash).await? {
            return Err(AuthError::NotAuthorized("Only owner can list grants".into()));
        }

        let grants = self.grants.read().unwrap();
        Ok(grants
            .iter()
            .filter(|((h, _), _)| h == file_hash)
            .map(|(_, g)| g.clone())
            .collect())
    }

    async fn list_shared_with(
        &self,
        grantee: &PublicKeyFingerprint,
    ) -> AuthResult<Vec<Hash>> {
        let grants = self.grants.read().unwrap();
        let mut files: HashSet<Hash> = HashSet::new();

        for ((file_hash, g), grant) in grants.iter() {
            if g == grantee && !grant.is_expired() {
                files.insert(*file_hash);
            }
        }

        Ok(files.into_iter().collect())
    }

    async fn unregister(
        &self,
        owner: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<()> {
        // Verify ownership
        if !self.is_owner(owner, file_hash).await? {
            return Err(AuthError::NotAuthorized("Only owner can unregister".into()));
        }

        // Remove ownership
        self.owners.write().unwrap().remove(file_hash);

        // Remove all grants for this file
        let mut grants = self.grants.write().unwrap();
        grants.retain(|(h, _), _| h != file_hash);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(n: u8) -> PublicKeyFingerprint {
        PublicKeyFingerprint::from_bytes([n; 32])
    }

    #[tokio::test]
    async fn test_register_and_ownership() {
        let store = InMemoryOwnershipStore::new();
        let owner = fp(1);
        let file = blake3::hash(b"test");

        store.register(&owner, &file).await.unwrap();

        assert!(store.is_owner(&owner, &file).await.unwrap());
        assert!(!store.is_owner(&fp(2), &file).await.unwrap());
    }

    #[tokio::test]
    async fn test_register_idempotent() {
        let store = InMemoryOwnershipStore::new();
        let owner = fp(1);
        let file = blake3::hash(b"test");

        store.register(&owner, &file).await.unwrap();
        store.register(&owner, &file).await.unwrap(); // Should succeed
    }

    #[tokio::test]
    async fn test_register_conflict() {
        let store = InMemoryOwnershipStore::new();
        let file = blake3::hash(b"test");

        store.register(&fp(1), &file).await.unwrap();
        let result = store.register(&fp(2), &file).await;

        assert!(matches!(result, Err(AuthError::AlreadyExists(_))));
    }

    #[tokio::test]
    async fn test_grant_access() {
        let store = InMemoryOwnershipStore::new();
        let owner = fp(1);
        let grantee = fp(2);
        let file = blake3::hash(b"test");

        store.register(&owner, &file).await.unwrap();

        let grant = AccessGrant::new(
            file, owner, grantee,
            vec![Operation::Read],
            None,
        );
        store.grant_access(grant).await.unwrap();

        assert!(store.has_access(&grantee, &file, Operation::Read).await.unwrap());
        assert!(!store.has_access(&grantee, &file, Operation::Write).await.unwrap());
    }

    #[tokio::test]
    async fn test_revoke_access() {
        let store = InMemoryOwnershipStore::new();
        let owner = fp(1);
        let grantee = fp(2);
        let file = blake3::hash(b"test");

        store.register(&owner, &file).await.unwrap();

        let grant = AccessGrant::new(file, owner, grantee, vec![Operation::Read], None);
        store.grant_access(grant).await.unwrap();

        assert!(store.has_access(&grantee, &file, Operation::Read).await.unwrap());

        store.revoke_access(&owner, &grantee, &file).await.unwrap();

        assert!(!store.has_access(&grantee, &file, Operation::Read).await.unwrap());
    }

    #[tokio::test]
    async fn test_transfer_ownership() {
        let store = InMemoryOwnershipStore::new();
        let alice = fp(1);
        let bob = fp(2);
        let file = blake3::hash(b"test");

        store.register(&alice, &file).await.unwrap();
        store.transfer(&alice, &bob, &file).await.unwrap();

        assert!(!store.is_owner(&alice, &file).await.unwrap());
        assert!(store.is_owner(&bob, &file).await.unwrap());
    }

    #[tokio::test]
    async fn test_owner_has_all_access() {
        let store = InMemoryOwnershipStore::new();
        let owner = fp(1);
        let file = blake3::hash(b"test");

        store.register(&owner, &file).await.unwrap();

        for op in crate::capability::ALL_OPERATIONS {
            assert!(store.has_access(&owner, &file, *op).await.unwrap());
        }
    }
}
```

#### 3. Memory Module

**File**: `crates/identikey-storage-auth/src/memory/mod.rs`

```rust
//! In-memory implementations for testing

mod ownership;
mod provider;

pub use ownership::InMemoryOwnershipStore;
pub use provider::InMemoryProviderIndex;
```

### Success Criteria

#### Automated Verification:

- [x] `cargo test -p identikey-storage-auth ownership` passes
- [x] All ownership scenarios tested (register, transfer, grant, revoke)

---

## Phase 4b.4: ProviderIndex Trait + InMemory Implementation

### Overview

Track where files are stored (hash → provider URLs) for hosting agility.

### Changes Required

#### 1. ProviderIndex Trait

**File**: `crates/identikey-storage-auth/src/provider.rs`

```rust
//! Provider index: where files are stored

use async_trait::async_trait;
use blake3::Hash;

use crate::error::AuthResult;

/// A storage provider URL
pub type ProviderUrl = String;

/// Tracks file locations across storage providers
///
/// Enables hosting agility: files can be moved between providers
/// without breaking references.
#[async_trait]
pub trait ProviderIndex: Send + Sync {
    /// Register a file's location
    ///
    /// A file can be stored at multiple providers for redundancy.
    async fn register(
        &self,
        file_hash: &Hash,
        provider_url: &ProviderUrl,
    ) -> AuthResult<()>;

    /// Look up all locations for a file
    async fn lookup(
        &self,
        file_hash: &Hash,
    ) -> AuthResult<Vec<ProviderUrl>>;

    /// Update a file's location (migration)
    async fn update_location(
        &self,
        file_hash: &Hash,
        old_url: &ProviderUrl,
        new_url: &ProviderUrl,
    ) -> AuthResult<()>;

    /// Remove a location (file deleted from provider)
    async fn remove_location(
        &self,
        file_hash: &Hash,
        provider_url: &ProviderUrl,
    ) -> AuthResult<()>;

    /// Remove all locations for a file
    async fn unregister(
        &self,
        file_hash: &Hash,
    ) -> AuthResult<()>;

    /// Check if a file has any registered locations
    async fn exists(
        &self,
        file_hash: &Hash,
    ) -> AuthResult<bool>;

    /// List all files at a provider (for provider management)
    async fn list_at_provider(
        &self,
        provider_url: &ProviderUrl,
    ) -> AuthResult<Vec<Hash>>;
}
```

#### 2. InMemoryProviderIndex

**File**: `crates/identikey-storage-auth/src/memory/provider.rs`

```rust
//! In-memory provider index

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use async_trait::async_trait;
use blake3::Hash;

use crate::error::{AuthError, AuthResult};
use crate::provider::{ProviderIndex, ProviderUrl};

/// In-memory provider index for testing
#[derive(Default)]
pub struct InMemoryProviderIndex {
    /// file_hash -> set of provider URLs
    locations: RwLock<HashMap<Hash, HashSet<ProviderUrl>>>,
}

impl InMemoryProviderIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of tracked files
    pub fn file_count(&self) -> usize {
        self.locations.read().unwrap().len()
    }

    /// Clear all data
    pub fn clear(&self) {
        self.locations.write().unwrap().clear();
    }
}

#[async_trait]
impl ProviderIndex for InMemoryProviderIndex {
    async fn register(
        &self,
        file_hash: &Hash,
        provider_url: &ProviderUrl,
    ) -> AuthResult<()> {
        let mut locations = self.locations.write().unwrap();
        locations
            .entry(*file_hash)
            .or_default()
            .insert(provider_url.clone());
        Ok(())
    }

    async fn lookup(
        &self,
        file_hash: &Hash,
    ) -> AuthResult<Vec<ProviderUrl>> {
        let locations = self.locations.read().unwrap();
        match locations.get(file_hash) {
            Some(urls) => Ok(urls.iter().cloned().collect()),
            None => Ok(vec![]),
        }
    }

    async fn update_location(
        &self,
        file_hash: &Hash,
        old_url: &ProviderUrl,
        new_url: &ProviderUrl,
    ) -> AuthResult<()> {
        let mut locations = self.locations.write().unwrap();

        if let Some(urls) = locations.get_mut(file_hash) {
            urls.remove(old_url);
            urls.insert(new_url.clone());
            Ok(())
        } else {
            Err(AuthError::FileNotFound(file_hash.to_string()))
        }
    }

    async fn remove_location(
        &self,
        file_hash: &Hash,
        provider_url: &ProviderUrl,
    ) -> AuthResult<()> {
        let mut locations = self.locations.write().unwrap();

        if let Some(urls) = locations.get_mut(file_hash) {
            urls.remove(provider_url);
            if urls.is_empty() {
                locations.remove(file_hash);
            }
        }
        Ok(())
    }

    async fn unregister(
        &self,
        file_hash: &Hash,
    ) -> AuthResult<()> {
        self.locations.write().unwrap().remove(file_hash);
        Ok(())
    }

    async fn exists(
        &self,
        file_hash: &Hash,
    ) -> AuthResult<bool> {
        let locations = self.locations.read().unwrap();
        Ok(locations.get(file_hash).map(|s| !s.is_empty()).unwrap_or(false))
    }

    async fn list_at_provider(
        &self,
        provider_url: &ProviderUrl,
    ) -> AuthResult<Vec<Hash>> {
        let locations = self.locations.read().unwrap();
        Ok(locations
            .iter()
            .filter(|(_, urls)| urls.contains(provider_url))
            .map(|(h, _)| *h)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_register_and_lookup() {
        let index = InMemoryProviderIndex::new();
        let file = blake3::hash(b"test");
        let url = "https://s3.example.com/bucket/file".to_string();

        index.register(&file, &url).await.unwrap();

        let locations = index.lookup(&file).await.unwrap();
        assert_eq!(locations, vec![url]);
    }

    #[tokio::test]
    async fn test_multiple_providers() {
        let index = InMemoryProviderIndex::new();
        let file = blake3::hash(b"test");

        let url1 = "https://provider1.com/file".to_string();
        let url2 = "https://provider2.com/file".to_string();

        index.register(&file, &url1).await.unwrap();
        index.register(&file, &url2).await.unwrap();

        let locations = index.lookup(&file).await.unwrap();
        assert_eq!(locations.len(), 2);
        assert!(locations.contains(&url1));
        assert!(locations.contains(&url2));
    }

    #[tokio::test]
    async fn test_update_location() {
        let index = InMemoryProviderIndex::new();
        let file = blake3::hash(b"test");

        let old_url = "https://old.com/file".to_string();
        let new_url = "https://new.com/file".to_string();

        index.register(&file, &old_url).await.unwrap();
        index.update_location(&file, &old_url, &new_url).await.unwrap();

        let locations = index.lookup(&file).await.unwrap();
        assert_eq!(locations, vec![new_url]);
    }

    #[tokio::test]
    async fn test_exists() {
        let index = InMemoryProviderIndex::new();
        let file = blake3::hash(b"test");

        assert!(!index.exists(&file).await.unwrap());

        index.register(&file, &"https://example.com".to_string()).await.unwrap();
        assert!(index.exists(&file).await.unwrap());
    }

    #[tokio::test]
    async fn test_list_at_provider() {
        let index = InMemoryProviderIndex::new();
        let provider = "https://s3.example.com".to_string();

        let file1 = blake3::hash(b"file1");
        let file2 = blake3::hash(b"file2");
        let file3 = blake3::hash(b"file3");

        index.register(&file1, &provider).await.unwrap();
        index.register(&file2, &provider).await.unwrap();
        index.register(&file3, &"https://other.com".to_string()).await.unwrap();

        let files = index.list_at_provider(&provider).await.unwrap();
        assert_eq!(files.len(), 2);
        assert!(files.contains(&file1));
        assert!(files.contains(&file2));
    }
}
```

### Success Criteria

#### Automated Verification:

- [x] `cargo test -p identikey-storage-auth provider` passes

---

## Phase 4b.5: SQLite Backend

### Overview

Add SQLite persistence for single-node production use. Feature-gated.

### Changes Required

#### 1. SQLite Module Structure

**File**: `crates/identikey-storage-auth/src/sqlite/mod.rs`

```rust
//! SQLite persistence backends

mod schema;
mod ownership;
mod provider;

pub use ownership::SqliteOwnershipStore;
pub use provider::SqliteProviderIndex;
pub use schema::{init_schema, SCHEMA_VERSION};
```

#### 2. Schema

**File**: `crates/identikey-storage-auth/src/sqlite/schema.rs`

```rust
//! SQLite schema definitions

use rusqlite::Connection;
use crate::error::AuthResult;

pub const SCHEMA_VERSION: u32 = 1;

/// Initialize the database schema
pub fn init_schema(conn: &Connection) -> AuthResult<()> {
    conn.execute_batch(r#"
        -- Schema version tracking
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY
        );

        -- File ownership
        CREATE TABLE IF NOT EXISTS ownership (
            file_hash BLOB PRIMARY KEY,           -- 32 bytes Blake3
            owner_fingerprint BLOB NOT NULL,       -- 32 bytes
            created_at INTEGER NOT NULL            -- Unix timestamp
        );

        CREATE INDEX IF NOT EXISTS idx_ownership_owner
            ON ownership(owner_fingerprint);

        -- Access grants
        CREATE TABLE IF NOT EXISTS access_grants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_hash BLOB NOT NULL,
            owner_fingerprint BLOB NOT NULL,
            grantee_fingerprint BLOB NOT NULL,
            operations TEXT NOT NULL,              -- JSON array: ["read", "write"]
            expires_at INTEGER NOT NULL,           -- 0 = no expiry
            created_at INTEGER NOT NULL,
            UNIQUE(file_hash, grantee_fingerprint)
        );

        CREATE INDEX IF NOT EXISTS idx_grants_file
            ON access_grants(file_hash);
        CREATE INDEX IF NOT EXISTS idx_grants_grantee
            ON access_grants(grantee_fingerprint);

        -- Provider index
        CREATE TABLE IF NOT EXISTS provider_locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_hash BLOB NOT NULL,
            provider_url TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            UNIQUE(file_hash, provider_url)
        );

        CREATE INDEX IF NOT EXISTS idx_locations_file
            ON provider_locations(file_hash);
        CREATE INDEX IF NOT EXISTS idx_locations_provider
            ON provider_locations(provider_url);
    "#)?;

    // Set schema version
    conn.execute(
        "INSERT OR REPLACE INTO schema_version (version) VALUES (?)",
        [SCHEMA_VERSION],
    )?;

    Ok(())
}

/// Check schema version
pub fn check_version(conn: &Connection) -> AuthResult<u32> {
    let version: u32 = conn.query_row(
        "SELECT version FROM schema_version LIMIT 1",
        [],
        |row| row.get(0),
    ).unwrap_or(0);
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_schema() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();

        let version = check_version(&conn).unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }
}
```

#### 3. SqliteOwnershipStore

**File**: `crates/identikey-storage-auth/src/sqlite/ownership.rs`

```rust
//! SQLite ownership store

use std::sync::Mutex;

use async_trait::async_trait;
use blake3::Hash;
use rusqlite::Connection;

use crate::error::{AuthError, AuthResult};
use crate::fingerprint::PublicKeyFingerprint;
use crate::grant::AccessGrant;
use crate::capability::Operation;
use crate::ownership::OwnershipStore;
use super::schema::init_schema;

/// SQLite-backed ownership store
pub struct SqliteOwnershipStore {
    conn: Mutex<Connection>,
}

impl SqliteOwnershipStore {
    /// Open or create a database at the given path
    pub fn open(path: &str) -> AuthResult<Self> {
        let conn = Connection::open(path)?;
        init_schema(&conn)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Create an in-memory database (for testing)
    pub fn in_memory() -> AuthResult<Self> {
        let conn = Connection::open_in_memory()?;
        init_schema(&conn)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }
}

#[async_trait]
impl OwnershipStore for SqliteOwnershipStore {
    async fn register(
        &self,
        owner: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<()> {
        let conn = self.conn.lock().unwrap();

        // Check for existing different owner
        let existing: Option<Vec<u8>> = conn.query_row(
            "SELECT owner_fingerprint FROM ownership WHERE file_hash = ?",
            [file_hash.as_bytes().as_slice()],
            |row| row.get(0),
        ).ok();

        if let Some(existing_owner) = existing {
            if existing_owner != owner.as_bytes().as_slice() {
                return Err(AuthError::AlreadyExists(format!(
                    "File {} already owned by different key",
                    file_hash
                )));
            }
            return Ok(()); // Idempotent
        }

        conn.execute(
            "INSERT INTO ownership (file_hash, owner_fingerprint, created_at) VALUES (?, ?, ?)",
            (file_hash.as_bytes().as_slice(), owner.as_bytes().as_slice(), Self::now()),
        )?;

        Ok(())
    }

    async fn is_owner(
        &self,
        owner: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<bool> {
        let conn = self.conn.lock().unwrap();

        let result: Option<Vec<u8>> = conn.query_row(
            "SELECT owner_fingerprint FROM ownership WHERE file_hash = ?",
            [file_hash.as_bytes().as_slice()],
            |row| row.get(0),
        ).ok();

        Ok(result.map(|v| v == owner.as_bytes().as_slice()).unwrap_or(false))
    }

    async fn list_owned(
        &self,
        owner: &PublicKeyFingerprint,
    ) -> AuthResult<Vec<Hash>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT file_hash FROM ownership WHERE owner_fingerprint = ?"
        )?;

        let hashes = stmt.query_map([owner.as_bytes().as_slice()], |row| {
            let bytes: Vec<u8> = row.get(0)?;
            Ok(bytes)
        })?
        .filter_map(|r| r.ok())
        .filter_map(|bytes| {
            if bytes.len() == 32 {
                let arr: [u8; 32] = bytes.try_into().ok()?;
                Some(Hash::from(arr))
            } else {
                None
            }
        })
        .collect();

        Ok(hashes)
    }

    async fn transfer(
        &self,
        from: &PublicKeyFingerprint,
        to: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<()> {
        if !self.is_owner(from, file_hash).await? {
            return Err(AuthError::NotAuthorized("Only owner can transfer".into()));
        }

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE ownership SET owner_fingerprint = ? WHERE file_hash = ?",
            (to.as_bytes().as_slice(), file_hash.as_bytes().as_slice()),
        )?;

        Ok(())
    }

    async fn grant_access(
        &self,
        grant: AccessGrant,
    ) -> AuthResult<()> {
        if !self.is_owner(&grant.owner, &grant.file_hash).await? {
            return Err(AuthError::NotAuthorized("Only owner can grant access".into()));
        }

        let ops_json: Vec<&str> = grant.operations.iter().map(|o| o.as_str()).collect();
        let ops_str = serde_json::to_string(&ops_json)
            .map_err(|e| AuthError::Storage(e.to_string()))?;

        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"INSERT OR REPLACE INTO access_grants
               (file_hash, owner_fingerprint, grantee_fingerprint, operations, expires_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?)"#,
            (
                grant.file_hash.as_bytes().as_slice(),
                grant.owner.as_bytes().as_slice(),
                grant.grantee.as_bytes().as_slice(),
                &ops_str,
                grant.expires_at as i64,
                grant.created_at as i64,
            ),
        )?;

        Ok(())
    }

    async fn revoke_access(
        &self,
        owner: &PublicKeyFingerprint,
        grantee: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<()> {
        if !self.is_owner(owner, file_hash).await? {
            return Err(AuthError::NotAuthorized("Only owner can revoke".into()));
        }

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM access_grants WHERE file_hash = ? AND grantee_fingerprint = ?",
            (file_hash.as_bytes().as_slice(), grantee.as_bytes().as_slice()),
        )?;

        Ok(())
    }

    async fn has_access(
        &self,
        pubkey: &PublicKeyFingerprint,
        file_hash: &Hash,
        operation: Operation,
    ) -> AuthResult<bool> {
        // Owner has all access
        if self.is_owner(pubkey, file_hash).await? {
            return Ok(true);
        }

        let conn = self.conn.lock().unwrap();
        let now = Self::now();

        let result: Option<String> = conn.query_row(
            r#"SELECT operations FROM access_grants
               WHERE file_hash = ? AND grantee_fingerprint = ?
               AND (expires_at = 0 OR expires_at > ?)"#,
            (file_hash.as_bytes().as_slice(), pubkey.as_bytes().as_slice(), now),
            |row| row.get(0),
        ).ok();

        if let Some(ops_json) = result {
            let ops: Vec<String> = serde_json::from_str(&ops_json)
                .map_err(|e| AuthError::Storage(e.to_string()))?;
            Ok(ops.contains(&operation.as_str().to_string()))
        } else {
            Ok(false)
        }
    }

    async fn list_grants(
        &self,
        owner: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<Vec<AccessGrant>> {
        if !self.is_owner(owner, file_hash).await? {
            return Err(AuthError::NotAuthorized("Only owner can list grants".into()));
        }

        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT grantee_fingerprint, operations, expires_at, created_at
               FROM access_grants WHERE file_hash = ?"#
        )?;

        let grants = stmt.query_map([file_hash.as_bytes().as_slice()], |row| {
            let grantee_bytes: Vec<u8> = row.get(0)?;
            let ops_json: String = row.get(1)?;
            let expires_at: i64 = row.get(2)?;
            let created_at: i64 = row.get(3)?;
            Ok((grantee_bytes, ops_json, expires_at, created_at))
        })?
        .filter_map(|r| r.ok())
        .filter_map(|(grantee_bytes, ops_json, expires_at, created_at)| {
            let grantee_arr: [u8; 32] = grantee_bytes.try_into().ok()?;
            let ops: Vec<String> = serde_json::from_str(&ops_json).ok()?;
            let operations: Vec<Operation> = ops.iter()
                .filter_map(|s| Operation::from_str(s))
                .collect();

            Some(AccessGrant {
                file_hash: *file_hash,
                owner: *owner,
                grantee: PublicKeyFingerprint::from_bytes(grantee_arr),
                operations,
                expires_at: expires_at as u64,
                created_at: created_at as u64,
            })
        })
        .collect();

        Ok(grants)
    }

    async fn list_shared_with(
        &self,
        grantee: &PublicKeyFingerprint,
    ) -> AuthResult<Vec<Hash>> {
        let conn = self.conn.lock().unwrap();
        let now = Self::now();

        let mut stmt = conn.prepare(
            r#"SELECT DISTINCT file_hash FROM access_grants
               WHERE grantee_fingerprint = ?
               AND (expires_at = 0 OR expires_at > ?)"#
        )?;

        let hashes = stmt.query_map([grantee.as_bytes().as_slice(), &now.to_le_bytes()], |row| {
            let bytes: Vec<u8> = row.get(0)?;
            Ok(bytes)
        })?
        .filter_map(|r| r.ok())
        .filter_map(|bytes| {
            if bytes.len() == 32 {
                let arr: [u8; 32] = bytes.try_into().ok()?;
                Some(Hash::from(arr))
            } else {
                None
            }
        })
        .collect();

        Ok(hashes)
    }

    async fn unregister(
        &self,
        owner: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<()> {
        if !self.is_owner(owner, file_hash).await? {
            return Err(AuthError::NotAuthorized("Only owner can unregister".into()));
        }

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM ownership WHERE file_hash = ?",
            [file_hash.as_bytes().as_slice()],
        )?;
        conn.execute(
            "DELETE FROM access_grants WHERE file_hash = ?",
            [file_hash.as_bytes().as_slice()],
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(n: u8) -> PublicKeyFingerprint {
        PublicKeyFingerprint::from_bytes([n; 32])
    }

    #[tokio::test]
    async fn test_sqlite_ownership_roundtrip() {
        let store = SqliteOwnershipStore::in_memory().unwrap();
        let owner = fp(1);
        let file = blake3::hash(b"test");

        store.register(&owner, &file).await.unwrap();
        assert!(store.is_owner(&owner, &file).await.unwrap());

        let owned = store.list_owned(&owner).await.unwrap();
        assert_eq!(owned.len(), 1);
    }

    #[tokio::test]
    async fn test_sqlite_grant_access() {
        let store = SqliteOwnershipStore::in_memory().unwrap();
        let owner = fp(1);
        let grantee = fp(2);
        let file = blake3::hash(b"test");

        store.register(&owner, &file).await.unwrap();

        let grant = AccessGrant::new(
            file, owner, grantee,
            vec![Operation::Read, Operation::Write],
            None,
        );
        store.grant_access(grant).await.unwrap();

        assert!(store.has_access(&grantee, &file, Operation::Read).await.unwrap());
        assert!(store.has_access(&grantee, &file, Operation::Write).await.unwrap());
        assert!(!store.has_access(&grantee, &file, Operation::Delete).await.unwrap());
    }
}
```

#### 4. SqliteProviderIndex

**File**: `crates/identikey-storage-auth/src/sqlite/provider.rs`

```rust
//! SQLite provider index

use std::sync::Mutex;

use async_trait::async_trait;
use blake3::Hash;
use rusqlite::Connection;

use crate::error::{AuthError, AuthResult};
use crate::provider::{ProviderIndex, ProviderUrl};
use super::schema::init_schema;

/// SQLite-backed provider index
pub struct SqliteProviderIndex {
    conn: Mutex<Connection>,
}

impl SqliteProviderIndex {
    /// Open or create a database at the given path
    pub fn open(path: &str) -> AuthResult<Self> {
        let conn = Connection::open(path)?;
        init_schema(&conn)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Create an in-memory database (for testing)
    pub fn in_memory() -> AuthResult<Self> {
        let conn = Connection::open_in_memory()?;
        init_schema(&conn)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }
}

#[async_trait]
impl ProviderIndex for SqliteProviderIndex {
    async fn register(
        &self,
        file_hash: &Hash,
        provider_url: &ProviderUrl,
    ) -> AuthResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO provider_locations (file_hash, provider_url, created_at) VALUES (?, ?, ?)",
            (file_hash.as_bytes().as_slice(), provider_url, Self::now()),
        )?;
        Ok(())
    }

    async fn lookup(
        &self,
        file_hash: &Hash,
    ) -> AuthResult<Vec<ProviderUrl>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT provider_url FROM provider_locations WHERE file_hash = ?"
        )?;

        let urls = stmt.query_map([file_hash.as_bytes().as_slice()], |row| {
            row.get::<_, String>(0)
        })?
        .filter_map(|r| r.ok())
        .collect();

        Ok(urls)
    }

    async fn update_location(
        &self,
        file_hash: &Hash,
        old_url: &ProviderUrl,
        new_url: &ProviderUrl,
    ) -> AuthResult<()> {
        let conn = self.conn.lock().unwrap();
        let updated = conn.execute(
            "UPDATE provider_locations SET provider_url = ? WHERE file_hash = ? AND provider_url = ?",
            (new_url, file_hash.as_bytes().as_slice(), old_url),
        )?;

        if updated == 0 {
            return Err(AuthError::FileNotFound(file_hash.to_string()));
        }
        Ok(())
    }

    async fn remove_location(
        &self,
        file_hash: &Hash,
        provider_url: &ProviderUrl,
    ) -> AuthResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM provider_locations WHERE file_hash = ? AND provider_url = ?",
            (file_hash.as_bytes().as_slice(), provider_url),
        )?;
        Ok(())
    }

    async fn unregister(
        &self,
        file_hash: &Hash,
    ) -> AuthResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM provider_locations WHERE file_hash = ?",
            [file_hash.as_bytes().as_slice()],
        )?;
        Ok(())
    }

    async fn exists(
        &self,
        file_hash: &Hash,
    ) -> AuthResult<bool> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM provider_locations WHERE file_hash = ?",
            [file_hash.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    async fn list_at_provider(
        &self,
        provider_url: &ProviderUrl,
    ) -> AuthResult<Vec<Hash>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT file_hash FROM provider_locations WHERE provider_url = ?"
        )?;

        let hashes = stmt.query_map([provider_url], |row| {
            let bytes: Vec<u8> = row.get(0)?;
            Ok(bytes)
        })?
        .filter_map(|r| r.ok())
        .filter_map(|bytes| {
            if bytes.len() == 32 {
                let arr: [u8; 32] = bytes.try_into().ok()?;
                Some(Hash::from(arr))
            } else {
                None
            }
        })
        .collect();

        Ok(hashes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sqlite_provider_roundtrip() {
        let index = SqliteProviderIndex::in_memory().unwrap();
        let file = blake3::hash(b"test");
        let url = "https://s3.example.com/bucket/file".to_string();

        index.register(&file, &url).await.unwrap();

        let locations = index.lookup(&file).await.unwrap();
        assert_eq!(locations, vec![url]);

        assert!(index.exists(&file).await.unwrap());
    }

    #[tokio::test]
    async fn test_sqlite_multiple_providers() {
        let index = SqliteProviderIndex::in_memory().unwrap();
        let file = blake3::hash(b"test");

        index.register(&file, &"https://provider1.com".to_string()).await.unwrap();
        index.register(&file, &"https://provider2.com".to_string()).await.unwrap();

        let locations = index.lookup(&file).await.unwrap();
        assert_eq!(locations.len(), 2);
    }
}
```

### Success Criteria

#### Automated Verification:

- [x] `cargo test -p identikey-storage-auth --features sqlite` passes
- [x] SQLite schema creates correctly
- [x] All ownership and provider operations work with SQLite

---

## Phase 4b.6: Integration Tests

### Overview

End-to-end tests combining auth with storage layer.

### Changes Required

**File**: `crates/identikey-storage-auth/tests/integration_tests.rs`

```rust
//! Integration tests: auth + storage working together

use dcypher_storage::{ChunkStorage, InMemoryStorage};
use identikey_storage_auth::{
    InMemoryOwnershipStore, InMemoryProviderIndex,
    OwnershipStore, ProviderIndex,
    Capability, Operation, AccessGrant, PublicKeyFingerprint,
};
use dcypher_core::sign::{SigningKeys, VerifyingKeys};
use dcypher_ffi::ed25519::ed25519_keygen;
use dcypher_ffi::liboqs::{PqAlgorithm, pq_keygen};

fn test_keys() -> (SigningKeys, VerifyingKeys, PublicKeyFingerprint) {
    let ed_kp = ed25519_keygen();
    let pq_kp = pq_keygen(PqAlgorithm::MlDsa87).unwrap();

    // Create fingerprint from combined key material
    let mut key_bytes = ed_kp.verifying_key.to_bytes().to_vec();
    key_bytes.extend(&pq_kp.public_key);
    let fingerprint = PublicKeyFingerprint::from_public_key(&key_bytes);

    let signing = SigningKeys {
        ed25519: ed_kp.signing_key,
        ml_dsa: pq_kp.secret_key,
    };

    let verifying = VerifyingKeys {
        ed25519: ed_kp.verifying_key,
        ml_dsa: pq_kp.public_key,
    };

    (signing, verifying, fingerprint)
}

#[tokio::test]
async fn test_full_upload_flow() {
    // Setup
    let storage = InMemoryStorage::new();
    let ownership = InMemoryOwnershipStore::new();
    let providers = InMemoryProviderIndex::new();

    let (signing_keys, verifying_keys, owner_fp) = test_keys();

    // 1. Upload encrypted file
    let plaintext = b"Secret document content";
    let ciphertext = b"encrypted-bytes-here"; // Simulated
    let file_hash = blake3::hash(ciphertext);

    storage.put(&file_hash, ciphertext).await.unwrap();

    // 2. Register ownership
    ownership.register(&owner_fp, &file_hash).await.unwrap();

    // 3. Register provider location
    let provider_url = "https://minio.local:9000/dcypher/chunks/b3/".to_string();
    providers.register(&file_hash, &provider_url).await.unwrap();

    // Verify
    assert!(ownership.is_owner(&owner_fp, &file_hash).await.unwrap());
    let locations = providers.lookup(&file_hash).await.unwrap();
    assert_eq!(locations.len(), 1);
}

#[tokio::test]
async fn test_share_flow() {
    let ownership = InMemoryOwnershipStore::new();

    let (alice_signing, alice_verifying, alice_fp) = test_keys();
    let (_, _, bob_fp) = test_keys();

    let file_hash = blake3::hash(b"alice's secret");

    // Alice uploads and registers
    ownership.register(&alice_fp, &file_hash).await.unwrap();

    // Alice grants Bob read access
    let grant = AccessGrant::new(
        file_hash,
        alice_fp,
        bob_fp,
        vec![Operation::Read],
        None,
    );
    ownership.grant_access(grant).await.unwrap();

    // Bob can read but not write
    assert!(ownership.has_access(&bob_fp, &file_hash, Operation::Read).await.unwrap());
    assert!(!ownership.has_access(&bob_fp, &file_hash, Operation::Write).await.unwrap());

    // Alice issues signed capability for Bob
    let cap = Capability::new_signed(
        file_hash,
        bob_fp,
        vec![Operation::Read],
        None,
        alice_fp,
        &alice_signing,
    ).unwrap();

    // Bob can verify the capability
    cap.verify(&alice_verifying, Operation::Read).unwrap();
}

#[tokio::test]
async fn test_revoke_flow() {
    let ownership = InMemoryOwnershipStore::new();

    let (_, _, alice_fp) = test_keys();
    let (_, _, bob_fp) = test_keys();

    let file_hash = blake3::hash(b"secret");

    ownership.register(&alice_fp, &file_hash).await.unwrap();

    // Grant then revoke
    let grant = AccessGrant::new(file_hash, alice_fp, bob_fp, vec![Operation::Read], None);
    ownership.grant_access(grant).await.unwrap();

    assert!(ownership.has_access(&bob_fp, &file_hash, Operation::Read).await.unwrap());

    ownership.revoke_access(&alice_fp, &bob_fp, &file_hash).await.unwrap();

    assert!(!ownership.has_access(&bob_fp, &file_hash, Operation::Read).await.unwrap());
}

#[tokio::test]
async fn test_capability_expiry() {
    let (signing_keys, verifying_keys, issuer_fp) = test_keys();
    let (_, _, grantee_fp) = test_keys();

    let file_hash = blake3::hash(b"test");

    // Create expired capability
    let cap = Capability::new_signed(
        file_hash,
        grantee_fp,
        vec![Operation::Read],
        Some(1), // Expired timestamp
        issuer_fp,
        &signing_keys,
    ).unwrap();

    // Signature is valid but capability is expired
    assert!(cap.verify_signature(&verifying_keys).is_ok());
    assert!(cap.is_expired());
    assert!(cap.verify(&verifying_keys, Operation::Read).is_err());
}
```

### Success Criteria

#### Automated Verification:

- [x] `cargo test -p identikey-storage-auth integration` passes
- [x] Full upload, share, revoke flows validated

---

## Phase 4b.7: Justfile Integration

### Overview

Add Justfile recipes for auth service development.

### Changes Required

**File**: `Justfile` (append)

```just
# =============================================================================
# Auth Service (Phase 4b)
# =============================================================================

# Run auth service tests (in-memory only)
test-auth:
    cargo test -p identikey-storage-auth -- --test-threads=1

# Run auth service tests with SQLite
test-auth-sqlite:
    cargo test -p identikey-storage-auth --features sqlite -- --test-threads=1

# Check auth service crate
check-auth:
    cargo check -p identikey-storage-auth
    cargo check -p identikey-storage-auth --features sqlite
    cargo clippy -p identikey-storage-auth -- -D warnings
    cargo clippy -p identikey-storage-auth --features sqlite -- -D warnings

# Generate auth service docs
docs-auth:
    cargo doc -p identikey-storage-auth --no-deps --open
```

### Success Criteria

#### Automated Verification:

- [x] `just test-auth` passes
- [x] `just test-auth-sqlite` passes
- [x] `just check-auth` passes (clippy clean)

---

## Testing Strategy

### Unit Tests

- Fingerprint encoding/decoding
- Capability signing and verification
- Operation permissions
- Expiry checking

### In-Memory Backend Tests

- Ownership registration, transfer, unregister
- Access grants and revocation
- Provider index CRUD

### SQLite Backend Tests

- Same test cases as in-memory
- Schema initialization
- Persistence across reopen

### Integration Tests

- Full upload flow (storage + auth)
- Share flow (grant + capability)
- Revoke flow

---

## Dependencies Summary

```toml
[dependencies]
recrypt-core = { path = "../recrypt-core" }
recrypt-proto = { path = "../recrypt-proto" }
blake3 = "1"
bs58 = "0.5"
tokio = { version = "1", features = ["full"] }
async-trait = "0.1"
thiserror = "2"
serde_json = "1"  # For SQLite operations JSON

# SQLite (optional)
rusqlite = { version = "0.32", features = ["bundled"], optional = true }
```

---

## Future Work

### Phase 5 HTTP API

- Expose ownership, capability, provider operations via REST
- Add rate limiting middleware
- Integrate with `recrypt-server`

### Postgres Backend (Future)

- Trait design supports pluggable backends
- Add `postgres` feature with `sqlx` or `tokio-postgres`
- Connection pooling for concurrent access

---

## References

- Design doc: `docs/storage-design.md`
- Phase 4 plan: `docs/plans/2026-01-06-phase-4-storage-layer.md`
- Proto schema: `crates/recrypt-proto/proto/dcypher.proto` (CapabilityProto)
- Multi-sig: `crates/recrypt-core/src/sign/mod.rs`
