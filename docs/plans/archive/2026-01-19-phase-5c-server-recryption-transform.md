# Phase 5c: Server-Side Recryption Transform Implementation

**Status:** 🔧 Ready to Implement  
**Duration:** ~2-3 hours  
**Goal:** Complete the placeholder recryption transform in `download_recrypted`

**Prerequisites:** Phases 1-6 ✅ Complete, CLI working end-to-end locally

---

## Overview

Phase 5 built the server scaffolding but left the actual recryption transformation as a placeholder. The server currently stores recrypt keys and returns files as-is. This plan wires up the actual cryptographic transformation.

**What needs to happen:**
1. Deserialize `EncryptedFile` from stored bytes
2. Reconstruct `RecryptKey` with proper backend type
3. Call `HybridEncryptor::recrypt()` to transform `wrapped_key`
4. Serialize result back to protobuf bytes
5. Return to client

---

## Current State Analysis

### What Exists

**File**: `recrypt-server/src/routes/recryption.rs` (lines 175-200)
```rust
// Load the encrypted file
let file_bytes = state.storage.get(&policy.file_hash).await
    .map_err(|e| ServerError::Internal(format!("Storage error: {e}")))?;

// NOTE: For MVP Phase 5, we're returning the file as-is without actual recryption transform
// Full implementation would:
// 1. Deserialize EncryptedFile from file_bytes using recrypt-proto
// 2. Call HybridEncryptor::recrypt(&recrypt_key, &encrypted_file)
// 3. Serialize the result back to bytes
// 4. Return as streaming response

let response = Response::builder()
    .status(StatusCode::OK)
    .header(header::CONTENT_TYPE, "application/octet-stream")
    .header("X-Share-Id", share_id)
    .header("X-Recrypted", "placeholder") // Changed from "true" to indicate MVP status
    .body(Body::from(file_bytes))
    .map_err(|e| ServerError::Internal(e.to_string()))?;
```

### Dependencies Already Available

| Crate | Provides | Status |
|-------|----------|--------|
| `recrypt-core` | `HybridEncryptor::recrypt()`, `PreBackend` trait | ✅ Ready |
| `recrypt-proto` | `EncryptedFile::from_protobuf()`, `to_protobuf()` | ✅ Ready |
| `recrypt-core::pre` | `RecryptKey`, `BackendId`, `Ciphertext` | ✅ Ready |

---

## Desired End State

After this plan:
1. Server performs actual PRE transformation on `download_recrypted`
2. Clients receive properly recrypted files they can decrypt with their own keys
3. E2E flow works: Alice uploads → shares with Bob → Bob downloads & decrypts

**Verification:**
```bash
# Run server
cargo run -p recrypt-server &

# Run CLI tests with server (requires test script update)
./test-cli-server.sh

# Unit tests
cargo test -p recrypt-server -- --test-threads=1
```

---

## What We're NOT Doing

- ❌ Streaming recryption (file fits in memory for now)
- ❌ Multiple PRE backends on server (start with one, configurable later)
- ❌ Caching recrypted results (each request transforms fresh)
- ❌ Parallel recryption (OpenFHE threading constraints)

---

## Implementation Approach

The key insight from `docs/openfhe-threading-model.md`:
- Context creation = single-threaded (do once at startup)
- Encrypt/decrypt/recrypt operations = thread-safe after init
- Key generation = needs serialization (but CLI generates keys, not server)

**Strategy:**
1. Add `PreBackend` to `AppState` (initialized once at startup)
2. In `download_recrypted`, deserialize → recrypt → serialize
3. Store `BackendId` with share policy to ensure correct deserialization

---

## Phase 5c.1: Add PRE Backend to AppState

### Changes Required

**File**: `recrypt-server/src/state.rs`

Add backend to AppState:

```rust
use recrypt_core::pre::{BackendId, PreBackend};
use recrypt_core::pre::backends::{LatticeBackend, MockBackend};

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<dyn ChunkStorage>,
    pub ownership: Arc<dyn OwnershipStore>,
    pub providers: Arc<dyn ProviderIndex>,
    pub accounts: Arc<RwLock<AccountStore>>,
    pub shares: Arc<RwLock<ShareStore>>,
    pub nonces: Arc<RwLock<NonceStore>>,
    pub config: Arc<Config>,
    /// PRE backend for recryption operations (initialized once at startup)
    pub pre_backend: Arc<dyn PreBackend + Send + Sync>,
}
```

Update `SharePolicy` to track backend:

```rust
#[derive(Clone, Debug)]
pub struct SharePolicy {
    pub id: String,
    pub from_fingerprint: String,
    pub to_fingerprint: String,
    pub file_hash: blake3::Hash,
    pub recrypt_key: Vec<u8>,
    pub backend_id: BackendId,  // NEW: track which backend to use
    pub created_at: u64,
}
```

Update `AppState::new()`:

```rust
impl AppState {
    pub async fn new(config: &Config) -> anyhow::Result<Self> {
        // ... existing storage setup ...

        // Initialize PRE backend (single-threaded, done once)
        let pre_backend: Arc<dyn PreBackend + Send + Sync> = 
            match config.pre_backend.as_deref().unwrap_or("mock") {
                "lattice" => {
                    let backend = LatticeBackend::new()
                        .map_err(|e| anyhow::anyhow!("Failed to init lattice backend: {e}"))?;
                    Arc::new(backend)
                }
                _ => Arc::new(MockBackend),
            };

        Ok(Self {
            storage,
            ownership,
            providers,
            accounts: Arc::new(RwLock::new(AccountStore::new())),
            shares: Arc::new(RwLock::new(ShareStore::new())),
            nonces: Arc::new(RwLock::new(NonceStore::new(config.nonce.window_secs))),
            config: Arc::new(config.clone()),
            pre_backend,
        })
    }
}
```

**File**: `recrypt-server/src/config.rs`

Add PRE backend config:

```rust
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    // ... existing fields ...
    
    /// PRE backend: "mock" (default) or "lattice"
    pub pre_backend: Option<String>,
}
```

### Success Criteria

- [ ] `cargo check -p recrypt-server` passes
- [ ] Server starts with mock backend by default
- [ ] Server can be configured with `pre_backend = "lattice"` in config

---

## Phase 5c.2: Update create_share to Store BackendId

### Changes Required

**File**: `recrypt-server/src/routes/recryption.rs`

Update `CreateShareRequest`:

```rust
#[derive(Deserialize)]
pub struct CreateShareRequest {
    pub to_fingerprint: String,
    pub file_hash: String,      // base58
    pub recrypt_key: String,    // base58
    pub backend_id: String,     // "mock" or "lattice"
}
```

Update `create_share` to parse and store backend:

```rust
// Parse backend ID
let backend_id: BackendId = body.backend_id.parse()
    .map_err(|_| ServerError::BadRequest(format!("Invalid backend_id: {}", body.backend_id)))?;

// ... existing code ...

let policy = SharePolicy {
    id: share_id.clone(),
    from_fingerprint: from_fingerprint.clone(),
    to_fingerprint: body.to_fingerprint.clone(),
    file_hash,
    recrypt_key: recrypt_key_bytes,
    backend_id,  // NEW
    created_at: now,
};
```

### Success Criteria

- [ ] Share creation accepts `backend_id` field
- [ ] Share policy stores backend information

---

## Phase 5c.3: Implement Actual Recryption Transform

### Changes Required

**File**: `recrypt-server/src/routes/recryption.rs`

Replace placeholder in `download_recrypted`:

```rust
use recrypt_core::{EncryptedFile, HybridEncryptor};
use recrypt_core::pre::{BackendId, Ciphertext, PublicKey, RecryptKey};
use recrypt_proto::MultiFormat;

/// GET /recryption/share/{id}/file
/// Downloads file with recryption transformation applied
pub async fn download_recrypted(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(share_id): Path<String>,
) -> ServerResult<Response> {
    let sig_headers = extract_signature_headers(&headers)?;
    let requester_fingerprint = sig_headers.fingerprint.clone();

    // Look up share
    let policy = {
        let shares = state.shares.read().await;
        shares.shares.get(&share_id)
            .ok_or_else(|| ServerError::NotFound("Share not found".into()))?
            .clone()
    };

    // Verify requester is the intended recipient
    if policy.to_fingerprint != requester_fingerprint {
        return Err(ServerError::Unauthorized("Not authorized for this share".into()));
    }

    // Look up requester's account for signature verification
    let requester_account = {
        let accounts = state.accounts.read().await;
        accounts.accounts.get(&requester_fingerprint)
            .ok_or_else(|| ServerError::NotFound("Requester account not found".into()))?
            .clone()
    };

    // Verify signature
    let message = format!(
        "DOWNLOAD:{}:{}:{}",
        requester_fingerprint, share_id, sig_headers.nonce
    );
    verify_multisig(
        message.as_bytes(),
        &sig_headers,
        &requester_account.ed25519_pk,
        &requester_account.ml_dsa_pk,
    )?;

    // Load the encrypted file
    let file_bytes = state.storage.get(&policy.file_hash).await
        .map_err(|e| ServerError::Internal(format!("Storage error: {e}")))?;

    // === ACTUAL RECRYPTION TRANSFORM ===
    
    // 1. Deserialize EncryptedFile from protobuf
    let encrypted = EncryptedFile::from_protobuf(&file_bytes)
        .map_err(|e| ServerError::Internal(format!("Failed to deserialize file: {e}")))?;

    // 2. Reconstruct RecryptKey from stored bytes
    // The recrypt key bytes are the raw key_data; we need to reconstruct the full struct
    let recrypt_key = RecryptKey::new(
        policy.backend_id,
        PublicKey::new(policy.backend_id, vec![]),  // from_public not needed for recrypt
        PublicKey::new(policy.backend_id, vec![]),  // to_public not needed for recrypt  
        policy.recrypt_key.clone(),
    );

    // 3. Perform recryption (transforms wrapped_key only)
    let encryptor = HybridEncryptor::new(state.pre_backend.as_ref());
    let recrypted = encryptor.recrypt(&recrypt_key, &encrypted)
        .map_err(|e| ServerError::Internal(format!("Recryption failed: {e}")))?;

    // 4. Serialize back to protobuf
    let recrypted_bytes = recrypted.to_protobuf()
        .map_err(|e| ServerError::Internal(format!("Failed to serialize: {e}")))?;

    // === END RECRYPTION TRANSFORM ===

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header("X-Share-Id", share_id)
        .header("X-Recrypted", "true")
        .header("X-Backend", policy.backend_id.to_string())
        .body(Body::from(recrypted_bytes))
        .map_err(|e| ServerError::Internal(e.to_string()))?;

    Ok(response)
}
```

### Success Criteria

- [ ] `cargo check -p recrypt-server` passes
- [ ] `cargo test -p recrypt-server -- --test-threads=1` passes
- [ ] Recrypted download returns transformed file (X-Recrypted: true)

---

## Phase 5c.4: Update CLI Client to Send BackendId

### Changes Required

**File**: `recrypt-cli/src/client/api.rs`

Update `create_share` to include backend_id:

```rust
pub async fn create_share(
    &self,
    identity: &Identity,
    file_hash: String,
    to_fingerprint: String,
    recrypt_key: Vec<u8>,
) -> Result<ShareResponse> {
    // ... existing nonce/signature code ...

    let body = serde_json::json!({
        "to_fingerprint": to_fingerprint,
        "file_hash": file_hash,
        "recrypt_key": bs58::encode(&recrypt_key).into_string(),
        "backend_id": identity.pre_backend.to_string(),  // NEW: include backend
    });

    // ... rest unchanged ...
}
```

### Success Criteria

- [ ] CLI sends backend_id when creating shares
- [ ] Server accepts and stores backend_id

---

## Phase 5c.5: E2E Test with Server

### Create Test Script

**File**: `test-cli-server.sh`

```bash
#!/bin/bash
set -e

echo "=== CLI + SERVER E2E TEST ==="

# Setup
TEST_DIR=$(mktemp -d)
export RECRYPT_WALLET="$TEST_DIR/test-wallet.recrypt"
export RECRYPT_BACKEND="mock"
export RECRYPT_WALLET_PASSWORD="testpass123"
export RECRYPT_SERVER="http://localhost:7222"
CLI="./target/release/recrypt"

# Start server in background
echo "Starting server..."
RUST_LOG=recrypt_server=debug cargo run -p recrypt-server &
SERVER_PID=$!
sleep 3  # Wait for server to start

cleanup() {
    echo "Cleaning up..."
    kill $SERVER_PID 2>/dev/null || true
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

# Verify server is running
curl -s http://localhost:7222/health | grep -q '"status":"ok"' || {
    echo "Server failed to start"
    exit 1
}
echo "✓ Server running"

# Create identities
echo "=== Creating identities ==="
$CLI identity new --name alice
$CLI identity new --name bob

# Get fingerprints
ALICE_FP=$($CLI --json identity show --name alice | jq -r '.fingerprint')
BOB_FP=$($CLI --json identity show --name bob | jq -r '.fingerprint')
echo "Alice: $ALICE_FP"
echo "Bob: $BOB_FP"

# Register accounts on server
echo "=== Registering accounts ==="
$CLI account register --name alice
$CLI account register --name bob

# Create test file
echo "Secret message for E2E test!" > "$TEST_DIR/secret.txt"

# Alice encrypts for herself
echo "=== Alice encrypts ==="
$CLI identity use alice
$CLI encrypt "$TEST_DIR/secret.txt" --for alice --output "$TEST_DIR/encrypted.enc"

# Alice uploads to server
echo "=== Alice uploads ==="
FILE_HASH=$($CLI --json file upload "$TEST_DIR/encrypted.enc" | jq -r '.hash')
echo "Uploaded: $FILE_HASH"

# Alice shares with Bob
echo "=== Alice shares with Bob ==="
$CLI share create "$FILE_HASH" --to bob

# Bob downloads and decrypts
echo "=== Bob downloads ==="
$CLI identity use bob
$CLI share list
SHARE_ID=$($CLI --json share list --to | jq -r '.[0].share_id')
$CLI share download "$SHARE_ID" --output "$TEST_DIR/bob_received.enc"

# Bob decrypts
$CLI decrypt "$TEST_DIR/bob_received.enc" --output "$TEST_DIR/bob_decrypted.txt"

# Verify
echo "=== Verify ==="
if diff -q "$TEST_DIR/secret.txt" "$TEST_DIR/bob_decrypted.txt"; then
    echo "✓ E2E TEST PASSED!"
else
    echo "✗ E2E TEST FAILED - content mismatch"
    exit 1
fi
```

### Success Criteria

#### Automated Verification:
- [ ] `cargo test -p recrypt-server -- --test-threads=1` passes
- [ ] `cargo clippy -p recrypt-server -- -D warnings` passes

#### Manual Verification:
- [ ] `./test-cli-server.sh` completes successfully
- [ ] Bob can decrypt Alice's shared file
- [ ] X-Recrypted header shows "true" in server logs

---

## Testing Strategy

### Unit Tests
- Recrypt key reconstruction from bytes
- Backend ID parsing
- Error handling for missing/invalid backend

### Integration Tests
- Full download_recrypted flow with mock backend
- Error cases: wrong recipient, missing share, corrupted file

### E2E Tests
- Alice→Bob flow via CLI + server
- Revocation flow (share revoked, download fails)

---

## Performance Considerations

1. **Backend initialization:** Done once at startup. OpenFHE context creation is slow (~2 min for lattice) but only happens once.

2. **Recryption latency:** Each recrypt operation is ~100ms for mock, potentially seconds for lattice. Acceptable for file download.

3. **Memory:** Entire file loaded into memory for recryption. Future: streaming for large files.

---

## References

- Phase 5 plan: `docs/plans/2026-01-07-phase-5-recryption-proxy.md`
- OpenFHE threading: `docs/openfhe-threading-model.md`
- Hybrid encryption: `docs/hybrid-encryption-architecture.md`
- CLI share command: `recrypt-cli/src/commands/share.rs`
