# Phase 6: CLI Application Implementation Plan

**Status:** 🚧 In Progress  
**Duration:** 4-5 days  
**Goal:** User-friendly CLI for local crypto operations and recrypt-server interaction

**Prerequisites:** Phases 1-5 ✅ Complete

---

## Overview

Build `recrypt-cli`: a command-line interface for managing identities, encrypting/decrypting files locally, and interacting with recrypt-server for file storage and sharing. Designed for air-gapped operation where possible, with a wallet system for multi-identity management.

**What recrypt-cli IS:**

- Local identity/key management (air-gapped capable)
- Local encryption/decryption using HybridEncryptor
- HTTP client for recrypt-server API
- Multi-identity wallet with password encryption
- Human-friendly and scriptable output

**What recrypt-cli IS NOT:**

- A server (recrypt-server remains separate binary)
- A GUI (Phase 7 TUI is separate)
- A hardware wallet manager (deferred)

---

## Current State Analysis

### What Exists

| Crate            | Provides                                      | Status   |
| ---------------- | --------------------------------------------- | -------- |
| `recrypt-core`   | `HybridEncryptor`, `MultiSig`, key generation | ✅ Ready |
| `recrypt-proto`  | Wire types, serialization, format detection   | ✅ Ready |
| `recrypt-ffi`    | ED25519, ML-DSA keygen/sign, OpenFHE PRE ops  | ✅ Ready |
| `recrypt-server` | REST API for accounts, files, recryption      | ✅ Ready |

### What's Missing

| Feature                     | Notes                   |
| --------------------------- | ----------------------- |
| CLI binary                  | Doesn't exist yet       |
| Wallet format               | Need to define          |
| HTTP client for server      | Need to build           |
| `GET /accounts/{fp}/files`  | Server endpoint missing |
| `GET /accounts/{fp}/shares` | Server endpoint missing |

---

## Desired End State

After Phase 6:

1. ✅ Can create identities offline (air-gapped)
2. ✅ Can encrypt files locally for any known recipient
3. ✅ Can decrypt files locally with own keys
4. ✅ Wallet stores multiple identities with password encryption
5. ✅ Can register account on recrypt-server
6. ✅ Can upload/download/list/delete files
7. ✅ Can create/list/revoke shares
8. ✅ Can download and decrypt shared files
9. ✅ Pretty and JSON output modes
10. ✅ Config file for defaults (server URL, default identity)

**Verification:**

```bash
# Unit tests
cargo test -p recrypt-cli

# Integration tests (requires server)
just test-cli-integration

# Manual E2E flow
dcypher identity new --name alice
dcypher identity new --name bob
dcypher encrypt secret.txt --for alice --output secret.enc
dcypher decrypt secret.enc --output secret.txt
dcypher account register --server http://localhost:3000
dcypher files upload secret.enc
dcypher share create <hash> --to <bob-fingerprint>
# ... bob downloads and decrypts
```

---

## What We're NOT Doing

- ❌ OS keychain integration (deferred to Phase 6b)
- ❌ Hardware wallet support (deferred)
- ❌ Real lattice PRE backend (using MockBackend, wiring real backend later)
- ❌ Shell completions (nice-to-have, deferred)
- ❌ Streaming large file support (deferred)
- ❌ Server binary bundling (keeping recrypt-server separate)

---

## Architecture

```
recrypt-cli/
├── Cargo.toml
├── src/
│   ├── main.rs                 # Entry point, clap setup
│   ├── commands/
│   │   ├── mod.rs
│   │   ├── identity.rs         # new, show, list, delete, use, export, import
│   │   ├── encrypt.rs          # Local encryption
│   │   ├── decrypt.rs          # Local decryption
│   │   ├── account.rs          # register, show (server interaction)
│   │   ├── files.rs            # upload, download, list, delete
│   │   ├── share.rs            # create, list, revoke, download
│   │   └── config.rs           # show, set
│   ├── wallet/
│   │   ├── mod.rs
│   │   ├── format.rs           # Wallet file format (encrypted JSON)
│   │   └── identity.rs         # Identity struct with all key types
│   ├── client/
│   │   ├── mod.rs
│   │   ├── api.rs              # HTTP client for recrypt-server
│   │   └── auth.rs             # Nonce fetch, message signing, headers
│   ├── config.rs               # CLI config (~/.config/dcypher/config.toml)
│   └── output.rs               # Pretty vs JSON output formatting
└── tests/
    ├── identity_tests.rs
    ├── crypto_tests.rs
    └── integration_tests.rs
```

---

## Key Design Decisions

### 1. Wallet Format (Encrypted JSON)

The wallet is password-encrypted using Argon2id for key derivation and XChaCha20-Poly1305 for authenticated encryption.

**Encrypted Wallet Structure:**

```
┌──────────────────────────────────────┐
│ Magic bytes: "DCYW" (4 bytes)        │
│ Version: 1 (1 byte)                  │
│ Argon2 salt (32 bytes)               │
│ XChaCha20 nonce (24 bytes)           │
│ Encrypted payload (variable)         │
│ Poly1305 tag (16 bytes)              │
└──────────────────────────────────────┘
```

**Decrypted Payload (JSON):**

```json
{
  "version": 1,
  "default_identity": "alice",
  "identities": {
    "alice": {
      "created_at": 1704067200,
      "ed25519": {
        "public": "<base58>",
        "secret": "<base58>"
      },
      "ml_dsa": {
        "public": "<base58>",
        "secret": "<base58>"
      },
      "pre": {
        "public": "<base58>",
        "secret": "<base58>"
      },
      "fingerprint": "<base58>"
    }
  }
}
```

**Location:** `~/.dcypher/wallet.dcyw` (or `$DCYPHER_WALLET`)

**Argon2 Parameters (OWASP recommendations):**

- Memory: 64 MiB
- Iterations: 3
- Parallelism: 4

### 2. Config File

```toml
# ~/.config/dcypher/config.toml
default_server = "https://dcypher.example.com"
default_identity = "alice"
output_format = "pretty"  # or "json"
wallet_path = "~/.dcypher/wallet.dcyw"
```

### 3. Command Structure

```bash
# Identity management (local, air-gapped capable)
dcypher identity new [--name <name>]
dcypher identity list
dcypher identity show [--name <name>]
dcypher identity use <name>
dcypher identity delete <name>
dcypher identity export <name> --output <file>
dcypher identity import <file> [--name <name>]

# Local crypto (air-gapped capable)
dcypher encrypt <file> --for <fingerprint|name> [--output <file.enc>]
dcypher decrypt <file.enc> [--output <file>]

# Server account
dcypher account register [--server <url>]
dcypher account show [<fingerprint>]

# File operations (requires server)
dcypher files upload <file> [--server <url>]
dcypher files download <hash> [--output <file>]
dcypher files list [--server <url>]
dcypher files delete <hash>

# Sharing (requires server)
dcypher share create <file-hash> --to <fingerprint>
dcypher share list [--from | --to]
dcypher share download <share-id> [--output <file>]
dcypher share revoke <share-id>

# Config
dcypher config show
dcypher config set <key> <value>

# Global flags
--json              # JSON output mode
--identity <name>   # Override default identity
--server <url>      # Override default server
--wallet <path>     # Override wallet path
--verbose / -v      # Verbose output
```

### 4. Identity Selection Priority

```
1. --identity <name>          # Explicit flag
2. $DCYPHER_IDENTITY          # Environment variable
3. config.default_identity    # Config file
4. wallet.default_identity    # Wallet default
5. (error if no identity)
```

### 5. Recipient Resolution

When encrypting `--for <target>`:

1. If `<target>` matches a wallet identity name → use that identity's PRE public key
2. If `<target>` looks like a fingerprint → fetch from server or local cache
3. Error if unresolvable

---

## Implementation Phases

### Phase 6.1: Scaffold & Wallet (Day 1)

**Goal:** CLI structure and encrypted wallet working

#### 1. Create recrypt-cli crate

**File:** `recrypt-cli/Cargo.toml`

```toml
[package]
name = "recrypt-cli"
version = "0.1.0"
edition = "2021"
description = "Command-line interface for Recrypt proxy recryption"

[[bin]]
name = "dcypher"
path = "src/main.rs"

[dependencies]
# CLI framework
clap = { version = "4", features = ["derive", "env", "wrap_help"] }

# Async
tokio = { version = "1", features = ["full"] }

# HTTP client
reqwest = { version = "0.12", features = ["json"] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"

# Crypto for wallet encryption
argon2 = "0.5"
chacha20poly1305 = "0.10"
rand = "0.8"

# Output
colored = "2"
indicatif = "0.17"
dialoguer = "0.11"

# Paths
directories = "5"

# Encoding
bs58 = "0.5"
base64 = "0.22"
blake3 = "1"

# Errors
thiserror = "1"
anyhow = "1"

# Workspace crates
recrypt-core = { path = "../crates/recrypt-core" }
recrypt-proto = { path = "../crates/recrypt-proto" }
recrypt-ffi = { path = "../crates/recrypt-ffi" }

[dev-dependencies]
assert_cmd = "2"
predicates = "3"
tempfile = "3"
```

**File:** `recrypt-cli/src/main.rs`

```rust
use anyhow::Result;
use clap::{Parser, Subcommand};

mod commands;
mod config;
mod wallet;
mod client;
mod output;

#[derive(Parser)]
#[command(name = "dcypher")]
#[command(about = "Quantum-resistant proxy recryption CLI")]
#[command(version)]
struct Cli {
    /// Output format
    #[arg(long, global = true)]
    json: bool,

    /// Identity to use
    #[arg(long, global = true, env = "DCYPHER_IDENTITY")]
    identity: Option<String>,

    /// Server URL
    #[arg(long, global = true, env = "DCYPHER_SERVER")]
    server: Option<String>,

    /// Wallet path
    #[arg(long, global = true, env = "DCYPHER_WALLET")]
    wallet: Option<String>,

    /// Verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage identities
    Identity {
        #[command(subcommand)]
        action: commands::identity::IdentityCommand,
    },
    /// Encrypt a file locally
    Encrypt(commands::encrypt::EncryptArgs),
    /// Decrypt a file locally
    Decrypt(commands::decrypt::DecryptArgs),
    /// Manage server account
    Account {
        #[command(subcommand)]
        action: commands::account::AccountCommand,
    },
    /// Manage files on server
    Files {
        #[command(subcommand)]
        action: commands::files::FilesCommand,
    },
    /// Manage file shares
    Share {
        #[command(subcommand)]
        action: commands::share::ShareCommand,
    },
    /// Manage configuration
    Config {
        #[command(subcommand)]
        action: commands::config::ConfigCommand,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let ctx = commands::Context {
        json_output: cli.json,
        identity_override: cli.identity,
        server_override: cli.server,
        wallet_override: cli.wallet,
        verbose: cli.verbose,
    };

    match cli.command {
        Commands::Identity { action } => commands::identity::run(action, &ctx).await,
        Commands::Encrypt(args) => commands::encrypt::run(args, &ctx).await,
        Commands::Decrypt(args) => commands::decrypt::run(args, &ctx).await,
        Commands::Account { action } => commands::account::run(action, &ctx).await,
        Commands::Files { action } => commands::files::run(action, &ctx).await,
        Commands::Share { action } => commands::share::run(action, &ctx).await,
        Commands::Config { action } => commands::config::run(action, &ctx).await,
    }
}
```

#### 2. Wallet encryption module

**File:** `recrypt-cli/src/wallet/format.rs`

Core wallet encryption/decryption using Argon2id + XChaCha20-Poly1305.

```rust
use anyhow::{anyhow, Result};
use argon2::{Argon2, Algorithm, Version, Params};
use chacha20poly1305::{XChaCha20Poly1305, aead::{Aead, KeyInit}};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const MAGIC: &[u8; 4] = b"DCYW";
const VERSION: u8 = 1;

// Argon2 params (OWASP recommendations)
const ARGON2_M_COST: u32 = 65536;  // 64 MiB
const ARGON2_T_COST: u32 = 3;      // 3 iterations
const ARGON2_P_COST: u32 = 4;      // 4 parallelism

#[derive(Serialize, Deserialize)]
pub struct WalletData {
    pub version: u8,
    pub default_identity: Option<String>,
    pub identities: HashMap<String, Identity>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Identity {
    pub created_at: u64,
    pub fingerprint: String,
    pub ed25519: KeyPair,
    pub ml_dsa: KeyPair,
    pub pre: KeyPair,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KeyPair {
    pub public: String,  // base58
    pub secret: String,  // base58
}

impl WalletData {
    pub fn new() -> Self {
        Self {
            version: 1,
            default_identity: None,
            identities: HashMap::new(),
        }
    }
}

pub fn encrypt_wallet(data: &WalletData, password: &str) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(data)?;

    // Generate salt and nonce
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);

    // Derive key with Argon2id
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), &salt, &mut key)?;

    // Encrypt with XChaCha20-Poly1305
    let cipher = XChaCha20Poly1305::new_from_slice(&key)?;
    let ciphertext = cipher.encrypt(&nonce.into(), json.as_slice())
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    // Assemble: magic || version || salt || nonce || ciphertext (includes tag)
    let mut output = Vec::with_capacity(4 + 1 + 32 + 24 + ciphertext.len());
    output.extend_from_slice(MAGIC);
    output.push(VERSION);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

pub fn decrypt_wallet(data: &[u8], password: &str) -> Result<WalletData> {
    if data.len() < 4 + 1 + 32 + 24 + 16 {
        return Err(anyhow!("Wallet file too short"));
    }

    // Parse header
    if &data[0..4] != MAGIC {
        return Err(anyhow!("Invalid wallet file (bad magic)"));
    }
    let version = data[4];
    if version != VERSION {
        return Err(anyhow!("Unsupported wallet version: {}", version));
    }

    let salt = &data[5..37];
    let nonce = &data[37..61];
    let ciphertext = &data[61..];

    // Derive key
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key)?;

    // Decrypt
    let cipher = XChaCha20Poly1305::new_from_slice(&key)?;
    let nonce_arr: [u8; 24] = nonce.try_into()?;
    let plaintext = cipher.decrypt(&nonce_arr.into(), ciphertext)
        .map_err(|_| anyhow!("Decryption failed (wrong password?)"))?;

    let wallet: WalletData = serde_json::from_slice(&plaintext)?;
    Ok(wallet)
}
```

#### Success Criteria (Phase 6.1):

**Automated Verification:**

- [x] `cargo build -p recrypt-cli` compiles
- [x] `cargo test -p recrypt-cli` passes wallet encryption roundtrip tests
- [x] `./target/debug/dcypher --help` shows all commands

**Manual Verification:**

- [ ] Wallet encrypts/decrypts correctly with password
- [ ] Wrong password fails gracefully with clear error

---

### Phase 6.2: Identity Commands (Day 1-2)

**Goal:** Full identity lifecycle management

#### Commands to implement:

```bash
dcypher identity new [--name <name>]
dcypher identity list
dcypher identity show [--name <name>]
dcypher identity use <name>
dcypher identity delete <name>
dcypher identity export <name> --output <file>
dcypher identity import <file> [--name <name>]
```

**File:** `recrypt-cli/src/commands/identity.rs`

Key generation uses:

- `dcypher_ffi::ed25519::ed25519_keygen()`
- `dcypher_ffi::liboqs::pq_keygen(PqAlgorithm::MlDsa87)`
- `dcypher_core::pre::backends::MockBackend::generate_keypair()` (for now)

Fingerprint computed as: `bs58::encode(blake3::hash(ed25519_pk))`

**Password handling:**

- First wallet creation: prompt for new password (with confirmation)
- Subsequent access: prompt for existing password
- Use `dialoguer::Password` for secure input (no echo)

#### Success Criteria (Phase 6.2):

**Automated Verification:**

- [ ] `dcypher identity new --name test` creates identity
- [ ] `dcypher identity list` shows created identity
- [ ] `dcypher identity show --name test` displays details
- [ ] `dcypher identity delete test` removes identity
- [ ] Export/import roundtrip preserves identity

**Manual Verification:**

- [ ] Password prompt appears and works correctly
- [ ] Pretty output is readable
- [ ] JSON output is valid JSON

---

### Phase 6.3: Local Crypto Commands (Day 2)

**Goal:** Encrypt and decrypt files locally

#### Commands:

```bash
dcypher encrypt <file> --for <fingerprint|name> [--output <file.enc>]
dcypher decrypt <file.enc> [--output <file>]
```

**Implementation:**

Uses `HybridEncryptor<MockBackend>` from recrypt-core.

**Recipient resolution:**

1. Check if `--for` matches wallet identity name
2. If not, treat as fingerprint (future: fetch PRE key from server)

**Output filename defaults:**

- Encrypt: `<filename>.enc`
- Decrypt: strip `.enc` or prompt

#### Success Criteria (Phase 6.3):

**Automated Verification:**

- [ ] Encrypt + decrypt roundtrip preserves content
- [ ] Encrypting for unknown recipient fails clearly
- [ ] Decrypting with wrong key fails clearly

**Manual Verification:**

- [ ] Progress indicator for large files
- [ ] Clear success/failure messages

---

### Phase 6.4: HTTP Client (Day 2-3)

**Goal:** Client library for recrypt-server API

**File:** `recrypt-cli/src/client/api.rs`

Implements:

- Nonce fetching (`GET /nonce`)
- Multi-sig header building (`X-Public-Key`, `X-Nonce`, `X-Signature-ED25519`, `X-Signature-ML-DSA`)
- All API endpoints

**File:** `recrypt-cli/src/client/auth.rs`

```rust
pub struct AuthHeaders {
    pub fingerprint: String,
    pub nonce: String,
    pub ed25519_sig: String,  // base64
    pub ml_dsa_sig: String,   // base64
}

pub async fn sign_request(
    client: &reqwest::Client,
    server: &str,
    message: &str,
    identity: &Identity,
) -> Result<AuthHeaders> {
    // 1. Fetch nonce from server
    // 2. Build signing message
    // 3. Sign with ED25519 and ML-DSA
    // 4. Return headers
}
```

#### Success Criteria (Phase 6.4):

**Automated Verification:**

- [ ] Can fetch nonce from running server
- [ ] Signed requests pass server validation

**Manual Verification:**

- [ ] Clear error messages for network failures
- [ ] Timeout handling works

---

### Phase 6.5: Server Commands (Day 3-4)

**Goal:** Full server interaction

#### Account commands:

```bash
dcypher account register [--server <url>]
dcypher account show [<fingerprint>]
```

#### File commands:

```bash
dcypher files upload <file> [--server <url>]
dcypher files download <hash> [--output <file>]
dcypher files list [--server <url>]
dcypher files delete <hash>
```

#### Share commands:

```bash
dcypher share create <file-hash> --to <fingerprint>
dcypher share list [--from | --to]
dcypher share download <share-id> [--output <file>]
dcypher share revoke <share-id>
```

**Share creation flow:**

1. Fetch recipient's account from server (need their PRE public key)
2. Generate recrypt key: `backend.generate_recrypt_key(&my_sk, &their_pk)`
3. POST to `/recryption/share`

#### Success Criteria (Phase 6.5):

**Automated Verification:**

- [ ] Account register + show works
- [ ] File upload + download roundtrip works
- [ ] Share create + download + revoke works

**Manual Verification:**

- [ ] Progress bars for uploads/downloads
- [ ] List output is well-formatted

---

### Phase 6.6: Server List Endpoints (Day 4)

**Goal:** Add missing server endpoints for list operations

**File:** `recrypt-server/src/routes/accounts.rs`

Add:

```rust
/// GET /accounts/{fingerprint}/files
pub async fn list_files(
    State(state): State<AppState>,
    Path(fingerprint): Path<String>,
) -> ServerResult<Json<Vec<FileInfo>>> {
    // Query ownership store for all files owned by fingerprint
}

/// GET /accounts/{fingerprint}/shares
pub async fn list_shares(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(fingerprint): Path<String>,
) -> ServerResult<Json<ShareListResponse>> {
    // Return shares where from_fingerprint or to_fingerprint matches
    // Requires auth (can only list own shares)
}
```

**File:** `recrypt-server/src/routes/mod.rs`

Add routes:

```rust
.route("/accounts/{fingerprint}/files", get(accounts::list_files))
.route("/accounts/{fingerprint}/shares", get(accounts::list_shares))
```

#### Success Criteria (Phase 6.6):

**Automated Verification:**

- [ ] `GET /accounts/{fp}/files` returns file list
- [ ] `GET /accounts/{fp}/shares` returns share list
- [ ] Auth required for shares endpoint

**Manual Verification:**

- [ ] CLI `files list` and `share list` work

---

### Phase 6.7: Polish (Day 4-5)

**Goal:** Production-quality UX

#### Tasks:

1. **Pretty output formatting** - Colored, aligned, human-readable
2. **JSON output mode** - `--json` flag, valid JSON on stdout
3. **Error messages** - Clear, actionable, no stack traces
4. **Help text** - Examples, descriptions
5. **Progress indicators** - For uploads, downloads, key generation
6. **Config commands** - `config show`, `config set`

#### Success Criteria (Phase 6.7):

**Automated Verification:**

- [ ] All commands have `--help`
- [ ] `--json` produces valid JSON
- [ ] Error exit codes are correct (0 success, 1 error)

**Manual Verification:**

- [ ] Output looks good
- [ ] Help text is useful
- [ ] Errors are understandable

---

## Testing Strategy

### Unit Tests

- Wallet encryption/decryption roundtrip
- Identity serialization
- Config loading
- Output formatting

### Integration Tests (with server)

- Full registration flow
- Upload → share → download flow
- Share revocation
- Error handling

### E2E Test Script

```bash
#!/bin/bash
set -e

# Start server
cargo run -p recrypt-server &
SERVER_PID=$!
sleep 2

# Create identities
dcypher identity new --name alice
dcypher identity new --name bob

# Get fingerprints
ALICE_FP=$(dcypher identity show --name alice --json | jq -r '.fingerprint')
BOB_FP=$(dcypher identity show --name bob --json | jq -r '.fingerprint')

# Register accounts
dcypher --identity alice account register --server http://localhost:3000
dcypher --identity bob account register --server http://localhost:3000

# Create test file
echo "Secret message" > secret.txt

# Encrypt and upload
dcypher --identity alice encrypt secret.txt --for alice --output secret.enc
HASH=$(dcypher --identity alice files upload secret.enc --json | jq -r '.hash')

# Share with Bob
dcypher --identity alice share create "$HASH" --to "$BOB_FP"

# Bob downloads and decrypts
SHARE_ID=$(dcypher --identity bob share list --json | jq -r '.[0].share_id')
dcypher --identity bob share download "$SHARE_ID" --output shared.enc
dcypher --identity bob decrypt shared.enc --output decrypted.txt

# Verify
diff secret.txt decrypted.txt && echo "✅ E2E test passed!"

kill $SERVER_PID
```

---

## Dependencies

```toml
[dependencies]
# CLI
clap = { version = "4", features = ["derive", "env", "wrap_help"] }
dialoguer = "0.11"
colored = "2"
indicatif = "0.17"

# Async + HTTP
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.12", features = ["json"] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"

# Wallet crypto
argon2 = "0.5"
chacha20poly1305 = "0.10"
rand = "0.8"

# Encoding
bs58 = "0.5"
base64 = "0.22"
blake3 = "1"

# Paths
directories = "5"

# Errors
thiserror = "1"
anyhow = "1"

# Workspace
recrypt-core = { path = "../crates/recrypt-core" }
recrypt-proto = { path = "../crates/recrypt-proto" }
recrypt-ffi = { path = "../crates/recrypt-ffi" }
```

---

## Overall Success Criteria

### Automated Verification:

- [x] `cargo build -p recrypt-cli` succeeds
- [x] `cargo test -p recrypt-cli` all pass
- [x] `cargo clippy -p recrypt-cli` no warnings
- [x] Integration tests pass with server running

### Manual Verification:

- [x] Identity creation works offline
- [x] Wallet password protection works
- [x] Full Alice→Bob sharing flow works
- [x] Output is beautiful and useful
- [x] Help text is comprehensive
- [x] Error messages are clear

---

## Deferred to Phase 6b

- OS keychain integration (`keyring` crate)
- Password change command
- Real lattice PRE backend (wiring OpenFHE)
- Shell completions
- `dcypher upgrade` command (self-update)

---

## References

- Main plan: `docs/IMPLEMENTATION_PLAN.md`
- Phase 5 (server): `docs/plans/2026-01-07-phase-5-recryption-proxy.md`
- Wire protocol: `docs/wire-protocol.md`
- Hybrid encryption: `docs/hybrid-encryption-architecture.md`
