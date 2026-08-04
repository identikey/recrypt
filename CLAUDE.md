# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Recrypt is a quantum-resistant proxy recryption system that enables secure, revocable file sharing with untrusted storage providers. It uses lattice-based cryptography (OpenFHE) with post-quantum signatures (liboqs) for end-to-end encryption where files can be shared without exposing private keys or plaintext.

**Status:** Phase 8 - Documentation & Deployment (Implementation Nearly Complete)

## Development Commands

### Build System (via Just)
- `just build` - Build the workspace
- `just build-release` - Build in release mode
- `just test` - Run all tests (sequential due to OpenFHE global state)
- `just test-ffi` - Test FFI bindings specifically
- `just lint` - Run clippy lints
- `just format` - Format code
- `just clean-rust` - Clean Rust build artifacts

### Dependencies & Setup
- `just setup` - First-time setup (submodules + deps + build)
- `just submodules` - Initialize/update git submodules
- `just build-openfhe` - Build OpenFHE C++ library (required for FFI)
- `just build-deps` - Build all C/C++ dependencies

### Testing by Component
- `just test-openfhe` - Test OpenFHE sys bindings
- `just test-storage` - Test storage layer
- `just test-auth` - Test auth service
- `just test-cli` - Test CLI functionality
- `just test-e2e` - Run Rust e2e test harness (36 tests, mock backend, ~30s)
- `just test-e2e-s3` - E2E tests with S3/Minio (requires Docker)
- `just test-e2e-full` - All e2e tests (mock + S3)
- `just test-e2e-lattice` - Legacy bash e2e with lattice backend (~3 min, post-quantum)

### Development Environment
- `just minio-up` - Start Minio for S3 development
- `just minio-down` - Stop Minio
- Minio console: http://localhost:9001 (minioadmin/minioadmin)

### Release Management
- `just version` - Show current version
- `just release X.Y.Z` - Create tagged release

## Architecture

### Workspace Structure
```
recrypt/
├── crates/
│   ├── recrypt-ffi/          # OpenFHE + liboqs FFI bindings
│   ├── recrypt-openfhe-sys/  # Low-level OpenFHE bindings
│   ├── recrypt-core/         # Core crypto operations (hybrid encryption)
│   ├── recrypt-wire/         # Wire protocol (Gordian Envelope + Bao verification)
│   ├── recrypt-storage/      # S3-compatible storage client
│   └── identikey-storage-auth/ # Auth service for storage access
├── recrypt-server/           # Recryption proxy server (Axum)
├── recrypt-cli/              # Command-line interface
├── tests/e2e/                # E2E test harness (recrypt-e2e-tests)
└── docs/                     # Design documents
```

### Key Design Principles

**Hybrid Encryption (KEM-DEM):**
- PRE-encrypt a 256-bit symmetric key (KEM)
- XChaCha20 + Bao encrypt bulk data (DEM)
- Only the wrapped key (~KB) is recrypted, not the file

**Pluggable PRE Backends:**
- OpenFHE BFV (post-quantum, default)
- EC-based backends available (classical)

**Storage Architecture:**
- Content-addressed S3-compatible storage
- Separate auth service controls access by public key → file hash
- Recryption proxy holds recryption keys (semi-trusted)

**Cryptographic Standards:**
- Blake3 for all hashing (4-8x faster than Blake2b)
- Blake3/Bao tree mode for streaming verification
- ED25519 (classical) + ML-DSA-87 (post-quantum) signatures
- Multi-signature authorization pattern

### Critical Implementation Details

**Non-Determinism:** OpenFHE operations have non-deterministic serialization. Tests validate semantic correctness (`decrypt(encrypt(x)) == x`), not byte equality.

**Thread Safety:** Tests run with `--test-threads=1` due to OpenFHE global state. The recryption proxy handles this by keeping crypto context immutable after setup.

**FFI Bindings:** Complex C++ integration with OpenFHE. Use `crates/recrypt-openfhe-sys` for low-level bindings, `recrypt-ffi` for safe Rust API.

## Common Development Tasks

### Adding New Tests
- Place OpenFHE-related tests in sequential crates (`--test-threads=1`)
- Use property-based testing with `proptest` for crypto operations
- Test semantic properties, not exact byte output

### Working with Cryptography
- Always use `HybridEncryptor` for file encryption (never raw PRE)
- Keep crypto contexts alive for related operations
- Use `MockBackend` for fast testing, lattice backend for integration tests

### Storage Development
- Use `just minio-up` for local S3 development
- Auth service provides capabilities for hash-based access control
- Files are content-addressed by Blake3 hash

### CLI Development
- Wallet is password-encrypted (Argon2id + XChaCha20-Poly1305), keys stored as raw bytes
- Active identity stored per-wallet (not in global config)
- Wallet key cached in OS keychain, keyed by wallet path hash
- Config dir overridable via `RECRYPT_CONFIG_DIR` env var (test isolation)
- Keychain bypass via `RECRYPT_NO_KEYCHAIN=1` (CI/testing)
- Use `recrypt identity new` to create test identities

## Testing Strategy

### Unit Tests
- Each crate has comprehensive unit tests
- Property-based testing for crypto operations
- Mock backends for fast iteration

### Integration & E2E Tests
- Rust e2e harness at `tests/e2e/` (36 tests: 19 CLI + 17 API)
- CLI tests: identity CRUD, account, encrypt/decrypt, file lifecycle, share commands
- API tests: share lifecycle, recryption roundtrip, multi-recipient, auth boundary, nonce replay
- S3 tests: feature-gated (`--features s3-tests`), requires Docker/Minio
- Each test gets isolated temp dir, ephemeral port, SQLite, `RECRYPT_CONFIG_DIR` + `RECRYPT_NO_KEYCHAIN`

### Performance Tests
- Benchmark baselines established in Phase 2
- E2e harness (mock): ~30 seconds for full suite
- Lattice backend: ~3 minutes for legacy bash E2E test

## Terminology

**Consistent throughout codebase:**
- "Recrypt" (capitalized) when naming the project; lowercase `recrypt` only for the CLI command, crate names, and the operation noun ("recrypt key"). Never "ReCrypt".
- "Recryption" (not "re-encryption")
- "Recryption key" (not "rekey" or "re-encryption key")
- "Recrypted" (data that has undergone recryption)

## Dependencies

### Core Crypto
- `cxx` - C++/Rust FFI for OpenFHE
- `oqs` v0.11 - Post-quantum signatures via liboqs
- `ed25519-dalek` - ED25519 signatures
- `blake3` - Standardized hashing

### Infrastructure
- `tokio` - Async runtime
- `axum` - HTTP server framework
- `aws-sdk-s3` - S3 client
- `bc-envelope` - Gordian Envelope serialization (dCBOR wire format)
- `figment` - Server configuration (TOML + env vars)
- `clap` - CLI framework
- `serde` - Config serialization

### Development
- `proptest` - Property-based testing
- `criterion` - Benchmarking (when needed)
- `thiserror` - Error handling

## Important Notes

- **OpenMP Required:** Install with `brew install libomp` on macOS for parallel operations
- **Sequential Tests:** Always run OpenFHE tests with `--test-threads=1`
- **Clean Slate:** No compatibility with Python prototype (intentional)
- **Security First:** Never expose secret keys or plaintext in logs/commits
- **Git Submodules:** OpenFHE and other deps are in `vendor/` as submodules

## Licensing

Per-crate split (authoritative: `license` field in each crate's Cargo.toml, map in `LICENSE`):
- Core library crates (`recrypt-core`, `recrypt-ffi`, `recrypt-openfhe-sys`, `recrypt-wire`, `recrypt-storage`, `recrypt-client`): **Apache-2.0 OR BSD-2-Clause-Patent** — publishable to crates.io, embeddable anywhere; both options carry a mandatory patent grant (never add an MIT election — see identikey-core's licensing-and-commons doctrine, Gap 2).
- Deployable stack (`recrypt-server`, `recrypt-cli`, `identikey-storage-auth`): **AGPL-3.0-or-later**, with a commercial license from Identikey Inc. as the carve-out (`LICENSE-COMMERCIAL.md`).
- Permissive crates must never depend on AGPL crates. New library crates inherit the workspace default (Apache-2.0 OR BSD-2-Clause-Patent); new services/binaries get an explicit `license = "AGPL-3.0-or-later"`.
- Identity-protocol code (wallet engine, hardware-backed auth) lives in the separate [identikey-protocol](https://github.com/identikey/identikey-protocol) repo; `recrypt-cli` consumes `identikey-wallet` as a git dependency and layers PRE key material on top via the `WalletIdentity` trait (`recrypt-cli/src/wallet/mod.rs`).
- Contributions require the CLA (`CLA.md`), which enables the dual licensing.
- Context: Shift Grants (EF d/acc) funded — the permissive core is the grant-funded public good.

## Decisions

Architectural and process decisions live in [`docs/decisions/`](docs/decisions/).
Read that directory before relitigating questions like:

- Wallet identity envelope vs. unified codegen schema (D-1)
- TS client distribution model (D-2)
- Capability tokens vs. RBAC; field-scoped recryption; issuance-derived
  provenance (D-5) — the recryption key *is* the bearer token

Each doc states the decision, rationale, alternatives considered, and
the reversal triggers that should reopen the question. If you're about
to make an architectural choice that has long-tail implications, leave
a doc behind in the same shape.

## Phase Status (Current: Phase 8)

✅ **Completed Phases:**
- Phase 0: Planning & Specification
- Phase 1: FFI Bindings (OpenFHE + liboqs)
- Phase 2: Core Cryptography
- Phase 3: Protocol Layer
- Phase 4: Storage Layer
- Phase 4b: Storage Auth Service
- Phase 5: Recryption Proxy Server
- Phase 6: CLI Application
- Phase 6b: Secure Credential Storage

🔄 **Current Phase 8:** Documentation, Wire Format & Deployment
- User guide complete (`docs/user-guide.md`)
- Gordian Envelope migration in progress (wire format, wallet format)
- E2E test harness built (`tests/e2e/`, 36 tests)
- Wallet format migrated to raw bytes (no more base58/base64 key encoding)
- API documentation needed
- Deployment guide needed

📋 **Next Phase 9:** Security Audit Prep
- Security audit preparation
- Gordian Envelope migration completion

## Issue tracking and agent workflow

See [AGENTS.md](AGENTS.md) for the canonical agent-facing instructions
(issue tracking via `bd`, session-close protocol, non-interactive
shell conventions). The `SessionStart` and `PreCompact` hooks in
`.claude/settings.json` re-prime that context automatically.
