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
- `just test-e2e` - Run end-to-end recryption test (mock backend)
- `just test-e2e-lattice` - E2E test with lattice backend (slower, post-quantum)

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
- Identity files are password-encrypted JSON in `~/Library/Application Support/io.identikey.recrypt/`
- Wallet keys cached in system keychain (macOS/Linux/Windows)
- Use `recrypt-cli identity new` to create test identities

## Testing Strategy

### Unit Tests
- Each crate has comprehensive unit tests
- Property-based testing for crypto operations
- Mock backends for fast iteration

### Integration Tests
- E2E recryption flow (Alice → Bob sharing)
- S3 storage integration (requires Minio)
- CLI command validation

### Performance Tests
- Benchmark baselines established in Phase 2
- Mock backend: ~5 seconds for E2E test
- Lattice backend: ~3 minutes for E2E test

## Terminology

**Consistent throughout codebase:**
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
- `bc-envelope` - Gordian Envelope serialization (dCBOR)
- `clap` - CLI framework
- `serde` - Config/identity serialization

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

🔄 **Current Phase 8:** Documentation & Deployment
- User guide complete (`docs/user-guide.md`)
- API documentation needed
- Deployment guide needed

📋 **Next Phase 9:** E2E Testing & Security Audit Prep
- Full CLI-to-CLI via server testing
- Security audit preparation