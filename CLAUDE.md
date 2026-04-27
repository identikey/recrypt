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

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:ca08a54f -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd dolt push
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->
