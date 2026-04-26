# Recrypt: Quantum-Resistant Proxy Recryption System

**Status:** 🚀 Implementation Phase  
**Version:** 2.0 (Rust)

---

## Overview

Recrypt is a production-ready proxy recryption system enabling secure, revocable file sharing with untrusted storage providers. Built on lattice-based cryptography (OpenFHE) with post-quantum signatures (liboqs), it provides end-to-end encryption where files can be shared without exposing private keys or plaintext.

### Core Innovation

**Proxy Recryption:** Transform ciphertext encrypted for Alice into ciphertext for Bob without ever decrypting. The storage provider facilitates sharing without accessing plaintext.

**Hybrid Encryption:** KEM-DEM architecture with pluggable PRE backends (lattice for post-quantum, EC for classical). Symmetric encryption (XChaCha20 + Bao) handles bulk data.

**Self-Correcting Identifiers:** HDprint provides human-readable identifiers that automatically correct typos and restore proper case from lowercase input.

---

## Current Status

### ✅ Phase 0: Planning — COMPLETE

- [x] Implementation plan (`docs/IMPLEMENTATION_PLAN.md`)
- [x] All design decisions documented
- [x] Workspace structure defined

### 🔲 Implementation Phases

| Phase | Description                                       | Status |
| ----- | ------------------------------------------------- | ------ |
| 1     | FFI Bindings (OpenFHE + liboqs)                   | 🔲     |
| 2     | Core Cryptography (PRE traits, hybrid encryption) | 🔲     |
| 3     | Protocol Layer (Gordian Envelope, Bao)             | 🔲     |
| 4     | Storage Client (S3-compatible)                    | 🔲     |
| 4b    | Auth Service (identikey-storage-auth)             | 🔲     |
| 5     | HDprint (parallelizable)                          | 🔲     |
| 6     | Recryption Proxy Server                           | 🔲     |
| 7     | CLI Application                                   | 🔲     |
| 8     | Minimal TUI                                       | 🔲     |

**Timeline:** 10-12 weeks to production-ready

---

## Repository Structure

```
recrypt/
├── README.md
├── docs/
│   ├── IMPLEMENTATION_PLAN.md    # 📋 Master plan - READ THIS FIRST
│   ├── hybrid-encryption-architecture.md
│   ├── pre-backend-traits.md
│   ├── storage-design.md
│   ├── wire-protocol.md
│   └── ...                       # Other design docs
│
├── python-prototype/             # 📦 ARCHIVED: Reference implementation
│   ├── src/recrypt/
│   ├── tests/
│   └── docs/
│
├── vendor/                       # Third-party dependencies
│   ├── openfhe-development/
│   ├── liboqs/
│   └── ...
│
└── [Rust workspace - Phase 1+]
    ├── crates/
    │   ├── recrypt-ffi/
    │   ├── recrypt-core/
    │   ├── recrypt-wire/
    │   ├── recrypt-storage/
    │   └── recrypt-hdprint/
    ├── recrypt-cli/
    ├── recrypt-server/
    ├── recrypt-tui/
    └── identikey-storage-auth/
```

---

## Quick Start (Coming Soon)

```bash
# Phase 1+: Build from source
cargo build --release

# Generate identity
recrypt identity new --output alice.json

# Encrypt file
recrypt encrypt myfile.txt --for <bob-pubkey> --output myfile.enc

# Share with Bob (generates recryption key)
recrypt share create <file-hash> --to <bob-pubkey>

# Bob downloads (server recrypts on-the-fly)
recrypt share download <share-id> --output myfile.txt
```

---

## Key Features

### 🔐 Cryptography

- **OpenFHE BFVrns** for lattice-based proxy recryption
- **ED25519** for classical signatures
- **ML-DSA-87** (mandatory) + optional PQ algorithms
- **Multi-signature** authorization (all keys must sign)

### 💾 Storage

- **S3-compatible** storage layer (Minio for dev, any S3 for prod)
- **Authenticated access** via file hash lookup
- **Chunked streaming** for large files
- **Content-addressed** storage

### 🎯 HDprint Identifiers

- **Error correction**: Automatically fixes single-character typos
- **Case restoration**: Type lowercase, get proper mixed-case
- **Hierarchical scaling**: 17.6 to 158+ bits security
- **Human-friendly**: Base58 encoding, visual separators

### 🌐 API & Interfaces

- **HTTP REST API** (Axum framework)
- **CLI application** with rich interactions
- **Minimal TUI** for visual operations

---

## Design Philosophy

### Key Decisions

| Area             | Decision                                           |
| ---------------- | -------------------------------------------------- |
| **Encryption**   | Hybrid KEM-DEM with pluggable PRE backends         |
| **Hashing**      | Blake3 everywhere (HMAC-SHA3-512 for HDprint only) |
| **Verification** | Blake3/Bao tree mode for streaming                 |
| **Wire format**  | Gordian Envelope (primary), ASCII armor (export)   |
| **Storage**      | Content-addressed S3 + auth service                |
| **Signatures**   | ED25519 (classical) + ML-DSA-87 (post-quantum)     |

### Changes from Python Prototype

| Removed             | Added                                 |
| ------------------- | ------------------------------------- |
| ECDSA/SECP256k1     | Pluggable PRE backends (lattice + EC) |
| Naive file storage  | S3-compatible + auth service          |
| Custom Merkle trees | Blake3/Bao streaming verification     |
| Mixed hashing       | Blake3 standardized                   |

**Clean Slate:** No compatibility with Python prototype (different serialization, no production deployments)

---

## Documentation

Start with [`docs/architecture.md`](docs/architecture.md) for the
system overview. Historical phase plans are in
[`docs/plans/archive/`](docs/plans/archive/).

### Design documents

| Document                                 | Description                            |
| ---------------------------------------- | -------------------------------------- |
| `docs/architecture.md`                   | System overview, per-crate ownership   |
| `docs/hybrid-encryption-architecture.md` | KEM-DEM with pluggable PRE backends    |
| `docs/pre-backend-traits.md`             | `PreBackend` trait hierarchy           |
| `docs/storage-design.md`                 | S3 + auth service architecture         |
| `docs/wire-protocol.md`                  | Gordian Envelope + ASCII armor formats |
| `docs/verification-architecture.md`      | Blake3/Bao streaming verification      |
| `docs/threat-model.md`                   | Threat model and security commitments  |
| `docs/security-tiers.md`                 | Security tier hierarchy                |
| `docs/non-determinism.md`                | Crypto testing strategy                |
| `docs/openfhe-threading-model.md`        | OpenFHE global-state threading rules   |

### Standards (interop specs)

| Document                                       | Description                                |
| ---------------------------------------------- | ------------------------------------------ |
| `docs/standards/recrypt-key-material-v1.md`    | Key material serialization                 |
| `docs/standards/xchacha20-bao-aead.md`         | Streaming AEAD construction                |
| `docs/standards/wallet-envelope-format.md`     | Encrypted wallet envelope format           |
| `docs/standards/identity-self-signature.md`    | Identity self-signature wire shape         |
| `docs/standards/dcbor-determinism.md`          | dCBOR interop contract                     |
| `docs/standards/hashing-standard.md`           | Blake3 standardization                     |

---

## Development

### Prerequisites

- Rust 1.75+ (stable)
- OpenFHE C++ library
- liboqs (post-quantum crypto)
- Docker (for Minio development environment)

### Python Prototype (Archived)

The original Python proof-of-concept is preserved in `python-prototype/` for reference. It demonstrated the feasibility of proxy recryption with post-quantum signatures and includes a full TUI implementation.

**To explore the prototype:**

```bash
cd python-prototype
# See python-prototype/README.md for setup instructions
```

**Note:** The Python implementation is archived and not actively maintained. All new development is in Rust.

---

## Terminology

- **Recryption**: Transformation of ciphertext from one key to another (not "re-encryption")
- **Recryption Key**: The key that enables recryption transformation (not "rekey" or "re-encryption key")
- **Recrypted**: Data that has undergone recryption transformation

This terminology is standardized throughout the Rust implementation.

---

## Architecture Highlights

### Crates

| Crate                    | Purpose                                     |
| ------------------------ | ------------------------------------------- |
| `recrypt-ffi`            | OpenFHE + liboqs FFI bindings               |
| `recrypt-core`           | PRE backends, hybrid encryption, signatures |
| `recrypt-wire`          | Wire protocol (Gordian Envelope + Bao)      |
| `recrypt-storage`        | S3-compatible storage client                |
| `recrypt-hdprint`        | Self-correcting identifiers                 |
| `identikey-storage-auth` | Auth service for storage access             |

### Binaries

| Binary           | Purpose                                                       |
| ---------------- | ------------------------------------------------------------- |
| `recrypt-server` | Recryption proxy (streams KEM ciphertext, holds recrypt keys) |
| `recrypt-cli`    | Command-line interface                                        |
| `recrypt-tui`    | Minimal terminal UI                                           |

---

## Security Model

### Trust Assumptions

| Component        | Trust Level  | Notes                                            |
| ---------------- | ------------ | ------------------------------------------------ |
| Storage provider | Untrusted    | Sees only ciphertext + wrapped keys              |
| Recryption proxy | Semi-trusted | Has recrypt keys, not secret keys; self-hostable |
| Auth service     | Trusted      | Controls access; can be self-hosted              |
| Client           | Trusted      | Holds secret keys                                |

### Cryptographic Guarantees

- **E2E Encryption**: Only key holders decrypt (plaintext never leaves client)
- **Quantum Resistance**: Lattice-based PRE + ML-DSA-87 signatures
- **Forward Secrecy**: Per-file random symmetric keys
- **Streaming Integrity**: Blake3/Bao verification during download

---

## Contributing

See [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md) for current phase and open tasks.

---

## License

[License TBD]

---

## Links

- **Website**: [identikey.io/recryption](https://identikey.io/recryption)

---

**→ [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md)** for full implementation details
