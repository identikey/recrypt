# Recrypt: Quantum-Resistant Proxy Recryption System

**Status:** Phase 8 — Documentation & Deployment (approaching 1.0)
**Version:** 0.1.0

---

## Overview

Recrypt is a quantum-resistant proxy recryption system enabling secure,
revocable file sharing with untrusted storage providers. Built on lattice-based
cryptography (OpenFHE) with post-quantum signatures (liboqs), it provides
end-to-end encryption where files can be shared without exposing private keys or
plaintext to any intermediary.

### Core ideas

**Proxy recryption.** A semi-trusted proxy transforms ciphertext encrypted for
Alice into ciphertext for Bob without ever decrypting it. The storage provider
facilitates sharing without access to plaintext, and access can be revoked
without re-encrypting the file.

**Hybrid encryption (KEM-DEM).** A 256-bit symmetric key is wrapped with the
post-quantum PRE backend (KEM); bulk data is encrypted with XChaCha20 + Bao
(DEM). Only the wrapped key (~KB) is recrypted on share — never the file itself.

**Pluggable PRE backends.** OpenFHE BFV is the post-quantum default; a `mock`
backend exists for fast testing.

---

## Quick start

### Build

```bash
just setup          # first time: submodules + C/C++ deps + build
just build-release  # subsequent release builds
```

See [Development](#development) for prerequisites.

### Use the CLI

```bash
# Create an identity (ED25519 + ML-DSA-87 keypair, stored in an encrypted wallet)
recrypt identity new

# Encrypt / decrypt locally (--for selects the recipient identity)
recrypt encrypt myfile.txt --for alice --output myfile.enc
recrypt decrypt myfile.enc --output myfile.txt

# Register an account and upload a file to the proxy
recrypt --server https://recrypt.example.com account register
recrypt --server https://recrypt.example.com file upload myfile.enc

# Share with a recipient (generates a recryption key for the proxy)
recrypt share create <file-hash> --to <recipient-pubkey>

# Recipient downloads; the proxy recrypts the wrapped key on the fly
recrypt share download <share-id> --output myfile.txt
```

Run `recrypt --help` (and `recrypt <command> --help`) for the full command set:
`identity`, `encrypt`, `decrypt`, `account`, `file`, `share`, `config`, `wallet`.

For a guided walkthrough see [`docs/user-guide.md`](docs/user-guide.md).

---

## Repository structure

```
recrypt/
├── crates/
│   ├── recrypt-ffi/            # Safe Rust API over OpenFHE + liboqs + ed25519
│   ├── recrypt-openfhe-sys/    # Low-level CXX bridge to OpenFHE C++
│   ├── recrypt-core/           # PRE backends, hybrid encryption, signatures
│   ├── recrypt-wire/           # Wire protocol (Gordian Envelope + Bao)
│   ├── recrypt-storage/        # S3-compatible content-addressed storage
│   ├── recrypt-storage-auth/ # Auth service (capabilities, ownership)
│   └── recrypt-client/         # Generated Rust HTTP client (from OpenAPI)
├── recrypt-server/             # Recryption proxy server (Axum)
├── recrypt-cli/                # Command-line interface
├── recrypt-client-ts/          # Generated TypeScript HTTP client
├── tests/e2e/                  # E2E test harness (36 tests)
├── docs/                       # Architecture, standards, decisions
└── vendor/                     # OpenFHE, liboqs (git submodules)
```

---

## Architecture

```
                      ┌──────────────────┐
                      │   recrypt-cli    │  workflows, wallet, HTTP client
                      └────────┬─────────┘
                               │ reqwest (HTTP)
                               ▼
                      ┌──────────────────┐
                      │  recrypt-server  │  Axum proxy, auth middleware, routes
                      └────────┬─────────┘
          ┌────────────────────┼──────────────────┐
          ▼                    ▼                  ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────────────┐
│   recrypt-core   │ │   recrypt-wire   │ │   recrypt-storage        │
│  crypto objects  │ │   wire format    │ │  content-addressed blobs │
└────────┬─────────┘ └──────────────────┘ └──────────────────────────┘
         ▼
┌──────────────────┐           ┌──────────────────────────┐
│   recrypt-ffi    │           │  recrypt-storage-auth  │
│  OpenFHE+liboqs  │           │  capabilities, ownership │
└────────┬─────────┘           └──────────────────────────┘
         ▼
┌────────────────────┐
│ recrypt-openfhe-sys│  raw CXX bridge to OpenFHE C++
└────────────────────┘
```

See [`docs/architecture.md`](docs/architecture.md) for per-crate ownership and
the full dependency graph.

### Crates

| Crate                    | Purpose                                      |
| ------------------------ | -------------------------------------------- |
| `recrypt-ffi`            | Safe Rust API over OpenFHE + liboqs          |
| `recrypt-openfhe-sys`    | Low-level CXX bridge to OpenFHE C++          |
| `recrypt-core`           | PRE backends, hybrid encryption, signatures  |
| `recrypt-wire`           | Wire protocol (Gordian Envelope + Bao)       |
| `recrypt-storage`        | S3-compatible content-addressed storage      |
| `recrypt-storage-auth` | Auth service for storage access              |
| `recrypt-client`         | Generated Rust HTTP client                   |

### Binaries & clients

| Component           | Purpose                                                   |
| ------------------- | -------------------------------------------------------- |
| `recrypt-server`    | Recryption proxy (holds recryption keys, never secrets)  |
| `recrypt-cli`       | Command-line interface                                    |
| `recrypt-client-ts` | Generated TypeScript client for the proxy API            |

Both HTTP clients are generated from the utoipa-annotated handlers in
`recrypt-server` (single source of truth → `openapi.json` → codegen). Regenerate
with `just openapi-regen`.

---

## Key features

### Cryptography
- **OpenFHE BFV** lattice-based proxy recryption (post-quantum)
- **ED25519** (classical) + **ML-DSA-87** (post-quantum) dual signatures
- **Multi-signature** authorization (all keys must sign)
- **Blake3** for all hashing; **Blake3/Bao** tree mode for streaming integrity
- **XChaCha20 + Bao** authenticated symmetric encryption

### Storage
- S3-compatible storage (Minio for dev, any S3 backend for prod)
- Content-addressed by Blake3 hash
- Separate auth service controls access by public key → file hash
- Chunked streaming for large files

### API & interfaces
- HTTP REST API (Axum) with OpenAPI schema
- CLI with encrypted wallet (Argon2id + XChaCha20-Poly1305), OS-keychain caching
- Generated Rust and TypeScript clients

---

## Security model

### Trust assumptions

| Component        | Trust level  | Notes                                            |
| ---------------- | ------------ | ------------------------------------------------ |
| Storage provider | Untrusted    | Sees only ciphertext + wrapped keys              |
| Recryption proxy | Semi-trusted | Has recryption keys, not secret keys; self-hostable |
| Auth service     | Trusted      | Controls access; can be self-hosted              |
| Client           | Trusted      | Holds secret keys                                |

### Cryptographic guarantees
- **E2E encryption** — plaintext never leaves the client
- **Quantum resistance** — lattice-based PRE + ML-DSA-87 signatures
- **Per-file keys** — fresh random symmetric key per file
- **Streaming integrity** — Blake3/Bao verification during download

See [`docs/threat-model.md`](docs/threat-model.md) and
[`docs/security-tiers.md`](docs/security-tiers.md) for the full model.

---

## Development

### Prerequisites
- Rust (stable, edition 2024)
- OpenFHE C++ library + liboqs (built via `just build-deps`; vendored as submodules)
- OpenMP — `brew install libomp` on macOS
- Docker (for the Minio S3 development environment)

### Common commands (via [Just](https://github.com/casey/just))

```bash
just build            # build the workspace
just test             # run all tests (--test-threads=1; OpenFHE global state)
just lint             # clippy
just format           # rustfmt
just test-e2e         # E2E harness (mock backend, ~30s)
just minio-up         # start Minio for S3 development
just openapi-regen    # regenerate Rust + TS clients from the server schema
```

### Testing
- Per-crate unit tests, with `proptest` property tests for crypto operations
- E2E harness at `tests/e2e/` — 36 tests (19 CLI + 17 API), ~30s on the mock backend
- S3 tests gated behind `--features s3-tests` (requires Docker/Minio)
- Tests validate **semantic** correctness (`decrypt(encrypt(x)) == x`), not byte
  equality — OpenFHE serialization is non-deterministic. See
  [`docs/non-determinism.md`](docs/non-determinism.md).

---

## Documentation

Start with [`docs/architecture.md`](docs/architecture.md) for the system
overview, then [`docs/user-guide.md`](docs/user-guide.md) for usage.

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
| `docs/http-api-reference.md`             | HTTP API reference                     |
| `docs/deployment.md`                     | Deployment guide                       |

### Standards (interop specs)

| Document                                    | Description                      |
| ------------------------------------------- | -------------------------------- |
| `docs/standards/recrypt-key-material-v1.md` | Key material serialization       |
| `docs/standards/xchacha20-bao-aead.md`      | Streaming AEAD construction       |
| `docs/standards/wallet-envelope-format.md`  | Encrypted wallet envelope format |
| `docs/standards/identity-self-signature.md` | Identity self-signature shape    |
| `docs/standards/dcbor-determinism.md`       | dCBOR interop contract           |
| `docs/standards/hashing-standard.md`        | Blake3 standardization           |

Architectural decisions live in [`docs/decisions/`](docs/decisions/); read them
before relitigating long-tail design questions.

---

## Terminology

- **Recryption** — transformation of ciphertext from one key to another (not "re-encryption")
- **Recryption key** — the key enabling that transformation (not "rekey")
- **Recrypted** — data that has undergone recryption

Standardized throughout the codebase.

---

## License

Recrypt uses a per-crate license split (see [LICENSE](LICENSE) for the full
map):

- **Core library crates** (`recrypt-core`, `recrypt-ffi`, `recrypt-openfhe-sys`,
  `recrypt-wire`, `recrypt-storage`, `recrypt-client`) — permissively licensed
  under **[Apache-2.0](LICENSE-APACHE) OR
  [BSD-2-Clause-Patent](LICENSE-BSD-2-CLAUSE-PATENT)**, your choice; both carry
  a mandatory patent grant. Use them anywhere, commercially or otherwise.
  (Identity-protocol crates live in
  [identikey-protocol](https://github.com/identikey/identikey-protocol).)
- **Deployable stack** (`recrypt-server`, `recrypt-cli`,
  `recrypt-storage-auth`) — **[AGPL-3.0-or-later](LICENSE-AGPL)**, free for
  any use that complies with its source-sharing terms (including the network
  clause, §13). A **commercial license** from **Identikey Inc.** is available
  for closed products and services — see
  [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md) or contact
  [sales@identikey.io](mailto:sales@identikey.io).

Contributions are accepted under the [CLA](CLA.md).

Vendored third-party dependencies under `vendor/` (e.g. OpenFHE, liboqs) remain
under their own licenses.

---

## Links

- **Website**: [identikey.io/recryption](https://identikey.io/recryption)
- **Repository**: [github.com/identikey/recrypt](https://github.com/identikey/recrypt)
