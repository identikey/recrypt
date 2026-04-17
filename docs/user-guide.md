# Recrypt User Guide

**Quantum-resistant proxy recryption CLI**

Recrypt enables end-to-end encrypted file storage and sharing where files can be shared and revoked cryptographically—without ever sharing keys.

---

## Quick Start

```bash
# 1. Create your first identity
recrypt identity new --name alice

# 2. Configure your server
recrypt config set default_server http://localhost:7222

# 3. Register on the server
recrypt account register

# 4. Encrypt and upload a file
recrypt encrypt secret.txt --for alice --output secret.enc
recrypt file upload secret.enc

# 5. Share with Bob (who has registered)
recrypt share create <file-hash> --to <bob-fingerprint>
```

---

## Table of Contents

1. [Installation](#installation)
2. [Core Concepts](#core-concepts)
3. [Identity Management](#identity-management)
4. [Local Encryption](#local-encryption)
5. [Server Operations](#server-operations)
6. [File Sharing](#file-sharing)
7. [Configuration](#configuration)
8. [Environment Variables](#environment-variables)
9. [Output Formats](#output-formats)
10. [Wallet Security](#wallet-security)
11. [Troubleshooting](#troubleshooting)

---

## Installation

### From Source

```bash
cd recrypt
cargo build --release
# Binary at: target/release/recrypt
```

### Verify Installation

```bash
recrypt --version
recrypt --help
```

---

## Core Concepts

### Identities

An **identity** is a set of cryptographic keypairs:

- **ED25519** — Classical digital signatures
- **ML-DSA-87** — Post-quantum digital signatures
- **PRE** — Proxy re-encryption keys (enables sharing)

Each identity has a **fingerprint** (`blake3(ed25519_public_key)` → base58), which serves as your public identifier.

### Proxy Recryption

Traditional encryption: Alice encrypts for Bob, Bob decrypts. If Alice later wants Carol to access, she must re-encrypt with Carol's key.

**Proxy recryption**: Alice encrypts once. To share with Bob, she generates a _recrypt key_ (Alice→Bob). A proxy server can transform ciphertexts for Bob _without_ seeing the plaintext. Revocation = delete the recrypt key.

### Wallet

Your identities are stored in an encrypted **wallet** file:

- **macOS**: `~/Library/Application Support/io.identikey.recrypt/wallet.recrypt`
- **Linux**: `~/.local/share/recrypt/wallet.recrypt`
- **Windows**: `C:\Users\<user>\AppData\Roaming\identikey\recrypt\wallet.recrypt`

The wallet is encrypted with a password-derived key (Argon2id). On subsequent runs, the key is cached in your OS keychain (macOS Keychain, Linux Secret Service, Windows Credential Manager) so you don't have to re-enter it.

---

## Identity Management

### Create an Identity

```bash
# Auto-named (identity-1, identity-2, etc.)
recrypt identity new

# Named identity
recrypt identity new --name alice
```

The first identity created becomes the active identity.

### List Identities

```bash
recrypt identity list
```

Output:

```
Identities:
  ★ alice (2YzWq8...)
    bob (5XjKm9...)
```

The star (★) marks the active identity.

### Show Identity Details

```bash
# Active identity
recrypt identity show

# Specific identity
recrypt identity show --name bob
```

### Set Active Identity

```bash
recrypt identity use bob
```

The active identity is used for all operations unless overridden with `--identity`.

### Delete an Identity

```bash
recrypt identity delete bob
```

⚠️ **Warning**: This is irreversible. Export first if you might need it later.

### Export/Import Identities

```bash
# Export (includes secret keys!)
recrypt identity export alice --output alice-backup.json

# Import
recrypt identity import alice-backup.json --name alice-restored
```

⚠️ **Security**: Exported files contain secret keys. Protect them accordingly.

---

## Local Encryption

Encrypt and decrypt files locally without involving a server.

### Encrypt a File

```bash
# Encrypt for yourself
recrypt encrypt document.pdf --for alice

# Encrypt for another identity in your wallet
recrypt encrypt document.pdf --for bob

# Custom output path
recrypt encrypt document.pdf --for alice --output encrypted/document.enc
```

Default output: `<filename>.enc`

### Decrypt a File

```bash
# Uses active identity
recrypt decrypt document.enc

# Specific identity
recrypt decrypt document.enc --identity alice

# Custom output
recrypt decrypt document.enc --output restored.pdf
```

Default output: strips `.enc` suffix, or appends `.decrypted`

---

## Server Operations

### Configure Server

```bash
recrypt config set default_server http://localhost:7222
```

Or use the `--server` flag per-command:

```bash
recrypt account register --server http://prod.example.com:7222
```

### Register Account

Before uploading files or sharing, register your identity:

```bash
recrypt account register
```

This uploads your public keys to the server. Secret keys never leave your machine.

### Show Account

```bash
# Your account
recrypt account show

# Someone else's account (by fingerprint)
recrypt account show 2YzWq8...
```

### Upload Files

```bash
recrypt file upload document.enc
```

Returns the file hash (content address):

```
✓ Uploaded document.enc
  Hash: 4xNvKp9...
```

### Download Files

```bash
# To default path (<hash>.bin)
recrypt file download 4xNvKp9...

# Custom output
recrypt file download 4xNvKp9... --output document.enc
```

### List Your Files

```bash
recrypt file list
```

### Delete a File

```bash
recrypt file delete 4xNvKp9...
```

---

## File Sharing

The magic of proxy recryption: share encrypted files without re-encrypting or sharing keys.

### Share a File

```bash
# Get recipient's fingerprint first
recrypt account show <bob-fingerprint>

# Create share
recrypt share create <file-hash> --to <bob-fingerprint>
```

This:

1. Generates a recrypt key (your secret → Bob's public)
2. Uploads the recrypt key to the server
3. Returns a share ID

Bob can now download the file, and the server will transform the ciphertext so Bob can decrypt it.

### List Shares

```bash
# All shares
recrypt share list

# Only outgoing (files you shared)
recrypt share list --from

# Only incoming (files shared with you)
recrypt share list --to
```

### Download a Shared File

When someone shares a file with you:

```bash
recrypt share download <share-id>

# Custom output
recrypt share download <share-id> --output received.enc
```

The server applies the recrypt transformation, and you can decrypt with your own keys.

### Revoke a Share

```bash
recrypt share revoke <share-id>
```

The recrypt key is deleted. The recipient can no longer access the file (even if they previously downloaded it, they can't get new versions or re-download).

---

## Configuration

Configuration is stored in:

- **macOS**: `~/Library/Application Support/io.identikey.recrypt/config.toml`
- **Linux**: `~/.config/recrypt/config.toml`
- **Windows**: `C:\Users\<user>\AppData\Roaming\identikey\recrypt\config.toml`

### View Configuration

```bash
recrypt config show
```

### Set Configuration

```bash
recrypt config set <key> <value>
```

| Key               | Description                              | Example                   |
| ----------------- | ---------------------------------------- | ------------------------- |
| `default_server`  | Server URL for API operations            | `http://localhost:7222`   |
| `active_identity` | Active identity — managed via `recrypt identity use <name>`, not set directly | `alice` |
| `output_format`   | Default output format                    | `pretty` or `json`        |
| `wallet_path`     | Custom wallet file location              | `/path/to/wallet.recrypt` |
| `default_backend` | PRE backend for new identities           | `lattice` or `mock`       |

---

## Environment Variables

Override configuration with environment variables:

| Variable                 | Description                            |
| ------------------------ | -------------------------------------- |
| `RECRYPT_SERVER`         | Server URL                             |
| `RECRYPT_IDENTITY`       | Identity name                          |
| `RECRYPT_WALLET`         | Wallet file path                       |
| `RECRYPT_WALLET_PASSWORD`| Wallet password (for CI/scripting)     |
| `RECRYPT_BACKEND`        | PRE backend: `lattice` or `mock`       |
| `RECRYPT_DEBUG`          | Enable debug logging (`1` or `true`)   |
| `RECRYPT_CONFIG_DIR`     | Override config directory location (useful for testing/CI) |
| `RECRYPT_NO_KEYCHAIN`    | When set, disables OS keychain and uses in-memory credential storage |

Example:

```bash
RECRYPT_SERVER=http://prod:7222 recrypt file list
```

---

## Output Formats

### Pretty Output (Default)

Human-readable, colored output:

```bash
recrypt identity list
```

### JSON Output

Machine-readable JSON:

```bash
recrypt --json identity list
```

Or set as default:

```bash
recrypt config set output_format json
```

Useful for scripting:

```bash
recrypt --json identity show | jq '.fingerprint'
```

---

## Wallet Security

### Wallet Commands

```bash
# Unlock wallet (prompts for password, caches key)
recrypt wallet unlock

# Lock wallet (clears cached key)
recrypt wallet lock

# Check wallet status
recrypt wallet status

# Show wallet file path
recrypt wallet path
```

### Password Protection

Your wallet is encrypted with Argon2id key derivation. Choose a strong password.

### Key Caching

After entering your password once, the derived key is cached in your OS keychain:

- **macOS**: Keychain Access
- **Linux**: GNOME Keyring / KWallet via Secret Service API
- **Windows**: Credential Manager

Subsequent commands won't prompt for a password until you reboot or the cache expires.

### CI/Headless Usage

For automated environments, set the wallet password via environment variable:

```bash
export RECRYPT_WALLET_PASSWORD=your-wallet-password
recrypt identity list
```

⚠️ **Security**: Don't commit passwords to version control. Use secrets management.

### Backup Your Wallet

```bash
cp ~/Library/Application\ Support/io.identikey.recrypt/wallet.recrypt ./wallet-backup.recrypt
```

Or export individual identities:

```bash
recrypt identity export alice --output alice-backup.json
```

---

## Troubleshooting

### "No identity specified"

```bash
# Set an active identity
recrypt identity use alice

# Or specify per-command
recrypt --identity alice file list
```

### "Could not determine config directory"

Ensure your home directory is accessible. On unusual systems, use explicit paths:

```bash
RECRYPT_WALLET=/tmp/wallet.recrypt recrypt identity new
```

### "Failed to decrypt wallet (wrong password?)"

The cached key may be stale. Clear it and re-enter your password:

- **macOS**: Delete "recrypt-wallet-key" in Keychain Access
- **Linux**: Use `secret-tool clear service recrypt`

### "Connection refused" / Server errors

1. Check server is running: `curl http://localhost:7222/health`
2. Verify URL: `recrypt config show`
3. Check network/firewall

### "Recipient has no PRE public key"

The recipient must have registered their account before you can share with them:

```bash
# Recipient runs:
recrypt account register
```

---

## Common Workflows

### End-to-End Encrypted File Sharing

**Alice (sender):**

```bash
# Setup
recrypt identity new --name alice
recrypt config set default_server http://server:7222
recrypt account register

# Encrypt and upload
recrypt encrypt secret.pdf --for alice
recrypt file upload secret.pdf.enc
# → Hash: 4xNvKp9...

# Share with Bob (get his fingerprint first)
recrypt share create 4xNvKp9... --to 5XjKm9...
# → Share ID: abc123
```

**Bob (recipient):**

```bash
# Setup
recrypt identity new --name bob
recrypt config set default_server http://server:7222
recrypt account register

# Download shared file
recrypt share list --to
# → Share ID: abc123
recrypt share download abc123 --output secret.enc

# Decrypt
recrypt decrypt secret.enc --output secret.pdf
```

**Alice (revoke access):**

```bash
recrypt share revoke abc123
# Bob can no longer access the file
```

---

## Command Reference

```
recrypt [OPTIONS] <COMMAND>

Options:
  --json              Output as JSON
  --identity <NAME>   Override active identity
  --server <URL>      Override server URL
  --wallet <PATH>     Override wallet path
  --backend <NAME>    PRE backend: "lattice" (default) or "mock"
  --debug             Enable debug logging
  -v, --verbose       Verbose output
  -h, --help          Print help
  -V, --version       Print version

Commands:
  identity   Manage identities (new, list, show, use, delete, export, import)
  encrypt    Encrypt a file locally
  decrypt    Decrypt a file locally
  account    Manage server account (register, show)
  file       Manage files on server (upload, download, list, delete)
  share      Manage file shares (create, list, download, revoke)
  config     Manage configuration (show, set)
  wallet     Manage wallet (unlock, lock, status, path)
```

---

**Questions?** Open an issue or check the API documentation in `docs/api-reference.md`.
