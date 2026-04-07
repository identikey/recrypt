# Recrypt Server HTTP API Reference

This document is the authoritative reference for the HTTP surface of
`recrypt-server`. Client implementations should treat the canonical signature
message format strings, header names, and encodings below as the
specification — they are load-bearing and any drift breaks interoperability.

For an overview of the system, see [architecture.md](architecture.md).
For the wire format of request/response bodies, see
[wire-protocol.md](wire-protocol.md).

---

## 1. Authentication model

### 1.1 Dual-stack multi-signature (ED25519 + ML-DSA-87)

Every protected endpoint requires **two signatures over the same canonical
message**: a classical ED25519 signature and a post-quantum ML-DSA-87
signature. The server verifies both independently. Either signature failing
causes the request to be rejected.

This dual-stack scheme is a deliberate hybrid security posture:

- **ED25519** — well-understood, fast, small (64 bytes), broken by sufficiently
  large quantum computers.
- **ML-DSA-87** (NIST FIPS 204, Dilithium Level 5) — post-quantum secure,
  large (~4 KB signatures), newer primitive with less cryptanalytic history.

We require **both** so an attacker must defeat **both** schemes to forge a
request. If ED25519 is ever broken by a quantum adversary, ML-DSA-87 still
protects us; if ML-DSA-87 turns out to have a classical weakness, ED25519 still
protects us. See [threat-model.md](threat-model.md) §4 (Adv-Q).

### 1.2 Required headers

All protected endpoints require the following headers:

| Header               | Value                                      | Encoding        |
| -------------------- | ------------------------------------------ | --------------- |
| `X-Public-Key`       | Requester's fingerprint                    | base58          |
| `X-Nonce`            | Fresh nonce string from `GET /nonce`       | plain UTF-8     |
| `X-Signature-Ed25519`| 64-byte ED25519 signature over the message | base64 standard |
| `X-Signature-MlDsa`  | ML-DSA-87 signature over the message       | base64 standard |

The fingerprint is computed as
`bs58::encode(blake3::hash(ed25519_public_key_bytes))`.

### 1.3 Canonical signature message format

The message that both signatures cover is a **UTF-8 string**, not binary, built
from action-specific templates. Fields are separated by a single colon (`:`).
Missing optional fields are represented by an empty substring (`::`). The
trailing field is always the nonce string exactly as it appears in the
`X-Nonce` header.

| Endpoint                              | Verb  | Canonical message template                                                |
| ------------------------------------- | :---: | -------------------------------------------------------------------------- |
| `POST   /accounts`                    | `CREATE`      | `CREATE:{ed25519_pk}:{ml_dsa_pk}:{pre_pk}:{nonce}`               |
| `POST   /files`                       | `UPLOAD`      | `UPLOAD:{fingerprint}:{file_hash}:{nonce}`                       |
| `DELETE /files/{hash}`                | `DELETE`      | `DELETE:{fingerprint}:{file_hash}:{nonce}`                       |
| `POST   /recryption/share`            | `SHARE`       | `SHARE:{from_fingerprint}:{to_fingerprint}:{file_hash}:{nonce}`  |
| `GET    /recryption/share/{id}/file`  | `DOWNLOAD`    | `DOWNLOAD:{requester_fingerprint}:{share_id}:{nonce}`            |
| `DELETE /recryption/share/{id}`       | `REVOKE`      | `REVOKE:{requester_fingerprint}:{share_id}:{nonce}`              |
| `GET    /accounts/{fp}/shares`        | `LIST_SHARES` | `LIST_SHARES:{fingerprint}:{nonce}`                              |

**Field encodings** (used in both the body/path values and the canonical
message string):

- `ed25519_pk`, `ml_dsa_pk`, `pre_pk` — base58-encoded raw public-key bytes
- `fingerprint`, `from_fingerprint`, `to_fingerprint`, `requester_fingerprint`
  — base58 of `blake3(ed25519_pk_bytes)`
- `file_hash` — base58 of `blake3(ciphertext_bytes)`
- `share_id` — base58 of `blake3("{from}:{to}:{file_hash}")`
- `nonce` — plain `{unix_ms}:{uuid}` string, not re-encoded

A CLI-side reference implementation of message construction and signing lives
in `recrypt-cli/src/client/auth.rs`; the server-side verification lives in
`recrypt-server/src/middleware/auth.rs` and each route's handler.

### 1.4 Nonce validation and replay prevention

Nonces are obtained from `GET /nonce` (see §3.1) and have the format
`{unix_ms}:{uuid}` — a Unix timestamp in milliseconds joined to an RFC 4122
UUID v4 by a colon.

The server enforces:

1. **Freshness** — the timestamp must be within `nonce.window_secs` seconds
   in the past (default: 300 s / 5 min) and no more than 60 s in the future
   (clock-skew tolerance).
2. **Single use** — a nonce that has been successfully used is rejected on
   reuse.

The nonce store is **in-memory only** in the current implementation. A server
restart clears the replay window. This is acceptable for the Phase 5 MVP but
should be addressed before production.

### 1.5 Error responses

All errors return a JSON body `{"error": "<message>"}` with an appropriate
HTTP status:

| Status | Variant                            | Meaning                                              |
| -----: | ---------------------------------- | ---------------------------------------------------- |
| 400    | `BadRequest` / `NonceInvalid`      | Missing header, malformed encoding, expired nonce    |
| 401    | `Unauthorized` / `SignatureInvalid`| Signature verification failed or caller unauthorized |
| 404    | `NotFound`                         | Account, file, or share does not exist               |
| 409    | `Conflict`                         | Resource already exists                              |
| 500    | `Internal`                         | Server-side failure (storage, serialization, crypto) |

---

## 2. Endpoint reference

### 2.1 Health & nonce (public)

#### `GET /health`
Returns server health. Takes no auth. Response body:

```json
{ "status": "ok", "version": "0.1.0" }
```

#### `GET /nonce`
Issues a fresh nonce. Takes no auth. Response body:

```json
{
  "nonce": "1680000000123:550e8400-e29b-41d4-a716-446655440000",
  "expires_at": 1680000300
}
```

`expires_at` is Unix seconds.

---

### 2.2 Accounts

#### `POST /accounts` — Create account

- **Auth:** required. Canonical message:
  `CREATE:{ed25519_pk}:{ml_dsa_pk}:{pre_pk}:{nonce}`
- **Request body (JSON):**
  ```json
  {
    "ed25519_pk": "<base58 32-byte key>",
    "ml_dsa_pk":  "<base58 ML-DSA-87 public key>",
    "pre_pk":     "<base58 PRE public key, optional>"
  }
  ```
- **Response: 201 Created**
  ```json
  {
    "fingerprint": "<base58>",
    "ed25519_pk":  "<base58>",
    "ml_dsa_pk":   "<base58>",
    "pre_pk":      "<base58 | null>",
    "created_at":  1680000000
  }
  ```
- **Errors:** `400` (malformed), `409` (already exists).

#### `GET /accounts/{fingerprint}` — Fetch account

- **Auth:** none.
- **Response: 200 OK** — same shape as `POST /accounts` response.
- **Errors:** `404` if the account does not exist.

#### `GET /accounts/{fingerprint}/files` — List files owned by account

- **Auth:** none.
- **Response: 200 OK**
  ```json
  [ { "hash": "<base58>" }, { "hash": "<base58>" } ]
  ```

#### `GET /accounts/{fingerprint}/shares` — List shares for account

- **Auth:** required. Canonical message: `LIST_SHARES:{fingerprint}:{nonce}`.
  The caller's `X-Public-Key` fingerprint must match the path `fingerprint`.
- **Response: 200 OK**
  ```json
  {
    "outgoing": [
      {
        "share_id": "<base58>",
        "from_fingerprint": "<base58>",
        "to_fingerprint":   "<base58>",
        "file_hash":        "<base58>",
        "created_at":       1680000000
      }
    ],
    "incoming": [ /* ... */ ]
  }
  ```

---

### 2.3 Files

#### `POST /files` — Upload

- **Auth:** required. Canonical message:
  `UPLOAD:{fingerprint}:{file_hash}:{nonce}`.
- **Request body:** raw binary ciphertext (not JSON). Typically a
  protobuf-encoded `EncryptedFileProto` — see
  [wire-protocol.md](wire-protocol.md) — but the server stores it as an
  opaque blob. Content-Type should be `application/octet-stream`.
- **Hash derivation:** the client must compute `file_hash =
  bs58(blake3(body))` and include it in the signature message. The server
  recomputes and rejects any mismatch.
- **Response: 201 Created**
  ```json
  { "hash": "<base58>", "size": 1024 }
  ```
- **Side effect:** the account identified by `X-Public-Key` is registered as
  the owner of this file hash.

#### `GET /files/{hash}` — Download

- **Auth:** none. Ciphertexts are public; confidentiality is provided by
  the encryption itself. This does leak metadata (existence, size); see
  [threat-model.md](threat-model.md) §4.
- **Response: 200 OK** — raw binary with
  `Content-Type: application/octet-stream`,
  `X-Content-Hash: <base58>`.
- **Errors:** `404` if the hash is unknown.

#### `DELETE /files/{hash}` — Delete

- **Auth:** required. Canonical message:
  `DELETE:{fingerprint}:{file_hash}:{nonce}`.
- **Authorization:** the caller's fingerprint must match the registered
  owner.
- **Response: 204 No Content.**
- **Errors:** `401` if not the owner, `404` if unknown.

---

### 2.4 Recryption / shares

#### `POST /recryption/share` — Create share

- **Auth:** required. Canonical message:
  `SHARE:{from_fingerprint}:{to_fingerprint}:{file_hash}:{nonce}`.
- **Request body (JSON):**
  ```json
  {
    "to_fingerprint": "<base58>",
    "file_hash":      "<base58>",
    "recrypt_key":    "<base58 serialized RecryptKey>",
    "backend_id":     "mock | lattice"
  }
  ```
  `backend_id` must match the PRE backend the recrypt key was generated with.
- **Response: 201 Created**
  ```json
  {
    "share_id":  "<base58>",
    "from":      "<base58>",
    "to":        "<base58>",
    "file_hash": "<base58>",
    "created_at": 1680000000
  }
  ```
  The `share_id` is `bs58(blake3("{from}:{to}:{file_hash}"))`.

#### `GET /recryption/share/{id}/file` — Download recrypted file

- **Auth:** required. Canonical message:
  `DOWNLOAD:{requester_fingerprint}:{share_id}:{nonce}`.
- **Authorization:** the caller's fingerprint must equal the share's
  `to_fingerprint`.
- **Server side transform:**
  1. Look up the share policy, backend, and recrypt key.
  2. Fetch the ciphertext blob from `ChunkStorage`.
  3. Deserialize as protobuf `EncryptedFileProto` →
     `recrypt_core::EncryptedFile`.
  4. Call `HybridEncryptor::recrypt(&recrypt_key, &encrypted)` — this
     transforms **only** `wrapped_key`; `ciphertext`, `bao_hash`, and
     `bao_outboard` are forwarded byte-for-byte.
  5. Reserialize to protobuf and return the bytes.
- **Response: 200 OK**
  - `Content-Type: application/octet-stream`
  - `X-Recrypted: true`
  - `X-Backend: mock | lattice`
  - `X-Share-Id: <base58>`
  - body: recrypted protobuf `EncryptedFileProto`

#### `DELETE /recryption/share/{id}` — Revoke share

- **Auth:** required. Canonical message:
  `REVOKE:{requester_fingerprint}:{share_id}:{nonce}`.
- **Authorization:** the caller must equal the share's `from_fingerprint`.
- **Response: 204 No Content.** The recrypt key is atomically removed from
  the server's in-memory store. See [threat-model.md](threat-model.md) §6
  for notes on eventual-consistency concerns between revoke and concurrent
  downloads.

---

## 3. Client implementation checklist

1. **Fetch nonce** — `GET /nonce`, keep the `nonce` field.
2. **Compute fingerprint** — `bs58(blake3(ed25519_pk_bytes))`.
3. **Build canonical message** — interpolate from the table in §1.3 using
   the exact field encodings specified. Do **not** add whitespace, quoting,
   or re-encoding.
4. **Sign twice** — ED25519 over the message bytes (UTF-8), ML-DSA-87 over
   the same bytes. Base64-encode both.
5. **Set headers** — `X-Public-Key`, `X-Nonce`, `X-Signature-Ed25519`,
   `X-Signature-MlDsa`.
6. **Send request** — with the method, path, and body from §2.
7. **On 400 "nonce"** — re-fetch a nonce and retry exactly once.
8. **On 401** — do not retry; the signature is wrong or the caller is not
   authorized.
9. **On 409** — the resource exists; treat as terminal.

---

## 4. Worked example: create account → upload → share → download

```
# 1. Alice creates an account
GET  /nonce                             → nonce₁
msg = "CREATE:{pk_ed}:{pk_ml}:{pk_pre}:" + nonce₁
POST /accounts
     X-Public-Key:       bs58(blake3(pk_ed_bytes))
     X-Nonce:            nonce₁
     X-Signature-Ed25519: b64(ed25519(msg))
     X-Signature-MlDsa:   b64(mldsa(msg))
     body: { "ed25519_pk": pk_ed, "ml_dsa_pk": pk_ml, "pre_pk": pk_pre }
                                        → 201 { "fingerprint": "alice_fp", ... }

# 2. Alice uploads an already-encrypted file
hash = bs58(blake3(ciphertext))
GET  /nonce                             → nonce₂
msg  = "UPLOAD:alice_fp:" + hash + ":" + nonce₂
POST /files (body = raw ciphertext)
                                        → 201 { "hash": hash, "size": N }

# 3. Alice shares with Bob
rk   = backend.generate_recrypt_key(alice_sk, bob_pk)
GET  /nonce                             → nonce₃
msg  = "SHARE:alice_fp:bob_fp:" + hash + ":" + nonce₃
POST /recryption/share
     body: {
       "to_fingerprint": "bob_fp",
       "file_hash":      hash,
       "recrypt_key":    bs58(rk.to_bytes()),
       "backend_id":     "lattice"
     }
                                        → 201 { "share_id": "sid", ... }

# 4. Bob downloads the recrypted file
GET  /nonce                             → nonce₄
msg  = "DOWNLOAD:bob_fp:sid:" + nonce₄
GET  /recryption/share/sid/file
                                        → 200 [recrypted protobuf bytes]
Bob: HybridEncryptor::decrypt(bob_sk, deserialized) → plaintext
```

---

## 5. Configuration knobs (server side)

Server configuration lives in `recrypt-server.toml` and/or environment
variables prefixed with `RECRYPT_`:

```toml
host = "127.0.0.1"
port = 7222

[storage]
backend    = "memory"         # "memory" | "local" | "s3"
local_path = "/var/lib/recrypt"  # for backend = "local"
s3_bucket  = "my-bucket"         # for backend = "s3"
s3_endpoint = "https://s3.example.com"

[nonce]
window_secs = 300             # replay window (seconds)

pre_backend = "lattice"       # "mock" | "lattice"
```

Notes:

- `pre_backend = "mock"` is fast but **not secure** — test-only.
- `pre_backend = "lattice"` takes ~2 minutes to initialize on startup and
  requires OpenFHE to be linked (`brew install libomp` on macOS).
- Storage backend `memory` is volatile and only appropriate for tests.
