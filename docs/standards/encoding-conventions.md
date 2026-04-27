# Encoding Conventions

**Status:** Stable
**Date:** 2026-04-27
**Scope:** Every place a byte sequence crosses a text boundary anywhere in recrypt.

---

## 1. The boundary rule

There are exactly two regimes:

- **Inside CBOR / Gordian Envelope payloads** (wire, wallet body, exported identity, signed messages): everything is **raw bytes** (CBOR major type 2). No base58, no base64, no hex, no JSON arrays. The dCBOR rules in [dcbor-determinism.md](dcbor-determinism.md) require byte-identical re-serialization, and any text wrapping breaks that contract.

- **At text boundaries** (HTTP headers, HTTP JSON bodies, console output, URL path segments, error messages, log lines): use the table in §2.

There is no third regime. JSON-with-byte-arrays is not a wire format.

## 2. Text encodings

| Use case                                                                                 | Encoding                  | Why                                                                       |
|------------------------------------------------------------------------------------------|---------------------------|---------------------------------------------------------------------------|
| Short stable identifiers (≤ 256 bytes): public keys, fingerprints, file hashes, share IDs | **base58**                | Compact, no padding, URL-safe, easy to read and visually compare          |
| Variable-length opaque blobs (> 256 bytes or runtime-variable): signatures, ML-DSA keys, lattice PRE keys, recryption keys, ciphertexts | **base64 standard** (RFC 4648, with padding) | Linear-time encoding; base58 is O(n²) and gets painful past a few KB     |
| Diagnostic dumps (CBOR diagnostic notation, debug logs, error details)                   | **hex (lowercase)**       | Direct byte-to-nibble mapping; matches CBOR-diag conventions              |
| Naturally textual values (identity name, backend ID, format-version, type tag)           | **utf-8 string** (or native CBOR / JSON type) | These aren't bytes                                              |

**Rule of thumb for choosing between base58 and base64:** if a human will copy/paste it, base58. If a machine produces and consumes it, base64. The 256-byte cutoff exists because base58's bignum arithmetic is quadratic — a 5 KB ML-DSA key takes orders of magnitude longer to encode than the 5 KB itself warrants.

## 3. Forbidden encodings

- **JSON byte arrays** (`[1, 2, 3, …]`). Anywhere. If you find yourself reaching for one, the right answer is CBOR (envelope) or one of the text encodings above. Serde's default for `[u8; N]` produces these — guard against it with `#[serde(with = "…")]` or a wrapper type at any boundary that touches JSON.
- **base58 of multi-KB values.** O(n²). Use base64.
- **hex outside diagnostics.** 2× expansion vs ~1.33× for base64; no upside.
- **base32, ASCII85, hex variants (uppercase/0x-prefixed), custom encodings.** Not part of recrypt's vocabulary.

## 4. Specific values

This table is normative — when implementing a new boundary, check here first.

| Value                                | Size       | Inside CBOR | At text boundary |
|--------------------------------------|------------|-------------|------------------|
| ED25519 public key                   | 32 B       | raw bytes   | base58           |
| ED25519 secret key                   | 32 B       | raw bytes   | base58 (rare)    |
| ED25519 signature                    | 64 B       | raw bytes   | base64           |
| ML-DSA-87 public key                 | ~2.5 KB    | raw bytes   | **base64**       |
| ML-DSA-87 secret key                 | ~4.9 KB    | raw bytes   | **base64**       |
| ML-DSA-87 signature                  | ~4.6 KB    | raw bytes   | base64           |
| Fingerprint (Blake3 of ed25519 pk)   | 32 B       | raw bytes   | base58           |
| File hash (Blake3 of plaintext/file) | 32 B       | raw bytes   | base58           |
| PRE public key (mock)                | 32 B       | raw bytes   | base58           |
| PRE public key (lattice-bfv)         | multi-KB   | raw bytes   | **base64**       |
| PRE secret key (lattice-bfv)         | multi-KB   | raw bytes   | **base64**       |
| Recryption key (mock)                | small      | raw bytes   | base58           |
| Recryption key (lattice-bfv)         | multi-KB   | raw bytes   | **base64**       |
| KeyMaterial (96-byte fixed PRE blob) | 96 B fixed | raw bytes (not CBOR-wrapped — see [wire-protocol.md §"KeyMaterial"](../wire-protocol.md)) | base64 |
| Argon2id salt (wallet shell)         | 32 B       | raw bytes (in shell header, not CBOR) | n/a (never exposed) |
| XChaCha20-Poly1305 nonce             | 24 B       | raw bytes   | base64 (rare)    |
| Server auth nonce                    | server-defined string | n/a         | utf-8 (server returns a string)          |
| Identity name, type tag, backend ID  | utf-8      | utf-8 string | utf-8           |

## 5. Known violations

These exist in the codebase as of 2026-04-27 and must be migrated to base64:

- `recrypt-cli/src/client/api.rs:179` — `CreateShareRequest.recrypt_key` is base58-encoded. For the lattice backend the recryption key is multi-KB; encoding cost is quadratic. Tracked: `recrypt-jtw`.
- `docs/http-api-reference.md` §1.3 — `ml_dsa_pk` is base58 in the `CREATE` canonical message. Multi-KB; quadratic. Migrating requires a coordinated server/client change (protocol version bump). Tracked: `recrypt-fil`.

## 6. References

- [wire-protocol.md](../wire-protocol.md) — wire format (envelope + dCBOR)
- [wallet-envelope-format.md](wallet-envelope-format.md) — wallet body encoding
- [http-api-reference.md](../http-api-reference.md) — header & JSON-body encodings
- [hashing-standard.md](hashing-standard.md) — fingerprint / file-hash construction
- [dcbor-determinism.md](dcbor-determinism.md) — dCBOR rules for byte-identical serialization
- [RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648) — base64 / base32 / base16 specs
- [Base58 (Bitcoin)](https://en.bitcoin.it/wiki/Base58Check_encoding) — alphabet origin and rationale
