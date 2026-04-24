# Identity Envelope Fixtures

Canonical binary fixtures for the `recrypt-wire` `Identity` type. Used by
`crates/recrypt-wire/tests/fixture_regenerate.rs` to enforce that the
envelope serialization format does not silently change between builds.

## Files

| File | Description |
|------|-------------|
| `identity-ed25519-only.envelope` | Minimal: ed25519 public key only, no secrets, no name, no created, no ml-dsa, no PRE |
| `identity-ed25519-only.json` | Metadata: fingerprint hex, byte length, assertions present/absent |
| `identity-hybrid-no-pre.envelope` | Dreamball-shaped: ed25519+ml-dsa keypairs, name, created, no PRE; contains unknown `dreamball-lineage` assertion |
| `identity-hybrid-no-pre.json` | Metadata |
| `identity-full.envelope` | Full recrypt: ed25519+ml-dsa keypairs, name, created, PRE backend=lattice-bfv |
| `identity-full.json` | Metadata |

## Seed Values

These are **format fixtures**, not crypto fixtures. The key bytes are
deterministic placeholders — they do not represent valid cryptographic material.

| Fixture | ed25519 seed | ml-dsa public | ml-dsa secret | PRE public | PRE secret |
|---------|-------------|----------------|----------------|------------|------------|
| ed25519-only | `[0x11; 32]` | — | — | — | — |
| hybrid-no-pre | `[0x22; 32]` | `[0xAA; 2592]` | `[0xBB; 4896]` | — | — |
| full | `[0x33; 32]` | `[0xAA; 2592]` | `[0xBB; 4896]` | `[0xCC; 64]` | `[0xDD; 64]` |

The ed25519 **public key** is derived from the seed via `SigningKey::from_bytes(seed).verifying_key()`.
The **fingerprint** is `Blake3(ed25519_public)`.

Fixed `created` timestamp: `1713652800` (2024-04-21 00:00:00 UTC).

## The hybrid-no-pre Unknown Assertion

This fixture is authored as a raw bc-envelope (not via `Identity::to_envelope_bytes`)
to simulate an externally-authored envelope from a Dreamball node. It contains:

```
"dreamball-lineage" → ByteString([0xDE, 0xAD, 0xBE, 0xEF])
```

After `Identity::from_envelope_bytes` parses it, the assertion is stored in
`unknown_assertions`. Re-emitting via `to_envelope_bytes` must produce byte-identical
CBOR, proving round-trip fidelity for third-party assertions.

## Regenerating

Run from the repo root:

```sh
cargo test -p recrypt-wire --test fixture_regenerate -- --ignored --nocapture
```

Then verify:

```sh
cargo test -p recrypt-wire --test fixture_regenerate
```

If the format spec changes (e.g. new mandatory field, dCBOR encoding rule change),
regenerate the fixtures and commit the new binary files alongside the spec change.
The JSON metadata files are the source of truth for what the tests assert.
