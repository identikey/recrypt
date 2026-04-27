# dCBOR Determinism: Interoperability Contract

**Status:** Spec  
**Date:** 2026-04-21  
**Scope:** Identity envelope serialization interop between Rust (`bc-envelope` 0.43.0) and Zig (hand-rolled dCBOR reader)  
**Reference:** [RFC 8949 §4.2.1 (Canonical CBOR)](https://datatracker.ietf.org/doc/html/rfc8949#section-4.2.1)

---

## 1. Overview

Both Rust and Zig implementations MUST produce **byte-identical** encoded output when serializing the same identity envelope. This document specifies the dCBOR rules that apply to identity envelopes and provides worked examples.

dCBOR is a strict subset of CBOR encoding that guarantees determinism through canonical rules on:
- Map key ordering
- Integer smallest-form encoding
- Float handling (not used in identity envelopes)
- String type discipline

---

## 2. Map Key Ordering

**Rule:** CBOR maps MUST have their keys sorted in **encoded-byte lexicographic order** (RFC 8949 §4.2.1).

Sort the CBOR-encoded form of each key, treating them as byte sequences, then compare lexicographically. This is **not** numeric order and **not** string-value order — it is the byte representation of the CBOR encoding.

### 2.1 Practical ordering for identity envelopes

In identity envelope subjects and assertions, keys are always UTF-8 text strings. A CBOR text string of length `n` (n < 24) encodes as `0x60 + n` followed by the UTF-8 bytes.

**Encoded forms of identity-envelope subject keys:**

| Key              | Length | First bytes (hex)     |
|------------------|-------:|-----------------------|
| `"type"`         |  4     | `64 74 79 70 65`      |
| `"fingerprint"`  | 11     | `6b 66 69 6e ...`     |
| `"format-version"` | 14   | `6e 66 6f 72 ...`     |
| `"ed25519-public"` | 14   | `6e 65 64 32 ...`     |

**Bytewise lexicographic sort** (compare byte-by-byte, starting from the length prefix):

1. `"type"` — first byte `0x64`, smallest.
2. `"fingerprint"` — first byte `0x6b`.
3. `"ed25519-public"` — first byte `0x6e`, second byte `0x65` (`'e'`).
4. `"format-version"` — first byte `0x6e`, second byte `0x66` (`'f'`).

For keys of differing length, the length byte (`0x60 + n`) dominates and short keys sort before long ones. For keys of the same length, the lexicographic order of their UTF-8 bytes decides.

**Identity envelope subject** emitted in deterministic order:
```
{ "type": "recrypt.identity",
  "fingerprint": h'...32 bytes...',
  "format-version": 1 }
```

**Implementation note:** The Rust `bc-envelope` library enforces this automatically. A Zig implementation MUST sort map keys in encoded-byte lex order before writing.

---

## 3. Integer Encoding: Smallest Form

**Rule:** Every integer MUST be encoded in the smallest CBOR form that represents its value.

| Value range        | Encoding form      | Example |
|--------------------|-------------------|---------|
| 0–23               | 1 byte: `0x00–0x17` | `1` → `0x01` |
| 24–255             | 2 bytes: `0x18 xx` | `24` → `0x18 0x18`, `255` → `0x18 0xff` |
| 256–65535          | 3 bytes: `0x19 xxyy` | `256` → `0x19 0x01 0x00` |
| 65536–4294967295   | 5 bytes: `0x1a xxyyzzzz` | `65536` → `0x1a 0x00 0x01 0x00 0x00` |
| ≥4294967296        | 9 bytes: `0x1b` + 8 bytes | rarely used in identity |

**Common error:** encoding `1` as `0x18 0x01` (2 bytes instead of 1 byte).

In identity envelopes, `format-version` is typically `1`, which encodes as `0x01` (single byte).

---

## 4. String Type: Byte-String vs Text-String

**Rule:** Distinguish between byte strings (CBOR major type 2) and text strings (CBOR major type 3):

- **Text string** (0x60–0x77 + UTF-8): used for predicates, names, backend identifiers
- **Byte string** (0x40–0x57 + raw bytes): used for key material, hashes, fingerprints

**Identity envelope examples:**
- `"type": "recrypt.identity"` → text string (major type 3)
- `"fingerprint": h'...'` → byte string (major type 2)
- `"ed25519-public": h'...'` → byte string (major type 2)
- `"name": "alice"` → text string (major type 3)

**Zig constraint:** When constructing maps, confirm the CBOR type (2 or 3) matches the field semantics. `bc-envelope` enforces this at the type level; hand-rolled decoders must validate it at parse time.

---

## 5. Float Handling (Not Used)

Identity envelopes do not include floating-point values. If a dCBOR encoder attempts to use floats, the specification rejects them as an error. CBOR tags for floats (major type 7, values 20–27) MUST NOT appear in identity envelopes.

---

## 6. Tagged Values

dCBOR permits CBOR tags (major type 6) for semantic labeling. Identity envelopes use the following tags:

| CBOR Tag | Role                        | Example            |
|----------|-----------------------------|--------------------|
| `#6.200` | Envelope wrapper            | Top level          |
| `#6.201` | Leaf subject (dCBOR map)    | Inside tag 200     |
| `#6.1`   | Epoch time (RFC 8949)       | In `"created"` assertions |

**Unknown tags are an error.** If a Zig decoder encounters a tag other than 200, 201, or 1, it MUST reject the envelope.

---

## 7. Assertion Ordering

Identity envelope assertions are emitted by the recrypt writer in a **fixed, predicate-alphabetical order** over string predicates. A Zig implementation MUST match this order byte-for-byte.

**Recrypt writer emission order for `recrypt.identity` assertions:**

1. `"created"` (if present)
2. `"ed25519-public"` (always present)
3. `"ed25519-secret"` (if present)
4. `"ml-dsa-public"` (if present)
5. `"ml-dsa-secret"` (if present)
6. `"name"` (if present)
7. `"pre-backend"` (if present)
8. `"pre-public"` (if present)
9. `"pre-secret"` (if present)
10. **Preserved unknown assertions** (any predicate not in the list above) — in the order they were read from the input envelope, appended after all known assertions.
11. `'signed'` assertions (bc-envelope KnownValue) — emitted last, after all other assertions.

### 7.1 Round-trip byte fidelity

A recrypt parser that reads an envelope containing unknown assertions (e.g., Dreamball's `"dreamball-lineage"`) MUST preserve those assertions in their original read order and re-emit them after the known-assertion block. This guarantees byte-identical round-trip for any envelope that conforms to rule 7.

### 7.2 Cross-encoder compatibility

If an encoder ignorant of rule 7 writes assertions in a different order (e.g., insertion order from a hash map), the resulting envelope is **semantically valid** but **not byte-identical** to a recrypt-emitted envelope of the same content. Fingerprint over subject is unaffected (the subject is a sorted map per §2); self-signatures over the subject digest are unaffected.

The canonical fixtures in `tests/fixtures/identity/` are the authoritative byte-level interop contract. Zig encoders MUST reproduce those bytes exactly.

---

## 8. Fingerprint Rule

**Fingerprint definition (immutable across all versions):**

```
fingerprint = Blake3(ed25519_public_32_bytes) = 32 raw bytes
```

No encoding, no base58, no hex — raw 32 bytes as a CBOR byte string.

Ed25519 is **mandatory**. The fingerprint algorithm is always defined because ed25519 is always present. All other key material (ML-DSA, PRE) is optional.

---

## 9. Worked Example

**Identity envelope: Minimal (ed25519-only)**

```
Semantic content:
{
  type: "recrypt.identity",
  format-version: 1,
  fingerprint: <32 bytes of Blake3(ed25519_public)>,
  name: "alice",
  created: <epoch seconds>,
  ed25519-public: <32 bytes>,
  ed25519-secret: <32 bytes>
}
```

**CBOR hex encoding** (dCBOR form):

```
d8c8                                    # Tag 200 (envelope)
  d8c9                                  # Tag 201 (leaf subject)
    a6                                  # Map with 6 items
      64                                # Text string, length 4
      7479706500                        # "type"
      77                                # Text string, length 23
      726563727970742e6964656e74697479 # "recrypt.identity"
      6f                                # Text string, length 15
      666f726d61742d76657273696f6e     # "format-version"
      01                                # Integer 1
      6b                                # Text string, length 11
      66696e67657270726e74              # "fingerprint"
      58 20                             # Byte string, length 32
      <32 bytes of fingerprint>
      64                                # Text string, length 4
      6e616d65                          # "name"
      65                                # Text string, length 5
      616c696365                        # "alice"
      67                                # Text string, length 7
      63726561746564                    # "created"
      d8 01                             # Tag 1 (epoch time)
        19                              # Unsigned integer, 2-byte form
        47c8                            # 18376 (example epoch)
  82                                    # Array with 2 items (2 assertions)
    a2                                  # Map with 2 items (assertion 1)
      6e                                # Text string, length 14
      6564323535313932332d7075626c6963 # "ed25519-public"
      58 20                             # Byte string, length 32
      <32 bytes of ed25519 public key>
    a2                                  # Map with 2 items (assertion 2)
      6e                                # Text string, length 14
      6564323535313932332d736563726574 # "ed25519-secret"
      58 20                             # Byte string, length 32
      <32 bytes of ed25519 secret key>
```

**Note:** Byte-level annotation of a complete fixture (`identity-ed25519-only.envelope`) will be added after task #3 lands.

---

## 10. Verification Checklist

When implementing a dCBOR encoder (Zig side):

- ✓ Map keys sorted by encoded-byte lex order (not string-value order)
- ✓ Integers in smallest form (no leading zeros, no padding)
- ✓ Text strings marked as major type 3, byte strings as major type 2
- ✓ Only tags 200, 201, 1 permitted in identity envelopes
- ✓ Fingerprint is raw 32 bytes (Blake3 output), not base58
- ✓ ed25519 present in subject and/or assertions; everything else optional
- ✓ No undefined-length arrays or maps (all lengths known at encode time)

---

## See also

- [Wire Protocol: dCBOR section](../wire-protocol.md#21-dcbor) — detailed dCBOR rules for all recrypt types
- [Wallet Envelope Format: Identity section](wallet-envelope-format.md#32-identity-envelope) — full identity envelope structure
- [Encoding Conventions](encoding-conventions.md) — when to use raw bytes vs base58 vs base64 at text boundaries
- [RFC 8949 §4.2: Preferred Encoding](https://datatracker.ietf.org/doc/html/rfc8949#section-4.2)
- [Blockchain Commons dCBOR](https://cborbook.com/part_2/cbor_cde_dcbor.html)
