# Recrypt KeyMaterial v1

**Document type:** Format specification
**Version:** 1
**Status:** Draft
**Date:** 2026-04-08
**Project:** [recrypt](../../README.md)

This document specifies the **KeyMaterial v1** binary format: the
fixed 96-byte plaintext bundle that the recrypt project encrypts
under a PRE (proxy recryption) public key as part of its hybrid
encryption scheme. It is paired with the **OpenFHE BFV** lattice
PRE backend and the **XChaCha20** stream cipher used for bulk file
encryption.

This format is independent of the recrypt wire protocol — it lives
*inside* a PRE ciphertext, never appears as a CBOR envelope, and is
visible only to the holder of the PRE secret key after successful
PRE decryption.

## 1. Scope

KeyMaterial is the bundle of secrets that a recrypt encryptor
produces for a single file and PRE-encrypts so that only the
intended recipient (and, after recryption, any subsequent
recipients) can recover them. It contains exactly the data the
recipient needs to decrypt and verify a recrypt-encrypted file:

- The XChaCha20 symmetric key.
- The XChaCha20 nonce.
- A Blake3 hash of the original plaintext (for post-decryption
  integrity checking).
- The original plaintext size.

KeyMaterial does not contain any routing information, recipient
identifier, format version of the wrapping envelope, or any other
metadata. It is the minimum sufficient bundle for "decrypt and
verify a single file."

## 2. Pairing with OpenFHE BFV

KeyMaterial v1 is sized to fit exactly within one **OpenFHE BFV
plaintext slot** under recrypt's chosen BFV parameters. Those
parameters yield a maximum plaintext size of **96 bytes per slot**.

OpenFHE's [BFV scheme](https://www.openfhe.org/) is a leveled
fully-homomorphic encryption scheme based on the Ring Learning
With Errors (RLWE) problem. Recrypt uses BFV in its proxy
recryption mode, which transforms a ciphertext encrypted under
key A into one encrypted under key B without revealing the
plaintext to the proxy.

For recrypt's purposes, BFV is used as a **post-quantum public-key
encapsulation mechanism**, not as a homomorphic compute substrate.
The "leveled" property is irrelevant; we only ever encrypt
KeyMaterial once and decrypt it once per recipient. Recryption is
the one operation we do *between* encrypt and decrypt, and that
operation does not consume noise budget the way arithmetic
homomorphic operations would.

The 96-byte plaintext capacity is a property of the chosen BFV
parameters. Different BFV parameter sets yield different plaintext
capacities; KeyMaterial v1 assumes 96 bytes specifically. A future
KeyMaterial v2 paired with different parameters could use a
different size, but all current implementations MUST treat
KeyMaterial as exactly 96 bytes.

The post-quantum security claim of recrypt's hybrid scheme rests
on the BFV layer — a quantum adversary capable of breaking ECDH
or factoring would still need to break Ring-LWE to recover
KeyMaterial. The XChaCha20 layer underneath is symmetric and
already considered post-quantum-secure (Grover's algorithm
provides only a quadratic speedup, leaving ChaCha20 effectively
at 128-bit post-quantum security with a 256-bit key).

## 3. Wire format

### 3.1 Layout

KeyMaterial v1 is exactly **96 bytes**, organized as:

```
Offset  Length  Field           Type   Notes
─────── ─────── ─────────────── ────── ────────────────────────────
[0]     1       version         u8     MUST be 1
[1]     32      symmetric_key   bytes  XChaCha20 256-bit key
[33]    24      nonce           bytes  XChaCha20 192-bit nonce
[57]    32      plaintext_hash  bytes  Blake3 of original plaintext
[89]    7       plaintext_size  u56le  Original plaintext byte count
```

Total: **96 bytes**.

The first byte is a **version discriminator**. Recrypt
implementations MUST verify this byte before interpreting the
remaining 95 bytes. An unknown version MUST be rejected with a
clear error and MUST NOT cause the implementation to attempt to
parse the remaining bytes under any other version's layout.

### 3.2 Field details

#### 3.2.1 `version` (offset 0, 1 byte)

A single unsigned byte. Value `0x01` denotes KeyMaterial v1. All
other values are either reserved for future versions or invalid;
implementations MUST reject any value other than the version(s)
they are built to recognize.

#### 3.2.2 `symmetric_key` (offset 1, 32 bytes)

The 256-bit XChaCha20 symmetric key used to encrypt the file
contents. Encoded as 32 raw bytes — no length prefix, no padding,
no encoding.

This key MUST be drawn from a cryptographically secure random
source (a CSPRNG seeded from the operating system's entropy pool).
Reuse of a key across files is forbidden — every encrypted file
gets a fresh symmetric key.

#### 3.2.3 `nonce` (offset 33, 24 bytes)

The 192-bit XChaCha20 nonce. Encoded as 24 raw bytes.

The 192-bit nonce length is a property of XChaCha20 (as opposed to
the 96-bit nonce of plain ChaCha20) and is large enough that
random nonce generation is birthday-safe up to ~2^96 messages
under the same key. Since recrypt uses a fresh symmetric key per
file, nonce collision is irrelevant in practice — but
implementations SHOULD draw the nonce randomly anyway as a defense
in depth against accidental key reuse.

#### 3.2.4 `plaintext_hash` (offset 57, 32 bytes)

The Blake3 hash of the file's original plaintext, computed before
XChaCha20 encryption. Encoded as 32 raw bytes.

This is the **integrity gate** for KeyMaterial. After PRE-decrypting
the wrapped key and XChaCha20-decrypting the file ciphertext, the
recipient computes Blake3 over the recovered plaintext and compares
to this field. A mismatch indicates either:

- The wrapped key has been tampered with (extremely unlikely given
  the PRE encryption around it, but the check is the post-hoc
  verification).
- The wrapped key was substituted for one belonging to a different
  file (the "wrong wrapped-key" confusion attack).
- The file ciphertext has been tampered with in a way that wasn't
  caught by the Bao tree hash check earlier in the decryption
  flow.

The plaintext_hash field is the cryptographic anchor that lets
recrypt's wrapped-key envelopes ship without their own signatures.
A maliciously-modified wrapped-key cannot pass this check unless
the attacker knows the original plaintext, which would defeat the
purpose of attacking the wrapped key in the first place.

#### 3.2.5 `plaintext_size` (offset 89, 7 bytes, u56 little-endian)

The byte count of the original plaintext, encoded as an unsigned
56-bit little-endian integer. The maximum representable value is
`2^56 - 1` ≈ **72 petabytes**.

To encode: take the low 7 bytes of the plaintext size's u64
little-endian representation. To decode: zero-extend the high
byte and interpret as u64 little-endian.

Encoders MUST reject any plaintext size larger than 2^56 - 1 with
a clear error. In practice this is unreachable: recrypt's
streaming encrypt path enforces a much smaller limit (currently
1 TiB = 2^40 bytes), well below the u56 cap.

The size is used after decryption as a **fast-fail truncation
check**: if the recovered plaintext is shorter or longer than
this value, decryption returns an error. This is a redundant
check (the plaintext_hash would also catch truncation) but it
provides faster feedback and a more specific error message.

### 3.3 Endianness

All multi-byte integer fields are **little-endian**. There is one
such field (`plaintext_size`).

### 3.4 Padding

KeyMaterial is exactly 96 bytes with no padding, no trailing
unused bytes, and no version-specific reserved space at the end.
A future v2 may use the bytes [1..96] differently, but v1 uses all
95 of them.

## 4. Why this format

### 4.1 Why fixed-size, not CBOR

KeyMaterial sits inside a fixed cryptographic plaintext slot. The
chosen BFV parameters yield 96 bytes of plaintext capacity. The
three 32-byte fields (symmetric_key, plaintext_hash, and combined
nonce + size making up another 32 bytes) consume 88 bytes by
themselves; even the most aggressive integer-keyed dCBOR framing
adds enough overhead to push the encoding past 96 bytes.

A version byte and a custom layout are 95 bytes more efficient
than that, while preserving the only property worth preserving
(forward compatibility via the version byte).

The rest of the recrypt wire format is dCBOR. KeyMaterial is the
one exception. The exception is justified because KeyMaterial:

- Lives inside a fixed-size cryptographic plaintext slot where
  bytes are non-negotiable.
- Has no third-party extension story (the recrypt project controls
  every encoder and decoder).
- Is never inspected by any tool that doesn't first hold the
  recipient's PRE secret key.
- Has no need for self-description because the wrapping envelope's
  type field already disambiguates it.

### 4.2 Why u56 for `plaintext_size`

The version byte costs one byte from the budget. Three options
were considered for where to take that byte from:

1. Steal from `plaintext_size` (u64 → u56). **Chosen.**
2. Drop `plaintext_size` from the bundle entirely.
3. Use some other field's bits.

Option 1 was chosen because the cap of 72 PB is wildly larger than
any realistic file (recrypt's enforced limit is 1 TiB), so the
u56 reduction has no practical cost. Option 2 would have removed
a useful fast-fail check and required the decryption flow to
trust the file envelope's size assertion (which is elidable for
privacy reasons). Option 3 would have fragmented the encoding.

### 4.3 Why a version byte at all

KeyMaterial v1 is the format we ship today. There is no plan to
ship v2 imminently. The version byte exists so that **the first
time we want to change KeyMaterial, the migration path exists**
without requiring a coordinated flag day across every encrypted
file in storage.

Concrete things a v2 might do:

- Support a different bulk cipher (e.g., AES-256-GCM as an
  alternative to XChaCha20).
- Support a key derivation function for deriving per-chunk
  subkeys.
- Support a different PRE backend with a different plaintext
  capacity.
- Add a key-rotation epoch field.

None of these are concrete needs today. The version byte is
**1 byte of insurance** against the cost of changing our minds.

## 5. Conformance

A KeyMaterial **encoder** MUST:

- Produce exactly 96 bytes.
- Set byte 0 to the version it is implementing (1 for v1).
- Pack `symmetric_key`, `nonce`, and `plaintext_hash` as raw
  bytes at the specified offsets.
- Encode `plaintext_size` as little-endian u56 in bytes [89..96].
- Reject any `plaintext_size` value greater than 2^56 - 1.
- Draw the symmetric_key and nonce from a CSPRNG (for v1; future
  versions may permit derivation).

A KeyMaterial **decoder** MUST:

- Reject any input that is not exactly 96 bytes.
- Read byte 0 as the version and reject any version it does not
  recognize.
- Reconstruct `plaintext_size` by zero-extending bytes [89..96]
  to a u64.
- Treat all 96 bytes as confidential — they are key material and
  zeroizing them on drop is RECOMMENDED.

A KeyMaterial **consumer** (the decryption path) MUST:

- Use `symmetric_key` and `nonce` to XChaCha20-decrypt the file
  ciphertext.
- Compute Blake3 over the recovered plaintext and compare to
  `plaintext_hash`.
- Verify the recovered plaintext length equals `plaintext_size`.
- Reject the entire decryption if either check fails.

## 6. Security considerations

### 6.1 What KeyMaterial protects against

KeyMaterial is the integrity anchor for recrypt's wrapped-key
envelopes. A wrapped-key envelope is unsigned at the envelope
level (see [wire-protocol.md §3.2.1](../wire-protocol.md)); its
integrity is established by:

1. The PRE encryption itself — only the recipient with the
   correct PRE secret key can decrypt it.
2. The plaintext_hash check after XChaCha20 decryption — the
   recovered plaintext must hash to the value committed to
   inside KeyMaterial.

Together these defeat:

- **Wrapped-key substitution.** An attacker who substitutes a
  wrapped-key from a different file produces KeyMaterial that
  decrypts the file ciphertext to garbage that fails the hash
  check.
- **Wrapped-key tampering.** An attacker who modifies the PRE
  ciphertext bytes either fails PRE decryption or produces
  garbage KeyMaterial.
- **Truncation.** The plaintext_size check catches truncation
  before the full hash check, with a more specific error.

### 6.2 What KeyMaterial does not protect against

- **Confidentiality of the KeyMaterial bytes themselves.** If an
  attacker can read the post-PRE-decryption plaintext (e.g., by
  compromising the recipient's process memory), they have the
  symmetric key and nonce and can decrypt any file encrypted with
  that wrapped-key. KeyMaterial is high-value material; treat it
  accordingly.
- **The PRE secret key.** KeyMaterial is irrelevant if the
  recipient's PRE secret key is compromised — the attacker decrypts
  the wrapped-key the same way the recipient does.
- **The original plaintext.** If the attacker has the plaintext,
  they can compute the same `plaintext_hash` and produce a
  KeyMaterial that the recipient will accept as valid for that
  plaintext. (This is a meaningless attack — the attacker already
  has what they wanted.)

### 6.3 Key reuse

The `symmetric_key` and `nonce` MUST be unique per file. Recrypt
generates them fresh per encryption operation; implementations
MUST NOT reuse a `(symmetric_key, nonce)` pair across files.

If the same `(symmetric_key, nonce)` pair is ever reused, the
XOR of the two ciphertexts equals the XOR of the two plaintexts,
which catastrophically breaks XChaCha20's confidentiality. The
192-bit nonce length makes accidental collision negligible under
normal random generation, but the single-use rule for
`symmetric_key` is what makes this safe in practice.

### 6.4 Zeroization

Implementations SHOULD zero KeyMaterial bytes on drop, especially
the `symmetric_key` field. The recrypt reference implementation
uses the `zeroize` crate for this purpose. Failing to zero key
material is not a *protocol* error but is a **defense-in-depth
issue** for any implementation hosted in an environment where
process memory might be observable.

### 6.5 Side channels

KeyMaterial's verification operations (the plaintext_hash
comparison and the plaintext_size comparison) SHOULD use
constant-time equality functions. Variable-time comparison creates
a timing oracle that, in principle, could let an attacker probe
which prefix of a candidate plaintext matches. The leakage is
small and the attack model unrealistic for most deployments, but
constant-time comparison is cheap and there is no reason to use
the variable-time form.

### 6.6 The post-quantum claim

KeyMaterial's confidentiality against a quantum adversary depends
entirely on the security of the OpenFHE BFV layer that wraps it.
BFV is based on the Ring Learning With Errors problem, which is
believed to be hard for both classical and quantum adversaries.
Recrypt uses BFV parameters chosen to provide approximately
**128-bit post-quantum security**.

XChaCha20 itself is not "post-quantum" in the sense of being
designed against quantum adversaries — it predates the post-
quantum standardization effort — but its 256-bit key length
provides ~128 bits of effective security against Grover's
algorithm, which is the best known quantum attack on symmetric
ciphers. This matches BFV's classical/quantum security level.

The integrity anchor (Blake3) is similarly post-quantum-secure at
~128 bits against Grover-style preimage attacks on the 256-bit
hash output.

The complete claim is therefore: **a quantum adversary capable of
breaking 128-bit symmetric primitives could break recrypt's
KeyMaterial confidentiality, but so could they break essentially
any post-quantum scheme of comparable parameters.** Recrypt does
not claim higher post-quantum security than its weakest component.

## 7. Future work

### 7.1 Anticipated v2 changes

We do not have a concrete plan for v2. Possibilities being
considered for the long term:

- **Cipher agility.** A v2 might add a 1-byte cipher identifier
  and let the bulk cipher be either XChaCha20 or AES-256-GCM,
  depending on the recipient's hardware preferences.
- **Larger plaintext capacity.** If we tune BFV parameters to
  yield a larger plaintext slot, v2 could use the extra bytes for
  a key-derivation salt or per-chunk subkeys.
- **Different hash function.** If Blake3 is ever superseded for
  post-quantum reasons (there is no current reason to expect
  this), v2 could swap in the replacement.

### 7.2 Cross-implementation interop

This document is specified in part so that implementations in
other languages (Swift, TypeScript, Python) can produce
byte-compatible KeyMaterial v1 bundles and interoperate with the
Rust reference implementation. The format is small and
unambiguous; a conformant implementation should fit in well under
100 lines of code in any language.

Implementations should test interoperability against the
reference implementation's known-answer test vectors (see §8).

## 8. Test vectors

**TODO before stable.** The vectors below are placeholders. They
need to be generated against the recrypt reference implementation
and verified to produce byte-identical output from any conformant
implementation.

### Vector 1: minimal valid v1

```
Inputs:
  symmetric_key:  0000000000000000000000000000000000000000000000000000000000000000
  nonce:          000000000000000000000000000000000000000000000000
  plaintext_hash: af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262   ; blake3("")
  plaintext_size: 0

Encoded (96 bytes hex):
  TODO — produce from reference implementation
```

### Vector 2: typical 1 MB file

```
Inputs:
  symmetric_key:  TODO (random 32 bytes)
  nonce:          TODO (random 24 bytes)
  plaintext_hash: TODO (Blake3 of a known 1 MB plaintext)
  plaintext_size: 1048576

Encoded:
  TODO
```

### Vector 3: maximum representable size

```
Inputs:
  symmetric_key:  TODO
  nonce:          TODO
  plaintext_hash: TODO
  plaintext_size: 72057594037927935   ; (2^56 - 1)

Encoded:
  TODO
```

### Vector 4: rejected — plaintext_size overflow

```
Inputs:
  plaintext_size: 72057594037927936   ; (2^56)
Expected: encoder error "plaintext_size exceeds u56 max"
```

### Vector 5: rejected — wrong version on decode

```
Encoded (first byte 0x02, otherwise valid v1 layout):
  02 [...95 bytes of valid v1 fields...]
Expected: decoder error "Unknown KeyMaterial version: 2"
```

## 9. References

- [recrypt project README](../../README.md)
- [recrypt wire protocol §3.3](../wire-protocol.md) — how
  KeyMaterial is wrapped in `recrypt.pre-wrapped-key` envelopes
- [XChaCha20+Bao AEAD specification](xchacha20-bao-aead.md) —
  the bulk encryption construction that uses KeyMaterial
- [recrypt threat model](../threat-model.md) — security analysis
  including KeyMaterial's role
- [Blake3 specification](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf)
- [draft-irtf-cfrg-xchacha](https://datatracker.ietf.org/doc/draft-irtf-cfrg-xchacha/) — XChaCha20 specification
- [OpenFHE](https://www.openfhe.org/) — the BFV implementation
  recrypt uses
- [Lyubashevsky, Peikert, Regev: "On Ideal Lattices and Learning with Errors over Rings"](https://eprint.iacr.org/2012/230) — RLWE foundation
- Reference implementation: [`crates/recrypt-core/src/hybrid/keymaterial.rs`](../../crates/recrypt-core/src/hybrid/keymaterial.rs)
