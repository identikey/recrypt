# Identity Envelope Self-Signature Spec

## What is signed

`Identity::sign_self_ed25519` uses the **wrap-then-sign** pattern. The identity
envelope is first wrapped (so the wrapper's subject digest covers the entire
inner envelope — subject **and** all assertions), and then the wrapper is
signed with the identity's ed25519 secret key.

This means the signature commits to **all** key material carried in the
envelope: `ed25519-public`, `ml-dsa-public`, `pre-public`, `pre-backend`,
`name`, `created`, and any unknown assertions present at signing time. An
attacker cannot strip or substitute the `ml-dsa-public` or `pre-public`
assertion without invalidating the signature.

## Wire format

A self-signed identity envelope has the following shape:

```
Envelope {
    subject: Wrapped(<identity envelope>),
    assertions: [
        'signed': Signature(ed25519, <64-byte signature over wrapper subject digest>)
    ]
}
```

Where `<identity envelope>` is the standard `recrypt.identity` envelope
produced by `to_envelope_bytes` (subject = `{type, format-version,
fingerprint}`, assertions = key material).

The `'signed'` predicate is the bc-envelope known value (tag 40000, value 3).
The object is a `Signature` CBOR-tagged value (tag 40020) containing the raw
64-byte ed25519 signature.

## Key binding and security order

Verification follows this strict order:

1. Parse the outer envelope and `try_unwrap` to obtain the inner identity
   envelope. (Rejects envelopes that are not wrap-then-signed.)
2. Parse the inner identity via `from_envelope_inner` — validates
   `fingerprint == Blake3(ed25519_public)`. This binds the embedded public
   key to the subject's fingerprint **before** that key is used as a
   verifier.
3. Construct a `SigningPublicKey` from the validated `ed25519_public`.
4. Verify the `'signed'` assertion on the **outer** envelope using that key.

This order prevents an attacker from substituting a different public key to
verify a forged signature: the fingerprint in the subject must match the key
used to verify, and the signature commits to the inner envelope contents
including the public key itself.

## API

```rust
impl Identity {
    /// Wraps the identity envelope and signs the wrapper's subject digest
    /// with the identity's ed25519 secret key. The signature covers all
    /// inner contents (subject + every assertion).
    /// Requires `self.ed25519_secret.is_some()`.
    pub fn sign_self_ed25519(&self) -> WireResult<Vec<u8>>;

    /// Parses a wrap-then-signed identity envelope, validates the
    /// fingerprint-key binding, and verifies the `'signed'` assertion.
    /// Returns `Err` if: outer is not wrapped, fingerprint mismatch,
    /// no `'signed'` assertion, or signature invalid.
    pub fn verify_self_signature_ed25519(envelope_bytes: &[u8]) -> WireResult<()>;
}
```

## Cryptography

The signature is produced by
`bc_components::SigningPrivateKey::new_ed25519(Ed25519PrivateKey::from_data(secret_bytes))`
and verified by
`bc_components::SigningPublicKey::from_ed25519(Ed25519PublicKey::from_data(public_bytes))`,
both wrapping the standard ed25519-dalek implementation with constant-time
comparison.

## Error messages

Error messages are intentionally generic ("signature verification failed") to
avoid leaking internal state. Detail is emitted at `tracing::debug!` level
only. Secret key material is never included in any error message or log. The
dedicated `WireError::SignatureVerification` variant is used for all
signature-related failures (no signature present, wrong key, invalid
signature, unwrap failure).

## Scope limitations

- Self-signature is not enforced on parse — `from_envelope_bytes` accepts
  unsigned envelopes. Callers that require authenticity must explicitly call
  `verify_self_signature_ed25519` (or `_hybrid`).
- There is no multi-signature support in this API (use bc-envelope's
  `add_signatures` directly for that).
- Assertions added to the wrapper *after* signing (siblings of the
  `'signed'` assertion) are not covered by the signature. Only the inner
  wrapped envelope is covered.

## Hybrid (ed25519 + ML-DSA-87) self-signature

The ed25519-only path is the canonical default. When the signer wants
post-quantum coverage as well — recrypt's hybrid posture — use the
`pq-self-sign` feature on `recrypt-wire` and call
`Identity::sign_self_hybrid(ml_dsa_secret)` /
`Identity::verify_self_signature_hybrid(bytes)`.

### Wire shape

```
Envelope {
    subject: Wrapped(<identity envelope>),
    assertions: [
        'signed': Signature(ed25519, <64-byte signature>),     // bc-envelope native
        "mldsa-signature": h'<raw ML-DSA-87 signature bytes>'  // sibling assertion
    ]
}
```

Both signatures commit to the **same payload**: the digest of the
wrapped envelope's subject (i.e. the inner identity envelope's digest).
ed25519 is signed by bc-envelope's `add_signature` (commits to that
digest internally); ML-DSA-87 is signed explicitly over
`wrapped.subject().digest().data()`.

The ML-DSA half lives in a sibling string-keyed assertion rather than a
second `'signed'` assertion because bc-envelope's `Signature` type does
not yet model ML-DSA. When/if upstream support lands, both signatures
can move to native `'signed'` and the `"mldsa-signature"` assertion can
be retired (additive, no version bump on `recrypt.identity`).

### Verification rules

1. Parse outer, unwrap, parse inner identity (validates
   `fingerprint == Blake3(ed25519_public)`).
2. Verify the bc-envelope `'signed'` assertion using the validated
   ed25519 public key. Failure → reject.
3. Extract `"mldsa-signature"` assertion bytes. Absent → reject.
4. Verify ML-DSA-87 using `inner.ml_dsa.public` (must be present) over
   `wrapped.subject().digest().data()`. Failure → reject.

A hybrid-signed envelope ALSO satisfies `verify_self_signature_ed25519`
(the ed25519 half is identical). Callers that require PQ coverage MUST
use the hybrid verifier — the ed25519-only verifier accepts envelopes
that lack the `"mldsa-signature"` assertion.

### Failure modes

All failures collapse to `WireError::SignatureVerification("signature
verification failed")` for caller-facing messages; details emit to
`tracing::debug!`. The one exception is missing `"mldsa-signature"`
assertion, which is a structural error rather than a cryptographic one
and surfaces a more specific message in the error chain (still under
`SignatureVerification`).
