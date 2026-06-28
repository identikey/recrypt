# IdentiKey Auth — Challenge/Response Protocol v1

**Status:** Draft spec
**Date:** 2026-06-27
**Crate:** `identikey-auth` (recrypt workspace; intended for later OSS split)
**Reference:** [RFC 8949 §4.2.1 (Canonical CBOR)](https://datatracker.ietf.org/doc/html/rfc8949#section-4.2.1),
[`dcbor-determinism.md`](./dcbor-determinism.md), [EIP-4361 (SIWE)](https://eips.ethereum.org/EIPS/eip-4361),
[CAIP-122 (SIWx)](https://standards.chainagnostic.org/CAIPs/caip-122)

---

## 1. Motivation

Papyrus is a server-less, P2P desktop application. The companion spike
[`SP-02`](../../../Papyrus/docs/spikes/SP-02-webauthn-tauri-passkey/report.md) established that browser
WebAuthn / passkeys are a dead end here: the JS API is broken or absent in two of three webview engines,
and platform passkeys are structurally bound to a hosted Relying-Party **domain** that a no-server app
cannot provide. The conclusion was to authenticate with a **hardware-protected private key** and a
**self-verifying challenge-response**, where a peer checks a signature directly with no Relying-Party server.

This is the same lineage as Sign-In-With-Ethereum (EIP-4361) and the chain-agnostic CAIP-122, but those
carry blockchain/wallet ceremony we don't need. This protocol keeps their load-bearing security
properties — audience binding, server-issued freshness, time-bounding, key binding — and cuts the rest.

This is one of the first IdentiKey authentication protocols; it is designed to stand alone and be
open-sourced.

## 2. Design goals

1. **Self-verifying.** A verifier needs only the protocol and the claimant's public key — no RP server,
   no hosted domain, no central directory. Works peer-to-peer.
2. **Cipher-agile.** Every key and signature is self-describing (carries its algorithm). The classical
   identity key is **Ed25519 or P-256**; an optional **post-quantum** signature (ML-DSA / FIPS 204) may
   accompany it. New algorithms are added by registry entry, not protocol revision.
3. **Hardware-enclave-backed.** The signing key lives in a hardware element where the platform allows it
   (P-256 in the Apple Secure Enclave / Windows TPM), gated by a biometric. Where the key type is not
   enclave-native (Ed25519 everywhere; any key on hardware that can't hold it), the key is **wrapped at
   rest under an enclave-held key** ("enclave-as-KEK"). See §8.
4. **Downgrade-proof.** A verifier sets a [`VerifyPolicy`](#7-verification); a present-but-unverifiable
   PQ signature is a hard error, never a silent skip. (Mirrors `recrypt-core::sign`.)
5. **Deterministic & self-describing wire format.** Canonical dCBOR (RFC 8949 §4.2.1) so the signed bytes
   are byte-identical across implementations and languages, per [`dcbor-determinism.md`](./dcbor-determinism.md).
6. **Minimal.** No chain-id, no blockchain address formatting, no human-readable ABNF template, no
   resource/URI lists. Only the irreducible challenge-response core.

## 3. Identity model

An **identity** is a classical public key, optionally paired with a post-quantum public key:

```
Identity := { classical: ClassicalKey, pq: Option<PqKey> }
```

Invariant — **PQ implies classical**: there is never a PQ-only identity. This keeps the fingerprint
(§5) universally derivable and lets verifiers fall back to a classical check when no PQ material is
present and policy permits.

### 3.1 Algorithm registry (self-describing tags)

Algorithms are identified by a short text tag carried on every key and signature.

| Tag          | Role      | Scheme                         | Notes |
|--------------|-----------|--------------------------------|-------|
| `"ed25519"`  | classical | Ed25519 (EdDSA, RFC 8032)      | software key; not enclave-native anywhere |
| `"p256"`     | classical | ECDSA on NIST P-256 (secp256r1)| **enclave-native** (Apple SE, Windows TPM, Android) |
| `"ml-dsa-44"`| pq        | ML-DSA-44 (FIPS 204)           | reserved |
| `"ml-dsa-65"`| pq        | ML-DSA-65 (FIPS 204)           | default PQ slot |
| `"ml-dsa-87"`| pq        | ML-DSA-87 (FIPS 204)           | matches recrypt-core's PQ ceiling |

`"p256"` is the hardware common denominator: it is the **only** asymmetric type the Apple Secure Enclave
supports, and is supported by the Windows TPM and Android StrongBox. Ed25519 is offered for software
identities and interop with the wider IdentiKey/recrypt ecosystem (whose fingerprints derive from Ed25519).

Note: ML-KEM / "Kyber" (FIPS 203) is a **KEM for encryption**, not a signature scheme, and is therefore
**not** in this registry. The PQ slot is a signature scheme (ML-DSA).

### 3.2 Key and signature encoding

```
PublicKey := { "alg": tstr, "key": bstr }      ; key = raw public key bytes for the algorithm
Signature := { "alg": tstr, "sig": bstr }      ; sig = raw signature bytes for the algorithm
```

Raw byte forms: Ed25519 = 32-byte public key / 64-byte signature; P-256 = 33-byte compressed SEC1 point
/ 64-byte fixed `r‖s` signature; ML-DSA = FIPS 204 public-key / signature byte strings.

## 4. Wire format

All structures are **deterministic CBOR maps** (dCBOR): keys sorted in encoded-byte lexicographic order,
integers in smallest form, definite-length, no floats — per [`dcbor-determinism.md`](./dcbor-determinism.md).
Keys are short text strings (self-describing).

### 4.1 Challenge (issued by the verifier / "host")

```
Challenge := {
  "v":     uint,    ; protocol version, = 1
  "aud":   tstr,    ; audience — the service/identity this proof is FOR (anti-phishing, anti-cross-replay)
  "nonce": bstr,    ; verifier-issued random challenge, >= 16 bytes (replay protection)
  "iat":   uint,    ; issued-at, Unix seconds
  "exp":   uint     ; expiry, Unix seconds; verifier rejects responses outside [iat, exp]
}
```

The verifier picks `nonce` (never the claimant) so freshness is server-controlled. `aud` is a free-form
service identifier (e.g. `"papyrus"`, or a scroll/Guild id for scoped proofs); it is **not** a hosted
domain and requires no DNS.

### 4.2 Response (returned by the claimant / "peer")

```
Response := {
  "chal": bstr,         ; the EXACT canonical dCBOR bytes of the Challenge being answered
  "pub":  PublicKey,    ; claimant's classical public key (§3.2)
  "sig":  Signature,    ; classical signature over the signing payload (§4.3)
  "pqpub": PublicKey,   ; OPTIONAL — claimant's PQ public key
  "pqsig": Signature    ; OPTIONAL — PQ signature over the SAME signing payload; requires "pqpub"
}
```

`"chal"` carries the verbatim challenge bytes rather than a re-encoded copy, so the verifier checks the
signature against exactly what it issued and never has to re-derive canonical bytes from a decoded form.

### 4.3 Signing payload (domain-separated)

Signatures are **not** computed over the bare challenge bytes. They are computed over a domain-separated
payload so a signature can never be lifted into another protocol or context:

```
SigningPayload := dcbor([ "identikey-auth/v1", "challenge", chal_bytes ])
```

A definite-length 3-element array: a fixed context tag, a purpose tag, and the verbatim challenge bytes.
Both the classical and (when present) PQ signatures sign the **same** `SigningPayload`.

## 5. Fingerprint

An identity's fingerprint commits to the algorithm as well as the key bytes, so two keys of different
algorithms can never collide:

```
fingerprint := Blake3( dcbor(PublicKey) )          ; 32 bytes
display      := base58(fingerprint)
```

This matches recrypt's `Blake3`-of-public-key, base58 convention (`identikey-storage-auth::fingerprint`),
generalized to be algorithm-committing. For pure-Ed25519 identities the input is the self-describing
`{"alg":"ed25519","key":…}` map, **not** the bare 32 bytes — so IdentiKey-auth fingerprints are a distinct
namespace from recrypt's raw-Ed25519 fingerprints by construction. (If raw-Ed25519 interop is ever needed,
it is added explicitly, not by accident.)

## 6. Protocol flow

```
Verifier                                   Claimant
  | -- Challenge (4.1) ------------------>  |
  |                                         |  build SigningPayload (4.3)
  |                                         |  biometric unlock -> sign with enclave key (§8)
  | <----------------- Response (4.2) ----- |
  |  decode; check aud, nonce-unused, now ∈ [iat,exp]
  |  verify classical sig; verify PQ per VerifyPolicy
  |  mark nonce used (replay)
```

## 7. Verification

A verifier MUST, in order:

1. Decode the `Response`; decode the embedded `Challenge` from `"chal"`.
2. Check `v == 1`, `aud` equals the expected audience, `len(nonce) >= 16`.
3. Check the nonce is one this verifier issued and has **not** been used (replay store).
4. Check `iat <= now <= exp` within an allowed clock-skew tolerance.
5. Recompute `SigningPayload` from `"chal"` and verify `"sig"` against `"pub"`.
6. Apply the PQ policy:

```
VerifyPolicy::PqOptional  -> if pqsig present, pqpub MUST be present and pqsig MUST verify;
                             if absent, accept classical-only.
VerifyPolicy::PqRequired  -> pqpub AND pqsig MUST be present and verify; classical-only is rejected.
```

A PQ signature present without a verifiable PQ key, or a PQ signature that fails, is a **hard error**
under both policies (downgrade resistance).

7. Bind the result to `fingerprint(pub)` (§5) — the authenticated identity.

## 8. Key storage — enclave-as-KEK

The signing key SHOULD be protected by a hardware element, gated by a biometric, per platform:

- **P-256 identity (preferred where hardware exists):** the private key is **generated inside** the
  Secure Enclave / TPM and never leaves it. Signing happens in-hardware, gated by Touch ID / Windows Hello.
  This is the strongest mode and the reason P-256 is the default hardware curve.
- **Ed25519 identity (or P-256 where no hardware):** the enclave cannot hold the key, so it is wrapped at
  rest. A hardware-held P-256 "wrapping key" (Secure Enclave / TPM) performs ECDH/ECIES to unwrap a
  symmetric data-encryption key, which decrypts the Ed25519 seed into memory only for the duration of a
  signature, then zeroizes. The unwrap is biometric-gated. This is a deliberate, documented compromise:
  the seed is briefly in process memory.

This mirrors the structure of recrypt's wallet envelope (KDF→KEK→AEAD-wrap-the-secret), substituting an
**enclave-held wrapping key** for the Argon2-password KEK. Platform backends:

| Platform | P-256 in hardware | Biometric | Crates |
|----------|-------------------|-----------|--------|
| macOS    | Secure Enclave    | Touch ID  | `security-framework` (SEP key + `SecAccessControl`), `objc2-local-authentication` (`LAContext`) |
| Windows  | TPM (CNG, `MS_PLATFORM_CRYPTO_PROVIDER`) | Windows Hello | `windows` (`NCrypt*`, `KeyCredentialManager`) |
| Linux    | TPM 2.0 where present | (none uniform) | `tss-esapi`; OS keyring (`keyring`/Secret Service) software fallback |

macOS note: Secure-Enclave keys require the binary to be **code-signed with a keychain-access-group
entitlement** (Papyrus already ships a Developer-ID + hardened-runtime build; this adds one entitlement).
Unsigned dev builds fall back to the software signer.

## 9. What we kept vs. cut from SIWE / CAIP-122

**Kept (the irreducible secure core):** audience (`aud`), server-issued `nonce`, `iat`/`exp` validity
window, the authenticating public-key identity, and a signature over a canonical encoding of all of it.
These give replay resistance, audience/cross-service-replay resistance, time-bounding, and key-binding.

**Cut:** `chain-id` (no blockchain), blockchain-address formatting (EIP-55 / CAIP-10) in favor of a
self-describing public key + Blake3 fingerprint, the `uri` field (redundant with `aud` for a desktop
app), `resources` / `request-id` (capability delegation is a separate concern — see recrypt's UCAN-style
capabilities), and the human-readable ABNF message template (we control both ends; canonical dCBOR is
cleaner and removes escaping/parse ambiguity). `version` is kept as a single integer.

## 10. Security considerations

- **Replay** is prevented by the verifier-issued single-use `nonce` plus the `exp` window; the verifier
  MUST persist used nonces until they expire.
- **Cross-service replay** is prevented by `aud` binding inside the signed payload.
- **Cross-protocol signature reuse** is prevented by the domain-separation tags in `SigningPayload` (§4.3).
- **Downgrade** (stripping the PQ signature) is prevented by `VerifyPolicy` + the hard-error rule (§7).
- **Algorithm confusion** is prevented by self-describing alg tags and an algorithm-committing fingerprint.
- **Key exfiltration** is mitigated by enclave residence (P-256) or enclave-gated wrapping (Ed25519); the
  wrapped-seed mode's in-memory exposure window is the documented residual risk.

## 11. Open questions / future work

- **NodeId attestation (Papyrus FR5/FR6).** The same signing key attests an iroh `NodeId` by signing it
  under a `"node-attestation"` purpose tag (same domain-separation scheme as §4.3). To be specified
  alongside the Papyrus transport work (`Papyrus-0tk` / `Papyrus-rh0`).
- **Delegation / capability chains.** Out of scope for v1; align with `identikey-storage-auth`'s
  UCAN-style capabilities when needed.
- **HD device-key derivation** (Papyrus FR30) — multiple devices under one IdentiKey root — deferred.
- **SLH-DSA (FIPS 205)** as a conservative hash-based PQ alternative — reserve a registry tag if needed.
- **OSS license** — the crate currently inherits the recrypt workspace license; pick the OSS license at
  split time.
