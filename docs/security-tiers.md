# Security Tiers: Base / Sentinel / Max

**Date:** 2026-04-08
**Status:** Design reference — sets vocabulary and guarantees
**Audience:** Anyone asking "why doesn't recrypt do X?" or "how secure is this for my use case?"

---

## Why tiers

Recrypt is designed as a family of deployments sharing one cryptographic
core, layered with progressively stronger enforcement. The base tier is
the universal, publicly-deployable shape; higher tiers add
enforcement surfaces for users who need stronger guarantees and are
willing to run (or pay for) additional infrastructure.

This document names the tiers, states what each one guarantees, and
explicitly lists what each does **not** guarantee. Features are assigned
to tiers so we can ship the base tier honestly without apologizing for
its limits.

---

## The three tiers

### Base tier

**Shipped:** v1 (current sprint).
**Deployment shape:** content-addressed blobs in untrusted S3-compatible
storage + recrypt proxy (metadata index + PRE key vending) + federated
IdentiKey clients.
**Trust assumptions:** clients trust their own IdentiKey; everyone else
is semi-trusted at best.

**Guarantees:**

- **Confidentiality of data at rest in the vault.** Storage providers
  see only ciphertext and content hashes. Multiple untrusted providers
  can federate without weakening this.
- **Cryptographic verifiability.** Every signed object (KeyspaceDoc,
  Grant, ciphertext manifest) carries Ed25519 + ML-DSA signatures.
  Clients verify before acting.
- **Content integrity.** Blake3/Bao root hashes pin ciphertexts;
  tampering is detectable.
- **Authority-agility.** Keyspaces can be forked under new authorities;
  content addresses are universal across providers.
- **Federation.** Any operator can run a proxy; clients can query
  multiple proxies and merge verified results.

**Accepted weaknesses (documented, not apologized for):**

- **No enforcement against re-delegation.** Once a client holds a
  decrypted DEK, nothing prevents them from re-sharing the plaintext or
  re-encrypting it for someone else. This is analogous to "I emailed
  you a decrypted file" — cryptographically unstoppable without a
  trusted enforcement point. Capability tokens at this tier are bearer
  tokens with signatures for audit, not presentation-time enforcement.
- **Cached PRE-wrapped DEKs grant lingering access.** A client that
  cached a recrypted DEK before revocation retains read access to that
  ciphertext. Mitigated by short-lived ephemeral session keys (see
  "Forward secrecy posture" below), not eliminated.
- **No audit log of reads.** The proxy sees PRE key requests but does
  not cryptographically commit to an audit trail. Operators can log
  but clients cannot verify completeness.
- **Metadata queries are not authenticated.** "Who is in this
  keyspace?" is answered by whichever proxy you ask. Clients verify
  signatures on results; unverified claims about absence ("this person
  is not a member") are only as trustworthy as the queried proxy.

**Appropriate for:** personal document stores, federated public
workspaces, research collaboration, small groups where members trust
each other not to exfiltrate plaintext.

**Not appropriate for:** regulated data (HIPAA, PCI), material
non-public information, anything where "user got fired yesterday, must
lose access today" is a hard requirement, or anything requiring an
audit trail that stands up in court.

---

### Sentinel tier

**Shipped:** planned as an optional component.
**Deployment shape:** everything in base tier, plus a **vault guardian**
— a process sitting in front of the content-addressed vault that
verifies presentation-time capability tokens before releasing
ciphertexts.

**Adds these guarantees on top of base:**

- **Presentation-time capability enforcement.** Requests to fetch a
  ciphertext must present a signed capability token with a fresh nonce
  and a timestamp within a tight window. The guardian verifies the
  token against the keyspace state *at request time*, not at issue
  time.
- **Revocation-windowed forward secrecy.** Capability tokens are
  time-limited (minutes, not days). A revoked member's cached DEK is
  useless because the ciphertext is no longer fetchable without a
  valid token. The cryptographic "I still have the DEK" attack
  becomes a race against token expiry.
- **Ratcheted read nonces.** High-sensitivity keyspaces can require
  one-shot ratchet nonces per read. Each fetch consumes a counter
  position; replay is prevented at the guardian.
- **Tamper-evident access logs.** Each fetch produces a signed log
  entry (guardian signature + client signature). The log is
  Merkle-chained so omissions are detectable by anyone replaying it.
- **Per-tenant rate limits and DoS mitigations.** Beyond proxy-level
  limits, per-capability quotas.

**Accepted weaknesses:**

- **Still can't stop out-of-band plaintext leaks.** If a client
  decrypts and then sends the plaintext elsewhere, the guardian never
  sees it. No cryptosystem defeats this.
- **Guardian is a trust concentration point.** Clients depend on the
  guardian to enforce policy. A compromised or coerced guardian
  invalidates revocation guarantees (though the underlying
  confidentiality still holds — the attacker can only bypass
  access-control, not read plaintext without the keys).
- **Federation becomes partial.** Each guardian is its own authority
  surface. Cross-guardian delegation is possible but adds protocol
  complexity.

**Appropriate for:** enterprises, regulated industries, offboarding
flows, B2B data rooms, anything where "cut off access now" is a
real operational requirement.

**Typical deployment:** a company runs its own guardian in front of
its own vault bucket, or subscribes to a guardian-as-a-service. The
recrypt proxy may be public; the guardian is private.

---

### Max tier

**Shipped:** future / commercial offering.
**Deployment shape:** everything in sentinel tier, plus eager
re-encryption, hardware attestation, and policy engines.

**Adds these guarantees on top of sentinel:**

- **True forward secrecy via eager re-encryption on revocation.**
  When a member is revoked, affected ciphertexts are re-encrypted under
  a new epoch key with the revoked member excluded. Cached DEKs from
  the old epoch decrypt nothing that still lives in the vault. O(N)
  cost in the size of the keyspace's content, so this is opt-in per
  keyspace or per operation ("burn mode").
- **Hardware-attested guardians.** Guardians run in TEEs (SGX, Nitro
  Enclaves, confidential VMs) with remote attestation. Clients can
  verify they're talking to unmodified guardian code before presenting
  tokens. Reduces the "compromised guardian" failure mode.
- **Policy engines as authorities.** Authority quorum includes
  attested policy-engine processes that check request context against
  declarative rules (business hours, geographic restrictions, MFA
  state, risk scores). Policy decisions are signed and auditable.
- **Threshold-signed decryption capabilities.** Rather than any
  single authority being able to authorize decryption, a quorum must
  sign. Escrow agents contribute partial signatures; the user still
  needs other shares. Analogous to SSS recovery but for operational
  reads, not just key recovery.
- **Cryptographic audit with public verifiability.** Access logs are
  published to a transparency log (Sigstore-like). Any auditor can
  verify completeness.
- **Zero-knowledge membership proofs.** Clients can prove "I am
  entitled to this resource" without revealing *which* identity they
  are, for privacy-preserving audit scenarios.

**Appropriate for:** heavily regulated industries (healthcare,
finance, government), nation-state threat models, anything requiring
compliance sign-off from auditors who want to verify crypto themselves.

**Likely commercial shape:** managed service. The cryptography is
open-source; the operational burden of running attested guardians,
policy engines, and transparency logs is where the commercial value
lives.

---

## Escrow: an orthogonal capability

Escrow is not a tier. It's a configuration available at any tier,
implemented most cleanly at sentinel and max.

An **escrow agent** is an authority that can contribute toward
decryption authorization *under policy*, without necessarily being
able to decrypt on its own. Key properties:

- **Threshold-based.** An escrow agent holds one share of a threshold
  key. Decryption requires T-of-N shares. The escrow agent alone
  cannot decrypt.
- **Policy-gated.** The escrow agent signs its contribution only when
  a declared policy is satisfied (court order, user death certificate,
  time elapsed, multi-party consent). Policies are machine-checkable
  where possible, human-in-the-loop where necessary.
- **Auditable.** Every escrow contribution is logged and signed.
  Users can see "my escrow agent contributed a share to this
  decryption" after the fact.
- **Minimally trusted.** Because the agent holds only a share, a
  compromised agent does not leak user data. Attackers still need
  T-1 other shares.

**Escrow vs. SSS recovery.** IdentiKey's SSS key-recovery model is for
restoring a lost IdentiKey. Escrow is for operational reads: "allow
decryption of a specific keyspace's content under a specific policy."
Same primitive (threshold secret sharing), different use case.

**Use cases:**

- **Estate recovery:** heirs trigger a policy ("death certificate
  verified") that releases one share toward decrypting the decedent's
  personal vault.
- **Compliance / e-discovery:** a corporate escrow agent contributes a
  share under a signed court order, combined with the company officer's
  share.
- **Operational continuity:** multi-party authorization for sensitive
  reads during normal business, where no single person should be able
  to unilaterally unlock.
- **Emergency break-glass:** multiple on-call engineers each hold a
  share; any T of them can authorize decryption during an incident.

Escrow agents are members of the relevant keyspace (see "Authority =
member with threshold share" below). They're not a separate concept.

---

## Authority = member with threshold share

The original sketch had a separate `Authority` enum with `can_decrypt:
bool`. A cleaner model:

**An authority that can decrypt is just a member whose read capability
requires a threshold of shares.** No separate concept.

- Regular member: holds their own DEK share, full read capability on
  their own.
- Escrow member: holds a share, cannot decrypt alone, contributes
  under policy. Their "read capability" is conditional.
- Signing authority: a member whose signature is required for rotation
  or admin operations. Orthogonal to decryption capability.

The `Member` type carries:
```
Member {
    fingerprint: PublicKeyFingerprint,
    capabilities: Vec<Capability>,       // Read, Write, Delegate, Admin, SignRotation
    decryption_policy: DecryptionPolicy,  // Standalone | ThresholdShare { of: u8, n: u8, policy_ref: Hash }
    added_at: u64,
    added_by: PublicKeyFingerprint,
}
```

`DecryptionPolicy::Standalone` is the common case. `ThresholdShare` makes the
member an escrow participant — their DEK access requires combining
with other shares under a named policy.

This collapses the "authority can decrypt?" question into
"is this member a standalone or threshold participant?" Clearer and
composable: you can have multiple threshold groups in a single
keyspace (e.g., owner + [2-of-3 escrow agents] + [3-of-5 emergency
break-glass]).

**Edge cases:**

- `threshold` must be >= 1.
- `ThresholdShare { threshold: 1, total: 1 }` is equivalent to
  `Standalone` and should be normalized to `Standalone` on construction.
- If all members with `SignRotation` capability are lost (below quorum),
  the keyspace cannot be rotated. Recovery path: fork the keyspace
  under a new authority set. The old keyspace is effectively frozen.
  This is by design — no backdoor mechanism should be able to override
  quorum requirements.

---

## Forward secrecy posture by tier

| Mechanism | Base | Sentinel | Max |
|---|---|---|---|
| Long-lived PRE keys per epoch | X | X | X |
| Short-lived session ephemeral keys | X | X | X |
| Presentation-time token enforcement | — | X | X |
| Ratcheted read nonces | — | optional | X |
| Eager re-encryption on revocation | — | — | opt-in |
| Lazy re-encryption on touch | — | X | X |

**Lazy re-encryption on touch:** when content from a stale epoch is
next accessed by any authorized member, the vault guardian triggers
re-encryption under the current epoch key. Amortized cost — content
is upgraded on read, not all at once on rotation.

At base, "forward secrecy" means "an attacker who compromises a key
today cannot decrypt past traffic captured earlier" (which holds
because each file has its own DEK). It does **not** mean "a revoked
member immediately loses access" — that requires sentinel.

---

## Delegation posture by tier

| Property | Base | Sentinel | Max |
|---|---|---|---|
| Capability tokens signed for audit | X | X | X |
| Presentation-time verification | — | X | X |
| Delegation depth limits | — | X | X |
| Delegation logging | best-effort | X | X |
| Delegation revocation | via rotation only | immediate | immediate |
| Re-encryption blocks re-delegation | — | — | X (burn mode) |

At base, delegation is **implicit and unstoppable** because clients
hold the DEK after decrypting. A delegate can re-encrypt and re-share
without touching any recrypt infrastructure. Capability tokens exist
for audit, not prevention.

At sentinel, delegation becomes presentable: a delegate must present a
fresh signed token to the guardian to read. Revoking the delegation
chain invalidates all descendants immediately.

At max, burn-mode revocation re-encrypts the content, so even
out-of-band plaintext copies become stale for future versions.

---

## What ships now

**Base tier. Full stop.**

The keyspace design (separate doc) is written targeting base-tier
semantics, with explicit extension points for sentinel-tier
enforcement. The `DecryptionPolicy` field on `Member` and the `RotationMode`
enum are forward-compatible with threshold escrow and burn-mode
revocation without requiring schema changes.

Sentinel tier's vault guardian is a future component, not a rewrite.
It sits in front of the existing vault; base-tier clients continue
working unchanged (they just don't benefit from the stronger
guarantees).

Max tier is further out and probably commercial.

---

## Documentation promises

- **Base-tier docs must state the accepted weaknesses.** Anyone
  evaluating recrypt for a regulated use case must be able to read
  "revocation is not immediate; cached DEKs persist" without digging.
- **Sentinel-tier upgrade path must be clear.** Users who start on
  base should be able to add a guardian without changing their
  KeyspaceDocs, clients, or content addresses.
- **Tier terminology should be consistent.** Base / Sentinel / Max.
  No aliases.

---

## See also

- [Keyspace and Grant design plan](plans/2026-04-08-keyspaces-and-grants.md)
  — the base-tier implementation of keyspaces, with forward-compat
  hooks for sentinel and max.
- [Architecture overview](architecture.md) — where the components live.
- [Production readiness sprint](plans/2026-04-07-production-readiness.md)
  — the trait-backed persistence layer keyspaces will build on.
