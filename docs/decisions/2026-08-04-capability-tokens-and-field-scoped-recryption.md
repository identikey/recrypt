# D-5: Capability tokens, field-scoped recryption, and issuance-derived provenance

**Date:** 2026-08-04
**Status:** Proposed — direction agreed, scope not yet cut
**Builds on:** [capability-chain decisions](2026-04-29-capability-chain-decisions.md)
**Beads:** `recrypt-lz0` (research), `recrypt-rb9` (ephemeral worker spike),
`recrypt-q0s` (error channel), `recrypt-99x` (data classes)

---

## Decision

**The recryption key is the bearer token.** Authority to read a piece of data
travels *with* the token and is redeemed by holding the private key the token
was geared to. There is no permission registry consulted at redemption time,
and no service that must be online and trusted to say yes.

Four consequences, each developed below:

1. Capability, not RBAC — the token carries authority instead of referencing it.
2. Bearer-plus-holder — possession of the token is necessary but not
   sufficient; you must also hold the key it targets.
3. Field-scoped — a capability names `(subject, field set)`, not just `subject`.
4. Provenance is derived from **issuance**, not from access logging.

---

## 0. Scope

This decides **the capability layer only** — §§1, 2 and 4 — resting on
`crates/identikey-storage-auth/`. That is Recrypt's to settle.

It **depends on, but does not decide**, two things that live outside this repo:

- A *substrate* that can deliver key material to a worker without the host
  seeing it. mjolnir does this today. The interface is deliberately thin — "a
  keypair was generated in-guest, here is the public half, deliver this blob to
  it" — and Recrypt should not grow opinions about hypervisors.
- A *schema layer* that says what a field class is and how one is declared on
  an envelope attribute. Dreamball has the machinery (core/attributes split,
  per-attribute digests, elision-valid-after-signing), but it is a sister
  project in a different org and `recrypt-wire` already has its own Gordian
  envelope. Whether Recrypt depends on Dreamball or both consume a shared
  vocabulary from `identikey-protocol` is **an open decision this doc does not
  make.** See `recrypt-99x`.

It **anticipates and does not claim** anything above: how pipelines of workers
are described, checked, or scheduled is not Recrypt's business. §5 names those
consumers only insofar as they shape this layer's interface.

---

## 1. Why this is not RBAC, and why that matters

The reference point is Amazon's **tokenator** pattern: PII is replaced by an
opaque token that flows freely across microservices, and only a service with
the right permission can redeem that token for the underlying value. Everything
in between carries a reference and never the data. That part is exactly right,
and it is the shape we want.

But tokenator is RBAC underneath. Redemption is a *lookup*: the service
authenticates to a centralized AAA registry, receives a short-lived access
token attesting to its role, and presents that token to redeem the tokenator
token. The registry is the authority. It must be online, it must be trusted, it
must be correct, and — the part that matters most for us — **it necessarily
knows every redemption**, because every redemption is a query it answers.

A capability system moves the authority into the token itself. Nothing is
consulted. The recryption key *is* the grant: it transforms ciphertext
addressed to one public key into ciphertext addressed to another, and it can do
so because the data owner minted it, not because a registry vouches for it.

Concretely, what falls away:

| | Tokenator / RBAC | Capability token |
|---|---|---|
| Authority lives in | A central registry | The token |
| Redemption requires | Registry online + trusted | Nothing but the key |
| Registry learns | Every redemption | Nothing (there is none) |
| Revocation | Delete the role binding | Expiry, rotation, or storage-auth refusal |
| Failure mode | Registry outage denies all reads | None — reads are offline-capable |

The last row is the one to hold onto. In an RBAC design the permission service
is a availability dependency on every single read. Here it is not on the path
at all.

## 2. Bearer-plus-holder, and why the shelf life is a feature

A pure bearer token is a liability: whoever steals it wields it. A recryption
key is not purely bearer, and this is the useful asymmetry.

The token is only redeemable by an entity that already holds the **private key
it was geared to**. Stealing the recryption key in transit yields nothing —
the thief cannot complete the transformation into anything they can read. The
capability names its recipient in the math, not merely in a claim field.

The direct consequence is that **key rotation is expiry**. When a recipient
rotates their keypair, every capability minted to the old key becomes inert
without anyone revoking anything, without a CRL, and without the issuer being
online to participate. Capabilities have a shelf life bounded by the recipient's
rotation cadence.

We are treating this as a feature rather than a limitation:

- It gives a **default-deny drift** to the whole system. Grants decay unless
  renewed. The failure mode of forgetting about a capability is that it stops
  working, not that it works forever.
- It makes rotation a **security operation with teeth** — rotating a
  compromised key revokes every grant to it, atomically, as a side effect.
- It means the revocation story does not depend on a distributed-systems
  problem (propagating a revocation list to every reader) that nobody has ever
  really solved.

It is not sufficient on its own — a capability is live for the window between
issuance and rotation, and short-lived grants still want explicit expiry.
`Capability.expires_at` already exists for that. The point is that rotation is a
*second, independent* mechanism that requires no coordination.

### RBAC is reconstructible on top, and we are deliberately not building it yet

If a deployment genuinely needs role semantics, they are recoverable: a
**transitive-access service** holds capabilities delegated to itself and
re-delegates them onward according to whatever role model the customer wants.
The existing chain verification already supports this — `parent.granted_to ==
child.issuer`, `child.permissions ⊆ parent.permissions` (see the
[capability-chain doc](2026-04-29-capability-chain-decisions.md), D-3
verification rules). Such a service is a *participant* in the capability graph,
not an authority over it, and it can only ever hand out attenuations of what it
was itself granted.

**We are not building that now.** Keeping the primitive simple and actually
using it will teach us more than speculatively designing the role layer above
it. If we build the role service first, we will design the capability layer to
serve it, and we will end up with RBAC wearing a capability costume.

## 3. Field-scoped capabilities

Today `Capability.subject` is a 32-byte resource address —
`crates/identikey-storage-auth/src/capability.rs:107`. The change is to let a
capability name a **subset of the subject's fields** rather than the whole
object.

This is expressible because of work already done elsewhere:

- **Dreamball** (`/Users/dukejones/work/WorldTree/Dreamball`) splits a Gordian
  envelope into a **core** (load-bearing anchors: type, format-version,
  identity key, content hashes) and **attributes** (mutable, elidable,
  descriptive) — `docs/PROTOCOL.md:82`.
- Attributes carry **per-attribute digests**, so they are separately
  addressable. Per-field encryption to different keys is therefore natural
  rather than a retrofit.
- **Elision remains valid after signing**: "Signatures cover the core digest
  plus every non-elided attribute's digest at signing time. Eliding a salted
  attribute after signing is valid" (`docs/PROTOCOL.md:453`). A worker can be
  handed a legitimately-signed object with whole field classes already removed,
  and it still verifies.
- The **capability/provider model** (`docs/decisions/2026-05-31-capability-provider-model.md`,
  largely landed) already has a ball declare a *need* and a host bind a
  provider, content-addressed and hash-pinned. A worker declaring the field set
  it needs is the same primitive aimed at data instead of code.

So the grant becomes `(subject, field-class set)`, and a recipient holds no key
material for classes it was not granted. It does not *refuse* to read them; it
**cannot**. That is the distinction worth paying for.

### Salting is mandatory here

`Capability.permissions` is already salted on the wire with the reasoning
recorded in the struct: *"a 4-value enum is trivially brute-forceable
unsalted"* (`capability.rs:113-114`). A field-class set is exactly such a
low-entropy space, often smaller. Field scoping inherits the salting policy
(recrypt `docs/wire-protocol.md` §6, which Dreamball's PROTOCOL.md cites) as a
hard requirement, not a nicety. The same reasoning applies to error codes —
see `recrypt-q0s`.

## 4. Provenance derived from issuance

This is the property that surprised us, and it may be the most valuable part.

Every capability issuance is a graph edge:

```
(issuer, granted_to, subject, field-class set, expires_at, parent) @ time
```

The union of those edges **is** the provenance graph. Which worker could read
which fields of which object, under whose authority, derived from which parent
grant, during which window — all of it is reconstructible from issuance records
alone.

Access logging normally has an unpleasant property: the log of who read what is
itself sensitive, so the audit trail becomes another asset to protect, and a
tempting one to breach. Here the inversion is clean:

> **The provenance record contains only grants, never data.** It is
> non-sensitive by construction, so it can be retained indefinitely,
> replicated, published to an auditor, or handed to a regulator without
> becoming a new liability.

It is also *more* complete than access logging, not less. A read log records
what was read; a grant log records what was **readable**, which is the question
an auditor actually asks. And because capabilities chain, the graph is
transitive: an auditor can trace an output back through every worker and every
attenuation that produced it.

Two invariants to preserve as this lands (candidates for the conformance doc,
`recrypt-oe4`):

- **Issuance completeness** — no path mints a capability without producing an
  edge.
- **Provenance non-sensitivity** — no edge field is derived from plaintext.
  `Capability.note` is free-form `String` and is the obvious hazard; it is
  salted today, but salting hides it from observers, not from whoever holds the
  log. Either constrain it to schema constants or exclude it from the
  provenance projection.

## 5. Consumers above this layer

Layer 2 exists to be consumed. Two consumers shape its interface, and both live
outside this repo (§0):

- **Multi-stage processing.** A capability that names a field-class subset is
  what lets a chain of workers each hold less than the last. What an
  orchestration layer does with that — how pipelines are described, checked, or
  scheduled — is not decided here.
- **Secrets as ordinary fields.** Credentials a worker needs are just fields
  encrypted to that worker, opaque to every intermediary. Recrypt issues the
  capability; the substrate delivers the material (mjolnir does this today via
  Iroh injection direct to the guest, with LUKS2 keeping it off host disk).

Both require only what §§1–4 decide: field-scoped grants, redemption by key
possession, and issuance records. Neither adds a requirement on this layer.

## Alternatives considered

- **Adopt tokenator/RBAC directly.** Rejected: it puts a trusted, online,
  omniscient registry on the read path, which is the thing this project exists
  to remove. It also makes the permission service a single point of both
  failure and surveillance.
- **Build the role/transitive-access layer first.** Rejected for now (§2). It
  would bias the primitive's design toward serving the role model, and we would
  arrive at RBAC by another route. Revisit when a real customer requirement
  names roles.
- **Revocation lists instead of rotation-as-expiry.** Rejected as the primary
  mechanism: CRL propagation is an unsolved distributed-systems problem and
  reintroduces an availability dependency. Explicit `expires_at` plus rotation
  covers the cases we can name. Storage-auth refusal remains available as a
  belt-and-braces layer for the hosted deployment.
- **Access logging for provenance.** Rejected: strictly less informative
  (records reads, not readability), and it makes the audit trail sensitive.

## Reversal triggers

Reopen this decision if:

- A customer requirement genuinely needs **immediate, global revocation**
  faster than rotation allows, and storage-auth refusal is insufficient because
  the data is not fetched through us.
- Field-class sets turn out to need **structure** (hierarchies, subsumption)
  rather than flat set inclusion — the same trigger the capability-chain doc
  names for `Permission`.
- The issuance graph turns out to leak more than expected, e.g. because
  `subject` hashes plus timing are correlatable into a behavioral profile. That
  would push provenance toward aggregation or delay.
- We adopt a **hardware-attested** worker model, which would change what a
  capability can safely be geared to (an attested measurement rather than a
  keypair) and would make rotation-as-expiry less central.

## Open questions

- Does the field-class set live in `Capability` directly, or in a separate
  attenuation envelope referenced by digest? Direct is simpler; separate keeps
  `format_version` stable.
- Is a field class a property of the *schema* (Dreamball, authored once) or of
  the *instance*? Schema is far more checkable and is the current assumption —
  see `recrypt-99x`.
- How does an ephemeral worker's keypair enter the capability graph without a
  registration round-trip that reintroduces a central authority? (`recrypt-rb9`)
