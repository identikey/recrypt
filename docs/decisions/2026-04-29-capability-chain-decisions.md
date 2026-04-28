# Capability chain verification decisions (recrypt-vju)

`recrypt-91h` shipped `Capability` envelope-native with a `parent`
digest field, but the chain wasn't actually walked. This document
captures the design choices made while implementing that walk
(recrypt-vju), so we don't relitigate them later.

---

## D-3. Bundled bare-digest resolver, not envelope elision

**Decision.** Chain verification is built on the existing bare-digest
`parent: Option<[u8; 32]>` field
([`crates/identikey-storage-auth/src/capability.rs`](../../crates/identikey-storage-auth/src/capability.rs)).
Holders ship parent envelopes alongside the leaf in a `BundledResolver`
keyed on each parent's `wrap().subject().digest()`. The verification
library is I/O-free: a `ParentResolver` trait abstracts how
parent-envelope bytes are looked up, with `BundledResolver` as the only
in-tree impl. No `format_version` bump; no envelope elision.

**Rationale.**

- **Cryptographic equivalence.** The bare-digest field already commits
  to the parent envelope under the leaf's signature (the digest is a
  non-salted assertion that the wrap-then-sign covers). An attacker
  who hands you the wrong "parent" can't forge a match. Switching to
  an elided sub-envelope at `add_assertion("parent", parent_envelope)`
  doesn't strengthen this — it's an encoding refinement.
- **Same privacy gradient.** Holders already control how much chain
  to reveal by choosing which parents to put in the bundle. Elision
  doesn't add new privacy modes here.
- **Wire migration risk.** `Capability` is a load-bearing bearer-token
  format; bumping `format_version` for an aesthetic encoding refinement
  before chain verification has any users is the kind of speculative
  migration that's hard to reverse cleanly. We can do it later under a
  v2 once we've felt actual pain.
- **Trait shape is reusable.** The same `ParentResolver` interface
  later admits an `HttpResolver` for a server-side digest store
  without rewriting the verification core.

**Alternatives considered.**

- *Envelope-elision parent slot* — switch `add_assertion("parent",
  ByteString)` to `add_assertion("parent", parent_envelope)` and let
  Gordian Envelope's elision API handle reveal/conceal. Rejected for
  this pass: encoding refinement, not semantic gain. Worth revisiting
  if we want a single-envelope wire form (see reversal triggers).
- *Server-side digest store as the only resolver* — server keeps every
  issued capability and resolves digests on demand. Rejected: server
  learns the entire delegation graph, couples chain verification to
  network availability, and biases the system toward
  server-as-authority instead of UCAN-style invocation.
- *Plain bundle without resolver trait* — pass `Vec<Vec<u8>>` of
  parent bytes directly. Rejected: locks in the bundled deployment
  model and would force a refactor when an HTTP resolver lands.

**Verification rules at each step (child → parent).** Implemented in
[`capability_chain::verify_chain`](../../crates/identikey-storage-auth/src/capability_chain.rs):

1. Both envelopes verify against their issuer's public keys
   (`issuer_keys_for` closure resolves fingerprint → keys).
2. `parent.granted_to == child.issuer` — the entity that signed the
   child must be the one the parent delegated to.
3. `parent.permits(Permission::Delegate)` — parent had authority to
   sub-delegate. The leaf is exempt; the root's authority is the
   caller's concern (route-handler policy).
4. `child.permissions ⊆ parent.permissions` — no permission expansion.
   Set inclusion is the right rule today; `Permission` is a flat
   5-variant enum. Subsumption rules become relevant only when
   permissions get structured.
5. `child.subject == parent.subject` and `child.subject_kind ==
   parent.subject_kind` — can't redirect a delegation to a different
   resource.
6. No ancestor is expired.
7. `child.expires_at <= parent.expires_at` if parent has expiry — can't
   extend expiry beyond what was granted; an unbounded child under a
   bounded parent is also rejected.

A chain ends when `parent: None`. Whether that root issuer is an
authoritative principal for the resource is **not** a library
invariant — the route handler that consumes the chain decides
(typically by checking the root issuer is registered in `/accounts` and
owns the resource).

**Default policy.** `ChainPolicy::default()` caps `max_depth` at 8 and
inherits the leaf's `VerifyPolicy::PqRequired`. Servers can override
both.

**Reversal triggers.**

- A consumer needs holder-side proof of just *part* of a chain
  (privacy-gradient use case that's awkward to express with separate
  envelopes) → consider migrating `parent` to an elided sub-envelope
  under `format_version: 2`.
- A real use case for server-side digest resolution lands (e.g.,
  always-online recryption proxy where holders shouldn't carry the
  whole chain) → add `HttpResolver` impl, no library change needed.
- `Permission` becomes structured (verb + resource pattern) → replace
  the set-inclusion attenuation rule with a subsumption check; the
  step boundaries in `verify_chain` stay the same.
- Bundle sizes start dominating request payloads at realistic
  delegation depths → the bare-digest format gives us a clean fallback
  to `HttpResolver` without rewriting verification.
