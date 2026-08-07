# Codegen pipeline decisions (epic recrypt-nj1)

Two decisions surfaced while building the schema-as-source-of-truth
pipeline. Captured here so future agents don't relitigate them; revisit
only when the listed reversal triggers fire.

---

## D-1. Wallet on-disk identity envelope stays separate from the unified schema

**Decision.** The wallet's on-disk `recrypt.identity` envelope
([`crates/recrypt-wire/src/identity.rs`](../../crates/recrypt-wire/src/identity.rs))
is **not** regenerated through the utoipa-driven codegen pipeline. It
keeps its hand-written envelope encoder.

**Rationale.**

- **Encoding mismatch.** Wallet identity uses raw-bytes for all key
  material per [encoding-conventions.md §1](https://github.com/identikey/identikey-protocol/blob/main/docs/standards/encoding-conventions.md);
  the codegen pipeline standardizes on base64 in JSON. Forcing the wallet
  through the pipeline would either re-encode keys (breaking the
  on-disk format that recrypt-03y just shipped) or carve out a
  per-field exception (defeating the "no per-field encoding decisions"
  point of the epic).
- **Always-secrets-present invariant.** The wallet identity assumes
  secrets are always present locally and selectively elided when
  exporting; a JSON-projected schema doesn't model elidable assertions.
- **Wrap-then-sign hybrid.** `Identity::sign_self_hybrid` is a
  hand-written wrap-then-sign pattern over both ed25519 (native
  `'signed'`) and ML-DSA (sibling raw-bytes assertion). utoipa cannot
  describe either signing form.

**Alternatives considered.**

- *Regenerate identity from utoipa schemas.* Rejected — the encoding
  carve-out would propagate every place wallets are read or written,
  and the codegen pipeline is built around JSON-shaped types, not
  envelopes with elision.
- *Replace utoipa with a CBOR-native schema generator and unify.*
  Theoretically clean but no such generator exists at maturity. Defer
  until one does (and even then, the wallet's invariants probably
  still want a hand-rolled encoder).

**Reversal triggers.**

- A CBOR-native schema/codegen tool emerges that handles salted
  assertions and wrap-then-sign signatures.
- We need to ship the wallet identity to a non-Rust language and the
  hand-rolled encoder becomes a maintenance bottleneck.

---

## D-2. Generated TS client lives as a sibling crate inside the recrypt repo (for now)

**Decision.** The TypeScript client generated from `openapi.json`
ships as a sibling crate inside the recrypt monorepo. Distribution as
a separate npm package is deferred until an external consumer asks
for one.

(Note: the actual TS generator is itself a follow-up — recrypt-uy3.
This decision is about *where* it lives once it exists.)

**Rationale.**

- **CI simplicity.** A sibling location lets the same CI job that
  bumps `openapi.json` regenerate and lint the TS client, with no
  cross-repo coordination, no separate publish step, and no version
  skew window.
- **Single source of truth, single build.** `just openapi-regen`
  already orchestrates Rust client + docs regeneration; adding TS to
  the same recipe is one more line. Splitting to a separate repo
  would mean a triggered job, a release pipeline, and the chronic
  problem of "which version of the TS client matches which version
  of the server."
- **No external consumer yet.** Dreamball has not written wire/integration
  code (per epic decisions). Ship a tree-friendly form first, extract
  later if external demand materializes.

**Alternatives considered.**

- *Separate npm package, published from CI.* Right move once an
  external (non-recrypt-repo) consumer needs to pin a version. Until
  then, the publish pipeline is overhead without payoff.
- *Bundle the TS client inside recrypt-cli.* Rejected — recrypt-cli
  is the Rust CLI; conflating it with a TS distribution would mix
  two unrelated concerns.

**Reversal triggers.**

- An external consumer needs to depend on the TS client without
  vendoring the recrypt repo.
- Multiple downstream packages need different recrypt-server
  versions, forcing per-version pinning.

When either trigger fires: extract `crates/recrypt-client-ts/` (or
wherever it lands) to its own repo, set up `npm publish` from CI,
and add a version-compat matrix to the docs.

---

## References

- Epic: recrypt-nj1
- Pilot: recrypt-gpc (`POST /accounts`)
- Capability rebuild: recrypt-91h
- TS generator selection: recrypt-uy3
- 3.1→3.0 OpenAPI workaround: recrypt-gym
