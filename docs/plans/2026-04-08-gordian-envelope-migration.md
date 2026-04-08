# Wire Format Migration: Protobuf → Gordian Envelope

**Status:** Planning
**Date:** 2026-04-08
**Author:** Duke + Claude (architectural conversation)
**Supersedes (in part):** [`2026-01-05-phase-3-protocol-layer.md`](2026-01-05-phase-3-protocol-layer.md)

## Context

Recrypt currently serializes its wire and storage format using Protobuf via
`prost` (see [`crates/recrypt-proto/proto/recrypt.proto`](../../crates/recrypt-proto/proto/recrypt.proto)).
Protobuf was adopted in Phase 3 with minimal deliberation — the design doc lists
it as a "key design decision" but contains no alternatives-considered section.

A retrospective analysis (April 2026) concluded that Protobuf is a poor fit for
recrypt's specific mix of requirements:

- **Long-lived archival blobs in S3** — protobuf is not self-describing; a
  blob without its `.proto` schema is structured noise.
- **Opaque crypto payloads** — every meaningful field in the schema is `bytes`,
  so protobuf's schema-based "type safety" buys nothing the application layer
  doesn't already enforce.
- **Extension by parties we don't control** — protobuf has no graceful story
  here; the `Any` escape hatch is universally regretted.
- **Forward compatibility for future overlay data types** — additive fields
  work, but field-number discipline becomes a coordination burden.

After evaluating alternatives (raw CBOR, COSE, Gordian Envelope), we are
adopting **Gordian Envelope** from Blockchain Commons.

This is a pre-production project with **no deployed clients and no stored
ciphertext**. The migration cost is one-time and the long-term cost of staying
on protobuf rises monotonically from here.

**Rollback path:** `git revert` the migration commit. No data migration
required — no ciphertext is deployed anywhere.

## Architectural commitment: envelope-native domain types

A load-bearing decision that shapes every other part of this plan: **domain
types in `recrypt-core` and `recrypt-proto` become envelope-native, not
struct-with-envelope-underneath**.

Two options were considered:

- **(A) Envelope at the wire boundary only.** Keep current Rust structs;
  add `to_envelope`/`from_envelope` serialization at the edges. Minimum
  diff, domain layer format-agnostic. **Rejected** because elision,
  selective signing, and metadata extension would be unreachable from
  domain code — you'd need a second code path operating on envelope
  bytes directly. That makes adopting Envelope "a worse protobuf": you
  pay the migration cost and get none of the benefits that motivated the
  choice.

- **(B) Envelope-native domain types.** `EncryptedFile` wraps or *is* an
  `Envelope`. Fields are accessed as assertions. Elision, selective
  signing, and metadata extension are first-class domain operations.
  **Chosen.** This is the only option that preserves the marquee reason
  for the migration (proxy-side elision of forwarded metadata).

Consequences of the (B) choice that propagate through this plan:

- Every consumer of `recrypt-core` types learns a small amount of
  envelope API surface. Onboarding cost is real.
- The alpha-status risk of `bc-envelope` now touches domain code, not
  just serialization. Mitigation: pin exact version; vendor if the crate
  regresses; document an escape hatch (ciborium + hand-rolled dCBOR
  subset) we could retreat to without changing the domain shape.
- The diff is larger than the initial estimate. See revised sizing
  below.
- Tests for each domain type need to cover both direct construction and
  envelope-round-trip equivalence.

## Decision: Adopt Gordian Envelope

[Gordian Envelope](https://developer.blockchaincommons.com/envelope/) is a
CBOR-based "smart document" format from Blockchain Commons (Wolf McNally,
Christopher Allen) developed within the Rebooting Web of Trust community —
which Identikey is part of. The fit is unusually good:

### What we get for free

1. **dCBOR** — a deterministic CBOR encoding profile. Solves the
   signature-input canonicalization problem we would otherwise have to
   hand-roll. Reference Rust implementation: [`bc-dcbor`](https://crates.io/crates/bc-dcbor).
2. **Self-describing archival format** — Envelope blobs are tagged
   (`#6.200`) and can be inspected via `cbor2diag` or `envelope-cli`
   without our schema present. Critical for blobs that may sit in S3 for
   years.
3. **Merkle-tree elision** — any assertion on an envelope can be replaced
   with its hash without invalidating top-level signatures. This is
   strictly more powerful than COSE's protected/unprotected header split.
   For us, the proxy server can strip or rewrite metadata before
   forwarding to recipients without breaking signatures.
4. **Semantic triples** (subject/predicate/object) — Envelope's internal
   structure is `subject [predicate: object]` assertions, which gives us
   first-class extensible metadata. Each assertion is independently
   signable, individually elidable, and can carry its own type via CBOR
   tags.
5. **Post-quantum CBOR tags already defined** — [BCR-2025-003](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2025-003-post-quantum.md)
   (Wolf McNally, April 2025) defines CBOR tags and UR types for ML-KEM
   and ML-DSA. We can use these as our standard PQ identifiers instead of
   inventing private ones.
6. **Mature Rust ecosystem** — `bc-envelope`, `bc-dcbor`, `bc-components`
   are actively maintained by Blockchain Commons (not community drive-by
   crates).
7. **Community alignment** — recrypt/Identikey is part of RWOT. Adopting
   Envelope means our wire format is legible to that community and future
   extensions can flow through the existing BC tag-registration process
   rather than being recrypt-only.
8. **IETF draft in flight** — `draft-mcnally-envelope` defines the
   `application/envelope+cbor` media type. Not yet an RFC, but on the
   standards track.

### What we still hand-roll

- **Proxy recryption primitives.** BC has no concept of PRE — it isn't in
  their scope. Our PRE-wrapped key remains a custom CBOR-tagged structure.
  See [Open Question 1](#open-questions) below.
- **Bao streaming verification.** Orthogonal to envelope format. Bao
  outboard hashes remain a sidecar S3 object (`{hash}.obao`), as in the
  current architecture per [`2026-04-06-bao-streaming-and-storage-simplification.md`](2026-04-06-bao-streaming-and-storage-simplification.md).
- **Multi-signature "all must verify" semantics.** Envelope supports
  attaching multiple signature assertions natively, but no standard
  enforces "all required." This is a recrypt application-layer rule.

### Acknowledged risks

- **Alpha status**: BC marks `BCSwiftEnvelope` as "should not be used for
  production tasks until further testing and auditing." For Phase 8
  research-grade work this is acceptable; we should re-evaluate before
  any security audit milestone.
- **Conceptual surface area**: semantic triples take a moment to
  internalize compared to "a flat CBOR map with some fields." The payoff
  (elision, recursion, clean metadata extension) is real but requires
  developer onboarding.
- **Dependency weight**: `bc-envelope` pulls `bc-dcbor` + `bc-components`
  + transitive deps. Heavier than `ciborium` alone, lighter than
  `prost` + `prost-build` + generated code.

## Functional requirements

What the migrated system must *do*. Every FR must be verifiable by a
specific test or gate before the migration is considered complete.

**FR-1: Round-trip fidelity.** Every current domain type
(`EncryptedFile`, `PublicKeyBundle`, `SecretKeyBundle`, `RecryptKey`,
`Capability`, `FileMetadata`, `KeyMaterial`) must round-trip through
the envelope format without semantic loss. Encode → decode → compare
equal.
*Gate: per-type round-trip test in `crates/recrypt-wire/tests/`.*

**FR-2: Deterministic encoding.** Serializing the same domain value
twice must yield byte-identical CBOR output. This is required for
signatures to be reproducible and verifiable.
*Gate: dCBOR byte-equality test asserting `encode(v) == encode(v)` for
each domain type.*

**FR-3: Multi-signature verification.** Every signature assertion
attached to an envelope must verify independently, and envelopes
must be rejected if any attached signature fails or if the expected
signature types (Ed25519 + ML-DSA-87) are not both present.
*Gate: signature-verification test suite; explicit test for the
"missing PQ signature" rejection path and the "missing classical
signature" rejection path.*

**FR-4: Elision preserves signature validity.** An envelope signed
with all assertions present must still verify after a subset of
non-signature assertions are elided (replaced with their hashes).
This is the marquee feature of the migration.
*Gate: sign-then-elide-then-verify test for each elision scenario we
document in Doc 1.*

**FR-5: Proxy recryption preserves envelope integrity.** The recryption
proxy's core operation — swapping the wrapped-key object for its
recrypted form — must produce an envelope that still verifies
under the recipient's keys, without requiring the proxy to hold or
forge the originator's signing keys.
*Gate: end-to-end test with Alice → proxy → Bob where proxy has
only the recryption key, not Alice's secret key.*

**FR-6: Content-addressed ciphertext unchanged.** The
XChaCha20+Bao-encrypted ciphertext and its content-addressed S3
location (Blake3 of ciphertext) must not change as part of this
migration. Only the metadata envelope and wrapped-key serialization
change.
*Gate: `just test-e2e` passes without changes to the storage layer's
content-addressing logic.*

**FR-7: ASCII armor still works.** Keys, capabilities, and encrypted
files can still be exported to and imported from ASCII armor. The
inner payload changes from protobuf-encoded to envelope-encoded;
the armor framing remains. BEGIN/END banners must be updated so
an armor blob from the old format cannot be silently misparsed.
*Gate: armor round-trip test per armor type; explicit rejection
test for old-format armor banners.*

**FR-8: HTTP content negotiation.** Server endpoints that currently
advertise `application/x-protobuf` must advertise
`application/envelope+cbor` instead, and reject requests with the
old content type explicitly.
*Gate: integration test sending both old and new `Content-Type`
headers; old MUST be rejected.*

**FR-9: CLI output stability.** The CLI's human-facing output (file
lists, status messages, identity commands) is unchanged. The CLI's
`--json` output may change field shapes; if it does, the new shape
is documented and a migration note appears in the CLI help.
*Gate: grep audit of `recrypt-cli/src/` for JSON output paths;
document any field-shape changes explicitly.*

**FR-10: Version discrimination.** A recrypt envelope must carry
enough information in its outer structure that a parser can reject
unsupported format versions before attempting full deserialization.
*Gate: test that an envelope claiming an unknown `format-version`
assertion is rejected with a clear error.*

## Non-functional requirements

What the migrated system must *be*. Measurable qualities, not features.

**NFR-1: No performance regression on hot paths.** The recryption
proxy's `GET /recryption/share/{id}/file` handler must not regress
more than 20% in p50 latency against the current protobuf
implementation. The hot path is: parse envelope → apply PRE
transform → re-serialize → return.
*Gate: criterion benchmark comparing old vs new before merge,
documented in Doc 1's benchmark table.*

**NFR-2: Storage overhead stays small.** Metadata envelope size
(everything except the content-addressed ciphertext) must stay
under 5% of payload size for typical files (1 MB+) and under 2 KB
absolute for any envelope regardless of payload.
*Gate: size measurement across test fixtures documented in Doc 1's
benchmark table.*

**NFR-3: Dependency surface controlled.** Adopting `bc-envelope`
must not pull in more than ~15 new transitive dependencies. If it
does, audit what's new and document in the plan changelog.
*Gate: `cargo tree` diff before and after, documented in the
migration PR description.*

**NFR-4: Build time not significantly worse.** Removing `prost`
codegen should roughly offset adding `bc-envelope` compilation.
Full `cargo build` wall time must not regress more than 10%.
*Gate: timed clean builds before and after.*

**NFR-5: Test suite runs in the same order of magnitude.**
`just test` wall time must not regress more than 25%. Envelope
construction is slower than protobuf decode, so some regression
is expected; anything beyond 25% suggests a test-setup issue
worth investigating.
*Gate: timed test runs before and after.*

**NFR-6: Self-describing archival property.** A recrypt envelope
blob, taken in isolation without any schema or source code, can
be parsed to its diagnostic notation by an off-the-shelf CBOR
tool (`cbor2diag`, `envelope-cli`) in a way that exposes its
top-level structure. This is the archival-future-proof property
that motivated the migration.
*Gate: manual verification — pipe a sample envelope into
`envelope-cli format` and confirm human-readable output.
Documented in Doc 1 with a concrete example.*

**NFR-7: Cryptographic invariants enforced at the type level
where feasible.** Where we can use Rust's type system to make
invalid states unrepresentable (e.g., "a signed envelope always
has at least one signature assertion"), we do. Where we can't,
the invariant is enforced by a constructor function and tested.
*Gate: code review — every domain type's public constructor
either uses types to enforce invariants or has an explicit
test for each invariant.*

**NFR-8: Error messages point at the cause.** Envelope parsing
errors must identify which assertion failed and why (missing
required assertion, wrong CBOR tag, invalid signature, etc.).
Generic "parse error" is not acceptable.
*Gate: error-path tests for each documented failure mode; each
error message is asserted against in the test.*

**NFR-9: Documentation is enough for a second implementer.** A
competent Rust engineer who has read Docs 0-3 and the `bc-envelope`
public docs must be able to reproduce the recrypt envelope format
without asking follow-up questions. This is the "degrades
gracefully in 5 years" property.
*Gate: have one other RWOT community member read Doc 1 + Doc 2
before merging — or, at minimum, have the docs reviewed via
`code-reviewer` agent with that lens applied.*

**NFR-10: No silent data loss across format changes.** The migration
must never produce an envelope that decodes to a domain type with
fewer fields populated than the encoding had. Envelope assertions
present at encode time must be either preserved, explicitly
stripped via elision, or rejected with an error — never silently
dropped.
*Gate: round-trip test with instrumentation asserting that no
assertion present at encode-time disappears without explicit
elision.*

## Migration gates

A linear sequence of checkpoints. Each gate must pass before the
next phase of work begins.

**Gate 0: Doc 0 spike validates the model.** The envelope sketch
compiles, round-trips in a scratch binary, and confirms the
semantic-triples model feels right for recrypt's data shape. If
this gate fails, re-evaluate option B vs a lighter-weight CBOR
approach. **Blocks: Doc 1, all code work.**

**Gate 1: Docs 1-3 are written and internally reviewed.** Wire
protocol, XChaCha20+Bao AEAD, and threat-model hybrid-sig
rationale are drafted and critiqued. FR/NFR list above has been
re-checked against the docs for coverage. **Blocks: code work.**

**Gate 2: `recrypt-wire` crate compiles and passes unit tests.**
Envelope-native domain types exist, round-trip tests (FR-1) pass,
dCBOR determinism tests (FR-2) pass, signature tests (FR-3) pass.
**Blocks: caller migration.**

**Gate 3: `recrypt-server` and `recrypt-cli` migrate.** All call
sites updated, armor banners updated (FR-7), Content-Type headers
updated (FR-8), CLI JSON audited (FR-9). `just test` passes.
**Blocks: integration validation.**

**Gate 4: End-to-end tests pass.** `just test-e2e` with mock
backend (FR-5, FR-6) and `just test-e2e-lattice` with real
OpenFHE. Elision test (FR-4) passes. **Blocks: benchmarks.**

**Gate 5: NFR benchmarks meet thresholds.** NFR-1 latency, NFR-2
size, NFR-3 dep surface, NFR-4 build time, NFR-5 test time all
measured and within thresholds. Results written into Doc 1's
benchmark table. **Blocks: merge.**

**Gate 6: External doc review.** NFR-9 satisfied — either one
RWOT reader or a `code-reviewer` agent pass has reviewed Docs 1
and 2 for clarity and completeness. **Blocks: merge.**

**Gate 7: Wolf feedback incorporated or timeout reached.** Either
BC has responded on the PRE-wrapped-key tag question and we've
aligned, or 2026-04-22 has passed and we've committed to the
private-use tag path. **Blocks: merge.**

## Documentation tasks (do these BEFORE writing code)

The conceptual surface is large enough that we should write the docs first
and let them drive the implementation, not the other way around.

**Exception:** Doc 0 / Spike below must happen before Doc 1. You cannot
write a credible envelope schema for `EncryptedFile` without having
sketched one against real types first.

### Doc 0: Envelope sketch spike (`docs/spikes/2026-04-envelope-sketch.md`)

**Not a polished doc — a grounded sketch.** Before writing Doc 1, spike
an envelope representation for each of the current domain types in
[`crates/recrypt-proto/src/`](../../crates/recrypt-proto/src/):

- `EncryptedFile` (the primary payload)
- `PublicKeyBundle` / `SecretKeyBundle`
- `RecryptKey`
- `Capability`
- `FileMetadata`

For each, write: (1) the CBOR diagnostic notation of the envelope as
concrete bytes, (2) which assertions are typically signed vs typically
elided, (3) any open questions. Run this against the actual `bc-envelope`
API to validate the shape compiles and round-trips.

**Acceptance criteria:**
- [ ] Every field in [`recrypt.proto`](../../crates/recrypt-proto/proto/recrypt.proto)
  has a corresponding envelope assertion in the sketch
- [ ] At least one sketch successfully round-trips via `bc-envelope` in
  a scratch Rust binary (can live in `/tmp`, not committed)
- [ ] Open Question 1 (PRE-wrapped key placement) has a concrete
  proposal by the end of the spike, ready to send to Wolf
- [ ] dCBOR edge cases we'll hit are enumerated (float handling,
  map key ordering, NaN rules)

Doc 1 is gated on completion of this spike.

### Doc 1: New `docs/wire-protocol.md`

Full rewrite. Sections to cover:

- **Why Envelope** — the alternatives-considered section the original
  Phase 3 plan never had. Cite this plan, COSE analysis, the protobuf
  retrospective.
- **Semantic triples primer** — short conceptual intro:
  `subject [predicate: object]` assertions, the Merkle digest tree,
  why this is more powerful than flat key-value headers. Link to
  [Wolf's cbor-book](https://github.com/BlockchainCommons/cbor-book) for
  deeper background.
- **Elision mechanics** — what it means to elide an assertion, how the
  signature survives, concrete recrypt use case: *proxy server may
  elide recipient PII or routing hints from the envelope it forwards
  without breaking the originator's signature*.
- **The recrypt EncryptedFile envelope schema** — written in CDDL or as
  annotated example envelopes. Lists every assertion we attach, its
  predicate, its CBOR tag, and whether it's typically protected
  (signed) or commonly elided.
- **Multi-signature policy** — explicit statement that recrypt requires
  *all* signature assertions on an envelope to verify. Document the
  Ed25519 + ML-DSA-87 pairing rationale (see Doc 3).
- **Versioning and forward compatibility** — how new assertions are
  added, the deprecation policy, the CBOR tag for the recrypt
  envelope itself.
- **Bao sidecar relationship** — clarify that Envelope handles
  metadata/wrapped-key/signatures and Bao+ciphertext live in a parallel
  content-addressed S3 object. The envelope references the bao hash;
  the ciphertext is fetched separately.
- **dCBOR rules that bite us** — enumerate the specific dCBOR
  constraints that differ from ciborium defaults: canonical float
  encoding (no NaN, no -0.0, smallest representation), strict map key
  ordering, integer encoding rules. Populated from the Doc 0 spike.
- **Benchmark parity numbers** — measured envelope blob size and
  encode/decode time for a representative `EncryptedFile`, compared
  against the current protobuf baseline. One table, one paragraph of
  interpretation. This closes the "does envelope overhead hurt?"
  question with a number instead of a hand-wave.

**Acceptance criteria for Doc 1:**
- [ ] Every field currently in `recrypt.proto` has a documented
  envelope assertion with its CBOR tag and typical protected/elided
  status
- [ ] CDDL or annotated diagnostic-notation examples for each domain
  type
- [ ] Benchmark table populated with real numbers from the spike
- [ ] dCBOR edge-case list is complete enough that an independent
  implementer would not be surprised

### Doc 2: New `docs/xchacha20-bao-aead.md`

Standalone definition of "XChaCha20 + Bao" as a streaming AEAD construction,
positioned as a sibling to the popular XChaCha20-Poly1305 variant. Sections:

- **Motivation** — why we want streaming verification (large files,
  partial reads, untrusted storage proxies serving chunks). Why
  Poly1305 alone isn't enough (single-shot, no incremental verify).
- **Construction** — XChaCha20 for confidentiality (24-byte nonce,
  256-bit key); Bao tree mode over the *ciphertext* for integrity and
  random-access verification; the bao root hash plays the role
  Poly1305's tag plays in the standard variant.
- **Security argument** — why authenticating the ciphertext via Bao is
  equivalent (in our threat model) to authenticating it via Poly1305,
  given that the bao root is signed by the producer's signing key.
  Encrypt-then-MAC reasoning.
- **Comparison table** — XChaCha20-Poly1305 vs XChaCha20-Bao on:
  streaming, random access, tag size, key/nonce sizes, throughput,
  failure modes.
- **Wire encoding** — how the bao root hash and outboard tree are
  carried (envelope assertion + sidecar S3 object).
- **Test vectors** — at least a few KAT-style examples so independent
  implementers can validate.

This doc is valuable beyond recrypt — it's a contribution back to the
community and would be the canonical reference for anyone wanting the
streaming-verification properties of Bao with the encryption properties of
XChaCha20. Worth eventually circulating to RWOT / BC for review.

**Acceptance criteria for Doc 2:**
- [ ] At least three KAT-style test vectors (key + nonce + plaintext →
  ciphertext + bao root) that a second implementer can reproduce
- [ ] Explicit encrypt-then-MAC security argument covering why signing
  the bao root is equivalent to a Poly1305 tag in our threat model
- [ ] Comparison table vs XChaCha20-Poly1305 with concrete numbers

### Doc 3: Update `docs/threat-model.md` (or create)

Document the rationale for the Ed25519 + ML-DSA-87 hybrid signature pairing
explicitly, since it's the load-bearing reason we're outside the
`draft-ietf-jose-pq-composite-sigs` standard set:

- **Ed25519 as identity primitive** — 32-byte deterministic public key
  derivable from a seed, small enough to use as a fingerprint base
  (Blake3(ed25519_pk) → `PublicKeyFingerprint`). ML-DSA-87 public keys
  are ~2.6 KB and unsuitable for this role.
- **Defense in depth** — ML-DSA implementations are new; pairing with a
  well-understood classical signature reduces blast radius of
  PQ-implementation bugs.
- **Audit/compliance posture** — explicit hybrid signals "we trust
  Ed25519 today and add PQ resistance for tomorrow's adversary"
  rather than "we bet everything on a 2024-finalized scheme."
- **Acknowledged asymmetry** — Ed25519 is ~128-bit classical, ML-DSA-87
  is ~256-bit (Cat 5). The standards-track composite drafts pair
  ML-DSA-87 with Ed448 specifically for level matching. We accept
  the asymmetry because the Ed25519 side is belt-not-suspenders
  for recrypt's threat model: it covers classical adversaries today,
  the ML-DSA side covers future quantum adversaries. We are not
  claiming Cat-5 classical security from the Ed25519 component.
- **Recrypt's "all must verify" rule** — explicit, since no standard
  enforces it.

**Acceptance criteria for Doc 3:**
- [ ] All four rationale points for Ed25519 + ML-DSA-87 pairing are
  stated explicitly
- [ ] "All signatures must verify" rule is documented as a recrypt
  application-layer invariant with a test reference
- [ ] The standards-asymmetry acknowledgment is written down so it
  cannot be rediscovered by an auditor

### Doc 4: Update `docs/architecture.md` and the README

Replace protobuf references throughout. Specifically the `recrypt-proto`
crate description, the wire format mentions in the storage and proxy
sections, and any diagrams that show "protobuf bytes" in flow arrows.

### Doc 5: Migration plan addendum (this document)

After documentation is written and reviewed, append a concrete
implementation checklist to this file with file-level scope estimates.

## Implementation outline (deferred until docs are done)

Sketched here for sizing only. Do not start coding until Docs 1-3 are
drafted and reviewed.

### Crate-level changes

- **`recrypt-proto` → rename to `recrypt-wire`** (or similar). The
  word "proto" is misleading once protobuf is gone. The crate's
  responsibilities shrink: it owns envelope construction/parsing,
  the recrypt-specific CBOR tags, and the `MultiFormat` trait
  (which collapses to envelope ↔ armor since JSON falls out).
- **Delete**: `proto/recrypt.proto`, `src/generated/`, `build.rs`,
  `prost` and `prost-build` dependencies, `prost-types`.
- **Add**: `bc-envelope`, `bc-dcbor`, `bc-components` (or whichever
  subset of BC crates we end up needing).
- **Rewrite**: `convert.rs` and `impls.rs` as envelope construction
  for each core type (`EncryptedFile`, `PublicKeyBundle`,
  `RecryptKey`, `Capability`, `FileMetadata`).
- **Keep**: `armor.rs` — it's format-agnostic, just wraps bytes.
  Inner payload changes from protobuf-encoded to envelope-encoded.

### Caller changes

Cite specific handlers, not just files, so the diff surface is visible:

- [`recrypt-server/src/routes/recryption.rs`](../../recrypt-server/src/routes/recryption.rs)
  — the share-GET handler (`EncryptedFile` deserialization + PRE
  transform + re-serialization). Grep for `to_protobuf`/`from_protobuf`
  to find the exact call sites before starting.
- [`recrypt-server/tests/recryption_share_test.rs`](../../recrypt-server/tests/recryption_share_test.rs)
  — fixture setup and golden bytes
- [`recrypt-cli/src/commands/encrypt.rs`](../../recrypt-cli/src/commands/encrypt.rs)
  — the `write_encrypted_file` path
- [`recrypt-cli/src/commands/decrypt.rs`](../../recrypt-cli/src/commands/decrypt.rs)
  — the `read_encrypted_file` path
- HTTP `Accept`/`Content-Type` headers — `application/x-protobuf` →
  `application/envelope+cbor`
- ASCII armor headers — current BEGIN/END banners contain the word
  "PROTOBUF" or similar; audit [`armor.rs`](../../crates/recrypt-proto/src/armor.rs)
  and update banner strings. This is a user-visible format break,
  not purely internal.
- CLI JSON output — grep `recrypt-cli/src` for any output paths that
  embed protobuf-derived field names or type URLs. Any such strings
  need to be either reshaped to envelope assertion predicates or
  explicitly deprecated.

### Testing strategy

Non-negotiable gates for the code migration:

1. **Round-trip test per envelope type.** For each of
   `EncryptedFile`, `PublicKeyBundle`, `RecryptKey`, `Capability`,
   `FileMetadata`: construct → serialize → deserialize → assert
   semantic equality. Replaces the current `tests/roundtrip.rs`.
2. **dCBOR determinism test.** Serialize the same domain value twice
   and assert **byte-identical** output. This is the whole point of
   dCBOR and if it doesn't hold, signatures break. Must be an
   explicit assertion, not an implicit assumption.
3. **Signature-over-elided-envelope test.** Construct an envelope,
   sign it, elide a subset of assertions, verify the signature still
   checks. This is the marquee feature of the migration and it needs
   an explicit test proving it works end-to-end with our signing
   code. If this test can't be written cleanly, the envelope-native
   domain-type decision (option B above) needs to be revisited.
4. **`just test-e2e` as integration gate.** The existing end-to-end
   recryption test (Alice → Bob via mock backend) must pass
   unchanged in behavior. This is the regression net for the whole
   migration.
5. **`just test-e2e-lattice` before merge.** Same test with the
   real OpenFHE backend. Slower; run once before merging, not on
   every iteration.
6. **Decision on `crates/recrypt-proto/tests/`:** `roundtrip.rs` and
   `signature_serialization.rs` get **rewritten in place** against
   the envelope types. Names stay; internals change. Don't delete
   and recreate — it confuses git history.

### Size estimate (revised)

Honest accounting after factoring in the option-B decision, the
alpha-crate learning curve, the crate rename, and the docs that
actually have to be written:

- **Doc 0 / Spike**: 0.5 day
- **Doc 2 (XChaCha20+Bao AEAD)**: 1 day (substantive, standalone)
- **Doc 1 (wire-protocol rewrite)**: 1 day (depends on Doc 0)
- **Doc 3 (threat model hybrid sig)**: 0.5 day
- **Docs 4-5 (architecture, README, this plan's checklist)**: 0.5 day
- **Code: envelope-native domain types**: 1.5 days (bigger than
  wire-boundary-only because every consumer touches envelope APIs)
- **Code: caller migration + armor/CLI audit**: 0.5 day
- **Code: crate rename `recrypt-proto` → `recrypt-wire`**: 0.5 day
  (workspace Cargo.toml + use statements + doc links)
- **Buffer for alpha-crate surprises**: 1 day
- **Benchmark pass + write-up**: 0.5 day

**Total: ~7 working days**, with docs gating code. If the crate
rename is deferred (Open Question 4), drop 0.5 day.

## Open questions

1. **Where does the PRE-wrapped key live?** Two options:

   a) **Inline as an envelope assertion** with a recrypt-specific CBOR
      tag — `["wrapped-key": tag(recrypt-pre-ciphertext, ...)]`.
      Simple, single artifact.

   b) **Separate envelope/structure**, referenced from the file
      envelope by hash. Cleaner separation: the file envelope holds
      metadata + signature + reference; the wrapped key is a separate
      addressable object.

   Decision: lean toward (b) on the principle that "after PRE
   transform, the wrapped key is just a symmetric key in a box" and
   that's a different kind of object than "an encrypted file." It also
   means the proxy recryption operation rewrites *only* the wrapped-key
   object and leaves the file envelope untouched, which is structurally
   cleaner and avoids re-signing on every recryption. Worth checking
   whether `bc-components` has a pattern (`SealedMessage`,
   `EncryptedMessage`, etc.) we can either reuse directly or
   parallel-construct for the PRE case. **Action:** ask Wolf if BC has
   anything pre-existing that fits, or if a `recrypt-wrapped-key` tag
   would be a reasonable addition to the BC registry.
   **Timeout:** if no BC guidance by **2026-04-22** (two weeks), proceed
   with option (b) and a private-use CBOR tag for `recrypt-wrapped-key`.
   We can retroactively align with whatever BC publishes later without
   breaking wire compat, since our private tag would live alongside
   any future BC tag.

2. **Should the bao root hash live as an envelope assertion or stay
   purely in S3 metadata?** Probably as an assertion so it's covered
   by the producer's signature. Confirm during Doc 1 drafting.

3. **dCBOR vs ciborium for non-envelope CBOR.** Some recrypt internal
   structures may not need to be envelopes (e.g., the
   `KeyMaterialProto` 96-byte bundle). We should standardize on dCBOR
   for everything-on-the-wire even when not wrapped in an envelope,
   for consistency. Worth a sentence in Doc 1.

4. **Migration of the existing `recrypt-proto` crate name.** Renaming
   touches every `Cargo.toml` in the workspace. Worth doing as part
   of this migration since we're already touching all the call sites,
   but it's a separate logical step. Could defer if we want to keep
   the diff focused. **Tentative decision:** do it as part of this
   migration; the name "proto" is actively misleading post-migration
   and every call site is already being touched.

## Alpha-status mitigation

`bc-envelope` is marked alpha. The option-B decision means this risk
touches domain code, not just serialization. Mitigation plan:

1. **Pin exact version** in `Cargo.toml` (not a semver range). Upgrade
   deliberately, not automatically.
2. **Vendor if needed.** If a specific version works and upstream
   regresses, we can `cargo vendor` and pin to a local copy while we
   decide whether to update.
3. **Documented escape hatch.** If BC crate becomes untenable, the
   fallback is: retreat to `ciborium` + a hand-rolled subset of
   dCBOR that enforces only the rules our signature canonicalization
   actually needs (map key ordering, canonical integer encoding,
   canonical float encoding, no indefinite-length items). This is
   ~100 LoC of serialization glue. The envelope-native domain
   *shape* does not need to change — `Envelope`-bearing types would
   be swapped for a minimal in-house equivalent with the same
   assertion/elision API surface, backed by raw CBOR. This is a
   multi-day escape hatch, not a day-of, but it's documented here
   so it's not a surprise if we need it.

The escape hatch would be a last resort — we'd only reach for it if
`bc-envelope` abandonware-ed or took a direction that broke our use
case. For the expected path (BC continues maintaining and the
alpha→beta→1.0 trajectory progresses over the next year), no action
beyond version pinning is needed.

## Next steps

1. **Read `bc-envelope-rust` examples** — get a feel for the API
   surface and the typical envelope construction patterns. ~1 hour.
2. **Sketch `EncryptedFile` as an envelope** in a scratch file (not
   committed) to validate the semantic-triples model feels right for
   our data shape. ~1 hour.
3. **Reach out to Wolf** about Open Question 1 — whether BC has a
   `SealedMessage`-like primitive we can adapt for PRE-wrapped keys,
   or whether registering a new tag is the right path.
4. **Write Doc 2 (XChaCha20+Bao AEAD)** first — it's the most
   self-contained and least dependent on envelope details. Good
   warmup before tackling Doc 1.
5. **Write Doc 1 (wire-protocol)** with concrete envelope examples
   driven by the sketch from step 2.
6. **Write Doc 3 (threat-model hybrid sig rationale)**.
7. **Implementation**, gated on doc review.

## References

- [Gordian Envelope developer docs](https://developer.blockchaincommons.com/envelope/)
- [draft-mcnally-envelope (IETF draft)](https://blockchaincommons.github.io/WIPs-IETF-draft-envelope/draft-mcnally-envelope.html)
- [BCR-2025-003: Post-Quantum CBOR Tags](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2025-003-post-quantum.md)
- [BCR-2023-013: Gordian Envelope Cryptography](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2023-013-envelope-crypto.md)
- [Gordian Sealed Transaction Protocol (GSTP)](https://developer.blockchaincommons.com/envelope/gstp)
- [The CBOR, dCBOR, and Gordian Envelope Book](https://github.com/BlockchainCommons/cbor-book) — Wolf McNally
- [`bc-envelope` crate](https://crates.io/crates/bc-envelope)
- [`bc-dcbor` crate](https://crates.io/crates/bc-dcbor)
- Original Phase 3 plan: [`2026-01-05-phase-3-protocol-layer.md`](2026-01-05-phase-3-protocol-layer.md)
- Bao streaming work: [`2026-04-06-bao-streaming-and-storage-simplification.md`](2026-04-06-bao-streaming-and-storage-simplification.md)

## Changelog

**2026-04-08 — Critic review pass (REVISE → APPROVED after updates):**

- Added rollback path (one-line, pre-prod trivial)
- Added explicit architectural commitment to **option B**
  (envelope-native domain types), with rejected option A documented
  and consequences propagated through the plan
- Added **Doc 0 / Spike** before Doc 1 to resolve chicken-and-egg:
  cannot write schema doc without sketching against real types first
- Added **acceptance criteria** to Docs 0, 1, 2, 3
- Added **testing strategy** section: round-trip per type, dCBOR
  determinism byte-equality assertion, signature-over-elided-envelope
  test, `test-e2e` + `test-e2e-lattice` gates, decision on existing
  `recrypt-proto/tests/` fate
- Added **benchmark parity** requirement (Doc 1 must contain
  measured size/speed table vs protobuf)
- Added **armor header and CLI JSON audit** items to caller changes
- Added specific handler citations to caller-changes section
- Added **dCBOR edge cases** subsection to Doc 1 scope
- Revised **size estimate** from 3 days to ~7 days honest accounting
  (option B diff is larger; alpha crate learning curve; crate rename;
  explicit buffer)
- Added **Wolf timeout**: 2026-04-22 deadline, proceed with
  private-use tag if no BC guidance
- Added **alpha-status mitigation** section: pinning, vendoring,
  documented ciborium+hand-rolled-dCBOR escape hatch
- Tentative decision recorded on Open Question 4 (do the crate
  rename as part of this migration, don't defer)
