# Next Steps Backlog

**Date:** 2026-04-07
**Status:** 📋 Living backlog — items here are explicitly deferred, not
abandoned

This document tracks work that is out of scope for the current sprints
but deliberately remembered. Each entry includes the context that
motivated deferral and a pointer to where the primitive or scaffolding
already lives, so picking it up later is cheap.

Critical-path sprints that this backlog explicitly excludes:
- [2026-04-06-bao-streaming-and-storage-simplification.md](2026-04-06-bao-streaming-and-storage-simplification.md)
- [2026-04-07-production-readiness.md](archive/2026-04-07-production-readiness.md)
- [2026-04-07-group-sharing.md](2026-04-07-group-sharing.md)

Anything below is "after those three land".

---

## Discoverability, sync, and indexes

The "feels like Dropbox" polish layer: how users actually navigate and
keep up with what's in their drive and in their groups.

### Per-user file index

- "My Drive" — the list of files I own, with folder/path metadata
  that lives outside the ciphertext objects
- "Shared with me" — files other users have shared with me, grouped
  by sharer or by group
- "Shared by me" — files I've shared, grouped by recipient or by
  group
- Sort, filter, search over my file list
- Tombstones for deleted files so sync knows to remove local copies

**Where the primitives already live:**
`recrypt-storage-auth::OwnershipStore::list_owned` and
`list_shared_with` give us the raw "which file hashes" queries.
Everything above those is UX metadata (names, folders, tags,
timestamps) that does not exist yet. That metadata should probably
live in a new "library" service or in the auth service's database as
additional per-user tables — to be designed.

### Group-level file index and notifications

- "What's new in Family?" — a feed of recent additions to a group
- Notifications when a new file is added, when a member is added or
  removed, when a share is revoked
- Incremental sync: "give me everything that's changed in group X
  since cursor Y"

**Where the primitives already live:**
Nowhere. The `shares` table has timestamps; a naive cursor-based sync
can be built on top of `updated_at`. Real pub/sub (WebSocket, SSE,
push notifications) is entirely new infrastructure.

### Watched folders / background sync client

- A background daemon that watches a local folder for changes and
  uploads new files to a configured group
- Reverse: a background daemon that pulls new files from a group
  into a local folder
- Conflict handling for edits

Classic Dropbox-client territory. Real product work, probably a
separate binary that depends on `recrypt-cli` internals.

---

## Plaintext layer

Content addressing and organization for plaintext files before they
become ciphertext objects in storage.

### Plaintext content addressing

- Stable local identifier for a plaintext file: `blake3(plaintext)`
- Used purely client-side (never transmitted)
- Lets a user answer "do I already have this file under a different
  name?" without re-encrypting to compare
- Separates "logical identity" from "ciphertext identity" — same
  plaintext can be re-encrypted under a new random key producing a
  new ciphertext with the same plaintext hash

**Why not cross-user (convergent encryption)?** Confirm-a-file
attacks and offline guessing attacks on low-entropy files — see the
dedup analysis in
[2026-04-06-bao-streaming-and-storage-simplification.md](2026-04-06-bao-streaming-and-storage-simplification.md).
Local-only plaintext addressing avoids these entirely.

### Folder / path metadata

Independent of ciphertext storage. A tree structure, names, parent
pointers, timestamps. Lives in a per-user metadata store, probably
the same place as the file index above.

Open question: is this stored encrypted on the server, stored only
locally with client-side sync, or something in between? Has
implications for multi-device.

### Search

Once plaintext content addressing and folder metadata exist,
client-side full-text search over decrypted content becomes possible.
Probably an index-as-you-encrypt approach (build an inverted index
locally, encrypt it, store it as its own file).

---

## Multi-device

Right now an identity is one wallet on one device. Real users want
phone + laptop + desktop.

### Identity sync

- Secure transfer of a wallet (or a derived sub-identity) from one
  device to another
- QR code handshake, PAKE-based pairing, or provisioning via a
  dedicated server

**Where this will be done:** identikey key-recovery code is being
moved into the identikey codebase, which specializes in exactly this.
Recrypt will integrate with identikey's provisioning/recovery APIs
rather than building its own.

### Per-device subkeys

Instead of copying the same wallet to every device, derive per-device
subkeys from a master. Devices can be revoked individually.

Requires a real key derivation hierarchy we don't have today.

### Account recovery

Related to multi-device: if all your devices are lost, how do you
recover access to your files? Options include social recovery
(Shamir shares with N-of-M friends), printed recovery phrases, or
trusted-device re-provisioning.

**Where this will be done:** identikey. Recrypt will not implement
its own recovery story; it will consume identikey's.

---

## Proxy trust model improvements

Making the recryption proxy less trusted than it is today.

### Non-transferable / obliviously delegatable proxy recryption

Make the proxy cryptographically unable to deliver a recrypted
ciphertext to the wrong recipient. The recrypt transform binds to a
live signed request from the intended recipient such that the
proxy's output is only usable by that specific signer.

Real research direction. Known techniques exist. Would eliminate the
"semi-trusted for policy enforcement" caveat in the threat model and
leave only availability + metadata as residual proxy capabilities.

**Prerequisite:** literature review, possibly backend support in the
PRE layer. Not something we can drop into the current implementation
without cryptographic work. Tracked as Phase 10+.

### Multi-proxy / federation

Multiple recryption proxies, clients pick which one to use, or
use multiple for redundancy. Protects against a single bad actor
proxy. Composes naturally with content-addressed storage (the blob
hash works anywhere) and with per-member recrypt keys (they're small
and can be replicated).

### Anonymous credentials for download authorization

Instead of `X-Public-Key` headers tying every download to a
fingerprint, use anonymous credentials where the proxy learns "this
caller is a legitimate member of group X" without learning *which*
member. Reduces metadata leakage. Research direction, non-trivial.

---

## Cryptographic hardening

### XChaCha20-Poly1305 vs raw XChaCha20

Today we use raw XChaCha20 and rely on the signed `bao_hash` as our
authenticator. This is correct as long as the signature is verified
before decryption — but a single code-path bug breaks the story.

Switching to XChaCha20-Poly1305 (AEAD) gives us a belt-and-suspenders
authenticator that decryption refuses to proceed without. The
tradeoff is that Poly1305 is a linear MAC — random-access
verification becomes harder.

See
[2026-04-06-bao-streaming-and-storage-simplification.md §8.6](2026-04-06-bao-streaming-and-storage-simplification.md)
for the full analysis. Decision target: before Phase 9 security audit.

### Nonce persistence

`NonceStore` is allowed to be in-memory today; restart opens a 5-minute
replay window. For a real production deployment this may need to flip
to SQLite-backed. Decision target: before Phase 9.

### Signature audit

Formal statement of what the multi-signature construction (ED25519 +
ML-DSA-87) guarantees, what it assumes, and what breaks if either
primitive falls. Part of the pre-audit threat model pass.

### `bao-tree` audit review

`bao-tree` is maintained by n0-computer, production-used by iroh, and
unaudited. The construction is a standard BLAKE3 Merkle tree. We
should write down our reasoning for why the lack of formal audit is
acceptable for our use case (or, if it isn't, what we need to do
about it).

Decision target: before Phase 9.

---

## Operations and deployment

### Deployment guide and Mjolnir integration

The deployment guide itself — covering `brew install libomp`, Minio
/ S3 setup, running the server, TLS via reverse proxy, backend
selection (mock vs lattice), operational concerns (orphan GC, nonce
store GC, SQLite backups).

**Where this will be done:** in concert with the Mjolnir system
which handles deployment orchestration in our environment. Gets
picked up after production-readiness lands.

### Monitoring / observability

Metrics (Prometheus exposition from the server), distributed tracing
(`tracing` crate is already in `recrypt-server`, needs exporters),
structured logging (already done).

Not in any current sprint. Comes with Mjolnir.

### Container images

Dockerfile for `recrypt-server`, reference docker-compose setup for
self-hosting, published image tags. Mjolnir-adjacent.

### Reference deployment

A known-good starter config for a small self-hosted deployment: one
recryption proxy, one SQLite database, Minio, nginx TLS termination,
sensible rate limits. The "hello world" for someone who wants to try
the system without reading ten docs.

### Orphaned S3 blob GC

The streaming plan introduces "metadata is the atomic commit point",
which means aborted uploads leave ciphertext+outboard sibling pairs
in S3 with no metadata pointing at them. Need a periodic GC sweep
that finds blobs older than `max_upload_lifetime` with no owning
metadata record and deletes them. Also: when a file is deleted, blobs
get marked for deletion and the GC sweep respects that.

Lives in `recrypt-server` as a background task. Not hard; just
needs design and implementation in the operational-readiness wave.

---

## Group sharing v2

Features intentionally punted from the Group plan
([2026-04-07-group-sharing.md](2026-04-07-group-sharing.md)) for MVP
scope control.

### Admin roles and multi-owner groups

- Co-owners / admins who can add and remove members
- Ownership transfer
- Delegated management (Alice owns Family but Bob can add kids to it)

### Read/write group membership

- Members who can upload new files to the group, not just read
- Requires a signing story for "Bob claims this upload is on behalf
  of the Family group"
- Opens questions about who can revoke Bob's writes vs his reads

### Group invite flow

Rather than the owner unilaterally adding members (requires the
owner to already have the member's public key), a real invite
protocol:
1. Owner creates an invite link / code
2. Recipient accepts, sending their public key to the server
3. Server notifies owner
4. Owner's client generates recrypt keys and publishes to the group

### Nested groups and group hierarchies

"Engineering" contains "Frontend" and "Backend", with files shared
with a parent group visible to all children. Real team-collaboration
feature.

### Group-owned files

Files that belong to the group itself rather than to an individual
member. Survives the original owner leaving. Requires a concept of
"group secret key" that no single person holds (threshold signing).

### Public groups and discovery

"Anyone can join this group and read these files" — turns recrypt
into a content publishing platform. Very different trust model from
the current private-sharing design.

---

## API and protocol polish

### `MultiFormat` JSON coverage

Full JSON implementations for `PublicKeyBundle`, `SecretKeyBundle`,
`RecryptKeyProto`, and `CapabilityProto` — currently they can only
go through proto + armor. See
[wire-protocol.md §3.2](../wire-protocol.md).

### API stability promise

At some point we commit to a stable wire format. What are the
compatibility guarantees? What's a breaking change? Which fields
are frozen? When does the proto package become `recrypt.v1` (stable)
versus today's "subject to change"?

Not a code change — a governance decision.

### Contributing guide

If recrypt becomes open source, on-ramp for new contributors: repo
layout, dev setup (including OpenFHE build quirks), how to run
tests, PR guidelines, commit message conventions.

### User guide updates

User guide currently reflects pre-streaming and pre-group APIs.
Needs refresh after those sprints land.

---

## Documentation polish

### `recrypt-core/src/lib.rs` rustdoc

- Why `KeyMaterial` is always 96 bytes (fixed to match
  `LatticeBackend::max_plaintext_size()`)
- Metadata-confidentiality rationale for encrypting `plaintext_hash`
  inside `wrapped_key`
- More prominent pointer to `non-determinism.md` in a Testing
  section

### Phase 4b auth service gaps

- Postgres backend is "future scale" per plan but not recorded as an
  explicit deferral
- Metadata-storage location was TBD in the Phase 4b plan, still
  unresolved
- SQLite schema has no design-doc counterpart

### Phase 5 recryption proxy gaps

- Tower rate limiting will be resolved by
  [2026-04-07-production-readiness.md](archive/2026-04-07-production-readiness.md)
- TLS termination expected to live at reverse proxy, documented in
  the deployment guide when it exists

### Phase 6b wallet lock/unlock commands

Infrastructure exists (`CredentialProvider`); CLI commands don't.
Small amount of plumbing work.

---

## Threat model and security audit prep

Deferred to pre-Phase-9 per the user's direction — the full audit
will happen then and a separate adversarial pass is not needed
before that point. The
[threat-model.md](../threat-model.md) stub is in place and captures
the structure; filling in the TODOs is a one-session pass before
audit kickoff.

Related: the cryptographic assumption walkthrough (what specifically
breaks if BFV PRE is wrong, if BLAKE3 collides, if Ed25519 falls, if
ML-DSA-87 falls, if Argon2 is bypassed) should also happen in that
pre-audit pass.

---

## Keyspace / Grant sprint (forthcoming)

Placeholder for the next sprint after production-readiness. Scope
will cover reworking recipient PRE public-key discovery now that
`pre_pk` has been removed from `AccountRecord`: PRE pubkeys are
capability artifacts, not identity. The sprint will promote the
existing `AccessGrant` / `Capability` scaffolding in
`crates/recrypt-storage-auth/src/{grant.rs,capability.rs}` into a
first-class `GrantStore` (in-memory impl already landed; SQLite impl
pending) wired into `AppState`, add keyspace-scoped PRE key bundles
attached to grants, and re-enable `recrypt-cli share create` against
the new flow. No backwards-compat shim with the old `pre_pk`-on-account
shape — the wire protocol break is intentional.

---

## How to use this document

When a question comes up mid-sprint that sounds like "shouldn't we
also…?", check here first. If it's already tracked, link to the
entry. If it isn't, add it with a short context blurb. Do not let it
derail the current sprint.

When starting a new sprint, skim this document for candidate work.
Anything marked with a specific sprint link is ready to pick up as
soon as its prerequisites land. Anything that's just a bullet point
probably needs its own design doc first.
