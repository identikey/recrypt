# Keyspaces and Grants

**Date:** 2026-04-08
**Status:** Design proposal — awaiting review
**Depends on:** [2026-04-07 production readiness sprint](archive/2026-04-07-production-readiness.md) (landed)
**Related:** [security-tiers.md](../security-tiers.md), [2026-04-08 gordian envelope migration](2026-04-08-gordian-envelope-migration.md) (parallel track)

> **TL;DR** Introduce `Keyspace` as a first-class, versioned, signed
> policy primitive, with `Grant` as the delegable capability that
> binds fingerprints to keyspace operations. Authorities are members
> with signing rights; escrow agents are members with threshold
> share policies. All rotation is explicit-mode. Base tier ships with
> ephemeral session keys for forward secrecy; sentinel tier adds
> presentation-time enforcement via the vault guardian.

---

## 1. Motivation

Until now, recrypt treated PRE public keys as if they were attached to
identities: `AccountRecord` carried an optional `pre_pk` field, and
the CLI's share flow synthesized recrypt keys between two fingerprints.
This conflated two different things:

- **Identity** — who a principal is. Stable, long-lived, rooted in
  Ed25519 and ML-DSA keypairs. IdentiKey's concern.
- **Ability** — what a principal can do with specific content. Bound
  to context, rotatable, per-resource. Recrypt's concern.

Treating PRE keys as identity-level artifacts made several things
awkward or impossible:

- **Revocation** required coordinating across every file an identity
  touched.
- **Rotation** meant reissuing identity, which is exactly what identity
  should not require.
- **Groups** had no natural representation — each member's identity
  didn't obviously compose into a shared ability.
- **Multiple abilities per identity** — Alice having different access
  levels in different contexts — had no shape.
- **Federation** across authorities was impossible because there was
  no named authority surface.

The fix: promote the existing `Capability` and `AccessGrant` scaffolding
into a real authorization layer, and introduce `Keyspace` as the named,
rotatable policy primitive that PRE keys are derived from.

This was surfaced during the production-readiness sprint when we
stripped `pre_pk` from `AccountRecord`. The CLI's `share create`
command was disabled pending this sprint.

---

## 2. Core concepts

### 2.1 Keyspace

A **Keyspace** is a named, versioned, signed policy document naming
members and their capabilities over a set of content addresses.

```rust
pub struct KeyspaceDoc {
    /// Stable random id. Never changes across versions.
    pub id: KeyspaceId,

    /// Monotonic version counter. Starts at 0.
    pub version: u64,

    /// Content hash of the previous KeyspaceDoc in this chain.
    /// None for version 0.
    pub parent: Option<KeyspaceDocHash>,

    /// Rotation mode of this version bump (v0 is Create).
    pub mode: RotationMode,

    /// Human-readable label. Not load-bearing.
    pub name: String,

    /// HD root public key for this keyspace. Epoch PRE keys are
    /// derived from this via IdentiKey HD paths.
    pub root_pk: HdRootPubkey,

    /// Content address of the current epoch PRE public key blob.
    pub epoch_pre_pk: PrePubkeyRef,

    /// Monotonic epoch counter. Advances on Hygiene/Revoke/Burn modes.
    pub epoch: u64,

    /// Members with their capabilities and share policies.
    pub members: Vec<Member>,

    /// Minimum signatures required to issue a new version.
    /// Computed from members with SignRotation capability.
    pub quorum: u8,

    /// Signatures by members holding SignRotation capability in the
    /// parent version (or founders, for v0).
    pub signatures: Vec<Signature>,

    pub created_at: u64,
}

pub struct Member {
    pub fingerprint: PublicKeyFingerprint,
    pub capabilities: BTreeSet<Capability>,
    pub share_policy: DecryptionPolicy,
    pub added_at: u64,
    pub added_by: PublicKeyFingerprint,
}

pub enum Capability {
    Read,          // decrypt content tagged with this keyspace
    Write,         // publish content into this keyspace's index
    Delegate,      // issue Grants of capabilities they hold
    Admin,         // propose member changes
    SignRotation,  // sign KeyspaceDoc version bumps
}

pub enum DecryptionPolicy {
    /// Member can decrypt on their own using their own share.
    Standalone,

    /// Member holds one share of a threshold key. Decryption requires
    /// `threshold` of `total` shares combined under the named policy.
    ThresholdShare {
        threshold: u8,
        total: u8,
        policy_ref: ContentHash,
    },
}

pub enum RotationMode {
    /// Initial creation. version == 0.
    Create,

    /// Add a member without changing the epoch. No existing access lost.
    Additive,

    /// Scheduled epoch rotation. All existing members retained. New
    /// writes use the new epoch key. Old ciphertexts remain accessible
    /// to existing members (they have the old epoch material too).
    Hygiene,

    /// Named members removed from future access. New epoch key derived;
    /// writes to the new epoch exclude the removed members. Old
    /// ciphertexts remain decryptable by anyone who had access
    /// (including removed members — base tier).
    Revoke { removed: Vec<PublicKeyFingerprint> },

    /// Epoch rotation with re-encryption of existing ciphertexts.
    /// O(N) in keyspace content size. Sentinel/Max tier only.
    Burn { removed: Vec<PublicKeyFingerprint> },

    /// Create a new keyspace with a new id, copying the current member
    /// set as a starting point. Used for authority change or community
    /// split. The new keyspace has no parent; lineage is documentary.
    Fork { new_id: KeyspaceId },

    /// Declare the keyspace retired. Signed by quorum. Proxies stop
    /// serving it in queries. Content in the vault is not removed
    /// (base tier cannot enforce deletion).
    Tombstone,
}
```

**The rotation mode is signed as part of the document.** Authorities
explicitly declare "this is additive" or "this is a revocation" — the
system never infers intent. This is the type-level answer to "don't
accidentally revoke members meant to be in there."

### 2.2 Grant

A **Grant** is a signed, delegable capability token that binds a
subject fingerprint to a set of capabilities on a keyspace resource.

```rust
pub struct AccessGrant {
    pub version: u32,
    pub keyspace: KeyspaceId,
    pub keyspace_version: u64,     // bound to a specific keyspace version
    pub subject: PublicKeyFingerprint,
    pub issuer: PublicKeyFingerprint,
    pub capabilities: BTreeSet<Capability>,
    pub expires_at: Option<u64>,
    pub delegation_depth: u8,       // 0 = non-delegable; decrement per redelegation
    pub parent_grant: Option<GrantId>, // for delegation chains
    pub signature: MultiSig,
}
```

Grants scaffolding already exists in
[`crates/recrypt-storage-auth/src/grant.rs`](../../crates/recrypt-storage-auth/src/grant.rs).
This sprint wires it into the Keyspace flow and adds a store trait
(`GrantStore`, already scaffolded in the same sprint as production
readiness).

**Delegation at base tier is unstoppable.** `delegation_depth` is
advisory metadata for audit. The Grant exists so that when sentinel
tier arrives, the vault guardian has a signed document to verify at
presentation time — the enforcement surface appears without a protocol
change.

### 2.3 Keyspace identity

A `KeyspaceId` is a random 32-byte value generated at creation. It
never changes across versions. The *document hash* (`KeyspaceDocHash`)
changes on every version bump — clients verify the chain from
`version 0` to the current version, checking `parent` pointers.

Proxies index `keyspace_id -> latest_version_hash` as a hot cache.

---

## 3. Operations

### 3.1 Create
```
create_keyspace(name, founders, quorum) -> KeyspaceDoc (v0)
```

- Generate random `KeyspaceId`
- Derive epoch-0 PRE keypair from a fresh HD root (path `m/0`)
- Store the epoch-0 PRE pubkey blob in the vault (content-addressed)
- Build `KeyspaceDoc` with `mode: Create`, `version: 0`, no parent
- Collect founder signatures (founders are members with
  `SignRotation` capability)
- Publish to the proxy index; store signed doc in vault

### 3.2 Additive (add member)
```
add_member(keyspace_id, new_member, capabilities, share_policy)
    -> KeyspaceDoc (v+1)
```

- Fetch current doc, verify chain
- Build v+1 with `mode: Additive`, appended member, incremented version,
  same epoch (no rotation)
- Collect quorum of `SignRotation` signatures from current members
- Publish

**No epoch change.** The new member gets access to everything existing
because the epoch PRE key is unchanged. This is the common case for
growing a group.

### 3.3 Hygiene (scheduled rotation)
```
rotate_hygiene(keyspace_id) -> KeyspaceDoc (v+1)
```

- Derive new epoch PRE keypair at HD path `m/(epoch+1)`
- Publish new epoch PRE pubkey blob
- Build v+1 with `mode: Hygiene`, incremented epoch, same members
- Collect quorum, publish

**New writes use the new epoch key.** Old ciphertexts remain accessible
to existing members (they can derive old epoch keys from the HD root
if they're authorities, or they cached prior DEKs).

### 3.4 Revoke
```
rotate_revoke(keyspace_id, removed: Vec<Fingerprint>)
    -> KeyspaceDoc (v+1)
```

- Derive new epoch PRE keypair
- Build v+1 with `mode: Revoke { removed }`, incremented epoch, members
  list with `removed` absent
- Collect quorum (not including removed members), publish

**Base tier caveat:** the removed members still hold the *old* epoch
material. They retain access to ciphertexts written before the
revocation. Forward secrecy for new content only. The accepted-weakness
documentation in [security-tiers.md](../security-tiers.md) says this
explicitly.

### 3.5 Burn (sentinel/max only)
```
rotate_burn(keyspace_id, removed) -> KeyspaceDoc (v+1)
```

- Same as Revoke, plus: re-encrypt all content currently indexed in
  this keyspace under the new epoch key. Old ciphertexts are
  replaced in the vault; new content hashes are issued.
- Expensive (O(N)), only triggerable at sentinel tier or higher where
  the vault guardian enforces policy.

### 3.6 Fork
```
fork_keyspace(source_id, new_authorities) -> KeyspaceDoc (v0, new id)
```

- Generate fresh `KeyspaceId`
- Copy current member set as the initial member set of the new keyspace
- Optionally change authority set (new founders, new quorum)
- Record the source's current hash in a `forked_from` assertion
  (documentary, not load-bearing)
- Publish as version 0 of the new keyspace

**Authority-agility.** If your authorities are compromised or
unavailable, fork under a new authority set and re-grant access.
Content addresses in the old keyspace are still valid; the new
keyspace simply references them via new grants or indexes.

### 3.7 Write (publish content into a keyspace)
```
put(keyspace_id, plaintext) -> ContentHash
```

- Fetch current `epoch_pre_pk`
- Hybrid encrypt: random DEK → PRE-wrap to `epoch_pre_pk`; bulk →
  XChaCha20 + Bao
- Build manifest: `{keyspace_id, keyspace_version, epoch, ciphertext_ref}`
- Publish manifest signed by the writer (requires `Write` capability)
- Store ciphertext in vault (content-addressed)
- Proxy indexes `content_hash -> keyspace_id` for reverse lookup

**"Write capability" is index membership**, not storage permission.
Anyone can push a blob to the vault; only members with `Write` can
publish a signed manifest claiming the blob belongs to this keyspace.
At base tier, nothing prevents a non-member from publishing a blob
and claiming it's in the keyspace — the signature check on the
manifest fails and clients reject it.

### 3.8 Read
```
get(keyspace_id, content_hash) -> plaintext
```

- Fetch ciphertext from any vault provider
- Fetch manifest, verify signature, verify writer was a keyspace member
  at the manifest's declared version
- Ask proxy for a recrypted DEK: "I am `fp`, I want to read `content_hash`
  in keyspace `K`"
- Proxy checks: current keyspace version, is `fp` a member with `Read`,
  does their `share_policy` allow standalone decryption
- If Standalone: proxy applies recrypt key from the manifest's epoch
  PRE pubkey to the requester's ephemeral session key; returns wrapped
  DEK
- If ThresholdShare: proxy returns "need shares from policy X"; client
  coordinates threshold combination out-of-band or via a threshold
  protocol (future)
- Client decrypts with session key, decrypts ciphertext with DEK

**Ephemeral session keys.** The client generates a fresh Ed25519
keypair per session (or per operation for high-sensitivity keyspaces).
The proxy recrypts the DEK to the ephemeral public key, not the
client's long-lived identity key. This caps the damage window of a
compromised client device to the session lifetime — forward secrecy
mitigation at base tier.

### 3.9 Delegate
```
delegate(grant_on, to_fp, capabilities, expires_at) -> AccessGrant
```

- Issuer must hold `Delegate` capability *and* the capabilities being
  delegated
- Issue a signed `AccessGrant` with decremented `delegation_depth`
- Publish to proxy grant index
- Base tier: grant is auditable but not enforceable at read time
  (client still presents keyspace membership via current version)
- Sentinel tier: grant is presented to the vault guardian; guardian
  verifies chain back to an authoritative member

---

## 4. Forward secrecy at base tier

Base tier combines three mechanisms:

1. **HD-derived epoch keys.** Each rotation derives the next epoch
   PRE keypair from the keyspace HD root. Authorities can regenerate
   old epoch keys deterministically; content always remains decryptable
   to those who had legitimate access. No key storage explosion.

2. **Ephemeral session keys.** Clients generate session keypairs per
   session (configurable: per-session, per-day, per-operation). The
   proxy recrypts DEKs to the ephemeral key. A compromised client
   device's cache is invalidated at session rollover.

3. **Short grant expiry.** Grants issued to delegates carry short
   `expires_at` by default. Renewal requires re-requesting from the
   current member.

**The gap this leaves:** a revoked member with a cached ephemeral
session key and a cached DEK can still read until session expiry.
Documented as an accepted base-tier weakness. The sentinel-tier vault
guardian closes this by requiring presentation-time token verification.

**Ratchet counters are deferred to sentinel tier.** Implementing them
at base would require proxy-held counter state that contradicts "proxy
is cache, not authority." At sentinel, the vault guardian owns the
counter and enforcement is natural.

---

## 5. Crate boundaries

| Concept | Crate | Rationale |
|---|---|---|
| `KeyspaceDoc`, `Member`, `Capability`, `DecryptionPolicy`, `RotationMode` | `recrypt-storage-auth` | Identity + authorization types |
| `AccessGrant`, `GrantId` | `recrypt-storage-auth` (done) | Already scaffolded |
| `KeyspaceStore` trait + InMemory/Sqlite impls | `recrypt-storage-auth` | Matches AccountStore pattern |
| `GrantStore` trait + InMemory (done) / Sqlite | `recrypt-storage-auth` | Scaffolded; add Sqlite |
| Signature verification, chain validation | `recrypt-storage-auth` | Pure auth logic |
| HD epoch key derivation | `recrypt-storage-auth` (via IdentiKey HD primitives) | Keyed on the keyspace HD root |
| Opaque PRE pubkey blobs in vault | `recrypt-storage` | Content-addressed bytes |
| KeyspaceDoc blobs in vault (optional backup) | `recrypt-storage` | Content-addressed bytes |
| Keyspace/Grant index tables | `recrypt-server` | Fast metadata cache |
| Query routes (`/keyspaces/:id`, `/grants/by-subject/:fp`, etc.) | `recrypt-server` | HTTP surface |
| Personal list (my keyspaces) | `recrypt-server` routes + IdentiKey client overlay | Source of truth + user overlay |
| CLI commands (`keyspace create`, `keyspace add-member`, etc.) | `recrypt-cli` | User-facing |

**No new crate.** Keyspace is core to recrypt-storage-auth's job.
The temptation to create `recrypt-keyspace` as a shared crate is
rejected on the principle of avoiding proliferation — keyspace logic
is auth logic.

---

## 6. KeyspaceDoc storage and discovery

Proposal: **hybrid** — signed doc lives in the vault as a
content-addressed backup; proxy maintains a hot index for queries.

1. **Vault copy (authoritative, federatable).** When a KeyspaceDoc
   is published, the signed bytes are written to the
   content-addressed vault. Anyone can fetch by hash, verify
   signatures, and reconstruct the chain. This is what makes
   federation work: a new proxy can bootstrap by reading docs from
   any vault.

2. **Proxy index (hot cache).** The proxy maintains SQLite tables
   keyed by `keyspace_id` with the current version hash, member
   reverse-index, and grant reverse-indexes. Clients query the proxy
   for discovery; clients verify signatures on results.

3. **Gossip between proxies.** Proxies can subscribe to each other's
   "new keyspace version" feeds and merge into their local indexes.
   No proxy is authoritative; all are useful.

Clients who don't want to trust any proxy can fetch directly from
vault by hash (slower, requires knowing the hash).

---

## 7. HTTP API sketch

New routes on `recrypt-server` (all subject to rate limiting):

```
POST   /keyspaces                           create (v0)
GET    /keyspaces/:id                       fetch latest version
GET    /keyspaces/:id/versions              list version history (hashes)
GET    /keyspaces/:id/versions/:hash        fetch specific version
POST   /keyspaces/:id/versions              publish new version (rotation)
GET    /keyspaces/by-member/:fp             "my keyspaces" (personal list, base query)

POST   /grants                              issue grant
GET    /grants/:id                          fetch grant
DELETE /grants/:id                          revoke (publishes revocation record)
GET    /grants/by-subject/:fp               grants where fp is subject
GET    /grants/by-resource/:hash            grants referencing a keyspace

POST   /keyspaces/:id/content               publish manifest (write)
GET    /keyspaces/:id/content/:hash/key     request recrypted DEK for read
GET    /keyspaces/:id/content               list content in keyspace
```

All POST routes verify signatures against current keyspace state.
GET routes return signed documents for client verification.

---

## 8. Personal list (v1)

The simplest thing: `GET /keyspaces/by-member/:fp` returns the list
of keyspaces where `:fp` appears in the current member list. Clients
display this as the user's "home view."

**v1 scope:**
- Proxy query is the source of truth
- No client-side overlay yet (no pins, nicknames, sort order)
- Clients verify each returned keyspace's signature chain before
  displaying

**Deferred to follow-up:**
- User-side overlay (pin, hide, nickname, sort)
- Recently-touched files across all keyspaces
- "Shared with me" grants that aren't full memberships
- Cross-proxy aggregation

Documented as a forthcoming expansion in the backlog.

---

## 9. Groups as a keyspace parameterization

A **Group** is a keyspace with:

- `quorum >= 2` (multi-party rotation authorization)
- Members holding `SignRotation` capability (authorities = members)
- `Additive` and `Hygiene` rotations are routine
- `Revoke` requires explicit member quorum action, not just a single
  admin

A **Personal vault** is a keyspace with:

- `quorum = 1`
- Single member with all capabilities
- May include escrow members with `ThresholdShare` policies

No separate `Group` type. Same primitive, different parameters.

---

## 10. Implementation plan

### Phase A — types and store traits (lands first)

1. Define `KeyspaceDoc`, `Member`, `Capability`, `DecryptionPolicy`,
   `RotationMode`, `KeyspaceId`, `KeyspaceDocHash` in
   `crates/recrypt-storage-auth/src/keyspace.rs`.
2. Define `KeyspaceStore` async trait with `InMemoryKeyspaceStore` impl.
3. Signature verification over the doc bytes (dcbor canonical encoding
   if the envelope migration has landed; otherwise ad-hoc canonical
   serialization with a `format_version` field).
4. Chain verification: walk from current back to v0, verify each
   parent pointer, verify each signature against the *previous*
   version's `SignRotation` members (bootstrap: v0 signed by
   founders).
5. Unit tests: create, additive, hygiene, revoke, chain verification,
   tampering detection.

### Phase B — SQLite impls

1. `SqliteKeyspaceStore`: `keyspaces` table (id, current_version_hash,
   current_version u64, name), `keyspace_docs` table (hash, keyspace_id,
   version, parent_hash, doc_bytes, created_at), `keyspace_members`
   table (keyspace_id, version, fingerprint, capabilities,
   share_policy) — denormalized for fast member-lookup queries.
2. `SqliteGrantStore` (the InMemory scaffolding exists already).
3. Reuse the single unified `recrypt.db` connection pattern from the
   production-readiness sprint.
4. Round-trip tests, chain verification across persistence.

### Phase C — HD epoch key derivation

1. Integrate with IdentiKey HD primitives (wherever they live in the
   IdentiKey codebase — may require a dependency added to
   `recrypt-storage-auth`).
2. `derive_epoch_pre_keypair(root: HdRoot, epoch: u64) -> PreKeypair`
3. Publish epoch PRE pubkey to vault on each rotation; store content
   hash in `KeyspaceDoc.epoch_pre_pk`.
4. Tests: determinism across independent clients.

### Phase D — recrypt-server wiring

1. Add `KeyspaceStore` + `GrantStore` to `AppState::from_config`.
2. HTTP routes per §7.
3. Member reverse index for fast "my keyspaces" queries.
4. Rate limiting already in place from production readiness sprint.
5. Integration tests via HTTP.

### Phase E — CLI commands

1. `recrypt keyspace create`
2. `recrypt keyspace add-member`
3. `recrypt keyspace rotate --mode hygiene|revoke|fork`
4. `recrypt keyspace list` (personal list)
5. `recrypt keyspace put` / `recrypt keyspace get` (replaces the
   disabled `share create` / `share accept` flow)
6. `recrypt grant issue` / `recrypt grant revoke` / `recrypt grant list`
7. Re-enable share flow in terms of keyspace operations.

### Phase F — documentation and migration

1. Update [architecture.md](../architecture.md) §3 and §5 with
   keyspace concepts.
2. Update [http-api-reference.md](../http-api-reference.md) with new
   routes.
3. Retire the old share-by-fingerprint flow from docs.
4. Add keyspace tutorial to user guide.

### Phase G — forward-compat hooks for sentinel tier

1. `DecryptionPolicy::ThresholdShare` is defined but unused at base tier.
   Shape must match what the sentinel tier will need.
2. `RotationMode::Burn` defined but rejected with "not supported at
   base tier" error when invoked without a guardian.
3. `AccessGrant.delegation_depth` tracked but not enforced (advisory).
4. Document the interfaces the vault guardian will consume so sentinel
   tier can be added without changing the base-tier schema.

---

## 11. Success criteria

- [ ] `KeyspaceDoc` and all supporting types compile and round-trip
- [ ] `KeyspaceStore` trait with InMemory + Sqlite impls, unit tests green
- [ ] Chain verification detects tampering, missing parents,
      invalid signatures
- [ ] Create → Additive → Hygiene → Revoke → Fork flow works end-to-end
      in integration tests
- [ ] HD epoch key derivation is deterministic and matches across
      independent derivations
- [ ] HTTP routes support create, rotate, query, member-lookup
- [ ] CLI replaces disabled `share create` with `keyspace put` + `grant`
- [ ] "My keyspaces" query returns correct results for test fixtures
- [ ] Ephemeral session keys are generated and used in the read flow
- [ ] Authority rotation (changing the `SignRotation` member set) works
      and is signed by the *old* quorum
- [ ] Documentation updated

---

## 12. Open questions

### 12.1 Canonical encoding of KeyspaceDoc

Do we use Gordian Envelope / dCBOR once the envelope migration lands,
or do we define our own canonical encoding now and migrate later?

**Recommendation:** if the envelope migration is close, wait and use
envelopes. If it's months out, use a simple canonical JSON or ad-hoc
CBOR and migrate. Check the status of
[2026-04-08 gordian envelope migration](2026-04-08-gordian-envelope-migration.md)
before Phase A starts.

### 12.2 HD root management

Where does the keyspace HD root secret live? Options:

- **On the keyspace creator's IdentiKey**, encrypted to the founding
  authorities. Rotation requires one authority to re-derive and
  publish.
- **Shared across authorities via threshold** (SSS) so no single
  authority holds the full root. More resilient but more complex.
- **Derived from an existing identity HD tree** so keyspaces inherit
  from the creator's identity, with a deterministic path like
  `m/identity/keyspace/:id`.

**Recommendation:** option 3 for simplicity; the creator's identity
HD tree is the source. Authorities can be granted derivation paths.
Threshold sharing is a sentinel-tier enhancement.

### 12.3 Authority rotation signing rule

Can the current `SignRotation` set add new signers, or does adding
signers require a separate protocol step?

**Recommendation:** a single version bump can change the
`SignRotation` member set as long as the bump is signed by a quorum
of the *old* `SignRotation` set. This prevents authority seizure
(attacker needs old quorum to install themselves). Document
explicitly.

### 12.4 Grant revocation semantics

When a grant is revoked, what happens?

**Recommendation:** revocation publishes a signed "grant revoked"
record keyed by `GrantId`. The proxy's grant index filters by
revocation records before returning results. At base tier, a client
with a cached grant can still try to use it; proxies will refuse.
Sentinel-tier guardian checks revocation list at presentation time.

### 12.5 Cross-keyspace references

If content lives in keyspace A but a grant references it in keyspace
B (e.g., linking a document from one project into another), how do
we model that? 

**Recommendation:** deferred. v1 says content belongs to one
keyspace. Cross-linking is a follow-up that needs more design.

### 12.6 Keyspace deletion

**Resolved:** `RotationMode::Tombstone` added to the type definition
in section 2.1. No hard delete; a tombstoned keyspace is retired by
quorum signature. Proxies stop serving it. Vault content is not
removed (base tier cannot enforce deletion).

---

## 13. What this does not change

- **Account identity.** `AccountRecord` stays as pure identity
  (fingerprint + Ed25519 + ML-DSA). No `pre_pk`.
- **Vault storage.** Content-addressed blobs are unchanged.
- **Proxy rate limiting.** Tower-governor stays.
- **Wire protocol.** If the envelope migration lands in parallel,
  KeyspaceDocs will use envelopes from day one. Otherwise
  canonical JSON/CBOR with format_version.

---

## 14. References

- [security-tiers.md](../security-tiers.md) — tier hierarchy and
  accepted-weaknesses doc
- [2026-04-07 production readiness](archive/2026-04-07-production-readiness.md) —
  persistence foundation
- [2026-04-07 next-steps backlog](2026-04-07-next-steps-backlog.md) —
  follow-up work including personal-list expansion
- [crates/recrypt-storage-auth/src/grant.rs](../../crates/recrypt-storage-auth/src/grant.rs) —
  existing grant scaffolding (this sprint extends it)
- [crates/recrypt-storage-auth/src/capability.rs](../../crates/recrypt-storage-auth/src/capability.rs) —
  existing capability type (to be replaced with the keyspace-scoped
  Capability enum)
