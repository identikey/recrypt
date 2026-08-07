# Group Sharing

**Date:** 2026-04-07
**Status:** 📋 Proposed — awaiting implementation
**Phase:** 8+ (the "Signal meets Dropbox" value-prop sprint)
**Depends on:** [2026-04-07-production-readiness.md](archive/2026-04-07-production-readiness.md)
(trait-backed persistence)

> **TL;DR** Add a `Group` abstraction to `recrypt-server` so one
> share-policy operation can grant (or revoke) access to N files for M
> members at once. The cryptography is free — a group share is just a
> batch of existing per-file recrypt-key operations. What's new is the
> data model, the batch endpoints, the canonical signature strings for
> group ops, the atomicity and race-condition story, and the CLI UX.
> This is the product-defining feature: add a person to "Family" and
> they immediately see every file in Family without any per-file
> ceremony; remove them and they lose everything at once with a single
> DELETE.

---

## 1. Motivation

Recrypt's distinguishing product value — "fine-grained revocable sharing
without a trusted cloud" — only realizes itself when groups exist.
Sharing 47 files with 5 people by calling `POST /recryption/share` 235
times is cryptographically fine but operationally absurd. The CLI UX
and API UX both need a first-class "group" concept to match how users
actually think about sharing (families, teams, projects, classes).

The cryptography does not change. A group share is **exactly** a batch
of per-file-per-member recrypt keys — the same primitives we already
have. The work in this plan is all in the application layer:

- A data model for groups, members, and group-file associations
- Server-side batch endpoints that apply atomic changes to that model
- Canonical signature-message strings for group operations
- Client-side fan-out of recrypt-key generation
- CLI commands and output formatting
- Atomicity and race-condition handling

---

## 2. Design

### 2.1 Data model

Three new tables in the persistence layer (SQLite / trait-backed from
the production-readiness sprint):

```sql
CREATE TABLE groups (
    group_id         BLOB PRIMARY KEY,        -- blake3(owner_fp || name || created_at)
    owner_fingerprint BLOB NOT NULL,
    name             TEXT NOT NULL,
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL
);

CREATE TABLE group_members (
    group_id         BLOB NOT NULL,
    member_fingerprint BLOB NOT NULL,
    added_at         INTEGER NOT NULL,
    PRIMARY KEY (group_id, member_fingerprint),
    FOREIGN KEY (group_id) REFERENCES groups(group_id) ON DELETE CASCADE
);

CREATE TABLE group_files (
    group_id         BLOB NOT NULL,
    file_hash        BLOB NOT NULL,
    added_at         INTEGER NOT NULL,
    PRIMARY KEY (group_id, file_hash),
    FOREIGN KEY (group_id) REFERENCES groups(group_id) ON DELETE CASCADE
);
```

Group shares materialize into the existing `shares` table: when `(group,
member, file)` is true, a row in `shares` carries the recrypt key for
that `(owner → member, file)` triple. Deleting a `group_members` row
deletes every `shares` row that was created on that member's behalf by
the group.

**Why materialize into `shares` rather than joining at query time?** So
that the download path stays unchanged. `GET /recryption/share/{id}` is
already the endpoint that serves a recrypted file; it reads from
`shares`. The group layer is a *batch publisher* into `shares`, not a
new runtime mechanism. The download path does not need to know
anything about groups.

### 2.2 Group lifecycle operations

| Operation                     | Effect                                                                      |
| ----------------------------- | --------------------------------------------------------------------------- |
| `create_group`                | New group, owner is the caller                                              |
| `add_member(group, member)`   | For every file already in the group, client generates a recrypt key and publishes to `shares`; adds row to `group_members` |
| `remove_member(group, member)` | Delete every `shares` row for this member created by this group; delete `group_members` row |
| `add_file(group, file)`       | For every current member, client generates a recrypt key and publishes to `shares`; adds row to `group_files` |
| `remove_file(group, file)`    | Delete every `shares` row for this file created by this group; delete `group_files` row |
| `delete_group`                | Cascades: delete all `shares` created by this group, delete all `group_members`, all `group_files`, the group itself |

**Important asymmetry:** the **client** does the recrypt-key generation
(it has the owner's secret key), then POSTs the batch of recrypt keys
to the server. The server does not touch any secret key material — it
only stores the transformation keys the client provides. This is
identical to the per-file share flow today.

### 2.3 HTTP endpoints

Following the existing `/recryption/*` conventions:

```
POST   /groups                                     create group
GET    /groups/{group_id}                          get group metadata
DELETE /groups/{group_id}                          delete group
GET    /groups/{group_id}/members                  list members
GET    /groups/{group_id}/files                    list files
POST   /groups/{group_id}/members                  add member (batch recrypt keys in body)
DELETE /groups/{group_id}/members/{fingerprint}    remove member
POST   /groups/{group_id}/files                    add file (batch recrypt keys in body)
DELETE /groups/{group_id}/files/{hash}             remove file
GET    /accounts/{fingerprint}/groups              list groups (owned + member-of)
```

**Request body for batch add operations:**

```json
// POST /groups/{group_id}/members
{
  "member_fingerprint": "<base58>",
  "recrypt_keys": [
    { "file_hash": "<base58>", "recrypt_key": "<base58>" },
    { "file_hash": "<base58>", "recrypt_key": "<base58>" },
    ...
  ]
}
```

The client computed one recrypt key per file currently in the group and
submits them as a single batch. The server validates each file actually
belongs to the group and inserts `shares` rows transactionally.

### 2.4 Canonical signature messages

Extend the existing table in
[http-api-reference.md](../http-api-reference.md):

| Endpoint                                              | Verb            | Canonical message                                                           |
| ----------------------------------------------------- | --------------- | --------------------------------------------------------------------------- |
| `POST /groups`                                        | `GROUP_CREATE`  | `GROUP_CREATE:{owner_fp}:{group_name}:{nonce}`                              |
| `DELETE /groups/{id}`                                 | `GROUP_DELETE`  | `GROUP_DELETE:{owner_fp}:{group_id}:{nonce}`                                |
| `POST /groups/{id}/members`                           | `GROUP_ADD_MEMBER` | `GROUP_ADD_MEMBER:{owner_fp}:{group_id}:{member_fp}:{files_digest}:{nonce}` |
| `DELETE /groups/{id}/members/{fp}`                    | `GROUP_REMOVE_MEMBER` | `GROUP_REMOVE_MEMBER:{owner_fp}:{group_id}:{member_fp}:{nonce}`        |
| `POST /groups/{id}/files`                             | `GROUP_ADD_FILE`  | `GROUP_ADD_FILE:{owner_fp}:{group_id}:{file_hash}:{members_digest}:{nonce}` |
| `DELETE /groups/{id}/files/{hash}`                    | `GROUP_REMOVE_FILE` | `GROUP_REMOVE_FILE:{owner_fp}:{group_id}:{file_hash}:{nonce}`           |
| `GET /groups/{id}/members`                            | `GROUP_LIST_MEMBERS` | `GROUP_LIST_MEMBERS:{caller_fp}:{group_id}:{nonce}`                    |
| `GET /groups/{id}/files`                              | `GROUP_LIST_FILES` | `GROUP_LIST_FILES:{caller_fp}:{group_id}:{nonce}`                        |
| `GET /accounts/{fp}/groups`                           | `LIST_GROUPS`   | `LIST_GROUPS:{fingerprint}:{nonce}`                                         |

**The `{files_digest}` and `{members_digest}` fields** are
`base58(blake3(concat_of_sorted_hashes))` — they commit the signature
to the exact set of files or members the client intended to batch.
This prevents a malicious proxy from replaying an old `GROUP_ADD_MEMBER`
signature after the group's file set has changed: the digest will no
longer match the server's current state, and the server can reject.

**Ordering:** the list of hashes is sorted lexicographically (by the
raw 32-byte hash, not the base58 string) before being concatenated and
hashed. Canonical ordering is part of the spec.

### 2.5 Atomicity and idempotency

Every batch operation is idempotent at the `(group_id, member, file)`
level:

- `add_member` with a member who is already in the group: no-op on
  `group_members`, and for each recrypt key in the batch, `INSERT OR
  IGNORE` into `shares`. This makes retries safe.
- `remove_member`: `DELETE FROM shares WHERE ... created_by_group =
  group_id AND to_fingerprint = member` + `DELETE FROM group_members`.
  Same row twice is fine.
- `add_file` / `remove_file`: symmetric.

All writes within one batch happen in a single SQLite transaction. If
the transaction fails (e.g. a constraint violation because a file was
concurrently removed), the whole batch rolls back and the client sees
an error. The client can then re-read the group state, recompute the
batch, and retry.

**Why `INSERT OR IGNORE` instead of transactional add-all-or-nothing
for retries?** Because a retried `add_member` after a partial failure
needs to reconcile with whatever state the server currently holds —
some shares may already exist from the first try. Idempotent inserts
let the client treat retry as "make sure these shares exist" rather
than "these shares must not already exist, crash otherwise".

### 2.6 Race conditions

Three races to think about:

**Race 1: `add_member` and `add_file` concurrently.**
Alice calls `add_member(G, Bob)` with the current file list `[F1,
F2]`, generating two recrypt keys. Concurrently, Alice (or another
admin — see §2.7) calls `add_file(G, F3)` which computes recrypt keys
for all *current* members, which does *not* include Bob yet.

Result: Bob has access to F1 and F2 but not F3. F3 is in the group
but Bob has no recrypt key for it.

**Resolution:** this is a logical bug that would manifest as "Bob
joined the family group but can't see the photo we added at the same
time". Options:

(a) **Serialize group modifications** at the server with a per-group
mutex. Only one `GROUP_*` operation against a given group at a time.
Simple; impacts throughput but groups are low-traffic structures.

(b) **Reconciliation sweep.** After any `group_members` or
`group_files` change, the server can return the full current state of
the group to the client, and the client recomputes any missing
recrypt keys and POSTs a fixup batch. More complex; requires a
two-round protocol.

**Recommendation: (a).** Groups don't change often; a per-group mutex
is fine. If we later hit contention, we revisit.

**Race 2: A file is removed from the group while a batch is being
published.**
Alice starts `add_member(G, Bob)` with `[F1, F2]`. While the request
is in flight, Carol (an admin) calls `remove_file(G, F2)`. Alice's
batch arrives and includes a recrypt key for F2 that no longer
belongs to the group.

**Resolution:** the `{files_digest}` in the canonical signature
message commits to a specific file set. If the server's current file
set disagrees, the signature verification effectively checks
something nobody signed, and the server rejects with a 409 Conflict.
The client reads current state and retries.

**Race 3: A member is removed and re-added in a short window.**
Alice removes Bob from G, then changes her mind and re-adds him. If
there are stored recrypt keys from the first membership that the
`remove_member` implementation didn't fully clean up, the re-add
could silently "work" using stale keys.

**Resolution:** `remove_member` must delete every `shares` row tagged
with `(group_id, to_fingerprint)` before the `group_members` DELETE
commits. Re-adding Bob then generates fresh recrypt keys — which is
what we want, because the *new* membership shouldn't inherit the
*old* ciphertext-to-member bindings (in case files have changed in
between).

### 2.7 Ownership vs admin roles — punted

This plan intentionally **only supports the group owner** doing
modifications. Multi-admin groups are a real feature but introduce a
whole layer of delegation and permission questions (who can demote
the owner? can admins remove other admins? etc.) that don't
need to block the MVP.

**Punted:** admin roles, ownership transfer, co-owners. Tracked in
[2026-04-07-next-steps-backlog.md](2026-04-07-next-steps-backlog.md).

### 2.8 Client-side flow

CLI commands:

```bash
recrypt group create "Family"
recrypt group add-member family bob_fingerprint
recrypt group remove-member family bob_fingerprint
recrypt group add-file family secret.txt.enc
recrypt group remove-file family <hash>
recrypt group list              # groups I own or am a member of
recrypt group show family       # members + files
recrypt group delete family
```

Under the hood, `add-member` does:

1. `GET /groups/{id}/files` to fetch the current file list (authenticated
   with `GROUP_LIST_FILES:`).
2. For each file, look up the owner's secret key and the new member's
   public key in the wallet.
3. Call `backend.generate_recrypt_key(owner_sk, member_pk)` locally
   for each file. N recrypt keys generated.
4. Compute `files_digest = blake3(sorted(file_hashes))`.
5. Sign `GROUP_ADD_MEMBER:{owner_fp}:{group_id}:{member_fp}:{files_digest}:{nonce}`.
6. POST the batch.
7. On 409 (files_digest mismatch): re-read file list, retry once. If
   it still fails, surface an error asking the user to retry.

### 2.9 Storage and scale

For a group of N members and F files, storage cost is:

| Artifact              | Count per group            | Typical size          |
| --------------------- | -------------------------- | --------------------- |
| `groups` row          | 1                          | ~100 bytes            |
| `group_members` row   | N                          | ~80 bytes each        |
| `group_files` row     | F                          | ~80 bytes each        |
| `shares` row          | N × F                      | ~1–2 KB each (recrypt key) |
| ciphertext objects    | F                          | actual file sizes     |
| outboard objects      | F (for files > 16 KiB)     | ~0.01% of file size   |

Key observation: **bulk storage (ciphertexts, outboards) is O(F), not
O(N × F).** The group sharing construction scales the shared artifacts
as O(1) in group size. Only the small recrypt keys scale as O(N × F)
and live entirely in SQLite on the server.

Concretely: a family of 5 people sharing 1,000 photos (~3 GiB total) =
one set of ciphertext+outboard objects taking ~3 GiB + some outboards,
and 5,000 recrypt-key rows in `shares` at ~1 KB each ≈ 5 MB. The
ciphertexts don't get copied; they're shared by reference.

---

## 3. Implementation plan

### 3.1 Steps

1. **Data model in `recrypt-storage-auth`**: add `GroupStore` trait,
   in-memory and SQLite impls, `Group`/`GroupMember`/`GroupFile`
   types. Schema migration.

2. **Server routes**: `recrypt-server/src/routes/groups.rs` with the
   endpoints from §2.3. Wire them into the router.

3. **Signature verification middleware**: extend the existing auth
   middleware to build and verify the `GROUP_*` canonical messages.
   Add `files_digest` and `members_digest` helpers.

4. **Per-group locking**: add an `Arc<DashMap<GroupId, Mutex<()>>>` or
   similar to `ServerState` for in-flight group operation serialization.
   Group operations acquire the relevant lock; non-group operations
   don't care.

5. **Client API**: `recrypt-cli/src/client/groups.rs` with typed
   methods for each endpoint. Handles signing, nonce fetching, retry
   on `files_digest` conflict.

6. **CLI commands**: `recrypt-cli/src/commands/group.rs` with the
   commands from §2.8. Pretty-print output for `list` and `show`;
   JSON output honored via the existing `--json` flag.

7. **Cross-test with per-file shares**: confirm that creating a group
   share for a file does not interfere with a user's existing per-file
   share of the same file, and vice versa. They should coexist
   cleanly because the `shares` rows are tagged by source (`via_group`
   optional column, or equivalent).

   **Schema addition**: add a `via_group` column to `shares` that is
   `NULL` for direct shares and `group_id` for group-published shares.
   `remove_member` from a group only deletes rows where
   `via_group = this_group_id`.

8. **End-to-end tests**:
   - Alice creates Family group, adds Bob and Carol, adds 3 files.
     Bob and Carol can download all 3. Alice removes Bob, Bob can no
     longer download, Carol still can.
   - Alice creates Family, adds one file, then adds 100 members in
     separate operations. Storage usage scales linearly in members
     for recrypt-key rows, flat in ciphertext objects.
   - Race test: `add_member` with a file list that is stale by one
     file returns 409; retry succeeds.
   - Idempotency: double-submit the same `add_member` batch; second
     request is a no-op.

9. **Documentation**:
   - Update `architecture.md` §3 (recrypt-server owns groups)
   - Add a §2.5 to `http-api-reference.md` (group endpoints)
   - Add group flow diagrams to `user-guide.md`

### 3.2 Parallelization

Steps 1 and 3 can proceed in parallel once the signature message
format is agreed. Steps 2, 4, 5 are a dependency chain. Step 6 waits
on step 5. Step 7 is a cross-cutting test that blocks the other
steps. Steps 8 and 9 are the final integration and docs.

### 3.3 Out of scope

- Admin roles, co-owners, delegated group management
- Group-level policies (expiration, operation whitelists)
- Nested groups
- Group discovery / search (alice wants to join a public group)
- Notifications when a member is added/removed or when new files land
- Any plaintext-layer concerns

All of the above are backlog items, tracked in
[2026-04-07-next-steps-backlog.md](2026-04-07-next-steps-backlog.md).

---

## 4. Success criteria

- [ ] All CLI commands in §2.8 work end-to-end against a real server
- [ ] Creating a 5-member / 10-file group produces exactly 50 `shares`
      rows, 5 `group_members` rows, 10 `group_files` rows, and 1
      `groups` row
- [ ] Removing a member from a group atomically revokes that
      member's access to all files in the group
- [ ] Removing a file from a group atomically revokes all members'
      access to that specific file (without affecting other files)
- [ ] Direct (non-group) shares and group shares for the same file
      coexist without interfering
- [ ] Every group operation is authenticated with a matching
      canonical signature message; tampering with the batch is
      rejected via the `files_digest` / `members_digest` check
- [ ] Idempotent retry of `add_member` and `add_file` is safe
- [ ] Per-group mutex prevents the §2.6 Race 1 scenario in a
      concurrent stress test
- [ ] A 100-member group adds a new file in one round trip; the
      CLI shows progress during local recrypt-key generation

---

## 5. Open questions

### 5.1 Member visibility: can members see each other?

If Bob is in the Family group, does he know Carol is also in Family?
For most "Signal meets Dropbox" use cases the answer is yes. But it
affects the endpoint: `GET /groups/{id}/members` — who can call it?
Owner only? Any member? Non-members?

**Leaning:** any member can list members of groups they belong to.
Non-members get 404 (not 403 — we don't want to leak group existence).

### 5.2 Group invite flow

Right now the plan has the owner add members unilaterally (because
the owner has the member's public key and just generates a recrypt
key to them). But a more typical product flow is an invite:

1. Alice creates a group
2. Alice sends an invite to Bob (out-of-band or via server)
3. Bob accepts
4. Server notifies Alice's client
5. Alice's client generates the recrypt keys and submits them

This is optional polish; the MVP can work without it if Alice already
has Bob's public key. But it affects how groups feel. Deferred to
backlog.

### 5.3 Group-owned files vs owner-owned files added to a group

Today: Alice owns file F, adds F to the Family group. Alice still
owns F; group membership just means "other members have read access".
What if Alice leaves the family? What about group-owned files (files
that belong to the group itself, not to a specific individual)?

These are real questions but they're the *next* iteration. MVP: every
file is owned by an individual, groups grant read access. Deferred.

### 5.4 Read vs write access inside a group

Current plan: group members get read-only access. Writes stay
owner-only. Real collaboration ("Bob can also upload to Family")
requires writable group membership, which introduces questions about
who-signs-what for writes.

Deferred. MVP is read-only group sharing, which is already the 80%
use case for a photo-sharing family drive.

### 5.5 Can a group be "owned" by a multi-sig?

Future work. Requires threshold signing or multi-party key
generation. Deferred.

---

## 6. References

- Sibling plans:
  - [2026-04-07-production-readiness.md](archive/2026-04-07-production-readiness.md) —
    must land first (trait-backed persistence)
  - [2026-04-06-bao-streaming-and-storage-simplification.md](2026-04-06-bao-streaming-and-storage-simplification.md) —
    orthogonal, compounds with group sharing for large-file use cases
  - [2026-04-07-next-steps-backlog.md](2026-04-07-next-steps-backlog.md) —
    everything deferred from this plan
- Existing machinery:
  - Per-file shares: `recrypt-server/src/routes/recryption.rs`
  - Recrypt key generation: `recrypt-core::pre::PreBackend::generate_recrypt_key`
  - Ownership tracking: `recrypt-storage-auth::OwnershipStore`
- The user-facing framing ("Signal meets Dropbox"):
  [architecture.md §1](../architecture.md),
  [threat-model.md §0](../threat-model.md)
