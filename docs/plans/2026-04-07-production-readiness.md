# Production Readiness: Persistence, Boundaries, Config, Rate Limiting

**Date:** 2026-04-07
**Status:** ✅ Implemented
**Phase:** 8 (Documentation & Deployment) / pre-9
**Depends on:** none (can land before or alongside
[bao-streaming-and-storage-simplification](2026-04-06-bao-streaming-and-storage-simplification.md))

> **TL;DR** Make `recrypt-server` stop being an in-memory prototype.
> Trait-backed state stores with SQLite-default / in-memory-for-tests
> implementations, a clean re-slicing of responsibilities between
> `recrypt-server`, `identikey-storage-auth`, and `recrypt-storage`,
> env-var config via `figment`, and drop-in `tower-governor` rate
> limiting. Smallest-possible change that turns the prototype into
> something you can actually run.

---

## 1. Motivation

Today, `recrypt-server` keeps every state store in a `HashMap` inside
`AppState`: accounts, shares, nonces. Restart the process and every
account registration, every active share, and every nonce in flight is
gone. This is fine for tests; it is not something anyone can rely on.

Three other things are "right there" and worth bundling with the
persistence sprint because they're small, unrelated to crypto
correctness, and missing them will be embarrassing the first time
someone runs the server in anger:

- **No environment-variable configuration.** Everything is
  `recrypt-server.toml`, which makes secrets handling and
  environment-specific overrides awkward.
- **No rate limiting.** The Phase 5 plan called for it; nobody wrote it.
- **A crate boundary that no longer reflects responsibilities.**
  `AccountStore` lives in `recrypt-server` (it's identity data, it
  belongs in the auth crate); `ProviderIndex` lives in
  `identikey-storage-auth` (it's "where is this blob stored", which is
  a storage-layer concern). Fixing this now — before we build more on
  top of the current layout — is substantially cheaper than fixing it
  later.

These four items form one coherent sprint because they all touch the
same `AppState` construction path at server startup. Doing them
together is one migration; doing them separately is three.

---

## 2. Decisions

### 2.1 Persistence: `tokio-rusqlite` + SQLite WAL, trait-backed

**Backend of choice:** SQLite via `tokio-rusqlite`, opened in WAL
(Write-Ahead Logging) mode. Reasoning:

- SQLite in WAL mode supports **many concurrent readers + one writer**
  without blocking. The recrypt-server workload is dominated by reads
  (every download request hits the account, share, and ownership
  stores) with relatively rare writes (account creation, share
  add/revoke). This is exactly the workload SQLite WAL is best at.
- `tokio-rusqlite` wraps the sync `rusqlite` API in a tokio
  blocking-thread pool, so it slots cleanly into our axum handlers
  without any `spawn_blocking` ceremony at the call site.
- `identikey-storage-auth` already uses `rusqlite` for its existing
  stores. Same toolchain, same schema-migration story, same
  connection-handling patterns.
- Postgres can come later if we hit scale. The trait design below
  makes that a drop-in swap, not a rewrite.

**NOT using `sqlx`** — its compile-time query checking and async
story are nice, but the dependency cost and the mixed workspace (some
crates already on `rusqlite`) make it the wrong choice today.

### 2.2 Trait-backed state stores

Every mutable state store in `recrypt-server` becomes a trait with
in-memory and SQLite implementations. `ServerState` holds `Arc<dyn
Trait>` for each. Config picks which implementation to instantiate at
startup.

```rust
// recrypt-server/src/state.rs

pub struct ServerState {
    pub accounts:   Arc<dyn AccountStore>,
    pub shares:     Arc<dyn ShareStore>,
    pub nonces:     Arc<dyn NonceStore>,
    pub ownership:  Arc<dyn OwnershipStore>,   // from identikey-storage-auth
    pub storage:    Arc<dyn ChunkStorage>,     // from recrypt-storage
    pub providers:  Arc<dyn ProviderIndex>,    // from recrypt-storage (after move)
    pub backend:    Arc<dyn PreBackend>,
}
```

The traits themselves:

```rust
// identikey-storage-auth::account (NEW, moved from recrypt-server)
#[async_trait]
pub trait AccountStore: Send + Sync {
    async fn register(&self, record: AccountRecord) -> AuthResult<()>;
    async fn get(&self, fingerprint: &PublicKeyFingerprint) -> AuthResult<Option<AccountRecord>>;
    async fn exists(&self, fingerprint: &PublicKeyFingerprint) -> AuthResult<bool>;
}

// recrypt-server::shares (NEW trait, existing type)
#[async_trait]
pub trait ShareStore: Send + Sync {
    async fn create(&self, policy: SharePolicy) -> ServerResult<ShareId>;
    async fn get(&self, id: &ShareId) -> ServerResult<Option<SharePolicy>>;
    async fn delete(&self, id: &ShareId) -> ServerResult<()>;
    async fn list_outgoing(&self, from: &PublicKeyFingerprint) -> ServerResult<Vec<SharePolicy>>;
    async fn list_incoming(&self, to:   &PublicKeyFingerprint) -> ServerResult<Vec<SharePolicy>>;
}

// recrypt-server::nonces (NEW trait, existing type)
#[async_trait]
pub trait NonceStore: Send + Sync {
    async fn mark_used(&self, nonce: &str, expires_at: u64) -> ServerResult<bool>;
    // returns true if this is the first use, false if replay
    async fn gc_expired(&self) -> ServerResult<usize>;
}
```

Each trait gets two implementations:

- **`InMemory*`** using `RwLock<HashMap<...>>` — kept for fast unit
  tests and for the `pre_backend = "mock"` path.
- **`Sqlite*`** using `tokio_rusqlite::Connection` with WAL mode and
  prepared statements.

### 2.3 Boundary refactor

The crate boundaries need a small re-slicing before we pour persistence
code into them. We're doing it here because it is substantially cheaper
to fix now than after SQLite schemas exist in the wrong places.

**Changes:**

| Type / concept     | Lives today in        | Should live in            | Why                                |
| ------------------ | --------------------- | ------------------------- | ---------------------------------- |
| `AccountStore`     | `recrypt-server`      | `identikey-storage-auth`  | Identity data is auth's job        |
| `AccountRecord`    | `recrypt-server`      | `identikey-storage-auth`  | Same                               |
| `ProviderIndex`    | `identikey-storage-auth` | `recrypt-storage`      | "Where is this blob" is storage    |
| `InMemoryProviderIndex` | `identikey-storage-auth` | `recrypt-storage`  | Same                               |
| `SqliteProviderIndex`   | `identikey-storage-auth` | `recrypt-storage`  | Same                               |
| `OwnershipStore`   | `identikey-storage-auth` | stays                   | Correct home                       |
| `Capability`, `AccessGrant` | `identikey-storage-auth` | stays (unused)  | Scaffolding for future work        |
| `ShareStore`       | `recrypt-server`      | stays                     | Tightly coupled to PRE backend     |
| `NonceStore`       | `recrypt-server`      | stays                     | Request-lifecycle ephemeral        |

**Principles behind the moves:**

1. **`identikey-storage-auth` owns identity and authorization.** Who
   are you, what do you own, what have you delegated. `AccountStore`
   is the "who are you" layer and belongs here.
2. **`recrypt-storage` owns blob identity and location.** Content
   addressing, chunk storage, provider registry. `ProviderIndex` is
   exactly the backend-agility primitive that was supposed to live
   next to `ChunkStorage` and got misplaced.
3. **`recrypt-server` owns recrypt-specific control plane.** Share
   policies carrying recrypt keys, nonce replay prevention, HTTP
   routing. Anything that is *not* recrypt-specific gets pushed down
   into the auth or storage crates.

**`Capability` and `AccessGrant` stay put** even though they are
currently unused by `recrypt-server` routes. They're the right
primitives for several future directions:

- Per-user capability tokens for the plaintext layer
- Non-transferable proxy recryption (a capability binds a recrypted
  output to a specific recipient)
- Delegated access without full share semantics

Deleting them now would be churn for no gain. Leaving them as
scaffolding is cheap.

### 2.4 Configuration via `figment`

Use [`figment`](https://crates.io/crates/figment) to layer config
sources with a consistent precedence:

```
default → recrypt-server.toml → env vars (RECRYPT_*) → CLI flags
         (later overrides earlier)
```

```rust
// recrypt-server/src/config.rs
use figment::{Figment, providers::{Format, Toml, Env}};

let config: Config = Figment::new()
    .merge(Toml::file("recrypt-server.toml"))
    .merge(Env::prefixed("RECRYPT_").split("__"))
    .extract()?;
```

Environment variables use double-underscore for nesting. Examples:

| Config key            | Env var                         |
| --------------------- | ------------------------------- |
| `host`                | `RECRYPT_HOST`                  |
| `port`                | `RECRYPT_PORT`                  |
| `storage.backend`     | `RECRYPT_STORAGE__BACKEND`      |
| `storage.s3_bucket`   | `RECRYPT_STORAGE__S3_BUCKET`    |
| `persistence.backend` | `RECRYPT_PERSISTENCE__BACKEND`  |
| `persistence.sqlite_path` | `RECRYPT_PERSISTENCE__SQLITE_PATH` |
| `nonce.window_secs`   | `RECRYPT_NONCE__WINDOW_SECS`    |
| `pre_backend`         | `RECRYPT_PRE_BACKEND`           |
| `rate_limit.per_ip_rps` | `RECRYPT_RATE_LIMIT__PER_IP_RPS` |
| `rate_limit.per_fingerprint_rps` | `RECRYPT_RATE_LIMIT__PER_FINGERPRINT_RPS` |

Secrets (S3 access keys, etc.) are env-vars-only by convention — never
written to `recrypt-server.toml`.

### 2.5 Rate limiting via `tower-governor`

Drop in [`tower-governor`](https://crates.io/crates/tower_governor) as
an axum middleware layer. Per-IP limiting out of the box; per-fingerprint
limiting via a custom key extractor that reads the `X-Public-Key` header.

```rust
let governor_conf = Arc::new(
    GovernorConfigBuilder::default()
        .per_second(config.rate_limit.per_ip_rps)
        .burst_size(config.rate_limit.per_ip_burst)
        .finish()
        .unwrap()
);

let app = Router::new()
    .route(...)
    .layer(GovernorLayer { config: governor_conf });
```

Defaults (configurable, these are starting points):

- Per-IP: 30 req/s, burst 60
- Per-fingerprint (for authenticated endpoints): 100 req/s, burst 200
- Global: no cap (we rely on per-IP + per-fingerprint)

Endpoints that explicitly bypass rate limiting: `GET /health`.

---

## 3. Implementation plan

### 3.1 Steps (ordered by dependency)

1. **Add dependencies.** `tokio-rusqlite`, `figment` (with `toml` +
   `env` features), `tower-governor`, and pin versions in the workspace
   `Cargo.toml`.

2. **Move `ProviderIndex` from `identikey-storage-auth` to
   `recrypt-storage`.** Pure code move — update `pub use`
   re-exports, update `recrypt-server::state::AppState` to import
   from the new location. No schema changes.

3. **Move `AccountStore` / `AccountRecord` from `recrypt-server` to
   `identikey-storage-auth`.** Promote `AccountStore` from an in-memory
   struct to a trait with an in-memory impl. Update
   `recrypt-server::routes::accounts` to go through the trait.

4. **Define trait + in-memory impls for `ShareStore` and
   `NonceStore`** in `recrypt-server`. Update routes to use the
   trait. All existing tests still pass; this is a pure refactor.

5. **Define `Config` struct** with `Serialize + Deserialize` covering
   persistence, rate limiting, and the existing storage/nonce/pre
   sections. Wire `figment` layering in `main.rs`. Update the example
   `recrypt-server.toml`.

6. **Implement `SqliteAccountStore`** in `identikey-storage-auth` next
   to existing SQLite stores. Schema: one table `accounts`
   (fingerprint PK, ed25519_pk, ml_dsa_pk, pre_pk, created_at).
   Migration at startup.

7. **Implement `SqliteShareStore`** and **`SqliteNonceStore`** in
   `recrypt-server`. Schemas:
   - `shares` (share_id PK, from_fp, to_fp, file_hash, recrypt_key,
     backend_id, created_at)
   - `nonces` (nonce PK, expires_at). GC query: `DELETE FROM nonces
     WHERE expires_at < ?`. GC runs on a tokio interval.

8. **Wire selection logic.** `ServerState::from_config(&config)`
   instantiates either in-memory or SQLite backends for each store
   based on `config.persistence.backend`. Keep in-memory as the
   default for `pre_backend = "mock"`.

9. **Add `tower-governor` middleware** to the router with config-driven
   limits. Per-IP layer applies to everything except `GET /health`;
   per-fingerprint layer applies to authenticated endpoints only.

10. **End-to-end test.** Start the server with `backend = "sqlite"`,
    register an account, create a share, restart the server (fresh
    process), confirm the account and share are still there and still
    work. Start the server with a low rate limit, fire 100 requests
    from one IP, confirm 429 responses past the limit.

11. **Update documentation.** `architecture.md` §3 (recrypt-server
    description), `storage-design.md` (ProviderIndex now lives in
    storage), `http-api-reference.md` (rate limit status codes),
    `.omc/state/architecture.md` gaps list (cross off persistence,
    env vars, rate limiting).

### 3.2 Parallelization

Step 2 and step 3 are independent and can be done in parallel. Step 5
is independent of 2–4. Steps 6, 7, 8, 9 serialize after the earlier
refactors land. Step 10 is the integration test; step 11 is docs.

### 3.3 Out of scope for this plan

Explicitly **not** doing in this sprint, to keep scope bounded:

- Postgres backend (trait-ready, add later if needed)
- Group sharing (separate plan:
  [2026-04-07-group-sharing.md](2026-04-07-group-sharing.md))
- Discoverability / sync / indexes (see backlog)
- Deployment artifacts beyond "env vars work" (Mjolnir integration
  lives elsewhere)
- Threat model adversarial pass (deferred to pre-Phase-9)
- Account recovery (deferred to identikey integration)
- The bao-streaming refactor
  ([2026-04-06-bao-streaming-and-storage-simplification.md](2026-04-06-bao-streaming-and-storage-simplification.md))
  is orthogonal and can land before, after, or concurrently

---

## 4. Success criteria

- [ ] `cargo build -p recrypt-server -p identikey-storage-auth
  -p recrypt-storage` clean
- [ ] All existing unit and integration tests pass unchanged
- [ ] New unit tests: trait-based stores, both in-memory and SQLite
  impls, round-trip register → query → delete for each
- [ ] Integration test: server restart preserves account and share
  state
- [ ] Integration test: rate limiter returns 429 after configured
  threshold, returns to 200 after burst window recovers
- [ ] Env var test: `RECRYPT_PORT=9999 recrypt-server` binds to 9999
  without a config file
- [ ] Env var test: `RECRYPT_PERSISTENCE__BACKEND=sqlite
  RECRYPT_PERSISTENCE__SQLITE_PATH=/tmp/recrypt.db` selects SQLite
- [ ] `identikey-storage-auth` exports `AccountStore`,
  `SqliteAccountStore`, `InMemoryAccountStore`
- [ ] `recrypt-storage` exports `ProviderIndex`,
  `SqliteProviderIndex`, `InMemoryProviderIndex`
- [ ] `recrypt-server` no longer contains `AccountStore` definition;
  imports it from `identikey-storage-auth`
- [ ] Docs updated to reflect new boundaries

---

## 5. Open questions

### 5.1 Nonce store: actually persist or not?

The only reason to persist nonces is to survive server restarts
without re-opening the replay window. That window is 5 minutes by
default, so a restart loses at most 5 minutes of replay protection.
For a real production deployment that might matter; for early-stage
users it almost certainly doesn't.

**Recommendation:** implement `SqliteNonceStore` for completeness, but
keep `InMemoryNonceStore` as the default in config. Users who care
can flip the switch. Re-evaluate before Phase 9 audit.

### 5.2 Connection pooling

`tokio-rusqlite` has a single-connection model by default. For our
workload (dominated by small fast queries on the critical path of
request handling) a pool is overkill, but if we hit contention we can
add `deadpool-sqlite`. Start with one connection + WAL, benchmark,
upgrade if needed.

### 5.3 SQLite file layout

One database file per crate (`identikey-auth.db`,
`recrypt-server.db`) or one unified file shared across crates? One
file is simpler to back up and harder to get inconsistent. Leaning
**one unified file** — `recrypt.db` at the configured path, with
tables for both crates' schemas. Requires a small cross-crate schema
coordination convention but is clearly the right choice
operationally.

### 5.4 Schema migrations

For now, single-version "create tables if not exist" at startup.
When we ship a v2 schema we'll introduce a real migration framework
(either `refinery`, `rusqlite_migration`, or a homegrown
`schema_version` table — the existing `identikey-storage-auth` uses
the latter). Pre-1.0 schema churn is acceptable.

---

## 6. References

- Current recrypt-server state:
  - [recrypt-server/src/state.rs](../../recrypt-server/src/state.rs)
  - [recrypt-server/src/routes/](../../recrypt-server/src/routes/)
- Existing SQLite patterns in `identikey-storage-auth`:
  - [crates/identikey-storage-auth/src/sqlite/](../../crates/identikey-storage-auth/src/sqlite/)
- [`tokio-rusqlite` docs](https://docs.rs/tokio-rusqlite)
- [`figment` docs](https://docs.rs/figment)
- [`tower-governor` docs](https://docs.rs/tower_governor)
- Sibling plans:
  - [2026-04-06-bao-streaming-and-storage-simplification.md](2026-04-06-bao-streaming-and-storage-simplification.md)
  - [2026-04-07-group-sharing.md](2026-04-07-group-sharing.md) (next)
  - [2026-04-07-next-steps-backlog.md](2026-04-07-next-steps-backlog.md) (backlog)

---

## 7. Changelog

During implementation, the following execution decisions were made:

- **tokio-rusqlite:** Bumped from 0.5 to 0.7 for improved async integration
- **rusqlite:** Bumped from 0.32 to 0.37 for compatibility with tokio-rusqlite 0.7
- **tower_governor:** Bumped from 0.4 to 0.7 for enhanced rate-limiting features
- **Nonce GC lifecycle:** Implemented via Drop guard on `NonceGcHandle` held by `AppState`. The tokio interval task (60s period calling `nonces.gc_expired()`) aborts cleanly when the last `AppState` clone drops.
- **SQLite file layout:** Single unified `recrypt.db` chosen (Question 5.3 resolved). All three stores (`AccountStore`, `ShareStore`, `NonceStore`) share ONE `tokio_rusqlite::Connection`. Auth service `OwnershipStore` and `ProviderIndex` coordinate schema across crates with a shared `schema_version` table for migrations.
