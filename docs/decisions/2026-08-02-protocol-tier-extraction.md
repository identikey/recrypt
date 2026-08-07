# D-4: Protocol-tier extraction (identikey-protocol) + patent-grant relicense

**Date:** 2026-08-02
**Status:** Accepted
**Supersedes parts of:** [D-3](2026-07-23-license-split.md) (crate list and
permissive-license choice)

## Decision

1. **The protocol tier gets its own repo:**
   [identikey-protocol](https://github.com/identikey/identikey-protocol),
   licensed `Apache-2.0 OR BSD-2-Clause-Patent`, containing:
   - `identikey-auth` — moved out of this repo unchanged (hardware-enclave
     challenge/response auth). Nothing here consumed it yet.
   - `identikey-wallet` — the wallet engine extracted from
     `recrypt-cli/src/wallet/`: `IKEYW` v2 file crypto (Argon2id +
     XChaCha20-Poly1305), OS keychain caching, and the Gordian Envelope
     container, made generic via a `WalletIdentity` trait + `WalletParams`.
   - `ikey` — standalone wallet CLI (Ed25519 + optional ML-DSA-87
     identities), for identity wallets in contexts beyond proxy recryption.

2. **Recrypt consumes `identikey-wallet` as a git dependency.**
   `recrypt-cli/src/wallet/mod.rs` supplies the Recrypt-specific layer:
   `RECRYPT_PARAMS` (the `recrypt.wallet` envelope type, `recrypt` keychain
   service, `RECRYPT_*` env vars — all byte/behavior-compatible with
   pre-extraction wallets) and `Identity` (Ed25519 + ML-DSA + PRE keypairs),
   whose envelope codec still delegates to `recrypt_wire::Identity` so
   wallet bytes remain identical to wire bytes.

3. **Gap 2 fix:** this repo's permissive crates move from
   `MIT OR Apache-2.0` to `Apache-2.0 OR BSD-2-Clause-Patent`. A disjunction
   containing MIT lets a hostile licensee elect MIT and dodge the patent
   grant; both remaining options make the grant mandatory. Decided while
   Duke is still the sole author, so no contributor consent was needed.

## Why a separate repo (not identikey-core, not in-tree)

Per the licensing-and-commons doctrine in the identikey-core repo
(`docs/licensing-and-commons.md`, 2026-07-28): *protocols permissive,
products copyleft-plus-commercial*. `identikey-core` is the hosted identity
product (AGPL + commercial) — the wrong tier for embeddable protocol code.
The doctrine's §5c decision names both the workspace (`identikey-protocol`)
and its license. Wallet mechanics are protocol-tier by that definition:
reference implementations of formats meant to outlive any steward.

## Boundary invariants

- `identikey-wallet` knows nothing about PRE, Recrypt, or recrypt-wire.
  App-specific key material rides as identity-level assertions; unknown
  assertions round-trip byte-stably in both directions, so `ikey` and
  `recrypt` can each edit wallets without destroying the other's data.
- Compatibility surfaces frozen by `RECRYPT_PARAMS`: the `recrypt.wallet`
  type string, keychain service `recrypt`, `RECRYPT_WALLET_PASSWORD` /
  `RECRYPT_WALLET_KEY` / `RECRYPT_NO_KEYCHAIN`, the v1 rejection string,
  and the default path (`io.identikey/recrypt/wallet.ikeyw`). Existing
  wallets and cached keychain entries keep working unmodified.
- The generic tool's own params (`IDENTIKEY_PARAMS`) use `identikey.wallet`
  / `identikey.identity` subjects and `IDENTIKEY_*` env vars.

## Follow-ups

All four are now tracked (2026-08-07). Protocol-tier work lives in
identikey-protocol's own bd workspace (`ikp-*`) rather than in a consumer's
tracker — see "Where protocol work is tracked" below.

- Publish `identikey-wallet` (and recrypt core crates) to crates.io; switch
  the git dependency to a version once published. → `ikp-6yz.1` (publish),
  `recrypt-c9q` (the dep switch here). Until then the dep is
  `branch = "main"`, i.e. unversioned: pin a `rev` if the publish slips.
- Wallet format + identity envelope specs with test vectors belong in the
  identikey-protocol repo (the doctrine's highest-leverage gap). →
  `ikp-6yz.2`.
- `ikey` reading `recrypt.wallet` files (cross-app wallet management) needs
  a tolerant container codec that accepts multiple type strings — deferred.
  → `ikp-pus`.
- ~~Consider renaming `identikey-storage-auth` → `recrypt-storage-auth`~~ —
  **done 2026-08-07** (`recrypt-5u9`). Code, `Cargo.toml`s, `Justfile`,
  `LICENSE`/`NOTICE`/`LICENSE-COMMERCIAL.md`/`LICENSE-EXCEPTIONS.md`,
  `README.md`, `CLAUDE.md`, and the live docs were rewritten; the crate
  stays `AGPL-3.0-or-later`. Decision records and `docs/plans/archive/`
  keep the old name deliberately — they are historical records of what was
  true when written, not current documentation.

## Where protocol work is tracked

identikey-protocol has its own bd workspace (prefix `ikp`). The alternative —
tracking it in identikey-core or here — reproduces at tracker level exactly
the coupling that identikey-core's ADR-002 split the repos to avoid: a fork
of the permissive tier would get the code and none of the reasoning. Two
consequences already visible:

- identikey-core's extraction epic (`identikey-core-jsv`) sat open with
  completed children for six days after this commit landed, because the work
  happened in a different repo than the tracker.
- `identikey-log` cites `Dreamball-*` issue IDs in its `Cargo.toml` for
  load-bearing dependency decisions (the bc-envelope feature set, fips204
  over pqcrypto-mldsa, the two-`getrandom`-majors plumbing). Tracked as
  `ikp-c1u`; the fix is that the protocol repo carries its own copy of the
  reasoning, not that consumers stop recording theirs.

## Reversal triggers

- The git-dependency workflow proves too brittle before crates.io publish
  → vendor the crate back temporarily, keep the API boundary.
- The `WalletIdentity` abstraction blocks a needed wallet feature →
  widen the trait in identikey-protocol rather than forking the engine.
