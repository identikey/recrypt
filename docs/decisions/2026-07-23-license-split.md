# D-3: Per-crate license split — permissive core, AGPL + commercial stack

**Date:** 2026-07-23
**Status:** Accepted

## Decision

Drop PolyForm Noncommercial 1.0.0 entirely. Recrypt is licensed per-crate:

- **MIT OR Apache-2.0** (workspace default): `recrypt-core`, `recrypt-ffi`,
  `recrypt-openfhe-sys`, `recrypt-wire`, `recrypt-storage`, `recrypt-client`,
  `identikey-auth` — the core cryptography/protocol library, publishable to
  crates.io.
- **AGPL-3.0-or-later + commercial carve-out**: `recrypt-server`,
  `recrypt-cli`, `identikey-storage-auth` — the deployable stack. Identikey
  Inc. sells a commercial license removing the AGPL's copyleft and §13
  network-disclosure obligations (`LICENSE-COMMERCIAL.md`).
- Contributions accepted under a CLA (`CLA.md`) granting relicensing rights,
  which is what makes the dual license possible.

## Rationale

1. **Grant alignment.** Recrypt is funded by Shift Grants (EF d/acc), whose
   guidelines state "open-source dissemination is the default." PolyForm
   Noncommercial is source-available, not open source (OSI) — a business-model
   exception, not the security exception the guidelines contemplate. The
   permissive core is the grant-funded public good; AGPL is genuinely open
   source, so the whole repo now satisfies the default.
2. **Adoption.** PolyForm-NC is auto-rejected by corporate license scanners
   and no MIT/Apache Rust crate can depend on it — the ecosystem norm is
   MIT OR Apache-2.0 dual. The permissive core makes Recrypt embeddable.
3. **Exit test.** Under PolyForm-NC + commercial, a lapsed commercial customer
   lost the right to run the software that decrypts their data. Under AGPL,
   use is free for everyone forever; only closed redistribution or closed
   network services need the commercial license.
4. **Revenue.** The AGPL + commercial model (MongoDB/Qt pattern, and the same
   structure as Lightning Mesh) preserves the revenue mechanism: enterprises
   that won't comply with AGPL §13 buy the carve-out.

## Constraints

- Permissive crates must never depend on AGPL crates (currently holds:
  server/CLI/storage-auth sit on top of the core, not vice versa).
- New library crates inherit the workspace default (MIT OR Apache-2.0); new
  services/binaries must set `license = "AGPL-3.0-or-later"` explicitly.
- Wallet-management code currently in `recrypt-cli` is planned to move into
  permissive identikey core crates; the CLA + sole authorship make that
  extraction from an AGPL crate unproblematic.

## Alternatives considered

- **Keep PolyForm-NC dual license** — rejected: not open source, conflicts
  with grant framing, blocks ecosystem adoption, fails the exit test.
- **BUSL-1.1 time-delayed open** — viable ("delayed open"), but weaker grant
  story than genuinely-open AGPL and adds a change-date bookkeeping burden.
- **Everything permissive** — maximizes diffusion but removes the commercial
  leverage on the hosted/proxy stack entirely.

## Reversal triggers

- crates.io or major downstreams treat the split as confusing enough to block
  adoption of the core crates.
- Commercial licensing produces no revenue and the AGPL boundary demonstrably
  deters deployments that would otherwise contribute back → consider going
  fully permissive.
- Shift Grants (or a future funder) requires different terms in writing.
