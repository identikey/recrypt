# Additional Permissions to the AGPL

These are **additional permissions** under section 7 of the GNU Affero General
Public License v3.0, granted by Identikey Inc. for the AGPL-licensed components
of this repository:

- `recrypt-server`
- `recrypt-cli`
- `crates/recrypt-storage-auth`

They apply **only** to those components, and only when you are exercising rights
under the AGPL. If you hold a commercial license (see
[`LICENSE-COMMERCIAL.md`](LICENSE-COMMERCIAL.md)) they are unnecessary — the
commercial license has no copyleft obligations to be excepted from.

Additional permissions may be removed by any recipient, per AGPL section 7. If you
convey a modified version, you may drop these permissions from your copy; you may
not add restrictions beyond what the AGPL allows.

---

## 1. Cryptographic library linking exception

> As an additional permission under section 7 of the GNU Affero General Public
> License version 3, you may link this software with, and distribute the resulting
> executable together with, general-purpose cryptographic libraries whose licenses
> are incompatible with the AGPL — including but not limited to OpenSSL, LibreSSL,
> BoringSSL, AWS-LC, and libraries derived from any of them — and you may convey
> the resulting work under the terms of the AGPL notwithstanding that
> incompatibility.
>
> This permission applies to the cryptographic library and to any code it requires,
> and extends to modified versions of this software that carry it forward. It does
> not extend to any other AGPL-incompatible code.
>
> You are not required to remove this permission from derived works, but you may.

### Why this exists

A transitive dependency can introduce an AGPL-incompatible crypto license without
anyone noticing. That is not hypothetical here: `aws-lc-sys` 0.36.0 declared
`ISC AND (Apache-2.0 OR ISC) AND OpenSSL`, and reached both AGPL binaries through
`recrypt-storage → aws-config/aws-sdk-s3 → aws-smithy-http-client → rustls →
aws-lc-rs`. The SPDX `OpenSSL` identifier is the OpenSSL 1.x / SSLeay dual license,
whose advertising clause the FSF lists as GPL-incompatible, and it was joined with
`AND` — so it could not be elected around.

That specific instance is resolved (`aws-lc-sys` ≥ 0.43.0 no longer declares it),
and CI enforces a license allowlist to catch recurrences. This permission exists so
that **the next occurrence is a routine dependency bump rather than a licensing
incident** — and so that anyone self-hosting or forking is never the one left
holding an undistributable binary.

It costs nothing. It is standard practice for AGPL network services, and it removes
a class of risk that falls hardest on exactly the people copyleft is meant to protect.

---

## 2. Interoperability note (not an exception)

For the avoidance of doubt, and consistent with how the AGPL already works:

Speaking the IdentiKey and Recrypt **wire protocols** — implementing the specs,
exchanging messages with a server, or writing an independent client — creates no
derivative work of the AGPL components and imposes no obligation whatsoever.

The protocol crates (`identikey-auth`, `recrypt-core`, `recrypt-wire`,
`recrypt-storage`, `recrypt-client`, `recrypt-ffi`, `recrypt-openfhe-sys`) are
permissively licensed for exactly this reason. See [`LICENSE`](LICENSE) for the
crate map.

**The copyleft boundary is the server, never the protocol.** If you are building a
client, an embedded integration, or an independent implementation, you are in
permissive territory and owe nothing.
