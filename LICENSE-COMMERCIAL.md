# Recrypt — Commercial License

The core library crates of Recrypt are permissively licensed (MIT OR
Apache-2.0) and never need a commercial license — see [LICENSE](LICENSE) for
the full crate map.

The deployable stack — `recrypt-server`, `recrypt-cli`, and
`identikey-storage-auth` — is **dual-licensed**. You may use it under
**either**:

1. The **GNU Affero General Public License v3.0 or later**
   (AGPL-3.0-or-later), the license in [`LICENSE-AGPL`](LICENSE-AGPL) — free
   of charge, forever; or
2. A **commercial license** from **Identikey Inc.**, described below.

You only need a commercial license if the AGPL's obligations don't work for
your product. If you're happy to comply with the AGPL, you owe nothing and
can stop reading.

---

## When you need a commercial license

The AGPL is a strong copyleft license. Under it, **section 5** requires that
anyone you convey a modified version to receives the complete corresponding
source under the AGPL, and **section 13** extends that to *network use*: if
you let users interact with a modified Recrypt server over a network, you
must offer them its complete corresponding source.

For most operators — individuals, researchers, nonprofits, community
deployments, and any organization willing to share source — the AGPL is a
perfect fit and is free, including running Recrypt in production
commercially.

You will likely want a **commercial license** if any of the following apply
and you do **not** wish to release your corresponding source under the AGPL:

- You offer a **hosted / SaaS service** built on the Recrypt server or auth
  service, and cannot or will not disclose its source under AGPL §13.
- You embed the AGPL-licensed crates in a **proprietary product** that you
  sell, lease, or distribute.
- You **link or combine** them with proprietary software in a way that would
  make that software a derivative work subject to the AGPL.
- Your legal/procurement policy **prohibits AGPL** software in shipped
  products.

A commercial license grants you the same code under terms that **remove the
AGPL's copyleft and network-source-disclosure obligations**, so you can ship
a closed product.

## How to obtain one

Email **sales@identikey.io** with:

- your company and product,
- roughly how Recrypt will be used (hosted service, embedded, internal
  deployment, etc.), and
- expected scale (deployments/users).

We'll follow up with a quote and a license agreement.

---

## Third-party components

Recrypt depends on third-party libraries (e.g. OpenFHE, liboqs) vendored
under `vendor/`. Those components are distributed under their own licenses,
which are unaffected by Recrypt's licensing and continue to apply to that
code. A commercial license does not relicense them.

*This document is a summary of the commercial-licensing offer, not the
commercial license agreement itself. The binding terms are in the signed
agreement provided at purchase. Nothing here modifies your rights under the
AGPL or the permissive licenses, which remain available to everyone.*
