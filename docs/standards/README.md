# Recrypt specifications

Format and protocol specs for the parts of Recrypt that are Recrypt's own.

| Spec | Specifies |
|---|---|
| [`recrypt-key-material-v1.md`](recrypt-key-material-v1.md) | The 96-byte KeyMaterial v1 bundle that gets PRE-encrypted |
| [`xchacha20-bao-aead.md`](xchacha20-bao-aead.md) | XChaCha20-Bao, the streaming AEAD construction |
| [`identity-self-signature.md`](identity-self-signature.md) | Wrap-then-sign over a Recrypt identity envelope, including `pre-public` / `pre-backend` |
| [`hashing-standard.md`](hashing-standard.md) | Blake3 everywhere |

## Moved to identikey-protocol (2026-08-07)

Five specs moved to the
[identikey-protocol](https://github.com/identikey/identikey-protocol) repo,
following the code that implements them (D-4, 2026-08-01). They specify
identity-tier formats that are meant to be reimplemented by people who have
no reason to read this repo, and a permissively-licensed protocol whose only
specification lives in an AGPL product repo is not really open:

| Spec | Now at |
|---|---|
| `identikey-auth-challenge-v1.md` | [identikey-protocol/docs/standards](https://github.com/identikey/identikey-protocol/blob/main/docs/standards/identikey-auth-challenge-v1.md) |
| `identikey-auth-platform-backends.md` | [identikey-protocol/docs/standards](https://github.com/identikey/identikey-protocol/blob/main/docs/standards/identikey-auth-platform-backends.md) |
| `wallet-envelope-format.md` | [identikey-protocol/docs/standards](https://github.com/identikey/identikey-protocol/blob/main/docs/standards/wallet-envelope-format.md) |
| `dcbor-determinism.md` | [identikey-protocol/docs/standards](https://github.com/identikey/identikey-protocol/blob/main/docs/standards/dcbor-determinism.md) |
| `encoding-conventions.md` | [identikey-protocol/docs/standards](https://github.com/identikey/identikey-protocol/blob/main/docs/standards/encoding-conventions.md) |

`encoding-conventions.md` followed on 2026-08-07, a few hours after the other
four. It had been held back because its scope line said "anywhere in recrypt"
and six Recrypt source files cite it — but Dreamball adopted the same envelope
format that day and had independently written a *conflicting* rule for the same
boundary. The document turned out to describe the shared substrate, not
Recrypt; its scope line described its history. It now binds Recrypt,
`identikey-*` and Dreamball alike, and gained a third regime: `ur:envelope/…`
is the canonical text form for a whole envelope, which demotes Recrypt's
ASCII armor block (§6) to legacy read-only.

Recrypt still depends on all five — `recrypt-cli` consumes `identikey-wallet`,
so the wallet container format is still normative here. They are upstream
documents now, not ours to change unilaterally.
