# Recrypt specifications

Format and protocol specs for the parts of Recrypt that are Recrypt's own.

| Spec | Specifies |
|---|---|
| [`recrypt-key-material-v1.md`](recrypt-key-material-v1.md) | The 96-byte KeyMaterial v1 bundle that gets PRE-encrypted |
| [`xchacha20-bao-aead.md`](xchacha20-bao-aead.md) | XChaCha20-Bao, the streaming AEAD construction |
| [`identity-self-signature.md`](identity-self-signature.md) | Wrap-then-sign over a Recrypt identity envelope, including `pre-public` / `pre-backend` |
| [`encoding-conventions.md`](encoding-conventions.md) | Every place a byte sequence crosses a text boundary in Recrypt |
| [`hashing-standard.md`](hashing-standard.md) | Blake3 everywhere |

## Moved to identikey-protocol (2026-08-07)

Four specs moved to the
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

Recrypt still depends on all four — `recrypt-cli` consumes `identikey-wallet`,
so the wallet container format is still normative here. They are upstream
documents now, not ours to change unilaterally.
