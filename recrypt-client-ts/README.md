# @recrypt/client

Generated TypeScript client for the recrypt proxy API.

The single source of truth is `crates/recrypt-client/openapi.json`,
which itself is generated from the utoipa-annotated handlers in
`recrypt-server` (see [`docs/decisions/2026-04-28-codegen-pipeline-decisions.md`](../docs/decisions/2026-04-28-codegen-pipeline-decisions.md)
for the distribution rationale).

## Install

```sh
cd recrypt-client-ts
bun install
```

`npm install` and `pnpm install` work too — Bun is just the project
default to match the Elysia/Eden ecosystem the consumer side is
likely to use.

## Use

```ts
import { client, createAccount } from '@recrypt/client';

client.setConfig({ baseUrl: 'https://recrypt.example.com' });

const { data, error } = await createAccount({
  body: {
    ed25519_pk: '...',
    ml_dsa_pk: '...',
  },
});
```

## Regenerate

After any change to a `#[utoipa::path]` handler in `recrypt-server`:

```sh
just openapi-regen
```

That runs `dump_openapi` (server → JSON snapshot), the markdown
splicer (snapshot → human docs), `cargo build -p recrypt-client`
(snapshot → Rust client), and `bun run generate` here (snapshot → TS
client). The generated TS lives under `src/generated/` and **is
committed** so consumers don't need a Bun install just to read the
types.

## Typecheck

```sh
bun run typecheck
```
