import { defineConfig } from '@hey-api/openapi-ts';

// Generated client for the recrypt proxy API. Source of truth is the
// utoipa-annotated handlers in `recrypt-server`; the OpenAPI snapshot
// at `crates/recrypt-client/openapi.json` is refreshed by
// `just openapi-regen`. This config drives codegen from that snapshot
// into `src/generated/` (which IS committed, so consumers don't need
// to run codegen on install).
export default defineConfig({
  input: '../crates/recrypt-client/openapi.json',
  output: {
    path: './src/generated',
    postProcess: ['prettier'],
  },
  plugins: [
    '@hey-api/client-fetch',
    '@hey-api/typescript',
    '@hey-api/sdk',
  ],
});
