# SDK Reorg Plan: `sdk/client`, `sdk/server`, `sdk/wasm` (+ `sdk/shared`)

This plan restructures the `sdk/` package to match the new threshold‑multichain architecture by making trust boundaries explicit:
- **client**: browser + wallet‑origin code (UI/orchestration/workers)
- **server**: relay backend (routers, storage, threshold adapters)
- **wasm**: Rust crates compiled with `wasm-pack` (all crypto + tx hashing/encoding)
- **shared** (recommended): cross‑platform types/utilities used by both client and server

We haven’t released this SDK yet, so we can do a hard cutover (no compatibility/migration shims required), but we should keep the **public package exports** stable where convenient.

---

## Goals
- Make the boundary between client and server unambiguous.
- Make WASM ownership explicit and reusable across client+server builds.
- Reduce cross‑imports that accidentally pull browser APIs into server code (or Node APIs into client code).
- Provide a clean home for the multichain threshold architecture:
  - client: chain adapters + scheme engines + SecureConfirm
  - server: `ThresholdSignerAdapter -> SignatureType -> Signer`

## Non-goals
- Splitting into multiple published NPM packages (can be a later follow‑on).
- Large public API redesign (keep `@tatchi-xyz/sdk` exports mostly as-is).

---

## Target directory layout

Within the existing `sdk/` package:

```
sdk/
  client/
    src/
      app/                    # React/plugins/host-side helpers (no secrets)
      wallet/                 # wallet-origin only: iframe + SecureConfirm + signing
      workers/                # *.worker.ts entrypoints (near/eth/tempo/secure-confirm)
      index.ts                # client entry (re-exported by sdk root)
    tsconfig.json

  server/
    src/
      auth/                   # LoginProvider registry + sessions + linking
      threshold/              # ThresholdSignerAdapter registry + per-scheme adapters
      storage/                # kv/postgres/do implementations
      router/                 # express + cloudflare wiring
      index.ts                # server entry (re-exported by sdk root)
    tsconfig.json

  wasm/
    near_signer/              # (currently sdk/src/wasm_near_signer)
    eth_signer/
    tempo_signer/
    threshold_ecdsa/          # future

  shared/
    src/
      types/                  # stable cross-platform types (sessions/intents/signatures)
      utils/                  # base64/bytes/errors/validation (no DOM, no Node-only)
    tsconfig.json

  dist/                       # unchanged build output
  package.json
  rolldown.config.ts
  scripts/
```

Notes:
- `sdk/shared` is strongly recommended; without it, either client imports server (bad) or code duplicates.
- Keep “wallet origin only” code in `client/src/wallet/*` to avoid accidental app-origin exposure.

---

## Build system changes

### TypeScript compilation
- Replace `sdk/tsconfig.build.json` (or update it) to include:
  - `client/src/**/*`
  - `server/src/**/*`
  - `shared/src/**/*`
- Use TS project references (`composite: true`) so:
  - `client` depends on `shared`
  - `server` depends on `shared`
  - neither depends on the other

### Bundling
- Update `sdk/rolldown.config.ts` inputs to point at:
  - `client/src/index.ts` and `server/src/index.ts` (or keep a top-level `sdk/src/index.ts` as a façade)
  - worker entrypoints under `client/src/workers/*`
- Update aliasing:
  - replace `@/* -> src/*` with explicit aliases (e.g. `@client/*`, `@server/*`, `@shared/*`) or use relative imports.

### WASM builds
- Move Rust crates out of TS source tree:
  - `sdk/src/wasm_near_signer` → `sdk/wasm/near_signer` (and similarly for eth/tempo)
- Update `sdk/scripts/generate-types.sh`, `sdk/scripts/build-*.sh`, `sdk/build-paths.*` to use new wasm paths.
- Keep the wasm-pack output names stable (e.g. `wasm_signer_worker.js`, `*_bg.wasm`) to avoid unnecessary churn.

---

## Public API surface

Recommended: keep `@tatchi-xyz/sdk` exports stable by having a thin façade:
- `sdk/src/index.ts` re-exports from `sdk/client/src/index.ts` and `sdk/server/src/index.ts` (or similar)
- `sdk/src/lite/index.ts` can move to `sdk/client/src/lite/index.ts`, with the top-level export preserved

If we’re okay with a breaking internal refactor, the façade file can be removed later.

---

## Step-by-step migration plan

### Phase 1 — Introduce skeleton + boundaries
- Create `sdk/client/src`, `sdk/server/src`, `sdk/shared/src`, `sdk/wasm`.
- Add tsconfig project references (`client` and `server` depend on `shared`).
- Add temporary re-export “facades” so existing imports still resolve during the move.

### Phase 2 — Move WASM crates to `sdk/wasm`
- Move:
  - `sdk/src/wasm_near_signer` → `sdk/wasm/near_signer`
  - `sdk/src/wasm_eth_signer` → `sdk/wasm/eth_signer`
  - `sdk/src/wasm_tempo_signer` → `sdk/wasm/tempo_signer`
- Update all relative imports from TS to new locations.
- Update scripts and bundler to copy:
  - `near_signer.wasm`, `eth_signer.wasm`, `tempo_signer.wasm` into `dist/workers/`.

### Phase 3 — Move shared code to `sdk/shared`
- Move cross-platform utilities and types first (lowest risk), for example:
  - `utils/` (base64/bytes/errors/validation)
  - shared request/response type definitions
- Update imports to reference `shared` (via TS paths or explicit relative imports).

### Phase 4 — Move client code to `sdk/client`
- Move:
  - wallet iframe runtime + SecureConfirm + multichain orchestration + workers
  - react + plugins (or keep them under `client/src/app/*`)
- Ensure worker entrypoints live under `client/src/workers/*` and bundling scripts point there.

### Phase 5 — Move server code to `sdk/server`
- Move:
  - `sdk/src/server/*` → `sdk/server/src/*`
  - threshold service code under `server/src/threshold/*`
  - auth providers under `server/src/auth/*`
- Keep both express + cloudflare route wiring under `server/src/router/*`.

### Phase 6 — Remove old `sdk/src` (except façade if desired)
- Delete/migrate remaining files.
- Clean up aliases and path mapping.
- Update docs references (paths) and example imports.

---

## Testing and validation
- `pnpm -C sdk build` (dev build)
- `pnpm -C sdk test:unit`
- Add/keep at least one e2e smoke test that exercises:
  - worker loading (near/eth/tempo wasm)
  - threshold-ed25519 signing path

---

## Risks and edge cases
- Path alias churn: `@/*` and other implicit aliases can cause subtle runtime-only failures.
- Worker URL resolution: ensure `resolveWorkerUrl` and wasm loader keep working after entrypoints move.
- Mixed environment imports: prevent server code from importing DOM APIs and client code from importing Node-only modules (project references help).
- WASM packaging: make sure wasm binaries are still emitted/copied where the wallet origin expects them (`/sdk/workers/*`).

