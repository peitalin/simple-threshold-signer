# SDK Modularity + Lazy Signer Loading Plan

Last updated: 2026-02-09

## Goal

- Ensure chain/signature code paths (NEAR, Tempo, EVM, threshold ECDSA helpers) are only loaded when actually used.
- Keep existing behavior and public APIs stable while reducing frontend bundle weight and startup work.

## Current state (baseline)

- `TatchiPasskey` always constructs `WebAuthnManager`, which currently has static multichain imports.
- Multichain worker/WASM boot is already lazy at runtime (workers start on first request), but module-level imports are not fully lazy.
- `client/src/index.ts` currently re-exports the multichain scaffold directly, which can pull extra modules into some app bundles.

## Phase 1 — Define modular boundaries

- [ ] Finalize import surface policy:
  - default `@tatchi-xyz/sdk` export stays NEAR-first/minimal
  - multichain moves behind explicit subpath import(s)
- [ ] Document supported entrypoints and intended usage:
  - high-level API users
  - advanced multichain engine users
- [x] Add/confirm subpath export map for modular consumption (e.g. `./multichain`, `./tempo`, `./near`) with stable typing.

## Phase 2 — Convert static signer wiring to lazy modules

- [x] Refactor `WebAuthnManager` multichain imports to `await import(...)` at call sites:
  - Tempo signing path
  - threshold ECDSA coordinator path
  - optional local secp256k1 helpers
- [x] Keep type-only imports (`import type`) where possible so runtime chunks are not eagerly loaded.
- [x] Preserve existing method signatures and error messages for backward compatibility.

## Phase 3 — Make prewarm behavior feature-aware

- [x] Keep NEAR signer worker prewarm for default flows.
- [x] Do not prewarm Tempo/EVM workers unless feature is explicitly enabled or invoked.
- [ ] Add config gates for optional eager warmup per signer kind (off by default).

## Phase 4 — Entry-point cleanup for tree-shaking

- [ ] Remove/limit eager top-level re-exports that force multichain code into default bundles.
- [ ] Ensure re-export files are split by feature area and avoid accidental barrel-import coupling.
- [ ] Verify side-effect-free module boundaries for multichain engine files.

## Phase 5 — Validation + CI guardrails

- [x] Add focused tests for lazy behavior:
  - Tempo code path loads only when `signTempo*` is called
  - NEAR-only usage does not instantiate Tempo/EVM workers
  - coverage added in `tests/unit/modularity.lazySigners.unit.test.ts`
- [ ] Add bundle-size regression checks:
  - baseline (`@tatchi-xyz/sdk` core only)
  - with multichain entrypoints enabled
- [ ] Add smoke tests for subpath imports in Vite/Next sample setups.

## Acceptance criteria

- [ ] NEAR-only apps can use `TatchiPasskey` without loading Tempo/EVM signer modules upfront.
- [ ] Tempo/EVM signer code is fetched/initialized only on first actual use.
- [ ] Existing public APIs continue to work without breaking changes.
- [ ] Bundle-size report shows measurable reduction for NEAR-only path.

## Risks and mitigations

- [ ] Risk: accidental behavior regressions during import refactors.
  - Mitigation: snapshot existing error contracts and keep compatibility tests.
- [ ] Risk: dynamic import path issues in iframe/cross-origin hosting.
  - Mitigation: add wallet-iframe e2e coverage for modular chunks.
- [ ] Risk: consumers relying on implicit barrel exports.
  - Mitigation: document migration path and keep temporary compatibility re-exports for one release.
