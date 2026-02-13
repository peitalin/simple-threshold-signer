# DB Refactor Plan (IndexedDBManager)

This document defines the implementation plan for refactoring:

- `client/src/core/IndexedDBManager/index.ts`
- `client/src/core/IndexedDBManager/passkeyClientDB.ts`
- `client/src/core/IndexedDBManager/passkeyNearKeysDB.ts`

Primary goal: reduce file complexity and clarify ownership boundaries without changing runtime behavior.

Refactor guardrail: no behavior changes allowed.

## Scope

- Keep existing DB schemas and migration semantics intact.
- Keep public API compatibility for current internal callers.
- Refactor by extraction/splitting and import rewiring only.

## Out of Scope

- New product features.
- Schema redesign.
- Changing signer business logic semantics.

## Target Structure

Proposed module breakdown:

- `client/src/core/IndexedDBManager/index.ts`
  - Barrel exports only.
- `client/src/core/IndexedDBManager/unifiedIndexedDBManager.ts`
  - `UnifiedIndexedDBManager` runtime façade and orchestration.
- `client/src/core/IndexedDBManager/passkeyClientDB/`
  - `types.ts`
  - `constants.ts`
  - `schema.ts`
  - `migrations.ts`
  - `invariants.ts`
  - `nearCompat.ts`
  - `outbox.ts`
  - `manager.ts` (composition layer)
- `client/src/core/IndexedDBManager/passkeyNearKeysDB/`
  - `types.ts`
  - `schema.ts`
  - `envelope.ts`
  - `manager.ts`

Current incremental step (landed):

- `client/src/core/IndexedDBManager/passkeyClientDB.types.ts`
- `client/src/core/IndexedDBManager/passkeyNearKeysDB.types.ts`
- `client/src/core/IndexedDBManager/passkeyClientDB/manager.ts`
- `client/src/core/IndexedDBManager/passkeyClientDB/schema.ts`
- `client/src/core/IndexedDBManager/passkeyClientDB/outbox.ts`
- `client/src/core/IndexedDBManager/passkeyClientDB/nearCompat.ts`
- `client/src/core/IndexedDBManager/passkeyClientDB/migrations.ts`
- `client/src/core/IndexedDBManager/passkeyClientDB/invariants.ts`
- `client/src/core/IndexedDBManager/passkeyNearKeysDB/manager.ts`
- `client/src/core/IndexedDBManager/passkeyNearKeysDB/schema.ts`
- `client/src/core/IndexedDBManager/passkeyNearKeysDB/envelope.ts`
- `client/src/core/IndexedDBManager/passkeyClientDB.ts` (compat entrypoint re-exporting manager + types)
- `client/src/core/IndexedDBManager/passkeyNearKeysDB.ts` (compat entrypoint re-exporting manager + types)

## Phased TODO Checklist

### Phase 0 - Baseline and safety rails

- [x] Capture baseline behavior with current DB-focused unit tests.
- [x] Record current public exports from `IndexedDBManager/index.ts`.
- [x] Add a short refactor guard note in this doc: "no behavior changes allowed".
- [ ] Ensure `pnpm -s type-check:sdk` passes before each phase branch merge.
  - Current status: blocked by existing unrelated test import errors in `tests/unit/thresholdEcdsa.tempoHighLevel.unit.test.ts`.

### Phase 1 - Type extraction (no logic moves)

- [x] Move exported types/interfaces from `passkeyClientDB.ts` into dedicated types module.
  - Implemented at `client/src/core/IndexedDBManager/passkeyClientDB.types.ts`.
- [x] Move exported types/interfaces from `passkeyNearKeysDB.ts` into dedicated types module.
  - Implemented at `client/src/core/IndexedDBManager/passkeyNearKeysDB.types.ts`.
- [x] Re-export all moved types through existing file entry points.
- [x] Verify no import path breakage in SDK/tests.

### Phase 2 - `index.ts` cleanup

- [x] Extract `UnifiedIndexedDBManager` into `unifiedIndexedDBManager.ts`.
- [x] Keep `index.ts` as a thin barrel + singleton wiring only.
- [x] Preserve `passkeyClientDB`, `passkeyNearKeysDB`, and `IndexedDBManager` export names.
- [x] Keep `configureIndexedDB` behavior unchanged.

### Phase 3 - `passkeyClientDB` decomposition

- [x] Extract DB/open/schema constants and upgrade wiring into `passkeyClientDB/schema.ts`.
- [x] Extract migration runner + checkpoints into `passkeyClientDB/migrations.ts`.
- [x] Extract invariant validation/quarantine logic into `passkeyClientDB/invariants.ts`.
- [x] Extract NEAR compatibility projection helpers into `passkeyClientDB/nearCompat.ts`.
- [x] Extract outbox APIs and helpers into `passkeyClientDB/outbox.ts`.
- [x] Keep `PasskeyClientDBManager` in `passkeyClientDB/manager.ts` as orchestrator.

### Phase 4 - `passkeyNearKeysDB` decomposition

- [x] Extract envelope/aad normalization and payload transformations into `passkeyNearKeysDB/envelope.ts`.
- [x] Extract schema/openDB setup into `passkeyNearKeysDB/schema.ts`.
- [x] Keep CRUD and public manager API in `passkeyNearKeysDB/manager.ts`.
- [x] Preserve legacy-store-drop behavior (`keyMaterial` deletion) in upgrade path.

### Phase 5 - Query/index hardening

- [x] Add composite outbox index for due-ops query (`status + nextAttemptAt`).
- [x] Add derived-address lookup index to remove in-memory filtering hot path.
- [x] Update query call sites to use new indexes directly.
- [x] Add tests proving equivalent results before/after index/query rewrites.
  - Implemented indexes:
    - `signerOpsOutbox.status_nextAttemptAt`
    - `derivedAddressesV2.profileId_sourceChainId_sourceAccountAddress_providerRef_path`

### Phase 6 - Final polish and cleanup

- [x] Remove dead internal helpers left after extraction.
  - Removed extraction pass-through wrappers from `passkeyClientDB/manager.ts` and wired call sites directly to `nearCompat` helpers.
- [x] Normalize file-level comments and module headers.
  - Normalized section headers in `passkeyClientDB/manager.ts` to a consistent style.
- [x] Update docs linking from `docs/db-multichain-schema.md` to this refactor plan.
- [x] Publish final "before/after" module map in this file.

## Validation Matrix (run each phase)

- [ ] `pnpm -s type-check:sdk`
  - Current status: fails on unrelated existing `viem` exports in `tests/unit/thresholdEcdsa.tempoHighLevel.unit.test.ts`.
- [x] `pnpm -C tests exec playwright test ./unit/dbMultichain.migrationAndSaga.unit.test.ts --reporter=line`
- [x] `pnpm -C tests exec playwright test ./unit/linkDevice.immediateSign.test.ts --reporter=line`

## Current Export Snapshot

`IndexedDBManager/index.ts` currently exports:

- `PasskeyClientDBManager`
- `DBConstraintError`
- `PasskeyNearKeysDBManager`
- `UnifiedIndexedDBManager`
- `passkeyClientDB`
- `passkeyNearKeysDB`
- `configureIndexedDB`
- `getIndexedDBNames`
- `IndexedDBManager`

## Exit Criteria

- [x] `index.ts` is barrel-oriented and no longer hosts large runtime logic blocks.
- [ ] `passkeyClientDB` and `passkeyNearKeysDB` each have clear module boundaries.
- [ ] No DB migration behavior regressions.
- [ ] Public API surface remains backward compatible for current SDK consumers.

## Before/After Module Map

Before (monolithic):
- `client/src/core/IndexedDBManager/index.ts`
  - Exports + singleton wiring + unified runtime logic.
- `client/src/core/IndexedDBManager/passkeyClientDB.ts`
  - Schema, migrations, invariants, NEAR compat projection, outbox, CRUD.
- `client/src/core/IndexedDBManager/passkeyNearKeysDB.ts`
  - Schema, upgrade, envelope normalization, CRUD.

After (decomposed):
- `client/src/core/IndexedDBManager/index.ts`
  - Barrel + singleton configuration/runtime entrypoints.
- `client/src/core/IndexedDBManager/unifiedIndexedDBManager.ts`
  - Unified façade and cross-DB orchestration.
- `client/src/core/IndexedDBManager/singletons.ts`
  - Shared singleton instances.
- `client/src/core/IndexedDBManager/passkeyClientDB.ts`
  - Compatibility entrypoint (manager + types exports).
- `client/src/core/IndexedDBManager/passkeyClientDB/manager.ts`
  - Composition/orchestration for DB APIs.
- `client/src/core/IndexedDBManager/passkeyClientDB/schema.ts`
  - DB config, stores, indexes, upgrade wiring.
- `client/src/core/IndexedDBManager/passkeyClientDB/migrations.ts`
  - Migration runner/checkpoints.
- `client/src/core/IndexedDBManager/passkeyClientDB/invariants.ts`
  - Invariant validation + quarantine.
- `client/src/core/IndexedDBManager/passkeyClientDB/nearCompat.ts`
  - NEAR compatibility parsing/projection/backfill helpers.
- `client/src/core/IndexedDBManager/passkeyClientDB/profileCleanup.ts`
  - Profile-scoped deletion helper for V2 stores.
- `client/src/core/IndexedDBManager/passkeyClientDB/outbox.ts`
  - Outbox creation/query/status helpers.
- `client/src/core/IndexedDBManager/passkeyNearKeysDB.ts`
  - Compatibility entrypoint (manager + types exports).
- `client/src/core/IndexedDBManager/passkeyNearKeysDB/manager.ts`
  - CRUD/public manager API.
- `client/src/core/IndexedDBManager/passkeyNearKeysDB/schema.ts`
  - DB config + upgrade wiring.
- `client/src/core/IndexedDBManager/passkeyNearKeysDB/envelope.ts`
  - Envelope/aad normalization + payload transforms.
