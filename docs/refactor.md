# Signing Structure Refactor Plan

Last updated: 2026-02-11

## Goal

Refactor signing-related code into a clear hierarchical structure where folder boundaries reflect ownership and dependency direction, while keeping behavior stable during migration.

Target structure:

```txt
client/src/core/signing/
  api/
    WebAuthnManager.ts
  chainAdaptors/
    near/
    tempo/
    evm/
  engines/
    secp256k1.ts
    webauthnP256.ts
  threshold/
    crypto/
    ports/
    session/
    workflows/
  webauthn/
    credentials/
    prompt/
    device/
    cose/
    fallbacks/
  secureConfirm/
    manager/
    flow/
    ui/
  workers/
```

## Why This Refactor

Current issues:

- Cross-tree dependency cycle:
  - `signing/multichain/*` imports `WebAuthnManager/*`
  - `WebAuthnManager/*` imports `signing/multichain/*`
- Overlapping utilities in multiple places (credential collection, PRF extraction, device resolution).
- Large mixed-responsibility files (notably `WebAuthnManager/index.ts`) that combine API facade, orchestration, flows, and infra concerns.
- Folder hierarchy does not consistently signal parent/child ownership.

## Scope

In scope:

- Folder/module reorganization under `client/src/core/signing`.
- Import direction cleanup and cycle removal.
- Compatibility shims for staged migration.

Out of scope:

- Protocol behavior changes.
- API behavior changes for SDK consumers (except import paths during migration windows).
- Feature rewrites unrelated to structure.

## Implementation Progress (Current Branch)

Completed so far:

- Canonical WebAuthn utility modules introduced under:
  - `signing/webauthn/credentials/*`
  - `signing/webauthn/device/*`
  - `signing/webauthn/cose/*`
- Legacy WebAuthnManager/threshold callsites updated to use canonical WebAuthn helpers.
- `signing/engines/*` and `signing/workers/signerWorkerManager/backends/multichainWorkerBackend.ts` added.
- `signing/chainAdaptors/{near,tempo,evm}/*` is now canonical implementation (including NEAR handlers, Tempo adapter/wasm, and EVM helpers/wasm).
- `signing/chainAdaptors/orchestrator.ts` and `signing/chainAdaptors/types.ts` are canonical.
- `signing/threshold/**` is now canonical implementation for threshold crypto/ports/session/workflows/validation.
- Core/runtime/test callsites were repointed from `signing/schemes/threshold/*` to `signing/threshold/*`.
- `signing/api/WebAuthnManager.ts` now hosts the `WebAuthnManager` implementation.
- Root SDK export now points to the facade path.
- `signing/secureConfirm/*` namespace now hosts the active SecureConfirm implementation:
  - moved code under `signing/secureConfirm/{confirmTxFlow,handlers,index.ts,secureConfirmBridge.ts}`
  - added `signing/secureConfirm/ui/*` canonical modules for shared UI tags/events/ensure-defined/types
  - switched worker/runtime callsites to import from `signing/secureConfirm/*`
- Compatibility shim trees removed:
  - `client/src/core/signing/multichain/**`
  - `client/src/core/signing/schemes/threshold/**`
  - `client/src/core/WebAuthnManager/SignerWorkerManager/**`
  - `client/src/core/WebAuthnManager/SecureConfirmWorkerManager/**`
  - `client/src/core/WebAuthnManager/WebAuthnFallbacks/**`
  - `client/src/core/WebAuthnManager/{index.ts,credentialsHelpers.ts,touchIdPrompt.ts,userPreferences.ts,collectAuthenticationCredentialForChallengeB64u.ts}`
- Dead/deprecated files removed:
  - `WebAuthnManager/SignerWorkerManager/thresholdSessionHelpers.ts`
  - `WebAuthnManager/userHandle.ts`
  - `signing/secureConfirm/ui/lit-components/ExportPrivateKey/index.ts`
  - `signing/secureConfirm/ui/lit-components/IframeTxConfirmer/index.ts`

Validation run:

- `pnpm -C sdk build` passes.
- `pnpm exec tsc --noEmit -p sdk/tsconfig.build.json` passes.
- `pnpm exec tsc -p client/tsconfig.json --noEmit` still fails due pre-existing workspace TS/JSX/type dependency issues unrelated to this refactor slice.

## Dependency Rules (Target State)

Hard rules:

1. `signing/api/*` is the composition root and may depend on lower layers.
2. `signing/chainAdaptors/*` may depend on `engines`, `threshold`, `webauthn`, `secureConfirm`, `workers`, shared core types.
3. `signing/engines/*` must not depend on `api` or chain handlers.
4. `signing/threshold/*` must not depend on `api` or chain handlers.
5. `signing/webauthn/*` must not depend on `api` or chain handlers.
6. `signing/secureConfirm/*` may depend on `webauthn`, `workers`, and core infra; not on `api`.
7. No module under `client/src/core/signing/**` may import from `client/src/core/WebAuthnManager/**` after migration.

## High-Level Mapping

### Move from `signing/multichain`

- `client/src/core/signing/multichain/near/**` -> `client/src/core/signing/chainAdaptors/near/**`
- `client/src/core/signing/multichain/tempo/**` -> `client/src/core/signing/chainAdaptors/tempo/**`
- `client/src/core/signing/multichain/evm/**` -> `client/src/core/signing/chainAdaptors/evm/**`
- `client/src/core/signing/multichain/engines/*` -> `client/src/core/signing/engines/*`
- `client/src/core/signing/multichain/webauthn/coseP256.ts` -> `client/src/core/signing/webauthn/cose/coseP256.ts`
- `client/src/core/signing/multichain/wasmWorkers/workerRpc.ts` -> `client/src/core/signing/workers/signerWorkerManager/backends/multichainWorkerBackend.ts`
- `client/src/core/signing/multichain/shared/orchestrator.ts` -> `client/src/core/signing/chainAdaptors/orchestrator.ts`
- `client/src/core/signing/multichain/shared/types.ts` -> `client/src/core/signing/chainAdaptors/types.ts`

### Move from `WebAuthnManager`

- `client/src/core/WebAuthnManager/collectAuthenticationCredentialForChallengeB64u.ts` -> `client/src/core/signing/webauthn/credentials/collectAuthenticationCredentialForChallengeB64u.ts`
- `client/src/core/WebAuthnManager/SignerWorkerManager/getDeviceNumber.ts` -> `client/src/core/signing/webauthn/device/getDeviceNumber.ts`
- `client/src/core/WebAuthnManager/touchIdPrompt.ts` -> `client/src/core/signing/webauthn/prompt/touchIdPrompt.ts`
- `client/src/core/WebAuthnManager/WebAuthnFallbacks/**` -> `client/src/core/signing/webauthn/fallbacks/**`
- `client/src/core/WebAuthnManager/SecureConfirmWorkerManager/**` -> `client/src/core/signing/secureConfirm/{manager,flow,ui}/**`
- `client/src/core/WebAuthnManager/index.ts` -> split into:
  - `client/src/core/signing/api/WebAuthnManager.ts` (public facade only)
  - internal orchestration modules under `signing/chainAdaptors`, `signing/threshold`, `signing/secureConfirm`, `signing/webauthn`

### Threshold namespace normalization

- `client/src/core/signing/schemes/threshold/**` -> `client/src/core/signing/threshold/**`

## Phased Execution Plan

### Phase 0: Baseline + Safety Rails

- [x] Capture baseline commands and results:
  - `pnpm -C sdk build`
  - repo typecheck/test commands currently used in CI
- [ ] Record current import-cycle baseline for `signing/*` and `WebAuthnManager/*`.
- [ ] Add a temporary refactor tracking checklist in PR descriptions.

Deliverable:

- A known-good baseline commit and command log for regression comparison.

### Phase 1: Create New Skeleton + Compatibility Entry Points

- [x] Create target directories under `client/src/core/signing/*`.
- [x] Add lightweight `index.ts` files for stable imports.
- [x] Keep old paths active with temporary re-export wrappers where needed.

Deliverable:

- New folder tree exists; no runtime behavior change.

### Phase 2: Extract Shared WebAuthn Primitives First

- [x] Move credential collection to `signing/webauthn/credentials`.
- [x] Move device helpers to `signing/webauthn/device`.
- [x] Move COSE parser to `signing/webauthn/cose`.
- [x] Replace duplicate implementations with single-source utilities.
- [x] Update imports from:
  - `WebAuthnManager/collectAuthenticationCredentialForChallengeB64u.ts`
  - `signing/schemes/threshold/ports/webauthn.ts`
  - `signing/multichain/near/handlers/*`

Deliverable:

- One canonical implementation per shared primitive.

### Phase 3: Move SecureConfirm into `signing/secureConfirm`

- [x] Move `SecureConfirmWorkerManager/**` to `signing/secureConfirm/{manager,flow,ui}`.
- [x] Update all consumers to import from the new namespace.
- [x] Preserve existing runtime behavior and worker protocol.

Deliverable:

- SecureConfirm logic is under signing hierarchy, not WebAuthnManager hierarchy.

### Phase 4: Move Multichain to `signing/chainAdaptors` + `signing/engines` + `signing/workers`

- [x] Move `multichain/near|tempo|evm` to `chainAdaptors/*`.
- [x] Move `multichain/engines/*` to `engines/*`.
- [x] Move `multichain/wasmWorkers/*` to `workers/*`.
- [x] Rename imports in orchestrators and handlers.

Deliverable:

- Chain-specific code is grouped by chain under a single hierarchy.

### Phase 5: Normalize Threshold Namespace

- [x] Move `signing/schemes/threshold/**` to `signing/threshold/**`.
- [x] Update imports in WebAuthn flows, chain handlers, and API entrypoints.
- [x] Remove temporary `signing/schemes/threshold/*` re-export shims after callsite migration.

Deliverable:

- Threshold code has one canonical root (`signing/threshold/*`).

### Phase 6: Introduce Thin API Facade

- [x] Create `client/src/core/signing/api/WebAuthnManager.ts` as the API entrypoint (implementation currently moved here).
- [ ] Move orchestration internals out of old monolith into domain modules.
- [x] Remove compatibility facade `client/src/core/WebAuthnManager/index.ts` after internal/test migration.
- [ ] Keep class and method signatures stable for consumers.

Deliverable:

- Public API remains stable; implementation lives in hierarchical signing modules.

### Phase 7: Remove Old Paths + Enforce Rules

- [x] Remove temporary re-export wrappers for chain/threshold/worker/fallback shims.
- [x] Delete obsolete folders under:
  - `client/src/core/signing/multichain`
  - `client/src/core/signing/schemes/threshold`
  - `client/src/core/WebAuthnManager/{SignerWorkerManager,SecureConfirmWorkerManager,WebAuthnFallbacks}`
- [ ] Finish `signing/secureConfirm/ui/lit-components -> signing/secureConfirm/ui` migration and remove remaining wrappers.
- [ ] Add lint/check rules to prevent forbidden imports:
  - no `signing/**` -> `WebAuthnManager/**`
  - no cyclic imports between `api` and lower layers

Deliverable:

- Final tree matches target hierarchy with enforced import boundaries.

## Suggested PR Breakdown

1. PR-1: Skeleton + shims.
2. PR-2: WebAuthn primitive extraction/dedup.
3. PR-3: SecureConfirm migration.
4. PR-4: Chains/engines/workers migration.
5. PR-5: Threshold namespace move.
6. PR-6: API facade split from monolith.
7. PR-7: Remove shims + add boundary enforcement.

## Verification Checklist Per PR

- [x] `pnpm -C sdk build` passes.
- [ ] Typecheck passes for client and sdk workspaces.
- [ ] Existing signing flows smoke-tested:
  - transaction signing
  - delegate signing
  - NEP-413 signing
  - Tempo signing
- [ ] No new imports from `client/src/core/WebAuthnManager/**` inside `client/src/core/signing/**`.
- [ ] No duplicated utility implementations remain for moved primitives.

## Acceptance Criteria

- Folder hierarchy under `client/src/core/signing/*` matches target structure.
- Import direction is acyclic and follows the dependency rules above.
- `WebAuthnManager` public surface remains compatible.
- Signing behavior is unchanged from baseline.

## WebAuthnManager Prune Sweep

This section is the explicit cleanup plan to prevent deprecated skeleton files/functions from being left behind.

Sweep method:

- TypeScript import graph over `client/tsconfig.json`.
- Manual verification of build-script and rollup entrypoints.
- Duplicate-function scan across `client/src/core/WebAuthnManager` and `client/src/core/signing`.

### Findings Summary

- `WebAuthnManager` subtree has 89 files total (72 TypeScript source files).
- 6 TypeScript files have zero inbound imports in the TS graph.
- Several utility functions are duplicated across `WebAuthnManager` and `signing/schemes/threshold`.
- Some files are intentionally zero-import (build entrypoints/type-level guards) and must not be auto-deleted.

### Prune Matrix

Delete (safe now):

- `client/src/core/WebAuthnManager/SignerWorkerManager/thresholdSessionHelpers.ts`
  - Empty file (0 bytes), zero inbound refs.
- `client/src/core/WebAuthnManager/userHandle.ts`
  - `parseAccountIdFromUserHandle` is not referenced anywhere in repo.
- `client/src/core/signing/secureConfirm/ui/lit-components/ExportPrivateKey/index.ts`
  - Unused barrel file, zero inbound refs.
- `client/src/core/signing/secureConfirm/ui/lit-components/IframeTxConfirmer/index.ts`
  - Unused barrel file, zero inbound refs.

Do not delete (intentional zero-import files):

- `client/src/core/signing/secureConfirm/ui/lit-components/ExportPrivateKey/iframe-export-bootstrap-script.ts`
  - Built directly by SDK build pipeline (`sdk/scripts/build-dev.sh`, `sdk/scripts/build-prod.sh`, `sdk/rolldown.config.ts`).
- `client/src/core/WebAuthnManager/SecureConfirmWorkerManager/confirmTxFlow/forbiddenMainThreadSecrets.typecheck.ts`
  - Type-level regression guard compiled by TS; keep (or move to dedicated typecheck test folder, but preserve coverage).

Reduce public surface (remove redundant exports, keep internals private):

- `client/src/core/WebAuthnManager/credentialsHelpers.ts`
  - `normalizeAuthenticationCredential` is currently unused; delete or make internal if no external contract requires it.
- `client/src/core/WebAuthnManager/touchIdPrompt.ts`
  - `generateDeviceSpecificUserId` is only used internally in the same file; remove `export`.
  - `RegisterCredentialsArgs` and `AuthenticateCredentialsForChallengeB64uArgs` are not imported externally; keep internal unless part of documented API.

### Duplicate Functions to Consolidate

Canonical module target for all WebAuthn primitives:

- `client/src/core/signing/webauthn/credentials/*`
- `client/src/core/signing/webauthn/device/*`
- `client/src/core/signing/webauthn/cose/*`

Consolidate these duplicates:

1. Credential collection helper
- Duplicate implementations:
  - `client/src/core/WebAuthnManager/collectAuthenticationCredentialForChallengeB64u.ts`
  - `client/src/core/signing/schemes/threshold/ports/webauthn.ts` (`collectAuthenticationCredentialForChallengeB64u`)
- Action:
  - Keep one canonical implementation in `signing/webauthn/credentials`.
  - Remove the duplicate implementation file and replace with import/re-export during migration.

2. Allow-credentials mapping
- Duplicate implementations:
  - `client/src/core/WebAuthnManager/touchIdPrompt.ts` (`authenticatorsToAllowCredentials`)
  - `client/src/core/signing/schemes/threshold/ports/webauthn.ts` (local `authenticatorsToAllowCredentials`)
- Action:
  - Create one shared mapper util (e.g. `signing/webauthn/credentials/allowCredentials.ts`).

3. PRF extraction helpers
- Duplicate logic appears in:
  - `client/src/core/WebAuthnManager/index.ts` (`extractPrfFirstB64u`, `extractPrfSecondB64u`)
  - `client/src/core/signing/schemes/threshold/ports/webauthn.ts` (`getPrfFirstB64uFromCredential`)
  - NEAR handler-local helpers in `client/src/core/signing/multichain/near/handlers/*` (`getPrfResultsFromCredential`)
  - worker keyOps parsing PRF fields directly (`recoverKeypairFromPasskey.ts`, `deriveNearKeypairAndEncryptFromSerialized.ts`)
- Action:
  - Centralize PRF extraction in one utility module and replace all inline parsers.

4. Credential extension redaction
- Duplicate implementations:
  - `client/src/core/WebAuthnManager/credentialsHelpers.ts` (`removePrfOutputGuard`)
  - `client/src/core/signing/schemes/threshold/ports/webauthn.ts` (`redactCredentialExtensionOutputs`)
- Action:
  - Keep one canonical redaction function; keep old name only as temporary alias with deprecation comment.

### Transitional Files to Remove After Migration

- `client/src/core/signing/multichain/{near,tempo,evm,shared}/**`
  - removed.
- `client/src/core/signing/schemes/threshold/**`
  - removed.
- `client/src/core/WebAuthnManager/SecureConfirmWorkerManager/**`
  - removed.
- `client/src/core/WebAuthnManager/SecureConfirmWorkerManager/confirmTxFlow/flows/index.ts`
  - removed with the SecureConfirmWorkerManager shim tree.
- Backward-compatibility re-export comments/files:
  - `client/src/core/signing/secureConfirm/ui/confirm-ui.ts` (currently forwards to `signing/secureConfirm/ui/lit-components/confirm-ui.ts`)
  - `client/src/core/signing/secureConfirm/ui/export-private-key/iframe-host.ts` (currently forwards to legacy LitComponents module)
  - remove these after LitComponents migration is complete.

### Cleanup Phases (No Skeleton Left Behind)

Phase A (immediate pruning):

- [x] Delete empty/dead files listed in "Delete (safe now)".
- [ ] Convert intentional zero-import files to explicit allowlist in cleanup checklist.

Phase B (dedupe):

- [x] Introduce canonical WebAuthn utility modules under `signing/webauthn/*`.
- [x] Replace duplicate callsites and remove old implementations.

Phase C (deprecations + barrel cleanup):

- [ ] Remove redundant exports/functions after one release cycle (or immediately if not public).
- [ ] Delete transitional barrel files after direct-import migration.

Phase D (guardrails in CI):

- [ ] Add lint/import rule: forbid `client/src/core/signing/**` importing `client/src/core/WebAuthnManager/**`.
- [ ] Add a dead-file check (no zero-byte `.ts` files).
- [ ] Add an allowlist-based check for intentional entrypoint files that may have zero inbound imports.

Definition of done for prune:

- No empty placeholder files remain.
- Every remaining zero-import file is documented as intentional.
- No duplicate implementations remain for credential collection, PRF extraction, or redaction.
- Legacy compatibility barrels are removed or explicitly justified.
