# Signing Structure Refactor Plan

Last updated: 2026-02-15

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
- Extracted smart-account deployment + threshold-ECDSA bootstrap persistence helpers from `WebAuthnManager` into:
  - `signing/api/smartAccountDeployment.ts`
  - `signing/api/thresholdEcdsaBootstrapPersistence.ts`
- Extracted threshold-ed25519 lifecycle helpers from `WebAuthnManager` into:
  - `signing/api/thresholdEd25519Lifecycle.ts`
  - moved derive/enroll/rotate orchestration into the helper and kept `WebAuthnManager` methods as delegators.
- Extracted NEAR signing API helpers from `WebAuthnManager` into:
  - `signing/api/nearSigning.ts`
  - moved `signTransactionsWithActions`, `signDelegateAction`, and `signNEP413Message` orchestration into the helper and kept facade methods as delegators.
- Extracted Tempo signing API helper from `WebAuthnManager` into:
  - `signing/api/tempoSigning.ts`
  - moved `signTempo` orchestration into the helper and kept facade methods as delegators.
- Extracted private-key export/recovery API helpers from `WebAuthnManager` into:
  - `signing/api/privateKeyExportRecovery.ts`
  - moved export/recovery orchestration (`exportNearKeypairWithUI*`, `exportPrivateKeysWithUI*`, `recoverKeypairFromPasskey`) into the helper and kept facade methods as delegators.
- Extracted NEAR key-derivation workflow helpers from `WebAuthnManager` into:
  - `signing/api/nearKeyDerivation.ts`
  - moved `deriveNearKeypairAndEncryptFromSerialized` and `deriveNearKeypairFromCredentialViaWorker` orchestration into the helper and kept facade methods as delegators.
- Extracted registration/account-lifecycle helpers from `WebAuthnManager` into:
  - `signing/api/registrationAccountLifecycle.ts`
  - moved registration persistence and current-user initialization orchestration into the helper and kept facade methods as delegators.
- Extracted registration-confirmation/session helpers from `WebAuthnManager` into:
  - `signing/api/registrationSession.ts`
  - moved registration confirmation and WebAuthn authentication-credential collection helpers into the module and kept facade methods as delegators.
- Extracted worker/resource warmup helpers from `WebAuthnManager` into:
  - `signing/api/workerResourceWarmup.ts`
  - moved worker prewarm + critical-resource warmup orchestration into the module and kept facade methods as delegators.
- Extracted signing-session policy/state helpers from `WebAuthnManager` into:
  - `signing/api/signingSessionState.ts`
  - moved session id generation, policy resolution, active-session management, and warm-session status lookup into the module and kept facade methods as delegators.
- Extracted threshold-session/activation orchestration helpers from `WebAuthnManager` into:
  - `signing/api/thresholdSessionActivation.ts`
  - moved threshold-ed25519 session-connect and threshold-ecdsa bootstrap orchestration into the module and kept facade methods as delegators.
- Extracted IndexedDB profile/account/signer-outbox facade helpers from `WebAuthnManager` into:
  - `signing/api/indexedDbFacade.ts`
  - moved profile/account/signer-outbox and core user/authenticator read/write wrapper methods into the module and kept facade methods as delegators.
- Extracted signer-worker bridge helpers from `WebAuthnManager` into:
  - `signing/api/signerWorkerBridge.ts`
  - moved `signNearWithIntent`, `extractCosePublicKey`, and `signTransactionWithKeyPair` bridge logic into the module and kept facade methods as delegators.
- Extracted user-preferences/theme/rpId facade helpers from `WebAuthnManager` into:
  - `signing/api/facadeSettings.ts`
  - moved facade surface helpers for rpId/theme/user-preferences lifecycle (`getRpId`, `setTheme`, `getTheme`, `getUserPreferences`, `destroy`) into the module and kept class methods as delegators.
- Extracted facade-only convenience wrapper helpers from `WebAuthnManager` into:
  - `signing/api/facadeConvenience.ts`
  - moved facade convenience wrappers (`signTempoWithThresholdEcdsa`, warmup/session-introspection surface delegation) into the module and kept class methods as delegators.
- Extracted constructor/runtime bootstrap helpers from `WebAuthnManager` into:
  - `signing/api/runtimeBootstrap.ts`
  - moved worker base-origin initialization/watchers and app-origin preference-init gating into the module.
- Consolidated facade dependency wiring through shared factory helpers:
  - `signing/api/facadeDependencyFactory.ts`
  - centralized creation of facade settings/convenience dependency objects to reduce inline dependency wiring in the API class.
- Consolidated orchestration dependency wiring through a dedicated bundle factory:
  - `signing/api/orchestrationDependencyFactory.ts`
  - moved non-facade dependency composition out of `WebAuthnManager`, removed low-value `get*Deps` methods, and rewired API delegators to use the shared bundle.
- Pruned compatibility aliases from `signing/webauthn/prompt/touchIdPrompt.ts` and moved callsites to canonical credential helpers/types:
  - `TatchiPasskey/login.ts` now imports `authenticatorsToAllowCredentials` from `signing/webauthn/credentials`.
  - `signing/api/{WebAuthnManager,registrationSession}.ts` now use `WebAuthnAllowCredential` from `signing/webauthn/credentials`.
  - removed prompt-surface export for `TouchIdPrompt.attachPageAbortHandlers` and kept it as an internal helper.
- Pruned redundant threshold compatibility typing surface:
  - removed unused `ThresholdAllowCredential` alias from `signing/threshold/webauthn.ts`.
  - retained threshold WebAuthn port aliases still used by threshold/orchestration workflows.
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
- `pnpm -s check:signing-architecture` passes.
- `pnpm exec tsc --noEmit -p sdk/tsconfig.build.json` passes.
- `pnpm exec tsc --noEmit -p client/tsconfig.json` passes.
- `pnpm -C tests exec playwright test ./unit --reporter=line` passes (`160 passed`, `5 skipped`).
- `pnpm -C tests exec playwright test tests/e2e/executeAction.twice.walletIframe.test.ts tests/e2e/thresholdEd25519.delegateSigning.test.ts tests/e2e/thresholdEd25519.nep413Signing.test.ts tests/e2e/thresholdEcdsa.tempoSigning.test.ts --reporter=line` passes.
- `pnpm -C tests exec playwright test lit-components/confirm-ui.handle.test.ts lit-components/confirm-ui.host-and-inline.test.ts` passes.

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
- [x] Record current import-cycle baseline for `signing/*` and `WebAuthnManager/*`.
  - `pnpm -s check:signing-architecture` now runs `sdk/scripts/check-signing-api-cycles.mjs` (current result: no api/lower-layer cycles).
- [x] Add a temporary refactor tracking checklist in PR descriptions.
  - Added at `.github/pull_request_template.md`.

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
- [x] Move orchestration internals out of old monolith into domain modules.
  - Completed extractions include smart-account deployment, threshold-ECDSA bootstrap persistence, threshold-ed25519 lifecycle, NEAR signing API, Tempo signing API, private-key export/recovery, NEAR key-derivation, registration/account-lifecycle, registration-confirmation/session, worker/resource warmup, signing-session policy/state, threshold-session/activation, IndexedDB facade, signer-worker bridge, user-preferences/theme/rpId facade, facade-only convenience wrappers, constructor/runtime bootstrap, facade dependency-factory helpers, and orchestration dependency-bundle helpers.
- [x] Extract smart-account deployment and threshold-ECDSA bootstrap persistence helpers into dedicated `signing/api/*` modules.
- [x] Extract threshold-ed25519 lifecycle helpers into dedicated `signing/api/*` module.
- [x] Extract NEAR signing API helpers into dedicated `signing/api/*` module.
- [x] Extract Tempo signing API helper into dedicated `signing/api/*` module.
- [x] Extract private-key export/recovery helpers into dedicated `signing/api/*` module.
- [x] Extract NEAR key-derivation workflow helpers into dedicated `signing/api/*` module.
- [x] Extract registration/account-lifecycle helpers into dedicated `signing/api/*` module.
- [x] Extract registration-confirmation/session helpers into dedicated `signing/api/*` module.
- [x] Extract worker/resource warmup helpers into dedicated `signing/api/*` module.
- [x] Extract signing-session policy/state helpers into dedicated `signing/api/*` module.
- [x] Extract threshold-session/activation orchestration helpers into dedicated `signing/api/*` module.
- [x] Extract IndexedDB profile/account/signer-outbox facade helpers into dedicated `signing/api/*` module.
- [x] Extract signer-worker bridge helpers into dedicated `signing/api/*` module.
- [x] Extract user-preferences/theme/rpId facade helpers into dedicated `signing/api/*` module.
- [x] Extract facade-only convenience wrappers into dedicated `signing/api/*` module.
- [x] Extract constructor/runtime bootstrap helpers into dedicated `signing/api/*` module.
- [x] Consolidate facade dependency wiring through dedicated `signing/api/*` factory helpers.
- [x] Collapse low-value in-class `get*Deps` methods via a dedicated orchestration dependency-bundle factory (`signing/api/orchestrationDependencyFactory.ts`).
- [x] Remove compatibility facade `client/src/core/WebAuthnManager/index.ts` after internal/test migration.
- [x] Keep class and method signatures stable for consumers.

Deliverable:

- Public API remains stable; implementation lives in hierarchical signing modules.

### Phase 7: Remove Old Paths + Enforce Rules

- [x] Remove temporary re-export wrappers for chain/threshold/worker/fallback shims.
- [x] Delete obsolete folders under:
  - `client/src/core/signing/multichain`
  - `client/src/core/signing/schemes/threshold`
  - `client/src/core/WebAuthnManager/{SignerWorkerManager,SecureConfirmWorkerManager,WebAuthnFallbacks}`
- [x] Finish `signing/secureConfirm/ui/lit-components -> signing/secureConfirm/ui` migration and remove remaining wrappers.
- [x] Add lint/check rules to prevent forbidden imports:
  - no `signing/**` -> `WebAuthnManager/**`
  - no cyclic imports between `api` and lower layers
  - `pnpm -s check:signing-architecture` now enforces forbidden import boundaries, wrapper removal checks, and explicit `signing/api` cycle detection.

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
- [x] Typecheck passes for client and sdk workspaces.
  - `pnpm exec tsc --noEmit -p sdk/tsconfig.build.json` passes.
  - `pnpm exec tsc --noEmit -p client/tsconfig.json` passes.
- [x] Existing signing flows smoke-tested:
  - transaction signing (`tests/e2e/executeAction.twice.walletIframe.test.ts`)
  - delegate signing (`tests/e2e/thresholdEd25519.delegateSigning.test.ts`)
  - NEP-413 signing (`tests/e2e/thresholdEd25519.nep413Signing.test.ts`)
  - Tempo signing (`tests/e2e/thresholdEcdsa.tempoSigning.test.ts`)
  - Targeted SecureConfirm UI smoke tests pass (`lit-components/confirm-ui.handle.test.ts`, `lit-components/confirm-ui.host-and-inline.test.ts`).
- [x] Unit suite passes for refactor-aware wiring and contracts.
  - `pnpm -C tests exec playwright test ./unit --reporter=line` passes (`160 passed`, `5 skipped`).
- [x] No new imports from `client/src/core/WebAuthnManager/**` inside `client/src/core/signing/**`.
- [x] No duplicated utility implementations remain for moved primitives.

## API Compatibility Evidence (2026-02-15)

- Generated declaration surface exists at:
  - `sdk/dist/types/client/src/core/signing/api/WebAuthnManager.d.ts`
- Post-refactor signature parity check (`WebAuthnManager.ts` vs generated `.d.ts`) reports:
  - `src_count=55`
  - `dts_count=55`
  - `missing_in_dts`: none
  - `missing_in_src`: none

## Remaining Steps (2026-02-15 Review)

1. No blocking refactor steps remain for the current scope.
   - `WebAuthnManager` is now a public facade with delegators and no private orchestration helper methods.
   - Current size is ~0.97k lines after extracting orchestration dependency composition into `signing/api/orchestrationDependencyFactory.ts`.

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

- `client/src/core/WebAuthnManager` subtree has been removed.
- `client/src/core/signing/secureConfirm/ui/*` wrappers were migrated; top-level `ui` modules are now canonical.
- PRF extraction helper callsites now route through canonical WebAuthn credential extension helpers.
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
- `client/src/core/signing/secureConfirm/confirmTxFlow/forbiddenMainThreadSecrets.typecheck.ts`
  - Type-level regression guard compiled by TS; keep (or move to dedicated typecheck test folder, but preserve coverage).

Reduce public surface (remaining):

- `client/src/core/signing/api/WebAuthnManager.ts`
  - Orchestration dependency composition has been extracted to `signing/api/orchestrationDependencyFactory.ts`; remaining methods are primarily public facade delegators and can be pruned only where wrappers are non-public.
- `client/src/core/signing/webauthn/prompt/touchIdPrompt.ts`
  - Keep exports minimal and remove compatibility-only wrappers once callsites are migrated.

### Duplicate Functions to Consolidate (Current State)

Canonical module target for all WebAuthn primitives:

- `client/src/core/signing/webauthn/credentials/*`
- `client/src/core/signing/webauthn/device/*`
- `client/src/core/signing/webauthn/cose/*`

Resolved duplicates:

1. Credential collection helper
- Canonical implementation: `client/src/core/signing/webauthn/credentials/collectAuthenticationCredentialForChallengeB64u.ts`.

2. Allow-credentials mapping
- Canonical implementation: `client/src/core/signing/webauthn/credentials/collectAuthenticationCredentialForChallengeB64u.ts` (`authenticatorsToAllowCredentials`).

3. Credential extension redaction
- Canonical implementation: `client/src/core/signing/webauthn/credentials/credentialExtensions.ts` (`redactCredentialExtensionOutputs`).

4. PRF extraction helpers
- Canonical extraction now routes through `client/src/core/signing/webauthn/credentials/credentialExtensions.ts` from API callsites.

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
  - removed (`confirm-ui.ts` and `export-private-key/iframe-host.ts` are now canonical implementations).
  - `client/src/core/signing/secureConfirm/ui/iframe-host.ts` removed.

### Cleanup Phases (No Skeleton Left Behind)

Phase A (immediate pruning):

- [x] Delete empty/dead files listed in "Delete (safe now)".
- [x] Convert intentional zero-import files to explicit allowlist in cleanup checklist.

Phase B (dedupe):

- [x] Introduce canonical WebAuthn utility modules under `signing/webauthn/*`.
- [x] Replace duplicate callsites and remove old implementations.

Phase C (deprecations + barrel cleanup):

- [x] Remove redundant exports/functions after one release cycle (or immediately if not public).
- [x] Delete transitional barrel files after direct-import migration.

Phase D (guardrails in CI):

- [x] Add lint/import rule: forbid `client/src/core/signing/**` importing `client/src/core/WebAuthnManager/**`.
- [x] Add a dead-file check (no zero-byte `.ts` files).
- [x] Add an allowlist-based check for intentional entrypoint files that may have zero inbound imports.

Definition of done for prune:

- No empty placeholder files remain.
- Every remaining zero-import file is documented as intentional.
- No duplicate implementations remain for credential collection, PRF extraction, or redaction.
- Legacy compatibility barrels are removed or explicitly justified.
