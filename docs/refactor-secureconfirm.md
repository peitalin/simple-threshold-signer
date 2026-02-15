# SecureConfirm Flow Consolidation Plan

Status: Draft  
Last updated: 2026-02-12

## Objective

Reduce SecureConfirm file scattering and callback hopping by introducing a single flow entrypoint for callers and consolidating duplicate flow handlers.

Target outcomes:

- Fewer files involved in the common signing path.
- One obvious module to read for SecureConfirm signing orchestration.
- No behavior change in worker/main-thread handshake or signing results.

## Current Pain Points

- Common Tempo/EVM signing confirmation path jumps across multiple files:
  - `signTempoWithSecureConfirm.ts -> handlers/confirmAndPrepareSigningSession.ts -> secureConfirmBridge.ts -> confirmTxFlow/handleSecureConfirmRequest.ts -> confirmTxFlow/flows/*`.
- Similar logic is split between:
  - `confirmTxFlow/flows/transactions.ts`
  - `confirmTxFlow/flows/intentDigest.ts`
- Registration confirmation is split across:
  - `handlers/requestRegistrationCredentialConfirmation.ts`
  - `confirmTxFlow/flows/requestRegistrationCredentialConfirmation.ts`
- Callers import deep internals instead of one stable flow API.

## Scope

In scope:

- Consolidate SecureConfirm flow modules under a single `secureConfirm/flow/*` API.
- Merge overlapping flow handlers.
- Repoint callsites to the new flow facade.
- Remove stale wrappers after migration.

Out of scope:

- Protocol changes (request/response wire schema).
- UI visual redesign.
- Worker transport redesign.

## Constraints

- Preserve existing `SecureConfirmationType` contracts.
- Preserve `awaitSecureConfirmationV2` worker bridge behavior.
- Preserve warm-session vs webauthn behavior and error messages.
- Keep public SDK behavior stable.

## Target Structure

```txt
client/src/core/signing/secureConfirm/
  index.ts
  manager.ts

  flow/
    index.ts
    confirmSigningSession.ts
    requestRegistrationCredentialConfirmation.ts
    runSecureConfirmFlow.ts
    types.ts
    handlers/
      signing.ts
      registration.ts
      localOnly.ts

  confirmTxFlow/
    adapters/
      common.ts
      createAdapters.ts
      interfaces.ts
      near.ts
      requestAdapter.ts
      requestHelpers.ts
      session.ts
      ui.ts
      webauthn.ts
    awaitSecureConfirmation.ts
    determineConfirmationConfig.ts
    handleSecureConfirmRequest.ts
    types.ts

  ui/
    ...
```

Notes:

- `flow/*` is the only import surface for other signing modules.
- `confirmTxFlow/*` remains as internal runtime plumbing (worker handshake + adapters).

## Consolidation Map

### New canonical flow API

- `flow/confirmSigningSession.ts`:
  - owns logic currently in `handlers/confirmAndPrepareSigningSession.ts`.
- `flow/requestRegistrationCredentialConfirmation.ts`:
  - owns logic currently split between handler wrapper + flow helper.
- `flow/runSecureConfirmFlow.ts`:
  - wraps `runSecureConfirm(...)` for a single callsite.

### Merge flow handlers

- Merge:
  - `confirmTxFlow/flows/transactions.ts`
  - `confirmTxFlow/flows/intentDigest.ts`
  into:
  - `flow/handlers/signing.ts`.

- Keep registration and local-only as separate focused handlers:
  - `flow/handlers/registration.ts`
  - `flow/handlers/localOnly.ts`.

### Files expected to be removed (end state)

- `client/src/core/signing/secureConfirm/handlers/index.ts`
- `client/src/core/signing/secureConfirm/handlers/confirmAndPrepareSigningSession.ts`
- `client/src/core/signing/secureConfirm/handlers/requestRegistrationCredentialConfirmation.ts`
- `client/src/core/signing/secureConfirm/confirmTxFlow/flows/intentDigest.ts`
- `client/src/core/signing/secureConfirm/confirmTxFlow/flows/transactions.ts`
- `client/src/core/signing/secureConfirm/confirmTxFlow/flows/requestRegistrationCredentialConfirmation.ts`

## Phased Execution

### Phase 0: Baseline and Safety

- Capture baseline:
  - `pnpm -C sdk build`
  - `pnpm -C tests test:unit`
- Record current SecureConfirm-related failing tests (if any) before refactor.

Deliverable:

- Known baseline behavior and command results.

### Phase 1: Introduce Flow Facade (No Behavior Change)

- Add:
  - `secureConfirm/flow/index.ts`
  - `secureConfirm/flow/confirmSigningSession.ts`
  - `secureConfirm/flow/requestRegistrationCredentialConfirmation.ts`
  - `secureConfirm/flow/runSecureConfirmFlow.ts`
  - `secureConfirm/flow/types.ts`
- Initially delegate to existing implementations.

Deliverable:

- One stable import surface for SecureConfirm flow.

### Phase 2: Repoint Callers to Facade

- Update callsites in:
  - `chainAdaptors/tempo/*`
  - `chainAdaptors/near/*`
  - `secureConfirm/index.ts`
- Ensure external modules no longer import deep `confirmTxFlow/flows/*` or `secureConfirm/handlers/*`.

Deliverable:

- Caller path reduced to `caller -> secureConfirm/flow/*`.

### Phase 3: Merge Signing Flow Handlers

- Create `flow/handlers/signing.ts`.
- Move and merge logic from:
  - `confirmTxFlow/flows/transactions.ts`
  - `confirmTxFlow/flows/intentDigest.ts`
- Keep type-discriminated branching by `SecureConfirmationType`.

Deliverable:

- One file for signing confirmation logic.

### Phase 4: Consolidate Registration Flow

- Move registration request flow into:
  - `flow/requestRegistrationCredentialConfirmation.ts`
  - `flow/handlers/registration.ts`
- Remove old wrapper layer once imports are cut over.

Deliverable:

- Registration confirmation path uses the same facade pattern.

### Phase 5: Cleanup and Boundary Enforcement

- Delete stale wrapper/legacy files.
- Add or extend architecture checks to forbid:
  - imports from `secureConfirm/confirmTxFlow/flows/*` outside `secureConfirm/flow/*`.
  - imports from `secureConfirm/handlers/*` outside `secureConfirm/*`.
- Update docs (`docs/refactor.md`, `docs/crypto-in-wasm.md`) to reflect final ownership.

Deliverable:

- Consolidated structure with enforced boundaries.

## Validation Gates

- Build and type checks:
  - `pnpm -C sdk build`
  - `pnpm -C sdk type-check`
- Target tests:
  - `pnpm -C tests test:unit`
  - `pnpm -C tests exec playwright test ./unit/tempo.signingAuthMode.unit.test.ts --reporter=line`
  - `pnpm -C tests exec playwright test ./unit/signingPipeline.unified.unit.test.ts --reporter=line`
  - `pnpm -C tests exec playwright test ./unit/confirmTxFlow.successPaths.test.ts --reporter=line`
  - `pnpm -C tests exec playwright test ./unit/confirmTxFlow.defensivePaths.test.ts --reporter=line`

## Success Criteria

- Common signing confirmation path is readable from one flow module tree.
- Callers no longer jump across `handlers + bridge + per-flow` files directly.
- SecureConfirm flow file count is reduced by deleting duplicate wrappers.
- No runtime behavior regressions in signing and confirmation tests.
