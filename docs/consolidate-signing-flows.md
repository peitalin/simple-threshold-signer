# Consolidate Signing Flows Plan

Status: In Progress  
Last updated: 2026-02-12

## Objective

Unify NEAR, EVM, and Tempo signing so they all use:

- one worker architecture layer (`SignerWorkerManager`)
- one worker operation entrypoint (`executeSignerWorkerOperation`)
- one signing intent pipeline (`executeSigningIntent`)

No bespoke parallel signing flow should remain after cutover.

## Naming Decisions (Locked)

- `SigningWorkerManager` -> `SignerWorkerManager`
- `MultichainSignerRuntimeDeps` -> `SigningRuntimeDeps`
- `requestNearWorkerOperation` -> `requestWorkerOperation`
- `executeNearWorkerOperation` + `executeMultichainWorkerOperation` -> `executeSignerWorkerOperation`

## Scope Clarifications (Locked)

- `executeSigningIntent` is the canonical path for user-initiated signing.
- Registration/provisioning activation is a separate internal flow (not public API).
- NEAR no-prompt AddKey helper is internal-only (`#activateNearThresholdKeyNoPrompt`).
- ctx-less multichain fallback has been removed; tests/utilities must pass explicit manager context.

## Current State

- NEAR and EVM/Tempo now share a single execute helper:
  - `client/src/core/signing/chainAdaptors/handlers/executeSignerWorkerOperation.ts`
- NEAR and Tempo now share one intent execution entry:
  - `client/src/core/signing/orchestration/signWithIntent.ts`
  - `WebAuthnManager` NEAR signing methods now call `NearAdapter + signWithIntent(...)`.
- Old execute helper files were deleted:
  - `client/src/core/signing/chainAdaptors/handlers/executeNearWorkerOperation.ts`
  - `client/src/core/signing/chainAdaptors/handlers/executeMultichainWorkerOperation.ts`
- Manager naming/runtime-deps naming/method naming were migrated to new names.
- `SignerWorkerManager` now owns:
  - unified kind-based operation dispatch (`requestWorkerOperation`)
    - `kind: 'nearSigner'` -> `NearSignerWorkerBackend`
    - `kind: 'ethSigner' | 'tempoSigner'` -> multichain backend gateway
- Worker module ownership naming is now consistent:
  - `client/src/core/signing/workers/signerWorkerManager/*`
- Threshold-ECDSA bootstrap activation now routes through chain adapters:
  - `client/src/core/signing/orchestration/activation/evm/*`
  - `client/src/core/signing/orchestration/activation/tempo/*`
  - shared helper in `client/src/core/signing/orchestration/activation/thresholdEcdsa/*`

## Phased Todo (Hard Switch, No Backward Compatibility)

### Phase 0: Boundary Lock

- [x] Remove direct backend-implementation imports from chain modules.
- [x] Add lint/CI import-boundary rule enforcing this.
- [x] Add CI grep checks for banned legacy symbols.

### Phase 1: Naming Normalization

- [x] Rename `SigningWorkerManager` -> `SignerWorkerManager`.
- [x] Rename `MultichainSignerRuntimeDeps` -> `SigningRuntimeDeps`.
- [x] Rename `requestNearWorkerOperation` -> `requestWorkerOperation`.
- [x] Replace near/multichain execute helpers with `executeSignerWorkerOperation`.
- [x] Update imports/usages in one pass (no compatibility aliases kept).
- [ ] Rename backend public type/class names to `*Transport` (optional cleanup).

### Phase 2: Unified Worker Operation API

- [x] Introduce explicit `SignerWorkerKind = 'nearSigner' | 'ethSigner' | 'tempoSigner'` in shared types.
- [x] Merge near + multichain operation contracts into one generic operation map.
- [x] Remove static multichain dispatch API; keep one manager-owned API (`requestWorkerOperation`).
- [x] Extend `requestWorkerOperation` typing in runtime deps to support near + multichain forms.
- [x] Route all worker dispatch through one manager API surface (remove static/instance split).

### Phase 3: Chain Routing Cutover

- [x] Delete duplicated execute helper modules.
- [x] Keep one chain execute helper entrypoint.
- [x] Route EVM/Tempo calls through manager instance context (not static dispatch).
- [x] Route NEAR through same argument shape as EVM/Tempo (`kind`-based dispatch).

### Phase 4: Shared Signing Pipeline Cutover

- [x] Define one canonical `signWithIntent(...)` orchestration entry.
- [x] Move NEAR transaction/delegate/NEP-413 onto adapter+intent flow (matching Tempo/EVM style).
- [x] Ensure all user-facing chain signing flows pass through `executeSigningIntent`.
- [ ] Restrict chain modules to adapter-specific normalization/finalization only.

### Phase 5A: Registration Activation Unification (Internal-Only)

- [x] Remove public exposure of NEAR no-prompt AddKey helper (internal activation adapter only; not part of SDK API).
- [x] Introduce shared internal activation contract (e.g., `activateThresholdKeyForChain`) for NEAR/EVM/Tempo onboarding.
- [x] Move NEAR activation implementation from `WebAuthnManager` into `orchestration/activation/near` and invoke it via the shared activation contract.
- [x] Add EVM activation implementation using the same internal activation contract.
- [x] Add Tempo activation implementation using the same internal activation contract.
- [ ] Ensure activation helpers are only reachable through registration/bootstrap workflows, never direct SDK API.

### Phase 5: SecureConfirm Unification

- [x] Standardize one SecureConfirm request/response shape for all chains.
- [x] Remove chain-specific SecureConfirm forks where behavior is equivalent.
- [x] Standardize warm-session vs WebAuthn handling across chains.

### Phase 6: Legacy/Stale Cleanup (Mandatory)

- [x] Delete stale files/folders from dual-path migration.
- [x] Delete stale functions, variables, and compatibility-only exports.
- [x] Remove obsolete type aliases and redundant wrapper modules.
- [x] Run dead-code/import checks and remove all unreachable code.

### Phase 7: Final Verification and Doc Lock

- [x] Pass build + targeted signing tests.
- [x] Add unified pipeline test asserting NEAR/EVM/Tempo traverse the same execution path.
- [x] Update architecture diagrams/docs to final ownership model.

## Validation Gates

- `pnpm -C sdk build`
- `pnpm -C tests exec playwright test ./unit/modularity.lazySigners.unit.test.ts --reporter=line`
- `pnpm -C tests exec playwright test ./unit/thresholdEcdsa.tempoHighLevel.unit.test.ts --reporter=line`
- `pnpm -C tests exec playwright test ./unit/signingPipeline.unified.unit.test.ts --reporter=line`
- `pnpm -C tests exec playwright test ./unit/tempo.signingAuthMode.unit.test.ts --reporter=line`
- NEAR signing tests (transactions, delegate, NEP-413)
- import-boundary checks:
  - no chain module imports backend implementation files
  - no legacy execute helper/module remains
  - no imports from removed `secureConfirm/flow/*` wrapper path

## Notes

- Boundary checks now live in `sdk/scripts/check-signing-architecture.sh` and are wired into root `check`.
- `executeSignerWorkerOperation` now requires runtime manager context for all worker kinds (`nearSigner`, `ethSigner`, `tempoSigner`); ctx-less dispatch is removed from runtime and tests/utilities must pass explicit context.
- Architecture check now also enforces that `executeSignerWorkerOperation` does not directly call multichain gateway fallback.
- Tempo SecureConfirm now uses `SecureConfirmWorkerManager.confirmAndPrepareSigningSession({ kind: 'intentDigest', ... })`, removing the bespoke `runSecureConfirm(...)` call path from chain handlers.
- Threshold-ECDSA bootstrap now dispatches via `activateThresholdKeyForChain` with internal `evm`/`tempo` activation adapters; default chain remains `tempo` when omitted.
- Warm-session auth mode for Tempo/EVM intent-digest signing now checks threshold PRF cache preflight and throws a reconnect-required error when the session is expired.
- Removed `secureConfirm/flow/*` wrapper modules and rewired all imports to canonical `secureConfirmBridge` + `confirmTxFlow/types`.

## Next Steps

1. [x] Remove ctx-less multichain fallback from `executeSignerWorkerOperation` and require manager context everywhere (migrate tests/utilities first).
2. [x] Implement EVM/Tempo activation adapters and wire them into registration/bootstrap workflows.
3. [ ] Add tests proving activation helpers are internal-only and user signing still routes through `executeSigningIntent`.
4. [x] Add unified pipeline test asserting NEAR/EVM/Tempo traverse the same execution path.
5. [x] Finish remaining consolidation hardening:
   - standardize warm-session vs WebAuthn handling across chains
   - remove obsolete type aliases/redundant wrappers
   - run dead-code/import checks and remove unreachable paths
6. [ ] Restrict remaining chain modules to adapter-specific normalization/finalization only.
