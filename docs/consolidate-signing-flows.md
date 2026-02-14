# Consolidate Signing Flows Plan

Status: In Progress  
Last updated: 2026-02-13

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
- Canonical signer implementation ownership is moving to shared Rust library crates (`crates/signer-core`), with WASM workers as thin binding layers.

## Current State

- NEAR and EVM/Tempo now share a single execute helper:
  - `client/src/core/signing/workers/operations/executeSignerWorkerOperation.ts`
- NEAR and Tempo now share one intent execution entry:
  - `client/src/core/signing/orchestration/signWithIntent.ts`
  - `WebAuthnManager` NEAR signing methods now call `NearAdapter + signWithIntent(...)`.
- Old execute helper files were deleted:
  - `client/src/core/signing/chainAdaptors/handlers/executeNearWorkerOperation.ts`
  - `client/src/core/signing/chainAdaptors/handlers/executeMultichainWorkerOperation.ts`
- Manager naming/runtime-deps naming/method naming were migrated to new names.
- `SignerWorkerManager` now owns:
  - unified kind-based operation dispatch (`requestWorkerOperation`)
    - `kind: 'nearSigner'` -> `NearSignerWorkerTransport`
    - `kind: 'ethSigner' | 'tempoSigner'` -> multichain worker transport gateway
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
- [x] Rename backend public type/class names to `*Transport` (optional cleanup).

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
- [x] Restrict chain modules to adapter-specific normalization/finalization only.

### Phase 5A: Registration Activation Unification (Internal-Only)

- [x] Remove public exposure of NEAR no-prompt AddKey helper (internal activation adapter only; not part of SDK API).
- [x] Introduce shared internal activation contract (e.g., `activateThresholdKeyForChain`) for NEAR/EVM/Tempo onboarding.
- [x] Move NEAR activation implementation from `WebAuthnManager` into `orchestration/activation/near` and invoke it via the shared activation contract.
- [x] Add EVM activation implementation using the same internal activation contract.
- [x] Add Tempo activation implementation using the same internal activation contract.
- [x] Ensure activation helpers are only reachable through registration/bootstrap workflows, never direct SDK API.

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

## Acceptance Criteria (EVM/Tempo Threshold Signing Policy)

- Registration/bootstrap for EVM/Tempo must produce a `threshold-ecdsa-secp256k1` keyRef and counterfactual smart-account metadata, without requiring immediate on-chain deployment.
- EVM/Tempo runtime signing entrypoints must reject secp256k1 signing when a threshold keyRef is not provided.
- EVM/Tempo runtime signing must not use `local-secp256k1` key refs in production signing flows.
- Local secp256k1 derivation is permitted only for explicit private-key export UX and must not be used as a signing-path key source.
- First EVM/Tempo outbound transaction flow must include a deployment gate (`ensureSmartAccountDeployed`) before submit when DB/account state is undeployed.
- Deployment result must be written back to DB/account state (`deployed`, `deploymentTxHash` when available) so later signing paths do not re-run deployment checks unnecessarily.
- NEAR registration defaults to threshold enrollment; local encrypted key material is backup/export-only data and does not set `new_public_key` in threshold registration payloads.

## Export Semantics and Account-Control Caveats

- Runtime signing policy is threshold-first: production EVM/Tempo signing uses `threshold-ecdsa-secp256k1` key refs.
- Exported local keys are for user-controlled backup/export UX only; they are not accepted in runtime signing paths.
- Exporting a secp256k1 private key does **not** automatically grant control of an ERC-4337 smart account unless that key is explicitly configured as an authorized owner on-chain.
- Counterfactual smart-account registration remains non-custodial: users can export key material, but account-control changes require explicit owner-management operations.
- NEAR local encrypted key material generated during threshold registration is backup data and is blocked from runtime signing selection.

## Next Steps

1. [x] Remove ctx-less multichain fallback from `executeSignerWorkerOperation` and require manager context everywhere (migrate tests/utilities first).
2. [x] Implement EVM/Tempo activation adapters and wire them into registration/bootstrap workflows.
3. [x] Add tests proving activation helpers are internal-only and user signing still routes through `executeSigningIntent`.
4. [x] Add unified pipeline test asserting NEAR/EVM/Tempo traverse the same execution path.
5. [x] Finish remaining consolidation hardening:
   - standardize warm-session vs WebAuthn handling across chains
   - remove obsolete type aliases/redundant wrappers
   - run dead-code/import checks and remove unreachable paths
6. [x] Restrict remaining chain modules to adapter-specific normalization/finalization only.
7. [x] Extract canonical signer logic into `crates/signer-core` and ensure existing `wasm/*` crates consume that library instead of owning duplicate logic.
8. [x] Add `crates/signer-platform-ios` planning/execution track and parity fixtures so iOS reuses the same signer core.
9. [x] Finalize smart-account deploy adapter rollout (backend route + default mode flip to `enforce`).
10. [x] Finish export-only local-key guardrails (runtime path cannot consume backup/export local keys).
11. [x] Close rollout gates: full signing validation (targeted deploy-path tests + docs lock landed).

## Phased Todo (Post-Consolidation: Smart Account + Threshold Policy)

### Phase 8: Counterfactual Registration Persistence

- [x] Persist counterfactual smart-account metadata during EVM/Tempo bootstrap (no on-chain deploy side effect).
- [x] Add DB fields for smart-account provisioning state:
  - `chainId`, `factory`, `entryPoint`, `salt`, `counterfactualAddress`
  - `deployed`, optional `deploymentTxHash`, `lastDeploymentCheckAt`
- [x] Ensure initial state is `deployed=false` after registration/bootstrap.
- [x] Add migration + backward-compat reads for existing users with missing smart-account metadata.

### Phase 9: Deploy-On-First-Use Gate

- [x] Introduce `ensureSmartAccountDeployed` orchestration helper for EVM/Tempo outbound signing flows.
  - Initial rollout is observe-mode preflight in Tempo secp256k1 signing (stamps `lastDeploymentCheckAt`, no hard block until deploy adapter wiring lands).
- [x] Run deployment check/gate before first user operation/transaction submit when account state is undeployed.
  - Gate now runs in enforce mode by default; `relayer.smartAccountDeploymentMode='observe'` remains available as an explicit compatibility override.
- [x] Update DB state on successful deployment (`deployed=true`, `deploymentTxHash` when available).
  - State writeback is handled by `ensureSmartAccountDeployed` once deploy adapter returns success.
- [x] Add retry/error semantics for deployment failures that preserve user-facing signing clarity.

### Phase 10: Threshold-Only Runtime Signing Enforcement

- [x] Remove/disable production runtime usage of `local-secp256k1` in secp256k1 signing engines.
- [x] Keep runtime secp256k1 signing paths bound to `threshold-ecdsa-secp256k1` key refs only.
- [x] Add architecture checks in `sdk/scripts/check-signing-architecture.sh` that fail on local-secp runtime signing imports/usages.
- [x] Update/replace tests that currently rely on local-secp runtime signing in unified pipeline tests.

### Phase 10A: NEAR Threshold-First Registration Defaults

- [x] Make registration default to `threshold-signer` when no per-call `signerMode` override is provided.
- [x] In threshold registration, derive/store local encrypted NEAR key material as backup/export data by default (`backupLocalKey=true`), while omitting `new_public_key` from relay payload.
- [x] Add explicit export-flow guardrails so backup local key material cannot be selected as runtime signing source.

### Phase 11: Export-Only Local Key Path

- [x] Keep secp256k1 local key derivation path available only for explicit private-key export UX.
- [x] Add guardrails to prevent export-derived local keys from being injected into runtime signing flows.
- [x] Document non-custodial export semantics and account-control caveats for smart accounts.

### Phase 12: Final Validation + Rollout

- [x] Add targeted test: registration persists counterfactual state without deployment.
- [x] Add targeted test: first EVM/Tempo send deploys when undeployed.
- [x] Add targeted test: subsequent sends skip deployment when already deployed.
- [x] Add targeted test: runtime secp signing rejects missing threshold keyRef.
- [x] Run full signing validation gates and architecture checks.
- [x] Update SDK/wallet integration docs with deployment lifecycle and threshold-only signing policy.
