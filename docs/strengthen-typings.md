# Strengthen Typings Plan

Status: Proposed  
Last updated: 2026-02-12

## Objective

Strengthen type safety in `client/src/core/signing/chainAdaptors` by:

- introducing stronger shared types and enums/constants for repeated string unions
- removing all `any` casts in chain adaptor code
- aligning formatting/linting so the folder is clean under current ESLint + Prettier rules

## Baseline Snapshot

Current folder: `client/src/core/signing/chainAdaptors`

- ESLint: 18 warnings, 0 errors
- Prettier: 16 files not formatted
- `any` hotspots (11 casts/usages):
  - `near/nearAdapter.ts`
  - `near/handlers/signTransactionsWithActions.ts`
  - `near/handlers/signDelegateAction.ts`
  - `near/handlers/signNep413Message.ts`
  - `tempo/handlers/signTempoWithSecureConfirm.ts`
  - `tempo/tempoAdapter.ts`

## Scope

In scope:

- all TypeScript under `client/src/core/signing/chainAdaptors/**`
- typing changes needed in directly-coupled orchestration signatures
- lint/format cleanup for this folder

Out of scope:

- protocol/behavior changes to signing flows
- API-level behavior changes in `WebAuthnManager`
- broad repo formatting outside `chainAdaptors`

## Phased Todo List

### Phase 0: Baseline + Guardrails

- [ ] Capture baseline command output in PR notes:
  - `pnpm exec eslint client/src/core/signing/chainAdaptors --ext .ts`
  - `pnpm exec prettier --check client/src/core/signing/chainAdaptors`
- [ ] Confirm no behavior changes are bundled with typing-only commits.
- [ ] Add a short “typing-only” test checklist to the PR template section for this refactor.

Deliverable:

- Repeatable before/after baseline for lint, format, and typecheck.

### Phase 1: Shared Type Foundations (Enums/Constants/Unions)

- [ ] Introduce chain-local typed constants/enums for repeated string literals:
  - NEAR intent kinds/sign request kinds/session kind
  - Tempo request kinds/sign labels
- [ ] Add explicit adapter UI model type for Tempo (replace `unknown` UI model usage).
- [ ] Tighten request/response discriminants used by `ChainAdapter` outputs.

Deliverable:

- Reduced string literal drift and clearer discriminated unions at adaptor boundaries.

### Phase 2: Remove `any` in NEAR Adapter + Local Payload Builders

- [ ] `near/nearAdapter.ts`: remove `validateActionArgsWasm(actions[i] as any)` by narrowing action list type.
- [ ] `near/handlers/signTransactionsWithActions.ts`:
  - replace threshold/local payload `as any` casts with typed builder functions
  - keep `Omit<WasmSignTransactionsWithActionsRequest, 'sessionId'>` shape explicit
- [ ] `near/handlers/signDelegateAction.ts`:
  - replace request payload `as any` with explicit `WasmSignDelegateActionRequest`-compatible builders
- [ ] `near/handlers/signNep413Message.ts`:
  - replace request payload `as any` casts with typed `WasmSignNep413MessageRequest` builders

Deliverable:

- No `any` left in NEAR chain adaptor flow.

### Phase 3: Remove `any` in Tempo Flow + Improve Sign Request Typing

- [ ] `tempo/handlers/signTempoWithSecureConfirm.ts`:
  - replace `(globalThis as any).crypto` with typed global narrowing
  - replace `intent.signRequests[0] as any` with typed narrowing/guard for digest vs webauthn request
  - replace credential `as any` by narrowing secure-confirm credential type before injection
- [ ] `tempo/tempoAdapter.ts`:
  - remove `(request.tx.aaAuthorizationList as any[])` with typed list guard

Deliverable:

- No `any` left in Tempo chain adaptor flow.

### Phase 4: Worker/WASM Boundary Type Hardening

- [ ] Replace loose `unknown` raw payload usage where practical with runtime guards + typed parser helpers.
- [ ] Keep boundary parsing explicit in:
  - `evm/ethSignerWasm.ts` progress payload parsing
  - worker operation request/result wrappers under `handlers/executeSignerWorkerOperation.ts`
- [ ] Ensure transfer payloads use concrete typed objects for operation payloads wherever the schema is known.

Deliverable:

- Safer boundary typing without weakening runtime checks.

### Phase 5: Orchestration Generic Tightening

- [ ] Strengthen generic maps for engines/key refs in orchestration callsites so algorithm-key mapping is explicit.
- [ ] Keep `executeSigningIntent` generic contracts strict for adaptor request unions.
- [ ] Ensure `signWithIntent` callsites avoid fallback `Record<string, ...>` when a narrower map is possible.

Deliverable:

- Stronger compile-time guarantees between sign request algorithm and selected engine/keyRef.

### Phase 6: Lint + Formatting Cleanup

- [ ] Remove unused eslint-disable comments in NEAR handlers.
- [ ] Remove dead/unused local types (for example, currently unused raw type aliases).
- [ ] Run:
  - `pnpm exec prettier --write client/src/core/signing/chainAdaptors`
  - `pnpm exec eslint client/src/core/signing/chainAdaptors --ext .ts --fix`

Deliverable:

- `chainAdaptors` folder passes format/lint cleanly.

### Phase 7: Verification + Completion Gate

- [ ] Verification commands:
  - `pnpm exec prettier --check client/src/core/signing/chainAdaptors`
  - `pnpm exec eslint client/src/core/signing/chainAdaptors --ext .ts`
  - `pnpm exec tsc -p client/tsconfig.json --noEmit`
- [ ] Run targeted unit tests covering NEAR + Tempo signing pipeline paths.
- [ ] Confirm no signing behavior regressions in fallback/warm-session/webauthn branches.

Deliverable:

- Typing refactor merged with clean static checks and no behavioral regressions.

## Definition of Done

- No `any` usage remains in `client/src/core/signing/chainAdaptors/**`.
- `client/src/core/signing/chainAdaptors/**` is Prettier-clean.
- ESLint reports 0 warnings and 0 errors for the folder.
- Orchestration and adapter generics preserve strict algorithm/request/result mapping.
