# Lit Components Refactor Plan

## Scope

Refactor confirmation UI mounting in wallet origin with three goals:

1. Decouple confirmation UI orchestration from `SecureConfirmWorkerManager`.
2. Slim architecture by removing overlap and reducing cross-cutting responsibilities.
3. Introduce a supported extension API so SDK consumers can render confirmation UI with custom Lit components.

## Current State Summary

### What is working well

- Confirm flow is centralized and testable via `confirmTxFlow` adapters.
- UI entry points are already narrowed to `renderConfirmUI`, `mountConfirmUI`, and `awaitConfirmUIDecision`.
- Canonical confirm/cancel events are consistent across modal and drawer variants.

### Main issues to address

1. `SecureConfirmWorkerManager` owns both worker/cache plumbing and confirm orchestration responsibilities.
2. Confirm path uses both worker handshake and direct `runSecureConfirm(...)`, which duplicates pathways and mental model.
3. `confirm-ui.ts` handles DOM mount, portal state, wallet host messaging, and intent guard logic in one module.
4. UI mounting is hard-wired to built-in components, with no public extension seam.
5. Confirm portal stacking currently uses direct style property writes, which conflicts with strict CSP direction.

## Target Architecture

## 1) Separate orchestration from transport/cache

Split current `SecureConfirmWorkerManager` responsibilities into:

- `SecureConfirmRuntime`:
  - owns `confirmTxFlow` orchestration and request handling
  - no worker lifecycle ownership
- `SecureConfirmWorkerCache` (or remove if feasible):
  - owns PRF.first cache transport and worker RPC only

Result: confirmation flow no longer conceptually depends on worker infrastructure.

## 2) Introduce a Confirm UI Provider interface

Add a public provider contract used by `confirmTxFlow/adapters/ui.ts`:

```ts
export type ConfirmUIMountArgs = {
  summary: TransactionSummary;
  txSigningRequests?: TransactionInputWasm[];
  securityContext?: Partial<SecureConfirmSecurityContext>;
  theme: ThemeName;
  uiMode: 'modal' | 'drawer';
  nearAccountIdOverride?: string;
};

export interface ConfirmUIProvider {
  mount(args: ConfirmUIMountArgs & { loading?: boolean }): Promise<ConfirmUIHandle>;
  awaitDecision(args: ConfirmUIMountArgs): Promise<{ confirmed: boolean; handle: ConfirmUIHandle; error?: string }>;
}
```

Default implementation remains existing Lit wrapper behavior.

## 3) Support custom UI providers in SDK config

Add optional SDK config for integrators:

```ts
type CustomConfirmUIConfig =
  | { mode: 'builtIn' }
  | { mode: 'factory'; provider: ConfirmUIProvider }
  | { mode: 'walletIframeElement'; tagName: string; moduleUrl: string };
```

- `factory`: for same-runtime usage where caller can pass functions/instances.
- `walletIframeElement`: serializable config for wallet-host runtime that can dynamically import and mount a custom element.

## 4) Reduce `confirm-ui.ts` surface

Split into focused modules:

- `confirm-ui/portal.ts`: portal lifecycle and stacking classes.
- `confirm-ui/events.ts`: event wiring and resolution helpers.
- `confirm-ui/built-in-provider.ts`: default provider implementation.
- `confirm-ui/intent-guard.ts`: digest guard logic.

Keep `confirm-ui.ts` as a small compatibility barrel.

## 5) Align with strict CSP

Replace direct stack depth `style.setProperty(...)` writes with class-based depth:

- `w3a-confirm-stack-0` ... `w3a-confirm-stack-4`

Move all geometry/depth visuals into stylesheet rules.

## Phased Execution Plan

### Phase 1: Extraction and no-behavior-change cleanup

1. Extract built-in confirm provider from `confirm-ui.ts`.
2. Route `adapters/ui.ts` through a provider instance.
3. Keep existing wrapper and events unchanged.
4. Add tests proving behavior parity for modal/drawer/skipClick/requireClick.

Exit criteria:

- No public API change required.
- Existing tests pass without flow regressions.

### Phase 2: Runtime split in `SecureConfirm`

1. Introduce `SecureConfirmRuntime` for flow orchestration.
2. Move worker-only PRF cache RPC into dedicated cache client.
3. Keep worker handshake path available only where needed.
4. Remove direct orchestration methods from manager once callers migrate.

Exit criteria:

- Confirm flow can run without depending on worker manager internals.
- PRF cache features still work with unchanged behavior.

### Phase 3: Public custom confirm component support

1. Add config plumbing from `TatchiPasskey` -> `WebAuthnManager` -> confirm adapters.
2. Implement `factory` mode (same runtime).
3. Implement `walletIframeElement` mode using explicit dynamic import + custom element mount.
4. Document required event contract (`TX_CONFIRMER_CONFIRM` / `TX_CONFIRMER_CANCEL`) and required props.
5. Add integration tests with a fake custom element.

Exit criteria:

- Integrator can replace confirmation modal/drawer UI without forking core SDK code.

### Phase 4: Cleanup and deprecations

1. Deprecate or rename `SecureConfirmWorkerManager` to reflect narrower responsibility.
2. Remove redundant pathways and dead wrappers.
3. Finalize docs and migration notes.

Exit criteria:

- Architecture is simpler and responsibilities are clear.
- Public extension path is stable and documented.

## Testing Plan

## Unit

- Provider contract tests for built-in provider.
- `adapters/ui.ts` tests with provider mocks.
- Intent guard tests remain green.
- Portal stacking class assignment tests.

## Integration

- Full confirm transaction flow in modal and drawer.
- `skipClick` and `requireClick` parity checks.
- Wallet iframe overlay open/close behavior still correct.
- Custom provider happy path and cancel/error paths.

## Regression focus

- nonce reservation/release semantics on cancel and errors
- confirm/cancel event ordering
- digest mismatch handling
- wallet host overlay lifecycle signals

## Risks and Mitigations

1. Risk: breaking confirm event semantics.
   - Mitigation: keep canonical event names and add adapter contract tests.

2. Risk: runtime mismatch between app-origin and wallet-origin custom components.
   - Mitigation: explicit provider modes with runtime-specific validation.

3. Risk: CSP regressions from inline style writes.
   - Mitigation: class-based depth and stylesheet-only geometry.

4. Risk: migration complexity for existing call sites.
   - Mitigation: compatibility barrel and staged deprecation.

## Initial Task Breakdown (Implementation-ready)

1. Create `confirm-ui/built-in-provider.ts` and wire provider injection.
2. Add optional `confirmUI` config type to SDK public config.
3. Thread config through `TatchiPasskey` and `WebAuthnManager` context.
4. Implement `walletIframeElement` dynamic import + mount helper.
5. Replace portal depth inline style writes with classes.
6. Add unit/integration tests for provider injection and custom element path.
7. Write migration notes in Lit components docs.

