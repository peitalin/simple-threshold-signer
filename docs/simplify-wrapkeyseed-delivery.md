# Plan: Simplify WrapKeySeed Delivery (Remove SecureConfirm→Signer MessagePort)

## Intent
Remove the SecureConfirm→Signer `MessagePort` pipeline and the SignerWorkerManager session reservation logic. Deliver PRF outputs directly in the signer WASM request payload. This avoids port/session lifecycle bugs while keeping the wallet-iframe origin boundary as the primary isolation layer.

Key constraints from the threat model:
- The VRF worker is gone; the original worker-to-worker isolation goal is no longer applicable.
- Cross-origin isolated wallet iframe provides most isolation.
- MessagePort piping does not materially mitigate malicious extension exfiltration.

## Requirements
- No SecureConfirm→Signer `MessagePort` handshake required for signing or key operations.
- No `reserveSignerWorkerSession` / session-bound `MessagePort` attachment logic in `SignerWorkerManager`.
- Signer WASM derives `WrapKeySeed` and any PRF-dependent keys directly from request fields (no waiting/timeout for session material).
- Keep PRF material out of persistence (no IndexedDB/localStorage); keep in-memory scope minimal; never log.
- Keep PRF.first caching inside the SecureConfirm worker (for threshold warm sessions).
- Stage rollout: “direct PRF” required-only in wallet-iframe mode first, then fully migrate everywhere.
- Remove all old MessagePort plumbing after migration (types, workers, session helpers, docs, tests).

## Staged rollout plan

### Phase 0 — Define the new request contract
- Define a minimal, explicit “direct PRF” struct used by signer WASM handlers:
  - `prfFirstB64u: string` (required when a flow needs WrapKeySeed)
  - `wrapKeySalt: string` (required when deriving KEK)
  - `prfSecondB64u?: string` (only for flows that require PRF.second)
- Decide naming/casing and serde mapping (TS camelCase vs Rust snake_case).
- Add a single source-of-truth doc for which requests require which PRF fields (tx signing, delegate signing, NEP-413, derive/encrypt, decrypt, recovery, device2, etc.).
- Confirm all PRF-dependent requests accept PRF outputs directly (no session/port assumption).

### Phase 1 — Implement “direct PRF” in wallet-iframe mode only
Goal: eliminate SecureConfirm→Signer ports for wallet-iframe flows first (where PRF exposure stays inside wallet origin).

- WASM signer worker:
  - Update request types to accept `prfFirstB64u` + `wrapKeySalt` (+ optional `prfSecondB64u` where required).
  - Refactor handlers to derive `WrapKey` from those fields directly (no session waiters).
  - Keep the legacy session/port path temporarily for non-wallet-iframe callers (compat only).

- Wallet-iframe signing flow (wallet origin main thread):
  - After WebAuthn `get()` returns, extract PRF outputs and pass them directly to signer worker requests.
  - Keep `removePrfOutputGuard(...)` for any relayer-facing credential serialization.
  - Do not reserve a signer worker session or attach any port.

- Threshold warm session (wallet-iframe):
  - Keep PRF.first caching in the SecureConfirm worker:
    - When a WebAuthn credential is collected, `putPrfFirstForThresholdSession(...)` still runs.
  - For warm sessions, call `dispensePrfFirstForThresholdSession(...)` to fetch PRF.first, then include it directly in the signer request payload (no port delivery).

- Guardrails:
  - Add strict “no accidental secrets” checks:
    - Never allow a PRF-bearing credential blob to be forwarded into the signer worker payload.
    - Never log PRF fields (including in errors).

- Tests (wallet-iframe only):
  - Keep/extend `sdk/src/__tests__/e2e/executeAction.twice.walletIframe.test.ts` to ensure 2nd tx progresses.
  - Add a warm-session reuse e2e for threshold-signer (2 consecutive calls with cached PRF.first).
  - Add a multi-request test (two concurrent sessions) to ensure no cross-talk.

### Phase 2 — Expand “direct PRF” to all modes and remove legacy path
Goal: fully migrate off MessagePorts everywhere (not just wallet-iframe).

- App-origin (non-iframe) mode:
  - Decide whether direct PRF is acceptable in the main thread for this mode; if yes, pass PRF in-request as well.
  - If not acceptable, require wallet-iframe for operations that need PRF (breaking change) or keep a separate “secure” path.

- Remove all legacy WrapKeySeed session/port waiting in WASM (no fallback).
- Remove any SecureConfirm worker messages that exist solely to deliver WrapKeySeed to signer.
- Update public docs and migration notes for integrators.

## Phased TODOs

### Phase 0 — Contract + inventory
- [ ] Specify the “direct PRF” fields per request type (`prfFirstB64u`, `wrapKeySalt`, optional `prfSecondB64u`) and their serde casing.
- [ ] Enumerate all WASM worker requests that need WrapKeySeed (tx signing, delegate signing, NEP-413, derive/encrypt, decrypt, recovery, device2).
- [ ] Add a compatibility/migration switch (wallet-iframe only first) and define how to detect “wallet-iframe host mode”.
- [ ] Add a redaction rule for all error/log paths that might include PRF fields.

### Phase 1 — Wallet-iframe mode only (required)
- [ ] WASM: accept direct PRF fields for required requests; derive `WrapKey` from request payload (keep legacy port path only as temporary fallback).
- [ ] Wallet origin: plumb PRF-first + wrapKeySalt into signer worker requests (never into relayer-facing credential JSON).
- [ ] Warm sessions: keep PRF.first caching in SecureConfirm worker; use `dispensePrfFirstForThresholdSession(...)` to get PRF.first and pass it directly in-request.
- [ ] Remove/disable SecureConfirm→Signer port usage in wallet-iframe mode (no session reservation, attach/clear/send-to-signer messages on this path).
- [ ] Add/keep regressions in wallet-iframe:
  - [ ] `executeAction` twice (second must reach broadcasting/action-complete)
  - [ ] Threshold warm-session reuse twice
  - [ ] Two concurrent sessions (no cross-talk)

### Phase 2 — Full migration (all modes)
- [ ] Decide app-origin (non-iframe) policy: allow direct PRF in-request, or require wallet-iframe for PRF-dependent operations.
- [ ] Remove legacy port-based fallback in WASM (direct PRF only).
- [ ] Remove any SecureConfirm worker message types that existed only for seed delivery (keep PRF.first cache APIs).
- [ ] Simplify `SignerWorkerManager` by removing session reservation + MessagePort plumbing entirely.
- [ ] Update docs/migration notes and add a final “no MessagePort path remains” verification step (grep-based).

## “Remove old MessagePort plumbing” checklist (final cleanup)
After Phase 2 is live and tests pass, remove all SecureConfirm→Signer `MessagePort` infrastructure:
- Delete signer session handshake helpers:
  - `sdk/src/core/WebAuthnManager/SignerWorkerManager/sessionHandshake.ts`
  - `sdk/src/core/WebAuthnManager/SignerWorkerManager/sessionMessages.ts`
- Remove session reservation machinery:
  - `reserveSignerWorkerSession` + `signingSessions` map in `SignerWorkerManager`
- Remove control-message types/usages:
  - `ATTACH_WRAP_KEY_SEED_PORT*` control messages, and any code that sends/awaits them.
- Remove SecureConfirm worker port registry and send-to-signer commands:
  - `THRESHOLD_*_TO_SIGNER` and `THRESHOLD_CLEAR_WRAP_KEY_SEED_PORT`
- Remove Rust session storage/waiters:
  - `sdk/src/wasm_signer_worker/src/wrap_key_handshake.rs` (and any callsites)
- Simplify worker managers:
  - Remove “reserve session worker / attach port / detach sender port” concepts from `SignerWorkerManager`.
- Remove any tests that depend on port timing/ACKs and replace with direct-PRF contract tests.
- Update docs:
  - Remove references to SecureConfirm→Signer secret delivery over `MessagePort`.
  - Document that PRF material is now passed to signer WASM as explicit request fields (and the security implications).

## Validation
- Build: `pnpm -C sdk build`
- Wallet-iframe tests: `pnpm -C sdk test:wallet-iframe`
- Targeted e2e: run executeAction twice + warm-session reuse + concurrent-session coverage.
- Grep for legacy types/messages to ensure complete removal (Phase 2).

## Risks / edge cases
- PRF material exposure increases in app-origin mode if migrated there; mitigate with:
  - narrow scoping (local variables only), no persistence, no logs, explicit redaction in error paths.
- “Warm session” correctness:
  - must bind cached PRF.first to `{nearAccountId, rpId, relayerKeyId, participantIds}` and enforce remainingUses/expiry.
- Multi-session concurrency:
  - ensure request correlation is explicit; avoid any global singleton state inside WASM that could cross-contaminate sessions.
- Migration:
  - roll out wallet-iframe-only first to limit blast radius; add a kill-switch/feature flag if needed.
