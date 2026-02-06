# Confirm TX Flow

## Overview

Secure confirmation is coordinated in the main thread and split into small, testable units.

- The **SecureConfirm worker** is the canonical initiator: it requests confirmation via `awaitSecureConfirmationV2(...)`.
- The **main thread** classifies the request and delegates to a per‑flow handler that prepares NEAR context, renders UI, optionally collects WebAuthn credentials, and responds back.
- For signing flows, the main thread extracts PRF outputs from the credential and passes them directly to signer-worker payloads; confirmTxFlow envelopes stay secret-free.

High‑level phases: Classify → Prepare → Confirm UI → Collect Credentials → Respond → Cleanup.

## Files

- Orchestrator: `handleSecureConfirmRequest.ts` (entry; validates, computes config, classifies, dispatches)
- Flows: `flows/localOnly.ts`, `flows/registration.ts`, `flows/transactions.ts`
- Shared barrel: `flows/index.ts` (re-exports `adapters/*` to keep imports stable)
- Adapters: `adapters/*` (NEAR context/nonce, WebAuthn helpers, UI renderer, sanitize, type helpers)
- Types: `types.ts` (discriminated unions bound to `request.type`)
- Worker bridge: `awaitSecureConfirmation.ts` (worker-side helper that posts the request to the main thread and awaits a decision)
- Config rules: `determineConfirmationConfig.ts` (merges user prefs + request overrides + iframe safety)

## Message Handshake

- Worker → Main: `PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD` with a V2 `SecureConfirmRequest`
- Main → Worker: `USER_PASSKEY_CONFIRM_RESPONSE` containing confirmation status, optional credential, and optional `{ transactionContext }`

### Defensive constraints (signing flows)

For `SecureConfirmationType.SIGN_TRANSACTION` / `SIGN_NEP413_MESSAGE`:
- The request payload must not contain secrets like `prfOutput`, `wrapKeySeed`, or `wrapKeySalt` (validated in `handleSecureConfirmRequest.ts`).
- The main-thread response intentionally omits `prfOutput`, `wrapKeySeed`, and `wrapKeySalt` for signing. PRF outputs are extracted from the credential after confirmation and sent directly to signer-worker requests.

### Canonical Initiator (Signing)

For signing flows, the canonical initiator is the **SecureConfirm worker**:

1. SecureConfirm runtime calls `awaitSecureConfirmationV2(request)` (JS function exposed globally in the SecureConfirm worker runtime).
2. `awaitSecureConfirmationV2` posts `PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD` to the main thread.
3. `SecureConfirmWorkerManager` intercepts that handshake message and runs `handlePromptUserConfirmInJsMainThread(...)` (confirmTxFlow) on the main thread.
4. The main thread posts `USER_PASSKEY_CONFIRM_RESPONSE` back to the SecureConfirm worker.
5. The SecureConfirm worker resolves the waiting request and continues the original worker flow.

## Flows

- LocalOnly
  - Types: `DECRYPT_PRIVATE_KEY_WITH_PRF`, `SHOW_SECURE_PRIVATE_KEY_UI`
  - No NEAR calls
  - Decrypt: silently collect an authentication credential via get(); UI is skipped; if user cancels, posts `WALLET_UI_CLOSED`
  - ShowSecurePrivateKeyUi: mounts export viewer (modal/drawer); returns confirmed=true and keeps viewer open

- Registration / LinkDevice
  - Fetches NEAR block context; renders UI per config
- Collects create() credentials; retries on `InvalidStateError` by bumping deviceNumber
- Serializes credential (PRF outputs live inside the serialized credential so wallet-origin code can pass them directly to signer workers without adding them to confirmTxFlow envelopes)

- Signing / NEP‑413
  - Fetches NEAR context via NonceManager (reserving per‑request nonces)
  - Renders UI per config
  - Supports a single flow with two signing modes, controlled by `payload.signingAuthMode`:
    - `webauthn` (default): collect get() credentials for a challenge digest (e.g. intent digest or threshold session policy digest).
    - `warmSession`: skip WebAuthn entirely when a wallet-origin warm session is available (e.g. PRF.first cached inside SecureConfirm).
- Signing responses intentionally omit PRF outputs; confirmTxFlow never carries PRF material.
  - Releases reserved nonces on cancel/negative confirmation

## UI Behavior

- `determineConfirmationConfig` combines user prefs and request overrides, with wallet‑iframe safety defaults
- `renderConfirmUI` supports `uiMode: 'none' | 'modal' | 'drawer'` and `behavior: 'skipClick' | 'requireClick'`
- For warm sessions (`signingAuthMode: 'warmSession'`), the confirmer UI still renders, but no WebAuthn prompt is performed.
- Wallet iframe overlay considerations remain: requireClick flows must be visible for clicks to register

## NEAR Context

- Signing and registration flows fetch NEAR block context for UI display and/or nonce reservation.
- NonceManager reserves/releases nonces for signing batches; registration does not use nonces.

## Types

- Discriminated unions bind `request.type` to its payload
- `LocalOnlySecureConfirmRequest`, `RegistrationSecureConfirmRequest`, `SigningSecureConfirmRequest`
- All responses are sanitized via `sanitizeForPostMessage` to ensure structured‑clone safety

## Sequence

1. Worker sends `PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD`
2. Main validates, computes effective `ConfirmationConfig`, and classifies the flow
3. Per‑flow handler prepares NEAR context and (when needed) a WebAuthn challenge digest
4. UI is rendered per config (none/modal/drawer); user confirms or cancels
5. If required, credentials are collected (create/get) and serialized
6. For signing flows, wallet-origin code extracts PRF outputs from the credential and calls the signer worker directly
7. Response is sent back; nonces released on cancel; UI closed as appropriate

## Notes

- Export viewer (ShowSecurePrivateKeyUi) posts `WALLET_UI_OPENED/CLOSED` to coordinate overlays
- Errors are returned in a structured format; best‑effort cleanup always runs
- Orchestrator imports helpers from `flows/index` + `adapters/requestAdapter` and never performs side effects directly
