# Lite Signer Refactor — Threshold-Only SDK (No VRF)

This plan replaces the current VRF-centric client architecture with a **threshold-signing-focused SDK** that uses **standard WebAuthn challenge/response** minted and verified by the **server/relay**. The goal is to keep the client small, explicit, and relay-compatible while removing `wasm_vrf_worker` + `vrf-wasm` entirely.

This is intended to be the **threshold signer for a neobanking app**, operated as a **regulated, compliant exchange**. In production, the **relay is the system of record** and must store **WebAuthn authenticators + signature counters privately** (not on-chain).

## Requirements
- **Hard cutover (no legacy, no migration)**: breaking change; delete/disable VRF-based flows, Shamir, and any “dual path” compatibility. Re-registration/re-onboarding is required; the old system is treated as archived.
- **Threshold signing first**: support 2-party threshold Ed25519 signing (client ↔ relay) for NEAR tx signing (optional: NEP-461 + NEP-413 as follow-ons).
- **No VRF**: remove `wasm_vrf_worker`/`vrf-wasm` and any VRF-WebAuthn/confirmTxFlow coupling from the “lite” path.
- **No Shamir 3-pass**: remove/avoid Shamir “server-lock” flows and key-rotation tooling used to reconstruct/unlock legacy VRF key material.
- **Standard WebAuthn auth**: server-minted challenge → `navigator.credentials.get(...)` assertion → server verification → session/token issuance.
- **WASM-first signing + crypto**: all low-level cryptography (hashing/signature ops) and transaction serialization/signing must run inside **WASM web workers**, not JS. JS is orchestration + UI only.
  - Target signer modules (lazily loaded): `near_signer.wasm`, `eth_signer.wasm`, `tempo_signer.wasm` (Tempo “wam” typo in notes should be treated as `.wasm`).
  - Constraint: WebAuthn itself is browser/OS-managed; we can’t “move” passkey signing into WASM, but we can keep all tx hashing/encoding and any non-WebAuthn signature logic in WASM workers.
- **Compliance / privacy**: store authenticators + counters privately in relay storage (encrypted at rest + access-controlled); do not rely on on-chain authenticator registries for verification.
- **Relay cutover**: keep the same threshold route family (`/threshold-ed25519/*`) but switch auth to standard WebAuthn; do not maintain VRF variants long-term.
- **Keep wallet origin boundary**: retain the cross-origin wallet iframe (or extension) so app-origin code cannot read PRF outputs or derived secrets.
- **Small surface area**: minimal, typed API; avoid bundling UI into the app origin.

## Scope
- In:
  - Threshold signing flows (authorize + 2-round FROST signing) and minimal NEAR tx serialization/broadcast plumbing.
  - WebAuthn login/session + (optional) per-intent authorization via relay-issued challenges.
  - Product flows required by the neobanking app: `emailRecovery`, `linkDevice`, and `syncAccounts` — reimplemented on the threshold-signer stack (VRF-free, relay-private storage).
  - Dependency/bundle-size budgets and an example app.
- Out:
  - VRF proofs, VRF sessions, VRF-derived challenges, Shamir 3-pass wrapping/unlock, and any “VRF-first” implementations of product flows (legacy email recovery/device linking/account sync).
  - Local signer mode for day-to-day signing (decrypting/storing `near_sk`), and any “export UX” bundled into the lite signer.
  - Heavy UI frameworks/components in the app origin (React/Lit). Keep wallet-iframe UI minimal and purpose-built (SecureConfirm + export).

## Current status (repo)
- VRF WASM removed from the build; the `web3authn-vrf.worker` bundle is now SecureConfirm + in-worker PRF.first warm-session cache/bridge.
- SecureConfirm (confirmTxFlow) is VRF-free and uses standard WebAuthn challenge/response.
- Threshold `/threshold-ed25519/session` is standard-WebAuthn verified and mints JWT/cookie sessions (“lite”).
- `@tatchi-xyz/sdk/lite` export exists for lite-only imports (package split to `@tatchi-xyz/lite-signer` can follow).
- `PRF_FIRST_SALT_V1` / `PRF_SECOND_SALT_V1` and HKDF v1 share derivation are implemented.
- Wallet-iframe “last logged-in user” is scoped by embedding app origin (regression covered).
- Atomic registration (`POST /create_account_and_register_user`) creates accounts as subaccounts of the relay signer (`RELAYER_ACCOUNT_ID`) and requires `new_account_id` to match that postfix.
- Relay storage can be backed by Postgres via `POSTGRES_URL` (durable persistence for WebAuthn authenticators/bindings/challenges and threshold key/session/auth stores); the example relay initializes schema on startup.
- `pnpm -C sdk build` compiles successfully.
- React surface:
  - `@tatchi-xyz/sdk/react` exports `DeviceLinkingPhase`/`Status` (and related `SyncAccount*`/`EmailRecovery*` enums + SSE event types) for app-side progress handling.
  - `@tatchi-xyz/sdk/react/profile` `AccountMenuButton` supports device-linking scan UX via `deviceLinkingScannerParams` (camera scan when available + manual paste fallback).
  - `useTheme()` optionally exposes `setTheme` when the host app controls theme via `TatchiPasskeyProvider theme={{ theme, setTheme }}`.
- `examples/tatchi-docs` updated to post-VRF APIs and typechecks cleanly (`npx tsc -p examples/tatchi-docs/tsconfig.json --noEmit`).

## Decisions (locked)
1. **Auth model**:
   - **Default: login session token**: WebAuthn once → relay returns short-lived token (JWT/cookie) → token gates threshold signing until expiry/uses.
   - **Alternative: per-sign WebAuthn**: relay issues a fresh challenge per `authorize` (best cryptographic binding, worst UX).
   - **No hybrid** (v1): choose either session-token or per-sign; do not mix within a single signing flow.
   - **Intent binding: yes** (required): relay binds the authorization/session to an `intentDigest` and enforces one-time challenges + expiry.
   - **Token transport**: default `Authorization: Bearer <jwt>`; also support httpOnly cookie mode for deployments that prefer it.
2. **Client share source (threshold Ed25519)**:
   - **Deterministic derivation from `PRF.first`** in the wallet origin (no “encrypted at rest” share storage).
   - **PRF salts (32 bytes, v1)**:
     - `PRF_FIRST_SALT_V1 = sha256("tatchi/lite/prf/threshold-ed25519-client-share/v1") = 0x400c318b6695973659a1698ae580dfd8001d9951ba32c695e6349947504f3f84`
     - `PRF_SECOND_SALT_V1 = sha256("tatchi/lite/prf/near-backup-key/v1") = 0x26da50e5ac964a7ea084527fb647f6330b32de51a9af46524b006d8f7fe7f4d1`
     - Use these as the WebAuthn PRF `extensions.prf.eval` salts (`first` for threshold share; `second` for backup key derivation).
   - **Derivation path + rotation**:
     - `derivationPath: u32` default `0`.
     - Rotating the *threshold share* changes `clientVerifyingShareB64u` and therefore requires a fresh threshold keygen/onboarding (new `relayerKeyId` / group key binding).
     - Rotating the *NEAR backup key* is “add a new access key” on NEAR (can coexist with old keys); rotation requires a derivation-version bump (e.g. change the HKDF salt/info labels) and submitting another `AddKey`.
   - **Recommended HKDF derivation (v1)**:
     - Inputs:
       - `prf_first_32`: 32 bytes from WebAuthn PRF extension
       - `nearAccountId`: UTF-8 string
       - `derivationPath`: `u32` (default `0`; reserved for future multiple-key support)
     - Derive:
       - `okm64 = HKDF-SHA256(ikm=prf_first_32, salt="tatchi/lite/threshold-ed25519/client-share:v1", info=nearAccountId || 0x00 || u32be(derivationPath), len=64)`
       - `clientShareScalar = ed25519_scalar_from_wide(okm64)`; reject zero
       - `clientVerifyingShare = (G * clientShareScalar).compress()`
3. **Export / escape hatch key (NEAR, non-custodial)**:
   - Use a client-derived backup key from `PRF.second` and ensure it is present on-chain during registration (preferred: create the account with `backup_pub_key` so no extra WebAuthn prompt is needed). The relay never derives or holds the backup private key.
   - **Current derivation (implemented)**:
     - `seed32 = HKDF-SHA256(ikm=prf_second_32, salt="near-key-derivation:<nearAccountId>", info="ed25519-signing-key-dual-prf-v1", len=32)`
     - `backup_pub_key = ed25519_public_key(seed32)`
4. **Wallet boundary enforcement**:
   - Ensure PRF outputs never cross origins (wallet-iframe ↔ app); only return public results (signatures, public keys, status).
   - Keep user-visible approval (SecureConfirm) on the wallet origin to prevent silent signing initiated by app-origin code.
5. **Intent digest schema**:
   - Use the existing canonical digest schema from `sdk/src/core/digests/intentDigest.ts` (same JSON shapes + `alphabetizeStringify` + sha256 → base64url).
6. **No migration/legacy support**:
   - Delete VRF/Shamir paths and do not maintain compatibility request shapes or UI flows.
   - A user must re-onboard on the new protocol; the old repo is treated as archived.

## Proposed client API (TS)
Package: `@tatchi-xyz/lite-signer` (name TBD; keep distinct from `@tatchi-xyz/sdk`).
- `createLiteSigner({ relayUrl, nearRpcUrl, rpId?, expectedOrigin? })`
- `setAccount({ nearAccountId, relayerKeyId, clientVerifyingShareB64u, participantIds? })`
- `keygenThresholdSigner({ nearAccountId, derivationPath? })` → provisions threshold key material (returns `relayerKeyId`, `thresholdPublicKey`, `participantIds`, `clientVerifyingShareB64u`)
- `loginWithPasskey({ allowCredentials?, userVerification? })` → `{ token, expiresAtMs, remainingUses? }`
- `authorizeSigning({ intent })` → `{ mpcSessionId }` (may be implicit inside `signTransactions`)
- `signTransactions({ transactions, intent, broadcast? })`
- Optional follow-ons: `signDelegateAction`, `signNep413Message`, `logout`

## Relay protocol changes (standard WebAuthn)
Keep the relay as the verifier and policy authority.

### Endpoints (suggested shape)
- Registration (optional if handled elsewhere):
  - `POST /auth/webauthn/register/options` → `PublicKeyCredentialCreationOptions`
  - `POST /auth/webauthn/register/verify` → store credential public key + counter
- Login/session:
  - `POST /auth/webauthn/login/options` → `PublicKeyCredentialRequestOptions`
  - `POST /auth/webauthn/login/verify` → verify assertion → return token `{sub/userId, rpId, exp, remainingUses, scope}`
- Threshold signing:
  - Keygen/onboarding:
    - `POST /threshold-ed25519/keygen` (session-authenticated; binds to `computeThresholdEd25519KeygenIntentDigest` schema)
  - Reuse `POST /threshold-ed25519/session` and/or `POST /threshold-ed25519/authorize` by accepting:
    - bearer token (or cookie) + `clientVerifyingShareB64u` + `relayerKeyId` + `nearAccountId`
  - Optional per-intent hardening:
    - `POST /threshold-ed25519/authorize/options` → challenge embedding `{nonce, exp, scope, intentDigest}`
    - `POST /threshold-ed25519/authorize/verify` → verify assertion → mint `mpcSessionId`

### Server-side verification checklist (must-have)
- Verify `clientDataJSON.type`, `challenge`, `origin`, `rpIdHash`, `UP/UV` flags per policy.
- Enforce one-time challenge use (KV) + expiry.
- Store and verify signature counter (clone detection).
- Bind token/challenge to `{rpId, origin, nearAccountId/userId, relayerKeyId}` (and optionally `clientVerifyingShareB64u`).

## Worker + crypto architecture (lite)
- Wallet iframe main thread owns WebAuthn calls (challenge/response + PRF extension).
- Two-worker model in the wallet origin:
  - **Signer worker** (WASM): threshold protocol + signing.
  - **SecureConfirm worker** (JS): exposes `awaitSecureConfirmationV2` and bridges confirmTxFlow to the main thread UI.
- Signer worker responsibilities:
  - request `/threshold-ed25519/authorize` (or `/session`) and run `/sign/init` ↔ `/sign/finalize`,
  - build signed NEAR transactions and optionally broadcast to RPC.
- SecureConfirm bridge:
  - Replace the VRF WASM worker with a minimal “SecureConfirm worker” that exposes `awaitSecureConfirmationV2` and forwards requests to the wallet-iframe main thread for UI + user gesture.

## Phased implementation checklist

### Phase 0 — Lock decisions + contracts
- [x] Auth model: session token vs per-sign (only); intent binding is required.
- [x] Client-share derivation: deterministic from `PRF.first` (wallet origin only; no at-rest storage); use HKDF derivation described above.
- [x] NEAR escape hatch: derive backup key from `PRF.second` and submit `AddKey(backup_pub_key)` (non-custodial).
- [x] Document the lite signer SDK/relay contract (types + API + example usage) in this plan.

### Phase 1 — Package boundaries (no VRF, no Shamir)
- [x] Add a new workspace package for the lite SDK (or refactor `sdk` with a separate `lite` export) with a strict dependency boundary that excludes VRF WASM and Shamir 3-pass.
- [x] Remove `wasm_vrf_worker` from the build (delete crate + remove Rolldown/build-script/package-export references).
- [x] Remove Shamir 3-pass from the **server/relay** (AuthService config + routes + examples).
- [x] Remove Shamir 3-pass from the **client** (delete `shamir3pass` configs, VRF wrapping/unlock flows, and any UI/docs tied to it).
- [x] Remove offline-export precache references to VRF WASM (no longer shipped).

### Phase 2 — SecureConfirm-only worker (replace VRF worker)
- [x] Refactor the VRF worker bundle into a SecureConfirm-only worker (delete VRF WASM dependency; keep `awaitSecureConfirmationV2` plumbing).
- [x] Make SecureConfirm signing prompts VRF-free (WebAuthn challenge = `sessionPolicyDigest32` or `intentDigest`; no VRF proof generation).
- [ ] Ensure SecureConfirm UI stays wallet-origin-only, minimal, and intent-driven (no app-origin UI dependency).
- [x] Cache `PRF.first` in-memory inside the SecureConfirm worker for the session TTL/remaining-uses window (mirror the legacy warm-session caching behavior) and dispense it to signer workers.
- [x] Rename “VRF” types/paths to “SecureConfirm” (follow-up cleanup; no compatibility shim).
  - [x] Remove `vrfChallenge` from SecureConfirm decision payloads; rely on WebAuthn `clientDataJSON.challenge` where needed.
  - [x] Replace `sdk/src/core/types/vrf-worker.ts` with `sdk/src/core/types/secure-confirm-worker.ts` and migrate the SecureConfirm worker manager to use it.
  - [x] Rename wallet-iframe status APIs from `onVrfStatusChanged`/`clearVrfSession` to `onLoginStatusChanged`/`logout`.
  - [x] Remove remaining `VRFChallenge` usage in client types and delete legacy VRF worker handlers.

### Phase 3 — Standard WebAuthn auth (relay challenge/response)
- [x] Add lite WebAuthn verification for `POST /threshold-ed25519/session` (standard assertion verified by relay; challenge = `sessionPolicyDigest32`).
- [x] Extend `/threshold-ed25519/session` routers to mint JWT/cookie for lite requests.
- [x] Add client helper `mintThresholdEd25519AuthSessionLite(...)` (no VRF payload; PRF outputs redacted before network).
- [x] Hard cutover: remove VRF variants from `/threshold-ed25519/session` request types and server branching.
- [x] Relayer: persist authenticators + signature counters in relay storage and verify lite WebAuthn assertions against relay-stored authenticators (no on-chain authenticator lookups in the threshold path).
- [x] Relayer: persist authenticators at registration time (relay as system of record) so the product can hard-delete the on-chain authenticator registry entirely.
- [x] Add `*/login/options` + `*/login/verify` (server-minted challenges, replay protection, counters) using `@simplewebauthn/server` (SimpleWebAuthn), then remove legacy `/verify-authentication-response` flows.

### Phase 3.5 — Threshold session reliability fixes (from `docs/threshold-bugs.md`)
- [x] Relayer: include threshold-session scope directly in JWT claims (`thresholdExpiresAtMs`, `participantIds`, `relayerKeyId`, `rpId`) so `/threshold-ed25519/authorize` does not depend on KV reads for scope/expiry validation.
- [x] Relayer: set standard JWT time claims for threshold sessions (`iat`, `exp = floor(thresholdExpiresAtMs / 1000)`) and enforce them in `SessionService.verifyJwt()` (do not rely on host `verifyToken` implementations).
- [x] Relayer: refactor `/threshold-ed25519/authorize` (session mode) to validate using JWT claims and only decrement remaining-uses via a KV operation (no “decrement then fetch record” split-brain); keep a fallback path for older tokens until cutover is complete.
- [x] Deployment: for Cloudflare Workers, require persistent stores (e.g. Upstash REST) for both threshold auth-session counters and MPC/signing sessions; fail-fast (or loudly warn) if configured as `in-memory`.
- [x] Cloudflare Workers: instantiate `AuthService` per request/event (avoid cross-request I/O errors for request-scoped bindings).
- [x] Tests: add a regression that covers relogin → authorize → sign → broadcast (ensure no “signed successfully” UI when `/authorize` is rejected).
- [x] Tests: add a negative test that simulates KV read-after-write lag (to ensure `/threshold-ed25519/authorize` succeeds when claims are valid and counters exist but the KV record read is temporarily unavailable).
- [x] Client: mint fresh threshold sessions (do not reuse a stable `sessionId`), and request `remainingUses >= usesNeeded` so signing does not accidentally create 1-use sessions or exhaust a cached token immediately.

### Phase 4 — Threshold signing path (wallet origin)
- [x] Implement VRF-free threshold keygen/onboarding end-to-end (persist *public* threshold material only).
  - Keygen WebAuthn challenge schema (v1): `sha256(alphabetizeStringify({ version:"threshold_keygen_v1", nearAccountId, rpId, keygenSessionId }))` (base64url string).
- [x] Add a wallet-origin keygen helper (`keygenThresholdEd25519Lite`) that derives `clientVerifyingShareB64u` from `PRF.first` and calls `POST /threshold-ed25519/keygen`.
- [x] Wire fixed, versioned WebAuthn PRF salts (`PRF_FIRST_SALT_V1` / `PRF_SECOND_SALT_V1`) into wallet-origin WebAuthn calls.
- [x] Add a wallet-origin helper to mint lite threshold sessions from `sessionPolicyDigest32` challenge and derive `clientVerifyingShareB64u` from `PRF.first`.
- [x] Decide where to cache `PRF.first` / derived share for session-token mode:
  - Preferred: cache inside the SecureConfirm worker (wallet origin) to reduce main-thread exposure.
- [x] Implement `loginWithPasskey` → derive client threshold share from `PRF.first` (wallet origin only).
- [x] Implement PRF.first warm-session reuse across signing calls (wallet origin):
  - SecureConfirm worker caches PRF.first (`ttlMs` + `remainingUses`) and dispenses it to the signer worker.
  - `signTransactionsWithActions` / `signDelegateAction` / `signNep413Message` use the worker cache (no JS in-memory cache).
- [x] Implement signing flows end-to-end (wallet origin) and validate against a live relay:
  - `signTransactionsWithActions`: session mint + warm session reuse + authorize + FROST signing.
  - `signDelegateAction`: same.
  - `signNep413Message`: same.

### Next steps (execute next)
- [x] Extract the lite package boundary: expose lite-only entry via `@tatchi-xyz/sdk/lite` (full package split to `@tatchi-xyz/lite-signer` can follow).
- [x] Move “warm session” caching into the SecureConfirm worker (PRF.first cache + dispense-to-signer bridge).
- [x] Remove local-signer coupling from threshold signing: threshold signing should not require `localKeyMaterial`/`wrapKeySalt`; it should be driven by `PRF.first` + relay share.
- [x] Hard-delete Shamir + VRF legacy client plumbing (keep `emailRecovery` / `linkDevice` / `syncAccounts` features): remove remaining VRF/Shamir types, IndexedDB fields, docs, and tests (no migration path; bump DB versions as needed).
  - [x] Remove remaining VRF/Shamir IndexedDB fields/types and legacy tests/docs (SecureConfirm-only).
  - [x] Restore `emailRecovery` / `linkDevice` / `syncAccounts` API surface + wallet-iframe protocol types (feature-preserving).
  - [x] Re-implement these flows on the threshold stack (relay-private storage; no on-chain authenticator registry dependence).
    - [x] `syncAccounts`: relay passkey→account lookup + client IndexedDB sync (no on-chain registry).
    - [x] `linkDevice`: QR/session handshake + relay-stored authenticator + threshold AddKey activation.
    - [x] `emailRecovery`: passkey+threshold keygen → mailto `recover-<requestId> <accountId> <newPublicKey>` → poll AddKey → finalize local state.
  - [x] Relay server: replace the contract verifier for `/verify-authentication-response` with SimpleWebAuthn + relay authenticator storage (no `verify_authentication_response` view call).
  - [x] Relay server: replace legacy `/verify-authentication-response` with standard WebAuthn login endpoints (`*/login/options`, `*/login/verify`) + replay protection.
- [x] `loginWithPasskey`: reuse login PRF.first to warm threshold share/session (wallet origin only).
- [x] Validate end-to-end threshold signing flows against a live relay:
  - `signTransactionsWithActions`, `signDelegateAction`, `signNep413Message`
- [x] Ship a minimal example + size budget: a wallet-iframe demo that keygens, mints a session, and signs a tx end-to-end; add bundle-size reporting.

### Next steps (current)
- [ ] Add integration tests (Playwright): login success/fail, replayed challenge rejection, expired token/session, and a full threshold signing roundtrip.
- [ ] Write breaking-change notes: “no migration/legacy support; re-register required”; call out relay-as-system-of-record and security/availability tradeoffs.
- [ ] Add a “Lite signer integration” guide for app teams (required config: `walletOrigin`, relay URL, rpId, cookie/session mode; recommended CSP/COOP/COEP notes).
- [ ] Test suite audit + deletion plan: inventory `sdk/src/__tests__`, delete redundant cases, and keep only high-signal “lite” coverage in default CI.

### Phase 5 — Backup/export flow (NEAR only)
- [x] Implement a high-friction wallet-origin flow to derive the backup key from `PRF.second`. Note: this should be done during registration flows (should already be implemented)
- [x] Avoid a second TouchID prompt during registration: create the account with `backup_pub_key` (client-derived from `PRF.second`), then have the client submit `AddKey(threshold_pub_key)` after validating the threshold key.

### Phase 6 — Examples, budgets, and tests
- [x] Fix `examples/tatchi-docs` to keep device linking + account recovery flows working on the threshold stack (no `PasskeyAuthMenu` legacy props; profile menu exposes “Link Device” scanner).
- [x] Add an `examples/*` app demonstrating login + threshold signing via wallet-iframe.
- [x] Add a bundle-size report (raw/gzip/brotli) with budgets for lite entry + wallet assets.
- [x] Add Postgres-backed relay persistence option + schema initialization on relay startup (system-of-record storage for authenticators + threshold sessions).
- [ ] Add integration tests (Playwright): login success/fail, replayed challenge rejection, expired token/session, and a full threshold signing roundtrip.
- [ ] Write breaking-change notes: “no migration/legacy support; re-register required”; call out security/availability tradeoffs.

### Phase 7 — Post-lite: multichain adapter/plugin refactor
- [ ] Refactor signing into `ChainAdapter` + `SignerEngine` plugins (see `doc/multichain_adaptor.md`).
- [ ] Make multichain adapters WASM-backed:
  - [ ] `eth_signer.wasm` worker: RLP, keccak, EIP-2718/1559 encoding, secp256k1 (where applicable).
  - [ ] `tempo_signer.wasm` worker: TempoTransaction (`0x76`) hashing/encoding, sponsorship hashing, and any non-WebAuthn signature logic.
  - [ ] `near_signer.wasm` worker: NEAR tx serialization/signing helpers (existing signer WASM should be renamed/aliased accordingly).
  - [ ] Ensure these workers are **lazy**: only loaded when the chain is configured/used by the wallet iframe.
  - [ ] Keep JS adapters thin: validate inputs + build UI model; delegate hash/encoding/signature ops to WASM workers.
  - [ ] Add EVM/Tempo golden vectors as WASM worker tests (JS tests validate “same payload → same digest” but do not reimplement crypto).

### Phase 8 — Test suite cleanup (post-refactor)
- [x] Delete debug/template E2E tests (safe now): `sdk/src/__tests__/e2e/_template.test.ts`, `sdk/src/__tests__/e2e/debug_import_map.test.ts`, `sdk/src/__tests__/e2e/debug_setup_error.test.ts`.
- [x] Keep local-signer coverage, but split it out of the “lite” validation suite (lite focuses on threshold-only / wallet-origin flows).
- [x] Wire CI to run `pnpm test:lite` by default on PRs.
- [x] Remove legacy test-only RPC bypasses for on-chain WebAuthn verification (`verify_authentication_response`) and re-run affected suites.
- [x] Update `sdk/src/__tests__/README.md` suite references after pruning (remove debug mentions, document any new “lite-only” suite split).
- [x] Fix PasskeyAuthMenu “Scan and Link Device” QR regression (derive `accountId` from context/last-used user when missing).
- [x] Fix atomic registration account domain mismatch by introducing `relayerAccount` config and using it for accountId postfix generation.
- [x] Make `pnpm test:lite` resilient when a local example relay-server is already using port 3000 (default test relay port → 3001).

### Phase 9 — Test suite audit + deletion plan
- [ ] Inventory `sdk/src/__tests__` by product surface (threshold-only “lite”, local-signer, email recovery, device linking, wallet-iframe plumbing).
  - Current layout (84 total):
    - `e2e/` (19): threshold signing + worker wiring + relay integration
    - `relayer/` (9): router + auth/session correctness
    - `wallet-iframe/` (7): transport + overlay routing correctness
    - `lit-components/` (4): confirm UI semantics
    - `unit/` (45): helpers, parsing, storage, worker behavior
- [ ] Identify and delete tests that only cover removed functionality (VRF worker, Shamir 3-pass, on-chain WebAuthn verifier) and update any fixtures/mocks that are now unused.
  - Quick scan: no `wasm_vrf_worker`/Shamir/on-chain `verify_authentication_response` tests remain; most “VRF” mentions assert VRF absence.
- [ ] Consolidate duplicate coverage (especially header/CSP and worker/iframe routing tests) and keep only the highest-signal cases.
  - Candidate dedupe area: multiple “headers” suites (`headers.*`, `wallet-service-headers.*`, `vite-wallet-corp.*`).
  - Low-signal wrappers removed: `sdk/src/__tests__/unit/next-headers.unit.test.ts`, `sdk/src/__tests__/unit/vite-headers.unit.test.ts`.
- [ ] Re-evaluate any `test.skip` branches: either delete, re-enable with new stack behavior, or move to “full” suite if they require non-lite features.
- [ ] Update `sdk/src/__tests__/README.md` with the final suite map after deletions.

## Testing and validation
- Client:
  - Unit tests for request/response typing and intent digest/canonicalization (if used).
  - E2E: login + authorize + sign + broadcast on local relay + local NEAR sandbox (or testnet).
- Server:
  - Negative tests: replayed challenge, wrong origin/rpId, counter rollback, expired token, mismatched `relayerKeyId`/`clientVerifyingShareB64u`.

## Risks and edge cases
- **Replay** if challenge use isn’t strictly one-time and TTL-bound.
- **Origin/rpId drift** across environments (localhost, custom domains, iframe embedding).
- **Session/token theft** (XSS) if stored in JS-accessible storage; prefer httpOnly cookies when feasible.
- **Client share handling**: lite must not silently weaken share security; document where the share comes from and how it’s protected.
- **UX vs security**: per-intent WebAuthn is safer; session tokens are smoother—make this an explicit, configurable policy.
- **Export flows**: a malicious extension can still exfiltrate keys at the moment the user derives/exports them; keep export behind an explicit, high-friction flow and (ideally) a trusted wallet origin.

## Open questions
- None (decisions captured above).
