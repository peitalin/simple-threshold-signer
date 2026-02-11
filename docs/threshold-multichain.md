# Threshold Multichain Plan — Clean TODO

Last updated: 2026-02-10

## Locked decisions (no reopen without explicit approval)

- [x] Keep backend chain-agnostic: backend signs canonical digest bytes; chain adapters remain wallet-origin.
- [x] Keep v1 trust model as fixed 2-party external signer set: `client + logical relayer`.
- [x] Keep deterministic client share derivation from passkey PRF (`PRF.first`, HKDF domain-separated).
- [x] Keep deterministic relayer share derivation from `THRESHOLD_SECP256K1_MASTER_SECRET_B64U` (hard requirement for recovery).
- [x] Use `near/threshold-signatures` with fixed participant IDs `client=1`, `relayer=2`.
- [x] For v1 share mapping, keep additive secret `x = x_client + x_relayer (mod n)` and encode protocol shares with fixed Lagrange constants:
  - `λ_client = 3`, `λ_relayer = -2`
  - `share_client = x_client * inv(3)`
  - `share_relayer = x_relayer * inv(-2)`
- [x] Accept breaking migration later via new `schemeId` (no in-place behavior forks).
- [x] Key lifecycle scope is export-only right now (no import flow).
- [x] Export scope includes both ECDSA and Ed25519, displayed in `ExportPrivateKey` inside wallet-iframe (cross-origin isolated iframe).

## Scope summary

- `threshold-ed25519-frost-2p-v1`: existing path, now in scheme-module architecture.
- `threshold-secp256k1-ecdsa-2p-v1`: new threshold ECDSA path with presign pool.
- Session model stays split:
  - app session (`/auth/*`)
  - threshold session (`/threshold-*/session` + `/threshold-*/authorize` + `/threshold-*/sign/*`)

## Backend checklist

### Phase 1 — Scheme-module shell + identity foundation

- [x] Scheme registry + `SchemeModule`/`ProtocolDriver` interfaces.
- [x] Ed25519 wrapped under scheme module dispatch.
- [x] Passkey auth hard-cut to `/auth/passkey/*`.
- [x] Login-provider registry (`passkey`, `google-oidc`) and identity map (`subject <-> userId`).
- [x] App-session + threshold-session token split (`kind` enforcement).
- [x] Legacy auth route cleanup (`/login/*`, SIWE, deprecated wiring).

### Phase 2 — ECDSA scaffolding

- [x] `/threshold-ecdsa/*` routes for Express + Cloudflare Workers.
- [x] ECDSA store prefixes and wiring (`KEYSTORE`, `SESSION`, `AUTH`).
- [x] `/threshold-ecdsa/session` and `/threshold-ecdsa/authorize`.
- [x] Deterministic relayer-share config via `THRESHOLD_SECP256K1_MASTER_SECRET_B64U`.

### Phase 3 — Threshold ECDSA signing

- [x] Protocol selected and integrated (`near/threshold-signatures`).
- [x] Relay signer state machine + wallet-origin coordinator.
- [x] `/threshold-ecdsa/presign/init` + `/threshold-ecdsa/presign/step`.
- [x] `/threshold-ecdsa/sign/init` + `/threshold-ecdsa/sign/finalize`.
- [x] Presignature pool: reserve/consume/discard semantics with durable backends.
- [x] Replay/digest/session binding invariants.
- [x] High-level Tempo API path (`signTempoWithThresholdEcdsa`) and direct threshold key-ref usage.
- [x] Multi-instance presign session hardening:
  - [x] implement distributed presign-session state (no in-memory coordinator-local map path in handlers)
  - [x] enforce atomic stage transitions and TTL expiry
  - [x] add multi-instance regression test that spans at least two coordinator instances (`tests/unit/thresholdEcdsa.presignDistributed.unit.test.ts`)

### Phase 4 — Key lifecycle

- [x] `POST /threshold-ecdsa/keygen` (deterministic derived-share flow).
- [x] ECDSA private-key export flow (wallet-origin only).
- [x] Ed25519 private-key export flow (wallet-origin only).
- [x] No key-import endpoints/UI in scope.

### Phase 5 — Validation + CI

- [x] Harness tests for threshold-ECDSA signature correctness.
- [x] Unit coverage for high-level secp256k1 path:
  - happy path
  - missing/expired threshold session
  - `pool_empty` refill/retry
  - PRF/key mismatch failure
- [x] E2E flow: keygen -> connect session -> Tempo threshold ECDSA signing.
- [x] CI guardrails for `wasm/eth_signer` build + Node/Workers runtime loading.
- [x] Threshold-core regression CI lane + failure artifact upload.
- [ ] Optional hardening: funded-environment live RPC broadcast check (`eth_sendRawTransaction`).

## Wallet-origin SDK checklist

### Public high-level APIs

- [x] `connectThresholdEcdsaSessionLite`.
- [x] `signTempoWithThresholdEcdsa`.
- [x] `bootstrapThresholdEcdsaSession` on `TatchiPasskey` (keygen + connect + keyRef return).

### NEAR multichain seam

- [x] Replace `NearAdapter` stub with concrete normalization/validation adapter.
- [x] Route `signTransactionsWithActions` through multichain seam without caller-facing behavior changes.
- [x] Keep strict/fallback threshold behavior parity.
- [x] Add parity regression/e2e coverage for NEAR flow:
  - intent digest binding checks (`tests/e2e/thresholdEd25519.digestBinding.test.ts`)
  - threshold warm-session reuse and expiry/re-mint (`tests/e2e/thresholdEd25519.sessionExhaustion.test.ts`)
  - strict/fallback downgrade behavior (`tests/e2e/thresholdEd25519.strictVsFallback.test.ts`)
  - concurrent wallet-iframe signing cross-talk regression (`tests/e2e/signTransactions.concurrentSessions.walletIframe.test.ts`)
- [x] Add dedicated wallet-iframe normalization e2e proving receiver normalization is applied before signer-worker digest/signing (`tests/e2e/nearMultichain.seamNormalization.walletIframe.test.ts`).
- [x] Normalize retry-path confirm inputs for NEAR signing:
  - warm-session fallback and threshold-session refresh retries now pass adapter-normalized `txSigningRequests` into `confirmAndPrepareSigningSession` (no raw caller `transactions` fallback path)

## Distributed Presign Sessions + Atomic Transitions (Implementation Status)

### Scope

- [x] Harden `/threshold-ecdsa/presign/init` and `/threshold-ecdsa/presign/step` for multi-instance coordinators.
- [x] Remove dependence on coordinator-local in-memory presign session state.
- [x] Enforce stage monotonicity + TTL in persistent storage.

### 1) Add a presign-session store interface

- [x] Introduce `ThresholdEcdsaPresignSessionStore` in `server/src/core/ThresholdService/stores/EcdsaSigningStore.ts`.
- [x] Core methods:
  - `createSession(id, record, ttlMs)` (insert-if-absent)
  - `getSession(id)` (read without consume)
  - `advanceSessionCas(id, expectedVersion, nextRecord, ttlMs)` (atomic compare-and-swap update)
  - `deleteSession(id)` (best-effort terminal cleanup)
- [x] Record fields:
  - scope binding: `userId`, `rpId`, `relayerKeyId`, `participantIds`, `clientParticipantId`, `relayerParticipantId`
  - protocol state: `stage`, `wasmSessionState` (opaque serialized blob), `version`
  - lifecycle: `createdAtMs`, `updatedAtMs`, `expiresAtMs`

### 2) Add protocol-state snapshot/restore in WASM

- [x] `/presign/step` reconstructs exact protocol state from persistent storage before applying new messages.
- [x] v1 uses deterministic replay snapshot/restore in relayer session state (`sessionSeedB64u` + transcripted steps), which supports multi-instance reconstruction without WASM export/import APIs.

### 3) Implement store backends

- [x] Postgres:
  - new table `threshold_ecdsa_presign_sessions(namespace, presign_session_id, record_json, stage, version, expires_at_ms, updated_at_ms)`
  - CAS: `UPDATE ... SET ... version = version + 1 WHERE ... AND version = $expected AND expires_at_ms > now RETURNING ...`
- [x] Redis TCP / Upstash:
  - one JSON key per session + TTL, CAS via Lua (`check version + expires + stage`, then update + `PEXPIRE`)
- [x] Cloudflare Durable Objects:
  - storage transactions + version checks preserve single-writer semantics

### 4) Refactor presign handlers to use store CAS

- [x] In `server/src/core/ThresholdService/ecdsaSigningHandlers.ts`:
  - removed `presignSessions` map + `gcPresignSessions()`
  - `/presign/init`:
    - create session record in store (stage `triples`, version `1`)
    - poll once and persist state for distributed continuation
  - `/presign/step`:
    - load record, validate scope + TTL
    - restore wasm session from persisted blob
    - apply requested stage/message inputs, poll
    - CAS write next state (`version + 1`)
    - if `presign_done`: write presignature to pool, then delete session record

### 5) Enforce atomic stage transitions

- [x] Allowed stage graph:
  - `triples -> triples|triples_done`
  - `triples_done -> triples_done|presign`
  - `presign -> presign|done`
- [x] Reject stale updates when CAS fails (`code: stale_session_state`), forcing client retry.
- [x] Reject stage regression and cross-scope reuse (`userId/rpId/participantIds/relayerKeyId` mismatch).

### 6) Multi-instance regression coverage

- [x] Added multi-instance coordinator regression for alternating `/presign/step` across two handler instances (`tests/unit/thresholdEcdsa.presignDistributed.unit.test.ts`).
- [x] Added durable-backend CAS coverage for Postgres/Redis/Upstash (`tests/relayer/threshold-ecdsa.durable-stores.test.ts`).

### 7) Rollout

- [x] Enabled by default (hard-cut) with no coordinator-local legacy handler path.
- [x] CI relayer lane includes presign distributed regression coverage and durable-store CAS checks.

## Security and auth hardening backlog

- [ ] If cookie threshold sessions are enabled in a deployment, require CSRF protection for state-changing endpoints and enforce `Secure`/`HttpOnly`/`SameSite` policy.
- [ ] Add redirect-based Google OIDC (`/auth/google/start`, `/auth/google/callback`) for deployments not using client-side `id_token` verify.
- [ ] Add account-merge UX for identity-link conflicts (`subject` already linked elsewhere).

## Future scheme/version track (post-v1)

- [ ] Define `schemeId` migration plan for a future DKG/resharing-compatible ECDSA variant.
- [ ] If moving beyond fixed 2-party set, redesign share encoding (do not reuse v1 fixed-Lagrange mapping).
- [ ] Implement relayer-fleet cosigning once product requires independent internal cosigners.
