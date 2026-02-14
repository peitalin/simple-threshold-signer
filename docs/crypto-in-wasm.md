# Crypto-in-WASM Refactor Plan

Status: Completed  
Last updated: 2026-02-14

## Architecture Direction Update (Locked)

This plan now assumes a shared Rust library architecture:

- Canonical signer implementation lives in `crates/signer-core`.
- Web execution reaches signer logic through `crates/signer-platform-web` bindings consumed by WASM workers.
- iOS will consume the same signer logic via Swift bindings over `signer-core`.
- Existing `wasm/{eth_signer,tempo_signer,near_signer}` crates are transition wrappers and should be reduced to binding glue.

## Objective

Move all low-level cryptographic operations out of TypeScript runtime code and into WASM worker modules.

Target rule:

- TypeScript owns orchestration, request shaping, and transport only.
- WASM workers own key derivation, hashing, signing, signature parsing/packing, and curve/share math.

## Scope

In scope:

- `client/src/core/signing/**`
- `client/src/core/near/nearCrypto.ts`
- `client/src/core/workers/{eth-signer.worker.ts,tempo-signer.worker.ts,near-signer.worker.ts}`
- `crates/{signer-core,signer-platform-web,signer-platform-ios}`
- `wasm/{eth_signer,tempo_signer,near_signer}`

Out of scope:

- API redesign for SDK consumers.
- Relayer protocol changes unless required by strict cryptographic boundary.

## Current TS Crypto Hotspots

- None under `client/src/core/signing` runtime paths.
- Inventory/classification is complete and reflected in this plan + architecture checks.

## Phased Todo Plan

### Phase 0: Boundary Lock + Inventory

- [x] Document strict boundary in signing architecture docs.
- [x] Classify each remaining TS crypto helper as `migrate`, `test-only`, or `delete`.
- [x] Add temporary tracking checklist in PR template for crypto migration progress.

Deliverable:

- One agreed boundary and migration inventory.

### Phase 1: Worker API Expansion

- [x] Extend multichain worker operation map with new crypto ops in:
  - `client/src/core/signing/workers/signerWorkerManager/backends/types.ts`
- [x] Implement new RPC handlers in:
  - `client/src/core/workers/eth-signer.worker.ts`
  - `client/src/core/workers/tempo-signer.worker.ts` (if needed)
  - `client/src/core/workers/near-signer.worker.ts` (if needed)
- [x] Add wrappers in:
  - `client/src/core/signing/chainAdaptors/evm/ethSignerWasm.ts`
  - `client/src/core/signing/chainAdaptors/tempo/tempoSignerWasm.ts`

Deliverable:

- TS callsites can use wasm-backed equivalents for every target crypto primitive.

### Phase 2: secp256k1 PRF.second Derivation Cutover

- [x] Add Rust implementation in `wasm/eth_signer/src/derive.rs` for deterministic secp256k1 keypair + address derivation from `PRF.second`.
- [x] Export from `wasm/eth_signer/src/lib.rs`.
- [x] Wire worker request/response path and typed wrapper.
- [x] Replace dynamic import callsite in:
  - `client/src/core/signing/api/WebAuthnManager.ts`
- [x] Remove runtime dependency on `client/src/core/signing/chainAdaptors/evm/deriveSecp256k1KeypairFromPrfSecond.ts` and delete the compatibility shim.

Deliverable:

- No runtime secp256k1 key derivation from `PRF.second` in TS.

### Phase 3: Threshold ECDSA Math Cutover

- [x] Move additive-share mapping logic from:
  - `shared/src/threshold/secp256k1Ecdsa2pShareMapping.ts`
  into `wasm/eth_signer`.
- [x] Move group public key reconstruction/validation (`Point.fromBytes`, point add/validate) from:
  - `client/src/core/signing/orchestration/walletOrigin/thresholdEcdsaCoordinator.ts`
  into wasm operations.
- [x] Update coordinator to call wasm only for curve/share math.

Deliverable:

- No secp256k1 curve arithmetic in TS signing runtime.

### Phase 4: Hashing/Serialization Runtime Cutover (EVM/Tempo)

- [x] Ensure runtime paths exclusively use wasm for:
  - EIP-1559 digest and encoding
  - Tempo sender hash and signed tx encoding
- [x] Remove runtime imports/usages of:
  - `client/src/core/signing/chainAdaptors/evm/{keccak.ts,eip1559.ts,rlp.ts}`
  - `client/src/core/signing/chainAdaptors/tempo/tempoTx.ts`
- [x] Update tests that currently import TS implementations to use wasm wrappers.
- [x] Lock deterministic tx-finalization vectors in `crates/signer-core/src/{eip1559.rs,tempo_tx.rs}` and enforce via `sdk/scripts/check-signer-parity.sh`.

Deliverable:

- EVM/Tempo hashing/encoding in runtime path is wasm-only.

### Phase 5: WebAuthn P-256 Low-Level Parsing Cutover

- [x] Keep credential collection in browser TS.
- [x] Move DER signature parsing, challenge binding verification, and packed signature byte assembly from:
  - `client/src/core/signing/engines/webauthnP256.ts`
  into wasm operation(s).
- [x] Keep engine as thin orchestration adapter around worker calls.

Deliverable:

- No low-level P-256 signature parsing/packing logic in TS runtime.

### Phase 6: NEAR Key Derivation Cutover

- [x] Move deterministic near key derivation from:
  - `client/src/core/near/nearCrypto.ts`
  into `wasm/near_signer`.
- [x] Replace runtime callsites in:
  - `client/src/core/signing/api/WebAuthnManager.ts`
  - `client/src/core/TatchiPasskey/registration.ts`
- [x] Keep only non-crypto formatting helpers in TS (if needed).

Deliverable:

- No runtime ed25519 key derivation in TS.

### Phase 7: Enforcement + Cleanup

- [x] Extend `sdk/scripts/check-signing-architecture.sh` with crypto boundary checks:
  - fail on `@noble/*` imports under runtime signing paths
  - fail on banned TS crypto helper modules in runtime imports
- [x] Remove dead modules and compatibility shims.
- [x] Update docs to final architecture and ownership model.

Deliverable:

- CI enforces the boundary and prevents regressions.

### Phase 8: Shared Rust Core Extraction

- [x] Stand up `crates/signer-core` and migrate common signer logic from platform-specific wasm crates.
- [x] Ensure `wasm/{eth_signer,tempo_signer}` consume the shared Rust platform layer for shared codec, secp256k1 derivation/public-key operations, and chain-finalization helpers (EIP-1559/Tempo tx hashing+encoding).
- [x] Migrate initial shared primitive from `wasm/near_signer` into `signer-core` and repoint near signer bindings (Ed25519 PRF.second key derivation).
- [x] Migrate remaining near shared primitives (KEK derivation + ChaCha20 helpers) into `signer-core` and repoint near signer bindings.
- [x] Migrate additional NEAR threshold helpers into `signer-core` and repoint near signer wrappers (`threshold/protocol`, `threshold/participant_ids`, `threshold/signer_backend` key parsing + client key package derivation, and NEP-413 digest hashing in `threshold/threshold_digests`).
- [x] Add explicit workspace boundaries so new signer logic cannot land outside `signer-core` (architecture check enforces `signer-platform-web` delegation in wasm signer wrappers).
- [x] Introduce `crates/signer-platform-web` as the canonical long-term web binding surface and repoint wasm wrappers through it.

Deliverable:

- One Rust signer core shared by all platform bindings.

### Phase 9: iOS Binding Parity Path

- [x] Scaffold `crates/signer-platform-ios` bindings over `signer-core` with a versioned `v1` API surface and parity tests against web bindings.
- [x] Add equivalent Swift ABI on top of `signer-platform-ios` (C-ABI export surface + Swift harness linkage).
- [x] Lock canonical vector corpus under `crates/signer-core/fixtures/signing-vectors/v1.json` and replay it through `signer-platform-web` + `signer-platform-ios` Rust tests.
- [x] Split platform binding parity tests out of `src/lib.rs` into dedicated `src/tests.rs` files and deduplicate shared vector helpers in `crates/signer-core/fixtures/signing-vectors/v1_test_vectors.rs`.
- [x] Add initial Web WASM replay test consuming canonical vectors through worker-facing bindings (`tests/unit/signingVectors.webWasmReplay.unit.test.ts`).
- [ ] Replay canonical signing vectors across Rust native + Web WASM + iOS Swift harnesses end-to-end (deferred for now; keep Swift harness scaffolded and re-enable via `RUN_IOS_SWIFT_REPLAY=1`).
- [x] Lock Rust binding CI parity checks to prevent cross-platform signer drift (`pnpm check` runs `check:signer-parity`, with Swift replay currently scaffolded/opt-in).

Deliverable:

- Web and iOS run the same signer logic through different binding layers.

## Final Architecture and Ownership Model

### Ownership by Module

- `client/src/core/signing/api`
  - Public SDK-facing methods and flow selection (`WebAuthnManager`).
  - Owns high-level defaults and backward-compatible API behavior.
- `client/src/core/signing/chainAdaptors`
  - Chain shaping/finalization only.
  - Builds `SigningIntent` per chain and finalizes chain-specific outputs.
  - Uses wasm wrappers for runtime hashing/encoding (`ethSignerWasm`, `tempoSignerWasm`).
- `client/src/core/signing/orchestration`
  - Canonical sign runner is `executeSigningIntent.ts`.
  - Activation entrypoint is `activation/activateThresholdKeyForChain.ts`.
  - Wallet-origin resolvers/coordinators live under `walletOrigin`.
- `client/src/core/signing/engines`
  - Algorithm adapters (`ed25519`, `secp256k1`, `webauthnP256`).
  - No low-level curve/hash/DER parsing in TS runtime paths.
- `client/src/core/signing/secureConfirm`
  - User confirmation, challenge/intent binding, warm-session vs webauthn mode selection.
  - Collects credentials and returns signing context; does not own crypto math.
- `client/src/core/signing/threshold`
  - Threshold workflows (keygen/session authorize/presign/sign orchestration).
  - Uses wasm worker RPC for crypto primitives and share math.
- `client/src/core/signing/webauthn`
  - Browser WebAuthn prompt, serialization, allow-credential selection, fallback bridges.
  - No runtime signature parsing/packing logic (moved to wasm worker ops).
- `client/src/core/signing/workers`
  - Typed RPC boundary (`workers/operations/executeSignerWorkerOperation.ts`) and worker backends.
  - All runtime low-level crypto execution crosses this boundary into wasm workers.
- `crates/signer-core`
  - Canonical signer logic shared across Web and iOS.
  - Owns signing-critical crypto, threshold state transitions, and chain-critical finalization.
- `crates/signer-platform-web` / `wasm/*`
  - Web binding/adaptation layer for workers only (`signer-platform-web` as the API surface, `wasm/*` as operational wrappers).
  - Must not own canonical signer logic.

### Canonical Runtime Sequences

1. NEAR intent signing
   - `WebAuthnManager.sign*` -> `signWithIntent` -> `executeSigningIntent`.
   - `NearAdapter` builds intent and `NearEd25519Engine` dispatches to near handlers.
   - Near handlers run SecureConfirm + session logic and call near worker ops through context.
2. Tempo/EVM digest signing
   - `WebAuthnManager.signTempo` -> `signTempoWithSecureConfirm`.
   - `TempoAdapter` computes digest/hash via wasm wrappers, then `executeSigningIntent` runs engines.
   - `Secp256k1Engine` / `WebAuthnP256Engine` sign via wasm worker ops; adapter finalizes raw tx bytes via wasm.
3. Threshold-ECDSA bootstrap activation
   - `WebAuthnManager.bootstrapThresholdEcdsaSessionLite` -> `activateThresholdKeyForChain`.
   - Chain adapters (`activation/evm`, `activation/tempo`) route into shared `activation/thresholdEcdsa`.
   - Shared flow runs keygen + session connect workflows and returns `threshold-ecdsa-secp256k1` keyRef.

### Enforced Boundary Rules

- Runtime `client/src/core/signing/**` must not import `@noble/*`.
- Removed TS crypto helper modules must not reappear or be imported.
- WebAuthn DER parsing/packing stays in wasm worker operations.
- Deterministic PRF-based key derivation routes through wasm worker operations.
- `executeSignerWorkerOperation` requires runtime context (`ctx`) for near + multichain calls.

## Validation Gates

Per phase, run:

- `pnpm exec tsc --noEmit -p sdk/tsconfig.build.json`
- `pnpm -C sdk run build`
- `bash sdk/scripts/check-signing-architecture.sh`
- `bash sdk/scripts/check-signer-parity.sh`
- targeted tests:
  - `pnpm -C tests exec playwright test ./unit/thresholdEcdsa.tempoHighLevel.unit.test.ts --reporter=line`
  - `pnpm -C tests exec playwright test ./unit/signingPipeline.unified.unit.test.ts --reporter=line`
  - `pnpm -C tests exec playwright test ./unit/tempo.signingAuthMode.unit.test.ts --reporter=line`
  - `pnpm -C tests exec playwright test ./unit/deriveSecp256k1KeypairFromPrfSecond.unit.test.ts --reporter=line`

## Exit Criteria

- [x] No low-level crypto operations in runtime TypeScript signing paths.
- [x] All runtime crypto is executed via wasm worker RPC.
- [x] CI checks block reintroduction of TS crypto primitives in signing runtime.
- [x] Canonical signer logic is centralized in `crates/signer-core`.
- [x] Web wasm wrappers are binding-only and free of duplicated signer implementations.
