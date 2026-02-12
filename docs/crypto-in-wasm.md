# Crypto-in-WASM Refactor Plan

Status: Draft  
Last updated: 2026-02-12

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
- `wasm/{eth_signer,tempo_signer,near_signer}`

Out of scope:

- API redesign for SDK consumers.
- Relayer protocol changes unless required by strict cryptographic boundary.

## Current TS Crypto Hotspots

- `client/src/core/signing/chainAdaptors/evm/deriveSecp256k1KeypairFromPrfSecond.ts`
- `client/src/core/signing/chainAdaptors/evm/{keccak.ts,eip1559.ts,rlp.ts}`
- `client/src/core/signing/orchestration/walletOrigin/thresholdEcdsaCoordinator.ts`
- `shared/src/threshold/secp256k1Ecdsa2pShareMapping.ts`
- `client/src/core/near/nearCrypto.ts`
- `client/src/core/signing/engines/webauthnP256.ts` (DER parsing + signature packing)

## Phased Todo Plan

### Phase 0: Boundary Lock + Inventory

- [ ] Document strict boundary in signing architecture docs.
- [ ] Classify each remaining TS crypto helper as `migrate`, `test-only`, or `delete`.
- [ ] Add temporary tracking checklist in PR template for crypto migration progress.

Deliverable:

- One agreed boundary and migration inventory.

### Phase 1: Worker API Expansion

- [ ] Extend multichain worker operation map with new crypto ops in:
  - `client/src/core/signing/workers/signerWorkerManager/backends/types.ts`
- [ ] Implement new RPC handlers in:
  - `client/src/core/workers/eth-signer.worker.ts`
  - `client/src/core/workers/tempo-signer.worker.ts` (if needed)
  - `client/src/core/workers/near-signer.worker.ts` (if needed)
- [ ] Add wrappers in:
  - `client/src/core/signing/chainAdaptors/evm/ethSignerWasm.ts`
  - `client/src/core/signing/chainAdaptors/tempo/tempoSignerWasm.ts`

Deliverable:

- TS callsites can use wasm-backed equivalents for every target crypto primitive.

### Phase 2: secp256k1 PRF.second Derivation Cutover

- [ ] Add Rust implementation in `wasm/eth_signer/src/derive.rs` for deterministic secp256k1 keypair + address derivation from `PRF.second`.
- [ ] Export from `wasm/eth_signer/src/lib.rs`.
- [ ] Wire worker request/response path and typed wrapper.
- [ ] Replace dynamic import callsite in:
  - `client/src/core/signing/api/WebAuthnManager.ts`
- [ ] Remove runtime dependency on `client/src/core/signing/chainAdaptors/evm/deriveSecp256k1KeypairFromPrfSecond.ts` (or keep only as temporary test oracle).

Deliverable:

- No runtime secp256k1 key derivation from `PRF.second` in TS.

### Phase 3: Threshold ECDSA Math Cutover

- [ ] Move additive-share mapping logic from:
  - `shared/src/threshold/secp256k1Ecdsa2pShareMapping.ts`
  into `wasm/eth_signer`.
- [ ] Move group public key reconstruction/validation (`Point.fromBytes`, point add/validate) from:
  - `client/src/core/signing/orchestration/walletOrigin/thresholdEcdsaCoordinator.ts`
  into wasm operations.
- [ ] Update coordinator to call wasm only for curve/share math.

Deliverable:

- No secp256k1 curve arithmetic in TS signing runtime.

### Phase 4: Hashing/Serialization Runtime Cutover (EVM/Tempo)

- [ ] Ensure runtime paths exclusively use wasm for:
  - EIP-1559 digest and encoding
  - Tempo sender hash and signed tx encoding
- [ ] Remove runtime imports/usages of:
  - `client/src/core/signing/chainAdaptors/evm/{keccak.ts,eip1559.ts,rlp.ts}`
  - `client/src/core/signing/chainAdaptors/tempo/tempoTx.ts`
- [ ] Update tests that currently import TS implementations to use wasm wrappers.

Deliverable:

- EVM/Tempo hashing/encoding in runtime path is wasm-only.

### Phase 5: WebAuthn P-256 Low-Level Parsing Cutover

- [ ] Keep credential collection in browser TS.
- [x] Move DER signature parsing, challenge binding verification, and packed signature byte assembly from:
  - `client/src/core/signing/engines/webauthnP256.ts`
  into wasm operation(s).
- [x] Keep engine as thin orchestration adapter around worker calls.

Deliverable:

- No low-level P-256 signature parsing/packing logic in TS runtime.

### Phase 6: NEAR Key Derivation Cutover

- [ ] Move deterministic near key derivation from:
  - `client/src/core/near/nearCrypto.ts`
  into `wasm/near_signer`.
- [ ] Replace runtime callsites in:
  - `client/src/core/signing/api/WebAuthnManager.ts`
  - `client/src/core/TatchiPasskey/registration.ts`
- [ ] Keep only non-crypto formatting helpers in TS (if needed).

Deliverable:

- No runtime ed25519 key derivation in TS.

### Phase 7: Enforcement + Cleanup

- [ ] Extend `sdk/scripts/check-signing-architecture.sh` with crypto boundary checks:
  - fail on `@noble/*` imports under runtime signing paths
  - fail on banned TS crypto helper modules in runtime imports
- [ ] Remove dead modules and compatibility shims.
- [ ] Update docs to final architecture and ownership model.

Deliverable:

- CI enforces the boundary and prevents regressions.

## Validation Gates

Per phase, run:

- `pnpm exec tsc --noEmit -p sdk/tsconfig.build.json`
- `pnpm -C sdk run build`
- `bash sdk/scripts/check-signing-architecture.sh`
- targeted tests:
  - `pnpm -C tests exec playwright test ./unit/thresholdEcdsa.tempoHighLevel.unit.test.ts --reporter=line`
  - `pnpm -C tests exec playwright test ./unit/signingPipeline.unified.unit.test.ts --reporter=line`
  - `pnpm -C tests exec playwright test ./unit/tempo.signingAuthMode.unit.test.ts --reporter=line`
  - `pnpm -C tests exec playwright test ./unit/deriveSecp256k1KeypairFromPrfSecond.unit.test.ts --reporter=line`

## Exit Criteria

- [ ] No low-level crypto operations in runtime TypeScript signing paths.
- [ ] All runtime crypto is executed via wasm worker RPC.
- [ ] CI checks block reintroduction of TS crypto primitives in signing runtime.
