# Rust Core + iOS Reuse Plan

_Date: February 13, 2026_

Status: In Progress  
Last updated: 2026-02-14

## Objective

Build a single Rust signing core that owns threshold signing logic and low-level cryptography, then expose it to both:

- Web via WASM worker bindings
- iOS via Swift bindings (UniFFI or C ABI)

This ensures NEAR/EVM/Tempo signing behavior is identical across platforms and avoids duplicating signer logic in TypeScript or Swift.

## Scope

In scope:

- Threshold keygen/session/signature logic for NEAR/EVM/Tempo
- Low-level crypto primitives and signature parsing/normalization
- Chain digesting/finalization that materially affects signatures
- Stable cross-platform operation contract and error model
- Conformance tests used by Web and iOS

Out of scope (for this plan):

- UI/UX changes
- Wallet transport/protocol redesign
- Full SDK surface redesign beyond signer boundary

## Architecture Decision (Locked)

Signer implementations must live in a reusable Rust library layer, then be consumed by platform-specific bindings.

- Rust signing logic is centralized in `crates/signer-core`.
- Web workers call Rust through WASM platform bindings only.
- iOS SDK calls the same Rust core via Swift-compatible bindings.
- Platform wrappers are transport/adaptation layers and must not own signer logic.

## Repository Layout Target

```text
/Users/pta/Dev/rust/simple-threshold-signer/
  crates/
    signer-core/            # canonical signer library (chain+crypto+threshold)
    signer-platform-web/    # wasm-bindgen wrapper for web worker consumption
    signer-platform-ios/    # UniFFI/C-ABI wrapper for Swift SDK
  wasm/
    eth_signer/             # transition wrapper or compatibility crate
    near_signer/            # transition wrapper or compatibility crate
    tempo_signer/           # transition wrapper or compatibility crate
```

Transition note:

- Existing `wasm/*` crates may remain during migration, but target end-state is that they import `signer-platform-web` and contain binding glue only.

## Architecture Target

### Rust crates

- `crates/signer-core` (new): canonical implementation
  - No `wasm-bindgen`
  - No platform-specific APIs
  - Owns threshold workflows, crypto, chain signing transforms
- `crates/signer-platform-web` (new or mapped from existing wasm crates)
  - Thin WASM bindings around `signer-core`
- `crates/signer-platform-ios` (new)
  - Swift-compatible bindings around `signer-core`

### Host responsibility boundary

TypeScript/Swift hosts may do:

- user confirmation and prompt orchestration
- storage/network access
- operation dispatch and response handling

TypeScript/Swift hosts must not do:

- private-key derivation math
- threshold round math
- signature DER/low-level normalization math
- chain-signature-critical hashing/encoding math

## Canonical Operation Contract

Define a single versioned operation protocol in Rust and mirror it in host layers.

Required contract properties:

- Request/response schemas are versioned (`v1`, `v2`, ...)
- Stable typed error codes (no string matching)
- Deterministic serialization for operation payloads
- Clear split between stateful workflow ops and pure stateless ops

Initial operation families:

- key lifecycle: derive/create/import/export (export gated)
- threshold lifecycle: start/connect/session/commit/sign
- chain finalize: tx/message digest + signed payload encoding
- utilities: parse/normalize signatures and keys

## Phased Todo Plan

### Phase 0: Freeze Boundary and Inventory

- Enumerate all signer-related crypto currently in TS under `client/src/core/signing`
- Tag each function as `Move to Rust`, `Keep in host`, or `Delete`
- Add lint/check script gate for new TS crypto in signing path

Exit criteria:

- Approved inventory list in repo
- CI guard present for boundary regressions

### Phase 1: Stand Up `signer-core`

- Create `crates/signer-core`
- Move shared domain models and error enums into core
- Add integration tests in Rust for existing behavior parity
- Make existing WASM crates depend on `signer-core` instead of duplicating signer logic

Exit criteria:

- Core builds independently
- Existing Web signer behavior still passes with adapter shims
- No newly added signer logic lands directly in platform-specific crates

### Phase 2: Move Low-Level Crypto to Core

- Port remaining TS crypto hotspots (including WebAuthn P-256 low-level parsing and secp256k1 derivation/normalization)
- Expose pure Rust APIs for worker/host wrappers

Exit criteria:

- TS crypto helpers in signing-critical paths removed or reduced to thin codec glue
- Rust tests cover each moved primitive

### Phase 3: Move Threshold Workflows to Core State Machines

- Consolidate threshold workflow steps into Rust-driven state transitions
- Ensure deterministic transition validation and typed failures

Exit criteria:

- Host orchestrators call coarse Rust ops instead of implementing workflow rules
- Workflow parity tests pass for NEAR/EVM/Tempo

### Phase 4: Move Chain-Critical Finalization to Core

- Move EVM/Tempo/NEAR signature-critical digest/finalization paths into Rust
- Keep host chain adapters as transport/value-mapping only

Exit criteria:

- Signature bytes and signed tx payloads generated from Rust across chains
- Chain adapter logic has no cryptographic branching

### Phase 5: Web Binding Stabilization

- Build thin WASM bindings from `signer-core`
- Keep worker operation names stable where possible; version where needed
- Add benchmark checks for latency/regression
- Ensure `wasm/*` crates are wrapper-only or replaced by `crates/signer-platform-web`

Exit criteria:

- Web path uses only Rust for signing-critical logic
- Existing SDK integration tests remain green

### Phase 6: iOS Binding Implementation

- Implement `crates/signer-platform-ios` binding surface
- Generate Swift bindings (prefer UniFFI)
- Add Swift-side integration harness that replays canonical vectors

Exit criteria:

- Swift can run the same operation families as Web
- Matching outputs for shared vector set

### Phase 7: Cross-Platform Conformance + Hardening

- Create canonical vector corpus from Rust (`fixtures/signing-vectors/*.json`)
- Verify exact output parity across:
  - Rust native tests
  - Web WASM worker tests
  - iOS Swift tests
- Lock boundary checks in CI

Exit criteria:

- No output drift for vectors across platforms
- CI blocks merges that reintroduce TS/Swift signer math

## Phased Todo Checklist

Use this checklist to track execution status across teams.

### Phase 0 Checklist

- [x] Finalize signer-crypto inventory from `client/src/core/signing/**`
- [x] Tag all items as `Move to Rust`, `Keep in host`, or `Delete`
- [x] Add CI check to block new signing-critical TS crypto helpers (`sdk/scripts/check-signing-architecture.sh`)
- [x] Commit inventory doc and ownership sign-off

### Phase 1 Checklist

- [x] Create `crates/signer-core` crate and workspace wiring
- [x] Move shared signer domain models and typed error enums (`crates/signer-core/src/error.rs`, `crates/signer-core/src/operation.rs`)
- [x] Add Rust integration tests for current baseline behavior (`crates/signer-core/tests/baseline_behavior.rs`)
- [x] Verify Web bindings still pass through compatibility shims (`cargo check` on `wasm/{eth_signer,near_signer,tempo_signer}` + parity replay gates)
- [x] Create `crates/signer-platform-web` and repoint `wasm/{eth_signer,tempo_signer,near_signer}` wrappers through it
- [x] Repoint initial `wasm/near_signer` shared primitive to consume shared core via platform-web (Ed25519 PRF.second key derivation)
- [x] Repoint remaining `wasm/near_signer` shared primitives to consume shared core via platform-web (KEK derivation + ChaCha20 helpers)
- [x] Add architecture checks enforcing platform-web delegation in wasm signer wrappers

### Phase 2 Checklist

- [x] Port WebAuthn P-256 low-level parsing/normalization to Rust (`crates/signer-core/src/webauthn_p256.rs`, delegated by `wasm/eth_signer/src/webauthn_p256.rs`)
- [x] Port remaining secp256k1 derivation/normalization helpers to Rust (`sign_secp256k1_recoverable` + low-s normalization moved to `crates/signer-core/src/secp256k1.rs`, delegated by `wasm/eth_signer/src/secp256k1_sign.rs`)
- [x] Move threshold-ECDSA compute/finalize signature math into `signer-core` (`crates/signer-core/src/threshold_ecdsa.rs`), delegated by `wasm/eth_signer/src/threshold.rs`
- [ ] Replace TS crypto implementations with thin request/response codecs
- [ ] Remove duplicate TS test fixtures replaced by Rust vectors

### Phase 3 Checklist

- [x] Move threshold-ECDSA presign session orchestration/state machine into `signer-core` and delegate from `wasm/eth_signer/src/threshold.rs`
- [x] Move NEAR threshold client-share derivation (`threshold_client_share`) into `signer-core` and delegate from `wasm/near_signer/src/threshold/threshold_client_share.rs`
- [x] Move NEAR threshold protocol/participant helpers into `signer-core` and delegate from `wasm/near_signer/src/threshold/{protocol,participant_ids}.rs`
- [x] Move NEAR threshold signer-backend key parsing/client key-package derivation and NEP-413 digest hashing into `signer-core`, delegated by `wasm/near_signer/src/threshold/{signer_backend,threshold_digests}.rs`
- [ ] Move remaining threshold state transition validation into Rust core (NEAR/FROST and shared workflow guards)
- [ ] Collapse host workflow branching into coarse Rust op calls
- [ ] Add state-machine regression vectors for NEAR/EVM/Tempo
- [ ] Verify deterministic error-code behavior for invalid transitions

### Phase 4 Checklist

- [x] Move chain-signature-critical digest/finalization into Rust (`signer-core` + `signer-platform-web` now back EIP-1559/Tempo tx hashing/encoding)
- [ ] Reduce chain adapters to shaping/mapping only
- [ ] Confirm byte-level output parity for signed payloads
- [ ] Remove host-side fallback branches for chain finalization

### Phase 5 Checklist

- [x] Wire `signer-core` into WASM platform crate(s) (`crates/signer-platform-web`)
- [x] Stabilize/version worker op contract for Web callers (versioned request envelope + runtime guardrails in worker backends/workers)
- [ ] Add latency benchmark checks for WASM operation calls
- [x] Validate no signing-critical TS crypto remains in Web runtime path (`sdk/scripts/check-signing-architecture.sh`)
- [ ] Validate that WASM crates contain bindings only (no duplicate signer logic)

### Phase 6 Checklist

- [x] Implement iOS binding crate over `signer-core` with versioned `v1` Rust API surface
- [x] Generate Swift-facing API surface (C ABI shipped now; UniFFI is optional follow-up)
- [x] Build Rust-side iOS binding harness using canonical vectors (fixture replay in `signer-platform-ios` tests)
- [ ] Verify Web and iOS outputs match for shared operation set via compiled Swift harness (deferred for now; scaffold exists and can be enabled with `RUN_IOS_SWIFT_REPLAY=1`)

### Phase 7 Checklist

- [x] Generate and lock canonical vector corpus from Rust
- [x] Run Rust binding parity checks in CI (`pnpm check` -> `check:signer-parity`, with Swift replay currently scaffolded/opt-in)
- [ ] Run Rust/Web/iOS parity in CI on every release branch
- [x] Enforce boundary checks that block TS/Swift signer math regressions (`sdk/scripts/check-signing-architecture.sh`)
- [ ] Publish migration-complete architecture and contract docs

## Legacy Cleanup and Pruning Plan

After each phase cutover, prune legacy code immediately instead of carrying dual paths.

### Cleanup Scope

- Remove pass-through wrappers that only re-export or rename Rust-backed operations
- Remove old host-side fallback paths (warm-session-only branches, ctx-less worker shortcuts, legacy no-prompt bypasses no longer needed)
- Remove duplicated chain-specific helper functions superseded by Rust op calls
- Remove deprecated operation names/types once all internal callsites are migrated
- Remove dead imports, stale test doubles, and unused fixtures that target deleted code paths
- Remove duplicate Rust signer implementations that remain in platform-specific crates after `signer-core` extraction

### Cleanup Workflow (Per Phase)

1. Mark candidates in a `legacy-prune` list during implementation.
2. Delete superseded functions in the same PR as cutover when possible.
3. If a phased temporary shim is required, add explicit expiry criteria and target phase for deletion.
4. Add/adjust tests to ensure behavior is preserved after deletion.
5. Run dead-code checks (`tsc`, lint, and targeted grep checks) before merge.

### Required Pruning Rules

- No long-lived compatibility wrappers without an explicit removal phase.
- No duplicate signer execution paths for the same operation family.
- No host-side crypto math in `client/src/core/signing/**` once equivalent Rust op exists.
- No deprecated op/type aliases after one release cycle unless explicitly approved.
- No duplicated signer logic across `signer-core` and platform binding crates.

### Cleanup Exit Criteria

- Zero known legacy signer execution paths remain for migrated phases.
- All replaced functions are either deleted or tracked with dated removal tickets.
- Code search confirms no stale imports/usages for removed APIs.
- CI checks pass with legacy flags disabled.

## Validation Gates

Required before completion:

- `pnpm -C sdk build` passes
- Existing threshold core tests pass
- New Rust integration tests pass
- Web worker signer tests pass
- iOS binding smoke/integration tests pass
- Cross-platform vector parity report generated in CI

## Acceptance Criteria

- All signing-critical cryptography and threshold logic runs in Rust core
- Web and iOS use the same Rust signer behavior via separate bindings
- EVM/Tempo mainline signing uses threshold workflow, not local key signing path
- Local key usage is explicitly limited to export-only flows
- Protocol is versioned and backward-compatible at operation boundary
- Documentation for operation contract and errors is checked in

## Risks and Mitigations

- Risk: Behavioral drift during migration
  - Mitigation: Snapshot/golden vectors before each phase and compare byte-for-byte
- Risk: Binding-specific serialization differences
  - Mitigation: Canonical encoding rules + shared fixtures in CI
- Risk: Large blast radius of stateful threshold flows
  - Mitigation: Move by workflow slice; keep adapters until parity proven

## Immediate Next Steps

1. Finish wrapper-only hardening for remaining `wasm/*` crates (next target: NEAR threshold coordinator/session orchestration + relayer transport paths under `wasm/near_signer/src/threshold/{coordinator,signer_backend,relayer_http}.rs`).
2. Replace TS crypto implementations with thin request/response codecs where Rust equivalents now exist.
3. Reduce chain adapter runtime paths to shaping/mapping only and remove final host fallback branches.
4. Wire full Rust/Web/iOS parity gates to release-branch CI.
5. Publish migration-complete operation-contract and architecture docs.
