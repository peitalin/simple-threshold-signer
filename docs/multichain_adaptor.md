# Multichain Adapter / Plugin Layer (Post Lite-MPC)

This document proposes a refactor that makes the SDK **chain-agnostic** by splitting “what to sign” (chain-specific) from “how to sign” (key + algorithm-specific). This is intended to run **after** the lite threshold-signer refactor (VRF removed; wallet-iframe retained; SecureConfirm remains).

## Goals
- Support multiple chains without hard-coding NEAR assumptions into the core signing APIs.
- Make it easy to add new signing surfaces:
  - NEAR transactions (Ed25519)
  - EVM transactions + `personal_sign` + EIP-712 (secp256k1)
  - (Later) Solana transactions/messages (Ed25519)
- Keep the **wallet-origin boundary**: app-origin code never receives PRF outputs, derived secrets, or private keys.
- Make adapters tree-shakeable: apps import only the chains they need.

## Non-goals
- Unifying account models across chains (EOA vs contract wallet vs NEAR accounts) beyond what is required to sign correctly.

---

## High-level architecture

### Key idea: “Adapter builds intent, engine signs digest”

1) **Chain adapter** parses/validates a payload and produces a `SigningIntent`:
- canonical, unambiguous **signing digest bytes**
- required **algorithm** (`ed25519`, `secp256k1`, …)
- **UI model** to show the user (recipient/value/fees/chainId, etc)
- any chain-specific “finalization” logic (e.g., build raw signed tx bytes)

2) **SecureConfirm** runs in the wallet origin to:
- render the intent UI
- require explicit user approval (and satisfy user-activation requirements for WebAuthn)

3) **Signer engine** signs the digest using a particular key source:
- local key (rare in the lite-threshold world; mainly “export/escape hatch”)
- threshold engine (client share + relay share)

4) **Chain adapter** finalizes the signature into chain-specific output:
- NEAR: base64 tx, signatures for `SignedTransaction`, etc
- EVM: `r,s,v`/`yParity`, raw signed tx, etc

### Suggested pipeline
`SDK.sign(request)` (wallet origin) → `adapter.buildIntent()` → `secureConfirm(intent.ui)` → `engine.sign(intent.digest)` → `adapter.finalize(signature)` → return public result to app origin

This is slightly different from “confirm → adaptor → wasm signer”; the adapter should run **before confirm** so the user reviews the exact digest being signed.

---

## Core interfaces (TypeScript)

### Request routing
The public API takes a discriminated union:
- `chain: 'near' | 'evm' | 'solana' | ...`
- `kind: 'transaction' | 'message' | 'typedData' | ...`
- `payload: unknown` (validated by adapter)

### `ChainAdapter`
Responsibilities:
- validate + normalize payload
- compute the exact signing digest
- produce a user-reviewable UI model
- finalize signature into signed artifacts

Shape (conceptual):
- `buildIntent(request) -> SigningIntent`
- `finalize(intent, signature) -> SignedResult`

### `SignerEngine`
Responsibilities:
- map digest bytes + `KeyRef` to a signature
- enforce algorithm constraints (low-s for secp256k1, etc)

Shape (conceptual):
- `canSign(intent, keyRef) -> boolean`
- `sign(intentDigestBytes, keyRef) -> Signature`

### `SecureConfirm`
Responsibilities (wallet origin):
- take `intent.ui` and request user approval
- coordinate user activation + WebAuthn when needed
- return a decision and optional auth/session artifacts (e.g., relay session token)

---

## Packaging / bundling strategy

To keep bundles small and avoid cross-chain dependencies:
- Put adapters behind subpath exports:
  - `@tatchi-xyz/lite-signer/adapters/near`
  - `@tatchi-xyz/lite-signer/adapters/evm`
- Put engines behind subpath exports:
  - `@tatchi-xyz/lite-signer/engines/threshold-ed25519`
  - `@tatchi-xyz/lite-signer/engines/secp256k1-local` (initial EVM path)
- Core orchestrator is small and only depends on the adapter/engine interfaces.

Wallet iframe can dynamically import adapters/engines based on configured `chains` to further reduce startup cost.

### WASM-first crypto + transaction encoding (hard requirement)
All low-level cryptography and transaction hashing/serialization must live in **WASM web workers**, not JS.
- Chain signer modules (lazily loaded): `near_signer.wasm`, `eth_signer.wasm`, `tempo_signer.wasm`
- JS remains orchestration + UI only (SecureConfirm + adapter UI models + RPC wiring)
- Constraint: WebAuthn assertion creation stays in JS (browser/OS-managed), but tx hashing/encoding and non-WebAuthn signature logic moves to WASM.

---

## NEAR vs EVM: key model differences (important for “export”)

### NEAR
NEAR accounts can hold **multiple access keys**. This makes non-custodial “escape hatch” patterns straightforward:
- derive a backup key in the wallet origin (e.g., from `PRF.second`)
- submit `AddKey(backup_pub_key)` so the user can later leave the threshold flow without reconstructing threshold secrets

### Ethereum EOA (secp256k1)
An EOA address is derived from a **single** secp256k1 keypair. There is no on-chain “AddKey” equivalent for the same address.

That means a threshold-ECDSA account (EOA) needs an explicit stance on “export”:
- **Preferred: no private-key export**. Provide an “account migration” flow:
  - threshold signer signs a transfer of funds/tokens to a new EOA controlled by an export key.
- **Better UX: use a smart contract wallet** (EIP-4337 / multisig / custom):
  - contract enforces multi-owner and key rotation
  - threshold key and backup key can both be owners
  - export is “add/rotate owner key”, not “reconstruct EOA secret”
- **Break-glass (discouraged): key reconstruction protocol**
  - parties intentionally reconstruct the ECDSA secret and return it to the user under encryption
  - this largely defeats the point of threshold custody and should be a separate, high-friction feature

This adapter layer should not hard-code any of the above; it should allow different `KeyRef` types for EVM:
- `evm-eoa-threshold-ecdsa` (future)
- `evm-eoa-local-secp256k1` (escape hatch / export-derived)
- `evm-contract-wallet` (multi-owner; recommended if threshold ECDSA is added)

---

## Incremental implementation plan (after lite-mpc)

This section is a phased TODO list for making “chain” and “signer” swappable, with an MVP target of **NEAR + Tempo**.

### Phase 0 — Lock the seam (core orchestrator)
- [ ] Define a public discriminated `SigningRequest` union: `{ chain, kind, payload }`.
- [ ] Define `SigningIntent`: `{ chain, algorithm, digestBytes, uiModel, finalizeHints }`.
- [ ] Define `ChainAdapter`: `buildIntent(request) -> intent`, `finalize(intent, signature) -> result`.
- [ ] Define `SignerEngine`: `canSign(intent, keyRef)`, `sign(intent, keyRef) -> signatureBytes`.
- [ ] Keep the entire pipeline wallet-origin: app-origin only sees `SignedResult` (public artifacts).
- [ ] Enforce EIP-2718 typed envelope rules for all EVM-shaped chains:
  - Typed tx: first byte `TransactionType` (`0x00..0x7f`) followed by opaque payload bytes.
  - Legacy tx detection: first byte `>= 0xc0` indicates legacy RLP tx.
  - Signing rule: include the `TransactionType` byte in the signed preimage to prevent cross-type replay.

### Phase 1 — NEAR adapterization (no behavior change)
- [ ] Extract NEAR digest computation + tx serialization behind `NearAdapter`.
- [ ] Reuse the existing threshold Ed25519 signer engine for NEAR (`ThresholdEd25519Engine`).
- [ ] Ensure `NearAdapter.uiModel` is sufficient for SecureConfirm to render a complete review (recipient/value/fees/actions).

### Phase 2 — SecureConfirm renders `intent.uiModel` (per-chain UI)
- [ ] Make SecureConfirm render based on `intent.uiModel` instead of NEAR-specific fields.
- [ ] Ensure “adapter runs before confirm”: user reviews the exact digest inputs (no hidden signing fields).
- [ ] Add unit tests: “UI model matches digest inputs” (no silent field injection).

### Phase 3 — Tempo support (TempoTransaction `0x76` + standard EIP-1559)
Tempo is EVM-shaped, but it has a Tempo-native typed transaction format (`TempoTransaction`, typed tx byte `0x76`) and supports multiple signature encodings (secp256k1, P256, WebAuthn).

- [ ] Add `TempoAdapter` with two transaction modes:
  - **TempoTransaction (`0x76`)**:
    - `buildIntent`: validate/normalize payload, produce the exact **sender signature hash** per Tempo spec (`keccak256(0x76 || rlp([...]))`, including fee-payer placeholder rules).
    - `finalize`: attach signature in Tempo’s encoding and return raw tx bytes.
  - **Standard EIP-1559 typed tx (`0x02`)**:
    - `buildIntent`: compute the standard EIP-1559 signing hash (`keccak256(0x02 || rlp([...]))`).
    - `finalize`: attach signature and return raw tx bytes.
  - Broadcast both via JSON-RPC (`eth_sendRawTransaction`).
- [ ] Implement WASM signer workers for Tempo MVP:
  - `eth_signer.wasm` worker: EIP-1559 `0x02` hashing + raw tx encoding + secp256k1 recoverable signing (low-s normalized).
  - `tempo_signer.wasm` worker: TempoTransaction `0x76` sender hash + raw tx encoding (MVP: AA list empty; no `keyAuthorization`).
  - Integrate both via lazy-loaded worker RPC in the wallet iframe.
- [ ] Add signer engines needed for Tempo MVP:
  - `WebAuthnP256Engine` (wallet-origin only) for passkey-based signing paths (Tempo WebAuthn envelope is `0x02`-prefixed and verifies `clientDataJSON` + P256).
  - `Secp256k1Engine` for standard EIP-1559 signing and TempoTransaction secp256k1 sender signatures, backed by `eth_signer.wasm` (no JS curve code).
- [ ] Decide Tempo MVP signature matrix:
  - `0x76` TempoTransaction: WebAuthn (`0x02`) only vs also raw P256 (`0x01` prefix)
  - `0x02` EIP-1559: secp256k1 only vs (if supported by Tempo) allow P256/WebAuthn-style signatures
- [ ] Lock down Tempo signature encodings (`TempoSignature`) for each algorithm:
  - **secp256k1**: exactly 65 bytes `r(32) || s(32) || v(1)` with **no** type prefix (backward-compatible).
  - **P256**: `0x01 || r(32) || s(32) || pub_key_x(32) || pub_key_y(32) || pre_hash(1)` (total 130 bytes).
  - **WebAuthn**: `0x02 || (authenticatorData || clientDataJSON) || r(32) || s(32) || pub_key_x(32) || pub_key_y(32)` (variable length; parse from the end).
  - (Later) **Keychain** signatures exist as `0x03 || ...` but are out of MVP scope.
- [ ] Decide Tempo MVP feature scope:
  - batching/calls, `nonce_key` (concurrent transactions), `valid_before/valid_after`, fee payer sponsorship, key authorization (defer complex fields until basic send works)
- [ ] Fee sponsorship details (TempoTransaction):
  - Sender signature uses the tx type byte domain (`0x76`) and conditionally **omits** `fee_token` when `fee_payer_signature` is present (placeholder mode).
  - Fee payer signature uses a **different domain separator** (magic byte `0x78`) and commits to a specific `sender_address`; fee payer signature is secp256k1-only.
  - Track fee payer relay support (optional): Tempo exposes a public testnet sponsor at `https://sponsor.moderato.tempo.xyz`.
- [ ] Batch calls details (TempoTransaction):
  - `calls` is a non-empty list; each call encodes as `rlp([to, value, input])`.
- [ ] Access keys details (TempoTransaction):
  - Model `key_authorization` as an optional trailing field (omitted entirely when absent) and keep it separate from the tx sender signature engine (authorization is an extra signed artifact).

### Phase 4 — Testing and vectors
- [ ] Add golden vectors per adapter: “same payload → same digest” and “digest changes when any UI-significant field changes”.
- [ ] Add end-to-end tests: sign + broadcast on NEAR and Tempo testnets (wallet-iframe + SecureConfirm approval gating).
- [ ] Add negative cases: malformed Tempo RLP, wrong typed tx byte, invalid WebAuthn envelope, replayed/invalid WebAuthn challenge (if Tempo flow uses WebAuthn challenge binding).

### Phase 5 — Follow-ons (not required for NEAR + Tempo)
- [ ] EVM adapter for non-Tempo EVM chains (Ethereum-style txs, legacy, `personal_sign`, EIP-712) as a separate adapter, not conflated with Tempo.
- [ ] Threshold ECDSA engine only when the protocol exists; keep it isolated behind `SignerEngine` and keep EVM “export” stance explicit (EOA migration vs contract wallet).

---

## Testing strategy
- Adapter unit tests:
  - “same payload → same digest”
  - “UI model matches digest inputs” (no hidden fields)
- Engine unit tests:
  - signature verification vs known vectors (ed25519 / secp256k1)
  - secp256k1 low-s normalization + correct `v`/`yParity`
- End-to-end:
  - wallet iframe SecureConfirm approval gates signing
  - app origin receives only public artifacts

## Related docs
- `docs/import_threshold_private_keys.md` (import a private key and convert it into threshold MPC signing material)
