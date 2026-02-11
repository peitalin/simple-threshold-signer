# Multichain Adapter / Plugin Layer

> Status (2026-02-09): the multichain adapter/intent abstraction is implemented for **Tempo** (`TempoTransaction` `0x76` and EIP-1559 `0x02`) and **NEAR transaction signing** in `client/src/core/signing/multichain/*`. NEAR now uses a concrete `NearAdapter` plus wallet-origin orchestration (`signNearWithSecureConfirm`) before delegating final signing to the existing signer worker/SecureConfirm flow for artifact parity.

This document proposes a refactor that makes the SDK **chain-agnostic** by splitting “what to sign” (chain-specific) from “how to sign” (key + algorithm-specific). This is intended to run **after** the lite threshold-signer refactor (SecureConfirm removed; wallet-iframe retained; SecureConfirm remains).

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

### Key idea: “Adapter builds intent, engines sign requests”

1. **Chain adapter** parses/validates a payload and produces a `SigningIntent`:

- **UI model** to show the user (recipient/value/fees/chainId, etc.)
- one or more `SignRequest`s (each request is either a 32-byte digest to sign, or a 32-byte WebAuthn challenge)
- a `finalize(signatures)` function that turns returned signatures into chain-specific artifacts (raw tx bytes, tx hash, etc.)

2. **SecureConfirm** runs in the wallet origin to:

- render the intent UI
- require explicit user approval (and satisfy user-activation requirements for WebAuthn)
- (when needed) collect a WebAuthn credential and return it to the wallet-origin caller

3. **Signer engines** sign each `SignRequest` using a particular key source:

- local key (rare in the lite-threshold world; mainly “export/escape hatch”)
- threshold engine (client share + relay share)

4. **Chain adapter** finalizes the signature into chain-specific output:

- NEAR: base64 tx, signatures for `SignedTransaction`, etc
- EVM-shaped: `r,s` + `yParity`, raw signed tx, etc

### Suggested pipeline

`walletOrigin.sign(request)` → `adapter.buildIntent()` → `SecureConfirm(intent.uiModel)` → for each `signRequest`: `engine.sign(signRequest, keyRef)` → `intent.finalize(signatures)` → return public result to app origin

This is slightly different from “confirm → adaptor → wasm signer”; the adapter should run **before confirm** so the user reviews the exact digest being signed.

---

## Core interfaces (TypeScript)

### Request routing

The public API takes a discriminated union:

- `chain: 'near' | 'evm' | 'solana' | ...`
- `kind: 'transaction' | 'message' | 'typedData' | ...`
- `payload: unknown` (validated by adapter)

### `SigningIntent` and `SignRequest`

In code, an intent is “UI + a list of signing requests + finalize”.

Conceptual shape:

- `SigningIntent = { chain, uiModel, signRequests, finalize(signatures) }`
- `SignRequest` is one of:
  - digest signing: `{ kind: 'digest', algorithm: 'ed25519' | 'secp256k1', digest32, label? }`
  - WebAuthn signing: `{ kind: 'webauthn', algorithm: 'webauthnP256', challenge32, rpId?, credential? }`

Notes:

- For the current set of chains, `digest32`/`challenge32` are always **32 bytes**.
- `credential` is optionally supplied by SecureConfirm so engines do not need to call `navigator.credentials.get(...)` themselves.

### `ChainAdapter`

Responsibilities:

- validate + normalize payload
- compute the exact 32-byte digest(s)/challenge(s)
- produce a user-reviewable UI model
- finalize signature(s) into chain-specific signed artifacts

### `SignerEngine`

Responsibilities:

- map a `SignRequest` + `KeyRef` to signature bytes
- enforce algorithm constraints (low-s for secp256k1, etc)

### `SecureConfirm`

Responsibilities (wallet origin):

- take `intent.uiModel` and request user approval
- coordinate user activation + WebAuthn when needed
- return a decision and optional auth/session artifacts (e.g., relay session token)

---

## Resolved architecture questions (Tempo MVP)

### Which signing surfaces are supported?

- EIP-1559 typed transactions (`0x02`) with **secp256k1** sender signatures.
- Tempo-native `TempoTransaction` typed transactions (`0x76`) with sender signatures using either:
  - **secp256k1** (recoverable), or
  - **WebAuthn P-256** (`webauthnP256`).

### What signature encodings do adapters/engines exchange?

- **secp256k1**: 65 bytes `r(32) || s(32) || recovery(1)` (no type prefix).
  - For EVM/EIP-1559 finalization, compute `yParity = recovery & 1`.
- **webauthnP256 (Tempo)**: `0x02 || webauthn_data || r(32) || s(32) || pub_key_x(32) || pub_key_y(32)` (variable length).

### What is explicitly out of scope for the MVP?

- `aaAuthorizationList` must be empty and `keyAuthorization` must be absent (adapter rejects otherwise).
- Multi-request intents are a follow-up; MVP assumes a single `SignRequest` per intent (and SecureConfirm currently supports at most one WebAuthn request).

---

## Packaging / bundling strategy

To keep bundles small and avoid cross-chain dependencies:

- Keep adapters and engines split by chain/algorithm in `client/src/core/signing/multichain/*`.
- Ensure wallet-origin entrypoints only import the chains they need (tree-shaking + optional dynamic import).
- If/when these become public API surface, add subpath exports under `@tatchi-xyz/sdk` that mirror the file layout.

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

This used to be a phased TODO list. The core seam exists today (intent + signRequests + finalize), and Tempo support is implemented. The remaining roadmap is primarily:

### NEAR adapterization (completed)

- `NearAdapter` now validates + normalizes NEAR transaction inputs and produces a stable NEAR intent UI model.
- NEAR wallet-origin signing now runs through `signNearWithSecureConfirm` so normalization happens before signer-worker execution.

### SecureConfirm UI parity (pending)

- Make SecureConfirm render the NEAR adapter UI model directly from intent inputs (no hidden fields).
- Standardize on “SecureConfirm renders `intent.uiModel`” for all multichain intents.
- Keep “digest-only” confirmations as a fallback mode, not the default UX.

### EVM (non-Tempo) adapters (future)

- Add an EVM adapter for non-Tempo chains: legacy/EIP-1559 txs, `personal_sign`, and EIP-712 (typed data).

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
