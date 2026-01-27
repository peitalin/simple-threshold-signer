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
- Implementing threshold ECDSA (this doc only defines the seam).
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

1) **Extract NEAR signing into `NearAdapter`**
- Move NEAR digest computation + tx serialization behind the adapter interface.
- Keep existing threshold Ed25519 engine as the signer for NEAR.

2) **Add `EvmAdapter` (local secp256k1 first)**
- Support:
  - EIP-1559 + legacy tx signing
  - `personal_sign`
  - EIP-712 hashing
- Use a local secp256k1 engine for MVP (e.g., PRF-derived export/escape key, wallet-origin only).

3) **Plumb SecureConfirm UI off of `intent.ui`**
- The confirm UI renders per-chain review fields from adapter output.
- The worker only proceeds to sign if the user explicitly approves.

4) **Add “future hooks” for threshold ECDSA**
- Keep all EVM-specific threshold logic in a separate engine package once the protocol exists.
- Decide EVM “export” stance (EOA migration vs contract wallet) before exposing threshold ECDSA broadly.

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

