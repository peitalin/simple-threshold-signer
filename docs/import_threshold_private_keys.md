# Plan

Implement “import private key → threshold MPC signing” for both Ed25519 (NEAR) and secp256k1/ECDSA (ETH/Tempo) while preserving the wallet-origin boundary and the WASM-first crypto requirement. The core idea is: import happens only in the wallet origin, the key is converted into threshold key material (shares + public commitments), the relay stores only its share + public commitments, and all signing thereafter uses the MPC protocol (no local full key).

## Requirements
- Wallet-origin only: app-origin never receives imported private key bytes, PRF outputs, or threshold shares.
- WASM-first: key parsing, secret sharing math, signature math, tx hashing/encoding live in WASM workers; JS orchestrates UI + network only.
- Server/relay is system of record for authenticators, counters, and the relay’s key share.
- Support “import → immediately sign” and “import → later sign” flows.
- Support multichain: same high-level UX + APIs, different algorithms and transaction encodings.

## Scope
- In:
  - Ed25519 import for NEAR threshold signing (2-party).
  - ECDSA threshold signing protocol for ETH/Tempo (2-party) and import pathway.
  - SecureConfirm UX for import and explicit user consent.
- Out:
  - “Zero-knowledge key injection” where no party ever sees the full private key during import.
  - Multi-device share replication/resharing (beyond the initial 2-party client↔relay setup).

## Files and entry points (expected)
- Wallet origin UI + confirmation:
  - `client/src/core/WebAuthnManager/SecureConfirmWorkerManager/confirmTxFlow/*` (new “IMPORT_PRIVATE_KEY” confirmation type)
- WASM signer modules + workers:
  - `near_signer.wasm` (extend existing NEAR signer worker to support import-to-threshold)
  - `eth_signer.wasm` (already does hashing/encoding + local secp signing; extend or add a dedicated MPC-ECDSA wasm module)
  - `tempo_signer.wasm` (Tempo `0x76` hashing/encoding)
- Relay endpoints:
  - `/threshold-ed25519/*` (extend with “import” endpoint)
  - New `/threshold-ecdsa/*` (or similar) for ECDSA sessions, presigning, signing, and optional import

## Data model / API changes
### Common (both algorithms)
- Introduce a “threshold key record” concept on the relay:
  - `keyId` (stable identifier)
  - `algorithm` (`ed25519` | `secp256k1`)
  - `publicKey` (or `address` for EVM)
  - `participantIds` + versioning
  - relay share ciphertext/encoding (relay-private)
  - public verification material (commitments / VSS commitments / public shares, depending on scheme)
  - `createdAt`, `rotatedAt`, `status`

### NEAR / Ed25519
- Add `POST /threshold-ed25519/keys/import`:
  - Request: `keyId`, `participantId=relay`, `shareBytes`, `commitments`, `publicKey`, metadata (account binding)
  - Relay validates share against commitments and stores relay share + commitments

### ETH/Tempo / ECDSA
- Add a new route family, e.g. `POST /threshold-ecdsa/*`:
  - Key lifecycle: DKG (optional), import (optional), refresh/rotate (later)
  - Signing lifecycle: start session → (optional) presign/preprocess → sign digest → finalize signature
  - Store relay share + any public verification material required by the chosen scheme

## Plan — Ed25519 keys (high level)

### Design choice: “dealer-based import” (client sees key during import)
We assume the client (wallet origin) receives the full Ed25519 secret during import. The client converts it into 2-party threshold material without ever sending the full secret to the relay.

### Protocol sketch (2-party FROST-style VSS with fixed secret)
1. User inputs an Ed25519 private key (supported formats: `ed25519:...`, base58, raw 32/64 bytes).
2. Wallet-origin WASM:
   - parses and normalizes to scalar `x` (and derives `pub = x·G`)
   - samples random polynomial `f(t) = x + a·t (mod L)` (degree 1)
   - computes shares:
     - client share `s1 = f(1)`
     - relay share `s2 = f(2)`
   - computes public commitments:
     - `C0 = x·G` (must equal `pub`)
     - `C1 = a·G`
3. Wallet stores `s1` (encrypted-at-rest, wallet origin only).
4. Wallet sends to relay: `{ keyId, s2, commitments [C0,C1], pub, participantIds }`.
5. Relay verifies `s2` is consistent with commitments:
   - check `s2·G == C0 + (2·C1)` (general VSS verification)
6. Relay stores `s2` + commitments and marks key as active.

### Integrate with existing threshold Ed25519 signing
- Make the threshold Ed25519 engine able to select a `keyId` that points to:
  - local share `s1` (client-side) and
  - relay share `s2` (server-side)
- Ensure signing produces signatures verifying under `pub == C0` (the imported key’s public key).

### UX / product flows
- SecureConfirm “Import private key” screen:
  - show derived public key and (NEAR) the corresponding access key/public key string
  - strongly warn about key exposure, clipboard, and environment trust
  - require explicit confirmation (and optional passkey re-auth)
- Optional follow-on UX (NEAR account migration):
  - if imported key is not currently an access key on the target NEAR account, provide a guided “AddKey threshold pubkey then remove old key” flow (signed by imported key before it’s split, or by threshold once installed).

## Plan — ECDSA keys (ETH/Tempo)

### Phase 0: Choose a 2-party threshold ECDSA protocol and threat model
Pick a concrete scheme with known security properties and implementation maturity. Two practical options:
- “Online” 2-party threshold ECDSA with preprocessing/presigning (faster signing at runtime).
- “Fully online” 2-party threshold ECDSA (simpler storage but slower signing).

Decisions to lock:
- 2-party only vs N-party extensibility
- Preprocessing strategy (how much can be cached, replay protections, invalidation)
- What public verification material the relay stores (depends on scheme)

### Phase 1: Implement threshold ECDSA signing end-to-end (no import yet)
1. Define `threshold-ecdsa` engine interface aligned with existing `SignerEngine` / multichain `SigningIntent`:
   - input: `digest32` + `keyId`
   - output: recoverable signature `r||s||recId` (low-s normalized) to support `yParity`/`v`
2. Implement client-side protocol steps in a WASM worker:
   - state machine that consumes/produces protocol messages
   - JS only forwards messages to relay (HTTP/WebSocket/SSE) and handles timeouts/retries
3. Implement relay-side protocol counterpart:
   - sessions, message ordering, replay protection, rate limits
   - store minimal per-session state and link to authenticated user session
4. Integrate with existing WASM tx hashing/encoding:
   - ETH/Tempo EIP-1559 (`0x02`) digest is already computed in WASM (`eth_signer.wasm`)
   - TempoTransaction (`0x76`) sender hash is computed in WASM (`tempo_signer.wasm`)
   - finalize raw tx bytes in WASM given `{r,s,yParity}` (EIP-1559) or Tempo signature bytes

#### Protocol choice (ECDSA)
Use NEAR’s production-hardened threshold ECDSA implementation as the baseline:
- `https://github.com/near/threshold-signatures` (OT-based ECDSA originally imported from Cait-Sith + NEAR hardening; plus `robust_ecdsa`)
- Used by `https://github.com/near/mpc` (pins `near/threshold-signatures` by git rev)

This keeps the signing contract compatible with our backend output requirement (`r||s||recId`) and aligns with the presignature-based “offline/online” split needed for low-latency EVM signing.

### Phase 2: Add ECDSA key import that converts a local key into threshold shares

#### Option A (recommended MVP): “client-known key → additive secret sharing”
Assume wallet-origin sees the secp256k1 secret scalar `x` during import.
1. Wallet-origin WASM parses `x` (32-byte hex, optionally supports common formats later).
2. Wallet-origin WASM samples random `x1` and sets `x2 = x - x1 (mod n)`.
3. Wallet stores `x1`; relay stores `x2`.
4. Derive and display public key/address to the user:
   - `Q = x·G`, `address = keccak256(Q)[12..]`
5. Relay may store public shares `Q1 = x1·G`, `Q2 = x2·G` and verify `Q == Q1 + Q2` (optional but recommended).
6. Convert the additive shares into the internal share encoding expected by the chosen threshold ECDSA protocol:
   - For `near/threshold-signatures`, use the fixed-participant Lagrange scaling mapping (`share_i = x_i * inv(λ_i)`) described in `docs/threshold-multichain.md`.

#### Option B (later): “key injection without exposing full key to client”
Out of MVP scope; requires a different protocol where the user provides encrypted material and neither party learns the full secret.

### Phase 3: Tempo-specific MVP details
- Ensure signature output format matches Tempo expectations:
  - Standard EIP-1559 tx: ECDSA signature fields `yParity,r,s` (typed tx `0x02`)
  - TempoTransaction `0x76`: secp256k1 sender signature is 65 bytes `r||s||v` (or `r||s||recId` normalized to Tempo’s `v` definition)
- Keep the fee payer signature domain (`0x78`) and other advanced Tempo fields out of MVP unless explicitly needed.

## Action items
[ ] Add `docs/import_threshold_private_keys.md` (this document) and link it from `docs/multichain_adaptor.md`.
[ ] Ed25519: add WASM function “import ed25519 key → (s1,s2,commitments)” to `near_signer.wasm`.
[ ] Ed25519: add relay endpoint `POST /threshold-ed25519/keys/import` + storage + verification.
[ ] Ed25519: add wallet-origin import UI + SecureConfirm gating + local storage for client share.
[ ] ECDSA: adopt `near/threshold-signatures` + implement fixed-participant derived-share mapping (`share_i = x_i * inv(λ_i)`).
[ ] ECDSA: implement `/threshold-ecdsa/*` sessions + presigning + signing (end-to-end) producing recoverable signatures.
[ ] ECDSA: implement “import secp256k1 key → additive shares” and store relay share + verification material.
[ ] Integrate both into multichain orchestrator/engines so adapters request `digest32` signing and get chain-specific finalized tx bytes.

## Testing and validation
- Ed25519:
  - Unit: imported key’s derived `pub` matches original
  - Unit: relay share verification (`s2·G == C0 + 2·C1`)
  - E2E: import → sign a NEAR tx → verify signature on chain (or local verifier)
- ECDSA:
  - Unit: threshold signature verifies vs `Q` and matches `recId` expectations
  - Unit: low-s normalization behavior and `recId` parity flip correctness
  - Integration: digest computed in WASM == digest used in signing == raw tx verifies in an EVM client

## Risks and edge cases
- Import is inherently high-risk (clipboard, logging, crash dumps); must harden UI, disable analytics, and keep bytes inside wallet-origin + WASM worker.
- Key format ambiguity (NEAR 32 vs 64 bytes; ECDSA 0x-prefixed 32 bytes vs keystore JSON).
- Correctness pitfalls:
  - Ed25519 clamping/normalization rules for imported secret keys
  - ECDSA low-s normalization and recovery id (`recId`) parity handling
  - Chain-specific tx hashing domains (EIP-2718 typed prefixes; Tempo `0x76` domain)
- Operational:
  - Relay must treat imported keys as sensitive and isolate storage/ACLs; implement rotation/revocation.

## Open questions
- Do we require passkey re-auth (WebAuthn) before import, or is SecureConfirm UI approval sufficient?
- For ECDSA, do we require preprocessing (presigning) for latency, or accept slower online signing for MVP?
- For Tempo, do we need fee sponsorship / fee payer signatures in MVP import+threshold signing, or can we defer?
