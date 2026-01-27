# Lite Signer SDK Contract (v1)

This document defines the concrete “contract” between:
- **App origin** (untrusted app code)
- **Wallet origin** (wallet-iframe / extension origin; trusted boundary)
- **Relay/server** (WebAuthn verifier + threshold cosigner)

It is the implementation target for the lite-signer refactor in `docs/lite-signer-refactor/plan.md`.

## Goals
- Threshold signing first (2-party threshold **Ed25519** for NEAR).
- Remove VRF worker + `vrf-wasm`; replace VRF-WebAuthn with **standard WebAuthn assertion verification** on the relay.
- Keep wallet-origin isolation so app-origin code never receives PRF outputs or secret shares.
- No legacy/migration: this is a breaking cutover; re-onboarding required.


---

## Terminology
- `PRF.first`, `PRF.second`: 32-byte outputs from the WebAuthn PRF extension.
- `clientShareScalar`: the client’s threshold signing share scalar (secret).
- `clientVerifyingShare`: `G * clientShareScalar` (public; 32-byte Ed25519 compressed point).
- `clientVerifyingShareB64u`: base64url encoding of `clientVerifyingShare`.
- `sessionPolicy`: relay-scope policy describing a short-lived signing session (TTL + remainingUses).
- `sessionPolicyDigest32`: `sha256(alphabetizeStringify(sessionPolicy))` (32 bytes), base64url-encoded.
- `intentDigest`: canonical UI intent digest (schema identical to `sdk/src/core/digests/intentDigest.ts`).

All “B64u” strings are base64url without padding.

---

## Passkey PRF salts (v1)

These salts are fixed 32-byte values used with `extensions.prf.eval`:

- `PRF_FIRST_SALT_V1` (threshold share seed):
  - `sha256("tatchi/lite/prf/threshold-ed25519-client-share/v1")`
  - `0x400c318b6695973659a1698ae580dfd8001d9951ba32c695e6349947504f3f84`
- `PRF_SECOND_SALT_V1` (NEAR backup key seed):
  - `sha256("tatchi/lite/prf/near-backup-key/v1")`
  - `0x26da50e5ac964a7ea084527fb647f6330b32de51a9af46524b006d8f7fe7f4d1`

Versioning/rotation:
- Changing either salt is a **breaking key derivation change**; bump `vN` and treat as a new onboarding universe.
- `derivationPath` is the supported “soft rotation” knob (see below).

---

## Key derivations

### Threshold client share (Ed25519, v1)

Inputs:
- `prf_first_32`: 32 bytes (`PRF.first` evaluated with `PRF_FIRST_SALT_V1`)
- `nearAccountId`: UTF-8
- `derivationPath`: `u32` (default `0`)

Derive:
- `okm64 = HKDF-SHA256(ikm=prf_first_32, salt="tatchi/lite/threshold-ed25519/client-share:v1", info=nearAccountId || 0x00 || u32be(derivationPath), len=64)`
- `clientShareScalar = ed25519_scalar_from_wide(okm64)`; reject zero
- `clientVerifyingShare = (G * clientShareScalar).compress()`

Storage:
- Do not persist `clientShareScalar` at rest.
- Wallet origin may **cache in-memory** for the relay session TTL/remainingUses window.

### NEAR escape hatch / export key (v1)

Inputs:
- `prf_second_32`: 32 bytes (`PRF.second` evaluated with `PRF_SECOND_SALT_V1`)
- `nearAccountId`: UTF-8
- `derivationPath`: `u32` (default `0`)

Derive a standard Ed25519 keypair:
- `sk_bytes = HKDF-SHA256(ikm=prf_second_32, salt="tatchi/lite/near-backup-key:v1", info=nearAccountId || 0x00 || u32be(derivationPath), len=32)`
- Clamp/normalize per the chosen Ed25519 library requirements (MUST be deterministic and stable across platforms).
- `backup_pub_key = ed25519_public_key(sk_bytes)`

On-chain:
- Preferred (1 prompt): create the account with `backup_pub_key` as the initial full-access key, then have the client submit `AddKey(threshold_pub_key)` after validating the returned threshold key.
- Fallback: if the account was created with only the threshold key, adding `backup_pub_key` requires a threshold-signed `AddKey` (extra prompt).

Security note:
- This is intentionally **non-custodial**: the relay never derives or stores the backup private key.

---

## Relay API contract (threshold-ed25519)

### `POST /threshold-ed25519/keygen` (lite)

Purpose: create (or upsert) a 2-party threshold Ed25519 key on the relay, returning:
- the group/public key (NEAR `ed25519:<base58>`)
- the relay verifying share (public)
- an opaque `relayerKeyId` to reference the relay-held share in future signing sessions

Request body:
- `nearAccountId: string`
- `rpId: string`
- `keygenSessionId: string` (client-generated unique nonce/id)
- `clientVerifyingShareB64u: string` (base64url 32-byte Ed25519 compressed point)
- `webauthn_authentication: WebAuthnAuthenticationCredential` (standard assertion; PRF outputs MUST be redacted)

WebAuthn binding (challenge v1):
- The client MUST set `publicKey.challenge` to the raw 32-byte digest of:
  - `sha256(alphabetizeStringify({ version:"threshold_keygen_v1", nearAccountId, rpId, keygenSessionId }))`
- The relay verifies `expectedChallenge == base64url(digest32)` during assertion verification.

Response:
- `200`: `{ ok:true, relayerKeyId, publicKey, relayerVerifyingShareB64u, clientParticipantId, relayerParticipantId, participantIds }`
- `4xx/5xx`: `{ ok:false, code, message }`

### `POST /threshold-ed25519/session` (lite)

Purpose: mint a short-lived **threshold auth session** (JWT or httpOnly cookie).

Request body (lite):
- `sessionKind?: "jwt" | "cookie"` (default `"jwt"`)
- `relayerKeyId: string`
- `clientVerifyingShareB64u: string`
- `sessionPolicy: { version:"threshold_session_v1", nearAccountId, rpId, relayerKeyId, sessionId, participantIds?, ttlMs, remainingUses }`
- `webauthn_authentication: WebAuthnAuthenticationCredential` (standard assertion; PRF outputs MUST be redacted)

WebAuthn binding:
- The client MUST set `publicKey.challenge` to the **raw 32 bytes** of `sessionPolicyDigest32`.
- The relay verifies `expectedChallenge == base64url(sessionPolicyDigest32)`.

Response:
- `200`: `{ ok:true, sessionId, expiresAt, remainingUses, jwt? }`
- `4xx/5xx`: `{ ok:false, code, message }`

Replay/idempotency:
- The relay must treat `sessionId` as idempotent and must not extend TTL/uses if the session already exists.

### `POST /threshold-ed25519/authorize` (session-token mode)

Purpose: exchange a short-lived threshold session token for a one-time `mpcSessionId` bound to a **single 32-byte signing digest**.

Auth:
- `Authorization: Bearer <jwt>` (default), or httpOnly cookie mode.

Request body:
- `relayerKeyId: string`
- `clientVerifyingShareB64u: string`
- `purpose: "near_tx" | "nep461_delegate" | "nep413" | string`
- `signing_digest_32: number[32]`
- `signingPayload?: unknown` (purpose-specific payload the relay re-hashes to enforce intent binding)

Response:
- `200`: `{ ok:true, mpcSessionId, expiresAt }`
- `4xx/5xx`: `{ ok:false, code, message }`

### Signing rounds

The existing 2-round endpoints remain:
- `POST /threshold-ed25519/sign/init`
- `POST /threshold-ed25519/sign/finalize`

The signer worker is responsible for:
- computing the digest being co-signed
- requesting `/authorize` (or using a provided `mpcSessionId`)
- running the FROST rounds against the relay

---

## Client SDK API surface (wallet origin)

This is the minimal contract the lite SDK should expose (exact naming may vary):

### Session + share warm-up
- `connectPasskey({ nearAccountId, rpId, relayerUrl, relayerKeyId, participantIds?, sessionPolicy? })`
  - Collects a WebAuthn assertion (challenge = `sessionPolicyDigest32`) with PRF enabled.
  - Derives `clientShareScalar` from `PRF.first` and caches it in-memory for the session.
  - Calls `POST /threshold-ed25519/session` to mint the session token.
  - Returns `{ sessionId, expiresAtMs, remainingUses, jwt? }` and public `clientVerifyingShareB64u`.

### Signing
- `signNearTransactions({ transactions, relayerKeyId, sessionToken?, confirmationConfig? })`
  - Builds `intentDigest` (per `sdk/src/core/digests/intentDigest.ts`) and shows SecureConfirm UI in wallet origin.
  - Uses cached `clientShareScalar` + relay cosigning to produce NEAR signatures.
  - Returns only public signed artifacts to app origin.

### Escape hatch
- `enableNearEscapeHatch({ derivationPath? })`
  - Derives backup key from `PRF.second` (requires TouchID prompt).
  - Produces and submits an `AddKey(backup_pub_key)` transaction (threshold-signed).

---

## Open items (must be implemented before “v1 ready”)
- Hard cutover: remove VRF/Shamir/VRF-worker artifacts from build + exports.
- Decide whether to keep `sessionPolicyDigest32` as challenge long-term or add server-minted challenges.
