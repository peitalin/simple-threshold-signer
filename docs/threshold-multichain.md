# Multichain Threshold Signing Backend — Plan

This document maps out a backend architecture that supports threshold signing across multiple signature schemes (initially **Ed25519** and **ECDSA/secp256k1**) using a pluggable adapter model:

`ThresholdSignerAdapter -> SignatureType -> Signer`

The goal is to keep the backend **chain-agnostic** (“sign digest bytes”), while allowing different signature schemes to plug into the same session/auth, storage, and routing scaffolding. Adding a new scheme later should look like “implement one new adapter + wire it into the registry”.

---

## Goals
- Support **Ed25519** (existing 2P FROST) and **ECDSA/secp256k1** (new 2P threshold ECDSA) behind a common backend shape.
- Keep the backend “what to sign” agnostic:
  - backend signs canonical digests (32 bytes or scheme-specific), not chain transactions.
  - chain tx hashing/encoding stays in wallet-origin WASM workers.
- Preserve the existing trust boundary:
  - wallet-origin collects WebAuthn assertions and computes digests
  - relay verifies session/auth and contributes threshold shares
- Make it easy to add new schemes later (P256, Schnorr, etc.) without rewriting routers/stores.

## Non-goals
- Implementing multi-party (t-of-n) across *independent* trust domains in v1 (we keep 2-party externally: client + logical relayer).
- Implementing DKG and proactive refresh in v1 (we keep “dealer-split / derived shares” patterns where appropriate).

---

## High-level architecture

### 1) Adapter registry
Create a registry of enabled signature schemes:
- `ed25519` → existing `ThresholdEd25519Adapter`
- `secp256k1-ecdsa` → new `ThresholdEcdsaAdapter`

The router chooses an adapter based on a stable scheme identifier and dispatches to that adapter’s handlers.

### 2) Common request pipeline (scheme-agnostic)
All schemes share the same high-level pipeline:
1. **Key lifecycle**: keygen (or import) → store relay share + public verification material
2. **Authorization**:
   - `session` (mint JWT/cookie after WebAuthn verification)
   - `authorize` (per-intent digest authorization; optional if policy allows session-only)
3. **Signing** (multi-round protocol):
   - `/sign/init` → round 1 (commitments / nonce commitments / preprocessing selection)
   - `/sign/finalize` → round 2 (signature share contribution)
4. **Internal relayer-fleet cosigning** (optional):
   - coordinator fans out to cosigners via `/internal/cosign/*` to produce a single “logical relayer” contribution

### 3) Scheme-specific “Signer” module
Each adapter delegates cryptographic operations to a scheme-specific signer implementation:
- Ed25519: FROST rounds + aggregation (already present)
- ECDSA: threshold ECDSA protocol state machine (to be implemented)

The “Signer” is responsible for producing the relayer-side contribution (commitments/signature share) given:
- the relayer share material (resolved from keystore or derived from master secret)
- the signer set and transcript (session store)
- the signing digest bytes

---

## Identity: pluggable `LoginProvider` (Passkey, SSO, Wallet)

Threshold signing needs a strong, replay-safe authorization mechanism. Separately, product UX often wants:
- **Passkey login** (WebAuthn)
- **SSO** (e.g. “Sign in with Google”)
- **Wallet-based login** (EVM wallet signs a login message; commonly “SIWE” / EIP-4361 style)

The clean integration is to treat these as **login providers** that mint an **app session**, and then require **step-up** to mint a **threshold signing session**.

### `LoginProvider` model (conceptual)
All auth methods implement the same shape:
- `options(...)` (optional): return client-side parameters needed to perform the login ceremony
- `verify(...)`: verify the result and mint/refresh an app session
- `link(...)` / `unlink(...)`: attach or remove an identity from an existing `userId` (requires step-up)

Provider examples (initial set):
- `passkey` (WebAuthn)
- `sso.google` (OIDC)
- `wallet.eip155` (SIWE / EIP-4361)

Endpoint shape (one possible pattern):
- `POST /auth/:provider/options`
- `POST /auth/:provider/verify`
- `POST /auth/link` / `POST /auth/unlink` (step-up required)

### Core idea: two session layers
- **App session** (SSO / wallet login):
  - Grants access to app features and lets the user manage/link credentials.
  - Does *not* automatically grant signing rights.
- **Threshold signing session** (step-up):
  - Grants access to `/threshold-*/authorize` and `/threshold-*/sign/*`.
  - Binds to a specific signing scope (scheme, keyId/relayerKeyId, participantIds, rpId, expiry, remainingUses).
  - For Ed25519 threshold today, step-up is naturally **WebAuthn** (passkey), because the client share is derived from passkey PRF in the wallet origin.

### Data model: stable `userId` + linked identifiers
Move away from “`nearAccountId` is the user id” and instead store:
- `userId` (internal stable identifier)
- linked identities:
  - `webauthn:{credentialId}` (passkey)
  - `google:{sub}` (OIDC subject)
  - `eip155:{chainId}:{address}` (wallet address)
  - `near:{accountId}` (optional mapping)
  - WebAuthn credential metadata: public key, counters, rpId

This allows:
- Gmail SSO onboarding → register passkey → create threshold key(s)
- Wallet login onboarding → register passkey → create threshold key(s)
- Account linking between these providers with explicit user consent

### Passkey (WebAuthn) login integration
Passkeys can serve both roles:
- a primary **LoginProvider** (mint app session)
- the **step-up** mechanism (mint threshold signing sessions)

Typical backend flow:
1. `POST /auth/webauthn/options` → returns WebAuthn options (registration or authentication) and a nonce/challenge binding.
2. Client calls `navigator.credentials.create/get(...)` in the wallet origin.
3. `POST /auth/webauthn/verify` → relay verifies and mints **app session**.

Step-up for threshold signing:
- Use the same WebAuthn verification machinery, but mint a **threshold signing session** (`/threshold-*/session`) scoped to `(scheme, keyId/relayerKeyId, rpId, participantIds, expiry, remainingUses)`.

### Google SSO (OIDC) integration
Backend flow (typical OIDC):
1. `GET /auth/google/start` → redirects to Google with PKCE + state.
2. `GET /auth/google/callback` → verifies `state`, exchanges code, verifies `id_token`, extracts `sub` + email.
3. Relay creates/loads `userId`, mints **app session cookie/JWT**.

Security notes:
- Use OIDC `sub` as the stable identifier; email is display/secondary.
- Bind session cookies with `SameSite`, `Secure`, and CSRF protection for state-changing endpoints.

### “Sign in with wallet” (SIWE-style) integration
Backend flow (EIP-4361 style):
1. `POST /auth/siwe/options` → returns `{ nonce, domain, uri, chainId, issuedAt, expirationTime }`.
2. App asks wallet to sign the SIWE message (EIP-191 / `personal_sign`) using an injected EIP-1193 provider (e.g. MetaMask).
3. `POST /auth/siwe/verify` → relay verifies:
  - signature recovers `address`
  - message fields match expected domain/uri/nonce/expiry
  - nonce not reused (replay protection)
4. Relay creates/loads `userId` linked to `eip155:{chainId}:{address}`, mints **app session**.

Optional follow-on:
- If the user already has a passkey-based account, allow “link wallet” by requiring step-up (passkey) before attaching the address to that `userId`.

### Mapping auth → threshold signing
Rules of thumb:
- `/threshold-*/session` mints **threshold signing session** only after step-up.
  - For Ed25519 (NEAR): require WebAuthn verification because the client share is PRF-derived.
  - For ECDSA threshold: you can still require WebAuthn step-up for consistency, even if the ECDSA client share is stored locally (or derived differently).
- `/threshold-*/authorize` should accept either:
  - threshold session JWT/cookie (fast path), or
  - per-intent proof (slower path; still possible), but keep it scheme-agnostic.
- SSO/wallet login sessions should never be sufficient to call `/threshold-*/sign/*` directly.

---

## Interfaces (conceptual)

### Signature types
Define a stable internal union for “what the backend returns to the client coordinator”:
- `ed25519`:
  - relayer contribution is a FROST signature share (scheme-defined encoding)
- `secp256k1-ecdsa`:
  - relayer contribution is a threshold-ECDSA partial (scheme-defined encoding)
  - final output for the client should become a recoverable signature `r||s||recId` (or `yParity,r,s`)

### `ThresholdSignerAdapter`
Each adapter implements the same handler surface:
- `healthz()`
- `keygen(request)` (optional for some schemes if import-only)
- `importKey(request)` (optional; used by “import private key → threshold” flows)
- `session(request)` (mint threshold session token)
- `authorize(request, claims)` (optional per-intent gating)
- `signInit(request)` (round 1)
- `signFinalize(request)` (round 2)
- `internalCosignInit(request)` / `internalCosignFinalize(request)` (optional relayer-fleet)

### Common context provided to adapters
- `auth`: verify WebAuthn login / threshold session JWT
- `stores`: key store, session store, auth session store (scheme-aware prefixes)
- `clock`, `logger`, `rateLimit`, `env/config`

---

## Routing plan

### Option A (recommended): per-scheme route families
Keep scheme-specific route families (matches existing `/threshold-ed25519/*`):
- `/threshold-ed25519/*` (existing)
- `/threshold-ecdsa/*` (new; secp256k1 ECDSA)

Pros:
- clear operational boundaries
- stable, explicit endpoints
- easier config gating per scheme

### Option B: unified route family with `scheme` parameter
Use a single prefix and route by `scheme`:
- `/threshold/v1/:scheme/keygen`, etc.

Pros:
- fewer routers
Cons:
- more complex compatibility story; less explicit

For now, keep **Option A** and share implementation via adapter registry.

---

## Storage model (scheme-agnostic shell + scheme-specific payloads)

### Key records
Store per-user per-key threshold material (relay side):
- `keyId` (stable)
- `scheme` (`ed25519` | `secp256k1-ecdsa`)
- `userId` (today: `nearAccountId`) + `rpId`
- `participantIds` and version
- `publicKeyMaterial`:
  - ed25519: group public key (NEAR access key) + verifying shares
  - ecdsa: group public key (secp256k1) + derived address(es)
- `relayerShareMaterial` (encrypted at rest; or derivable)
- `derivationMode` (`kv` | `derived` | `auto`)

### Session records
Store signing transcripts keyed by `signingSessionId`:
- `scheme`
- `keyId` / `relayerKeyId`
- `participantIds` (signer set)
- `digest` (32 bytes) and metadata
- protocol round 1 messages (commitments/nonces)
- protocol round 2 messages (partials)
- TTL + replay protection

### Auth session records
Store threshold session counters/uses:
- `sessionId`, `scheme?` (optional), `keyId?` (optional)
- `rpId`, `userId`
- `remainingUses`, `expiresAtMs`
- “policy hash” for request binding (optional)

---

## Scheme plans

## Ed25519 (existing): keep behavior, refactor into adapter form
Ed25519 already exists as `/threshold-ed25519/*` with:
- keygen
- session minting
- authorize
- sign/init + sign/finalize
- optional coordinator/cosigner internal endpoints

Work required:
- extract the existing `ThresholdSigningService` into:
  - `ThresholdEd25519Adapter` (implements the adapter interface)
  - shared “adapter plumbing” (router+stores+auth wiring) that can host multiple adapters

## ECDSA/secp256k1 (new): add threshold ECDSA adapter and backend routes

### Phase 0: protocol selection + output contract
Decide:
- which 2-party threshold ECDSA protocol to implement (and its Rust implementation strategy)
- the stable “client-facing signature output” format:
  - `r(32) || s(32) || recId(1)` preferred (wallet can derive `yParity/v`)
- whether to require preprocessing/presigning for latency (recommended for production)

### Phase 1: implement `/threshold-ecdsa/*` skeleton with shared plumbing
- Add express + cloudflare routers mirroring the Ed25519 structure:
  - `/threshold-ecdsa/healthz`
  - `/threshold-ecdsa/session`
  - `/threshold-ecdsa/authorize`
  - `/threshold-ecdsa/sign/init`
  - `/threshold-ecdsa/sign/finalize`
  - `/threshold-ecdsa/internal/cosign/*` (optional; later)
- Add config + keystore/session store scaffolding:
  - prefixes and storage kinds mirroring Ed25519 (in-memory, redis, postgres, DO)
- For now, return explicit “not implemented” errors from signer steps while wiring auth + storage.

### Phase 2: implement threshold ECDSA signing (end-to-end)
- Implement relayer-side signer module:
  - resolves relayer share material for a given `keyId`
  - executes protocol rounds for `/sign/init` and `/sign/finalize`
  - returns relayer contribution needed for the client to finalize signature
- Implement transcript validation rules:
  - bind signature sessions to `(scheme, keyId, digest, participantIds, expiry)`
  - reject replays and transcript mismatches
- Add invariants:
  - low-s normalization requirements (if normalization can happen at finalize)
  - consistent recovery id rules

### Phase 3: key establishment for ECDSA
Support one or both:
- **Keygen**: create a new threshold ECDSA key (DKG-like or dealer-split)
- **Import**: convert an existing ECDSA private key into threshold shares (see `docs/import_threshold_private_keys.md`)

For v1, “import with client-known key” is the simplest:
- wallet-origin sees the private key, splits into shares, relay stores its share.

### Phase 4: relayer-fleet cosigning (optional but planned)
Mirror the Ed25519 “logical relayer participant” approach:
- coordinator is public-facing
- cosigners are internal-only
- coordinator fans out and combines cosigner partials into one relayer contribution for the client

This should be a mechanical repeat of the Ed25519 pattern once the ECDSA scheme supports combining internal partials.

---

## Cross-cutting concerns

### Auth and policy binding
Keep session auth orthogonal to scheme:
- threshold session JWT binds: `userId`, `rpId`, `expiresAtMs`, `participantIds`, `keyId/relayerKeyId`, and optionally `scheme`
- authorization endpoint binds a specific digest to a session (if required by policy)

### Observability
Standardize logs/metrics tags:
- `scheme`, `route`, `keyId`, `sessionId`, `signingSessionId`, `participantIds`, `nodeRole`

### Deployment and configuration
Add a top-level “enabled schemes” config concept:
- enable Ed25519 only (current)
- enable ECDSA only (testing)
- enable both

---

## Phased TODO list (backend)

### Phase 1 — Refactor ed25519 into adapter shell (no behavior change)
- [ ] Define a `ThresholdSignerAdapter` interface in server-core types.
- [ ] Wrap existing `ThresholdSigningService` behind `ThresholdEd25519Adapter`.
- [ ] Introduce an adapter registry and a shared router wiring layer.

### Phase 1.5 — Identity providers + step-up sessions
- [ ] Introduce a `LoginProvider` registry (passkey, google-oidc, wallet-siwe) and route `/auth/*` through it.
- [ ] Add app-session auth routes:
  - [ ] Passkey (WebAuthn) options/verify for app-session login.
  - [ ] Google OIDC (start/callback) or “verify id_token” (server-to-server) depending on deployment needs.
  - [ ] SIWE options/verify for wallet-based login.
- [ ] Add account-linking flows gated by step-up (passkey) to prevent takeover via a single provider.
- [ ] Split “app session” vs “threshold signing session” semantics in docs and middleware.

### Phase 2 — Add threshold-ecdsa scaffolding (no crypto yet)
- [ ] Add `/threshold-ecdsa/*` routes for both express + cloudflare.
- [ ] Add keystore/session/auth store prefixes and storage kind support.
- [ ] Add request/response types and status codes (mirroring ed25519 patterns).

### Phase 3 — Implement threshold ECDSA signing
- [ ] Choose protocol + implement relayer signer state machine.
- [ ] Implement `/threshold-ecdsa/sign/init` and `/threshold-ecdsa/sign/finalize`.
- [ ] Add digest-binding invariants + replay protections.

### Phase 4 — Key lifecycle (keygen + import)
- [ ] Add `keygen` and/or `keys/import` for ECDSA.
- [ ] Add key import for Ed25519 if needed by product (optional; see import doc).

### Phase 5 — End-to-end integration tests
- [ ] Ed25519: existing tests remain; add adapter-registry coverage.
- [ ] ECDSA: add harness tests that sign a known digest and verify signature.

---

## Testing and validation
- Unit:
  - request parsing/validation per adapter
  - transcript binding (digest/session/participantIds invariants)
  - signature correctness tests (ed25519 verify; ecdsa verify + recovery id)
- Integration:
  - wallet-origin computes digest in WASM and backend signs it
  - Tempo/EVM raw tx validates with an EVM client after attaching signature

---

## Risks and edge cases
- Threshold ECDSA protocol complexity and implementation maturity (largest risk).
- Correct handling of ECDSA low-s normalization and recovery id across the MPC protocol.
- Key import security (clipboard/logging/exfil) must remain wallet-origin only.
- Maintaining compatibility across both express and cloudflare deployments.
