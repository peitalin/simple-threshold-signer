# Multichain Threshold Signing Backend — Plan

This document maps out a backend architecture that supports threshold signing across multiple signature schemes (initially **Ed25519** and **ECDSA/secp256k1**) using a versioned, scheme-module model:

`Router (shared plumbing) -> schemeId -> SchemeModule -> ProtocolDriver`

Mental model:
- Router (shared plumbing) chooses `SchemeModule` by `schemeId`
- `SchemeModule` returns a `ProtocolDriver`
- `ProtocolDriver` runs MPC rounds + enforces transcript invariants
- Chain adapters stay client-side (wallet origin): they produce `SigningDigest` + UI model; backend only signs digests

The goal is to keep the backend **chain-agnostic** (“sign digest bytes”), while allowing different schemes to plug into the same auth/session, storage, and routing scaffolding. Adding a new scheme later should look like “implement one new `SchemeModule` + `ProtocolDriver`, then register it under a new `schemeId`”.

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
- Maintaining backwards compatibility with legacy threshold APIs/session tokens (clean switch).

---

## Compatibility policy (clean switch)
- Legacy support is not a priority. Prefer removing old entry points over keeping dual-mode fallbacks.
- When behavior must change, bump `schemeId` (e.g. add `...-v2`) instead of branching inside an existing scheme module.
- Plan deployments as breaking: update wallet-origin SDK + relayer(s) together.

---

## High-level architecture

### 1) Router + scheme registry (`schemeId` → `SchemeModule`)
Create a registry of enabled schemes (algorithm + protocol + version):
- `threshold-ed25519-frost-2p-v1` → `Ed25519Frost2pSchemeModule` (wrap existing Ed25519 threshold service)
- `threshold-secp256k1-ecdsa-2p-v1` → `Secp256k1Ecdsa2pSchemeModule` (new)

The router chooses a `SchemeModule` by `schemeId` (either implied by the route family, or explicitly passed in a unified routing variant) and dispatches to that module’s handlers.

### 2) Common request pipeline (scheme-agnostic)
All schemes share the same high-level pipeline:
1. **Key lifecycle**: keygen → store relay share + public verification material
2. **Authorization**:
   - `session` (mint JWT/cookie after WebAuthn verification)
   - `authorize` (per-intent digest authorization; optional if policy allows session-only)
3. **Signing** (multi-round protocol):
   - `/sign/init` → round 1 (commitments / nonce commitments / preprocessing selection)
   - `/sign/finalize` → round 2 (signature share contribution)
4. **Internal relayer-fleet cosigning** (optional):
   - coordinator fans out to cosigners via `/internal/cosign/*` to produce a single “logical relayer” contribution

### 3) `SchemeModule` → `ProtocolDriver`
Each `SchemeModule` owns scheme-specific orchestration:
- key material resolution/storage (keystore) and record shapes/prefixes
- key lifecycle entrypoints (`keygen` and optional `export` UX/API surfaces)
- session/auth flows (`session`, optional `authorize`)

It delegates MPC round logic to a `ProtocolDriver`, which is responsible for:
- `/sign/init` + `/sign/finalize` round logic
- transcript binding invariants: `(schemeId, keyId/relayerKeyId, digest, participantIds, expiry)` + replay protection
- producing the relayer-side contribution (commitments/partials) needed by the client coordinator

### 4) Chain adapters (client-side only)
Chain adapters live in the wallet-origin SDK (see `docs/multichain_adaptor.md`):
- build a canonical `SigningDigest` and a user-reviewable UI model
- finalize signatures into chain-specific artifacts (NEAR tx, EVM raw tx, etc.)
The backend never parses chain transactions.

---

## Identity: pluggable `LoginProvider` (Passkey + SSO)

Threshold signing needs a strong, replay-safe authorization mechanism. Separately, product UX often wants:
- **Passkey login** (WebAuthn)
- **SSO** (e.g. “Sign in with Google”)

The clean integration is to treat these as **login providers** that mint an **app session**, and then require **step-up** to mint a **threshold signing session**.

### `LoginProvider` model (conceptual)
All auth methods implement the same shape:
- `options(...)` (optional): return client-side parameters needed to perform the login ceremony
- `verify(...)`: verify the result and mint/refresh an app session
- `link(...)` / `unlink(...)`: attach or remove an identity from an existing `userId` (requires step-up)

Provider examples (initial set):
- `passkey` (WebAuthn)
- `sso.google` (OIDC)

Endpoint shape (one possible pattern):
- `POST /auth/:provider/options`
- `POST /auth/:provider/verify`
- `POST /auth/link` / `POST /auth/unlink` (step-up required)

### Core idea: two session layers
- **App session** (passkey / SSO):
  - Grants access to app features and lets the user manage/link credentials.
  - Does *not* automatically grant signing rights.
- **Threshold signing session** (step-up):
  - Grants access to `/threshold-*/authorize` and `/threshold-*/sign/*`.
  - Binds to a specific signing scope (schemeId, keyId/relayerKeyId, participantIds, rpId, expiry, remainingUses).
  - For Ed25519 threshold today, step-up is naturally **WebAuthn** (passkey), because the client share is derived from passkey PRF in the wallet origin.

### Data model: stable `userId` + linked identifiers
Move away from “`nearAccountId` is the user id” and instead store:
- `userId` (internal stable identifier)
- linked identities:
  - `webauthn:{credentialId}` (passkey)
  - `google:{sub}` (OIDC subject)
  - `near:{accountId}` (optional mapping)
  - WebAuthn credential metadata: public key, counters, rpId

This allows:
- Gmail SSO onboarding → register passkey → create threshold key(s)
- Account linking between these providers with explicit user consent

### Passkey (WebAuthn) login integration
Passkeys can serve both roles:
- a primary **LoginProvider** (mint app session)
- the **step-up** mechanism (mint threshold signing sessions)

Typical backend flow:
1. `POST /auth/passkey/options` → returns WebAuthn options (registration or authentication) and a nonce/challenge binding.
2. Client calls `navigator.credentials.create/get(...)` in the wallet origin.
3. `POST /auth/passkey/verify` → relay verifies and mints **app session**.

Step-up for threshold signing:
- Use the same WebAuthn verification machinery, but mint a **threshold signing session** (`/threshold-*/session`) scoped to `(schemeId, keyId/relayerKeyId, rpId, participantIds, expiry, remainingUses)`.

### Google SSO (OIDC) integration
Backend flow (two viable patterns):
1) **Redirect-based PKCE (classic OIDC)**
   1. `GET /auth/google/start` → redirects to Google with PKCE + state.
   2. `GET /auth/google/callback` → verifies `state`, exchanges code, verifies `id_token`, extracts `sub` + email.
   3. Relay creates/loads `userId`, mints **app session cookie/JWT**.

2) **`id_token` verify (server-side verify, no redirect endpoints)**
   1. Client completes OIDC with Google and obtains `id_token` (e.g. via Google Identity Services).
   2. `POST /auth/google/verify` → relay verifies signature (JWKS) + `aud` + time claims, extracts `sub` + email.
   3. Relay creates/loads `userId`, mints **app session cookie/JWT**.

Security notes:
- Use OIDC `sub` as the stable identifier; email is display/secondary.
- Bind session cookies with `SameSite`, `Secure`, and CSRF protection for state-changing endpoints.

### Mapping auth → threshold signing
Rules of thumb:
- `/threshold-*/session` mints **threshold signing session** only after step-up.
  - For Ed25519 (NEAR): require WebAuthn verification because the client share is PRF-derived.
  - For ECDSA threshold: you can still require WebAuthn step-up for consistency, even if the ECDSA client share is stored locally (or derived differently).
- `/threshold-*/authorize` should accept either:
  - threshold session JWT/cookie (fast path), or
  - per-intent proof (slower path; still possible), but keep it scheme-agnostic.
- App sessions should never be sufficient to call `/threshold-*/sign/*` directly.

---

## Interfaces (conceptual)

### Scheme identifiers (`schemeId`)
Use a stable, versioned scheme identifier (algorithm + protocol + version) to select behavior and storage namespaces:
- `threshold-ed25519-frost-2p-v1`
- `threshold-secp256k1-ecdsa-2p-v1`

### `SchemeModule`
Each scheme module is responsible for scheme-scoped orchestration and returns/owns the protocol driver:
- `schemeId`
- `healthz()`
- `keygen(request)` (optional)
- `exportKey(request)` (optional; wallet-origin mediated)
- `session(request)` (mint threshold session token; step-up required)
- `authorize(request, claims)` (optional per-intent gating)
- `signInit(request)` → delegates to `ProtocolDriver`
- `signFinalize(request)` → delegates to `ProtocolDriver`
- `internalCosignInit/Finalize` (optional relayer-fleet)

### `ProtocolDriver`
The protocol driver is MPC/crypto focused:
- runs `/sign/init` + `/sign/finalize` round logic
- validates transcript binding invariants (must bind `(schemeId, keyId/relayerKeyId, digest, participantIds, expiry)` and reject replays/mismatches)
- outputs the relayer-side contribution encoding required for the client coordinator

### Client-side chain adapters (out of backend)
Chain adapters stay client-side only: they produce `SigningDigest` bytes + UI model and finalize signatures into chain-specific outputs.

### Common context provided to scheme modules / protocol drivers
- `auth`: verify WebAuthn login / threshold session JWT
- `stores`: key store, session store, auth session store (schemeId-aware prefixes)
- `clock`, `logger`, `rateLimit`, `env/config`

---

## Routing plan

### Option A (recommended): per-scheme route families
Keep scheme-specific route families (matches existing `/threshold-ed25519/*`):
- `/threshold-ed25519/*` (existing)
- `/threshold-ecdsa/*` (new; secp256k1 ECDSA)
  - Each route family maps to a concrete `schemeId` (e.g. `/threshold-ed25519/*` → `threshold-ed25519-frost-2p-v1`).

Pros:
- clear operational boundaries
- stable, explicit endpoints
- easier config gating per scheme

### Option B: unified route family with `schemeId` parameter
Use a single prefix and route by `schemeId`:
- `/threshold/v1/:schemeId/keygen`, etc.

Pros:
- fewer routers
Cons:
- less explicit operational boundaries
- route-shape changes are treated as breaking (no legacy support)

For now, keep **Option A** and share implementation via the scheme registry + shared router plumbing.

---

## Storage model (scheme-agnostic shell + scheme-specific payloads)

### Key records
Store per-user per-key threshold material (relay side):
- `keyId` (stable)
- `schemeId` (e.g. `threshold-ed25519-frost-2p-v1` | `threshold-secp256k1-ecdsa-2p-v1`)
- `userId` (today: `nearAccountId`) + `rpId`
- `participantIds` and version
- `publicKeyMaterial`:
  - ed25519: group public key (NEAR access key) + verifying shares
  - ecdsa: group public key (secp256k1) + derived address(es)
    - client secret share derived deterministically from passkey PRF.first (wallet-origin only)
    - client sends only its public share / verifying material to the relay
- `relayerShareMaterial` (encrypted at rest; or derivable)
- `derivationMode` (`kv` | `derived` | `auto`)

### Session records
Store signing transcripts keyed by `signingSessionId`:
- `schemeId`
- `keyId` / `relayerKeyId`
- `participantIds` (signer set)
- `digest` (32 bytes) and metadata
- protocol round 1 messages (commitments/nonces)
- protocol round 2 messages (partials)
- TTL + replay protection

### Auth session records
Store threshold session counters/uses:
- `sessionId`, `schemeId?` (optional), `keyId?` (optional)
- `rpId`, `userId`
- `remainingUses`, `expiresAtMs`
- “policy hash” for request binding (optional)

---

## Scheme plans

## Ed25519 (existing): keep behavior, refactor into scheme-module form
Ed25519 already exists as `/threshold-ed25519/*` with:
- keygen
- session minting
- authorize
- sign/init + sign/finalize
- optional coordinator/cosigner internal endpoints

Work required:
- extract the existing `ThresholdSigningService` into:
  - `Ed25519Frost2pSchemeModule` (registered under a `schemeId`)
  - `Ed25519Frost2pProtocolDriver` (MPC rounds + transcript invariants)
  - shared router plumbing (auth+stores+request parsing) that can host multiple scheme modules

## ECDSA/secp256k1 (new): add threshold ECDSA scheme module + protocol driver + backend routes

### Phase 0: protocol selection + output contract
Decide:
- which 2-party threshold ECDSA protocol to implement (and its Rust implementation strategy)
- the stable “client-facing signature output” format:
  - `r(32) || s(32) || recId(1)` preferred (wallet can derive `yParity/v`)
- whether to require preprocessing/presigning for latency (recommended for production)

#### Chosen protocol (v1): NEAR `threshold-signatures` (Cait-Sith-derived OT-based ECDSA)
Use NEAR’s production-hardened Rust implementation as the reference protocol + codebase:
- Repo: `https://github.com/near/threshold-signatures` (MIT)
- Used by NEAR MPC node: `https://github.com/near/mpc` (see `near/mpc` `Cargo.toml` dependency on `near/threshold-signatures` pinned to a git rev)

Implementation choice:
- Default: **OT-based ECDSA** (`src/ecdsa/ot_based_ecdsa/*`) which NEAR describes as “originally imported from Cait-Sith and amended to meet industrial needs”.
- Keep **robust ECDSA** (`src/ecdsa/robust_ecdsa/*`) as a follow-on option or fallback if we want different security/perf tradeoffs.

Output contract mapping:
- `threshold-signatures` exposes ECDSA signatures as `{ big_r: AffinePoint, s: Scalar }` with `s` normalized low (see `src/ecdsa/mod.rs` in `near/threshold-signatures`).
- Our backend contract stays `r(32)||s(32)||recId(1)`:
  - `r = x_coordinate(big_r)` (32 bytes)
  - `s` is already low-s normalized by the protocol
  - `recId`/`yParity` derived from `big_r`:
    - `yParity = is_odd(big_r.y)` (0/1) and flips when `s` is normalized (`s -> n-s`)
    - if we choose a “full” recover-id byte (0–3), include the “x overflow” bit (whether `big_r.x >= n`) as well; if we only need EVM `yParity`, we can drop that bit

**References (NEAR)**
- `near/mpc` overview + “triples/presign/sign” production pipeline: `https://raw.githubusercontent.com/near/mpc/fdb528f7fc4c151fae73b8a6f291ee166d2d9491/AGENTS.md`
- `near/mpc` pins `near/threshold-signatures` as a git dependency (rev shown in workspace `Cargo.toml`): `https://raw.githubusercontent.com/near/mpc/fdb528f7fc4c151fae73b8a6f291ee166d2d9491/Cargo.toml`
- `near/threshold-signatures` protocol overview + audit note: `https://raw.githubusercontent.com/near/threshold-signatures/db609be5021eb9d794f577601f422818fbdfe246/README.md`
- OT-based ECDSA entrypoints:
  - Keygen/reshare: `https://raw.githubusercontent.com/near/threshold-signatures/db609be5021eb9d794f577601f422818fbdfe246/src/lib.rs`
  - Triples: `https://github.com/near/threshold-signatures/tree/db609be5021eb9d794f577601f422818fbdfe246/src/ecdsa/ot_based_ecdsa/triples`
  - Presign: `https://raw.githubusercontent.com/near/threshold-signatures/db609be5021eb9d794f577601f422818fbdfe246/src/ecdsa/ot_based_ecdsa/presign.rs`
  - Sign: `https://raw.githubusercontent.com/near/threshold-signatures/db609be5021eb9d794f577601f422818fbdfe246/src/ecdsa/ot_based_ecdsa/sign.rs`
  - Signature type + low-s verification: `https://raw.githubusercontent.com/near/threshold-signatures/db609be5021eb9d794f577601f422818fbdfe246/src/ecdsa/mod.rs`
  - Participant id → scalar mapping + Lagrange helpers: `https://raw.githubusercontent.com/near/threshold-signatures/db609be5021eb9d794f577601f422818fbdfe246/src/participants.rs`

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
  - bind signature sessions to `(schemeId, keyId, digest, participantIds, expiry)`
  - reject replays and transcript mismatches
- Add invariants:
  - low-s normalization requirements (if normalization can happen at finalize)
  - consistent recovery id rules

### Phase 3: key establishment for ECDSA
Product decision: keygen-only (no private-key import path).
- **Keygen**: create a new threshold ECDSA key (DKG-like or dealer-split)
- **Export (optional)**: wallet-origin backup/export flow for key material metadata or recovery package.

For v1, “deterministic 2-share keygen” is the simplest and matches the ed25519 mental model:
- Client share is derived deterministically from passkey `PRF.first` (wallet-origin only).
- Relayer share is derived deterministically from `THRESHOLD_SECP256K1_MASTER_SECRET_B64U`.
- No secret share is ever transmitted; only the client verifying share is sent to the relay.
- Group public key is computed as `clientPub + relayerPub` (compressed secp256k1).

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
- threshold session JWT binds: `userId`, `rpId`, `expiresAtMs`, `participantIds`, `keyId/relayerKeyId`, and `schemeId`
- authorization endpoint binds a specific digest to a session (if required by policy)

### Observability
Standardize logs/metrics tags:
- `schemeId`, `route`, `keyId`, `sessionId`, `signingSessionId`, `participantIds`, `nodeRole`

### Deployment and configuration
Add a top-level “enabled schemes” config concept:
- enable Ed25519 only (current)
- enable ECDSA only (testing)
- enable both

---

## Phased TODO list (backend)

### Phase 1 — Refactor ed25519 into scheme-module shell (no behavior change)
- [x] Define `SchemeModule` + `ProtocolDriver` interfaces in server-core types.
- [x] Wrap existing `ThresholdSigningService` behind an Ed25519 `SchemeModule` (registered under a `schemeId`).
- [x] Introduce a scheme registry and shared router plumbing that dispatches by `schemeId`.

### Phase 1.5 — Identity providers + step-up sessions
- [x] Hard-cut passkey auth to `/auth/passkey/*` (no `/login/*` compatibility).
- [x] Introduce a `LoginProvider` registry (passkey, google-oidc) and route `/auth/*` through it.
- [x] Add a durable identity map (`subject` → `userId`, `userId` → linked identities) backed by the same persistence layer as threshold stores.
- [x] Add app-session auth routes:
  - [x] Passkey (WebAuthn) options/verify for app-session login (`/auth/passkey/options`, `/auth/passkey/verify`).
  - [x] Google OIDC “verify id_token” (`/auth/google/verify`) with JWKS signature verification + `aud` checks.
- [x] Add account-linking flows gated by step-up (passkey) to prevent takeover via a single provider.
  - Linking/unlinking refers to attaching/detaching additional identity providers to the same `userId`
    (e.g. `google:{sub}`, `near:{accountId}`), not “SSO” specifically.
  - Unlink should require step-up and should refuse to remove the last remaining auth factor.
  - Implemented: `/auth/identities` (list), `/auth/link`, `/auth/unlink` (step-up required via passkey).
- [x] Split “app session” vs “threshold signing session” tokens via a `kind` claim + middleware checks (token confusion mitigation).
- [x] Default threshold sessions to JWTs (Authorization header); optionally set HttpOnly cookies when `sessionKind: "cookie"`.

#### Next steps (Phase 1.5)
- [x] Add app-session revocation rules for removed identities: include an `appSessionVersion` claim in app-session JWTs and validate it server-side; rotate it on `/auth/unlink` and reissue the caller’s session.
- Optional: add redirect-based Google OIDC (`/auth/google/start`, `/auth/google/callback`) for deployments that can’t/do not want to use client-side `id_token` flows.
- If cookies are used broadly: add CSRF protection for state-changing endpoints and standardize cookie flags (`Secure`, `HttpOnly`, `SameSite`).
- Consider “merge accounts” UX when linking a subject already linked to a different user (currently allowed only when that subject is the other user’s sole identity).

### Cleanup — Prune deprecated auth code paths
- [x] Remove deprecated (unwired) routes (`webauthnLogin.ts` in express + cloudflare).
- [x] Remove SIWE (wallet login) endpoints and supporting code (`/auth/siwe/*`, nonce store, SIWE parsing helpers).
- [x] Remove any remaining legacy auth route references in docs/tests/examples.

### Phase 2 — Add threshold-ecdsa scaffolding (no crypto yet)
- [x] Add `/threshold-ecdsa/*` routes for both express + cloudflare.
- [x] Add `THRESHOLD_SECP256K1_MASTER_SECRET_B64U` config for deterministic relayer shares (stateless key material).
- [x] Implement `/threshold-ecdsa/session` and `/threshold-ecdsa/authorize` (WebAuthn step-up + session/token scope + mpcSessionId minting).
- [x] Add ECDSA keystore/session/auth store prefixes + store wiring (`THRESHOLD_ECDSA_{KEYSTORE,SESSION,AUTH}_PREFIX`) so ECDSA state does not collide with Ed25519.
- [x] Add request/response types and status codes (mirroring ed25519 patterns).

### Phase 3 — Implement threshold ECDSA signing
- [x] Choose protocol: NEAR `threshold-signatures` (OT-based ECDSA; Cait-Sith-derived).
- [x] Implement relayer signer state machine.
- [x] Client share derivation: derive secp256k1 client share deterministically from PRF.first (HKDF domain-separated by `schemeId` + key path).
- [x] Implement `/threshold-ecdsa/presign/init` and `/threshold-ecdsa/presign/step` (relay-side; interactive with wallet-origin).
- [x] Implement `/threshold-ecdsa/sign/init` and `/threshold-ecdsa/sign/finalize`.
- [x] Implement relay-side presignature pool management (reserve, consume, discard) and wire it into `/threshold-ecdsa/sign/*` (v1: in-memory).
- [x] Add digest-binding invariants + replay protections (mpc session + signing session scoping + single-use “take” semantics).
- [x] Implement wallet-origin presignature share pool coordinator (refill, reserve, consume; handles `pool_empty` backpressure).

#### Next steps (Phase 2/3)
- [x] Add high-level SDK wrappers for key lifecycle/session bootstrap (`keygenThresholdEcdsaLite` + `connectThresholdEcdsaSessionLite`) so apps can avoid manual helper wiring.
- [x] Expand multichain signer abstractions so `threshold-ecdsa-secp256k1` can be selected as a first-class engine where needed.
- [x] Make the relay presignature pool + signing-session store durable for production (Redis/Postgres/DO) with atomic reserve/consume semantics.
- Add end-to-end tests for threshold-ecdsa signing flows (pool empty/refill, replay, expiry, wrong-scope failures).
- Add CI guardrails for `wasm/eth_signer` builds (C toolchain for `blst` on wasm32) and verify server runtime WASM loading works in both Node and Workers.

#### Keygen/share format alignment (for `near/threshold-signatures`)
`near/threshold-signatures` is built around Shamir-style threshold shares: each participant holds a scalar share and the protocol “linearizes” shares using Lagrange coefficients computed from participant identifiers (see `participants.lagrange(..)` usage in `src/ecdsa/ot_based_ecdsa/*` and `src/ecdsa/robust_ecdsa/sign.rs`).

We currently derive **2-party additive/linear shares**:
- client derives `x_client` from passkey PRF.first (wallet origin)
- relayer derives `x_relayer` from `THRESHOLD_SECP256K1_MASTER_SECRET_B64U` (relay)
- group secret is `x = x_client + x_relayer (mod n)` and public key is `X = x·G`

Options to align:
1) **Adopt NEAR DKG keygen (store shares)** (most “canonical”):
   - Run `threshold-signatures` keygen for secp256k1 during `/threshold-ecdsa/keygen`.
   - Persist each party’s `SigningShare` (client in wallet-origin storage; relayer in relay storage).
   - Pros: matches NEAR assumptions; supports future n-of-t relayer-fleet; enables refresh/reshare cleanly.
   - Cons: adds a multi-round keygen; requires durable secret-share storage; gives up “stateless derived relayer share”.
2) **Keep derived shares + encode them as Shamir shares for a fixed 2-party signer set** (fastest path for 2P):
   - Treat derived shares as the *linearized* shares the protocol wants after Lagrange weighting.
   - For a fixed 2-party signer set, compute Lagrange coefficients `λ_client`, `λ_relayer` at 0 for those participant ids.
   - Define the Shamir-form shares fed into `threshold-signatures` as:
     - `share_client = x_client * inv(λ_client)`
     - `share_relayer = x_relayer * inv(λ_relayer)`
   - Then protocol linearization (`λ_i * share_i`) recovers the original derived share contributions, and the combined secret remains `x_client + x_relayer`.
   - Pros: keeps our existing PRF-first + master-secret derivation model; avoids new keygen rounds; preserves stateless relayer-share derivation.
   - Cons: only safe if the signer set used by the protocol is stable and agreed ahead of time; if we later vary signer subsets (multi-relayer), the Lagrange weights change and this mapping must be redesigned.

Decision (v1):
- Use **option 2** with a fixed signer set and deterministic shares (to match our existing threshold-ed25519 derived-share model).
- Fix participant ids for the ECDSA protocol as: `client=1`, `relayer=2` (to match our existing 2P signer set conventions).
  - `near/threshold-signatures` maps `id -> (id+1)` as the Shamir x-coordinate scalar, so `{1,2}` maps to x-coordinates `{2,3}`.
- For `{2,3}` the Lagrange coefficients at `0` are constant:
  - `λ_client = 3`, `λ_relayer = -2`
  - so `share_client = x_client * inv(3)` and `share_relayer = x_relayer * inv(-2) = -(x_relayer * inv(2))` (all mod secp256k1 scalar order)
- Keep storing/verifying **additive** public shares for binding (`X_client = x_client·G`, `X_relayer = x_relayer·G`, `X = X_client + X_relayer`), and derive the `threshold-signatures` share encoding on demand inside the ECDSA scheme.
- Key rollover: rotate by deriving a new deterministic key path/version (PRF.first + HKDF domain separation includes `schemeId` + `keyId`/`keyVersion`), and invalidate any outstanding presignatures for the old key.

#### Presignature pool (why it matters)
NEAR’s production design (and the Cait-Sith lineage) separates ECDSA signing into:
- **Offline:** triple generation (expensive, key-independent) → presignature generation (expensive, key-dependent but message-independent)
- **Online:** sign a message hash using a presignature (cheap, low-latency)

A presignature pool is the operational mechanism for this split:
- Keep a rolling buffer of “ready” presignatures per key (and optionally a larger pool of key-independent triples).
- Consume exactly one presignature per signature request (never reuse), with strict accounting/replay protection.
- For a 2-party **wallet (client) ↔ relayer** signer set, both parties must hold a synchronized pool of presignature *shares*; refills typically happen at login/warm-session time (when the wallet origin is online).

Benefits:
- Makes `/threshold-ecdsa/sign/*` fast enough for wallet UX (no heavy offline work on the critical path).
- Smooths CPU/network load (generate in background, sign in bursts).
- Improves reliability under concurrency (signing doesn’t stall waiting for triple generation).
- Gives clear operational SLO knobs: pool size, refill thresholds, and backpressure when empty.

Decision (v1):
- Run a presignature pool.
- Relayer storage: in-memory is acceptable only for local dev/tests; production should use a durable store (Redis/Postgres/DO) with strict one-time-consumption semantics.
- Wallet-origin storage: keep the client’s presignature share pool in-memory inside the wallet-origin worker and refill opportunistically (e.g. at login/warm-session time); if we need reload-resilience, persist encrypted-at-rest in wallet-origin storage.

Pool semantics (v1):
- A presignature item is identified by `presignatureId` and exists as **two shares** (client + relayer) generated by the same interactive presign protocol run.
- Reservation/consumption is server-coordinated:
  - `/threshold-ecdsa/sign/init` reserves a `presignatureId` for the signing session (or triggers a refill if empty), and returns the relayer message(s) for the online signing step.
  - `/threshold-ecdsa/sign/finalize` consumes the reserved presignature and returns the final `r||s||recId` signature. On any protocol failure, discard the reserved presignature on both sides (never “return to pool”).
- Concurrency: pool operations must be atomic per key (`LPOP`-style semantics in Redis, or transactions in SQL) to prevent double-spend of a presignature.

NEAR’s `mpc` docs explicitly call out background triple generation and presignature consumption patterns (see the `near/mpc` `AGENTS.md` reference above).

### Phase 4 — Key lifecycle (keygen + export)
- [x] Add `keygen` for ECDSA (`POST /threshold-ecdsa/keygen`, deterministic derived shares).
- [x] Add key export flow for ECDSA (optional; wallet-origin only).
- [x] Add key export flow for Ed25519 if needed by product (optional).

### Phase 5 — End-to-end integration tests
- [x] Ed25519: existing tests remain; add scheme registry + dispatch coverage.
- [x] ECDSA: add harness tests that sign a known digest and verify signature.
- [x] ECDSA: add high-level API flow tests for secp256k1 happy path, missing/expired session failure, `pool_empty` refill/retry, and PRF/key mismatch failure.
- [x] ECDSA: add one e2e flow covering keygen -> connect session -> Tempo threshold signing.

---

## Phased TODO list (wallet-origin SDK)

### Phase A — ECDSA sessions (no signing yet)
- [x] Add `ThresholdEcdsaSessionPolicy` + digest builder (WebAuthn challenge = policy digest).
- [x] Add `connectThresholdEcdsaSessionLite` (derive `clientVerifyingShareB64u` from PRF.first; mint `/threshold-ecdsa/session`).
- [x] Add an `authorize` helper (`POST /threshold-ecdsa/authorize`) and integrate it into client-side chain adapters.

### Phase B — ECDSA signing integration
- [x] Implement the wallet-origin coordinator for `/threshold-ecdsa/presign/*` + `/threshold-ecdsa/sign/*` (client presign-share pool + finalize).
- [x] Expose a dedicated high-level API entrypoint for Tempo threshold-ECDSA signing (`signTempoWithThresholdEcdsa`).
- [x] Add first-class threshold-ECDSA session bootstrap API on `TatchiPasskey` (`bootstrapThresholdEcdsaSession`: keygen + connect + keyRef return).

---

## Testing and validation
- Unit:
  - request parsing/validation per scheme module
  - transcript binding (digest/session/participantIds invariants)
  - signature correctness tests (ed25519 verify; ecdsa verify + recovery id)
- Integration:
  - wallet-origin computes digest in WASM and backend signs it
  - Tempo/EVM raw tx validates with an EVM client after attaching signature

---

## Risks and edge cases
- Threshold ECDSA protocol complexity and implementation maturity (largest risk).
- Correct handling of ECDSA low-s normalization and recovery id across the MPC protocol.
- Key export security (clipboard/logging/exfil) must remain wallet-origin only.
- Maintaining parity across both express and cloudflare deployments.
- Token confusion: enforce `kind`-based checks so app-session tokens can’t access `/threshold-*/session|authorize|sign/*`, and threshold-session tokens can’t be treated as app sessions; preserve claims on refresh and use `appSessionVersion` checks for server-side revocation.
- Session transport: JWT is the default; if using HttpOnly cookies, require CSRF defenses + `Secure`/`SameSite` correctness for any state-changing endpoints.
- Hard cutovers: older clients/old auth routes (e.g. `/login/*` vs `/auth/passkey/*`) and old session-token formats will fail; coordinate deploys.
- Account linking/unlinking: always gate by step-up (passkey) to prevent takeover via a single provider; enforce “unlink” safety rules (can’t remove last factor; revoke related app sessions via `appSessionVersion` rotation).
