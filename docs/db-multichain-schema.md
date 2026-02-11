# DB Multichain Schema Refactor Plan

Status: Draft  
Last updated: 2026-02-12

## Scope

Refactor IndexedDB persistence so account, key, and derived-address storage are chain-agnostic while preserving compatibility with current NEAR flows.

In scope:
- `client/src/core/IndexedDBManager/passkeyClientDB.ts`
- `client/src/core/IndexedDBManager/passkeyNearKeysDB.ts`
- `client/src/core/IndexedDBManager/index.ts`
- Call sites that currently require `nearAccountId`-first APIs
- Signing facade + orchestrators under:
  - `client/src/core/signing/api/*`
  - `client/src/core/signing/chains/*`
  - `client/src/core/signing/engines/*`
  - `client/src/core/signing/orchestration/*`
  - `client/src/core/signing/workers/*`
  - `client/src/core/signing/secureConfirm/*`
  - `client/src/core/signing/webauthn/*`
  - `client/src/core/workers/*`

Out of scope:
- Server-side schema changes
- Relayer API contract changes (except optional additive fields)

## Repository Structure Alignment (2026-02-12)

The plan targets the refactored signing layout currently in this repo:

- Public signing API:
  - `client/src/core/signing/api/WebAuthnManager.ts`
  - `client/src/core/signing/api/userPreferences.ts`
- Chain orchestration + handlers:
  - `client/src/core/signing/chains/{near,evm,tempo}/*`
  - `client/src/core/signing/chains/near/handlers/*`
  - `client/src/core/signing/chains/tempo/handlers/*`
- Intent orchestration:
  - `client/src/core/signing/orchestration/executeSigningIntent.ts`
  - `client/src/core/signing/orchestration/types.ts`
  - `client/src/core/signing/orchestration/walletOrigin/*`
- Signing engines:
  - `client/src/core/signing/engines/*`
- WebAuthn utilities:
  - `client/src/core/signing/webauthn/{credentials,cose,prompt,device,fallbacks}/*`
- Secure confirm flow:
  - `client/src/core/signing/secureConfirm/*`
  - `client/src/core/signing/secureConfirm/confirmTxFlow/adapters/*`
  - `client/src/core/signing/secureConfirm/ui/lit-components/*`
- Worker managers and worker RPC:
  - `client/src/core/signing/workers/*`
  - `client/src/core/signing/workers/signerWorkerManager/{internal,keyOps}/*`
- Browser worker entrypoints:
  - `client/src/core/workers/passkey-confirm.worker.ts`
  - `client/src/core/workers/{near-signer,eth-signer,tempo-signer}.worker.ts`

Migration work should prioritize these paths first and treat legacy `client/src/core/WebAuthnManager/*` modules as compatibility surfaces only.

## Why This Refactor

Current storage is NEAR-anchored at the schema level:
- Primary keys and indexes are keyed by `nearAccountId`.
- Core user record stores `clientNearPublicKey` as a first-class field.
- Key material DB types are NEAR-only (`local_near_sk_v3`, `threshold_ed25519_2p_v1`).
- Derived addresses are partially generalized, but still keyed by `[nearAccountId, contractId, path]`.

This blocks clean support for EVM/Tempo and creates ongoing coupling in application APIs.

## Goals

- Add chain-agnostic identity and key material storage.
- Support multi-signer accounts by default across NEAR and EVM.
- Treat EVM smart accounts (ERC-4337) as the default account model for account-level signer management.
- Preserve current NEAR behavior during migration.
- Avoid destructive migrations and data loss.
- Provide a clear cutover path from NEAR-specific APIs to generic APIs.
- Keep runtime compatibility with wallet iframe mode and legacy mode.

## Non-Goals

- Rewriting all signing handlers in one pass.
- Removing NEAR-specific methods immediately.
- Introducing breaking SDK API changes in the first migration release.

## Design Principles

- Prefer additive schema changes first, destructive cleanup last.
- Support dual-read/dual-write during transition.
- Model account ownership as `account -> many signers` for all chains.
- Treat `deviceNumber` as a wallet-local signer slot, not chain-specific protocol state.
- Use explicit chain metadata in keys (do not encode chain into opaque path strings).
- Keep chain-specific validation/normalization in adapters, not DB manager internals.
- Keep migrations idempotent and resumable.

## Proposed Canonical Identifiers

Use CAIP-style references where practical.

```ts
type ProfileId = string;            // wallet-local user/profile id (uuid-like)
type DeviceNumber = number;         // existing 1-indexed signer slot (legacy name)
type ChainId = string;              // e.g. "near:testnet", "eip155:1", "tempo:testnet"
type AccountAddress = string;       // chain-native address/account string
type SignerId = string;             // stable signer identifier per account

interface AccountRef {
  profileId: ProfileId;
  chainId: ChainId;
  accountAddress: AccountAddress;
}
```

Notes:
- `ProfileId` becomes the wallet-internal anchor instead of `nearAccountId`.
- A profile can own multiple chain accounts.
- `deviceNumber` remains for compatibility, but semantically represents a local signer slot.

## Multi-signer Account Model (Default)

- NEAR already supports multiple signers per account; the new schema preserves this as the baseline model.
- EVM should follow the same model via ERC-4337 smart accounts (multiple owners/signers/modules).
- Device linking and email recovery are modeled as signer-management operations:
  - Link device = add signer to an existing account.
  - Email recovery = add/activate recovery signer (or rotate signer set) on an existing account.
- EOAs (`eip155` externally owned accounts) can still be supported for basic flows, but do not support true account-level multi-signer semantics without moving to a smart account.

## Chain Capability Matrix (Constraint Baseline)

| `accountModel` | Multi-signer | Add/remove signer | Session signer | Recovery signer |
| --- | --- | --- | --- | --- |
| `near-native` | Yes | Yes | Adapter-defined | Yes |
| `erc4337` | Yes | Yes | Yes | Yes |
| `eoa` | No (single signer) | No (requires account migration) | No | No |
| `tempo-native` | Adapter-defined | Adapter-defined | Adapter-defined | Adapter-defined |

Rules:
- Feature enablement must be derived from `(chainId, accountModel)` and not from UI assumptions.
- Attempting unsupported signer operations must fail early with typed capability errors.

## Hard Invariants

- `I1`: One `chainAccounts` row per unique `["profileId", "chainId", "accountAddress"]`.
- `I2`: At most one `isPrimary=true` account per `["profileId", "chainId"]`.
- `I3`: For a given `["chainId", "accountAddress"]`, each active signer has a unique `signerSlot`.
- `I4`: If `keyMaterialV2.signerId` is set, matching `accountSigners` row must exist.
- `I5`: `accountModel="eoa"` must have at most one active signer.
- `I6`: `status="revoked"` requires `removedAt` timestamp.
- `I7`: `lastProfileState` must reference an existing profile and signer slot.

## Signer Lifecycle State Machine

States:
- `pending`
- `active`
- `revoked`

Allowed transitions:
- `pending -> active` (on-chain confirmation or final local commit)
- `pending -> revoked` (cancelled/failed setup)
- `active -> revoked` (explicit revoke/rotation)

Forbidden transitions:
- `revoked -> active` (must create a new signer record)
- direct `active -> pending`

## Target Schema

## 1) `PasskeyClientDB` (next version)

Keep existing stores for compatibility; add new stores:

### `profiles` store
- Key path: `profileId`
- Fields:
  - `profileId`
  - `defaultDeviceNumber`
  - `passkeyCredential` (existing shape)
  - `preferences` (global preferences)
  - `createdAt`, `updatedAt`
- Indexes:
  - `updatedAt`

### `profileAuthenticators` store
- Key path: `["profileId", "deviceNumber", "credentialId"]`
- Fields:
  - `profileId`, `deviceNumber`, `credentialId`, `credentialPublicKey`, `transports`, `name`, `registered`, `syncedAt`
- Indexes:
  - `profileId`
  - `credentialId`

### `chainAccounts` store
- Key path: `["profileId", "chainId", "accountAddress"]`
- Fields:
  - `profileId`, `chainId`, `accountAddress`
  - `accountModel` (`near-native`, `erc4337`, `eoa`, `tempo-native`, ...)
  - `isPrimary` (for chain-specific default)
  - `createdAt`, `updatedAt`
  - Optional compatibility fields: `legacyNearAccountId`
- Indexes:
  - `chainId`
  - `["chainId", "accountAddress"]`
  - `["profileId", "chainId"]`

### `accountSigners` store
- Key path: `["chainId", "accountAddress", "signerId"]`
- Fields:
  - `profileId`, `chainId`, `accountAddress`
  - `signerId`
  - `signerSlot` (maps to legacy `deviceNumber`)
  - `signerType` (`passkey`, `threshold`, `session`, `recovery`)
  - `status` (`active`, `pending`, `revoked`)
  - `addedAt`, `updatedAt`, `removedAt?`
  - `metadata` (chain/account-model-specific details, e.g. ERC-4337 owner module ref)
- Indexes:
  - `profileId`
  - `["profileId", "chainId"]`
  - `["chainId", "accountAddress"]`
  - `["chainId", "accountAddress", "status"]`

### `signerOpsOutbox` store
- Purpose:
  - Durable queue for signer mutations requiring async/on-chain confirmation.
  - Guarantees retry and idempotency across reloads/crashes.
- Key path: `opId`
- Fields:
  - `opId` (uuid)
  - `idempotencyKey`
  - `opType` (`add-signer`, `revoke-signer`, `activate-recovery-signer`)
  - `chainId`, `accountAddress`, `signerId`
  - `payload`
  - `status` (`queued`, `submitted`, `confirmed`, `failed`, `dead-letter`)
  - `attemptCount`, `nextAttemptAt`, `lastError?`, `txHash?`
  - `createdAt`, `updatedAt`
- Indexes:
  - `status`
  - `nextAttemptAt`
  - `idempotencyKey` (unique)
  - `["chainId", "accountAddress"]`

### `derivedAddressesV2` store
- Key path: `["profileId", "sourceChainId", "sourceAccountAddress", "targetChainId", "path"]`
- Fields:
  - `profileId`
  - `sourceChainId`, `sourceAccountAddress`
  - `targetChainId`
  - `providerRef` (replaces NEAR-only `contractId`; can still hold NEAR contract id)
  - `path`
  - `address`
  - `updatedAt`
- Indexes:
  - `["profileId", "targetChainId"]`
  - `["sourceChainId", "sourceAccountAddress"]`

### `recoveryEmailsV2` store
- Key path: `["profileId", "hashHex"]`
- Fields:
  - `profileId`, `hashHex`, `email`, `addedAt`
- Indexes:
  - `profileId`

### `appState` additions
- `lastProfileState`:
  - `{ profileId, deviceNumber, scope? }`
- Migration flags:
  - `migration.dbMultichainSchema.v1 = { status, startedAt, finishedAt, counts }`
- Migration lock/meta:
  - `migration.dbMultichainSchema.v1.lock = { ownerTabId, acquiredAt, heartbeatAt }`
  - `migration.dbMultichainSchema.v1.checkpoints = { storeName: { lastKey, completedAt } }`

## 2) `PasskeyNearKeysDB` -> chain-capable key store

Option A (preferred near-term): keep DB name, add V2 store in same DB.  
Option B (later cleanup): rename class/file to `passkeyChainKeysDB.ts`.

### `keyMaterialV2` store
- Key path: `["profileId", "deviceNumber", "chainId", "keyKind"]`
- Fields:
  - `profileId`, `deviceNumber`, `chainId`
  - `signerId` (joins to `accountSigners`; optional during migration)
  - `algorithm` (`ed25519`, `secp256k1`, ...)
  - `keyKind` (`local_sk_encrypted_v1`, `threshold_share_v1`, ...)
  - `publicKey`
  - `wrapKeySalt?`
  - `payload` (chain/scheme-specific object)
  - `timestamp`, `schemaVersion`
- Indexes:
  - `["profileId", "deviceNumber"]`
  - `["chainId", "keyKind"]`
  - `publicKey`

NEAR compatibility mapping:
- `local_near_sk_v3` -> `chainId=near:*`, `algorithm=ed25519`, `keyKind=local_sk_encrypted_v1`
- `threshold_ed25519_2p_v1` -> `chainId=near:*`, `algorithm=ed25519`, `keyKind=threshold_share_v1`

## API Refactor Plan

Introduce additive generic APIs first:

- `getProfile(profileId)`
- `getProfileByAccount(chainId, accountAddress)`
- `upsertChainAccount({ profileId, chainId, accountAddress, ... })`
- `upsertAccountSigner({ chainId, accountAddress, signerId, signerSlot, signerType, ... })`
- `listAccountSigners({ chainId, accountAddress })`
- `setAccountSignerStatus({ chainId, accountAddress, signerId, status })`
- `enqueueSignerOperation({ opType, chainId, accountAddress, signerId, payload, idempotencyKey })`
- `processSignerOutbox({ now })`
- `setDerivedAddressV2({ profileId, sourceChainId, sourceAccountAddress, targetChainId, providerRef, path, address })`
- `getKeyMaterialV2({ profileId, deviceNumber, chainId, keyKind })`

Keep compatibility wrappers:
- Existing `nearAccountId` methods remain, internally resolve `profileId` via `chainAccounts`.
- Existing NEAR key methods (`getLocalKeyMaterial`, `getThresholdKeyMaterial`) map to `keyMaterialV2`.
- Existing "link device" and "email recovery" flows call the new signer APIs while preserving current external method signatures.

Deprecation path:
1. Add `@deprecated` tags and log-once warnings on NEAR-specific methods.
2. Migrate internal call sites.
3. Remove old methods in a later major release.

## Normalization and Validation Rules

- `chainId`:
  - Store canonical lower-case CAIP-style values (`near:testnet`, `eip155:1`, ...).
- Account identifiers:
  - NEAR: trim + lower-case before write.
  - EVM: store lower-case canonical form for keying; preserve optional checksum display form separately.
- `signerId`:
  - Stable, deterministic per signer record; never reused after revoke.
- `deviceNumber`/`signerSlot`:
  - Positive integer (`>=1`).
  - Validate uniqueness among active signers per account.
- Reject writes that violate capability matrix or invariants before persistence.

## Encryption and Sensitive Data Policy

- `keyMaterialV2.payload` must be encrypted-at-rest using versioned envelope metadata:
  - `encVersion`, `alg`, `nonce`, `ciphertext`, `tag`.
- Additional authenticated data (AAD) must bind:
  - `profileId`, `chainId`, `accountAddress` (when present), `signerId`, `keyKind`, `schemaVersion`.
- Sensitive recovery metadata must avoid raw PII where possible:
  - keep hashes/opaque identifiers in primary rows;
  - keep cleartext only where operationally required and documented.
- Envelope upgrades must be backward readable for at least one stable release.

## Cross-DB Consistency Strategy

Wallet state and key material span two DBs; treat multi-step operations as a saga:

1. In `PasskeyClientDB` transaction:
   - Insert/mark signer as `pending`.
   - Insert outbox operation (`queued`) with idempotency key.
2. Write encrypted key material in key DB.
3. Submit/confirm on-chain mutation via outbox processor.
4. Finalize signer state (`active`/`revoked`) and operation status.

Compensation/recovery:
- If step 2 fails, mark outbox op `failed` and keep signer `pending` for retry/repair.
- If on-chain submission fails, exponential retry using `nextAttemptAt`.
- On startup, reconcile dangling `pending` signers with outbox state.

## Index and Query Plan

| Query | Store | Index |
| --- | --- | --- |
| Resolve profile by chain account | `chainAccounts` | `["chainId", "accountAddress"]` |
| List accounts for profile+chain | `chainAccounts` | `["profileId", "chainId"]` |
| List active signers for account | `accountSigners` | `["chainId", "accountAddress", "status"]` |
| Resolve keys for signer slot | `keyMaterialV2` | `["profileId", "deviceNumber"]` |
| Find pending ops due now | `signerOpsOutbox` | `status` + `nextAttemptAt` |
| Idempotency lookup | `signerOpsOutbox` | `idempotencyKey` |

Constraint:
- Every new read path added during implementation must declare the backing index before merge.

## Cutover Gates (Must Pass Before Legacy Removal)

- `G1`: Migration success rate >= 99.9% on upgraded clients.
- `G2`: Legacy/V2 parity mismatch rate == 0 on sampled critical entities.
- `G3`: V2 read hit rate >= 99% for 7 consecutive days.
- `G4`: Legacy fallback read rate < 1% for 7 consecutive days.
- `G5`: No open P0/P1 migration defects.
- `G6`: Recovery/device-linking signer flows pass NEAR + ERC-4337 integration suites.

## Migration Plan (Phased)

## Phased Todo Checklist

Use this section as the execution tracker for this refactor. Mark items as complete as work lands.

### Phase 0 - Pre-migration hardening checklist
- [ ] Add chain capability matrix and typed capability error model.
- [ ] Define hard invariants (`I1`-`I7`) and validation hooks.
- [ ] Define signer lifecycle state machine + transition guards.
- [ ] Fix composite-key deletion bugs in legacy stores (`users`, rollback paths).
- [ ] Remove destructive key-store recreation behavior during DB upgrade.
- [ ] Add migration telemetry logs (start/end/duration/error/counts).
- [ ] Define canonical normalization rules (CAIP/account/address/signer ids).
- [ ] Add regression tests for existing NEAR login/signing/link-device behavior.
- [ ] Add regression tests for the refactored signing entrypoints (`signing/api`, `signing/chains/*/handlers`, `signing/orchestration`, `signing/workers`).
- [ ] Document rollback switch/feature flag for emergency fallback.
- [ ] Phase 0 exit review completed and approved.

### Phase 1 - Schema + type foundations checklist
- [ ] Add canonical types: `ProfileId`, `ChainId`, `AccountRef`, `SignerId`.
- [ ] Add `profiles` store + indexes.
- [ ] Add `chainAccounts` store + indexes.
- [ ] Add `accountSigners` store + indexes.
- [ ] Add `signerOpsOutbox` store + indexes.
- [ ] Add `profileAuthenticators` store + indexes.
- [ ] Add `derivedAddressesV2` store + indexes.
- [ ] Add `recoveryEmailsV2` store + indexes.
- [ ] Add `keyMaterialV2` store + indexes in key DB.
- [ ] Add app-state keys for migration checkpoint and `lastProfileState`.
- [ ] Add migration lock metadata and per-store checkpoint metadata.
- [ ] Implement envelope format for encrypted sensitive payloads.
- [ ] Add invariant checks for writes in generic DB APIs.
- [ ] Add generic API surface (profile/account/signer/key methods) without removing legacy APIs.
- [ ] Wire new DB API types into `client/src/core/signing/api/*` contracts.
- [ ] Phase 1 exit review completed and approved.

### Phase 2 - Backfill migration checklist
- [ ] Implement migration lock (`navigator.locks` or equivalent tab-coordination fallback).
- [ ] Migrate legacy users to `profiles`.
- [ ] Migrate NEAR account rows to `chainAccounts`.
- [ ] Backfill `accountSigners` from legacy `deviceNumber`/key material.
- [ ] Migrate authenticators to `profileAuthenticators`.
- [ ] Migrate derived addresses to `derivedAddressesV2`.
- [ ] Migrate recovery emails to `recoveryEmailsV2`.
- [ ] Migrate key records to `keyMaterialV2`.
- [ ] Add per-store checkpoints and resumable rerun behavior.
- [ ] Add parity checks (legacy count vs V2 count) and log results.
- [ ] Validate invariant checks post-migration and quarantine invalid rows.
- [ ] Phase 2 exit review completed and approved.

### Phase 3 - Dual-read / dual-write checklist
- [ ] Read paths prefer V2 stores with safe fallback to legacy stores.
- [ ] Write paths dual-write to V2 + legacy stores.
- [ ] Route signer mutations through `signerOpsOutbox` with idempotency keys.
- [ ] Add cross-DB saga recovery for partial failures (client DB vs key DB).
- [ ] Add one-time warning/deprecation logs for NEAR-specific DB APIs.
- [ ] Migrate internal consumers to new generic APIs (preserve external compatibility wrappers).
- [ ] Migrate DB call sites in `client/src/core/signing/chains/near/handlers/*`.
- [ ] Migrate DB call sites in `client/src/core/signing/chains/tempo/handlers/*`.
- [ ] Migrate DB call sites in `client/src/core/signing/api/*`, `client/src/core/signing/orchestration/*`, and `client/src/core/signing/workers/*`.
- [ ] Ensure `client/src/core/signing/secureConfirm/confirmTxFlow/adapters/*` uses generic DB lookups (no legacy direct assumptions).
- [ ] Ensure worker entrypoints under `client/src/core/workers/*` use the same V2 DB resolution path.
- [ ] Add telemetry dashboards/metrics for V2 read-hit ratio and fallback rate.
- [ ] Add telemetry for outbox retries, dead-letter count, and saga-repair actions.
- [ ] Validate NEAR + EVM/Tempo happy-path integration tests in CI.
- [ ] Phase 3 exit review completed and approved.

### Phase 4 - Cutover and cleanup checklist
- [ ] Stop legacy writes behind feature flag.
- [ ] Run burn-in period with V2-only writes + legacy fallback reads.
- [ ] Verify cutover gates (`G1`-`G6`) are satisfied.
- [ ] Remove legacy read fallback after stability threshold is met.
- [ ] Remove deprecated NEAR-only DB methods.
- [ ] Remove legacy DB access usage from `client/src/core/WebAuthnManager/*` (if any remain).
- [ ] Drop legacy stores in final cleanup migration.
- [ ] Update docs/changelog/migration notes for SDK users.
- [ ] Phase 4 exit review completed and approved.

### Cross-phase quality gates checklist
- [ ] No destructive schema operation occurs on upgrade path.
- [ ] Migration is idempotent and safe across tab crashes/reloads.
- [ ] Capability checks enforce account-model constraints (`near-native`, `erc4337`, `eoa`, ...).
- [ ] State transitions enforce signer lifecycle rules.
- [ ] Outbox idempotency guarantees no duplicate signer mutations.
- [ ] Data integrity checks pass (profile/account/signer/key linkage).
- [ ] Security review completed for key/recovery-sensitive fields.
- [ ] Index/query plan validated against real read paths (no unindexed scans on critical flows).
- [ ] All test matrices pass on fresh install and upgraded DB snapshots.

## Phase 0 - Pre-migration hardening

- Add chain capability matrix and invariant/state-machine constraints.
- Fix composite-key deletion bugs in legacy stores:
  - user deletion currently uses `nearAccountId` instead of `[nearAccountId, deviceNumber]`.
- Remove destructive key-store upgrade behavior ("always recreate store") before rollout.
- Add migration telemetry logging.
- Define normalization policy for chain/account/signer identifiers.

Exit criteria:
- Existing tests pass.
- No destructive schema operations on upgrade paths.

## Phase 1 - Add schema and generic types

- Add `ProfileId`, `ChainId`, `AccountRef` types.
- Bump DB versions and create new stores/indexes.
- Add outbox store and write-path invariant checks.
- Add encryption envelope metadata for sensitive payloads.
- Keep old stores untouched.

Exit criteria:
- Fresh installs write/read only new schema paths.
- Upgraded installs do not fail open.

## Phase 2 - Backfill migration job

Implement resumable migration in `runMigrationsIfNeeded`:

1. Read legacy users (`nearAccountId`, `deviceNumber`).
2. Create deterministic `profileId` per logical user (recommended: UUID persisted in mapping table).
3. Write `profiles`, `chainAccounts` (`chainId=near:testnet|mainnet`).
4. Create `accountSigners` rows from legacy devices (`deviceNumber` -> `signerSlot`; one signer per existing device/keyset).
5. Migrate authenticators to `profileAuthenticators`.
6. Migrate derived addresses and recovery emails to V2 stores.
7. Migrate NEAR key materials into `keyMaterialV2`.
8. Write migration checkpoint and counts.
9. Validate parity and invariant compliance; mark invalid rows for repair.

Idempotency requirements:
- Safe to rerun after interruption.
- Upsert semantics only.
- Single active migrator tab with lock + heartbeat.

## Phase 3 - Dual-read / dual-write

- Reads:
  - Prefer new stores.
  - Fallback to legacy stores if no V2 data.
- Writes:
  - Write both V2 and legacy for one release window.
  - Signer updates go through outbox + idempotency keys.
- Enforce saga repair between wallet DB and key DB on startup.
- Migrate active refactored signing modules first (`signing/api`, `signing/chains`, `signing/orchestration`, `signing/workers`, `signing/secureConfirm`), then residual compatibility modules.

Exit criteria:
- Internal metrics show new-store read hit-rate near 100%.
- No regression in login/signing/link-device/email-recovery flows.

## Phase 4 - Cutover and cleanup

- Stop legacy writes.
- Keep legacy read fallback behind feature flag for one more release.
- Remove fallback and delete legacy stores in final cleanup migration.
- Require `G1`-`G6` cutover gates before deleting legacy stores.

Exit criteria:
- No calls to NEAR-specific DB methods from signing core paths (`signing/api`, `signing/chains`, `signing/engines`, `signing/orchestration`, `signing/workers`, `signing/secureConfirm`, `signing/webauthn`).
- Legacy stores removable without user-visible data loss.

## PR Breakdown

1. PR-1 Hardening
- Composite-key delete fixes.
- Non-destructive upgrade behavior in key DB.
- Capability matrix, invariants, normalization, lifecycle constraints.

2. PR-2 Schema + types
- Add new stores and canonical identifiers.
- Add generic manager APIs, outbox schema, and invariant checks.

3. PR-3 Data migration
- Implement resumable backfill with lock/checkpoints/parity validation.
- Add migration telemetry.

4. PR-4 Call site migration
- Migrate internal consumers to generic APIs.
- Keep NEAR wrappers and route signer flows via outbox.

5. PR-5 Cleanup
- Enforce cutover gates, disable legacy writes, then remove legacy stores/methods.

## Testing Plan

- Unit tests:
  - New store CRUD.
  - Adapter validation (`near`, `eip155`, `tempo`).
  - Capability matrix enforcement (`erc4337` vs `eoa` behavior).
  - Signer lifecycle transition guards.
  - Outbox idempotency and retry behavior.
  - Idempotent migration reruns.
- Integration tests:
  - Upgrade from existing DB versions with realistic seeded data.
  - Login, link device, signing for NEAR and EVM/Tempo after migration.
  - ERC-4337 account flows: add signer, revoke signer, sign with newly added signer.
  - Email recovery flow verifies signer addition/activation on an existing account.
  - Wallet iframe mode + scoped `lastUser` behavior using `lastProfileState`.
- Failure tests:
  - Mid-migration interruption and resume.
  - Unknown chain IDs (must fail validation, not corrupt stores).
  - Cross-DB partial failure and saga recovery.

## Rollback Strategy

- Keep legacy stores intact until post-cutover verification.
- Use feature flag to force legacy reads if V2 issues are detected.
- Avoid dropping old stores before at least one stable release with V2-only reads.

## Open Questions

- Exact `ChainId` normalization policy for Tempo networks.
- Whether `profileId` should be random UUID or deterministic hash from first passkey credential.
- Whether recovery emails should remain profile-scoped or account-scoped per chain.
- Whether to keep two DB files long-term or consolidate into one DB after migration.
- Policy for EVM EOAs: auto-upgrade path to ERC-4337 account or explicit opt-in.

## Definition of Done

- NEAR, EVM, and Tempo accounts can coexist under one profile without schema hacks.
- NEAR and EVM account records support multiple active signers per account.
- Device linking and email recovery are implemented as signer-management flows in the DB layer.
- No DB upgrade path performs destructive store recreation.
- All critical flows pass on both fresh and upgraded installs.
- Internal APIs no longer require `nearAccountId` as the canonical wallet identity anchor.
