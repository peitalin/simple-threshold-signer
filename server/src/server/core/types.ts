// Platform-agnostic types for server functionality
import {
  AuthenticatorOptions,
  UserVerificationPolicy,
  OriginPolicyInput
} from '@/core/types/authenticatorOptions';
import type { InitInput } from '../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import type { ZkEmailProverClientOptions } from '../email-recovery/zkEmail';
import type { Logger } from './logger';

/**
 * WASM Bindgen generates a `free` method and a `[Symbol.dispose]` method on all structs.
 * Strip both so we can pass plain objects to the worker.
 */
export type StripFree<T> = T extends object
  ? { [K in keyof T as K extends 'free' | symbol ? never : K]: StripFree<T[K]> }
  : T;

// Standard request/response interfaces that work across all platforms
export interface ServerRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}

export interface ServerResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

export type SignerWasmModuleSupplier =
  | InitInput
  | Promise<InitInput>
  | (() => InitInput | Promise<InitInput>);

export interface SignerWasmConfig {
  /**
   * Optional override for locating the signer WASM module. Useful for serverless
   * runtimes (e.g. Workers) where filesystem-relative URLs are unavailable.
   * Accepts any value supported by `initSignerWasm({ module_or_path })` or a
   * function that resolves to one.
   */
  moduleOrPath?: SignerWasmModuleSupplier;
}

// ================================
// Threshold Ed25519 key persistence
// ================================

export type ThresholdEd25519KeyStoreKind = 'in-memory' | 'upstash-redis-rest' | 'redis-tcp' | 'cloudflare-do';

// Structural types so Workers can pass Durable Object bindings without depending on CF type packages.
export interface CloudflareDurableObjectStubLike {
  fetch(input: RequestInfo, init?: RequestInit): Promise<Response>;
}

export interface CloudflareDurableObjectNamespaceLike {
  idFromName(name: string): unknown;
  get(id: unknown): CloudflareDurableObjectStubLike;
}

export type ThresholdEd25519KeyStoreConfig =
  | { kind: 'in-memory' }
  | { kind: 'upstash-redis-rest'; url: string; token: string; keyPrefix?: string }
  | { kind: 'redis-tcp'; redisUrl: string; keyPrefix?: string }
  | { kind: 'postgres'; postgresUrl: string; keyPrefix?: string }
  | {
      kind: 'cloudflare-do';
      /**
       * Durable Object namespace binding (e.g. `env.THRESHOLD_STORE`).
       * Must point to a DO class compatible with the SDK's threshold store protocol.
       */
      namespace: CloudflareDurableObjectNamespaceLike;
      /**
       * Optional DO instance name. Defaults to `threshold-ed25519-store`.
       * Use different names to isolate environments within the same Worker script.
       */
      name?: string;
    };

/**
 * Env-shaped input for threshold key store selection.
 * - Upstash REST (Cloudflare-friendly): UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN
 * - Redis TCP (Node-only): REDIS_URL
 */
export type ThresholdEd25519KeyStoreEnvInput = {
  UPSTASH_REDIS_REST_URL?: string;
  UPSTASH_REDIS_REST_TOKEN?: string;
  REDIS_URL?: string;
  /** Node-only Postgres connection string for durable storage. */
  POSTGRES_URL?: string;
  /**
   * Optional global base prefix for all threshold keyspaces.
   *
   * When set, and the more specific `THRESHOLD_ED25519_*_PREFIX` variables are not set,
   * the SDK derives:
   * - `THRESHOLD_ED25519_AUTH_PREFIX` = `${THRESHOLD_PREFIX}:threshold-ed25519:auth:`
   * - `THRESHOLD_ED25519_SESSION_PREFIX` = `${THRESHOLD_PREFIX}:threshold-ed25519:sess:`
   * - `THRESHOLD_ED25519_KEYSTORE_PREFIX` = `${THRESHOLD_PREFIX}:threshold-ed25519:key:`
   *
   * Trailing `:` is optional.
   */
  THRESHOLD_PREFIX?: string;
  THRESHOLD_ED25519_KEYSTORE_PREFIX?: string;
  THRESHOLD_ED25519_SESSION_PREFIX?: string;
  THRESHOLD_ED25519_AUTH_PREFIX?: string;
  /**
   * Optional prefixes for threshold ECDSA key/session/auth storage.
   * Defaults derive from `THRESHOLD_PREFIX` with a `threshold-ecdsa:*` namespace when unset.
   */
  THRESHOLD_ECDSA_KEYSTORE_PREFIX?: string;
  THRESHOLD_ECDSA_SESSION_PREFIX?: string;
  THRESHOLD_ECDSA_AUTH_PREFIX?: string;
  /**
   * Optional override for the client FROST participant identifier (u16, >= 1).
   * Must be distinct from `THRESHOLD_ED25519_RELAYER_PARTICIPANT_ID`.
   */
  THRESHOLD_ED25519_CLIENT_PARTICIPANT_ID?: string;
  /**
   * Optional override for the relayer FROST participant identifier (u16, >= 1).
   * Must be distinct from `THRESHOLD_ED25519_CLIENT_PARTICIPANT_ID`.
   */
  THRESHOLD_ED25519_RELAYER_PARTICIPANT_ID?: string;
  /**
   * 32-byte base64url master secret used to deterministically derive relayer signing shares.
   * When set (and enabled via `THRESHOLD_ED25519_SHARE_MODE`), the relayer can be stateless for
   * long-lived threshold key material.
   */
  THRESHOLD_ED25519_MASTER_SECRET_B64U?: string;
  /**
   * 32-byte base64url master secret used to deterministically derive relayer signing shares
   * for secp256k1-based threshold schemes (e.g. threshold ECDSA).
   */
  THRESHOLD_SECP256K1_MASTER_SECRET_B64U?: string;
  /**
   * Relayer share mode:
   * - "kv": use persisted relayer signing shares (current default behavior)
   * - "derived": derive relayer signing shares from the master secret (stateless relayer)
   * - "auto": prefer derived when master secret is configured, otherwise kv
   */
  THRESHOLD_ED25519_SHARE_MODE?: string;
  /**
   * Threshold node role.
   * - "coordinator" (default): exposes `/threshold-ed25519/sign/*` and can fan out to cosigners when configured.
   * - "cosigner": does not expose public signing endpoints; intended for internal relayer-fleet t-of-n cosigning.
   */
  THRESHOLD_NODE_ROLE?: string;
  /**
   * 32-byte base64url shared secret used to authenticate coordinator→peer calls.
   *
   * When set, cosigner relayers can expose internal endpoints that accept
   * coordinator-signed grants (HMAC-SHA256).
   */
  THRESHOLD_COORDINATOR_SHARED_SECRET_B64U?: string;
  /**
   * Optional relayer-fleet cosigner list (JSON) for internal t-of-n cosigning.
   *
   * When configured on a coordinator node, the coordinator can fan out to relayer cosigners
   * (internal-only nodes) and combine their partials into a single outer relayer signature share.
   *
   * Example:
   * `THRESHOLD_ED25519_RELAYER_COSIGNERS=[{"cosignerId":1,"relayerUrl":"https://cosigner-a.internal"},{"cosignerId":2,"relayerUrl":"https://cosigner-b.internal"},{"cosignerId":3,"relayerUrl":"https://cosigner-c.internal"}]`
   */
  THRESHOLD_ED25519_RELAYER_COSIGNERS?: string;
  /**
   * Internal relayer cosigner id for this node (u16, >= 1).
   * Required when running `THRESHOLD_NODE_ROLE=cosigner`.
   */
  THRESHOLD_ED25519_RELAYER_COSIGNER_ID?: string;
  /**
   * Internal relayer cosigner threshold `T` (integer, >= 1).
   * When set together with `THRESHOLD_ED25519_RELAYER_COSIGNERS`, the coordinator will wait for
   * `T` cosigners per signing round.
   */
  THRESHOLD_ED25519_RELAYER_COSIGNER_T?: string;
};

/**
 * Threshold key store config input.
 *
 * Accepts either:
 * - an env-shaped object (for ergonomics in server examples), or
 * - an explicit `kind` object, optionally augmented with env-shaped overrides
 *   (useful when wiring via code but still wanting env vars like THRESHOLD_NODE_ROLE).
 */
export type ThresholdEd25519KeyStoreConfigInput =
  | ThresholdEd25519KeyStoreEnvInput
  | (ThresholdEd25519KeyStoreConfig & Partial<ThresholdEd25519KeyStoreEnvInput>);

export interface AuthServiceConfig {
  relayerAccountId: string;
  relayerPrivateKey: string;
  webAuthnContractId: string;
  nearRpcUrl: string;
  networkId: string;
  accountInitialBalance: string;
  createAccountAndRegisterGas: string;
  signerWasm?: SignerWasmConfig;
  /**
   * Optional persistence for relayer-held threshold signing shares.
   * Defaults to in-memory unless env-shaped config enables Redis/Upstash.
   */
  thresholdEd25519KeyStore?: ThresholdEd25519KeyStoreConfigInput;
  /**
   * Optional logger. When unset, the server SDK is silent (no `console.*`).
   * Pass `logger: console` to enable default logging.
   */
  logger?: Logger | null;
  /**
   * Optional zk-email prover configuration used by `EmailRecoveryService` when
   * handling zk-email mode (`explicitMode: 'zk-email'` or email body hint).
   */
  zkEmailProver?: ZkEmailProverClientOptions;
  /**
   * Optional Google OIDC configuration for verifying Google `id_token` login sessions.
   */
  googleOidc?: GoogleOidcConfig;
}

/**
 * Env-var-shaped zk-email prover input, for ergonomic wiring in examples.
 * This is normalized to `ZkEmailProverClientOptions` by `createAuthServiceConfig(...)`.
 */
export interface ZkEmailProverConfigEnvInput {
  ZK_EMAIL_PROVER_BASE_URL?: string;
  ZK_EMAIL_PROVER_TIMEOUT_MS?: string;
}

export type ZkEmailProverConfigInput = ZkEmailProverClientOptions | ZkEmailProverConfigEnvInput;

export type GoogleOidcConfig = {
  /** Allowed OAuth client ids (audiences) for Google ID tokens. */
  clientIds: string[];
  /** Optional hosted domain allowlist (the `hd` claim). */
  hostedDomains?: string[];
};

export interface GoogleOidcConfigEnvInput {
  /** Single client id convenience. */
  GOOGLE_OIDC_CLIENT_ID?: string;
  /** Comma-separated client ids. */
  GOOGLE_OIDC_CLIENT_IDS?: string;
  /** Optional comma-separated hosted domains (`hd` claim). */
  GOOGLE_OIDC_HOSTED_DOMAINS?: string;
}

export type GoogleOidcConfigInput = GoogleOidcConfig | GoogleOidcConfigEnvInput;

/**
 * User-facing input shape for `AuthService`. Fields that have SDK defaults are optional here.
 *
 * Defaults are applied by `createAuthServiceConfig(...)` and by `new AuthService(...)`.
 */
export type AuthServiceConfigInput = Omit<
  AuthServiceConfig,
  'webAuthnContractId'
  | 'nearRpcUrl'
  | 'networkId'
  | 'accountInitialBalance'
  | 'createAccountAndRegisterGas'
  | 'thresholdEd25519KeyStore'
  | 'zkEmailProver'
  | 'googleOidc'
> & {
  webAuthnContractId?: string;
  nearRpcUrl?: string;
  networkId?: string;
  accountInitialBalance?: string;
  createAccountAndRegisterGas?: string;
  thresholdEd25519KeyStore?: ThresholdEd25519KeyStoreConfigInput;
  zkEmailProver?: ZkEmailProverConfigInput;
  googleOidc?: GoogleOidcConfigInput;
};

// Account creation and registration types (imported from relay-server types)
export interface AccountCreationRequest {
  accountId: string;
  publicKey: string;
}

export interface AccountCreationResult {
  success: boolean;
  transactionHash?: string;
  accountId?: string;
  error?: string;
  message?: string;
}

// WebAuthn registration credential structure
export interface WebAuthnRegistrationCredential {
  id: string;
  rawId: string; // base64-encoded
  type: string;
  authenticatorAttachment: string | null;
  response: {
    clientDataJSON: string;
    attestationObject: string;
    transports: string[];
  };
  // PRF outputs are not sent to the relay server
  clientExtensionResults: null;
}

// Interface for atomic account creation and registration
export interface CreateAccountAndRegisterRequest {
  new_account_id: string;
  /**
   * Optional NEAR access key to add to the newly created account.
   *
   * - Local-signer flows provide a locally derived public key.
   * - Threshold-signer flows typically provide a locally derived "backup" key (Option B) so the client
   *   can add the threshold key after validating it. Older clients may omit this (Option A).
   */
  new_public_key?: string;
  /**
   * Device number used during registration.
   *
   * This is used to deterministically derive the registration WebAuthn challenge
   * in WebAuthn-only mode (e.g. `sha256("register:${accountId}:${deviceNumber}")`).
   */
  device_number?: number;
  threshold_ed25519?: {
    client_verifying_share_b64u: string;
  };
  /**
   * WebAuthn RP ID used for the registration ceremony (e.g. `wallet.example.com`).
   *
   * This is required for standard WebAuthn verification on the relay.
   */
  rp_id: string;
  webauthn_registration: WebAuthnRegistrationCredential;
  /**
   * Optional expected origin override for strict WebAuthn verification.
   *
   * Routers typically populate this from the request `Origin` header.
   */
  expected_origin?: string;
  authenticator_options?: AuthenticatorOptions;
}

// Result type for atomic account creation and registration
export interface CreateAccountAndRegisterResult {
  success: boolean;
  transactionHash?: string;
  thresholdEd25519?: {
    relayerKeyId: string;
    publicKey: string;
    relayerVerifyingShareB64u?: string;
    clientParticipantId?: number;
    relayerParticipantId?: number;
    participantIds?: number[];
  };
  error?: string;
  message?: string;
  contractResult?: any; // FinalExecutionOutcome
}

// Runtime-tested NEAR error types
export interface NearActionErrorKind {
  AccountAlreadyExists?: {
    accountId: string;
  };
  AccountDoesNotExist?: {
    account_id: string;
  };
  InsufficientStake?: {
    account_id: string;
    stake: string;
    minimum_stake: string;
  };
  LackBalanceForState?: {
    account_id: string;
    balance: string;
  };
  [key: string]: any;
}

export interface NearActionError {
  kind: NearActionErrorKind;
  index: string;
}

export interface NearExecutionFailure {
  ActionError?: NearActionError;
  [key: string]: any;
}

export interface NearReceiptStatus {
  SuccessValue?: string;
  SuccessReceiptId?: string;
  Failure?: NearExecutionFailure;
}

export interface NearReceiptOutcomeWithId {
  id: string;
  outcome: {
    logs: string[];
    receipt_ids: string[];
    gas_burnt: number;
    tokens_burnt: string;
    executor_id: string;
    status: NearReceiptStatus;
  };
}

// Re-export authenticator types from core
export type { AuthenticatorOptions, UserVerificationPolicy, OriginPolicyInput };

export interface WebAuthnAuthenticationCredential {
  id: string;
  rawId: string; // base64-encoded
  type: string;
  authenticatorAttachment: string | null;
  response: {
    clientDataJSON: string; // base64url-encoded
    authenticatorData: string; // base64url-encoded
    signature: string; // base64url-encoded
    userHandle: string | null; // base64url-encoded or null
  };
  clientExtensionResults: any | null;
}

export interface VerifyAuthenticationResponse {
  success: boolean;
  verified?: boolean;
  jwt?: string;
  sessionCredential?: any;
  // Unified error model
  code?: string;
  message?: string;
  contractResponse?: any;
}

// ================================
// Threshold Ed25519 (2-party) APIs
// ================================

export type ThresholdEd25519Purpose = 'near_tx' | 'nep461_delegate' | 'nep413' | string;

export type ThresholdEd25519SessionPolicy = {
  version: 'threshold_session_v1';
  nearAccountId: string;
  rpId: string;
  relayerKeyId: string;
  sessionId: string;
  /** Optional participant ids that scope the session to a signer set. */
  participantIds?: number[];
  ttlMs: number;
  remainingUses: number;
};

export interface ThresholdEd25519SessionRequest {
  relayerKeyId: string;
  /** Base64url-encoded 32-byte client verifying share (Ed25519 compressed point) for participant id=1. */
  clientVerifyingShareB64u: string;
  sessionPolicy: ThresholdEd25519SessionPolicy;
  webauthn_authentication: WebAuthnAuthenticationCredential;
  // Optional: whether to return JWT in JSON or set an HttpOnly cookie
  sessionKind?: 'jwt' | 'cookie';
}

export interface ThresholdEd25519SessionResponse {
  ok: boolean;
  code?: string;
  message?: string;
  sessionId?: string;
  /** Server-enforced expiry (ms since epoch). */
  expiresAtMs?: number;
  expiresAt?: string;
  /** Signer-set binding (sorted unique participant ids) when available. */
  participantIds?: number[];
  remainingUses?: number;
  jwt?: string;
}

export interface ThresholdEd25519AuthorizeWithSessionRequest {
  relayerKeyId: string;
  /** Base64url-encoded 32-byte client verifying share (Ed25519 compressed point) for participant id=1. */
  clientVerifyingShareB64u: string;
  purpose: ThresholdEd25519Purpose;
  signing_digest_32: number[];
  signingPayload?: unknown;
}

export interface ThresholdEd25519AuthorizeResponse {
  ok: boolean;
  code?: string;
  message?: string;
  mpcSessionId?: string;
  expiresAt?: string;
}

export type ThresholdEd25519KeygenRequest = ThresholdEd25519KeygenWithWebAuthnRequest;

export interface ThresholdEd25519KeygenWithWebAuthnRequest {
  /**
   * Base64url-encoded 32-byte verifying share (Ed25519 compressed point) for participant id=1.
   * This is derived deterministically on the client from PRF.first (via WrapKeySeed).
   */
  clientVerifyingShareB64u: string;
  /**
   * NEAR account id for keygen.
   */
  nearAccountId: string;
  /**
   * WebAuthn RP ID expected during verification.
   */
  rpId: string;
  /**
   * Client-generated keygen session id (used to bind the WebAuthn challenge).
   */
  keygenSessionId: string;
  webauthn_authentication: WebAuthnAuthenticationCredential;
}

export interface ThresholdEd25519KeygenResponse {
  ok: boolean;
  code?: string;
  message?: string;
  /** FROST participant identifier (u16, >= 1) used for the client share. */
  clientParticipantId?: number;
  /** FROST participant identifier (u16, >= 1) used for the relayer share. */
  relayerParticipantId?: number;
  /** Convenience list of participant ids for this 2P signer set. */
  participantIds?: number[];
  /**
   * Opaque identifier for the relayer-held share record.
   * Default: equals `publicKey` for stateless recovery.
   */
  relayerKeyId?: string;
  /** NEAR ed25519 public key string (`ed25519:<base58>`). */
  publicKey?: string;
  /** Base64url-encoded 32-byte relayer verifying share (Ed25519 compressed point). */
  relayerVerifyingShareB64u?: string;
}

export interface ThresholdEd25519SignInitRequest {
  mpcSessionId: string;
  relayerKeyId: string;
  nearAccountId: string;
  /**
   * Base64url-encoded message bytes (the exact digest the co-signers will sign).
   * For NEAR tx/delegate flows this is expected to be 32 bytes.
   */
  signingDigestB64u: string;
  clientCommitments: {
    hiding: string;
    binding: string;
  };
}

export interface ThresholdEd25519SignInitResponse {
  ok: boolean;
  code?: string;
  message?: string;
  signingSessionId?: string;
  /** Commitments keyed by participant id (stringified u16). */
  commitmentsById?: Record<string, { hiding: string; binding: string }>;
  /** Relayer verifying shares keyed by relayer participant id (stringified u16). */
  relayerVerifyingSharesById?: Record<string, string>;
  /** Convenience list of participant ids for this signer set. */
  participantIds?: number[];
}

export interface ThresholdEd25519SignFinalizeRequest {
  signingSessionId: string;
  clientSignatureShareB64u: string;
}

export interface ThresholdEd25519SignFinalizeResponse {
  ok: boolean;
  code?: string;
  message?: string;
  /** Signature shares keyed by relayer participant id (stringified u16). */
  relayerSignatureSharesById?: Record<string, string>;
}

// =======================================
// Threshold Ed25519 (internal cosigner RPC)
// =======================================

export interface ThresholdEd25519CosignInitRequest {
  coordinatorGrant: string;
  signingSessionId: string;
  /**
   * Base64url-encoded 32-byte relayer cosigner signing share (a secret share; unweighted).
   * The cosigner derives its effective outer-protocol share from this and the selected cosigner set.
   */
  cosignerShareB64u: string;
  clientCommitments: {
    hiding: string;
    binding: string;
  };
}

export interface ThresholdEd25519CosignInitResponse {
  ok: boolean;
  code?: string;
  message?: string;
  relayerCommitments?: {
    hiding: string;
    binding: string;
  };
}

export interface ThresholdEd25519CosignFinalizeRequest {
  coordinatorGrant: string;
  signingSessionId: string;
  /**
   * The selected cosigner id set used for internal Lagrange interpolation.
   * Must include this cosigner's configured id.
   */
  cosignerIds: number[];
  /** NEAR ed25519 public key string (`ed25519:<base58>`). */
  groupPublicKey: string;
  /**
   * The combined outer-protocol relayer commitments (sum across the selected cosigners).
   * This must match what the client used for its signing transcript.
   */
  relayerCommitments: {
    hiding: string;
    binding: string;
  };
}

export interface ThresholdEd25519CosignFinalizeResponse {
  ok: boolean;
  code?: string;
  message?: string;
  relayerSignatureShareB64u?: string;
}

// ================================
// Threshold ECDSA (2-party) APIs
// ================================

export type ThresholdEcdsaPurpose = string;

export interface ThresholdEcdsaKeygenRequest {
  userId: string;
  rpId: string;
  keygenSessionId: string;
  /**
   * Base64url-encoded compressed secp256k1 public key (33 bytes) for the client share.
   * This is derived deterministically on the client from passkey PRF.first.
   */
  clientVerifyingShareB64u: string;
  webauthn_authentication: WebAuthnAuthenticationCredential;
}

export interface ThresholdEcdsaKeygenResponse {
  ok: boolean;
  code?: string;
  message?: string;
  /** Opaque identifier for the relay-held key record / derived share scope. */
  relayerKeyId?: string;
  /** Base64url-encoded compressed secp256k1 group public key (33 bytes). */
  groupPublicKeyB64u?: string;
  /** Hex-encoded EVM address derived from the group public key (0x + 20 bytes). */
  ethereumAddress?: string;
  /** Base64url-encoded compressed secp256k1 relayer verifying share (33 bytes). */
  relayerVerifyingShareB64u?: string;
  participantIds?: number[];
}

export type ThresholdEcdsaSessionPolicy = {
  version: 'threshold_session_v1';
  userId: string;
  rpId: string;
  relayerKeyId: string;
  sessionId: string;
  /** Optional participant ids that scope the session to a signer set. */
  participantIds?: number[];
  ttlMs: number;
  remainingUses: number;
};

export interface ThresholdEcdsaSessionRequest {
  relayerKeyId: string;
  /**
   * Base64url-encoded compressed secp256k1 public key (33 bytes) for the client share.
   * Used to validate that `relayerKeyId` is correctly bound to the client share (derived, stateless relayer mode).
   */
  clientVerifyingShareB64u: string;
  sessionPolicy: ThresholdEcdsaSessionPolicy;
  webauthn_authentication: WebAuthnAuthenticationCredential;
  sessionKind?: 'jwt' | 'cookie';
}

export interface ThresholdEcdsaSessionResponse {
  ok: boolean;
  code?: string;
  message?: string;
  sessionId?: string;
  expiresAtMs?: number;
  expiresAt?: string;
  participantIds?: number[];
  remainingUses?: number;
  jwt?: string;
}

export interface ThresholdEcdsaAuthorizeWithSessionRequest {
  relayerKeyId: string;
  /**
   * Base64url-encoded compressed secp256k1 public key (33 bytes) for the client share.
   * Used to validate that `relayerKeyId` is correctly bound to the client share (derived, stateless relayer mode).
   */
  clientVerifyingShareB64u: string;
  purpose: ThresholdEcdsaPurpose;
  signing_digest_32: number[];
  signingPayload?: unknown;
}

export interface ThresholdEcdsaAuthorizeResponse {
  ok: boolean;
  code?: string;
  message?: string;
  mpcSessionId?: string;
  expiresAt?: string;
}

// =====================================
// Threshold ECDSA (presignature pool)
// =====================================

export type ThresholdEcdsaPresignInitRequest = {
  relayerKeyId: string;
  /**
   * Base64url-encoded compressed secp256k1 public key (33 bytes) for the client share.
   * Used to validate that `relayerKeyId` is correctly bound to the client share.
   */
  clientVerifyingShareB64u: string;
  /**
   * Number of presignatures to generate.
   * v1 supports only `1` (single presignature session).
   */
  count?: number;
};

export type ThresholdEcdsaPresignInitResponse = {
  ok: boolean;
  code?: string;
  message?: string;
  presignSessionId?: string;
  stage?: 'triples' | 'triples_done' | 'presign' | 'done';
  outgoingMessagesB64u?: string[];
};

export type ThresholdEcdsaPresignStepRequest = {
  presignSessionId: string;
  /**
   * The client-requested stage transition:
   * - `triples`: continue triple generation
   * - `presign`: start/continue presigning (only valid once server is `triples_done`)
   */
  stage: 'triples' | 'presign';
  outgoingMessagesB64u?: string[];
};

export type ThresholdEcdsaPresignStepResponse = {
  ok: boolean;
  code?: string;
  message?: string;
  stage?: 'triples' | 'triples_done' | 'presign' | 'done';
  event?: 'none' | 'triples_done' | 'presign_done';
  outgoingMessagesB64u?: string[];
  /** Deterministic id derived from `bigR` (only present when `event==='presign_done'`). */
  presignatureId?: string;
  /** Base64url-encoded compressed secp256k1 point (33 bytes) for `R` (only present when `event==='presign_done'`). */
  bigRB64u?: string;
};

export type ThresholdEcdsaSignInitClientRound1V1 = {
  /**
   * Optional presignature id chosen by the client.
   * When omitted, the relayer selects a presignature from its pool.
   */
  presignatureId?: string;
};

export type ThresholdEcdsaSignInitRelayerRound1V1 = {
  presignatureId: string;
  /**
   * Base64url-encoded 32 bytes of public entropy used for presignature rerandomization.
   * Both parties must use exactly this value.
   */
  entropyB64u: string;
  /**
   * Base64url-encoded compressed secp256k1 point (33 bytes) for R = k·G (optional echo).
   * When present, the client should verify it matches its local presignature.
   */
  bigRB64u?: string;
};

export interface ThresholdEcdsaSignInitRequest {
  mpcSessionId: string;
  relayerKeyId: string;
  /** Base64url-encoded digest bytes (typically 32 bytes for secp256k1/ECDSA). */
  signingDigestB64u: string;
  /** Scheme-specific round-1 payload (nonce commitments, preprocessing selection, etc.). */
  clientRound1?: ThresholdEcdsaSignInitClientRound1V1;
}

export interface ThresholdEcdsaSignInitResponse {
  ok: boolean;
  code?: string;
  message?: string;
  signingSessionId?: string;
  /** Scheme-specific round-1 payload to return to the client. */
  relayerRound1?: ThresholdEcdsaSignInitRelayerRound1V1;
}

export type ThresholdEcdsaSignFinalizeClientRound2V1 = {
  /**
   * Base64url-encoded scalar signature share produced by the client (implementation-defined).
   * For NEAR `threshold-signatures` OT-based ECDSA, this is the participant's `s_i`.
   */
  clientSignatureShareB64u: string;
};

export type ThresholdEcdsaSignFinalizeRelayerRound2V1 = {
  /**
   * Base64url-encoded recoverable ECDSA signature bytes: `r(32) || s(32) || recId(1)`.
   * `s` must be low-s normalized.
   */
  signature65B64u: string;
  /** Base64url-encoded 32-byte `r` (x-coordinate of R). */
  rB64u: string;
  /** Base64url-encoded 32-byte low-s `s`. */
  sB64u: string;
  /** Recovery id in [0..3]. EVM yParity is `recId & 1`. */
  recId: number;
};

export interface ThresholdEcdsaSignFinalizeRequest {
  signingSessionId: string;
  /** Scheme-specific round-2 payload (signature share contribution, etc.). */
  clientRound2?: ThresholdEcdsaSignFinalizeClientRound2V1;
}

export interface ThresholdEcdsaSignFinalizeResponse {
  ok: boolean;
  code?: string;
  message?: string;
  /** Scheme-specific relayer-side contribution used by the client to finalize the signature. */
  relayerRound2?: ThresholdEcdsaSignFinalizeRelayerRound2V1;
}

// =====================================
// Threshold ECDSA (internal cosigner RPC)
// =====================================

export interface ThresholdEcdsaCosignInitRequest {
  coordinatorGrant: string;
  signingSessionId: string;
  cosignerShareB64u: string;
  clientRound1?: unknown;
}

export interface ThresholdEcdsaCosignInitResponse {
  ok: boolean;
  code?: string;
  message?: string;
  relayerRound1?: unknown;
}

export interface ThresholdEcdsaCosignFinalizeRequest {
  coordinatorGrant: string;
  signingSessionId: string;
  cosignerIds: number[];
  groupPublicKey: string;
  relayerRound1?: unknown;
}

export interface ThresholdEcdsaCosignFinalizeResponse {
  ok: boolean;
  code?: string;
  message?: string;
  relayerRound2?: unknown;
}

export interface RefreshSessionResult {
  ok: boolean;
  jwt?: string;
  code?: string;
  message?: string;
}
