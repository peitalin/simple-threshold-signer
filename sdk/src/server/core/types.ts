// Platform-agnostic types for server functionality
import {
  AuthenticatorOptions,
  UserVerificationPolicy,
  OriginPolicyInput
} from '../../core/types/authenticatorOptions';
import type { InitInput } from '../../wasm_near_signer/pkg/wasm_signer_worker.js';
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
> & {
  webAuthnContractId?: string;
  nearRpcUrl?: string;
  networkId?: string;
  accountInitialBalance?: string;
  createAccountAndRegisterGas?: string;
  thresholdEd25519KeyStore?: ThresholdEd25519KeyStoreConfigInput;
  zkEmailProver?: ZkEmailProverConfigInput;
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

export interface RefreshSessionResult {
  ok: boolean;
  jwt?: string;
  code?: string;
  message?: string;
}
