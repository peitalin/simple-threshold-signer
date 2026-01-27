import { ActionType, type ActionArgsWasm, validateActionArgsWasm } from '../../core/types/actions';
import { MinimalNearClient, SignedTransaction, type AccessKeyList } from '../../core/NearClient';
import type { FinalExecutionOutcome } from '@near-js/types';
import { toPublicKeyStringFromSecretKey } from './nearKeys';
import { createAuthServiceConfig } from './config';
import { formatGasToTGas, formatYoctoToNear } from './utils';
import { parseContractExecutionError } from './errors';
import { isValidAccountId, toOptionalTrimmedString, toRorOriginOrNull } from '../../utils/validation';
import { coerceThresholdEd25519ShareMode, coerceThresholdNodeRole } from './ThresholdService/config';
import type { ThresholdSigningService as ThresholdSigningServiceType } from './ThresholdService';
import { createThresholdSigningService } from './ThresholdService';
import { sha256BytesUtf8 } from '../../utils/digests';
import initSignerWasm, {
  handle_signer_message,
  WorkerRequestType,
  WorkerResponseType,
  type InitInput,
  type WasmTransaction,
  type WasmSignature,
} from '../../wasm_signer_worker/pkg/wasm_signer_worker.js';

import type {
  AuthServiceConfig,
  AuthServiceConfigInput,
  AccountCreationRequest,
  AccountCreationResult,
  CreateAccountAndRegisterRequest,
  CreateAccountAndRegisterResult,
  WebAuthnAuthenticationCredential,
  SignerWasmModuleSupplier,
} from './types';

import { DEFAULT_EMAIL_RECOVERY_CONTRACTS } from '../../core/defaultConfigs2';
import { EmailRecoveryService } from '../email-recovery';
import { SignedDelegate } from '../../core/types/delegate';
import {
  type ExecuteSignedDelegateResult,
  executeSignedDelegateWithRelayer,
  type DelegateActionPolicy,
} from '../delegateAction';
import { coerceLogger, type NormalizedLogger } from './logger';
import { errorMessage, toError } from '../../utils/errors';
import { base64Decode, base64UrlDecode, base64UrlEncode } from '../../utils/encoders';
import {
  createWebAuthnAuthenticatorStore,
  type WebAuthnAuthenticatorRecord,
  type WebAuthnAuthenticatorStore,
} from './WebAuthnAuthenticatorStore';
import { createWebAuthnLoginChallengeStore, type WebAuthnLoginChallengeStore } from './WebAuthnLoginChallengeStore';
import {
  createWebAuthnCredentialBindingStore,
  type WebAuthnCredentialBindingRecord,
  type WebAuthnCredentialBindingStore,
} from './WebAuthnCredentialBindingStore';
import { createWebAuthnSyncChallengeStore, type WebAuthnSyncChallengeStore } from './WebAuthnSyncChallengeStore';
import {
  createDeviceLinkingSessionStore,
  type DeviceLinkingSessionRecord,
  type DeviceLinkingSessionStore,
} from './DeviceLinkingSessionStore';
import { ensurePostgresSchema, getPostgresUrlFromConfig } from '../storage/postgres';

function isObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

function decodeBase64UrlOrBase64(input: string, fieldName: string): Uint8Array {
  try {
    return base64UrlDecode(input);
  } catch {
    try {
      return base64Decode(input);
    } catch (err) {
      throw new Error(`Invalid ${fieldName}: expected base64url/base64 string (${errorMessage(err) || 'decode failed'})`);
    }
  }
}

function parseClientDataJsonBase64url(clientDataJSONB64u: string): { challenge: string; origin: string; type: string } {
  const bytes = decodeBase64UrlOrBase64(clientDataJSONB64u, 'webauthn_authentication.response.clientDataJSON');
  const json = new TextDecoder().decode(bytes);
  const obj = JSON.parse(json) as unknown;
  if (!isObject(obj)) throw new Error('Invalid clientDataJSON: expected object');
  const challenge = typeof obj.challenge === 'string' ? obj.challenge : '';
  const origin = typeof obj.origin === 'string' ? obj.origin : '';
  const type = typeof obj.type === 'string' ? obj.type : '';
  if (!challenge) throw new Error('Invalid clientDataJSON.challenge');
  if (!origin) throw new Error('Invalid clientDataJSON.origin');
  if (!type) throw new Error('Invalid clientDataJSON.type');
  return { challenge, origin, type };
}

function originHostnameOrEmpty(origin: string): string {
  try {
    return new URL(origin).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function isHostWithinRpId(host: string, rpId: string): boolean {
  const h = (host || '').toLowerCase();
  const r = (rpId || '').toLowerCase();
  if (!h || !r) return false;
  return h === r || h.endsWith(`.${r}`);
}

function coerceDeviceNumber(input: unknown, fallback: number): number {
  const n = typeof input === 'number' ? input : Number(input);
  if (!Number.isFinite(n) || n < 1) return fallback;
  return Math.floor(n);
}

// =============================
// WASM URL CONSTANTS + HELPERS
// =============================

// Primary location (preserveModules output)
const SIGNER_WASM_MAIN_PATH = '../../wasm_signer_worker/pkg/wasm_signer_worker_bg.wasm';
// Fallback location (dist/workers copy step)
const SIGNER_WASM_FALLBACK_PATH = '../../../workers/wasm_signer_worker_bg.wasm';

function getSignerWasmUrls(logger: NormalizedLogger): URL[] {
  const paths = [SIGNER_WASM_MAIN_PATH, SIGNER_WASM_FALLBACK_PATH];
  const resolved: URL[] = [];
  const baseUrl = import.meta.url;

  for (const path of paths) {
    try {
      if (!baseUrl) throw new Error('import.meta.url is undefined');
      resolved.push(new URL(path, baseUrl));
    } catch (err) {
      logger.warn(`Failed to resolve signer WASM relative URL for path "${path}":`, err);
    }
  }

  if (!resolved.length) {
    throw new Error('Unable to resolve signer WASM location from import.meta.url. Provide AuthServiceConfig.signerWasm.moduleOrPath in this runtime.');
  }

  return resolved;
}

function summarizeThresholdEd25519Config(cfg: AuthServiceConfig['thresholdEd25519KeyStore']): string {
  if (!cfg) return 'thresholdEd25519: not configured';

  const nodeRole = coerceThresholdNodeRole(cfg.THRESHOLD_NODE_ROLE);
  const shareMode = coerceThresholdEd25519ShareMode(cfg.THRESHOLD_ED25519_SHARE_MODE);

  const masterSecretSet = (() => {
    if ('kind' in cfg) return false;
    return Boolean(toOptionalTrimmedString(cfg.THRESHOLD_ED25519_MASTER_SECRET_B64U));
  })();

  const store = (() => {
    if ('kind' in cfg) {
      if (cfg.kind === 'upstash-redis-rest') return 'upstash';
      if (cfg.kind === 'redis-tcp') return 'redis';
      if (cfg.kind === 'postgres') return 'postgres';
      return 'in-memory';
    }
    const upstashUrl = toOptionalTrimmedString(cfg.UPSTASH_REDIS_REST_URL);
    const upstashToken = toOptionalTrimmedString(cfg.UPSTASH_REDIS_REST_TOKEN);
    const redisUrl = toOptionalTrimmedString(cfg.REDIS_URL);
    const postgresUrl = toOptionalTrimmedString(cfg.POSTGRES_URL);
    if (postgresUrl) return 'postgres';
    return (upstashUrl || upstashToken) ? 'upstash' : (redisUrl ? 'redis' : 'in-memory');
  })();

  const parts = [`thresholdEd25519: configured`, `nodeRole=${nodeRole}`, `shareMode=${shareMode}`, `store=${store}`];
  if (masterSecretSet) parts.push('masterSecret=set');
  return parts.join(' ');
}

/**
 * Framework-agnostic NEAR account service
 * Core business logic for account creation and registration operations
 */
export class AuthService {
  private config: AuthServiceConfig;
  private isInitialized = false;
  private nearClient: MinimalNearClient;
  private relayerPublicKey: string = '';
  private signerWasmReady = false;
  private readonly logger: NormalizedLogger;
  private thresholdSigningServiceInitialized = false;
  private thresholdSigningService: ThresholdSigningServiceType | null = null;
  private webAuthnAuthenticatorStoreInitialized = false;
  private webAuthnAuthenticatorStore: WebAuthnAuthenticatorStore | null = null;
  private webAuthnLoginChallengeStoreInitialized = false;
  private webAuthnLoginChallengeStore: WebAuthnLoginChallengeStore | null = null;
  private webAuthnCredentialBindingStoreInitialized = false;
  private webAuthnCredentialBindingStore: WebAuthnCredentialBindingStore | null = null;
  private webAuthnSyncChallengeStoreInitialized = false;
  private webAuthnSyncChallengeStore: WebAuthnSyncChallengeStore | null = null;
  private deviceLinkingSessionStoreInitialized = false;
  private deviceLinkingSessionStore: DeviceLinkingSessionStore | null = null;
  private storageInitPromise: Promise<void> | null = null;

  // Transaction queue to prevent nonce conflicts
  private transactionQueue: Promise<any> = Promise.resolve();
  private queueStats = { pending: 0, completed: 0, failed: 0 };

  // DKIM/TEE email recovery logic (delegated to EmailRecoveryService)
  public readonly emailRecovery: EmailRecoveryService | null = null;

  constructor(config: AuthServiceConfigInput) {
    this.config = createAuthServiceConfig(config);
    this.logger = coerceLogger(this.config.logger);
    this.nearClient = new MinimalNearClient(this.config.nearRpcUrl);
    this.emailRecovery = new EmailRecoveryService({
      relayerAccountId: this.config.relayerAccountId,
      relayerPrivateKey: this.config.relayerPrivateKey,
      networkId: this.config.networkId,
      emailDkimVerifierContract: DEFAULT_EMAIL_RECOVERY_CONTRACTS.emailDkimVerifierContract,
      nearClient: this.nearClient,
      logger: this.config.logger,
      ensureSignerAndRelayerAccount: () => this._ensureSignerAndRelayerAccount(),
      queueTransaction: <T>(fn: () => Promise<T>, label: string) => this.queueTransaction(fn, label),
      fetchTxContext: (accountId: string, publicKey: string) => this.fetchTxContext(accountId, publicKey),
      signWithPrivateKey: (input) => this.signWithPrivateKey(input),
      getRelayerPublicKey: () => this.relayerPublicKey,
      zkEmailProver: this.config.zkEmailProver,
    });

    // Log effective configuration at construction time so operators can
    // verify wiring immediately when the service is created.
    this.logger.info(`
    AuthService initialized with:
    • networkId: ${this.config.networkId}
    • nearRpcUrl: ${this.config.nearRpcUrl}
    • relayerAccountId: ${this.config.relayerAccountId}
    • webAuthnContractId: ${this.config.webAuthnContractId}
    • accountInitialBalance: ${this.config.accountInitialBalance} (${formatYoctoToNear(this.config.accountInitialBalance)} NEAR)
    • createAccountAndRegisterGas: ${this.config.createAccountAndRegisterGas} (${formatGasToTGas(this.config.createAccountAndRegisterGas)})
    • ${summarizeThresholdEd25519Config(this.config.thresholdEd25519KeyStore)}
    ${this.config.zkEmailProver?.baseUrl
        ? `• zkEmailProver: ${this.config.zkEmailProver.baseUrl}`
        : `• zkEmailProver: not configured`
      }
    `);
  }

  /**
   * Initializes backing storage (e.g. Postgres schema) when configured.
   * Safe to call multiple times; initialization is memoized.
   */
  async initStorage(): Promise<void> {
    if (this.storageInitPromise) return this.storageInitPromise;

    this.storageInitPromise = (async () => {
      if (!this.config.thresholdEd25519KeyStore) return;

      const cfg = this.config.thresholdEd25519KeyStore as unknown as Record<string, unknown>;
      const kind = toOptionalTrimmedString((cfg as any).kind);
      const postgresUrl = getPostgresUrlFromConfig(cfg);

      const usePostgres = kind === 'postgres' || (!kind && Boolean(postgresUrl));
      if (!usePostgres) return;
      if (!postgresUrl) throw new Error('Postgres store selected but POSTGRES_URL is not set');

      await ensurePostgresSchema({ postgresUrl, logger: this.logger });
    })();

    return this.storageInitPromise;
  }

  async getRelayerAccount(): Promise<{ accountId: string; publicKey: string }> {
    await this._ensureSignerAndRelayerAccount();
    return {
      accountId: this.config.relayerAccountId,
      publicKey: this.relayerPublicKey
    };
  }

  /**
   * Lightweight config accessor (no RPC) for diagnostics and well-known endpoints.
   * This is safe to call even when the relayer account has not been warmed/validated yet.
   */
  getRelayerAccountId(): string {
    return this.config.relayerAccountId;
  }

  async viewAccessKeyList(accountId: string): Promise<AccessKeyList> {
    await this._ensureSignerAndRelayerAccount();
    return this.nearClient.viewAccessKeyList(accountId);
  }

  /**
   * Lazily constructs the threshold signing service when `thresholdEd25519KeyStore` is configured.
   * Routers may call this to auto-enable `/threshold-ed25519/*` endpoints.
   */
  getThresholdSigningService(): ThresholdSigningServiceType | null {
    if (this.thresholdSigningServiceInitialized) return this.thresholdSigningService;
    this.thresholdSigningServiceInitialized = true;

    if (!this.config.thresholdEd25519KeyStore) {
      this.thresholdSigningService = null;
      return null;
    }

    this.thresholdSigningService = createThresholdSigningService({
      authService: this,
      thresholdEd25519KeyStore: this.config.thresholdEd25519KeyStore,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.thresholdSigningService;
  }

  getWebAuthnContractId(): string {
    return this.config.webAuthnContractId;
  }

  private getWebAuthnAuthenticatorStore(): WebAuthnAuthenticatorStore {
    if (this.webAuthnAuthenticatorStoreInitialized && this.webAuthnAuthenticatorStore) {
      return this.webAuthnAuthenticatorStore;
    }
    if (this.webAuthnAuthenticatorStoreInitialized) {
      // Defensive: should never happen, but avoids returning null.
      this.webAuthnAuthenticatorStore = createWebAuthnAuthenticatorStore({
        config: this.config.thresholdEd25519KeyStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.webAuthnAuthenticatorStore;
    }

    this.webAuthnAuthenticatorStoreInitialized = true;
    this.webAuthnAuthenticatorStore = createWebAuthnAuthenticatorStore({
      config: this.config.thresholdEd25519KeyStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.webAuthnAuthenticatorStore;
  }

  private getWebAuthnLoginChallengeStore(): WebAuthnLoginChallengeStore {
    if (this.webAuthnLoginChallengeStoreInitialized && this.webAuthnLoginChallengeStore) {
      return this.webAuthnLoginChallengeStore;
    }
    if (this.webAuthnLoginChallengeStoreInitialized) {
      // Defensive: should never happen, but avoids returning null.
      this.webAuthnLoginChallengeStore = createWebAuthnLoginChallengeStore({
        config: this.config.thresholdEd25519KeyStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.webAuthnLoginChallengeStore;
    }

    this.webAuthnLoginChallengeStoreInitialized = true;
    this.webAuthnLoginChallengeStore = createWebAuthnLoginChallengeStore({
      config: this.config.thresholdEd25519KeyStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.webAuthnLoginChallengeStore;
  }

  private getWebAuthnCredentialBindingStore(): WebAuthnCredentialBindingStore {
    if (this.webAuthnCredentialBindingStoreInitialized && this.webAuthnCredentialBindingStore) {
      return this.webAuthnCredentialBindingStore;
    }
    if (this.webAuthnCredentialBindingStoreInitialized) {
      // Defensive: should never happen, but avoids returning null.
      this.webAuthnCredentialBindingStore = createWebAuthnCredentialBindingStore({
        config: this.config.thresholdEd25519KeyStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.webAuthnCredentialBindingStore;
    }

    this.webAuthnCredentialBindingStoreInitialized = true;
    this.webAuthnCredentialBindingStore = createWebAuthnCredentialBindingStore({
      config: this.config.thresholdEd25519KeyStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.webAuthnCredentialBindingStore;
  }

  private getWebAuthnSyncChallengeStore(): WebAuthnSyncChallengeStore {
    if (this.webAuthnSyncChallengeStoreInitialized && this.webAuthnSyncChallengeStore) {
      return this.webAuthnSyncChallengeStore;
    }
    if (this.webAuthnSyncChallengeStoreInitialized) {
      // Defensive: should never happen, but avoids returning null.
      this.webAuthnSyncChallengeStore = createWebAuthnSyncChallengeStore({
        config: this.config.thresholdEd25519KeyStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.webAuthnSyncChallengeStore;
    }

    this.webAuthnSyncChallengeStoreInitialized = true;
    this.webAuthnSyncChallengeStore = createWebAuthnSyncChallengeStore({
      config: this.config.thresholdEd25519KeyStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.webAuthnSyncChallengeStore;
  }

  private getDeviceLinkingSessionStore(): DeviceLinkingSessionStore {
    if (this.deviceLinkingSessionStoreInitialized && this.deviceLinkingSessionStore) {
      return this.deviceLinkingSessionStore;
    }
    if (this.deviceLinkingSessionStoreInitialized) {
      // Defensive: should never happen, but avoids returning null.
      this.deviceLinkingSessionStore = createDeviceLinkingSessionStore({
        config: this.config.thresholdEd25519KeyStore || null,
        logger: this.logger,
        isNode: this.isNodeEnvironment(),
      });
      return this.deviceLinkingSessionStore;
    }

    this.deviceLinkingSessionStoreInitialized = true;
    this.deviceLinkingSessionStore = createDeviceLinkingSessionStore({
      config: this.config.thresholdEd25519KeyStore || null,
      logger: this.logger,
      isNode: this.isNodeEnvironment(),
    });
    return this.deviceLinkingSessionStore;
  }

  async txStatus(txHash: string, senderAccountId: string): Promise<FinalExecutionOutcome> {
    await this._ensureSignerAndRelayerAccount();
    return this.nearClient.txStatus(txHash, senderAccountId);
  }

  private async _ensureSignerAndRelayerAccount(): Promise<void> {
    if (this.isInitialized) {
      return;
    }

    // Derive public key from configured relayer private key
    try {
      this.relayerPublicKey = toPublicKeyStringFromSecretKey(this.config.relayerPrivateKey);
    } catch (e) {
      this.logger.warn('Failed to derive public key from relayerPrivateKey; ensure it is in ed25519:<base58> format');
      this.relayerPublicKey = '';
    }

    // Prepare signer WASM for transaction building/signing
    await this.ensureSignerWasm();
    this.isInitialized = true;
  }

  private async ensureSignerWasm(): Promise<void> {
    if (this.signerWasmReady) return;
    const override = this.config.signerWasm?.moduleOrPath;
    if (override) {
      try {
        const moduleOrPath = await this.resolveSignerWasmOverride(override);
        await initSignerWasm({ module_or_path: moduleOrPath as InitInput });
        this.signerWasmReady = true;
        return;
      } catch (e) {
        this.logger.error('Failed to initialize signer WASM via provided override:', e);
        throw e;
      }
    }

    let candidates: URL[];
    try {
      candidates = getSignerWasmUrls(this.logger);
    } catch (err) {
      this.logger.error('Failed to resolve signer WASM URLs:', err);
      throw err;
    }

    try {
      if (this.isNodeEnvironment()) {
        await this.initSignerWasmForNode(candidates);
        this.signerWasmReady = true;
        return;
      }

      let lastError: unknown = null;
      for (const candidate of candidates) {
        try {
          await initSignerWasm({ module_or_path: candidate as InitInput });
          this.signerWasmReady = true;
          return;
        } catch (err) {
          lastError = err;
          this.logger.warn(`Failed to initialize signer WASM from ${candidate.toString()}, trying next candidate...`);
        }
      }

      throw lastError ?? new Error('Unable to initialize signer WASM from any candidate URL');
    } catch (e) {
      this.logger.error('Failed to initialize signer WASM:', e);
      throw e instanceof Error ? e : new Error(String(e));
    }
  }

  private isNodeEnvironment(): boolean {
    // Detect true Node.js, not Cloudflare Workers with nodejs_compat polyfills.
    const processObj = (globalThis as unknown as { process?: { versions?: { node?: string } } }).process;
    const isNode = Boolean(processObj?.versions?.node);
    // Cloudflare Workers expose WebSocketPair and may polyfill process.
    const webSocketPair = (globalThis as unknown as { WebSocketPair?: unknown }).WebSocketPair;
    const nav = (globalThis as unknown as { navigator?: { userAgent?: unknown } }).navigator;
    const isCloudflareWorker = typeof webSocketPair !== 'undefined'
      || (typeof nav?.userAgent === 'string' && nav.userAgent.includes('Cloudflare-Workers'));
    return isNode && !isCloudflareWorker;
  }

  private async resolveSignerWasmOverride(override: SignerWasmModuleSupplier): Promise<InitInput> {
    const candidate = typeof override === 'function'
      ? await (override as () => InitInput | Promise<InitInput>)()
      : await override;

    if (!candidate) {
      throw new Error('Signer WASM override resolved to an empty value');
    }

    return candidate;
  }

  /**
   * Initialize signer WASM in Node by loading the wasm file from disk.
   * Tries multiple candidate locations and falls back to path-based init if needed.
   */
  private async initSignerWasmForNode(candidates: URL[]): Promise<void> {
    const { fileURLToPath } = await import('node:url');
    const { readFile } = await import('node:fs/promises');

    // 1) Try reading and compiling bytes
    for (const url of candidates) {
      try {
        const filePath = fileURLToPath(url);
        const bytes = await readFile(filePath);
        // Ensure we pass an ArrayBuffer (not Buffer / SharedArrayBuffer) for WebAssembly.compile
        const ab = new ArrayBuffer(bytes.byteLength);
        new Uint8Array(ab).set(bytes);
        const module = await WebAssembly.compile(ab);
        await initSignerWasm({ module_or_path: module });
        return;
      } catch { } // throw at end of function
    }

    // 2) Fallback: pass file path directly (supported in some environments)
    for (const url of candidates) {
      try {
        const filePath = fileURLToPath(url);
        await initSignerWasm({ module_or_path: filePath as unknown as InitInput });
        return;
      } catch { } // throw at end of function
    }

    throw new Error('[AuthService] Failed to initialize signer WASM from filesystem candidates');
  }

  /**
   * ===== Registration & authentication =====
   *
   * Helpers for creating accounts, registering WebAuthn credentials,
   * and verifying authentication responses.
   */

  /**
   * Create a new account with the specified balance
   */
  async createAccount(request: AccountCreationRequest): Promise<AccountCreationResult> {
    await this._ensureSignerAndRelayerAccount();

    return this.queueTransaction(async () => {
      try {
        if (!isValidAccountId(request.accountId)) {
          throw new Error(`Invalid account ID format: ${request.accountId}`);
        }

        // Check if account already exists
        this.logger.info(`Checking if account ${request.accountId} already exists...`);
        const accountExists = await this.checkAccountExists(request.accountId);
        if (accountExists) {
          throw new Error(`Account ${request.accountId} already exists. Cannot create duplicate account.`);
        }
        this.logger.info(`Account ${request.accountId} is available for creation`);

        const initialBalance = this.config.accountInitialBalance;

        this.logger.info(`Creating account: ${request.accountId}`);
        this.logger.info(`Initial balance: ${initialBalance} yoctoNEAR`);

        // Build actions for CreateAccount + Transfer + AddKey(FullAccess)
        const actions: ActionArgsWasm[] = [
          { action_type: ActionType.CreateAccount },
          { action_type: ActionType.Transfer, deposit: String(initialBalance) },
          {
            action_type: ActionType.AddKey,
            public_key: request.publicKey,
            access_key: JSON.stringify({
              nonce: 0,
              permission: { FullAccess: {} },
            }),
          }
        ];

        actions.forEach(validateActionArgsWasm);

        // Fetch nonce and block hash for relayer
        const { nextNonce, blockHash } = await this.fetchTxContext(this.config.relayerAccountId, this.relayerPublicKey);

        // Sign with relayer private key using WASM
        const signed = await this.signWithPrivateKey({
          nearPrivateKey: this.config.relayerPrivateKey,
          signerAccountId: this.config.relayerAccountId,
          receiverId: request.accountId,
          nonce: nextNonce,
          blockHash: blockHash,
          actions
        });

        // Broadcast transaction via MinimalNearClient using a strongly typed SignedTransaction
        const result = await this.nearClient.sendTransaction(signed);

        this.logger.info(`Account creation completed: ${result.transaction.hash}`);
        const nearAmount = (Number(BigInt(initialBalance)) / 1e24).toFixed(6);
        return {
          success: true,
          transactionHash: result.transaction.hash,
          accountId: request.accountId,
          message: `Account ${request.accountId} created with ${nearAmount} NEAR initial balance`
        };

      } catch (error: any) {
        this.logger.error(`Account creation failed for ${request.accountId}:`, error);
        const msg = errorMessage(error) || 'Unknown account creation error';
        return {
          success: false,
          error: msg,
          message: `Failed to create account ${request.accountId}: ${msg}`
        };
      }
    }, `create account ${request.accountId}`);
  }

  /**
   * Create a new NEAR subaccount and register a WebAuthn authenticator in relay-private storage.
   *
   * Notes:
   * - WebAuthn-only: the registration challenge is derived deterministically from `{ accountId, device_number }`.
   * - Contract-free: no on-chain WebAuthn verifier is used.
   */
  async createAccountAndRegisterUser(request: CreateAccountAndRegisterRequest): Promise<CreateAccountAndRegisterResult> {
    await this._ensureSignerAndRelayerAccount();

    return this.queueTransaction(async () => {
      try {
        const accountId = String(request?.new_account_id || '').trim();
        if (!isValidAccountId(accountId)) throw new Error(`Invalid account ID format: ${accountId}`);

        const relayerAccountId = String(this.config.relayerAccountId || '').trim();
        const expectedSuffix = relayerAccountId ? `.${relayerAccountId}` : '';
        if (!relayerAccountId || !expectedSuffix || !accountId.endsWith(expectedSuffix)) {
          throw new Error(`new_account_id must be a subaccount of relayerAccountId (${relayerAccountId})`);
        }

        // Account creation key:
        // - Local-signer flows provide a concrete access key here (derived client-side).
        // - Threshold-signer flows SHOULD provide a "backup"/local key as well (Option B),
        //   but we keep compatibility with older clients that omit it (Option A).
        let newPublicKey = String(request?.new_public_key || '').trim();
        const thresholdClientVerifyingShareB64u = String((request as any)?.threshold_ed25519?.client_verifying_share_b64u || '').trim();
        let thresholdKeygen:
          | (Awaited<ReturnType<NonNullable<ThresholdSigningServiceType['keygenFromClientVerifyingShareForRegistration']>>> & { ok: true })
          | null = null;

        const rpId = String(
          (request as unknown as { rp_id?: unknown; rpId?: unknown })?.rp_id
          ?? (request as unknown as { rpId?: unknown })?.rpId
          ?? '',
        ).trim();
        if (!rpId) throw new Error('Missing rp_id');

        if (thresholdClientVerifyingShareB64u) {
          const threshold = this.getThresholdSigningService();
          if (!threshold) {
            throw new Error('threshold signing is not configured on this server');
          }
          const out = await threshold.keygenFromClientVerifyingShareForRegistration({
            nearAccountId: accountId,
            rpId,
            clientVerifyingShareB64u: thresholdClientVerifyingShareB64u,
          });
          if (!out.ok) {
            throw new Error(out.message || 'threshold-ed25519 registration keygen failed');
          }
          // IMPORTANT: persist relayer key material before returning the threshold public key.
          // If persistence fails and the user later adds the threshold key on-chain, the account can become unusable for MPC signing.
          await threshold.putRelayerKeyMaterial({
            relayerKeyId: out.relayerKeyId,
            publicKey: out.publicKey,
            relayerSigningShareB64u: out.relayerSigningShareB64u,
            relayerVerifyingShareB64u: out.relayerVerifyingShareB64u,
          });
          thresholdKeygen = out as any;
        }

        // Backward compatibility: older threshold-signer clients omitted new_public_key, and the relay created the
        // account directly with the threshold/group public key. Prefer Option B (client-provided local/backup key),
        // but fall back to Option A when necessary.
        if (!newPublicKey && thresholdKeygen) {
          newPublicKey = thresholdKeygen.publicKey;
        }

        if (!newPublicKey) throw new Error('Missing new_public_key');

        const deviceNumber = (() => {
          const raw = (request as unknown as { device_number?: unknown; deviceNumber?: unknown })?.device_number
            ?? (request as unknown as { deviceNumber?: unknown })?.deviceNumber
            ?? 1;
          const n = typeof raw === 'number' ? raw : Number(raw);
          return Number.isFinite(n) && n > 0 ? Math.floor(n) : 1;
        })();

        const expectedOrigin = String(
          (request as unknown as { expected_origin?: unknown; expectedOrigin?: unknown })?.expected_origin
          ?? (request as unknown as { expectedOrigin?: unknown })?.expectedOrigin
          ?? '',
        ).trim();

        const cred = request.webauthn_registration as any;
        if (!cred || typeof cred !== 'object') throw new Error('Missing webauthn_registration');

        // 1) Verify the registration ceremony (standard WebAuthn) off-chain.
        const expectedIntent = `register:${accountId}:${deviceNumber}`;
        const expectedChallenge = base64UrlEncode(await sha256BytesUtf8(expectedIntent));

        const clientData = parseClientDataJsonBase64url(String(cred.response?.clientDataJSON || ''));
        if (clientData.type !== 'webauthn.create') {
          throw new Error('Invalid webauthn_registration.clientDataJSON.type (expected webauthn.create)');
        }
        if (clientData.challenge !== expectedChallenge) {
          throw new Error('Registration challenge mismatch');
        }
        const originHost = originHostnameOrEmpty(clientData.origin);
        if (!isHostWithinRpId(originHost, rpId)) {
          throw new Error('WebAuthn origin is not within rpId');
        }

        const mod = await import('@simplewebauthn/server');
        const verifyRegistrationResponse = (mod as any).verifyRegistrationResponse as undefined | ((args: any) => Promise<any>);
        if (typeof verifyRegistrationResponse !== 'function') {
          throw new Error('WebAuthn registration verifier is unavailable in this runtime');
        }

        // Require a concrete origin when possible (routers should pass the request Origin header).
        const expectedOriginStrict = expectedOrigin || clientData.origin;
        const verification = await verifyRegistrationResponse({
          response: cred,
          expectedChallenge,
          expectedOrigin: expectedOriginStrict,
          expectedRPID: rpId,
          requireUserVerification: false,
        });
        if (!verification?.verified) {
          throw new Error('Registration verification failed');
        }

        // 2) Create the on-chain account as a subaccount of the relayer signer.
        // In the VRF-free / lite architecture, account creation is done directly (no WebAuthn contract call).
        const accountExists = await this.checkAccountExists(accountId);
        if (accountExists) {
          throw new Error(`Account ${accountId} already exists. Cannot create duplicate account.`);
        }

        const actions: ActionArgsWasm[] = [
          {
            action_type: ActionType.CreateAccount,
          },
          {
            action_type: ActionType.Transfer,
            deposit: String(this.config.accountInitialBalance),
          },
          {
            action_type: ActionType.AddKey,
            public_key: newPublicKey,
            access_key: JSON.stringify({
              nonce: 0,
              permission: { FullAccess: {} },
            }),
          },
        ];
        actions.forEach(validateActionArgsWasm);

        const { nextNonce, blockHash } = await this.fetchTxContext(relayerAccountId, this.relayerPublicKey);
        const signed = await this.signWithPrivateKey({
          nearPrivateKey: this.config.relayerPrivateKey,
          signerAccountId: relayerAccountId,
          receiverId: accountId,
          nonce: nextNonce,
          blockHash,
          actions,
        });
        const result = await this.nearClient.sendTransaction(signed);

        // 3) Persist the authenticator privately on the relay.
        const credentialIdB64u = String(verification?.registrationInfo?.credential?.id || '').trim();
        const credentialPublicKey = verification?.registrationInfo?.credential?.publicKey as Uint8Array | undefined;
        const counter = verification?.registrationInfo?.credential?.counter as number | undefined;

        if (!credentialIdB64u || !credentialPublicKey) {
          throw new Error('Registration verification did not return credential public key material');
        }

        const store = this.getWebAuthnAuthenticatorStore();
        const now = Date.now();
        await store.put(accountId, {
          version: 'webauthn_authenticator_v1',
          credentialIdB64u,
          credentialPublicKeyB64u: base64UrlEncode(credentialPublicKey),
          counter: Number.isFinite(counter) && counter! >= 0 ? Math.floor(counter!) : 0,
          createdAtMs: now,
          updatedAtMs: now,
        });

        // 4) Persist passkey→account binding for sync/link/recovery flows.
        // This is relay-private storage (no on-chain authenticator registry dependence).
        const bindingStore = this.getWebAuthnCredentialBindingStore();
        const binding: WebAuthnCredentialBindingRecord = {
          version: 'webauthn_credential_binding_v1',
          rpId,
          credentialIdB64u,
          userId: accountId,
          deviceNumber,
          // For threshold signers, the binding "publicKey" is the threshold/group public key (used by sync/session flows),
          // even when the account was created with a separate local/backup key (Option B).
          publicKey: thresholdKeygen ? thresholdKeygen.publicKey : newPublicKey,
          ...(thresholdKeygen ? { relayerKeyId: thresholdKeygen.relayerKeyId } : {}),
          ...(thresholdKeygen ? { clientParticipantId: thresholdKeygen.clientParticipantId } : {}),
          ...(thresholdKeygen ? { relayerParticipantId: thresholdKeygen.relayerParticipantId } : {}),
          ...(thresholdKeygen ? { participantIds: thresholdKeygen.participantIds } : {}),
          ...(thresholdKeygen ? { relayerVerifyingShareB64u: thresholdKeygen.relayerVerifyingShareB64u } : {}),
          createdAtMs: now,
          updatedAtMs: now,
        };
        await bindingStore.put(binding);

        this.logger.info(`Registration completed: ${result.transaction.hash}`);
        return {
          success: true,
          transactionHash: result.transaction.hash,
          ...(thresholdKeygen
            ? {
                thresholdEd25519: {
                  relayerKeyId: thresholdKeygen.relayerKeyId,
                  publicKey: thresholdKeygen.publicKey,
                  relayerVerifyingShareB64u: thresholdKeygen.relayerVerifyingShareB64u,
                  clientParticipantId: thresholdKeygen.clientParticipantId,
                  relayerParticipantId: thresholdKeygen.relayerParticipantId,
                  participantIds: thresholdKeygen.participantIds,
                },
              }
            : {}),
          message: `Account ${accountId} created and registered successfully`,
        };

      } catch (error: any) {
        this.logger.error(`Atomic registration failed for ${request.new_account_id}:`, error);
        const msg = errorMessage(error) || 'Unknown atomic registration error';
        return {
          success: false,
          error: msg,
          message: `Failed to create and register account ${request.new_account_id}: ${msg}`
        };
      }
    }, `atomic create and register ${request.new_account_id}`);
  }

  /**
   * Standard WebAuthn assertion verification for lite flows.
   *
   * This verifies:
   * - the assertion signature against the credential public key stored in relay-private storage,
   * - the RP ID hash against `rpId`,
   * - the challenge against `expectedChallenge` (base64url string),
   * - and that `clientDataJSON.origin` is within the RP ID domain.
   *
   * Notes:
   * - This intentionally does not involve legacy VRF proofs or `verify_authentication_response`.
   * - Replay protection is handled by upstream protocol bindings (e.g., unique sessionPolicyDigest32 via sessionId).
   */
  async verifyWebAuthnAuthenticationLite(input: {
    nearAccountId: string;
    rpId: string;
    expectedChallenge: string;
    webauthn_authentication: WebAuthnAuthenticationCredential;
    expected_origin?: string;
  }): Promise<{ success: boolean; verified: boolean; code?: string; message?: string }> {
    try {
      await this._ensureSignerAndRelayerAccount();

      const nearAccountId = String(input.nearAccountId || '').trim();
      const rpId = String(input.rpId || '').trim();
      const expectedChallenge = String(input.expectedChallenge || '').trim();
      const expectedOriginOverride = toOptionalTrimmedString(input.expected_origin);
      const cred = input.webauthn_authentication as any;

      if (!nearAccountId) return { success: false, verified: false, code: 'invalid_body', message: 'Missing nearAccountId' };
      if (!rpId) return { success: false, verified: false, code: 'invalid_body', message: 'Missing rpId' };
      if (!expectedChallenge) return { success: false, verified: false, code: 'invalid_body', message: 'Missing expectedChallenge' };
      if (!cred || typeof cred !== 'object') return { success: false, verified: false, code: 'invalid_body', message: 'Missing webauthn_authentication' };

      let clientData: { challenge: string; origin: string; type: string };
      try {
        clientData = parseClientDataJsonBase64url(String(cred.response?.clientDataJSON || ''));
      } catch (e: unknown) {
        return {
          success: false,
          verified: false,
          code: 'invalid_body',
          message: errorMessage(e) || 'Invalid webauthn_authentication.response.clientDataJSON',
        };
      }
      const originHost = originHostnameOrEmpty(clientData.origin);
      if (!isHostWithinRpId(originHost, rpId)) {
        return { success: false, verified: false, code: 'invalid_origin', message: 'WebAuthn origin is not within rpId' };
      }

      const credentialId = String(cred.id || '').trim();
      const rawId = String(cred.rawId || '').trim();
      const chosen = rawId || credentialId;
      if (!chosen) {
        return { success: false, verified: false, code: 'invalid_body', message: 'Missing webauthn_authentication.id/rawId' };
      }

      let credentialIDBytes: Uint8Array;
      try {
        credentialIDBytes = decodeBase64UrlOrBase64(chosen, 'webauthn_authentication.rawId');
      } catch (e: unknown) {
        return { success: false, verified: false, code: 'invalid_body', message: errorMessage(e) || 'Invalid credential rawId' };
      }
      const credentialIdB64u = base64UrlEncode(credentialIDBytes);

      const store = this.getWebAuthnAuthenticatorStore();
      const matched = await store.get(nearAccountId, credentialIdB64u);
      if (!matched) {
        return { success: false, verified: false, code: 'unknown_credential', message: 'Credential is not registered for user' };
      }

      // Lazy import to avoid forcing Node-only deps into non-Node runtimes unless used.
      const mod = await import('@simplewebauthn/server');
      const verifyAuthenticationResponse = (mod as any).verifyAuthenticationResponse as undefined | ((args: any) => Promise<any>);
      if (typeof verifyAuthenticationResponse !== 'function') {
        return { success: false, verified: false, code: 'unsupported', message: 'WebAuthn verifier is unavailable in this runtime' };
      }

      let credentialPublicKeyBytes: Uint8Array;
      try {
        credentialPublicKeyBytes = decodeBase64UrlOrBase64(
          matched.credentialPublicKeyB64u,
          'authenticator.credentialPublicKeyB64u',
        );
      } catch (e: unknown) {
        return {
          success: false,
          verified: false,
          code: 'internal',
          message: `Stored credential public key is invalid: ${errorMessage(e) || 'decode failed'}`,
        };
      }

      const credential = {
        id: credentialIdB64u,
        publicKey: (typeof Buffer !== 'undefined' ? Buffer.from(credentialPublicKeyBytes) : credentialPublicKeyBytes),
        counter: matched.counter,
      };

      let verification: any;
      try {
        verification = await verifyAuthenticationResponse({
          response: cred,
          expectedChallenge,
          expectedOrigin: expectedOriginOverride || clientData.origin,
          expectedRPID: rpId,
          credential,
          requireUserVerification: false,
        });
      } catch (e: unknown) {
        return {
          success: false,
          verified: false,
          code: 'invalid_assertion',
          message: errorMessage(e) || 'Authentication assertion verification threw',
        };
      }

      if (!verification?.verified) {
        return { success: false, verified: false, code: 'not_verified', message: 'Authentication verification failed' };
      }

      const newCounter = (() => {
        const v = (verification as { authenticationInfo?: { newCounter?: unknown } })?.authenticationInfo?.newCounter;
        const n = typeof v === 'number' ? v : Number(v);
        return Number.isFinite(n) && n >= 0 ? Math.floor(n) : null;
      })();

      // Persist signature counter updates to harden against assertion replay.
      // Note: some authenticators do not implement counters (always 0); in that case, replay defense must come from one-time challenges.
      if (newCounter !== null) {
        try {
          const latest = await store.get(nearAccountId, credentialIdB64u);
          if (latest && newCounter > latest.counter) {
            await store.put(nearAccountId, {
              ...latest,
              credentialPublicKeyB64u: matched.credentialPublicKeyB64u,
              counter: newCounter,
              updatedAtMs: Date.now(),
            });
          }
        } catch (e: unknown) {
          return {
            success: false,
            verified: false,
            code: 'internal',
            message: `Failed to persist authenticator counter: ${errorMessage(e) || 'store error'}`,
          };
        }
      }

      return { success: true, verified: true };
    } catch (e: unknown) {
      const msg = errorMessage(e) || 'Verification failed';
      this.logger.error('[webauthn] verifyWebAuthnAuthenticationLite internal error', {
        message: msg,
        nearAccountId: String(input?.nearAccountId || ''),
        rpId: String(input?.rpId || ''),
      });
      return { success: false, verified: false, code: 'internal', message: msg };
    }
  }

  async createWebAuthnLoginOptions(request: {
    user_id?: unknown;
    rp_id?: unknown;
    ttl_ms?: unknown;
    ttlMs?: unknown;
  }): Promise<{
    ok: boolean;
    challengeId?: string;
    challengeB64u?: string;
    expiresAtMs?: number;
    code?: string;
    message?: string;
  }> {
    try {
      const userId = String(request?.user_id || '').trim();
      const rpId = String(request?.rp_id || '').trim();
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing user_id' };
      if (!isValidAccountId(userId)) return { ok: false, code: 'invalid_body', message: 'Invalid user_id' };
      if (!rpId) return { ok: false, code: 'invalid_body', message: 'Missing rp_id' };

      const ttlMsRaw = request?.ttlMs ?? request?.ttl_ms;
      const ttlMs = (() => {
        const n = typeof ttlMsRaw === 'number' ? ttlMsRaw : Number(ttlMsRaw);
        if (!Number.isFinite(n) || n <= 0) return 5 * 60_000;
        return Math.floor(n);
      })();
      const ttlMsClamped = Math.min(Math.max(ttlMs, 10_000), 10 * 60_000);

      if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
        return { ok: false, code: 'unsupported', message: 'crypto.getRandomValues is unavailable in this runtime' };
      }

      const createdAtMs = Date.now();
      const expiresAtMs = createdAtMs + ttlMsClamped;
      const challengeId = base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
      const challengeB64u = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));

      const store = this.getWebAuthnLoginChallengeStore();
      await store.put({
        version: 'webauthn_login_challenge_v1',
        challengeId,
        userId,
        rpId,
        challengeB64u,
        createdAtMs,
        expiresAtMs,
      });

      return { ok: true, challengeId, challengeB64u, expiresAtMs };
    } catch (e: unknown) {
      return { ok: false, code: 'internal', message: errorMessage(e) || 'Failed to create login options' };
    }
  }

  async verifyWebAuthnLogin(request: {
    challengeId?: unknown;
    challenge_id?: unknown;
    webauthn_authentication?: unknown;
    expected_origin?: string;
  }): Promise<{
    ok: boolean;
    verified?: boolean;
    userId?: string;
    rpId?: string;
    code?: string;
    message?: string;
  }> {
    try {
      const challengeId = String(request?.challengeId ?? request?.challenge_id ?? '').trim();
      if (!challengeId) return { ok: false, code: 'invalid_body', message: 'Missing challengeId' };

      const store = this.getWebAuthnLoginChallengeStore();
      const record = await store.consume(challengeId);
      if (!record) {
        return { ok: false, verified: false, code: 'challenge_expired_or_invalid', message: 'Login challenge expired or invalid' };
      }

      const verification = await this.verifyWebAuthnAuthenticationLite({
        nearAccountId: record.userId,
        rpId: record.rpId,
        expectedChallenge: record.challengeB64u,
        webauthn_authentication: request?.webauthn_authentication as any,
        expected_origin: request.expected_origin,
      });

      if (!verification.success || !verification.verified) {
        return {
          ok: false,
          verified: false,
          code: verification.code || 'not_verified',
          message: verification.message || 'Authentication verification failed',
        };
      }

      return { ok: true, verified: true, userId: record.userId, rpId: record.rpId };
    } catch (e: unknown) {
      return { ok: false, verified: false, code: 'internal', message: errorMessage(e) || 'Login verification failed' };
    }
  }

  async createWebAuthnSyncAccountOptions(request: {
    rp_id?: unknown;
    ttl_ms?: unknown;
    ttlMs?: unknown;
  }): Promise<{
    ok: boolean;
    challengeId?: string;
    challengeB64u?: string;
    expiresAtMs?: number;
    code?: string;
    message?: string;
  }> {
    try {
      const rpId = String(request?.rp_id || '').trim();
      if (!rpId) return { ok: false, code: 'invalid_body', message: 'Missing rp_id' };

      const ttlMsRaw = request?.ttlMs ?? request?.ttl_ms;
      const ttlMs = (() => {
        const n = typeof ttlMsRaw === 'number' ? ttlMsRaw : Number(ttlMsRaw);
        if (!Number.isFinite(n) || n <= 0) return 5 * 60_000;
        return Math.floor(n);
      })();
      const ttlMsClamped = Math.min(Math.max(ttlMs, 10_000), 10 * 60_000);

      if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
        return { ok: false, code: 'unsupported', message: 'crypto.getRandomValues is unavailable in this runtime' };
      }

      const createdAtMs = Date.now();
      const expiresAtMs = createdAtMs + ttlMsClamped;
      const challengeId = base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
      const challengeB64u = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));

      const store = this.getWebAuthnSyncChallengeStore();
      await store.put({
        version: 'webauthn_sync_challenge_v1',
        challengeId,
        rpId,
        challengeB64u,
        createdAtMs,
        expiresAtMs,
      });

      return { ok: true, challengeId, challengeB64u, expiresAtMs };
    } catch (e: unknown) {
      return { ok: false, code: 'internal', message: errorMessage(e) || 'Failed to create sync account options' };
    }
  }

  async verifyWebAuthnSyncAccount(request: {
    challengeId?: unknown;
    challenge_id?: unknown;
    webauthn_authentication?: unknown;
    expected_origin?: string;
  }): Promise<{
    ok: boolean;
    verified?: boolean;
    accountId?: string;
    rpId?: string;
    deviceNumber?: number;
    publicKey?: string;
    relayerKeyId?: string;
    credentialIdB64u?: string;
    credentialPublicKeyB64u?: string;
    thresholdEd25519?: {
      relayerKeyId: string;
      publicKey: string;
      relayerVerifyingShareB64u?: string;
      clientParticipantId?: number;
      relayerParticipantId?: number;
      participantIds?: number[];
    };
    code?: string;
    message?: string;
  }> {
    try {
      const challengeId = String(request?.challengeId ?? request?.challenge_id ?? '').trim();
      if (!challengeId) return { ok: false, code: 'invalid_body', message: 'Missing challengeId' };

      const store = this.getWebAuthnSyncChallengeStore();
      const challenge = await store.consume(challengeId);
      if (!challenge) {
        return { ok: false, verified: false, code: 'challenge_expired_or_invalid', message: 'Sync challenge expired or invalid' };
      }

      const cred = request?.webauthn_authentication as any;
      const credentialId = String(cred?.id || '').trim();
      const rawId = String(cred?.rawId || '').trim();
      const chosen = rawId || credentialId;
      if (!chosen) {
        return { ok: false, verified: false, code: 'invalid_body', message: 'Missing webauthn_authentication.id/rawId' };
      }

      const credentialIDBytes = decodeBase64UrlOrBase64(chosen, 'webauthn_authentication.rawId');
      const credentialIdB64u = base64UrlEncode(credentialIDBytes);

      const bindingStore = this.getWebAuthnCredentialBindingStore();
      const binding = await bindingStore.get(challenge.rpId, credentialIdB64u);
      if (!binding) {
        return { ok: false, verified: false, code: 'unknown_credential', message: 'Credential is not registered on this relay' };
      }

      const verification = await this.verifyWebAuthnAuthenticationLite({
        nearAccountId: binding.userId,
        rpId: binding.rpId,
        expectedChallenge: challenge.challengeB64u,
        webauthn_authentication: request?.webauthn_authentication as any,
        expected_origin: request.expected_origin,
      });

      if (!verification.success || !verification.verified) {
        return {
          ok: false,
          verified: false,
          code: verification.code || 'not_verified',
          message: verification.message || 'Authentication verification failed',
        };
      }

      const authStore = this.getWebAuthnAuthenticatorStore();
      const auth = await authStore.get(binding.userId, credentialIdB64u);
      if (!auth) {
        return { ok: false, verified: false, code: 'unknown_credential', message: 'Credential is not registered for user' };
      }

      const thresholdEd25519 = binding.relayerKeyId
        ? {
            relayerKeyId: binding.relayerKeyId,
            publicKey: binding.publicKey,
            ...(binding.relayerVerifyingShareB64u ? { relayerVerifyingShareB64u: binding.relayerVerifyingShareB64u } : {}),
            ...(typeof binding.clientParticipantId === 'number' ? { clientParticipantId: binding.clientParticipantId } : {}),
            ...(typeof binding.relayerParticipantId === 'number' ? { relayerParticipantId: binding.relayerParticipantId } : {}),
            ...(Array.isArray(binding.participantIds) ? { participantIds: binding.participantIds } : {}),
          }
        : undefined;

      return {
        ok: true,
        verified: true,
        accountId: binding.userId,
        rpId: binding.rpId,
        deviceNumber: binding.deviceNumber,
        publicKey: binding.publicKey,
        ...(binding.relayerKeyId ? { relayerKeyId: binding.relayerKeyId } : {}),
        credentialIdB64u,
        credentialPublicKeyB64u: auth.credentialPublicKeyB64u,
        ...(thresholdEd25519 ? { thresholdEd25519 } : {}),
      };
    } catch (e: unknown) {
      return { ok: false, verified: false, code: 'internal', message: errorMessage(e) || 'Sync verification failed' };
    }
  }

  async getLinkDeviceSession(request: {
    session_id?: unknown;
    sessionId?: unknown;
  }): Promise<
    | { ok: true; session: DeviceLinkingSessionRecord }
    | { ok: false; code: string; message: string }
  > {
    try {
      const sessionId = String(request?.session_id ?? request?.sessionId ?? '').trim();
      if (!sessionId || !/^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/.test(sessionId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid sessionId' };
      }

      const store = this.getDeviceLinkingSessionStore();
      const session = await store.get(sessionId);
      if (!session) return { ok: false, code: 'not_found', message: 'Unknown or expired link-device session' };
      return { ok: true, session };
    } catch (e: unknown) {
      return { ok: false, code: 'internal', message: errorMessage(e) || 'Failed to load link-device session' };
    }
  }

  async registerLinkDeviceSession(request: {
    session_id?: unknown;
    sessionId?: unknown;
    device2_public_key?: unknown;
    device2PublicKey?: unknown;
    expires_at_ms?: unknown;
    expiresAtMs?: unknown;
  }): Promise<
    | { ok: true; session: DeviceLinkingSessionRecord }
    | { ok: false; code: string; message: string }
  > {
    try {
      const sessionId = String(request?.session_id ?? request?.sessionId ?? '').trim();
      if (!sessionId || !/^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/.test(sessionId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid sessionId' };
      }

      const device2PublicKey = String(request?.device2_public_key ?? request?.device2PublicKey ?? '').trim();
      if (!device2PublicKey || !device2PublicKey.startsWith('ed25519:')) {
        return { ok: false, code: 'invalid_body', message: 'Invalid device2PublicKey (expected ed25519:...)' };
      }

      const now = Date.now();
      const requestedExpiresRaw = request?.expires_at_ms ?? request?.expiresAtMs;
      const requestedExpires = typeof requestedExpiresRaw === 'number'
        ? requestedExpiresRaw
        : Number(requestedExpiresRaw);
      const ttlMs = 15 * 60_000;
      const maxTtlMs = 60 * 60_000;
      const baseExpires = now + ttlMs;
      const expiresAtMs = Number.isFinite(requestedExpires) && requestedExpires > now
        ? Math.min(Math.floor(requestedExpires), now + maxTtlMs)
        : baseExpires;

      const store = this.getDeviceLinkingSessionStore();
      const existing = await store.get(sessionId);
      if (existing?.device2PublicKey && existing.device2PublicKey !== device2PublicKey) {
        return { ok: false, code: 'conflict', message: 'Session public key mismatch' };
      }

      const session: DeviceLinkingSessionRecord = {
        version: 'device_linking_session_v1',
        sessionId,
        device2PublicKey,
        createdAtMs: existing?.createdAtMs ?? now,
        expiresAtMs: Math.max(existing?.expiresAtMs ?? 0, expiresAtMs),
        ...(existing?.claimedAtMs ? { claimedAtMs: existing.claimedAtMs } : {}),
        ...(existing?.accountId ? { accountId: existing.accountId } : {}),
        ...(existing?.deviceNumber ? { deviceNumber: existing.deviceNumber } : {}),
        ...(existing?.addKeyTxHash ? { addKeyTxHash: existing.addKeyTxHash } : {}),
      };

      await store.put(session);
      this.logger.info('[link-device] session registered', {
        sessionId,
        device2PublicKey,
        expiresAtMs: session.expiresAtMs,
        hasExisting: !!existing,
        storeKind: String((this.config.thresholdEd25519KeyStore as any)?.kind || ''),
      });
      return { ok: true, session };
    } catch (e: unknown) {
      return { ok: false, code: 'internal', message: errorMessage(e) || 'Failed to register link-device session' };
    }
  }

  async claimLinkDeviceSession(request: {
    session_id?: unknown;
    sessionId?: unknown;
    account_id?: unknown;
    accountId?: unknown;
    device2_public_key?: unknown;
    device2PublicKey?: unknown;
    device_number?: unknown;
    deviceNumber?: unknown;
    add_key_tx_hash?: unknown;
    addKeyTxHash?: unknown;
  }): Promise<
    | { ok: true; session: DeviceLinkingSessionRecord }
    | { ok: false; code: string; message: string }
  > {
    try {
      await this._ensureSignerAndRelayerAccount();

      const sessionId = String(request?.session_id ?? request?.sessionId ?? '').trim();
      if (!sessionId || !/^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/.test(sessionId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid sessionId' };
      }

      const accountId = String(request?.account_id ?? request?.accountId ?? '').trim();
      if (!accountId || !isValidAccountId(accountId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid accountId' };
      }

      const device2PublicKey = String(request?.device2_public_key ?? request?.device2PublicKey ?? '').trim();
      if (!device2PublicKey || !device2PublicKey.startsWith('ed25519:')) {
        return { ok: false, code: 'invalid_body', message: 'Invalid device2PublicKey (expected ed25519:...)' };
      }

      const addKeyTxHash = String(request?.add_key_tx_hash ?? request?.addKeyTxHash ?? '').trim() || undefined;

      const keys = await this.nearClient.viewAccessKeyList(accountId);
      const hasKey = Array.isArray(keys?.keys) && keys.keys.some((k: any) => String(k?.public_key || '').trim() === device2PublicKey);
      if (!hasKey) {
        return {
          ok: false,
          code: 'missing_access_key',
          message: 'device2 public key is not present on account (ensure AddKey has been submitted and propagated)',
        };
      }

      const store = this.getDeviceLinkingSessionStore();
      const existing = await store.get(sessionId);
      if (existing?.accountId && existing.accountId !== accountId) {
        return { ok: false, code: 'conflict', message: 'Session is already claimed by a different accountId' };
      }
      if (existing?.device2PublicKey && existing.device2PublicKey !== device2PublicKey) {
        return { ok: false, code: 'conflict', message: 'Session public key mismatch' };
      }

      const fallbackDeviceNumber = coerceDeviceNumber(request?.device_number ?? request?.deviceNumber ?? existing?.deviceNumber ?? 2, 2);
      let deviceNumber = fallbackDeviceNumber;
      try {
        const bindingStore = this.getWebAuthnCredentialBindingStore();
        if (bindingStore.getMaxDeviceNumber) {
          const maxDeviceNumber = await bindingStore.getMaxDeviceNumber({ userId: accountId });
          if (typeof maxDeviceNumber === 'number' && maxDeviceNumber >= deviceNumber) {
            deviceNumber = maxDeviceNumber + 1;
          }
        }
      } catch {
        // ignore and keep fallback
      }

      const now = Date.now();
      const ttlMs = 15 * 60_000;
      const expiresAtMs = Math.max(existing?.expiresAtMs ?? 0, now + ttlMs);

      const session: DeviceLinkingSessionRecord = {
        version: 'device_linking_session_v1',
        sessionId,
        device2PublicKey,
        createdAtMs: existing?.createdAtMs ?? now,
        expiresAtMs,
        claimedAtMs: now,
        accountId,
        deviceNumber,
        ...(addKeyTxHash ? { addKeyTxHash } : {}),
      };

      await store.put(session);
      this.logger.info('[link-device] session claimed', {
        sessionId,
        accountId,
        device2PublicKey,
        deviceNumber,
        addKeyTxHash: addKeyTxHash || '',
        storeKind: String((this.config.thresholdEd25519KeyStore as any)?.kind || ''),
      });
      return { ok: true, session };
    } catch (e: unknown) {
      return { ok: false, code: 'internal', message: errorMessage(e) || 'Failed to claim link-device session' };
    }
  }

  async prepareLinkDevice(request: {
    account_id?: unknown;
    accountId?: unknown;
    device_number?: unknown;
    deviceNumber?: unknown;
    threshold_ed25519?: unknown;
    rp_id?: unknown;
    webauthn_registration?: unknown;
    expected_origin?: string;
  }): Promise<
    | {
        ok: true;
        accountId: string;
        deviceNumber: number;
        credentialIdB64u: string;
        thresholdEd25519: {
          relayerKeyId: string;
          publicKey: string;
          relayerVerifyingShareB64u: string;
          clientParticipantId?: number;
          relayerParticipantId?: number;
          participantIds?: number[];
        };
      }
    | { ok: false; code: string; message: string }
  > {
    try {
      await this._ensureSignerAndRelayerAccount();

      const accountId = String(request?.account_id ?? request?.accountId ?? '').trim();
      if (!accountId || !isValidAccountId(accountId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid accountId' };
      }

      const rpId = String(request?.rp_id || '').trim();
      if (!rpId) return { ok: false, code: 'invalid_body', message: 'Missing rp_id' };

      const deviceNumber = (() => {
        const raw = request?.device_number ?? request?.deviceNumber ?? 2;
        const n = typeof raw === 'number' ? raw : Number(raw);
        return Number.isFinite(n) && n >= 1 ? Math.floor(n) : 2;
      })();

      const thresholdClientVerifyingShareB64u = String((request as any)?.threshold_ed25519?.client_verifying_share_b64u || '').trim();
      if (!thresholdClientVerifyingShareB64u) {
        return { ok: false, code: 'invalid_body', message: 'Missing threshold_ed25519.client_verifying_share_b64u' };
      }

      const cred = request.webauthn_registration as any;
      if (!cred || typeof cred !== 'object') return { ok: false, code: 'invalid_body', message: 'Missing webauthn_registration' };

      // NOTE: We reuse the same deterministic registration intent schema as account creation:
      // `sha256("register:<accountId>:<deviceNumber>")`. This keeps client-side plumbing simple
      // (reuses existing SecureConfirm registration helpers).
      const expectedIntent = `register:${accountId}:${deviceNumber}`;
      const expectedChallenge = base64UrlEncode(await sha256BytesUtf8(expectedIntent));

      const clientData = parseClientDataJsonBase64url(String(cred.response?.clientDataJSON || ''));
      if (clientData.type !== 'webauthn.create') {
        return { ok: false, code: 'invalid_body', message: 'Invalid webauthn_registration.clientDataJSON.type (expected webauthn.create)' };
      }
      if (clientData.challenge !== expectedChallenge) {
        return { ok: false, code: 'challenge_mismatch', message: 'Registration challenge mismatch' };
      }
      const originHost = originHostnameOrEmpty(clientData.origin);
      if (!isHostWithinRpId(originHost, rpId)) {
        return { ok: false, code: 'invalid_origin', message: 'WebAuthn origin is not within rpId' };
      }

      const mod = await import('@simplewebauthn/server');
      const verifyRegistrationResponse = (mod as any).verifyRegistrationResponse as undefined | ((args: any) => Promise<any>);
      if (typeof verifyRegistrationResponse !== 'function') {
        return { ok: false, code: 'unsupported', message: 'WebAuthn registration verifier is unavailable in this runtime' };
      }

      const expectedOriginStrict = request.expected_origin || clientData.origin;
      const registration = await verifyRegistrationResponse({
        response: cred,
        expectedChallenge,
        expectedOrigin: expectedOriginStrict,
        expectedRPID: rpId,
        requireUserVerification: false,
      });
      if (!registration?.verified) {
        return { ok: false, code: 'not_verified', message: 'Registration verification failed' };
      }

      const threshold = this.getThresholdSigningService();
      if (!threshold) {
        return { ok: false, code: 'not_configured', message: 'Threshold signing is not configured on this server' };
      }
      const keygen = await threshold.keygenFromClientVerifyingShareForRegistration({
        nearAccountId: accountId,
        rpId,
        clientVerifyingShareB64u: thresholdClientVerifyingShareB64u,
      });
      if (!keygen.ok) return { ok: false, code: keygen.code, message: keygen.message };

      // Persist key material before returning the threshold public key. If the account later adds this
      // key on-chain but the relay lacks the signing share, the new device would be unable to sign.
      await threshold.putRelayerKeyMaterial({
        relayerKeyId: keygen.relayerKeyId,
        publicKey: keygen.publicKey,
        relayerSigningShareB64u: keygen.relayerSigningShareB64u,
        relayerVerifyingShareB64u: keygen.relayerVerifyingShareB64u,
      });

      const credentialIdB64u = String(registration?.registrationInfo?.credential?.id || '').trim();
      const credentialPublicKey = registration?.registrationInfo?.credential?.publicKey as Uint8Array | undefined;
      const counter = registration?.registrationInfo?.credential?.counter as number | undefined;

      if (!credentialIdB64u || !credentialPublicKey) {
        return { ok: false, code: 'internal', message: 'Registration verification did not return credential public key material' };
      }

      const now = Date.now();

      const authStore = this.getWebAuthnAuthenticatorStore();
      await authStore.put(accountId, {
        version: 'webauthn_authenticator_v1',
        credentialIdB64u,
        credentialPublicKeyB64u: base64UrlEncode(credentialPublicKey),
        counter: Number.isFinite(counter) && counter! >= 0 ? Math.floor(counter!) : 0,
        createdAtMs: now,
        updatedAtMs: now,
      });

      const bindingStore = this.getWebAuthnCredentialBindingStore();
      await bindingStore.put({
        version: 'webauthn_credential_binding_v1',
        rpId,
        credentialIdB64u,
        userId: accountId,
        deviceNumber,
        publicKey: keygen.publicKey,
        relayerKeyId: keygen.relayerKeyId,
        clientParticipantId: keygen.clientParticipantId,
        relayerParticipantId: keygen.relayerParticipantId,
        participantIds: keygen.participantIds,
        relayerVerifyingShareB64u: keygen.relayerVerifyingShareB64u,
        createdAtMs: now,
        updatedAtMs: now,
      });

      return {
        ok: true,
        accountId,
        deviceNumber,
        credentialIdB64u,
        thresholdEd25519: {
          relayerKeyId: keygen.relayerKeyId,
          publicKey: keygen.publicKey,
          relayerVerifyingShareB64u: keygen.relayerVerifyingShareB64u,
          clientParticipantId: keygen.clientParticipantId,
          relayerParticipantId: keygen.relayerParticipantId,
          participantIds: keygen.participantIds,
        },
      };
    } catch (e: unknown) {
      return { ok: false, code: 'internal', message: errorMessage(e) || 'Link device preparation failed' };
    }
  }

  async prepareEmailRecovery(request: {
    account_id?: unknown;
    accountId?: unknown;
    request_id?: unknown;
    requestId?: unknown;
    device_number?: unknown;
    deviceNumber?: unknown;
    threshold_ed25519?: unknown;
    rp_id?: unknown;
    webauthn_registration?: unknown;
    expected_origin?: string;
  }): Promise<
    | {
        ok: true;
        accountId: string;
        requestId: string;
        deviceNumber: number;
        credentialIdB64u: string;
        thresholdEd25519: {
          relayerKeyId: string;
          publicKey: string;
          relayerVerifyingShareB64u: string;
          clientParticipantId?: number;
          relayerParticipantId?: number;
          participantIds?: number[];
        };
      }
    | { ok: false; code: string; message: string }
  > {
    try {
      await this._ensureSignerAndRelayerAccount();

      const accountId = String(request?.account_id ?? request?.accountId ?? '').trim();
      if (!accountId || !isValidAccountId(accountId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid accountId' };
      }

      const requestId = String(request?.request_id ?? request?.requestId ?? '').trim();
      if (!requestId || !/^[A-Za-z0-9_-]{3,64}$/.test(requestId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid requestId' };
      }

      const rpId = String(request?.rp_id || '').trim();
      if (!rpId) return { ok: false, code: 'invalid_body', message: 'Missing rp_id' };

      const deviceNumber = (() => {
        const raw = request?.device_number ?? request?.deviceNumber ?? 1;
        const n = typeof raw === 'number' ? raw : Number(raw);
        return Number.isFinite(n) && n >= 1 ? Math.floor(n) : 1;
      })();

      const thresholdClientVerifyingShareB64u = String((request as any)?.threshold_ed25519?.client_verifying_share_b64u || '').trim();
      if (!thresholdClientVerifyingShareB64u) {
        return { ok: false, code: 'invalid_body', message: 'Missing threshold_ed25519.client_verifying_share_b64u' };
      }

      const cred = request.webauthn_registration as any;
      if (!cred || typeof cred !== 'object') return { ok: false, code: 'invalid_body', message: 'Missing webauthn_registration' };

      // Reuse the canonical deterministic registration challenge schema.
      // Email recovery authorization happens out-of-band (DKIM/zk-email), so we don't
      // need to bind the WebAuthn registration challenge to the email `requestId`.
      const expectedIntent = `register:${accountId}:${deviceNumber}`;
      const expectedChallenge = base64UrlEncode(await sha256BytesUtf8(expectedIntent));

      const clientData = parseClientDataJsonBase64url(String(cred.response?.clientDataJSON || ''));
      if (clientData.type !== 'webauthn.create') {
        return { ok: false, code: 'invalid_body', message: 'Invalid webauthn_registration.clientDataJSON.type (expected webauthn.create)' };
      }
      if (clientData.challenge !== expectedChallenge) {
        return { ok: false, code: 'challenge_mismatch', message: 'Registration challenge mismatch' };
      }
      const originHost = originHostnameOrEmpty(clientData.origin);
      if (!isHostWithinRpId(originHost, rpId)) {
        return { ok: false, code: 'invalid_origin', message: 'WebAuthn origin is not within rpId' };
      }

      const mod = await import('@simplewebauthn/server');
      const verifyRegistrationResponse = (mod as any).verifyRegistrationResponse as undefined | ((args: any) => Promise<any>);
      if (typeof verifyRegistrationResponse !== 'function') {
        return { ok: false, code: 'unsupported', message: 'WebAuthn registration verifier is unavailable in this runtime' };
      }

      const expectedOriginStrict = request.expected_origin || clientData.origin;
      const registration = await verifyRegistrationResponse({
        response: cred,
        expectedChallenge,
        expectedOrigin: expectedOriginStrict,
        expectedRPID: rpId,
        requireUserVerification: false,
      });
      if (!registration?.verified) {
        return { ok: false, code: 'not_verified', message: 'Registration verification failed' };
      }

      const threshold = this.getThresholdSigningService();
      if (!threshold) {
        return { ok: false, code: 'not_configured', message: 'Threshold signing is not configured on this server' };
      }
      const keygen = await threshold.keygenFromClientVerifyingShareForRegistration({
        nearAccountId: accountId,
        rpId,
        clientVerifyingShareB64u: thresholdClientVerifyingShareB64u,
      });
      if (!keygen.ok) return { ok: false, code: keygen.code, message: keygen.message };

      await threshold.putRelayerKeyMaterial({
        relayerKeyId: keygen.relayerKeyId,
        publicKey: keygen.publicKey,
        relayerSigningShareB64u: keygen.relayerSigningShareB64u,
        relayerVerifyingShareB64u: keygen.relayerVerifyingShareB64u,
      });

      const credentialIdB64u = String(registration?.registrationInfo?.credential?.id || '').trim();
      const credentialPublicKey = registration?.registrationInfo?.credential?.publicKey as Uint8Array | undefined;
      const counter = registration?.registrationInfo?.credential?.counter as number | undefined;

      if (!credentialIdB64u || !credentialPublicKey) {
        return { ok: false, code: 'internal', message: 'Registration verification did not return credential public key material' };
      }

      const now = Date.now();

      const authStore = this.getWebAuthnAuthenticatorStore();
      await authStore.put(accountId, {
        version: 'webauthn_authenticator_v1',
        credentialIdB64u,
        credentialPublicKeyB64u: base64UrlEncode(credentialPublicKey),
        counter: Number.isFinite(counter) && counter! >= 0 ? Math.floor(counter!) : 0,
        createdAtMs: now,
        updatedAtMs: now,
      });

      const bindingStore = this.getWebAuthnCredentialBindingStore();
      await bindingStore.put({
        version: 'webauthn_credential_binding_v1',
        rpId,
        credentialIdB64u,
        userId: accountId,
        deviceNumber,
        publicKey: keygen.publicKey,
        relayerKeyId: keygen.relayerKeyId,
        clientParticipantId: keygen.clientParticipantId,
        relayerParticipantId: keygen.relayerParticipantId,
        participantIds: keygen.participantIds,
        relayerVerifyingShareB64u: keygen.relayerVerifyingShareB64u,
        createdAtMs: now,
        updatedAtMs: now,
      });

      return {
        ok: true,
        accountId,
        requestId,
        deviceNumber,
        credentialIdB64u,
        thresholdEd25519: {
          relayerKeyId: keygen.relayerKeyId,
          publicKey: keygen.publicKey,
          relayerVerifyingShareB64u: keygen.relayerVerifyingShareB64u,
          clientParticipantId: keygen.clientParticipantId,
          relayerParticipantId: keygen.relayerParticipantId,
          participantIds: keygen.participantIds,
        },
      };
    } catch (e: unknown) {
      return { ok: false, code: 'internal', message: errorMessage(e) || 'Email recovery preparation failed' };
    }
  }

  /**
   * Fetch Related Origin Requests (ROR) allowed origins from a NEAR view method.
   * Defaults: contractId = webAuthnContractId, method = 'get_allowed_origins', args = {}.
   * Returns a sanitized, deduplicated list of absolute origins.
   */
  public async getRorOrigins(opts?: { contractId?: string; method?: string; args?: unknown }): Promise<string[]> {
    const contractId = toOptionalTrimmedString(opts?.contractId) || this.config.webAuthnContractId.trim();
    const method = toOptionalTrimmedString(opts?.method) || 'get_allowed_origins';
    const args = opts?.args ?? {};

    try {
      const result = await this.nearClient.view<unknown, unknown>({ account: contractId, method, args });
      let list: unknown[] = [];
      if (Array.isArray(result)) {
        list = result;
      } else if (isObject(result) && Array.isArray(result.origins)) {
        list = result.origins;
      }
      const out = new Set<string>();
      for (const item of list) {
        const norm = toRorOriginOrNull(item);
        if (norm) out.add(norm);
      }
      return Array.from(out);
    } catch (e) {
      this.logger.warn('[AuthService] getRorOrigins failed:', e);
      return [];
    }
  }

  /**
   * Account existence helper used by registration flows.
   */
  async checkAccountExists(accountId: string): Promise<boolean> {
    await this._ensureSignerAndRelayerAccount();
    const isNotFound = (m: string) => /does not exist|UNKNOWN_ACCOUNT|unknown\s+account/i.test(m);
    const isRetryable = (m: string) => /server error|internal|temporar|timeout|too many requests|429|empty response|rpc request failed/i.test(m);
    const attempts = 3;
    let lastErr: Error | null = null;
    for (let i = 1; i <= attempts; i++) {
      try {
        const view = await this.nearClient.viewAccount(accountId);
        return !!view;
      } catch (error: unknown) {
        const err = toError(error);
        lastErr = err;
        const msg = err.message;
        const details = (err as { details?: unknown }).details;
        let detailsBlob = '';
        if (details) {
          try {
            detailsBlob = typeof details === 'string' ? details : JSON.stringify(details);
          } catch {
            detailsBlob = '';
          }
        }
        const combined = `${msg}\n${detailsBlob}`;
        if (isNotFound(combined)) return false;
        if (isRetryable(msg) && i < attempts) {
          const backoff = 150 * Math.pow(2, i - 1);
          await new Promise((r) => setTimeout(r, backoff));
          continue;
        }
        // As a safety valve for flaky RPCs, treat persistent retryable errors as not-found
        if (isRetryable(msg)) {
          this.logger.warn(`[AuthService] Assuming account '${accountId}' not found after retryable RPC errors:`, msg);
          return false;
        }
        this.logger.error(`Error checking account existence for ${accountId}:`, err);
        throw err;
      }
    }
    throw lastErr || new Error('Unknown error');
  }

  /**
   * ===== Delegate actions & transaction execution =====
   *
   * Flows that build and submit on-chain transactions, including NEP-461
   * SignedDelegate meta-transactions.
   */

  /**
   * Execute a NEP-461 SignedDelegate by wrapping it in an outer transaction
   * from the relayer account. This method is intended to be called by
   * example relayers (Node/Cloudflare) once a SignedDelegate has been
   * produced by the signer worker and returned to the application.
   *
   * Notes:
   * - Signature and hash computation are performed by the signer worker.
   *   This method focuses on expiry/policy enforcement and meta-tx submission.
   * - Nonce/replay protection is left to the integrator; see docs for guidance.
   */
  async executeSignedDelegate(input: {
    hash: string;
    signedDelegate: SignedDelegate;
    policy?: DelegateActionPolicy;
  }): Promise<ExecuteSignedDelegateResult> {
    await this._ensureSignerAndRelayerAccount();

    if (!input?.hash || !input?.signedDelegate) {
      return {
        ok: false,
        code: 'invalid_delegate_request',
        error: 'hash and signedDelegate are required',
      };
    }

    const senderId = input.signedDelegate?.delegateAction?.senderId ?? 'unknown-sender';

    return this.queueTransaction(
      () => executeSignedDelegateWithRelayer({
        nearClient: this.nearClient,
        relayerAccountId: this.config.relayerAccountId,
        relayerPublicKey: this.relayerPublicKey,
        relayerPrivateKey: this.config.relayerPrivateKey,
        hash: input.hash,
        signedDelegate: input.signedDelegate,
        signWithPrivateKey: (args) => this.signWithPrivateKey(args),
      }),
      `execute signed delegate for ${senderId}`,
    );
  }

  // === Internal helpers for signing & RPC ===
  private async fetchTxContext(accountId: string, publicKey: string): Promise<{ nextNonce: string; blockHash: string }> {
    // Access key (if missing, assume nonce=0)
    let nonce = 0n;
    try {
      const ak = await this.nearClient.viewAccessKey(accountId, publicKey);
      nonce = BigInt(ak?.nonce ?? 0);
    } catch {
      nonce = 0n;
    }
    // Block
    const block = await this.nearClient.viewBlock({ finality: 'final' });
    const txBlockHash = block.header.hash;
    const nextNonce = (nonce + 1n).toString();
    return { nextNonce, blockHash: txBlockHash };
  }

  private async signWithPrivateKey(input: {
    nearPrivateKey: string;
    signerAccountId: string;
    receiverId: string;
    nonce: string;
    blockHash: string;
    actions: ActionArgsWasm[];
  }): Promise<SignedTransaction> {
    await this.ensureSignerWasm();
    const message = {
      type: WorkerRequestType.SignTransactionWithKeyPair,
      payload: {
        nearPrivateKey: input.nearPrivateKey,
        signerAccountId: input.signerAccountId,
        receiverId: input.receiverId,
        nonce: input.nonce,
        blockHash: input.blockHash,
        actions: input.actions
      }
    };
    // uses wasm signer worker's SignTransactionWithKeyPair action (no WebAuthn/PRF session required)
    let response: unknown;
    try {
      response = await handle_signer_message(message);
    } catch (e: unknown) {
      const msg = errorMessage(e);
      // Log payload for debugging (redacting private key)
      this.logger.error('Signer WASM rejected message:', {
        error: msg,
        payload: JSON.stringify(message, (key, value) =>
          key === 'nearPrivateKey' ? '[REDACTED]' : value
        )
      });

      // This specific error is intentionally redacted inside the WASM worker.
      // When it occurs in production, it's commonly due to a JS/WASM version mismatch
      // (the JS message schema changed but an old worker wasm is still deployed).
      if (msg.includes('Invalid payload for SIGN_TRANSACTION_WITH_KEYPAIR')) {
        throw new Error(
          `Signer WASM rejected SIGN_TRANSACTION_WITH_KEYPAIR payload: ${msg}. Rebuild + redeploy the relayer so the bundled \`wasm_signer_worker.js\` and \`wasm_signer_worker_bg.wasm\` come from the same build.`,
        );
      }
      throw (e instanceof Error ? e : new Error(msg || 'Signing failed'));
    }
    const {
      transaction,
      signature,
      borshBytes
    } = extractFirstSignedTransactionFromWorkerResponse(response);

    return new SignedTransaction({
      transaction: transaction,
      signature: signature,
      borsh_bytes: borshBytes,
    });
  }

  /**
   * ZK-email recovery helper (stub).
   * Intended to call the global ZkEmailVerifier and per-user recovery contract
   * once zk-email proofs and public inputs are wired through.
   */
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async recoverAccountFromZkEmailVerifier(_request: {
    accountId: string;
    proof: unknown;
    publicInputs: unknown;
  }): Promise<{
    success: boolean;
    transactionHash?: string;
    message?: string;
    error?: string;
  }> {
    return {
      success: false,
      error: 'recoverAccountFromZkEmailVerifier is not yet implemented',
      message: 'recoverAccountFromZkEmailVerifier is not yet implemented',
    };
  }

  /**
   * Queue transactions to prevent nonce conflicts
   */
  private async queueTransaction<T>(operation: () => Promise<T>, description: string): Promise<T> {
    this.queueStats.pending++;
    this.logger.debug(`[AuthService] Queueing: ${description} (pending: ${this.queueStats.pending})`);

    this.transactionQueue = this.transactionQueue
      .then(async () => {
        try {
          this.logger.debug(`[AuthService] Executing: ${description}`);
          const result = await operation();
          this.queueStats.completed++;
          this.queueStats.pending--;
          this.logger.debug(`[AuthService] Completed: ${description} (pending: ${this.queueStats.pending})`);
          return result;
        } catch (error: any) {
          this.queueStats.failed++;
          this.queueStats.pending--;
          this.logger.error(
            `[AuthService] Failed: ${description} (failed: ${this.queueStats.failed}):`,
            errorMessage(error) || 'unknown error',
          );
          throw error;
        }
      })
      .catch((error) => {
        throw error;
      });

    return this.transactionQueue;
  }
}

interface WorkerSignedTransactionPayload {
  transaction: WasmTransaction;
  signature: WasmSignature;
  borshBytes?: number[];
  borsh_bytes?: number[];
}

function extractFirstSignedTransactionFromWorkerResponse(response: any): {
  transaction: WasmTransaction;
  signature: WasmSignature;
  borshBytes: number[];
} {
  const res = (typeof response === 'string' ? JSON.parse(response) : response) as {
    type?: WorkerResponseType;
    payload?: { signedTransactions?: WorkerSignedTransactionPayload[]; error?: string };
  } | undefined;

  if (res?.type !== WorkerResponseType.SignTransactionWithKeyPairSuccess) {
    const errMsg = res?.payload?.error || 'Signing failed';
    throw new Error(errMsg);
  }

  const payload = res?.payload;
  const signedTxs = (payload?.signedTransactions ?? []) as WorkerSignedTransactionPayload[];
  if (!Array.isArray(signedTxs) || signedTxs.length === 0) {
    throw new Error('No signed transaction returned');
  }
  const first = signedTxs[0];
  const borshBytes = first?.borshBytes ?? first?.borsh_bytes;
  if (!Array.isArray(borshBytes)) {
    throw new Error('Missing borsh bytes');
  }
  return {
    transaction: first.transaction,
    signature: first.signature,
    borshBytes,
  };
}
