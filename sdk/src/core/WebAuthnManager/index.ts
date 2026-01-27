import {
  IndexedDBManager,
  type ClientUserData,
  type ClientAuthenticatorData,
  type UnifiedIndexedDBManager,
} from '../IndexedDBManager';
import { StoreUserDataInput } from '../IndexedDBManager/passkeyClientDB';
import type { ThresholdEd25519_2p_V1Material } from '../IndexedDBManager/passkeyNearKeysDB';
import { buildThresholdEd25519Participants2pV1 } from '../../threshold/participants';
import { type NearClient, SignedTransaction } from '../NearClient';
import { SignerWorkerManager } from './SignerWorkerManager';
import { SecureConfirmWorkerManager } from './SecureConfirmWorkerManager';
import { AllowCredential, TouchIdPrompt } from './touchIdPrompt';
import { toAccountId } from '../types/accountIds';
import { UserPreferencesManager } from './userPreferences';
import UserPreferencesInstance from './userPreferences';
import { NonceManager } from '../nonceManager';
import NonceManagerInstance from '../nonceManager';
import { ActionType, type ActionArgsWasm, type TransactionInputWasm } from '../types/actions';
import type { RegistrationEventStep3, RegistrationHooksOptions, RegistrationSSEEvent, onProgressEvents } from '../types/sdkSentEvents';
import type { SignTransactionResult, SigningSessionStatus, TatchiConfigs, ThemeName } from '../types/tatchi';
import type { AccountId } from '../types/accountIds';
import type { AuthenticatorOptions } from '../types/authenticatorOptions';
import type { DelegateActionInput } from '../types/delegate';
import {
  INTERNAL_WORKER_REQUEST_TYPE_SIGN_ADD_KEY_THRESHOLD_PUBLIC_KEY_NO_PROMPT,
  isSignAddKeyThresholdPublicKeyNoPromptSuccess,
  type ConfirmationConfig,
  type RpcCallPayload,
  type SignerMode,
  type ThresholdBehavior,
  type WasmSignedDelegate,
} from '../types/signer-worker';
import { WebAuthnRegistrationCredential, WebAuthnAuthenticationCredential } from '../types';
import { RegistrationCredentialConfirmationPayload } from './SignerWorkerManager/handlers/validation';
import { resolveWorkerBaseOrigin, onEmbeddedBaseChange } from '../sdkPaths';
import { DEFAULT_WAIT_STATUS, type TransactionContext } from '../types/rpc';
import { getLastLoggedInDeviceNumber } from './SignerWorkerManager/getDeviceNumber';
import { __isWalletIframeHostMode } from '../WalletIframe/host-mode';
import { hasAccessKey } from '../rpcCalls';
import { ensureEd25519Prefix } from '../../utils/validation';
import { base64UrlEncode } from '../../utils/encoders';
import { enrollThresholdEd25519KeyHandler } from './threshold/enrollThresholdEd25519Key';
import { rotateThresholdEd25519KeyPostRegistrationHandler } from './threshold/rotateThresholdEd25519KeyPostRegistration';
import { connectThresholdEd25519SessionLite } from '../threshold/connectThresholdEd25519SessionLite';
import { collectAuthenticationCredentialForChallengeB64u } from './collectAuthenticationCredentialForChallengeB64u';
import { computeThresholdEd25519KeygenIntentDigest } from '../digests/intentDigest';
import { deriveNearKeypairFromPrfSecondB64u } from '../nearCrypto';
import { runSecureConfirm } from './SecureConfirmWorkerManager/secureConfirmBridge';
import { SecureConfirmationType, type SecureConfirmRequest } from './SecureConfirmWorkerManager/confirmTxFlow/types';

type SigningSessionOptions = {
  /** PRF-bearing credential; PRF outputs are extracted in wallet origin */
  credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
  /**
   * Optional wrapKeySalt for WrapKeySeed delivery.
   * When provided, it is used as-is; otherwise a fresh random value is generated.
   */
  wrapKeySalt?: string;
};

/**
 * WebAuthnManager - Main orchestrator for WebAuthn operations
 *
 * Architecture:
 * - index.ts (this file): Main class orchestrating everything
 * - signerWorkerManager: NEAR transaction signing and threshold signing helpers
 * - secureConfirmWorkerManager: wallet-origin confirmations + WebAuthn credential collection
 * - touchIdPrompt: TouchID prompt for biometric authentication
 */
export class WebAuthnManager {
  private readonly secureConfirmWorkerManager: SecureConfirmWorkerManager;
  private readonly signerWorkerManager: SignerWorkerManager;
  private readonly touchIdPrompt: TouchIdPrompt;
  private readonly userPreferencesManager: UserPreferencesManager;
  private readonly nearClient: NearClient;
  private readonly nonceManager: NonceManager;
  private workerBaseOrigin: string = '';
  private theme: ThemeName = 'dark';
  // Wallet-origin signing session id per account (warm session reuse).
  private activeSigningSessionIds: Map<string, string> = new Map();

  readonly tatchiPasskeyConfigs: TatchiConfigs;

  constructor(tatchiPasskeyConfigs: TatchiConfigs, nearClient: NearClient) {
    this.tatchiPasskeyConfigs = tatchiPasskeyConfigs;
    this.nearClient = nearClient;
    // Respect rpIdOverride. Safari get() bridge fallback is always enabled.
    this.touchIdPrompt = new TouchIdPrompt(
      tatchiPasskeyConfigs.iframeWallet?.rpIdOverride,
      true,
    );
    this.userPreferencesManager = UserPreferencesInstance;
    // Apply integrator-provided default signer mode (in-memory only; user preferences may override later).
    this.userPreferencesManager.configureDefaultSignerMode?.(tatchiPasskeyConfigs.signerMode);
    this.nonceManager = NonceManagerInstance;
    // Group SecureConfirm worker configuration and pass context
    this.secureConfirmWorkerManager = new SecureConfirmWorkerManager(
      {},
      {
        touchIdPrompt: this.touchIdPrompt,
        nearClient: this.nearClient,
        indexedDB: IndexedDBManager,
        userPreferencesManager: this.userPreferencesManager,
        nonceManager: this.nonceManager,
        rpIdOverride: this.touchIdPrompt.getRpId(),
        nearExplorerUrl: tatchiPasskeyConfigs.nearExplorerUrl,
        getTheme: () => this.theme,
      }
    );
    this.signerWorkerManager = new SignerWorkerManager(
      this.secureConfirmWorkerManager,
      nearClient,
      this.userPreferencesManager,
      this.nonceManager,
      this.tatchiPasskeyConfigs.relayer.url,
      tatchiPasskeyConfigs.iframeWallet?.rpIdOverride,
      true,
      tatchiPasskeyConfigs.nearExplorerUrl,
      () => this.theme,
    );

    // Compute initial worker base origin once
    this.workerBaseOrigin = resolveWorkerBaseOrigin() || (typeof window !== 'undefined' ? window.location.origin : '');
    this.signerWorkerManager.setWorkerBaseOrigin(this.workerBaseOrigin);
    this.secureConfirmWorkerManager.setWorkerBaseOrigin?.(this.workerBaseOrigin as any);

    // Keep base origin updated if the wallet sets a new embedded base
    if (typeof window !== 'undefined') {
      onEmbeddedBaseChange((url) => {
        const origin = new URL(url, window.location.origin).origin;
        if (origin && origin !== this.workerBaseOrigin) {
          this.workerBaseOrigin = origin;
          this.signerWorkerManager.setWorkerBaseOrigin(origin);
          this.secureConfirmWorkerManager.setWorkerBaseOrigin?.(origin as any);
        }
      });
    }

    // Best-effort: load persisted preferences unless we are in app-origin iframe mode,
    // where the wallet origin owns persistence and the app should avoid IndexedDB.
    const shouldAvoidAppOriginIndexedDB =
      !!tatchiPasskeyConfigs.iframeWallet?.walletOrigin && !__isWalletIframeHostMode();
    if (!shouldAvoidAppOriginIndexedDB) {
      void this.userPreferencesManager.initFromIndexedDB().catch(() => undefined);
    }
  }

  /**
   * Public pre-warm hook to initialize signer workers ahead of time.
   * Safe to call multiple times; errors are non-fatal.
   */
  prewarmSignerWorkers(): void {
    if (typeof window === 'undefined' || typeof (window as any).Worker === 'undefined') return;
    // Avoid noisy SecurityError in cross‑origin dev: only prewarm when same‑origin
    if (this.workerBaseOrigin && this.workerBaseOrigin !== window.location.origin) return;
    this.signerWorkerManager.preWarmWorkerPool().catch(() => { });
  }

  /**
   * Warm critical resources to reduce first-action latency.
   * - Initialize current user (sets up NonceManager and local state)
   * - Prefetch latest block context (and nonce if missing)
   * - Pre-open IndexedDB and warm encrypted key for the active account (best-effort)
   * - Pre-warm signer workers in the background
   */
  async warmCriticalResources(nearAccountId?: string): Promise<void> {
    // Initialize current user first (best-effort)
    if (nearAccountId) {
      await this.initializeCurrentUser(toAccountId(nearAccountId), this.nearClient).catch(() => null);
    }
    // Prefetch latest block/nonce context (best-effort)
    await this.nonceManager.prefetchBlockheight(this.nearClient).catch(() => null);
    // Best-effort: open IndexedDB and warm key data for the account
    if (nearAccountId) {
      await IndexedDBManager.getUserWithKeys(toAccountId(nearAccountId)).catch(() => null);
    }
    // Warm signer workers in background
    this.prewarmSignerWorkers();
  }

  /**
   * Resolve the effective rpId used for WebAuthn operations.
   * Delegates to TouchIdPrompt to centralize rpId selection logic.
   */
  getRpId(): string {
    return this.touchIdPrompt.getRpId();
  }

  /** Getter for NonceManager instance */
  getNonceManager(): NonceManager {
    return this.nonceManager;
  }

  /**
   * WebAuthnManager-level orchestrator for wallet-origin signing sessions.
   * Creates sessionId, wires `MessagePort` between SecureConfirm and signer workers, and ensures cleanup.
   *
   * Overload 1: plain signing session (no WrapKeySeed derivation).
   * Overload 2: signing session with WrapKeySeed derivation, when `SigningSessionOptions`
   *             (PRF.first_auth) are provided. wrapKeySalt is generated in wallet origin
   *             when a new vault entry is being created.
   */
  private generateSessionId(prefix: string): string {
    return (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function')
      ? crypto.randomUUID()
      : `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }

  private toNonNegativeInt(value: unknown): number | undefined {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return undefined;
    return Math.floor(value);
  }

  private resolveSigningSessionPolicy(args: {
    ttlMs?: number;
    remainingUses?: number;
  }): {
    ttlMs: number;
    remainingUses: number;
  } {
    const ttlMs = this.toNonNegativeInt(args.ttlMs)
      ?? this.tatchiPasskeyConfigs.signingSessionDefaults.ttlMs;
    const remainingUses = this.toNonNegativeInt(args.remainingUses)
      ?? this.tatchiPasskeyConfigs.signingSessionDefaults.remainingUses;
    return { ttlMs, remainingUses };
  }

  private getOrCreateActiveSigningSessionId(nearAccountId: AccountId): string {
    const key = String(toAccountId(nearAccountId));
    const existing = this.activeSigningSessionIds.get(key);
    if (existing) return existing;
    const sessionId = this.generateSessionId('signing-session');
    this.activeSigningSessionIds.set(key, sessionId);
    return sessionId;
  }

  private async withSigningSession<T>(args: {
    sessionId?: string;
    prefix?: string;
    options?: SigningSessionOptions;
    attachWrapKeySeedPortToSecureConfirmWorker?: boolean;
    handler: (sessionId: string) => Promise<T>;
  }): Promise<T> {
    if (typeof args.handler !== 'function') {
      throw new Error('withSigningSession requires a handler function');
    }
    const sessionId = args.sessionId || (args.prefix ? this.generateSessionId(args.prefix) : '');
    if (!sessionId) {
      throw new Error('withSigningSession requires a sessionId or prefix');
    }
    return await this.withSigningSessionInternal({
      sessionId,
      options: args.options,
      attachWrapKeySeedPortToSecureConfirmWorker: args.attachWrapKeySeedPortToSecureConfirmWorker,
      handler: args.handler,
    });
  }

  private async withSigningSessionInternal<T>(args: {
    sessionId: string;
    options?: SigningSessionOptions;
    attachWrapKeySeedPortToSecureConfirmWorker?: boolean;
    handler: (sessionId: string) => Promise<T>;
  }): Promise<T> {
    const { wrapKeySeedSenderPort } = await this.signerWorkerManager.reserveSignerWorkerSession(args.sessionId);
    const shouldAttachPortToWorker = args.attachWrapKeySeedPortToSecureConfirmWorker === true && !args.options;
    let attachedPortToWorker = false;
    try {
      if (shouldAttachPortToWorker) {
        if (!wrapKeySeedSenderPort) {
          throw new Error('Failed to create WrapKeySeed channel for signer worker');
        }
        await this.secureConfirmWorkerManager.attachWrapKeySeedPort(args.sessionId, wrapKeySeedSenderPort);
        this.signerWorkerManager.detachWrapKeySeedSenderPort(args.sessionId);
        attachedPortToWorker = true;
      }
      if (args.options) {
        const prfResults = (args.options.credential as any)?.clientExtensionResults?.prf?.results as
          | { first?: string; second?: string }
          | undefined;
        const prfFirstB64u = typeof prfResults?.first === 'string' ? prfResults.first.trim() : '';
        const prfSecondB64u = typeof prfResults?.second === 'string' ? prfResults.second.trim() : '';

        const wrapKeySalt =
          String(args.options.wrapKeySalt || '').trim()
          || (() => {
            const bytes = new Uint8Array(32);
            crypto.getRandomValues(bytes);
            return base64UrlEncode(bytes);
          })();

        if (!wrapKeySeedSenderPort) {
          throw new Error('Failed to create WrapKeySeed channel for signer worker');
        }

        try {
          if (!prfFirstB64u) {
            wrapKeySeedSenderPort.postMessage({ ok: false, error: 'Missing PRF.first output from credential' });
            throw new Error('Missing PRF.first output from credential');
          }
          wrapKeySeedSenderPort.postMessage({
            ok: true,
            wrap_key_seed: prfFirstB64u,
            wrapKeySalt,
            ...(prfSecondB64u ? { prfSecond: prfSecondB64u } : {}),
          });
        } finally {
          try { wrapKeySeedSenderPort.close(); } catch { /* noop */ }
        }
      }
      return await args.handler(args.sessionId);
    } finally {
      if (attachedPortToWorker) {
        // Best-effort cleanup: if the signing flow failed before sending WrapKeySeed,
        // ensure the SecureConfirm worker releases the transferred port.
        await this.secureConfirmWorkerManager.clearWrapKeySeedPort(args.sessionId).catch(() => {});
      }
      this.signerWorkerManager.releaseSigningSession(args.sessionId);
    }
  }

  /**
   * SecureConfirm registration confirmation helper.
   * Runs confirmTxFlow (wallet origin) and returns registration artifacts.
   *
   * SecureConfirm wrapper for link-device / registration: prompts user in-iframe to create a
   * new passkey (device N), returning artifacts for subsequent derivation.
   */
  async requestRegistrationCredentialConfirmation(params: {
    nearAccountId: string;
    deviceNumber: number;
    confirmerText?: { title?: string; body?: string };
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
  }): Promise<RegistrationCredentialConfirmationPayload> {
    return this.secureConfirmWorkerManager.requestRegistrationCredentialConfirmation({
      nearAccountId: params.nearAccountId,
      deviceNumber: params.deviceNumber,
      confirmerText: params.confirmerText,
      confirmationConfigOverride: params.confirmationConfigOverride,
      contractId: this.tatchiPasskeyConfigs.contractId,
      nearRpcUrl: this.tatchiPasskeyConfigs.nearRpcUrl,
    });
  }

  setTheme(next: ThemeName): void {
    if (next !== 'light' && next !== 'dark') return;
    this.theme = next;
  }

  getTheme(): ThemeName {
    return this.theme;
  }

  getAuthenticationCredentialsSerialized({
    nearAccountId,
    challengeB64u,
    allowCredentials,
    includeSecondPrfOutput = false,
  }: {
    nearAccountId: AccountId;
    challengeB64u: string;
    allowCredentials: AllowCredential[];
    includeSecondPrfOutput?: boolean;
  }): Promise<WebAuthnAuthenticationCredential> {
    return this.touchIdPrompt.getAuthenticationCredentialsSerializedForChallengeB64u({
      nearAccountId,
      challengeB64u,
      allowCredentials,
      includeSecondPrfOutput,
    });
  }

  /**
   * Derive NEAR keypair directly from a serialized WebAuthn registration credential
   */
  async deriveNearKeypairAndEncryptFromSerialized({
    credential,
    nearAccountId,
    options,
  }: {
    credential: WebAuthnRegistrationCredential;
    nearAccountId: string;
    options?: {
      authenticatorOptions?: AuthenticatorOptions;
      deviceNumber?: number;
    };
  }): Promise<{
    success: boolean;
    nearAccountId: string;
    publicKey: string;
    chacha20NonceB64u?: string;
    wrapKeySalt?: string;
    error?: string;
  }> {
    return this.withSigningSession({
      prefix: 'reg',
      options: { credential },
      handler: (sessionId) =>
        this.signerWorkerManager.deriveNearKeypairAndEncryptFromSerialized({
          credential,
          nearAccountId: toAccountId(nearAccountId),
          options,
          sessionId,
        }),
    });
  }

  ///////////////////////////////////////
  // INDEXEDDB OPERATIONS
  ///////////////////////////////////////

  async storeUserData(userData: StoreUserDataInput): Promise<void> {
    await IndexedDBManager.clientDB.storeWebAuthnUserData({
      ...userData,
      deviceNumber: userData.deviceNumber ?? 1,
      version: userData.version || 2,
    });
  }

  async getAllUsers(): Promise<ClientUserData[]> {
    return await IndexedDBManager.clientDB.getAllUsers();
  }

  async getUserByDevice(nearAccountId: AccountId, deviceNumber: number): Promise<ClientUserData | null> {
    return await IndexedDBManager.clientDB.getUserByDevice(nearAccountId, deviceNumber);
  }

  async getLastUser(): Promise<ClientUserData | null> {
    return await IndexedDBManager.clientDB.getLastUser();
  }

  async getAuthenticatorsByUser(nearAccountId: AccountId): Promise<ClientAuthenticatorData[]> {
    return await IndexedDBManager.clientDB.getAuthenticatorsByUser(nearAccountId);
  }

  async updateLastLogin(nearAccountId: AccountId): Promise<void> {
    return await IndexedDBManager.clientDB.updateLastLogin(nearAccountId);
  }

  /**
   * Set the last logged-in user
   * @param nearAccountId - The account ID of the user
   * @param deviceNumber - The device number (defaults to 1)
   */
  async setLastUser(nearAccountId: AccountId, deviceNumber: number = 1): Promise<void> {
    return await IndexedDBManager.clientDB.setLastUser(nearAccountId, deviceNumber);
  }


  /**
   * Initialize current user authentication state
   * This should be called after the user is authenticated (e.g. after login)
   * to ensure the user is properly tracked and can perform transactions.
   *
   * @param nearAccountId - The NEAR account ID to initialize
   * @param nearClient - The NEAR client for nonce prefetching
   */
  async initializeCurrentUser(
    nearAccountId: AccountId,
    nearClient?: NearClient,
  ): Promise<void> {
    const accountId = toAccountId(nearAccountId);

    // Set as last user for future sessions, preserving the current deviceNumber
    // when it is already known for this account.
    let deviceNumberToUse: number | null = null;
    const lastUser = await IndexedDBManager.clientDB.getLastUser().catch(() => null);
    if (
      lastUser &&
      toAccountId(lastUser.nearAccountId) === accountId &&
      Number.isFinite(lastUser.deviceNumber)
    ) {
      deviceNumberToUse = lastUser.deviceNumber;
    }

    if (deviceNumberToUse === null) {
      const userForAccount = await IndexedDBManager.clientDB
        .getUserByDevice(accountId, 1)
        .catch(() => null);
      if (userForAccount && Number.isFinite(userForAccount.deviceNumber)) {
        deviceNumberToUse = userForAccount.deviceNumber;
      }
    }

    if (deviceNumberToUse === null) {
      deviceNumberToUse = 1;
    }

    await this.setLastUser(accountId, deviceNumberToUse);

    // Set as current user for immediate use
    this.userPreferencesManager.setCurrentUser(accountId);
    // Ensure confirmation preferences are loaded before callers read them (best-effort)
    await this.userPreferencesManager.reloadUserSettings().catch(() => undefined);

    // Initialize NonceManager with the selected user's public key (best-effort)
    const userData = await IndexedDBManager.clientDB
      .getUserByDevice(accountId, deviceNumberToUse)
      .catch(() => null);
    if (userData && userData.clientNearPublicKey) {
      this.nonceManager.initializeUser(accountId, userData.clientNearPublicKey);
    }

    // Prefetch block height for better UX (non-fatal if it fails and nearClient is provided)
    if (nearClient) {
      await this.nonceManager
        .prefetchBlockheight(nearClient)
        .catch((prefetchErr) => console.debug('Nonce prefetch after authentication state initialization failed (non-fatal):', prefetchErr));
    }
  }

  async registerUser(storeUserData: StoreUserDataInput): Promise<ClientUserData> {
    return await IndexedDBManager.clientDB.registerUser(storeUserData);
  }

  async storeAuthenticator(authenticatorData: {
    credentialId: string;
    credentialPublicKey: Uint8Array;
    transports?: string[];
    name?: string;
    nearAccountId: AccountId;
    registered: string;
    syncedAt: string;
    deviceNumber?: number;
  }): Promise<void> {
    const deviceNumber = Number(authenticatorData.deviceNumber);
    const normalizedDeviceNumber = Number.isSafeInteger(deviceNumber) && deviceNumber >= 1 ? deviceNumber : 1;
    const authData = {
      ...authenticatorData,
      nearAccountId: toAccountId(authenticatorData.nearAccountId),
      deviceNumber: normalizedDeviceNumber, // Default to device 1 (1-indexed)
    };
    return await IndexedDBManager.clientDB.storeAuthenticator(authData);
  }

  extractUsername(nearAccountId: AccountId): string {
    return IndexedDBManager.clientDB.extractUsername(nearAccountId);
  }

  async atomicOperation<T>(callback: (db: any) => Promise<T>): Promise<T> {
    return await IndexedDBManager.clientDB.atomicOperation(callback);
  }

  async rollbackUserRegistration(nearAccountId: AccountId): Promise<void> {
    return await IndexedDBManager.clientDB.rollbackUserRegistration(nearAccountId);
  }

  async hasPasskeyCredential(nearAccountId: AccountId): Promise<boolean> {
    return await IndexedDBManager.clientDB.hasPasskeyCredential(nearAccountId);
  }

  /**
   * Atomically store registration data (user + authenticator)
   */
  async atomicStoreRegistrationData({
    nearAccountId,
    credential,
    publicKey,
  }: {
    nearAccountId: AccountId;
    credential: WebAuthnRegistrationCredential;
    publicKey: string;
  }): Promise<void> {
    await this.atomicOperation(async (db) => {
      // Store credential for authentication
      const credentialId: string = credential.rawId;
      const attestationB64u: string = credential.response.attestationObject;
      const transports: string[] = credential.response?.transports;

      await this.storeAuthenticator({
        nearAccountId: nearAccountId,
        credentialId: credentialId,
        credentialPublicKey: await this.extractCosePublicKey(attestationB64u),
        transports,
        name: `Passkey for ${this.extractUsername(nearAccountId)}`,
        registered: new Date().toISOString(),
        syncedAt: new Date().toISOString(),
      });

      // Store WebAuthn user data
      await this.storeUserData({
        nearAccountId,
        deviceNumber: 1,
        clientNearPublicKey: publicKey,
        lastUpdated: Date.now(),
        passkeyCredential: {
          id: credential.id,
          rawId: credentialId
        },
        version: 2,
      });

      return true;
    });
  }

  ///////////////////////////////////////
  // SIGNER WASM WORKER OPERATIONS
  ///////////////////////////////////////

  /**
   * Transaction signing with contract verification and progress updates.
   * Demonstrates the "streaming" worker pattern similar to SSE.
   *
   * Requires a successful TouchID/biometric prompt before transaction signing in wasm worker
   * Automatically verifies the authentication with the web3authn contract.
   *
   * @param transactions - Transaction payload containing:
   *   - receiverId: NEAR account ID receiving the transaction
   *   - actions: Array of NEAR actions to execute
   * @param rpcCall: RpcCallPayload containing:
   *   - contractId: Web3Authn contract ID for verification
   *   - nearRpcUrl: NEAR RPC endpoint URL
   *   - nearAccountId: NEAR account ID performing the transaction
   * @param confirmationConfigOverride: Optional confirmation configuration override
   * @param onEvent: Optional callback for progress updates during signing
   * @param onEvent - Optional callback for progress updates during signing
   */
  async signTransactionsWithActions({
    transactions,
    rpcCall,
    signerMode,
    confirmationConfigOverride,
    title,
    body,
    onEvent,
    sessionId,
  }: {
    transactions: TransactionInputWasm[],
    rpcCall: RpcCallPayload,
    signerMode: SignerMode;
    // Accept partial override; merging happens in handlers layer
    confirmationConfigOverride?: Partial<ConfirmationConfig>,
    title?: string;
    body?: string;
    onEvent?: (update: onProgressEvents) => void,
    sessionId?: string;
  }): Promise<SignTransactionResult[]> {
    const signingSessionPolicy = this.resolveSigningSessionPolicy({});
    const resolvedSessionId = String(sessionId || '').trim()
      || this.getOrCreateActiveSigningSessionId(toAccountId(rpcCall.nearAccountId));
    return this.withSigningSession({
      sessionId: resolvedSessionId,
      attachWrapKeySeedPortToSecureConfirmWorker: true,
      handler: (sessionId) =>
        this.signerWorkerManager.signTransactionsWithActions({
          transactions,
          rpcCall,
          signerMode,
          confirmationConfigOverride,
          title,
          body,
          onEvent,
          signingSessionTtlMs: signingSessionPolicy.ttlMs,
          signingSessionRemainingUses: signingSessionPolicy.remainingUses,
          sessionId,
        }),
    });
  }

  /**
   * Sign AddKey(thresholdPublicKey) for `receiverId === nearAccountId` without running confirmTxFlow.
   *
   * This is a narrowly-scoped, internal-only helper for post-registration activation flows where
   * the caller already has a PRF-bearing credential in memory (e.g., immediately after registration)
   * and wants to avoid an extra TouchID/WebAuthn prompt.
   */
  async signAddKeyThresholdPublicKeyNoPrompt(args: {
    nearAccountId: AccountId | string;
    credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
    wrapKeySalt: string;
    transactionContext: TransactionContext;
    thresholdPublicKey: string;
    relayerVerifyingShareB64u: string;
    clientParticipantId?: number;
    relayerParticipantId?: number;
    deviceNumber?: number;
    onEvent?: (update: onProgressEvents) => void;
  }): Promise<SignTransactionResult> {
    const nearAccountId = toAccountId(args.nearAccountId);
    const wrapKeySalt = args.wrapKeySalt;
    if (!wrapKeySalt) throw new Error('Missing wrapKeySalt for AddKey(thresholdPublicKey) signing');
    if (!args.credential) throw new Error('Missing credential for AddKey(thresholdPublicKey) signing');
    if (!args.transactionContext) throw new Error('Missing transactionContext for no-prompt signing');
    const thresholdPublicKey = ensureEd25519Prefix(args.thresholdPublicKey);
    if (!thresholdPublicKey) throw new Error('Missing thresholdPublicKey for AddKey(thresholdPublicKey) signing');
    const relayerVerifyingShareB64u = args.relayerVerifyingShareB64u;
    if (!relayerVerifyingShareB64u) throw new Error('Missing relayerVerifyingShareB64u for AddKey(thresholdPublicKey) signing');

    const deviceNumber = Number(args.deviceNumber);
    const resolvedDeviceNumber = Number.isSafeInteger(deviceNumber) && deviceNumber >= 1
      ? deviceNumber
      : await getLastLoggedInDeviceNumber(nearAccountId, IndexedDBManager.clientDB).catch(() => 1);

    const localKeyMaterial = await IndexedDBManager.nearKeysDB.getLocalKeyMaterial(
      nearAccountId,
      resolvedDeviceNumber,
    );
    if (!localKeyMaterial) {
      throw new Error(`No local key material found for account ${nearAccountId} device ${resolvedDeviceNumber}`);
    }

    if (localKeyMaterial.wrapKeySalt !== wrapKeySalt) {
      throw new Error('wrapKeySalt mismatch for AddKey(thresholdPublicKey) signing');
    }

    return await this.withSigningSession({
      prefix: 'no-prompt-add-threshold-key',
      options: { credential: args.credential, wrapKeySalt },
      handler: async (sessionId) => {
        const response = await this.signerWorkerManager.getContext().sendMessage({
          sessionId,
          message: {
            type: INTERNAL_WORKER_REQUEST_TYPE_SIGN_ADD_KEY_THRESHOLD_PUBLIC_KEY_NO_PROMPT,
            payload: {
              createdAt: Date.now(),
              decryption: {
                encryptedPrivateKeyData: localKeyMaterial.encryptedSk,
                encryptedPrivateKeyChacha20NonceB64u: localKeyMaterial.chacha20NonceB64u,
              },
              transactionContext: args.transactionContext,
              nearAccountId,
              thresholdPublicKey,
              relayerVerifyingShareB64u,
              clientParticipantId: typeof args.clientParticipantId === 'number' ? args.clientParticipantId : undefined,
              relayerParticipantId: typeof args.relayerParticipantId === 'number' ? args.relayerParticipantId : undefined,
            },
          },
          onEvent: args.onEvent,
        });

        if (!isSignAddKeyThresholdPublicKeyNoPromptSuccess(response)) {
          throw new Error('AddKey(thresholdPublicKey) signing failed');
        }
        if (!response.payload.success) {
          throw new Error(response.payload.error || 'AddKey(thresholdPublicKey) signing failed');
        }

        const signedTransactions = response.payload.signedTransactions || [];
        if (signedTransactions.length !== 1) {
          throw new Error(`Expected 1 signed transaction but received ${signedTransactions.length}`);
        }

        const signedTx = signedTransactions[0];
        if (!signedTx || !(signedTx as any).transaction || !(signedTx as any).signature) {
          throw new Error('Incomplete signed transaction data received for AddKey(thresholdPublicKey)');
        }
        return {
          signedTransaction: new SignedTransaction({
            transaction: (signedTx as any).transaction,
            signature: (signedTx as any).signature,
            borsh_bytes: Array.from((signedTx as any).borshBytes || []),
          }),
          nearAccountId: String(nearAccountId),
          logs: response.payload.logs || [],
        };
      },
    });
  }

  async signDelegateAction({
    delegate,
    rpcCall,
    signerMode,
    confirmationConfigOverride,
    title,
    body,
    onEvent,
  }: {
    delegate: DelegateActionInput;
    rpcCall: RpcCallPayload;
    signerMode: SignerMode;
    // Accept partial override; merging happens in handlers layer
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    title?: string;
    body?: string;
    onEvent?: (update: onProgressEvents) => void;
  }): Promise<{
    signedDelegate: WasmSignedDelegate;
    hash: string;
    nearAccountId: AccountId;
    logs?: string[];
  }> {
    const nearAccountId = toAccountId(rpcCall.nearAccountId || delegate.senderId);
    const signingSessionPolicy = this.resolveSigningSessionPolicy({});
    const normalizedRpcCall: RpcCallPayload = {
      contractId: rpcCall.contractId || this.tatchiPasskeyConfigs.contractId,
      nearRpcUrl: rpcCall.nearRpcUrl || this.tatchiPasskeyConfigs.nearRpcUrl,
      nearAccountId,
    };

    try {
      const activeSessionId = this.getOrCreateActiveSigningSessionId(nearAccountId);
      return await this.withSigningSession({
        sessionId: activeSessionId,
        attachWrapKeySeedPortToSecureConfirmWorker: true,
        handler: (sessionId) => {
          console.debug('[WebAuthnManager][delegate] session created', { sessionId });
          return this.signerWorkerManager.signDelegateAction({
            delegate,
            rpcCall: normalizedRpcCall,
            signerMode,
            confirmationConfigOverride,
            title,
            body,
            onEvent,
            signingSessionTtlMs: signingSessionPolicy.ttlMs,
            signingSessionRemainingUses: signingSessionPolicy.remainingUses,
            sessionId,
          });
        }
      });
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('[WebAuthnManager][delegate] failed', err);
      throw err;
    }
  }

  async signNEP413Message(payload: {
    message: string;
    recipient: string;
    nonce: string;
    state: string | null;
    accountId: AccountId;
    signerMode: SignerMode;
    title?: string;
    body?: string;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
  }): Promise<{
    success: boolean;
    accountId: string;
    publicKey: string;
    signature: string;
    state?: string;
    error?: string;
  }> {
    try {
      const activeSessionId = this.getOrCreateActiveSigningSessionId(payload.accountId);
      const signingSessionPolicy = this.resolveSigningSessionPolicy({});
      const contractId = this.tatchiPasskeyConfigs.contractId;
      const nearRpcUrl = (this.tatchiPasskeyConfigs.nearRpcUrl.split(',')[0] || this.tatchiPasskeyConfigs.nearRpcUrl);
      const result = await this.withSigningSession({
        sessionId: activeSessionId,
        attachWrapKeySeedPortToSecureConfirmWorker: true,
        handler: (sessionId) =>
          this.signerWorkerManager.signNep413Message({
            ...payload,
            sessionId,
            contractId,
            nearRpcUrl,
            signingSessionTtlMs: signingSessionPolicy.ttlMs,
            signingSessionRemainingUses: signingSessionPolicy.remainingUses,
          }),
      });
      if (result.success) {
        return result;
      } else {
        throw new Error(`NEP-413 signing failed: ${result.error || 'Unknown error'}`);
      }
    } catch (error: any) {
      console.error('WebAuthnManager: NEP-413 signing error:', error);
      return {
        success: false,
        accountId: '',
        publicKey: '',
        signature: '',
        error: error.message || 'Unknown error'
      };
    }
  }

  // === COSE OPERATIONS ===

  /**
   * Extract COSE public key from WebAuthn attestation object using WASM worker
   */
  async extractCosePublicKey(attestationObjectBase64url: string): Promise<Uint8Array> {
    return await this.signerWorkerManager.extractCosePublicKey(attestationObjectBase64url);
  }

  ///////////////////////////////////////
  // PRIVATE KEY EXPORT (Drawer/Modal in sandboxed iframe)
  ///////////////////////////////////////

  /** Worker-driven export: two-phase V2 (collect PRF → decrypt → show UI) */
  async exportNearKeypairWithUIWorkerDriven(
    nearAccountId: AccountId,
    options?: { variant?: 'drawer' | 'modal', theme?: 'dark' | 'light' }
  ): Promise<void> {
    const resolvedTheme = options?.theme ?? this.theme;

    const accountId = toAccountId(nearAccountId);
    const [last, latest] = await Promise.all([
      IndexedDBManager.clientDB.getLastUser().catch(() => null),
      IndexedDBManager.clientDB.getLastDBUpdatedUser(accountId).catch(() => null),
    ]);
    const userForAccount = (last && last.nearAccountId === accountId) ? last : latest;
    const deviceNumber =
      (last && last.nearAccountId === accountId && typeof last.deviceNumber === 'number')
        ? last.deviceNumber
        : (latest && typeof latest.deviceNumber === 'number')
          ? latest.deviceNumber
          : null;
    if (deviceNumber === null) {
      throw new Error(`No deviceNumber found for account ${accountId} (export/decrypt)`);
    }

    const [keyMaterial, thresholdKeyMaterial] = await Promise.all([
      IndexedDBManager.nearKeysDB.getLocalKeyMaterial(accountId, deviceNumber).catch(() => null),
      IndexedDBManager.nearKeysDB.getThresholdKeyMaterial(accountId, deviceNumber).catch(() => null),
    ]);

    // === Local-signer export: decrypt stored key material via PRF.first and show UI ===
    const wrapKeySalt = String(keyMaterial?.wrapKeySalt || '').trim();
    if (keyMaterial && wrapKeySalt) {
      const publicKey = String(userForAccount?.clientNearPublicKey || '').trim();
      if (!publicKey) {
        throw new Error(`Missing public key for account ${accountId}; please login again.`);
      }

      const requestId = (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function')
        ? crypto.randomUUID()
        : `decrypt-${Date.now()}-${Math.random().toString(16).slice(2)}`;

      // Prompt user + collect a WebAuthn assertion (with PRF outputs) via SecureConfirm.
      const decision = await runSecureConfirm(this.secureConfirmWorkerManager.getContext(), {
        requestId,
        type: SecureConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF,
        summary: {
          operation: 'Decrypt Private Key',
          accountId: String(accountId),
          publicKey,
          warning: 'Authenticate with your passkey to decrypt your local key material.',
        },
        payload: {
          nearAccountId: String(accountId),
          publicKey,
        },
        intentDigest: `decrypt:${accountId}:${deviceNumber}`,
      } satisfies SecureConfirmRequest);

      if (!decision?.confirmed) {
        throw new Error(decision?.error || 'User rejected decrypt request');
      }
      if (!decision.credential) {
        throw new Error('Missing WebAuthn credential for decrypt request');
      }

      // Phase 2 + 3: deliver WrapKeySeed to the signer worker, decrypt, then show UI.
      await this.withSigningSession({
        prefix: 'export-session',
        options: {
          credential: decision.credential as WebAuthnAuthenticationCredential,
          wrapKeySalt,
        },
        handler: async (sessionId) => this.signerWorkerManager.exportNearKeypairUi({
          nearAccountId,
          variant: options?.variant,
          theme: resolvedTheme,
          sessionId,
        }),
      });
      return;
    }

    // === Threshold-signer export: derive the backup/escape-hatch key from PRF.second and show UI ===
    if (thresholdKeyMaterial) {
      const publicKeyHint = String(userForAccount?.clientNearPublicKey || thresholdKeyMaterial.publicKey || '').trim();

      const requestId = (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function')
        ? crypto.randomUUID()
        : `export-${Date.now()}-${Math.random().toString(16).slice(2)}`;

      const decision = await runSecureConfirm(this.secureConfirmWorkerManager.getContext(), {
        requestId,
        type: SecureConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF,
        summary: {
          operation: 'Export Private Key',
          accountId: String(accountId),
          publicKey: publicKeyHint || '(derived from passkey)',
          warning: 'Authenticate with your passkey to derive your backup key (escape hatch).',
        },
        payload: {
          nearAccountId: String(accountId),
          publicKey: publicKeyHint,
        },
        intentDigest: `export-backup:${accountId}:${deviceNumber}`,
      } satisfies SecureConfirmRequest);

      if (!decision?.confirmed) {
        throw new Error(decision?.error || 'User rejected export request');
      }
      if (!decision.credential) {
        throw new Error('Missing WebAuthn credential for export request');
      }

      const prfSecondB64u = String((decision.credential as any)?.clientExtensionResults?.prf?.results?.second || '').trim();
      if (!prfSecondB64u) {
        throw new Error('Missing PRF.second output from credential (requires a PRF-enabled passkey)');
      }

      const derived = await deriveNearKeypairFromPrfSecondB64u({ prfSecondB64u, nearAccountId: String(accountId) });
      await runSecureConfirm(this.secureConfirmWorkerManager.getContext(), {
        requestId: `${requestId}-show`,
        type: SecureConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI,
        summary: {
          operation: 'Export Private Key',
          accountId: String(accountId),
          publicKey: derived.publicKey,
          warning: 'Anyone with your private key can fully control your account. Never share it.',
        },
        payload: {
          nearAccountId: String(accountId),
          publicKey: derived.publicKey,
          privateKey: derived.privateKey,
          variant: options?.variant,
          theme: resolvedTheme,
        },
        intentDigest: `export-backup:${accountId}:${deviceNumber}`,
      } satisfies SecureConfirmRequest);
      return;
    }

    throw new Error(`No key material found for account ${accountId} device ${deviceNumber}`);
  }

  async exportNearKeypairWithUI(
    nearAccountId: AccountId,
    options?: {
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light'
    }
  ): Promise<{ accountId: string; publicKey: string; privateKey: string }> {
    // Route to worker-driven two-phase flow. UI is shown inside the wallet host; no secrets are returned.
    await this.exportNearKeypairWithUIWorkerDriven(nearAccountId, options);
    // Surface the freshest device key for this account to the caller.
    // Prefer last user when it matches the account, else pick the most recently
    // updated user record for this account.
    let userData = await this.getLastUser();
    if (!userData || userData.nearAccountId !== nearAccountId) {
      userData = await IndexedDBManager.clientDB.getLastDBUpdatedUser(nearAccountId);
    }
    return {
      accountId: String(nearAccountId),
      publicKey: userData?.clientNearPublicKey ?? '',
      privateKey: '',
    };
  }

  ///////////////////////////////////////
  // REGISTRATION
  ///////////////////////////////////////

  ///////////////////////////////////////
  // ACCOUNT RECOVERY
  ///////////////////////////////////////

  /**
   * Recover keypair from authentication credential for account recovery
   * Uses dual PRF outputs to re-derive the same NEAR keypair and re-encrypt it
   * @param challenge - Random challenge for WebAuthn authentication ceremony
   * @param authenticationCredential - The authentication credential with dual PRF outputs
   * @param accountIdHint - Optional account ID hint for recovery
   * @returns Public key and encrypted private key for secure storage
   */
  async recoverKeypairFromPasskey(
    authenticationCredential: WebAuthnAuthenticationCredential,
    accountIdHint?: string,
  ): Promise<{
    publicKey: string;
    encryptedPrivateKey: string;
    /**
     * Base64url-encoded AEAD nonce (ChaCha20-Poly1305) for the encrypted private key.
     */
    chacha20NonceB64u: string;
    accountIdHint?: string;
    wrapKeySalt: string;
    stored?: boolean;
  }> {
    try {
      // Verify we have an authentication credential (not registration)
      if (!authenticationCredential) {
        throw new Error(
          'Authentication credential required for account recovery. ' +
          'Use an existing credential with dual PRF outputs to re-derive the same NEAR keypair.'
        );
      }

      // Verify dual PRF outputs are available
      const prfResults = authenticationCredential.clientExtensionResults?.prf?.results;
      if (!prfResults?.first || !prfResults?.second) {
        throw new Error('Dual PRF outputs required for account recovery - both AES and Ed25519 PRF outputs must be available');
      }

      // Extract PRF.first for WrapKeySeed derivation
      // Orchestrate a SecureConfirm-owned signing session with WrapKeySeed derivation, then ask
      // the signer to recover and re-encrypt the NEAR keypair.
      const result = await this.withSigningSession({
        prefix: 'recover',
        options: { credential: authenticationCredential },
        handler: (sessionId) =>
          this.signerWorkerManager.recoverKeypairFromPasskey({
            credential: authenticationCredential,
            accountIdHint,
            sessionId,
          }),
      });
      return result;

    } catch (error: any) {
      console.error('WebAuthnManager: Deterministic keypair derivation error:', error);
      throw new Error(`Deterministic keypair derivation failed: ${error.message}`);
    }
  }

  async getAuthenticationCredentialsSerializedDualPrf({
    nearAccountId,
    challengeB64u,
    credentialIds,
  }: {
    nearAccountId: AccountId;
    challengeB64u: string;
    credentialIds: string[];
  }): Promise<WebAuthnAuthenticationCredential> {
    // Same as getAuthenticationCredentialsSerialized but returns both PRF outputs (PRF.first + PRF.second).
    return this.touchIdPrompt.getAuthenticationCredentialsSerializedForChallengeB64u({
      nearAccountId,
      challengeB64u,
      allowCredentials: credentialIds.map(id => ({
        id: id,
        type: 'public-key',
        transports: ['internal', 'hybrid', 'usb', 'ble'] as AuthenticatorTransport[]
      })),
      includeSecondPrfOutput: true,
    });
  }

  /**
   * Sign transaction with raw private key
   * for key replacement in device linking
   * No TouchID/PRF required - uses provided private key directly
   */
  async signTransactionWithKeyPair({
    nearPrivateKey,
    signerAccountId,
    receiverId,
    nonce,
    blockHash,
    actions
  }: {
    nearPrivateKey: string;
    signerAccountId: string;
    receiverId: string;
    nonce: string;
    blockHash: string;
    actions: ActionArgsWasm[];
  }): Promise<{
    signedTransaction: SignedTransaction;
    logs?: string[];
  }> {
    return await this.signerWorkerManager.signTransactionWithKeyPair({
      nearPrivateKey,
      signerAccountId,
      receiverId,
      nonce,
      blockHash,
      actions
    });
  }

  // ==============================
  // Threshold Signing
  // ==============================

  /**
   * Lite threshold session connect (WebAuthn-only):
   * - builds a threshold session policy (and digest)
   * - collects a WebAuthn assertion with challenge=sessionPolicyDigest32
   * - derives `clientVerifyingShareB64u` from PRF.first (via signer worker)
   * - mints a relay session token via `POST /threshold-ed25519/session`
   *
   * Wallet-origin only: callers should run this in the wallet iframe / extension origin.
   */
  async connectThresholdEd25519SessionLite(args: {
    nearAccountId: AccountId | string;
    relayerKeyId: string;
    participantIds?: number[];
    sessionKind?: 'jwt' | 'cookie';
    relayerUrl?: string;
    ttlMs?: number;
    remainingUses?: number;
  }): Promise<Awaited<ReturnType<typeof connectThresholdEd25519SessionLite>>> {
    const relayerUrl = String(args.relayerUrl || this.tatchiPasskeyConfigs.relayer?.url || '').trim();
    if (!relayerUrl) {
      throw new Error('Missing relayer url (configs.relayer.url)');
    }
    return await connectThresholdEd25519SessionLite({
      indexedDB: IndexedDBManager,
      touchIdPrompt: this.touchIdPrompt,
      signerWorkerManager: this.signerWorkerManager,
      relayerUrl,
      relayerKeyId: args.relayerKeyId,
      nearAccountId: toAccountId(args.nearAccountId),
      participantIds: args.participantIds,
      sessionKind: args.sessionKind,
      sessionId: this.getOrCreateActiveSigningSessionId(toAccountId(args.nearAccountId)),
      ttlMs: args.ttlMs,
      remainingUses: args.remainingUses,
    });
  }

  /**
   * Read the wallet-origin warm signing session status (PRF.first cache) for the active signing session id.
   *
   * Notes:
   * - This is a best-effort introspection helper; it never prompts.
   * - When no active signing session id exists for the account, returns null.
   */
  async getWarmSigningSessionStatus(nearAccountId: AccountId | string): Promise<SigningSessionStatus | null> {
    try {
      const key = String(toAccountId(nearAccountId));
      const sessionId = this.activeSigningSessionIds.get(key);
      if (!sessionId) return null;

      const peek = await this.secureConfirmWorkerManager.peekPrfFirstForThresholdSession({ sessionId });
      if (peek.ok) {
        return {
          sessionId,
          status: 'active',
          remainingUses: peek.remainingUses,
          expiresAtMs: peek.expiresAtMs,
        };
      }

      const status =
        peek.code === 'expired'
          ? 'expired'
          : peek.code === 'exhausted'
            ? 'exhausted'
            : 'not_found';

      return { sessionId, status };
    } catch {
      return null;
    }
  }

  /**
   * Derive the deterministic threshold client verifying share (2-of-2 ed25519) from WrapKeySeed.
   * This is safe to call during registration because it only requires the PRF-bearing credential
   * (no on-chain verification needed) and returns public material only.
   */
  async deriveThresholdEd25519ClientVerifyingShareFromCredential(args: {
    credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
    nearAccountId: AccountId | string;
  }): Promise<{
    success: boolean;
    nearAccountId: string;
    clientVerifyingShareB64u: string;
    error?: string;
  }> {
    const nearAccountId = toAccountId(args.nearAccountId);
    try {
      return await this.withSigningSession({
        prefix: 'threshold-client-share',
        options: { credential: args.credential },
        handler: (sessionId) =>
          this.signerWorkerManager.deriveThresholdEd25519ClientVerifyingShare({
            sessionId,
            nearAccountId,
          }),
      });
    } catch (error: unknown) {
      const message = String((error as { message?: unknown })?.message ?? error);
      return {
        success: false,
        nearAccountId,
        clientVerifyingShareB64u: '',
        error: message,
      };
    }
  }

  /**
   * Threshold key enrollment (post-registration):
   * prompts for a dual-PRF WebAuthn authentication to obtain PRF.first/second,
   * then runs the `/threshold-ed25519/keygen` enrollment flow.
   *
   * This is intended to be called only after the passkey is registered on-chain.
   */
  async enrollThresholdEd25519KeyPostRegistration(args: {
    nearAccountId: AccountId | string;
    deviceNumber?: number;
  }): Promise<{
    success: boolean;
    publicKey: string;
    relayerKeyId: string;
    error?: string;
  }> {
    const nearAccountId = toAccountId(args.nearAccountId);

    try {
      const rpId = this.touchIdPrompt.getRpId();
      if (!rpId) throw new Error('Missing rpId for WebAuthn keygen challenge');

      // WebAuthn-only keygen uses a server-verified WebAuthn assertion bound to a deterministic
      // challenge digest (v1) with a client-generated nonce.
      const keygenSessionId = this.generateSessionId('threshold-keygen');
      const challengeB64u = await computeThresholdEd25519KeygenIntentDigest({
        nearAccountId,
        rpId,
        keygenSessionId,
      });

      const authCredential = await collectAuthenticationCredentialForChallengeB64u({
        indexedDB: IndexedDBManager,
        touchIdPrompt: this.touchIdPrompt,
        nearAccountId,
        challengeB64u,
      });

      return await this.enrollThresholdEd25519Key({
        credential: authCredential,
        nearAccountId,
        deviceNumber: args.deviceNumber,
        keygenSessionId,
      });
    } catch (error: unknown) {
      const message = String((error as { message?: unknown })?.message ?? error);
      return { success: false, publicKey: '', relayerKeyId: '', error: message };
    }
  }

  /**
   * Threshold key rotation (post-registration):
   * - keygen (new relayerKeyId + publicKey)
   * - AddKey(new threshold publicKey)
   * - DeleteKey(old threshold publicKey)
   *
   * Uses the local signer key for AddKey/DeleteKey, and requires the account to already
   * have a stored `threshold_ed25519_2p_v1` key material entry for the target device.
   */
  async rotateThresholdEd25519KeyPostRegistration(args: {
    nearAccountId: AccountId | string;
    deviceNumber?: number;
  }): Promise<{
    success: boolean;
    oldPublicKey: string;
    oldRelayerKeyId: string;
    publicKey: string;
    relayerKeyId: string;
    deleteOldKeyAttempted: boolean;
    deleteOldKeySuccess: boolean;
    warning?: string;
    error?: string;
  }> {
    const nearAccountId = toAccountId(args.nearAccountId);

    let oldPublicKey = '';
    let oldRelayerKeyId = '';

    try {
      const deviceNumber = Number(args.deviceNumber);
      const resolvedDeviceNumber = Number.isSafeInteger(deviceNumber) && deviceNumber >= 1
        ? deviceNumber
        : await getLastLoggedInDeviceNumber(nearAccountId, IndexedDBManager.clientDB).catch(() => 1);

      const existing = await IndexedDBManager.nearKeysDB.getThresholdKeyMaterial(nearAccountId, resolvedDeviceNumber);
      if (!existing) {
        throw new Error(
          `No threshold key material found for account ${nearAccountId} device ${resolvedDeviceNumber}. Call enrollThresholdEd25519Key() first.`,
        );
      }
      oldPublicKey = existing.publicKey;
      oldRelayerKeyId = existing.relayerKeyId;

      const enrollment = await this.enrollThresholdEd25519KeyPostRegistration({
        nearAccountId,
        deviceNumber: resolvedDeviceNumber,
      });
      if (!enrollment.success) {
        throw new Error(enrollment.error || 'Threshold keygen/enrollment failed');
      }

      return await rotateThresholdEd25519KeyPostRegistrationHandler(
        {
          nearClient: this.nearClient,
          contractId: this.tatchiPasskeyConfigs.contractId,
          nearRpcUrl: this.tatchiPasskeyConfigs.nearRpcUrl,
          signTransactionsWithActions: (params) => this.signTransactionsWithActions(params),
        },
        {
          nearAccountId,
          deviceNumber: resolvedDeviceNumber,
          oldPublicKey,
          oldRelayerKeyId,
          newPublicKey: enrollment.publicKey,
          newRelayerKeyId: enrollment.relayerKeyId,
        },
      );
    } catch (error: unknown) {
      const message = String((error as { message?: unknown })?.message ?? error);
      return {
        success: false,
        oldPublicKey,
        oldRelayerKeyId,
        publicKey: '',
        relayerKeyId: '',
        deleteOldKeyAttempted: false,
        deleteOldKeySuccess: false,
        error: message,
      };
    }
  }

  /**
   * Threshold key enrollment (2-of-2): deterministically derive the client verifying share
   * from WrapKeySeed and register the corresponding relayer share via `/threshold-ed25519/keygen`.
   *
   * Stores a v3 vault entry of kind `threshold_ed25519_2p_v1` (breaking; no migration).
   */
  async enrollThresholdEd25519Key(args: {
    credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
    nearAccountId: AccountId | string;
    deviceNumber?: number;
    /**
     * Client-generated nonce/id used for the keygen challenge (v1).
     * When provided, this is also used as the signer-worker session id so the
     * challenge nonce and internal share-derivation session are trivially correlated.
     */
    keygenSessionId?: string;
  }): Promise<{
    success: boolean;
    publicKey: string;
    relayerKeyId: string;
    error?: string;
  }> {
    const nearAccountId = toAccountId(args.nearAccountId);
    const relayerUrl = this.tatchiPasskeyConfigs.relayer.url;

    try {
      if (!relayerUrl) throw new Error('Missing relayer url (configs.relayer.url)');
      if (!args.credential) throw new Error('Missing credential');

      const deviceNumber = Number(args.deviceNumber);
      const resolvedDeviceNumber = Number.isSafeInteger(deviceNumber) && deviceNumber >= 1
        ? deviceNumber
        : await getLastLoggedInDeviceNumber(nearAccountId, IndexedDBManager.clientDB).catch(() => 1);

      const keygenSessionId = String(args.keygenSessionId || '').trim() || undefined;
      const keygen = await this.withSigningSession({
        ...(keygenSessionId ? { sessionId: keygenSessionId } : { prefix: 'threshold-keygen' }),
        options: { credential: args.credential },
        handler: (sessionId) =>
          enrollThresholdEd25519KeyHandler(
            {
              signerWorkerManager: this.signerWorkerManager,
              touchIdPrompt: this.touchIdPrompt,
              relayerUrl,
            },
            {
              sessionId,
              keygenSessionId,
              nearAccountId,
              webauthnAuthentication: (() => {
                const c = args.credential as WebAuthnAuthenticationCredential;
                if (!(c as any)?.response?.authenticatorData) {
                  throw new Error('Authentication credential required for threshold keygen');
                }
                return c;
              })(),
            },
          ),
      });

      if (!keygen.success) {
        throw new Error(keygen.error || 'Threshold keygen failed');
      }

      const publicKey = keygen.publicKey;
      const clientVerifyingShareB64u = keygen.clientVerifyingShareB64u;
      const relayerKeyId = keygen.relayerKeyId;
      const relayerVerifyingShareB64u = keygen.relayerVerifyingShareB64u;
      if (!clientVerifyingShareB64u) throw new Error('Threshold keygen returned empty clientVerifyingShareB64u');

      // If the key is already present (e.g. relay-created threshold-signer accounts), skip AddKey
      // and just persist local threshold metadata.
      const alreadyActive = await hasAccessKey(this.nearClient, nearAccountId, publicKey, { attempts: 1, delayMs: 0 });
      if (!alreadyActive) {
        // Activate threshold enrollment on-chain by submitting AddKey(publicKey) signed with the local key.
        const localKeyMaterial = await IndexedDBManager.nearKeysDB.getLocalKeyMaterial(nearAccountId, resolvedDeviceNumber);
        if (!localKeyMaterial) {
          throw new Error(`No local key material found for account ${nearAccountId} device ${resolvedDeviceNumber}`);
        }

        this.nonceManager.initializeUser(nearAccountId, localKeyMaterial.publicKey);
        const txContext = await this.nonceManager.getNonceBlockHashAndHeight(this.nearClient, { force: true });

        const signed = await this.signAddKeyThresholdPublicKeyNoPrompt({
          nearAccountId,
          credential: args.credential,
          wrapKeySalt: localKeyMaterial.wrapKeySalt,
          transactionContext: txContext,
          thresholdPublicKey: publicKey,
          relayerVerifyingShareB64u,
          clientParticipantId: keygen.clientParticipantId,
          relayerParticipantId: keygen.relayerParticipantId,
          deviceNumber: resolvedDeviceNumber,
        });

        const signedTx = signed?.signedTransaction;
        if (!signedTx) throw new Error('Failed to sign AddKey(thresholdPublicKey) transaction');

        await this.nearClient.sendTransaction(signedTx, DEFAULT_WAIT_STATUS.thresholdAddKey);

        const activated = await hasAccessKey(this.nearClient, nearAccountId, publicKey);
        if (!activated) throw new Error('Threshold access key not found on-chain after AddKey');
      }

      const keyMaterial: ThresholdEd25519_2p_V1Material = {
        kind: 'threshold_ed25519_2p_v1',
        nearAccountId,
        deviceNumber: resolvedDeviceNumber,
        publicKey,
        relayerKeyId,
        clientShareDerivation: 'prf_first_v1',
        participants: buildThresholdEd25519Participants2pV1({
          clientParticipantId: keygen.clientParticipantId,
          relayerParticipantId: keygen.relayerParticipantId,
          relayerKeyId,
          relayerUrl,
          clientVerifyingShareB64u,
          relayerVerifyingShareB64u,
          clientShareDerivation: 'prf_first_v1',
        }),
        timestamp: Date.now(),
      };
      await IndexedDBManager.nearKeysDB.storeKeyMaterial(keyMaterial);

      return {
        success: true,
        publicKey,
        relayerKeyId,
      };
    } catch (error: unknown) {
      const message = String((error as { message?: unknown })?.message ?? error);
      return { success: false, publicKey: '', relayerKeyId: '', error: message };
    }
  }

  // ==============================
  // USER SETTINGS
  // ==============================

  /** * Get user preferences manager */
  getUserPreferences(): UserPreferencesManager {
    return this.userPreferencesManager;
  }

  /** * Clean up resources */
  destroy(): void {
    if (this.userPreferencesManager) {
      this.userPreferencesManager.destroy();
    }
    if (this.nonceManager) {
      this.nonceManager.clear();
    }
    this.activeSigningSessionIds.clear();
  }

}
