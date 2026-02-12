import {
  IndexedDBManager,
  type ClientUserData,
  type ClientAuthenticatorData,
  type ProfileRecord,
  type ChainAccountRecord,
  type AccountSignerRecord,
  type SignerOpOutboxRecord,
  type UpsertProfileInput,
  type UpsertChainAccountInput,
  type UpsertAccountSignerInput,
  type EnqueueSignerOperationInput,
  type AccountSignerStatus,
  type UnifiedIndexedDBManager,
} from '../../IndexedDBManager';
import { StoreUserDataInput } from '../../IndexedDBManager/passkeyClientDB';
import { buildThresholdEd25519Participants2pV1 } from '../../../../../shared/src/threshold/participants';
import { type NearClient, SignedTransaction } from '../../near/NearClient';
import { SignerWorkerManager } from '../workers/signerWorkerManager';
import { SecureConfirmWorkerManager } from '../secureConfirm/manager';
import { AllowCredential, TouchIdPrompt } from '../webauthn/prompt/touchIdPrompt';
import { toAccountId } from '../../types/accountIds';
import { UserPreferencesManager } from './userPreferences';
import UserPreferencesInstance from './userPreferences';
import { NonceManager } from '../../near/nonceManager';
import NonceManagerInstance from '../../near/nonceManager';
import { ActionType, type ActionArgsWasm, type TransactionInputWasm } from '../../types/actions';
import type {
  RegistrationEventStep3,
  RegistrationHooksOptions,
  RegistrationSSEEvent,
  onProgressEvents,
} from '../../types/sdkSentEvents';
import type {
  SignTransactionResult,
  SigningSessionStatus,
  TatchiConfigs,
  ThemeName,
} from '../../types/tatchi';
import type { AccountId } from '../../types/accountIds';
import type { AuthenticatorOptions } from '../../types/authenticatorOptions';
import type { DelegateActionInput } from '../../types/delegate';
import {
  type ConfirmationConfig,
  type RpcCallPayload,
  type SignerMode,
  type ThresholdBehavior,
  type WasmSignedDelegate,
} from '../../types/signer-worker';
import { WebAuthnRegistrationCredential, WebAuthnAuthenticationCredential } from '../../types';
import { RegistrationCredentialConfirmationPayload } from '../workers/signerWorkerManager/internal/validation';
import { resolveWorkerBaseOrigin, onEmbeddedBaseChange } from '../../runtimeAssetPaths';
import { DEFAULT_WAIT_STATUS } from '../../types/rpc';
import { getLastLoggedInDeviceNumber } from '../webauthn/device/getDeviceNumber';
import { __isWalletIframeHostMode } from '../../WalletIframe/host-mode';
import { hasAccessKey } from '../../near/rpcCalls';
import { enrollThresholdEd25519KeyHandler } from '../threshold/workflows/enrollThresholdEd25519Key';
import { rotateThresholdEd25519KeyPostRegistrationHandler } from '../threshold/workflows/rotateThresholdEd25519KeyPostRegistration';
import { connectThresholdEd25519SessionLite } from '../threshold/workflows/connectThresholdEd25519SessionLite';
import { collectAuthenticationCredentialForChallengeB64u } from '../webauthn/credentials/collectAuthenticationCredentialForChallengeB64u';
import { computeThresholdEd25519KeygenIntentDigest } from '../../../utils/intentDigest';
import { deriveNearKeypairFromPrfSecondB64u } from '../../near/nearCrypto';
import { runSecureConfirm } from '../secureConfirm/secureConfirmBridge';
import {
  SecureConfirmationType,
  type SecureConfirmRequest,
  type ExportPrivateKeyDisplayEntry,
} from '../secureConfirm/confirmTxFlow/types';
import type { NearIntentResult, NearSigningRequest } from '../chainAdaptors/near/nearAdapter';
import type {
  TempoSecp256k1SigningRequest,
  TempoSigningRequest,
} from '../chainAdaptors/tempo/types';
import type { TempoSignedResult } from '../chainAdaptors/tempo/tempoAdapter';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../orchestration/types';
import {
  activateEvmThresholdEcdsaSessionLite,
  activateNearThresholdKeyNoPrompt,
  activateTempoThresholdEcdsaSessionLite,
  activateThresholdKeyForChain,
} from '../orchestration/activation';
import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from '../orchestration/activation';
export type { ThresholdEcdsaSessionBootstrapResult } from '../orchestration/activation';

const DUMMY_WRAP_KEY_SALT_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

/**
 * WebAuthnManager - Main orchestrator for WebAuthn operations
 *
 * Architecture:
 * - index.ts (this file): Main class orchestrating everything
 * - signerWorkerManager: signer-worker runtime bridge + nearKeyOps service
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
    this.touchIdPrompt = new TouchIdPrompt(tatchiPasskeyConfigs.iframeWallet?.rpIdOverride, true);
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
      },
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
    this.workerBaseOrigin =
      resolveWorkerBaseOrigin() || (typeof window !== 'undefined' ? window.location.origin : '');
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
    this.signerWorkerManager.preWarmWorkerPool().catch(() => {});
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
      await this.initializeCurrentUser(toAccountId(nearAccountId), this.nearClient).catch(
        () => null,
      );
    }
    // Prefetch latest block/nonce context (best-effort)
    await this.nonceManager.prefetchBlockheight(this.nearClient).catch(() => null);
    // Best-effort: open IndexedDB and warm key data for the account
    if (nearAccountId) {
      const accountId = toAccountId(nearAccountId);
      const deviceNumber = await getLastLoggedInDeviceNumber(accountId, IndexedDBManager.clientDB).catch(
        () => 1,
      );
      await Promise.all([
        IndexedDBManager.getNearLocalKeyMaterialV2First(accountId, deviceNumber),
        IndexedDBManager.getNearThresholdKeyMaterialV2First(accountId, deviceNumber),
      ]).catch(() => null);
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
   * Generate a unique session id for signer-worker requests.
   * Session ids also key the wallet-origin warm PRF cache.
   */
  private generateSessionId(prefix: string): string {
    return typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID()
      : `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }

  private toNonNegativeInt(value: unknown): number | undefined {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return undefined;
    return Math.floor(value);
  }

  private resolveSigningSessionPolicy(args: { ttlMs?: number; remainingUses?: number }): {
    ttlMs: number;
    remainingUses: number;
  } {
    const ttlMs =
      this.toNonNegativeInt(args.ttlMs) ?? this.tatchiPasskeyConfigs.signingSessionDefaults.ttlMs;
    const remainingUses =
      this.toNonNegativeInt(args.remainingUses) ??
      this.tatchiPasskeyConfigs.signingSessionDefaults.remainingUses;
    return { ttlMs, remainingUses };
  }

  private extractPrfFirstB64u(
    credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential,
  ): string {
    const prfFirst = (credential as any)?.clientExtensionResults?.prf?.results?.first;
    const trimmed = typeof prfFirst === 'string' ? prfFirst.trim() : '';
    if (!trimmed) {
      throw new Error('Missing PRF.first output from credential (requires a PRF-enabled passkey)');
    }
    return trimmed;
  }

  private extractPrfSecondB64u(
    credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential,
  ): string {
    const prfSecond = (credential as any)?.clientExtensionResults?.prf?.results?.second;
    const trimmed = typeof prfSecond === 'string' ? prfSecond.trim() : '';
    if (!trimmed) {
      throw new Error('Missing PRF.second output from credential (requires a PRF-enabled passkey)');
    }
    return trimmed;
  }

  private getOrCreateActiveSigningSessionId(nearAccountId: AccountId): string {
    const key = String(toAccountId(nearAccountId));
    const existing = this.activeSigningSessionIds.get(key);
    if (existing) return existing;
    const sessionId = this.generateSessionId('signing-session');
    this.activeSigningSessionIds.set(key, sessionId);
    return sessionId;
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
      persistToDb?: boolean;
    };
  }): Promise<{
    success: boolean;
    nearAccountId: string;
    publicKey: string;
    chacha20NonceB64u?: string;
    wrapKeySalt?: string;
    encryptedSk?: string;
    error?: string;
  }> {
    const sessionId = this.generateSessionId('reg');
    return this.signerWorkerManager.nearKeyOps.deriveNearKeypairAndEncryptFromSerialized({
      credential,
      nearAccountId: toAccountId(nearAccountId),
      options,
      sessionId,
    });
  }

  ///////////////////////////////////////
  // INDEXEDDB OPERATIONS
  ///////////////////////////////////////

  async storeUserData(userData: StoreUserDataInput): Promise<void> {
    await IndexedDBManager.clientDB.upsertNearAccountProjection({
      ...userData,
      deviceNumber: userData.deviceNumber ?? 1,
      version: userData.version || 2,
    });
  }

  // === V2 MULTICHAIN INDEXEDDB OPERATIONS ===

  async getProfile(profileId: string): Promise<ProfileRecord | null> {
    return await IndexedDBManager.getProfile(profileId);
  }

  async upsertProfile(input: UpsertProfileInput): Promise<ProfileRecord> {
    return await IndexedDBManager.upsertProfile(input);
  }

  async upsertChainAccount(input: UpsertChainAccountInput): Promise<ChainAccountRecord> {
    return await IndexedDBManager.upsertChainAccount(input);
  }

  async getProfileByAccount(chainId: string, accountAddress: string): Promise<ProfileRecord | null> {
    return await IndexedDBManager.getProfileByAccount(chainId, accountAddress);
  }

  async upsertAccountSigner(input: UpsertAccountSignerInput): Promise<AccountSignerRecord> {
    return await IndexedDBManager.upsertAccountSigner(input);
  }

  async listAccountSigners(args: {
    chainId: string;
    accountAddress: string;
    status?: AccountSignerStatus;
  }): Promise<AccountSignerRecord[]> {
    return await IndexedDBManager.listAccountSigners(args);
  }

  async setAccountSignerStatus(args: {
    chainId: string;
    accountAddress: string;
    signerId: string;
    status: AccountSignerStatus;
    removedAt?: number;
  }): Promise<AccountSignerRecord | null> {
    return await IndexedDBManager.setAccountSignerStatus(args);
  }

  async enqueueSignerOperation(input: EnqueueSignerOperationInput): Promise<SignerOpOutboxRecord> {
    return await IndexedDBManager.enqueueSignerOperation(input);
  }

  async getAllUsers(): Promise<ClientUserData[]> {
    return await IndexedDBManager.clientDB.listNearAccountProjections();
  }

  async getUserByDevice(
    nearAccountId: AccountId,
    deviceNumber: number,
  ): Promise<ClientUserData | null> {
    return await IndexedDBManager.clientDB.getNearAccountProjection(nearAccountId, deviceNumber);
  }

  async getLastUser(): Promise<ClientUserData | null> {
    return await IndexedDBManager.clientDB.getLastSelectedNearAccountProjection();
  }

  async getAuthenticatorsByUser(nearAccountId: AccountId): Promise<ClientAuthenticatorData[]> {
    return await IndexedDBManager.clientDB.listNearAuthenticators(nearAccountId);
  }

  async updateLastLogin(nearAccountId: AccountId): Promise<void> {
    return await IndexedDBManager.clientDB.touchLastLoginForNearAccount(nearAccountId);
  }

  /**
   * Set the last logged-in user
   * @param nearAccountId - The account ID of the user
   * @param deviceNumber - The device number (defaults to 1)
   */
  async setLastUser(nearAccountId: AccountId, deviceNumber: number = 1): Promise<void> {
    return await IndexedDBManager.clientDB.setLastProfileStateForNearAccount(nearAccountId, deviceNumber);
  }

  /**
   * Initialize current user authentication state
   * This should be called after the user is authenticated (e.g. after login)
   * to ensure the user is properly tracked and can perform transactions.
   *
   * @param nearAccountId - The NEAR account ID to initialize
   * @param nearClient - The NEAR client for nonce prefetching
   */
  async initializeCurrentUser(nearAccountId: AccountId, nearClient?: NearClient): Promise<void> {
    const accountId = toAccountId(nearAccountId);

    // Set as last profile/device for future sessions, preferring the existing pointer.
    let deviceNumberToUse = await getLastLoggedInDeviceNumber(accountId, IndexedDBManager.clientDB).catch(
      () => null as number | null,
    );
    if (deviceNumberToUse === null) {
      const context = await IndexedDBManager.clientDB.resolveNearAccountContext(accountId).catch(() => null);
      const profile = context?.profileId
        ? await IndexedDBManager.clientDB.getProfile(context.profileId).catch(() => null)
        : null;
      const defaultDevice = Number(profile?.defaultDeviceNumber);
      deviceNumberToUse =
        Number.isSafeInteger(defaultDevice) && defaultDevice >= 1
          ? defaultDevice
          : 1;
    }
    await IndexedDBManager.clientDB.setLastProfileStateForNearAccount(accountId, deviceNumberToUse);

    // Set as current user for immediate use
    this.userPreferencesManager.setCurrentUser(accountId);
    // Ensure confirmation preferences are loaded before callers read them (best-effort)
    await this.userPreferencesManager.reloadUserSettings().catch(() => undefined);

    // Initialize NonceManager with the selected user's public key (best-effort)
    const userData = await this.getUserByDevice(accountId, deviceNumberToUse).catch(() => null);
    if (userData && userData.clientNearPublicKey) {
      this.nonceManager.initializeUser(accountId, userData.clientNearPublicKey);
    }

    // Prefetch block height for better UX (non-fatal if it fails and nearClient is provided)
    if (nearClient) {
      await this.nonceManager
        .prefetchBlockheight(nearClient)
        .catch((prefetchErr) =>
          console.debug(
            'Nonce prefetch after authentication state initialization failed (non-fatal):',
            prefetchErr,
          ),
        );
    }
  }

  async registerUser(storeUserData: StoreUserDataInput): Promise<ClientUserData> {
    return await IndexedDBManager.clientDB.upsertNearAccountProjection(storeUserData);
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
    const normalizedDeviceNumber =
      Number.isSafeInteger(deviceNumber) && deviceNumber >= 1 ? deviceNumber : 1;
    const authData = {
      ...authenticatorData,
      nearAccountId: toAccountId(authenticatorData.nearAccountId),
      deviceNumber: normalizedDeviceNumber, // Default to device 1 (1-indexed)
    };
    return await IndexedDBManager.clientDB.upsertNearAuthenticator(authData);
  }

  extractUsername(nearAccountId: AccountId): string {
    return String(nearAccountId).split('.')[0] || '';
  }

  async atomicOperation<T>(callback: (db: any) => Promise<T>): Promise<T> {
    return await IndexedDBManager.clientDB.atomicOperation(callback);
  }

  async rollbackUserRegistration(nearAccountId: AccountId): Promise<void> {
    return await IndexedDBManager.clientDB.rollbackNearAccountRegistration(nearAccountId);
  }

  async hasPasskeyCredential(nearAccountId: AccountId): Promise<boolean> {
    return await IndexedDBManager.clientDB.hasNearPasskeyCredential(nearAccountId);
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
      const credentialPublicKey = await this.extractCosePublicKey(attestationB64u);

      // Persist profile/account mapping first.
      await this.storeUserData({
        nearAccountId,
        deviceNumber: 1,
        clientNearPublicKey: publicKey,
        lastUpdated: Date.now(),
        passkeyCredential: {
          id: credential.id,
          rawId: credentialId,
        },
        version: 2,
      });

      await this.storeAuthenticator({
        nearAccountId: nearAccountId,
        credentialId: credentialId,
        credentialPublicKey,
        transports,
        name: `Passkey for ${this.extractUsername(nearAccountId)}`,
        registered: new Date().toISOString(),
        syncedAt: new Date().toISOString(),
      });

      return true;
    });
  }

  ///////////////////////////////////////
  // SIGNER WASM WORKER OPERATIONS
  ///////////////////////////////////////

  private async signNearWithIntent<TRequest extends NearSigningRequest>(
    request: TRequest,
  ): Promise<NearIntentResult<TRequest>> {
    const [{ signWithIntent }, { NearAdapter }, { NearEd25519Engine, NEAR_ED25519_KEY_REF }] =
      await Promise.all([
        import('../orchestration/signWithIntent'),
        import('../chainAdaptors/near/nearAdapter'),
        import('../engines/ed25519'),
      ]);

    return await signWithIntent({
      adapter: new NearAdapter(),
      request,
      engines: { ed25519: new NearEd25519Engine() },
      resolveSignInput: async (signReq) => ({ signReq, keyRef: NEAR_ED25519_KEY_REF }),
    }) as NearIntentResult<TRequest>;
  }

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
    deviceNumber,
    signerMode,
    confirmationConfigOverride,
    title,
    body,
    onEvent,
    sessionId,
  }: {
    transactions: TransactionInputWasm[];
    rpcCall: RpcCallPayload;
    deviceNumber?: number;
    signerMode: SignerMode;
    // Accept partial override; merging happens in handlers layer
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    title?: string;
    body?: string;
    onEvent?: (update: onProgressEvents) => void;
    sessionId?: string;
  }): Promise<SignTransactionResult[]> {
    const signingSessionPolicy = this.resolveSigningSessionPolicy({});
    const resolvedSessionId =
      String(sessionId || '').trim() ||
      this.getOrCreateActiveSigningSessionId(toAccountId(rpcCall.nearAccountId));
    const ctx = this.signerWorkerManager.getContext();
    return await this.signNearWithIntent({
      chain: 'near',
      kind: 'transactionsWithActions',
      payload: {
        ctx,
        transactions,
        rpcCall,
        deviceNumber,
        signerMode,
        confirmationConfigOverride,
        title,
        body,
        onEvent,
        signingSessionTtlMs: signingSessionPolicy.ttlMs,
        signingSessionRemainingUses: signingSessionPolicy.remainingUses,
        sessionId: resolvedSessionId,
      },
    });
  }

  async signDelegateAction({
    delegate,
    rpcCall,
    deviceNumber,
    signerMode,
    confirmationConfigOverride,
    title,
    body,
    onEvent,
  }: {
    delegate: DelegateActionInput;
    rpcCall: RpcCallPayload;
    deviceNumber?: number;
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
      console.debug('[WebAuthnManager][delegate] session created', { sessionId: activeSessionId });
      const ctx = this.signerWorkerManager.getContext();
      return await this.signNearWithIntent({
        chain: 'near',
        kind: 'delegateAction',
        payload: {
          ctx,
          delegate,
          rpcCall: normalizedRpcCall,
          deviceNumber,
          signerMode,
          confirmationConfigOverride,
          title,
          body,
          onEvent,
          signingSessionTtlMs: signingSessionPolicy.ttlMs,
          signingSessionRemainingUses: signingSessionPolicy.remainingUses,
          sessionId: activeSessionId,
        },
      }) as {
        signedDelegate: WasmSignedDelegate;
        hash: string;
        nearAccountId: AccountId;
        logs?: string[];
      };
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
    deviceNumber?: number;
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
      const nearRpcUrl =
        this.tatchiPasskeyConfigs.nearRpcUrl.split(',')[0] || this.tatchiPasskeyConfigs.nearRpcUrl;
      const ctx = this.signerWorkerManager.getContext();
      const result = await this.signNearWithIntent({
        chain: 'near',
        kind: 'nep413',
        payload: {
          ctx,
          payload: {
            ...payload,
            sessionId: activeSessionId,
            contractId,
            nearRpcUrl,
            signingSessionTtlMs: signingSessionPolicy.ttlMs,
            signingSessionRemainingUses: signingSessionPolicy.remainingUses,
          },
        },
      }) as {
        success: boolean;
        accountId: string;
        publicKey: string;
        signature: string;
        state?: string;
        error?: string;
      };
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
        error: error.message || 'Unknown error',
      };
    }
  }

  async signTempo(args: {
    nearAccountId: string;
    request: TempoSigningRequest;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    thresholdEcdsaKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
  }): Promise<TempoSignedResult> {
    if (args.request.chain !== 'tempo') {
      throw new Error('[WebAuthnManager] invalid Tempo request: chain must be tempo');
    }
    if (args.request.senderSignatureAlgorithm === 'secp256k1' && !args.thresholdEcdsaKeyRef) {
      throw new Error('[WebAuthnManager] Tempo secp256k1 signing requires thresholdEcdsaKeyRef');
    }

    const [{ signTempoWithSecureConfirm }, { Secp256k1Engine }, { WebAuthnP256Engine }] =
      await Promise.all([
        import('../chainAdaptors/tempo/handlers/signTempoWithSecureConfirm'),
        import('../engines/secp256k1'),
        import('../engines/webauthnP256'),
      ]);

    const signerWorkerCtx = this.signerWorkerManager.getContext();
    const ctx = this.secureConfirmWorkerManager.getContext();
    return await signTempoWithSecureConfirm({
      ctx,
      secureConfirmWorkerManager: this.secureConfirmWorkerManager,
      workerCtx: signerWorkerCtx,
      nearAccountId: args.nearAccountId,
      request: args.request,
      engines: {
        secp256k1: new Secp256k1Engine({
          getRpId: () => ctx.touchIdPrompt.getRpId(),
          workerCtx: signerWorkerCtx,
          dispenseThresholdEcdsaPrfFirstForSession: (payload) =>
            this.secureConfirmWorkerManager.dispensePrfFirstForThresholdSession(payload),
        }),
        webauthnP256: new WebAuthnP256Engine(),
      },
      ...(args.thresholdEcdsaKeyRef
        ? { keyRefsByAlgorithm: { secp256k1: args.thresholdEcdsaKeyRef } }
        : {}),
      confirmationConfigOverride: args.confirmationConfigOverride,
    });
  }

  async signTempoWithThresholdEcdsa(args: {
    nearAccountId: string;
    request: TempoSecp256k1SigningRequest;
    thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
  }): Promise<TempoSignedResult> {
    if (args.request.senderSignatureAlgorithm !== 'secp256k1') {
      throw new Error(
        '[WebAuthnManager] signTempoWithThresholdEcdsa requires senderSignatureAlgorithm=secp256k1',
      );
    }
    return await this.signTempo({
      nearAccountId: args.nearAccountId,
      request: args.request,
      thresholdEcdsaKeyRef: args.thresholdEcdsaKeyRef,
      confirmationConfigOverride: args.confirmationConfigOverride,
    });
  }

  // === COSE OPERATIONS ===

  /**
   * Extract COSE public key from WebAuthn attestation object using WASM worker
   */
  async extractCosePublicKey(attestationObjectBase64url: string): Promise<Uint8Array> {
    return await this.signerWorkerManager.nearKeyOps.extractCosePublicKey(attestationObjectBase64url);
  }

  ///////////////////////////////////////
  // PRIVATE KEY EXPORT (Drawer/Modal in sandboxed iframe)
  ///////////////////////////////////////

  /** Worker-driven export: two-phase V2 (collect PRF → decrypt → show UI) */
  async exportNearKeypairWithUIWorkerDriven(
    nearAccountId: AccountId,
    options?: { variant?: 'drawer' | 'modal'; theme?: 'dark' | 'light' },
  ): Promise<void> {
    const resolvedTheme = options?.theme ?? this.theme;

    const accountId = toAccountId(nearAccountId);
    const deviceNumber = await getLastLoggedInDeviceNumber(accountId, IndexedDBManager.clientDB).catch(
      () => null as number | null,
    );
    if (deviceNumber == null) {
      throw new Error(`No deviceNumber found for account ${accountId} (export/decrypt)`);
    }
    const userForAccount = await IndexedDBManager.clientDB
      .getNearAccountProjection(accountId, deviceNumber)
      .catch(() => null);

    const [keyMaterial, thresholdKeyMaterial] = await Promise.all([
      IndexedDBManager.getNearLocalKeyMaterialV2First(accountId, deviceNumber).catch(() => null),
      IndexedDBManager.getNearThresholdKeyMaterialV2First(accountId, deviceNumber).catch(
        () => null,
      ),
    ]);

    // === Local-signer export: decrypt stored key material via PRF.first and show UI ===
    const wrapKeySalt = String(keyMaterial?.wrapKeySalt || '').trim();
    if (keyMaterial && wrapKeySalt) {
      const publicKey = String(userForAccount?.clientNearPublicKey || '').trim();
      if (!publicKey) {
        throw new Error(`Missing public key for account ${accountId}; please login again.`);
      }

      const requestId =
        typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
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

      const prfFirstB64u = this.extractPrfFirstB64u(
        decision.credential as WebAuthnAuthenticationCredential,
      );
      const sessionId = requestId;

      // Phase 2 + 3: decrypt in signer worker using direct PRF, then show UI.
      await this.signerWorkerManager.nearKeyOps.exportNearKeypairUi({
        nearAccountId,
        variant: options?.variant,
        theme: resolvedTheme,
        sessionId,
        prfFirstB64u,
        wrapKeySalt,
      });
      return;
    }

    // === Threshold-signer export: derive the backup/escape-hatch key from PRF.second and show UI ===
    if (thresholdKeyMaterial) {
      const publicKeyHint = String(
        userForAccount?.clientNearPublicKey || thresholdKeyMaterial.publicKey || '',
      ).trim();

      const requestId =
        typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
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

      const prfSecondB64u = String(
        (decision.credential as any)?.clientExtensionResults?.prf?.results?.second || '',
      ).trim();
      if (!prfSecondB64u) {
        throw new Error(
          'Missing PRF.second output from credential (requires a PRF-enabled passkey)',
        );
      }

      const derived = await deriveNearKeypairFromPrfSecondB64u({
        prfSecondB64u,
        nearAccountId: String(accountId),
      });
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
      theme?: 'dark' | 'light';
    },
  ): Promise<{ accountId: string; publicKey: string; privateKey: string }> {
    // Route to worker-driven two-phase flow. UI is shown inside the wallet host; no secrets are returned.
    await this.exportNearKeypairWithUIWorkerDriven(nearAccountId, options);
    const accountId = toAccountId(nearAccountId);
    const deviceNumber = await getLastLoggedInDeviceNumber(accountId, IndexedDBManager.clientDB).catch(
      () => null as number | null,
    );
    const userData =
      deviceNumber != null
        ? await IndexedDBManager.clientDB.getNearAccountProjection(accountId, deviceNumber).catch(() => null)
        : null;
    return {
      accountId: String(nearAccountId),
      publicKey: userData?.clientNearPublicKey ?? '',
      privateKey: '',
    };
  }

  /**
   * Worker-driven multi-key export:
   * - collects PRF outputs in wallet origin
   * - derives/decrypts requested key material
   * - displays all requested keys in ExportPrivateKey iframe viewer
   */
  async exportPrivateKeysWithUIWorkerDriven(
    nearAccountId: AccountId,
    options?: {
      schemes?: Array<'ed25519' | 'secp256k1'>;
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    },
  ): Promise<void> {
    const resolvedTheme = options?.theme ?? this.theme;
    const requestedSchemes =
      Array.isArray(options?.schemes) && options?.schemes.length
        ? options.schemes
        : (['ed25519', 'secp256k1'] as const);
    const schemes = Array.from(new Set(requestedSchemes)).filter(
      (scheme): scheme is 'ed25519' | 'secp256k1' => scheme === 'ed25519' || scheme === 'secp256k1',
    );
    if (!schemes.length) throw new Error('No export schemes requested');

    const accountId = toAccountId(nearAccountId);
    const deviceNumber = await getLastLoggedInDeviceNumber(accountId, IndexedDBManager.clientDB).catch(
      () => null as number | null,
    );
    if (deviceNumber == null) {
      throw new Error(`No deviceNumber found for account ${accountId} (export/decrypt)`);
    }
    const userForAccount = await IndexedDBManager.clientDB
      .getNearAccountProjection(accountId, deviceNumber)
      .catch(() => null);

    const [keyMaterial, thresholdKeyMaterial] = await Promise.all([
      IndexedDBManager.getNearLocalKeyMaterialV2First(accountId, deviceNumber).catch(() => null),
      IndexedDBManager.getNearThresholdKeyMaterialV2First(accountId, deviceNumber).catch(
        () => null,
      ),
    ]);
    if (!keyMaterial && !thresholdKeyMaterial) {
      throw new Error(`No key material found for account ${accountId} device ${deviceNumber}`);
    }

    const publicKeyHint = String(
      userForAccount?.clientNearPublicKey ||
        keyMaterial?.publicKey ||
        thresholdKeyMaterial?.publicKey ||
        '',
    ).trim();

    const requestId =
      typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
        ? crypto.randomUUID()
        : `export-keys-${Date.now()}-${Math.random().toString(16).slice(2)}`;

    const decision = await runSecureConfirm(this.secureConfirmWorkerManager.getContext(), {
      requestId,
      type: SecureConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF,
      summary: {
        operation: 'Export Private Key',
        accountId: String(accountId),
        publicKey: publicKeyHint || '(derived from passkey)',
        warning: 'Authenticate with your passkey to prepare export keys.',
      },
      payload: {
        nearAccountId: String(accountId),
        publicKey: publicKeyHint,
      },
      intentDigest: `export-keys:${accountId}:${deviceNumber}`,
    } satisfies SecureConfirmRequest);

    if (!decision?.confirmed) {
      throw new Error(decision?.error || 'User rejected export request');
    }
    if (!decision.credential) {
      throw new Error('Missing WebAuthn credential for export request');
    }

    const credential = decision.credential as WebAuthnAuthenticationCredential;
    const exportKeys: ExportPrivateKeyDisplayEntry[] = [];

    if (schemes.includes('ed25519')) {
      const localWrapKeySalt = String(keyMaterial?.wrapKeySalt || '').trim();
      if (keyMaterial && localWrapKeySalt) {
        const prfFirstB64u = this.extractPrfFirstB64u(credential);
        const decrypted = await this.signerWorkerManager.nearKeyOps.decryptPrivateKeyWithPrf({
          nearAccountId: accountId,
          authenticators: [],
          sessionId: `${requestId}:ed25519`,
          prfFirstB64u,
          wrapKeySalt: localWrapKeySalt,
        });
        exportKeys.push({
          scheme: 'ed25519',
          label: 'NEAR Ed25519',
          publicKey: String(keyMaterial.publicKey || publicKeyHint || '').trim(),
          privateKey: String(decrypted.decryptedPrivateKey || '').trim(),
        });
      } else {
        const prfSecondB64u = this.extractPrfSecondB64u(credential);
        const derived = await deriveNearKeypairFromPrfSecondB64u({
          prfSecondB64u,
          nearAccountId: String(accountId),
        });
        exportKeys.push({
          scheme: 'ed25519',
          label: 'NEAR Ed25519',
          publicKey: derived.publicKey,
          privateKey: derived.privateKey,
        });
      }
    }

    if (schemes.includes('secp256k1')) {
      const prfSecondB64u = this.extractPrfSecondB64u(credential);
      const { deriveSecp256k1KeypairFromPrfSecondB64u } = await import(
        '../chainAdaptors/evm/deriveSecp256k1KeypairFromPrfSecond'
      );
      const derived = deriveSecp256k1KeypairFromPrfSecondB64u({
        prfSecondB64u,
        nearAccountId: String(accountId),
      });
      exportKeys.push({
        scheme: 'secp256k1',
        label: 'EVM secp256k1',
        publicKey: derived.publicKeyHex,
        privateKey: derived.privateKeyHex,
        address: derived.ethereumAddress,
      });
    }

    if (!exportKeys.length) {
      throw new Error('No exportable keys were produced');
    }

    const first = exportKeys[0]!;
    await runSecureConfirm(this.secureConfirmWorkerManager.getContext(), {
      requestId: `${requestId}-show`,
      type: SecureConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI,
      summary: {
        operation: 'Export Private Key',
        accountId: String(accountId),
        publicKey: first.publicKey,
        warning: 'Anyone with your private key can fully control your account. Never share it.',
      },
      payload: {
        nearAccountId: String(accountId),
        publicKey: first.publicKey,
        privateKey: first.privateKey,
        keys: exportKeys,
        variant: options?.variant,
        theme: resolvedTheme,
      },
      intentDigest: `export-keys:${accountId}:${deviceNumber}`,
    } satisfies SecureConfirmRequest);
  }

  async exportPrivateKeysWithUI(
    nearAccountId: AccountId,
    options?: {
      schemes?: Array<'ed25519' | 'secp256k1'>;
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    },
  ): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
    const requestedSchemes =
      Array.isArray(options?.schemes) && options?.schemes.length
        ? options.schemes
        : (['ed25519', 'secp256k1'] as const);
    const exportedSchemes = Array.from(new Set(requestedSchemes)).filter(
      (scheme): scheme is 'ed25519' | 'secp256k1' => scheme === 'ed25519' || scheme === 'secp256k1',
    );
    await this.exportPrivateKeysWithUIWorkerDriven(nearAccountId, options);
    return {
      accountId: String(nearAccountId),
      exportedSchemes,
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
            'Use an existing credential with dual PRF outputs to re-derive the same NEAR keypair.',
        );
      }

      // Verify dual PRF outputs are available
      const prfResults = authenticationCredential.clientExtensionResults?.prf?.results;
      if (!prfResults?.first || !prfResults?.second) {
        throw new Error(
          'Dual PRF outputs required for account recovery - both AES and Ed25519 PRF outputs must be available',
        );
      }

      // Extract PRF.first for WrapKeySeed derivation
      // Orchestrate a SecureConfirm-owned signing session with WrapKeySeed derivation, then ask
      // the signer to recover and re-encrypt the NEAR keypair.
      const sessionId = this.generateSessionId('recover');
      const result = await this.signerWorkerManager.nearKeyOps.recoverKeypairFromPasskey({
        credential: authenticationCredential,
        accountIdHint,
        sessionId,
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
      allowCredentials: credentialIds.map((id) => ({
        id: id,
        type: 'public-key',
        transports: ['internal', 'hybrid', 'usb', 'ble'] as AuthenticatorTransport[],
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
    actions,
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
    return await this.signerWorkerManager.nearKeyOps.signTransactionWithKeyPair({
      nearPrivateKey,
      signerAccountId,
      receiverId,
      nonce,
      blockHash,
      actions,
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
    const relayerUrl = String(
      args.relayerUrl || this.tatchiPasskeyConfigs.relayer?.url || '',
    ).trim();
    if (!relayerUrl) {
      throw new Error('Missing relayer url (configs.relayer.url)');
    }
    return await connectThresholdEd25519SessionLite({
      indexedDB: IndexedDBManager,
      touchIdPrompt: this.touchIdPrompt,
      signingKeyOps: this.signerWorkerManager.nearKeyOps,
      prfFirstCache: {
        putPrfFirstForThresholdSession: this.secureConfirmWorkerManager
          .putPrfFirstForThresholdSession
          .bind(this.secureConfirmWorkerManager),
      },
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
   * Threshold ECDSA (secp256k1) bootstrap helper:
   * - runs `/threshold-ecdsa/keygen`
   * - mints a threshold signing session via `/threshold-ecdsa/session`
   * - returns a ready `threshold-ecdsa-secp256k1` keyRef for high-level Tempo/EVM signing APIs
   *
   * Defaults to `chain: 'tempo'` when omitted for backward compatibility.
   *
   * Wallet-origin only: callers should run this in the wallet iframe / extension origin.
   */
  async bootstrapThresholdEcdsaSessionLite(args: {
    nearAccountId: AccountId | string;
    chain?: ThresholdEcdsaActivationChain;
    relayerUrl?: string;
    participantIds?: number[];
    sessionKind?: 'jwt' | 'cookie';
    ttlMs?: number;
    remainingUses?: number;
  }): Promise<ThresholdEcdsaSessionBootstrapResult> {
    const nearAccountId = toAccountId(args.nearAccountId);
    const chain: ThresholdEcdsaActivationChain = args.chain || 'tempo';
    const relayerUrl = String(
      args.relayerUrl || this.tatchiPasskeyConfigs.relayer?.url || '',
    ).trim();
    if (!relayerUrl) {
      throw new Error('Missing relayer url (configs.relayer.url)');
    }

    const signerWorkerCtx = this.signerWorkerManager.getContext();
    const activationDeps = {
      indexedDB: IndexedDBManager,
      touchIdPrompt: this.touchIdPrompt,
      prfFirstCache: {
        putPrfFirstForThresholdSession: this.secureConfirmWorkerManager
          .putPrfFirstForThresholdSession
          .bind(this.secureConfirmWorkerManager),
      },
      workerCtx: signerWorkerCtx,
      getOrCreateActiveSigningSessionId:
        this.getOrCreateActiveSigningSessionId.bind(this),
    };
    return await activateThresholdKeyForChain({
      chain,
      adapters: {
        evm: (request) =>
          activateEvmThresholdEcdsaSessionLite(activationDeps, request),
        tempo: (request) =>
          activateTempoThresholdEcdsaSessionLite(activationDeps, request),
      },
      request: {
        nearAccountId,
        relayerUrl,
        participantIds: args.participantIds,
        sessionKind: args.sessionKind,
        ttlMs: args.ttlMs,
        remainingUses: args.remainingUses,
      },
    });
  }

  /**
   * Read the wallet-origin warm signing session status (PRF.first cache) for the active signing session id.
   *
   * Notes:
   * - This is a best-effort introspection helper; it never prompts.
   * - When no active signing session id exists for the account, returns null.
   */
  async getWarmSigningSessionStatus(
    nearAccountId: AccountId | string,
  ): Promise<SigningSessionStatus | null> {
    try {
      const key = String(toAccountId(nearAccountId));
      const sessionId = this.activeSigningSessionIds.get(key);
      if (!sessionId) return null;

      const peek = await this.secureConfirmWorkerManager.peekPrfFirstForThresholdSession({
        sessionId,
      });
      if (peek.ok) {
        return {
          sessionId,
          status: 'active',
          remainingUses: peek.remainingUses,
          expiresAtMs: peek.expiresAtMs,
        };
      }

      const status =
        peek.code === 'expired' ? 'expired' : peek.code === 'exhausted' ? 'exhausted' : 'not_found';

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
      const prfFirstB64u = this.extractPrfFirstB64u(args.credential);
      const sessionId = this.generateSessionId('threshold-client-share');
      return await this.signerWorkerManager.nearKeyOps.deriveThresholdEd25519ClientVerifyingShare({
        sessionId,
        nearAccountId,
        prfFirstB64u,
        wrapKeySalt: DUMMY_WRAP_KEY_SALT_B64U,
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
      const resolvedDeviceNumber =
        Number.isSafeInteger(deviceNumber) && deviceNumber >= 1
          ? deviceNumber
          : await getLastLoggedInDeviceNumber(nearAccountId, IndexedDBManager.clientDB);

      const existing = await IndexedDBManager.getNearThresholdKeyMaterialV2First(
        nearAccountId,
        resolvedDeviceNumber,
      );
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
          signTransactionsWithActions: (params: {
            transactions: TransactionInputWasm[];
            rpcCall: RpcCallPayload;
            signerMode: SignerMode;
            confirmationConfigOverride?: Partial<ConfirmationConfig>;
            title?: string;
            body?: string;
          }) => this.signTransactionsWithActions(params),
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
      const resolvedDeviceNumber =
        Number.isSafeInteger(deviceNumber) && deviceNumber >= 1
          ? deviceNumber
          : await getLastLoggedInDeviceNumber(nearAccountId, IndexedDBManager.clientDB);

      const keygenSessionId = String(args.keygenSessionId || '').trim() || undefined;
      const sessionId = keygenSessionId || this.generateSessionId('threshold-keygen');
      const prfFirstB64u = this.extractPrfFirstB64u(args.credential);
      const keygen = await enrollThresholdEd25519KeyHandler(
        {
          signingKeyOps: this.signerWorkerManager.nearKeyOps,
          touchIdPrompt: this.touchIdPrompt,
          relayerUrl,
        },
        {
          sessionId,
          keygenSessionId,
          nearAccountId,
          prfFirstB64u,
          wrapKeySalt: DUMMY_WRAP_KEY_SALT_B64U,
          webauthnAuthentication: (() => {
            const c = args.credential as WebAuthnAuthenticationCredential;
            if (!(c as any)?.response?.authenticatorData) {
              throw new Error('Authentication credential required for threshold keygen');
            }
            return c;
          })(),
        },
      );

      if (!keygen.success) {
        throw new Error(keygen.error || 'Threshold keygen failed');
      }

      const publicKey = keygen.publicKey;
      const clientVerifyingShareB64u = keygen.clientVerifyingShareB64u;
      const relayerKeyId = keygen.relayerKeyId;
      const relayerVerifyingShareB64u = keygen.relayerVerifyingShareB64u;
      if (!clientVerifyingShareB64u)
        throw new Error('Threshold keygen returned empty clientVerifyingShareB64u');

      // If the key is already present (e.g. relay-created threshold-signer accounts), skip AddKey
      // and just persist local threshold metadata.
      const alreadyActive = await hasAccessKey(this.nearClient, nearAccountId, publicKey, {
        attempts: 1,
        delayMs: 0,
      });
      if (!alreadyActive) {
        // Activate threshold enrollment on-chain by submitting AddKey(publicKey) signed with the local key.
        const localKeyMaterial = await IndexedDBManager.getNearLocalKeyMaterialV2First(
          nearAccountId,
          resolvedDeviceNumber,
        );
        if (!localKeyMaterial) {
          throw new Error(
            `No local key material found for account ${nearAccountId} device ${resolvedDeviceNumber}`,
          );
        }

        this.nonceManager.initializeUser(nearAccountId, localKeyMaterial.publicKey);
        const txContext = await this.nonceManager.getNonceBlockHashAndHeight(this.nearClient, {
          force: true,
        });
        const signerWorkerCtx = this.signerWorkerManager.getContext();

        const signed = await activateThresholdKeyForChain({
          chain: 'near',
          adapters: {
            near: (request) =>
              activateNearThresholdKeyNoPrompt(
                {
                  requestWorkerOperation: signerWorkerCtx.requestWorkerOperation,
                  createSessionId: this.generateSessionId.bind(this),
                },
                request,
              ),
          },
          request: {
            nearAccountId,
            credential: args.credential,
            wrapKeySalt: localKeyMaterial.wrapKeySalt,
            transactionContext: txContext,
            thresholdPublicKey: publicKey,
            relayerVerifyingShareB64u,
            clientParticipantId: keygen.clientParticipantId,
            relayerParticipantId: keygen.relayerParticipantId,
            deviceNumber: resolvedDeviceNumber,
          },
        });

        const signedTx = signed?.signedTransaction;
        if (!signedTx) throw new Error('Failed to sign AddKey(thresholdPublicKey) transaction');

        await this.nearClient.sendTransaction(signedTx, DEFAULT_WAIT_STATUS.thresholdAddKey);

        const activated = await hasAccessKey(this.nearClient, nearAccountId, publicKey);
        if (!activated) throw new Error('Threshold access key not found on-chain after AddKey');
      }

      await IndexedDBManager.storeNearThresholdKeyMaterialV2({
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
      });

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
