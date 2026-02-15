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
} from '../../IndexedDBManager';
import { StoreUserDataInput } from '../../IndexedDBManager/passkeyClientDB';
import { type NearClient, SignedTransaction } from '../../near/NearClient';
import type { SignerWorkerManager } from '../workers/signerWorkerManager';
import type { SecureConfirmWorkerManager } from '../secureConfirm/manager';
import type { TouchIdPrompt } from '../webauthn/prompt/touchIdPrompt';
import type { WebAuthnAllowCredential } from '../webauthn/credentials';
import { toAccountId } from '../../types/accountIds';
import type { UserPreferencesManager } from './userPreferences';
import type { NonceManager } from '../../near/nonceManager';
import { type ActionArgsWasm, type TransactionInputWasm } from '../../types/actions';
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
import { DEFAULT_WAIT_STATUS } from '../../types/rpc';
import type {
  TempoSecp256k1SigningRequest,
  TempoSigningRequest,
} from '../chainAdaptors/tempo/types';
import type { TempoSignedResult } from '../chainAdaptors/tempo/tempoAdapter';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../orchestration/types';
import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from '../orchestration/activation';
import {
  persistThresholdEcdsaBootstrapChainAccount as persistThresholdEcdsaBootstrapChainAccountValue,
  type ThresholdEcdsaSmartAccountBootstrapInput,
} from './thresholdEcdsaBootstrapPersistence';
import {
  deriveThresholdEd25519ClientVerifyingShareFromCredential as deriveThresholdEd25519ClientVerifyingShareFromCredentialValue,
  enrollThresholdEd25519Key as enrollThresholdEd25519KeyValue,
  enrollThresholdEd25519KeyPostRegistration as enrollThresholdEd25519KeyPostRegistrationValue,
  rotateThresholdEd25519KeyPostRegistration as rotateThresholdEd25519KeyPostRegistrationValue,
} from './thresholdEd25519Lifecycle';
import {
  signDelegateAction as signDelegateActionValue,
  signNEP413Message as signNEP413MessageValue,
  signTransactionsWithActions as signTransactionsWithActionsValue,
} from './nearSigning';
import {
  signTempo as signTempoValue,
} from './tempoSigning';
import {
  exportNearKeypairWithUI as exportNearKeypairWithUIValue,
  exportNearKeypairWithUIWorkerDriven as exportNearKeypairWithUIWorkerDrivenValue,
  exportPrivateKeysWithUI as exportPrivateKeysWithUIValue,
  exportPrivateKeysWithUIWorkerDriven as exportPrivateKeysWithUIWorkerDrivenValue,
  recoverKeypairFromPasskey as recoverKeypairFromPasskeyValue,
} from './privateKeyExportRecovery';
import {
  deriveNearKeypairAndEncryptFromSerialized as deriveNearKeypairAndEncryptFromSerializedValue,
  deriveNearKeypairFromCredentialViaWorker as deriveNearKeypairFromCredentialViaWorkerValue,
} from './nearKeyDerivation';
import {
  atomicOperation as atomicOperationValue,
  atomicStoreRegistrationData as atomicStoreRegistrationDataValue,
  extractUsername as extractUsernameValue,
  hasPasskeyCredential as hasPasskeyCredentialValue,
  initializeCurrentUser as initializeCurrentUserValue,
  registerUser as registerUserValue,
  rollbackUserRegistration as rollbackUserRegistrationValue,
  storeAuthenticator as storeAuthenticatorValue,
  storeUserData as storeUserDataValue,
  type StoreAuthenticatorInput,
} from './registrationAccountLifecycle';
import {
  getAuthenticationCredentialsSerialized as getAuthenticationCredentialsSerializedValue,
  getAuthenticationCredentialsSerializedDualPrf as getAuthenticationCredentialsSerializedDualPrfValue,
  requestRegistrationCredentialConfirmation as requestRegistrationCredentialConfirmationValue,
} from './registrationSession';
import {
  enqueueSignerOperation as enqueueSignerOperationValue,
  getAllUsers as getAllUsersValue,
  getAuthenticatorsByUser as getAuthenticatorsByUserValue,
  getLastUser as getLastUserValue,
  getProfile as getProfileValue,
  getProfileByAccount as getProfileByAccountValue,
  getUserByDevice as getUserByDeviceValue,
  listAccountSigners as listAccountSignersValue,
  setAccountSignerStatus as setAccountSignerStatusValue,
  setLastUser as setLastUserValue,
  updateLastLogin as updateLastLoginValue,
  upsertAccountSigner as upsertAccountSignerValue,
  upsertChainAccount as upsertChainAccountValue,
  upsertProfile as upsertProfileValue,
} from './indexedDbFacade';
import {
  bootstrapThresholdEcdsaSessionLiteValue,
  connectThresholdEd25519SessionLiteValue,
} from './thresholdSessionActivation';
import {
  extractCosePublicKey as extractCosePublicKeyValue,
  signTransactionWithKeyPair as signTransactionWithKeyPairValue,
  signNearWithIntent as signNearWithIntentValue,
} from './signerWorkerBridge';
import {
  destroyFacade as destroyFacadeValue,
  getNonceManager as getNonceManagerValue,
  getRpId as getRpIdValue,
  getTheme as getThemeValue,
  getUserPreferences as getUserPreferencesValue,
  setTheme as setThemeValue,
  type FacadeSettingsDeps,
} from './facadeSettings';
import {
  getWarmSigningSessionStatusSurface as getWarmSigningSessionStatusSurfaceValue,
  prewarmSignerWorkersSurface as prewarmSignerWorkersSurfaceValue,
  signTempoWithThresholdEcdsa as signTempoWithThresholdEcdsaValue,
  warmCriticalResourcesSurface as warmCriticalResourcesSurfaceValue,
} from './facadeConvenience';
import { createFacadeSettingsDeps } from './facadeDependencyFactory';
import { initializeRuntimeBootstrap } from './runtimeBootstrap';
import { createManagerAssembly } from './managerAssembly';
import {
  createOrchestrationDependencyBundle,
  type OrchestrationDependencyBundle,
} from './orchestrationDependencyFactory';
export type { ThresholdEcdsaSessionBootstrapResult } from '../orchestration/activation';

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
  private readonly facadeSettingsDeps: FacadeSettingsDeps;
  private readonly orchestrationDeps: OrchestrationDependencyBundle;

  readonly tatchiPasskeyConfigs: TatchiConfigs;

  constructor(tatchiPasskeyConfigs: TatchiConfigs, nearClient: NearClient) {
    this.tatchiPasskeyConfigs = tatchiPasskeyConfigs;
    this.nearClient = nearClient;
    const assembly = createManagerAssembly({
      tatchiPasskeyConfigs: this.tatchiPasskeyConfigs,
      nearClient: this.nearClient,
      getTheme: () => this.theme,
    });
    this.touchIdPrompt = assembly.touchIdPrompt;
    this.userPreferencesManager = assembly.userPreferencesManager;
    this.nonceManager = assembly.nonceManager;
    this.secureConfirmWorkerManager = assembly.secureConfirmWorkerManager;
    this.signerWorkerManager = assembly.signerWorkerManager;
    this.facadeSettingsDeps = createFacadeSettingsDeps({
      touchIdPrompt: this.touchIdPrompt,
      nonceManager: this.nonceManager,
      userPreferencesManager: this.userPreferencesManager,
      activeSigningSessionIds: this.activeSigningSessionIds,
    });
    this.orchestrationDeps = createOrchestrationDependencyBundle({
      tatchiPasskeyConfigs: this.tatchiPasskeyConfigs,
      nearClient: this.nearClient,
      touchIdPrompt: this.touchIdPrompt,
      userPreferencesManager: this.userPreferencesManager,
      nonceManager: this.nonceManager,
      secureConfirmWorkerManager: this.secureConfirmWorkerManager,
      signerWorkerManager: this.signerWorkerManager,
      activeSigningSessionIds: this.activeSigningSessionIds,
      getWorkerBaseOrigin: () => this.workerBaseOrigin,
      getTheme: () => this.theme,
      signTempo: (args) => this.signTempo(args),
      signTransactionsWithActions: (args) => this.signTransactionsWithActions(args),
      signNearWithIntent: signNearWithIntentValue,
      deriveNearKeypairFromCredentialViaWorker: (args) =>
        this.deriveNearKeypairFromCredentialViaWorker(args),
      extractCosePublicKey: (attestationObjectBase64url: string) =>
        this.extractCosePublicKey(attestationObjectBase64url),
      initializeCurrentUser: (nearAccountId: AccountId, nearClientArg?: NearClient) =>
        this.initializeCurrentUser(nearAccountId, nearClientArg),
      persistThresholdEcdsaBootstrapChainAccount: (args) =>
        this.persistThresholdEcdsaBootstrapChainAccount(args),
    });

    initializeRuntimeBootstrap({
      tatchiPasskeyConfigs: this.tatchiPasskeyConfigs,
      userPreferencesManager: this.userPreferencesManager,
      getWorkerBaseOrigin: () => this.workerBaseOrigin,
      setWorkerBaseOrigin: (origin: string) => {
        this.workerBaseOrigin = origin;
        this.signerWorkerManager.setWorkerBaseOrigin(origin);
        this.secureConfirmWorkerManager.setWorkerBaseOrigin?.(origin as any);
      },
    });
  }

  /**
   * Public pre-warm hook to initialize signer workers ahead of time.
   * Safe to call multiple times; errors are non-fatal.
   */
  prewarmSignerWorkers(): void {
    prewarmSignerWorkersSurfaceValue(this.orchestrationDeps.getFacadeConvenienceDeps());
  }

  /**
   * Warm critical resources to reduce first-action latency.
   * - Initialize current user (sets up NonceManager and local state)
   * - Prefetch latest block context (and nonce if missing)
   * - Pre-open IndexedDB and warm encrypted key for the active account (best-effort)
   * - Pre-warm signer workers in the background
   */
  async warmCriticalResources(nearAccountId?: string): Promise<void> {
    await warmCriticalResourcesSurfaceValue(
      this.orchestrationDeps.getFacadeConvenienceDeps(),
      nearAccountId,
    );
  }

  /**
   * Resolve the effective rpId used for WebAuthn operations.
   * Delegates to TouchIdPrompt to centralize rpId selection logic.
   */
  getRpId(): string {
    return getRpIdValue(this.facadeSettingsDeps);
  }

  /** Getter for NonceManager instance */
  getNonceManager(): NonceManager {
    return getNonceManagerValue(this.facadeSettingsDeps);
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
    return await requestRegistrationCredentialConfirmationValue(this.orchestrationDeps.registrationSessionDeps, params);
  }

  setTheme(next: ThemeName): void {
    this.theme = setThemeValue(this.theme, next);
  }

  getTheme(): ThemeName {
    return getThemeValue(this.theme);
  }

  getAuthenticationCredentialsSerialized({
    nearAccountId,
    challengeB64u,
    allowCredentials,
    includeSecondPrfOutput = false,
  }: {
    nearAccountId: AccountId;
    challengeB64u: string;
    allowCredentials: WebAuthnAllowCredential[];
    includeSecondPrfOutput?: boolean;
  }): Promise<WebAuthnAuthenticationCredential> {
    return getAuthenticationCredentialsSerializedValue(this.orchestrationDeps.registrationSessionDeps, {
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
    return await deriveNearKeypairAndEncryptFromSerializedValue(this.orchestrationDeps.nearKeyDerivationDeps, {
      credential,
      nearAccountId,
      options,
    });
  }

  async deriveNearKeypairFromCredentialViaWorker(args: {
    credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
    nearAccountId: AccountId;
  }): Promise<{ publicKey: string; privateKey: string }> {
    return await deriveNearKeypairFromCredentialViaWorkerValue(this.orchestrationDeps.nearKeyDerivationDeps, args);
  }

  ///////////////////////////////////////
  // INDEXEDDB OPERATIONS
  ///////////////////////////////////////

  async storeUserData(userData: StoreUserDataInput): Promise<void> {
    await storeUserDataValue(this.orchestrationDeps.registrationAccountLifecycleDeps, userData);
  }

  // === V2 MULTICHAIN INDEXEDDB OPERATIONS ===

  async getProfile(profileId: string): Promise<ProfileRecord | null> {
    return await getProfileValue(this.orchestrationDeps.indexedDbFacadeDeps, profileId);
  }

  async upsertProfile(input: UpsertProfileInput): Promise<ProfileRecord> {
    return await upsertProfileValue(this.orchestrationDeps.indexedDbFacadeDeps, input);
  }

  async upsertChainAccount(input: UpsertChainAccountInput): Promise<ChainAccountRecord> {
    return await upsertChainAccountValue(this.orchestrationDeps.indexedDbFacadeDeps, input);
  }

  async getProfileByAccount(chainId: string, accountAddress: string): Promise<ProfileRecord | null> {
    return await getProfileByAccountValue(this.orchestrationDeps.indexedDbFacadeDeps, chainId, accountAddress);
  }

  async upsertAccountSigner(input: UpsertAccountSignerInput): Promise<AccountSignerRecord> {
    return await upsertAccountSignerValue(this.orchestrationDeps.indexedDbFacadeDeps, input);
  }

  async listAccountSigners(args: {
    chainId: string;
    accountAddress: string;
    status?: AccountSignerStatus;
  }): Promise<AccountSignerRecord[]> {
    return await listAccountSignersValue(this.orchestrationDeps.indexedDbFacadeDeps, args);
  }

  async setAccountSignerStatus(args: {
    chainId: string;
    accountAddress: string;
    signerId: string;
    status: AccountSignerStatus;
    removedAt?: number;
  }): Promise<AccountSignerRecord | null> {
    return await setAccountSignerStatusValue(this.orchestrationDeps.indexedDbFacadeDeps, args);
  }

  async enqueueSignerOperation(input: EnqueueSignerOperationInput): Promise<SignerOpOutboxRecord> {
    return await enqueueSignerOperationValue(this.orchestrationDeps.indexedDbFacadeDeps, input);
  }

  async getAllUsers(): Promise<ClientUserData[]> {
    return await getAllUsersValue(this.orchestrationDeps.indexedDbFacadeDeps);
  }

  async getUserByDevice(
    nearAccountId: AccountId,
    deviceNumber: number,
  ): Promise<ClientUserData | null> {
    return await getUserByDeviceValue(this.orchestrationDeps.indexedDbFacadeDeps, nearAccountId, deviceNumber);
  }

  async getLastUser(): Promise<ClientUserData | null> {
    return await getLastUserValue(this.orchestrationDeps.indexedDbFacadeDeps);
  }

  async getAuthenticatorsByUser(nearAccountId: AccountId): Promise<ClientAuthenticatorData[]> {
    return await getAuthenticatorsByUserValue(this.orchestrationDeps.indexedDbFacadeDeps, nearAccountId);
  }

  async updateLastLogin(nearAccountId: AccountId): Promise<void> {
    await updateLastLoginValue(this.orchestrationDeps.indexedDbFacadeDeps, nearAccountId);
  }

  /**
   * Set the last logged-in user
   * @param nearAccountId - The account ID of the user
   * @param deviceNumber - The device number (defaults to 1)
   */
  async setLastUser(nearAccountId: AccountId, deviceNumber: number = 1): Promise<void> {
    await setLastUserValue(this.orchestrationDeps.indexedDbFacadeDeps, nearAccountId, deviceNumber);
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
    await initializeCurrentUserValue(this.orchestrationDeps.registrationAccountLifecycleDeps, {
      nearAccountId,
      nearClient,
    });
  }

  async registerUser(storeUserData: StoreUserDataInput): Promise<ClientUserData> {
    return await registerUserValue(this.orchestrationDeps.registrationAccountLifecycleDeps, storeUserData);
  }

  async storeAuthenticator(authenticatorData: StoreAuthenticatorInput): Promise<void> {
    await storeAuthenticatorValue(this.orchestrationDeps.registrationAccountLifecycleDeps, authenticatorData);
  }

  extractUsername(nearAccountId: AccountId): string {
    return extractUsernameValue(nearAccountId);
  }

  async atomicOperation<T>(callback: (db: any) => Promise<T>): Promise<T> {
    return await atomicOperationValue(this.orchestrationDeps.registrationAccountLifecycleDeps, callback);
  }

  async rollbackUserRegistration(nearAccountId: AccountId): Promise<void> {
    await rollbackUserRegistrationValue(this.orchestrationDeps.registrationAccountLifecycleDeps, nearAccountId);
  }

  async hasPasskeyCredential(nearAccountId: AccountId): Promise<boolean> {
    return await hasPasskeyCredentialValue(this.orchestrationDeps.registrationAccountLifecycleDeps, nearAccountId);
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
    await atomicStoreRegistrationDataValue(this.orchestrationDeps.registrationAccountLifecycleDeps, {
      nearAccountId,
      credential,
      publicKey,
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
    return await signTransactionsWithActionsValue(this.orchestrationDeps.nearSigningDeps, {
      transactions,
      rpcCall,
      deviceNumber,
      signerMode,
      confirmationConfigOverride,
      title,
      body,
      onEvent,
      sessionId,
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
    return await signDelegateActionValue(this.orchestrationDeps.nearSigningDeps, {
      delegate,
      rpcCall,
      deviceNumber,
      signerMode,
      confirmationConfigOverride,
      title,
      body,
      onEvent,
    });
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
    return await signNEP413MessageValue(this.orchestrationDeps.nearSigningDeps, payload);
  }

  async signTempo(args: {
    nearAccountId: string;
    request: TempoSigningRequest;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    thresholdEcdsaKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
  }): Promise<TempoSignedResult> {
    return await signTempoValue(this.orchestrationDeps.tempoSigningDeps, args);
  }

  async signTempoWithThresholdEcdsa(args: {
    nearAccountId: string;
    request: TempoSecp256k1SigningRequest;
    thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
  }): Promise<TempoSignedResult> {
    return await signTempoWithThresholdEcdsaValue(this.orchestrationDeps.getFacadeConvenienceDeps(), args);
  }

  // === COSE OPERATIONS ===

  /**
   * Extract COSE public key from WebAuthn attestation object using WASM worker
   */
  async extractCosePublicKey(attestationObjectBase64url: string): Promise<Uint8Array> {
    return await extractCosePublicKeyValue(this.orchestrationDeps.signerWorkerBridgeDeps, attestationObjectBase64url);
  }

  ///////////////////////////////////////
  // PRIVATE KEY EXPORT (Drawer/Modal in sandboxed iframe)
  ///////////////////////////////////////

  /** Worker-driven export: two-phase V2 (collect PRF → decrypt → show UI) */
  async exportNearKeypairWithUIWorkerDriven(
    nearAccountId: AccountId,
    options?: { variant?: 'drawer' | 'modal'; theme?: 'dark' | 'light' },
  ): Promise<void> {
    await exportNearKeypairWithUIWorkerDrivenValue(this.orchestrationDeps.privateKeyExportRecoveryDeps, {
      nearAccountId,
      options,
    });
  }

  async exportNearKeypairWithUI(
    nearAccountId: AccountId,
    options?: {
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    },
  ): Promise<{ accountId: string; publicKey: string; privateKey: string }> {
    return await exportNearKeypairWithUIValue(this.orchestrationDeps.privateKeyExportRecoveryDeps, {
      nearAccountId,
      options,
    });
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
    await exportPrivateKeysWithUIWorkerDrivenValue(this.orchestrationDeps.privateKeyExportRecoveryDeps, {
      nearAccountId,
      options,
    });
  }

  async exportPrivateKeysWithUI(
    nearAccountId: AccountId,
    options?: {
      schemes?: Array<'ed25519' | 'secp256k1'>;
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    },
  ): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
    return await exportPrivateKeysWithUIValue(this.orchestrationDeps.privateKeyExportRecoveryDeps, {
      nearAccountId,
      options,
    });
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
    return await recoverKeypairFromPasskeyValue(this.orchestrationDeps.privateKeyExportRecoveryDeps, {
      authenticationCredential,
      accountIdHint,
    });
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
    return await getAuthenticationCredentialsSerializedDualPrfValue(this.orchestrationDeps.registrationSessionDeps, {
      nearAccountId,
      challengeB64u,
      credentialIds,
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
    return await signTransactionWithKeyPairValue(this.orchestrationDeps.signerWorkerBridgeDeps, {
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
  }): Promise<Awaited<ReturnType<typeof connectThresholdEd25519SessionLiteValue>>> {
    return await connectThresholdEd25519SessionLiteValue(this.orchestrationDeps.thresholdSessionActivationDeps, args);
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
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  }): Promise<ThresholdEcdsaSessionBootstrapResult> {
    return await bootstrapThresholdEcdsaSessionLiteValue(this.orchestrationDeps.thresholdSessionActivationDeps, args);
  }

  async persistThresholdEcdsaBootstrapChainAccount(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  }): Promise<void> {
    await persistThresholdEcdsaBootstrapChainAccountValue({
      indexedDB: IndexedDBManager,
      nearAccountId: toAccountId(args.nearAccountId),
      chain: args.chain,
      bootstrap: args.bootstrap,
      smartAccount: args.smartAccount,
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
    return await getWarmSigningSessionStatusSurfaceValue(this.orchestrationDeps.getFacadeConvenienceDeps(), nearAccountId);
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
    return await deriveThresholdEd25519ClientVerifyingShareFromCredentialValue(
      this.orchestrationDeps.thresholdEd25519LifecycleDeps,
      args,
    );
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
    return await enrollThresholdEd25519KeyPostRegistrationValue(
      this.orchestrationDeps.thresholdEd25519LifecycleDeps,
      args,
    );
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
    return await rotateThresholdEd25519KeyPostRegistrationValue(
      this.orchestrationDeps.thresholdEd25519LifecycleDeps,
      args,
    );
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
    return await enrollThresholdEd25519KeyValue(this.orchestrationDeps.thresholdEd25519LifecycleDeps, args);
  }

  // ==============================
  // USER SETTINGS
  // ==============================

  /** * Get user preferences manager */
  getUserPreferences(): UserPreferencesManager {
    return getUserPreferencesValue(this.facadeSettingsDeps);
  }

  /** * Clean up resources */
  destroy(): void {
    destroyFacadeValue(this.facadeSettingsDeps);
  }
}
