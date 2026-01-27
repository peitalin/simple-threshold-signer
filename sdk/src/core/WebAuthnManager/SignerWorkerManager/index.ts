import { SIGNER_WORKER_MANAGER_CONFIG } from "../../../config";
import { ClientAuthenticatorData, UnifiedIndexedDBManager } from '../../IndexedDBManager';
import { IndexedDBManager } from '../../IndexedDBManager';
import { SignedTransaction, type NearClient } from '../../NearClient';
import { isObject } from '@/utils/validation';
import { resolveWorkerUrl } from '../../sdkPaths';
import {
  WorkerRequestType,
  WorkerResponseForRequest,
  isWorkerProgress,
  isWorkerError,
  isWorkerSuccess,
  WorkerProgressResponse,
  WorkerErrorResponse,
  WorkerRequestTypeMap,
} from '../../types/signer-worker';
import { SecureConfirmWorkerManager } from '../SecureConfirmWorkerManager';
import type { ActionArgsWasm, TransactionInputWasm } from '../../types/actions';
import type { DelegateActionInput } from '../../types/delegate';
import type { onProgressEvents } from '../../types/sdkSentEvents';
import type { AuthenticatorOptions } from '../../types/authenticatorOptions';
import { AccountId } from "../../types/accountIds";
import {
  ConfirmationConfig,
  type SignerMode,
  WasmSignedDelegate,
} from '../../types/signer-worker';
import type { ThresholdBehavior } from '../../types/signer-worker';
import { TouchIdPrompt } from "../touchIdPrompt";
import { isSignerWorkerControlMessage } from './sessionMessages';
import { WorkerControlMessage } from '../../workerControlMessages';

import {
  decryptPrivateKeyWithPrf,
  signTransactionsWithActions,
  recoverKeypairFromPasskey,
  extractCosePublicKey,
  signTransactionWithKeyPair,
  signNep413Message,
  deriveNearKeypairAndEncryptFromSerialized,
  signDelegateAction,
  exportNearKeypairUi,
  deriveThresholdEd25519ClientVerifyingShare,
} from './handlers';
import { RpcCallPayload } from '../../types/signer-worker';
import { UserPreferencesManager } from '../userPreferences';
import { NonceManager } from '../../nonceManager';
import type { ThemeName } from '../../types/tatchi';
import { WebAuthnAuthenticationCredential, WebAuthnRegistrationCredential } from '../../types';
import { toError } from '@/utils/errors';
import { withSessionId } from './handlers/session';
import { attachSessionPort } from './sessionHandshake.js';

type WithOptionalSessionId<T> = T extends { sessionId: string }
  ? Omit<T, 'sessionId'> & { sessionId?: string }
  : T;

type SigningSessionEntry = {
  worker: Worker;
  wrapKeySeedPort?: MessagePort;
  wrapKeySeedSenderPort?: MessagePort;
  createdAt: number;
};

export type WrapKeySeedDeliveryMessage =
  | { ok: true; wrap_key_seed: string; wrapKeySalt: string; prfSecond?: string }
  | { ok: false; error: string };

export interface SignerWorkerManagerContext {
  touchIdPrompt: TouchIdPrompt;
  nearClient: NearClient;
  indexedDB: UnifiedIndexedDBManager;
  userPreferencesManager: UserPreferencesManager;
  nonceManager: NonceManager;
  getTheme?: () => ThemeName;
  relayerUrl: string;
  rpIdOverride?: string;
  nearExplorerUrl?: string;
  secureConfirmWorkerManager?: SecureConfirmWorkerManager;
  postWrapKeySeedToSigner: (args: { sessionId: string; message: WrapKeySeedDeliveryMessage }) => void;
  sendMessage: <T extends keyof WorkerRequestTypeMap>(args: {
    message: {
      type: T;
      payload: WithOptionalSessionId<WorkerRequestTypeMap[T]['request']>;
    };
    onEvent?: (update: onProgressEvents) => void;
    timeoutMs?: number;
    sessionId?: string;
  }) => Promise<WorkerResponseForRequest<T>>;
};

/**
 * WebAuthnWorkers handles PRF, workers, and COSE operations
 *
 * Note: This stack is WebAuthn-only; challenges are either server-minted
 * (e.g. login) or derived from intent/session digests (e.g. threshold sessions).
 */
export class SignerWorkerManager {

  private indexedDB: UnifiedIndexedDBManager;
  private touchIdPrompt: TouchIdPrompt;
  private secureConfirmWorkerManager: SecureConfirmWorkerManager;
  private nearClient: NearClient;
  private userPreferencesManager: UserPreferencesManager;
  private nonceManager: NonceManager;
  private relayerUrl: string;
  private workerBaseOrigin: string | undefined;
  private nearExplorerUrl?: string;
  private getTheme?: () => ThemeName;

  constructor(
    secureConfirmWorkerManager: SecureConfirmWorkerManager,
    nearClient: NearClient,
    userPreferencesManager: UserPreferencesManager,
    nonceManager: NonceManager,
    relayerUrl: string,
    rpIdOverride?: string,
    enableSafariGetWebauthnRegistrationFallback: boolean = true,
    nearExplorerUrl?: string,
    getTheme?: () => ThemeName,
  ) {
    this.indexedDB = IndexedDBManager;
    this.touchIdPrompt = new TouchIdPrompt(rpIdOverride, enableSafariGetWebauthnRegistrationFallback);
    this.secureConfirmWorkerManager = secureConfirmWorkerManager;
    this.nearClient = nearClient;
    this.userPreferencesManager = userPreferencesManager;
    this.nonceManager = nonceManager;
    this.relayerUrl = relayerUrl;
    this.nearExplorerUrl = nearExplorerUrl;
    this.getTheme = getTheme;
  }

  setWorkerBaseOrigin(origin: string | undefined): void {
    this.workerBaseOrigin = origin;
  }

  getContext(): SignerWorkerManagerContext {
    return {
      sendMessage: this.sendMessage.bind(this), // bind to access this.createSecureWorker
      indexedDB: this.indexedDB,
      touchIdPrompt: this.touchIdPrompt,
      secureConfirmWorkerManager: this.secureConfirmWorkerManager,
      nearClient: this.nearClient,
      userPreferencesManager: this.userPreferencesManager,
      nonceManager: this.nonceManager,
      getTheme: this.getTheme,
      rpIdOverride: this.touchIdPrompt.getRpId(),
      nearExplorerUrl: this.nearExplorerUrl,
      relayerUrl: this.relayerUrl,
      postWrapKeySeedToSigner: this.postWrapKeySeedToSigner.bind(this),
    };
  }

  createSecureWorker(): Worker {
    const workerUrlStr = resolveWorkerUrl(
      SIGNER_WORKER_MANAGER_CONFIG.WORKER.URL,
      { worker: 'signer', baseOrigin: this.workerBaseOrigin }
    )
    try {
      const worker = new Worker(workerUrlStr, {
        type: SIGNER_WORKER_MANAGER_CONFIG.WORKER.TYPE,
        name: SIGNER_WORKER_MANAGER_CONFIG.WORKER.NAME
      });
      // minimal error handler in tests; avoid noisy logs
      worker.onerror = () => {};
      return worker;
    } catch (error) {
      // Do not silently downgrade to same‑origin. Cross‑origin workers must be
      // resolvable under the configured wallet origin with proper headers.
      // Surface a precise error so tests assert the real path.
      const msg = error instanceof Error ? error.message : String(error);
      throw new Error(`Failed to create secure worker: ${msg}`);
    }
  }

  /**
   * Executes a worker operation by sending a message to the secure worker.
   * Handles progress updates via onEvent callback, supports both single and multiple response patterns.
   * Intercepts secure confirmation handshake messages for pluggable UI.
   * Resolves with the final worker response or rejects on error/timeout.
   *
   * @template T - Worker request type.
   * @param params.message - The message to send to the worker.
   * @param params.onEvent - Optional callback for progress events.
   * @param params.timeoutMs - Optional timeout in milliseconds.
   * @returns Promise resolving to the worker response for the request.
   */
  private workerPool: Worker[] = [];
  private readonly MAX_WORKER_POOL_SIZE = 3; // Increased for security model
  // Map of active signing sessions to reserved workers and optional WrapKeySeed ports
  private signingSessions: Map<string, SigningSessionEntry> = new Map();
  private readonly SIGNING_SESSION_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

  private getWorkerFromPool(): Worker {
    if (this.workerPool.length > 0) {
      return this.workerPool.pop()!;
    }
    return this.createSecureWorker();
  }

  private terminateAndReplaceWorker(worker: Worker): void {
    // Always terminate workers to clear memory
    worker.terminate();
    // Asynchronously create a replacement worker for the pool
    this.createReplacementWorker();
  }

  /**
   * Reserve a signer worker "session"
   *
   * What this does:
   * - Reserves a specific `Worker` instance from the pool and pins it to `sessionId`.
   * - Ensures the signer worker has a dedicated `MessagePort` attached for receiving `WrapKeySeed`
   *   from the SecureConfirm worker (SecureConfirm → Signer channel).
   *
   * Port wiring:
   * - The SecureConfirm worker retains one end of a `MessageChannel` and the signer worker receives the other.
   * - This method attaches the signer-facing port via a control message (`ATTACH_WRAP_KEY_SEED_PORT`)
   *   and waits for an ACK (`ATTACH_WRAP_KEY_SEED_PORT_OK`) before exposing the session.
   *
   * @param sessionId - Session identifier used to correlate MessagePorts + ready signals.
   * @param opts.signerPort - Optional signer-facing `MessagePort` created/owned by the caller.
   *                         If omitted, this method creates a fresh `MessageChannel` and returns `wrapKeySeedSenderPort`
   *                         so the caller can transfer it to the SecureConfirm worker.
   * @returns `{ worker, signerPort, wrapKeySeedSenderPort }` where `wrapKeySeedSenderPort` is only present when we created the channel here.
   */
  async reserveSignerWorkerSession(sessionId: string, opts?: { signerPort?: MessagePort }): Promise<{ worker: Worker; signerPort?: MessagePort; wrapKeySeedSenderPort?: MessagePort }> {
    if (this.signingSessions.has(sessionId)) {
      throw new Error(`Signing session already exists for id: ${sessionId}`);
    }
    // Reserve a worker from the pool for this sessionId.
    const worker = this.getWorkerFromPool();
    let signerPort = opts?.signerPort;
    let wrapKeySeedSenderPort: MessagePort | undefined;
    if (!signerPort) {
      // If caller did not provide a signer-facing port, create a channel.
      // - port1 => signer worker (receiver)
      // - port2 => SecureConfirm worker (sender) returned to caller
      const channel = new MessageChannel();
      signerPort = channel.port1;
      wrapKeySeedSenderPort = channel.port2;
    }

    // Attach the signerPort to the worker and wait for ACK before adding to signingSessions
    try {
      if (!signerPort) {
        throw new Error('Missing signerPort for signing session');
      }

      // Use centralized handshake logic (registers listener, sends message, waits for ACK)
      await attachSessionPort(worker, sessionId, signerPort);

      // Only add to signingSessions after successful attachment
      // (prevents callers from observing a session that can't receive WrapKeySeed yet).
      this.signingSessions.set(sessionId, {
        worker,
        wrapKeySeedPort: signerPort,
        wrapKeySeedSenderPort,
        createdAt: Date.now(),
      });

    } catch (err) {
      console.error('[SignerWorkerManager]: Failed to attach WrapKeySeed port to signer worker', err);
      // Best-effort cleanup
      try { signerPort?.close(); } catch {}
      try { wrapKeySeedSenderPort?.close(); } catch {}
      this.terminateAndReplaceWorker(worker);
      this.signingSessions.delete(sessionId);
      throw err;
    }
    return { worker, signerPort, wrapKeySeedSenderPort };
  }

  postWrapKeySeedToSigner(args: { sessionId: string; message: WrapKeySeedDeliveryMessage }): void {
    const sessionId = String(args.sessionId || '').trim();
    if (!sessionId) throw new Error('postWrapKeySeedToSigner: missing sessionId');
    const entry = this.signingSessions.get(sessionId);
    if (!entry?.wrapKeySeedSenderPort) {
      throw new Error(`postWrapKeySeedToSigner: no sender port for signing session ${sessionId}`);
    }
    try {
      entry.wrapKeySeedSenderPort.postMessage(args.message);
    } finally {
      try { entry.wrapKeySeedSenderPort.close(); } catch {}
      entry.wrapKeySeedSenderPort = undefined;
    }
  }

  /**
   * Detach (but do not close) the WrapKeySeed sender port for a signing session.
   *
   * This is used when we transfer ownership of the sender port to another worker
   * (e.g., the SecureConfirm worker) so the main thread does not attempt to use
   * or close a transferred (detached) port.
   */
  detachWrapKeySeedSenderPort(sessionId: string): void {
    const key = String(sessionId || '').trim();
    if (!key) return;
    const entry = this.signingSessions.get(key);
    if (!entry) return;
    entry.wrapKeySeedSenderPort = undefined;
  }

  /**
   * Release a signing session: close ports and terminate/replace the worker to zeroize state.
   */
  releaseSigningSession(sessionId: string): void {
    const entry = this.signingSessions.get(sessionId);
    if (!entry) return;
    try { entry.wrapKeySeedPort?.close() } catch {}
    try { entry.wrapKeySeedSenderPort?.close() } catch {}
    try { this.terminateAndReplaceWorker(entry.worker) } catch {}
    this.signingSessions.delete(sessionId);
  }

  /**
   * Sweep expired signing sessions based on createdAt and timeout.
   */
  sweepExpiredSigningSessions(): void {
    const now = Date.now();
    for (const [sessionId, entry] of this.signingSessions.entries()) {
      if (now - entry.createdAt > this.SIGNING_SESSION_TIMEOUT_MS) {
        this.releaseSigningSession(sessionId);
      }
    }
  }

  private async createReplacementWorker(): Promise<void> {
    try {
      const worker = this.createSecureWorker();

      // Simple health check
      const healthPromise = new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('Health check timeout')), 5000);

        const onMessage = (event: MessageEvent) => {
          if (event.data?.type === WorkerControlMessage.WORKER_READY || event.data?.ready) {
            worker.removeEventListener('message', onMessage);
            clearTimeout(timeout);
            resolve();
          }
        };

        worker.addEventListener('message', onMessage);
        worker.onerror = () => {
          worker.removeEventListener('message', onMessage);
          clearTimeout(timeout);
          reject(new Error('Worker error during health check'));
        };
      });

      await healthPromise;

      if (this.workerPool.length < this.MAX_WORKER_POOL_SIZE) {
        this.workerPool.push(worker);
      } else {
        worker.terminate();
      }
    } catch (error: unknown) {
      console.warn('SignerWorkerManager: Failed to create replacement worker:', error);
    }
  }

  /**
   * Pre-warm worker pool by creating and initializing workers in advance
   * This reduces latency for the first transaction by having workers ready
   */
  async preWarmWorkerPool(): Promise<void> {
    const promises: Promise<void>[] = [];

    for (let i = 0; i < this.MAX_WORKER_POOL_SIZE; i++) {
      promises.push(
        new Promise<void>((resolve, reject) => {
          try {
            const worker = this.createSecureWorker();

            // Set up one-time ready handler
            const onReady = (event: MessageEvent) => {
              if (event.data?.type === WorkerControlMessage.WORKER_READY || event.data?.ready) {
                worker.removeEventListener('message', onReady);
                this.terminateAndReplaceWorker(worker);
                resolve();
              }
            };

            worker.addEventListener('message', onReady);

            // Set up error handler
            worker.onerror = (error) => {
              worker.removeEventListener('message', onReady);
              console.error(`WebAuthnManager: Worker ${i + 1} pre-warm failed:`, error);
              reject(error);
            };

            // Timeout after 5 seconds
            setTimeout(() => {
              worker.removeEventListener('message', onReady);
              // Pre-warm timeouts are benign; workers will be created on-demand later.
              // console.debug(`WebAuthnManager: Worker ${i + 1} pre-warm timeout`);
              reject(new Error('Pre-warm timeout'));
            }, 5000);

          } catch (error: unknown) {
            console.error(`WebAuthnManager: Failed to create worker ${i + 1}:`, error);
            reject(toError(error));
          }
        })
      );
    }

    try {
      await Promise.allSettled(promises);
    } catch (error: unknown) {
      console.warn('WebAuthnManager: Some workers failed to pre-warm:', error);
    }
  }

  private async sendMessage<T extends keyof WorkerRequestTypeMap>({
    sessionId,
    message,
    onEvent,
    timeoutMs = SIGNER_WORKER_MANAGER_CONFIG.TIMEOUTS.DEFAULT, // 60s
  }: {
    sessionId?: string;
    message: { type: T; payload: WithOptionalSessionId<WorkerRequestTypeMap[T]['request']> };
    onEvent?: (update: onProgressEvents) => void;
    timeoutMs?: number;
  }): Promise<WorkerResponseForRequest<T>> {

    // Clean up any expired signing sessions before allocating a worker
    this.sweepExpiredSigningSessions();

    const payloadSessionId = (message.payload as any)?.sessionId as string | undefined;
    if (sessionId && payloadSessionId && payloadSessionId !== sessionId) {
      throw new Error(
        `sendMessage: payload.sessionId (${payloadSessionId}) does not match provided sessionId (${sessionId})`
      );
    }

    const effectiveSessionId = sessionId || payloadSessionId;
    const sessionEntry = effectiveSessionId ? this.signingSessions.get(effectiveSessionId) : undefined;
    if (effectiveSessionId && !sessionEntry) {
      throw new Error(`Signing session not found for id: ${effectiveSessionId}`);
    }

    // Normalize/inject sessionId into payload once to avoid duplication at call sites.
    const finalPayload = effectiveSessionId
      ? withSessionId(effectiveSessionId, message.payload)
      : (message.payload);

    const worker = sessionEntry ? sessionEntry.worker : this.getWorkerFromPool();
    const isSessionWorker = !!sessionEntry;

    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        try {
          if (isSessionWorker && effectiveSessionId) {
            // Release reserved session to avoid leaking worker/port
            this.releaseSigningSession(effectiveSessionId);
          } else {
            this.terminateAndReplaceWorker(worker);
          }
        } catch {}
        // Notify any open modal host to transition to error state
        try {
          const seconds = Math.round(timeoutMs / 1000);
          window.postMessage({ type: 'MODAL_TIMEOUT', payload: `Timed out after ${seconds}s, try again` }, '*');
        } catch {}
        reject(new Error(`Worker operation timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      const responses: WorkerResponseForRequest<T>[] = [];

      worker.onmessage = async (event) => {
        try {
          // Ignore control messages (lifecycle/session setup) – they are handled elsewhere.
          if (isSignerWorkerControlMessage(event?.data)) {
            return;
          }
          // Ignore readiness pings that can arrive if a worker was just spawned
          if (event?.data?.type === WorkerControlMessage.WORKER_READY || event?.data?.ready) {
            return; // not a response to an operation
          }
          // Use strong typing from WASM-generated types
          const response = event.data as WorkerResponseForRequest<T>;
          responses.push(response);

          // Handle progress updates using WASM-generated numeric enum values
          if (isWorkerProgress(response)) {
            const progressResponse = response as WorkerProgressResponse;
            onEvent?.(progressResponse.payload as onProgressEvents);
            return; // Continue listening for more messages
          }

          // Handle errors using WASM-generated enum
          if (isWorkerError(response)) {
            clearTimeout(timeoutId);
            if (!isSessionWorker) this.terminateAndReplaceWorker(worker);
            const errorResponse = response as WorkerErrorResponse;
            console.error('Worker error response:', errorResponse);
            reject(new Error(errorResponse.payload.error));
            return;
          }

          // Handle successful completion types using strong typing
          if (isWorkerSuccess(response)) {
            clearTimeout(timeoutId);
            if (!isSessionWorker) this.terminateAndReplaceWorker(worker);
            resolve(response as WorkerResponseForRequest<T>);
            return;
          }

          // If we reach here, the response doesn't match any expected type
          console.error('Unexpected worker response format:', {
            response,
          });

          // Check if it's a generic Error object
          if (isObject(response) && 'message' in response && 'stack' in response) {
            clearTimeout(timeoutId);
            if (!isSessionWorker) this.terminateAndReplaceWorker(worker);
            console.error('Worker sent generic Error object:', response);
            reject(new Error(`Worker sent generic error: ${(response as Error).message}`));
            return;
          }

          // Unknown response format
          clearTimeout(timeoutId);
          if (!isSessionWorker) this.terminateAndReplaceWorker(worker);
          reject(new Error(`Unknown worker response format: ${JSON.stringify(response)}`));
        } catch (error: unknown) {
          clearTimeout(timeoutId);
          if (!isSessionWorker) this.terminateAndReplaceWorker(worker);
          console.error('Error processing worker message:', error);
          const err = toError(error);
          reject(new Error(`Worker message processing error: ${err.message}`));
        }
      };

      worker.onerror = (event) => {
        clearTimeout(timeoutId);
        if (!isSessionWorker) this.terminateAndReplaceWorker(worker);
        const errorMessage = event.error?.message || event.message || 'Unknown worker error';
        console.error('Worker error details (progress):', {
          message: errorMessage,
          filename: event.filename,
          lineno: event.lineno,
          colno: event.colno,
          error: event.error
        });
        reject(new Error(`Worker error: ${errorMessage}`));
      };

      // Format message for Rust SignerWorkerMessage structure using WASM types
      const formattedMessage = {
        type: message.type, // Numeric enum value from WorkerRequestType
        payload: finalPayload,
      };

      worker.postMessage(formattedMessage);
    });
  }

  /**
   * Derive NEAR keypair from a serialized WebAuthn registration credential
   */
  async deriveNearKeypairAndEncryptFromSerialized(args: {
    credential: WebAuthnRegistrationCredential;
    nearAccountId: AccountId;
    options?: {
      authenticatorOptions?: AuthenticatorOptions;
      deviceNumber?: number;
    };
    sessionId: string;
  }): Promise<{
    success: boolean;
    nearAccountId: AccountId;
    publicKey: string;
    /**
     * Base64url-encoded AEAD nonce (ChaCha20-Poly1305) for the encrypted private key.
     */
    chacha20NonceB64u?: string;
    wrapKeySalt?: string;
  }> {
    return deriveNearKeypairAndEncryptFromSerialized({ ctx: this.getContext(), ...args });
  }

  async deriveThresholdEd25519ClientVerifyingShare(args: {
    sessionId: string;
    nearAccountId: AccountId;
  }): Promise<{
    success: boolean;
    nearAccountId: string;
    clientVerifyingShareB64u: string;
    error?: string;
  }> {
    return deriveThresholdEd25519ClientVerifyingShare({
      ctx: this.getContext(),
      sessionId: args.sessionId,
      nearAccountId: String(args.nearAccountId),
    });
  }

  /**
   * Secure private key decryption with dual PRF
   */
  async decryptPrivateKeyWithPrf(args: {
    nearAccountId: AccountId,
    authenticators: ClientAuthenticatorData[],
    sessionId: string,
  }): Promise<{
    decryptedPrivateKey: string;
    nearAccountId: AccountId
  }> {
    return decryptPrivateKeyWithPrf({ ctx: this.getContext(), ...args });
  }

  // === ACTION-BASED SIGNING METHODS ===

  /**
   * Sign multiple transactions with a shared WebAuthn credential.
   * Efficiently processes multiple transactions with one PRF-backed signing session.
   */
  async signTransactionsWithActions(args: {
    transactions: TransactionInputWasm[],
    rpcCall: RpcCallPayload,
    signerMode: SignerMode,
    onEvent?: (update: onProgressEvents) => void,
    confirmationConfigOverride?: Partial<ConfirmationConfig>,
    title?: string;
    body?: string;
    signingSessionTtlMs?: number;
    signingSessionRemainingUses?: number;
    sessionId: string,
  }): Promise<Array<{
    signedTransaction: SignedTransaction;
    nearAccountId: AccountId;
    logs?: string[]
  }>> {
    return signTransactionsWithActions({
      ctx: this.getContext(),
      ...args
    });
  }

  async signDelegateAction(args: {
    delegate: DelegateActionInput;
    rpcCall: RpcCallPayload;
    signerMode: SignerMode;
    onEvent?: (update: onProgressEvents) => void;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    title?: string;
    body?: string;
    signingSessionTtlMs?: number;
    signingSessionRemainingUses?: number;
    sessionId: string;
  }): Promise<{
    signedDelegate: WasmSignedDelegate;
    hash: string;
    nearAccountId: AccountId;
    logs?: string[];
  }> {
    return signDelegateAction({ ctx: this.getContext(), ...args });
  }

  /**
   * Recover keypair from authentication credential for account recovery
   * Uses dual PRF-based Ed25519 key derivation with account-specific HKDF and AES encryption
   */
  async recoverKeypairFromPasskey(args: {
    credential: WebAuthnAuthenticationCredential;
    accountIdHint?: string;
    sessionId: string,
  }): Promise<{
    publicKey: string;
    encryptedPrivateKey: string;
    /** Base64url-encoded AEAD nonce (ChaCha20-Poly1305) for encrypted key */
    chacha20NonceB64u: string;
    accountIdHint?: string;
    wrapKeySalt: string;
  }> {
    return recoverKeypairFromPasskey({ ctx: this.getContext(), ...args });
  }

  /**
   * Extract COSE public key from WebAuthn attestation object
   * Simple operation that doesn't require TouchID or progress updates
   */
  async extractCosePublicKey(attestationObjectBase64url: string): Promise<Uint8Array> {
    return extractCosePublicKey({ ctx: this.getContext(), attestationObjectBase64url });
  }

  /**
   * Sign transaction with raw private key (for key replacement in Option D device linking)
   * No TouchID/PRF required - uses provided private key directly
   */
  async signTransactionWithKeyPair(args: {
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
    return signTransactionWithKeyPair({ ctx: this.getContext(), ...args });
  }

  /**
   * Sign a NEP-413 message using the user's passkey-derived private key
   *
   * @param payload - NEP-413 signing parameters including message, recipient, nonce, and state
   * @returns Promise resolving to signing result with account ID, public key, and signature
   */
  async signNep413Message(payload: {
    message: string;
    recipient: string;
    nonce: string;
    state: string | null;
    accountId: string;
    signerMode: SignerMode;
    title?: string;
    body?: string;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    signingSessionTtlMs?: number;
    signingSessionRemainingUses?: number;
    sessionId: string;
    contractId?: string;
    nearRpcUrl?: string;
  }): Promise<{
    success: boolean;
    accountId: string;
    publicKey: string;
    signature: string;
    state?: string;
    error?: string;
  }> {
    return signNep413Message({
      ctx: this.getContext(),
      payload
    });
  }

  /**
   * Two-phase export (worker-driven):
   *  - Phase 1: collect PRF (uiMode: 'none')
   *  - Decrypt inside worker
   *  - Phase 2: show export UI with decrypted key (kept open until user closes)
   */
  async exportNearKeypairUi(args: {
    nearAccountId: AccountId,
    variant?: 'drawer'|'modal',
    theme?: 'dark'|'light',
    sessionId: string,
  }): Promise<void> {
    return exportNearKeypairUi({ ctx: this.getContext(), ...args });
  }

}
