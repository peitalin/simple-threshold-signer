/**
 * SecureConfirm Worker Manager
 *
 * This manager retains the worker/main-thread handshake for SecureConfirm UI orchestration
 * and the PRF.first warm-session cache.
 */

import type {
  SecureConfirmWorkerManagerConfig,
  SecureConfirmWorkerMessage,
  SecureConfirmWorkerResponse,
} from '../../types/secure-confirm-worker';
import { BUILD_PATHS } from '../../../../../sdk/build-paths';
import { resolveWorkerUrl } from '../../runtimeAssetPaths';
import type { TouchIdPrompt } from '../touchIdPrompt';
import type { NearClient } from '../../near/NearClient';
import type { UnifiedIndexedDBManager } from '../../IndexedDBManager';
import type { UserPreferencesManager } from '../userPreferences';
import type { NonceManager } from '../../near/nonceManager';
import {
  SecureConfirmMessageType,
  type SecureConfirmRequest,
  type SerializableCredential,
  type SigningAuthMode,
} from './confirmTxFlow/types';
import type { TransactionInputWasm } from '../../types/actions';
import type { RpcCallPayload, ConfirmationConfig } from '../../types/signer-worker';
import type { TransactionContext } from '../../types/rpc';
import type { ThemeName } from '../../types/tatchi';
import type { RegistrationCredentialConfirmationPayload } from '../SignerWorkerManager/internal/validation';
import { handlePromptUserConfirmInJsMainThread } from './confirmTxFlow';
import type { SecureConfirmWorkerManagerHandlerContext } from './handlers/types';
import {
  confirmAndPrepareSigningSession,
  requestRegistrationCredentialConfirmation,
} from './handlers';

/** SecureConfirm-owned host context passed into confirmTxFlow. */
export interface SecureConfirmWorkerManagerContext {
  touchIdPrompt: TouchIdPrompt;
  nearClient: NearClient;
  indexedDB: UnifiedIndexedDBManager;
  userPreferencesManager: UserPreferencesManager;
  nonceManager: NonceManager;
  getTheme?: () => ThemeName;
  rpIdOverride?: string;
  nearExplorerUrl?: string;
}

/**
 * SecureConfirm Worker Manager
 *
 * This worker previously hosted a legacy challenge WASM runtime. In the lite threshold-signer refactor,
 * the worker only hosts SecureConfirm (confirmTxFlow bridge) and the threshold PRF.first cache.
 */
export class SecureConfirmWorkerManager {
  private worker: Worker | null = null;
  private initializationPromise: Promise<void> | null = null;
  private messageId = 0;
  private config: SecureConfirmWorkerManagerConfig;
  private workerBaseOrigin: string | undefined;
  private context: SecureConfirmWorkerManagerContext;

  constructor(config: SecureConfirmWorkerManagerConfig, context: SecureConfirmWorkerManagerContext) {
    this.config = {
      // Default to client-hosted worker file using centralized config
      workerUrl: BUILD_PATHS.RUNTIME.SECURE_CONFIRM_WORKER,
      workerTimeout: 60_000,
      debug: false,
      ...config
    };
    this.context = context;
  }

  /** Context used by confirmTxFlow. */
  getContext(): SecureConfirmWorkerManagerContext {
    return this.context;
  }

  private getHandlerContext(): SecureConfirmWorkerManagerHandlerContext {
    return {
      ensureWorkerReady: this.ensureWorkerReady.bind(this),
      sendMessage: this.sendMessage.bind(this),
      generateMessageId: this.generateMessageId.bind(this),
      getContext: this.getContext.bind(this),
      postToWorker: (message: unknown, transfer?: Transferable[]) => {
        if (!this.worker) {
          throw new Error('SecureConfirm worker not available');
        }
        this.worker.postMessage(message, transfer as any);
      },
    };
  }

  async putPrfFirstForThresholdSession(args: {
    sessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
  }): Promise<void> {
    await this.ensureWorkerReady(false);
    const res = await this.sendMessage({
      type: 'THRESHOLD_PRF_FIRST_CACHE_PUT',
      id: this.generateMessageId(),
      payload: args as any,
    });
    if (!res?.success) {
      throw new Error(String(res?.error || 'Failed to cache PRF.first for threshold session'));
    }
  }

  async peekPrfFirstForThresholdSession(args: {
    sessionId: string;
  }): Promise<{ ok: true; remainingUses: number; expiresAtMs: number } | { ok: false; code: string; message: string }> {
    await this.ensureWorkerReady(false);
    const res = await this.sendMessage({
      type: 'THRESHOLD_PRF_FIRST_CACHE_PEEK',
      id: this.generateMessageId(),
      payload: args as any,
    });
    const data = res?.data as any;
    if (res?.success !== true || !data || typeof data.ok !== 'boolean') {
      return { ok: false, code: 'worker_error', message: String(res?.error || 'PRF.first cache peek failed') };
    }
    return data;
  }

  async dispensePrfFirstForThresholdSession(args: {
    sessionId: string;
    uses?: number;
  }): Promise<
    | { ok: true; prfFirstB64u: string; remainingUses: number; expiresAtMs: number }
    | { ok: false; code: string; message: string }
  > {
    await this.ensureWorkerReady(false);
    const res = await this.sendMessage({
      type: 'THRESHOLD_PRF_FIRST_CACHE_DISPENSE',
      id: this.generateMessageId(),
      payload: args as any,
    });
    const data = res?.data as any;
    if (res?.success !== true || !data || typeof data.ok !== 'boolean') {
      return { ok: false, code: 'worker_error', message: String(res?.error || 'PRF.first cache dispense failed') };
    }
    return data;
  }

  async clearPrfFirstForThresholdSession(args: { sessionId: string }): Promise<void> {
    await this.ensureWorkerReady(false);
    const res = await this.sendMessage({
      type: 'THRESHOLD_PRF_FIRST_CACHE_CLEAR',
      id: this.generateMessageId(),
      payload: args as any,
    });
    if (!res?.success) {
      throw new Error(String(res?.error || 'Failed to clear PRF.first cache for threshold session'));
    }
  }

  /**
   * SecureConfirm confirmation helper for signing flows.
   * Runs confirmTxFlow on the main thread and returns the artifacts needed by the signer worker.
   */
  async confirmAndPrepareSigningSession(params: {
    ctx: SecureConfirmWorkerManagerContext;
    sessionId: string;
    signingAuthMode?: SigningAuthMode;
    sessionPolicyDigest32?: string;
    kind: 'transaction';
    txSigningRequests: TransactionInputWasm[];
    rpcCall: RpcCallPayload;
    title?: string;
    body?: string;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
  } | {
    ctx: SecureConfirmWorkerManagerContext;
    sessionId: string;
    signingAuthMode?: SigningAuthMode;
    sessionPolicyDigest32?: string;
    kind: 'delegate';
    nearAccountId: string;
    title?: string;
    body?: string;
    delegate: {
      senderId: string;
      receiverId: string;
      actions: TransactionInputWasm['actions'];
      nonce: string | number | bigint;
      maxBlockHeight: string | number | bigint;
    };
    rpcCall: RpcCallPayload;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
  } | {
    ctx: SecureConfirmWorkerManagerContext;
    sessionId: string;
    signingAuthMode?: SigningAuthMode;
    sessionPolicyDigest32?: string;
    kind: 'nep413';
    nearAccountId: string;
    message: string;
    recipient: string;
    title?: string;
    body?: string;
    contractId?: string;
    nearRpcUrl?: string;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
  }): Promise<{
    sessionId: string;
    transactionContext: TransactionContext;
    intentDigest: string;
    credential?: SerializableCredential;
  }> {
    return confirmAndPrepareSigningSession(this.getHandlerContext(), params);
  }

  /**
   * SecureConfirm helper for registration confirmation.
   * Runs confirmTxFlow on the main thread and returns registration artifacts.
   */
  async requestRegistrationCredentialConfirmation(params: {
    nearAccountId: string;
    deviceNumber: number;
    confirmerText?: { title?: string; body?: string };
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    contractId: string;
    nearRpcUrl: string;
  }): Promise<RegistrationCredentialConfirmationPayload> {
    return requestRegistrationCredentialConfirmation(this.getHandlerContext(), params);
  }

  setWorkerBaseOrigin(origin: string | undefined): void {
    this.workerBaseOrigin = origin;
  }

  /**
   * Ensure the SecureConfirm worker is ready for operations
   * @param requireHealthCheck - Whether to perform health check after initialization
   */
  private async ensureWorkerReady(requireHealthCheck = false): Promise<void> {
    if (this.initializationPromise) {
      await this.initializationPromise;
    } else if (!this.worker) {
      await this.initialize();
    }
    if (!this.worker) {
      throw new Error('SecureConfirm worker failed to initialize');
    }
    // Optional health check for critical operations
    if (requireHealthCheck) {
      try {
        const healthResponse = await this.sendMessage({
          type: 'PING',
          id: this.generateMessageId(),
          payload: {}
        }, 3000);

        if (!healthResponse.success) {
          throw new Error('SecureConfirm worker failed health check');
        }
      } catch (error) {
        console.error('[SecureConfirmWorker] health check failed:', error);
        throw new Error('SecureConfirm worker failed health check');
      }
    }
  }

  /**
   * Initialize the SecureConfirm worker.
   */
  async initialize(): Promise<void> {
    if (this.initializationPromise) {
      return this.initializationPromise;
    }
    // =============================================================
    // This improved error handling ensures that:
    // 1. Initialization failures are properly logged with full details
    // 2. Errors are re-thrown to callers (no silent swallowing)
    // 3. Failed initialization promise is reset for retry
    // 4. Debug logs actually appear in test output
    this.initializationPromise = this.createSecureConfirmWorker().catch(error => {
      console.error('[SecureConfirmWorker] initialization failed:', error);
      console.error('[SecureConfirmWorker] error details:', {
        message: error.message,
        stack: error.stack,
        name: error.name
      });
      // Reset promise so initialization can be retried
      this.initializationPromise = null;
      throw error; // Re-throw so callers know it failed
    });

    const result = await this.initializationPromise;
    return result;
  }

  /** Initialize the SecureConfirm worker (client-hosted bundle). */
  private async createSecureConfirmWorker(): Promise<void> {
    try {
      const relativePath = this.config.workerUrl || BUILD_PATHS.RUNTIME.SECURE_CONFIRM_WORKER;
      const workerUrlStr = resolveWorkerUrl(relativePath, { worker: 'secureConfirm', baseOrigin: this.workerBaseOrigin })
      console.debug('[SecureConfirmWorker] Worker URL:', workerUrlStr);
      // Create Web Worker from resolved URL
      this.worker = new Worker(workerUrlStr, {
        type: 'module',
        name: 'Web3AuthnSecureConfirmWorker'
      });
      // Set up error handling
      this.worker.onerror = (error) => {
        console.error('[SecureConfirmWorker] error:', error);
      };
      // Test communication with the Web Worker
      await this.testWebWorkerCommunication();

    } catch (error: any) {
      throw new Error(`SecureConfirm worker initialization failed: ${error.message}`);
    }
  }

  /**
   * Send message to Web Worker and wait for response
   */
  private async sendMessage<TPayload = unknown>(
    message: SecureConfirmWorkerMessage<TPayload>,
    customTimeout?: number
  ): Promise<SecureConfirmWorkerResponse> {
    return new Promise((resolve, reject) => {
      if (!this.worker) {
        reject(new Error('SecureConfirm worker not available'));
        return;
      }

      const timeoutMs = (customTimeout ?? this.config.workerTimeout ?? 60_000);
      const timeout = setTimeout(() => {
        reject(new Error(`SecureConfirm worker communication timeout (${timeoutMs}ms) for message type: ${message.type}`));
      }, timeoutMs);

      const handleMessage = (event: MessageEvent) => {
        const payload = event.data as SecureConfirmWorkerResponse | {
          type?: unknown;
          data?: unknown;
        };

        // Intercept SecureConfirm handshake messages from the worker and
        // dispatch them through confirmTxFlow on the main thread. The decision
        // is sent back to the worker as USER_PASSKEY_CONFIRM_RESPONSE and
        // consumed by awaitSecureConfirmationV2; this should not resolve the
        // original request promise.
        if ((payload as any)?.type === SecureConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD) {
          const env = payload as {
            type: SecureConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD;
            data: SecureConfirmRequest;
          };
          const ctx = this.getContext();
          if (!this.worker) {
            console.error('[SecureConfirmWorker] missing worker for PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD');
            return;
          }
          void handlePromptUserConfirmInJsMainThread(ctx, env, this.worker);
          return;
        }

        const response = payload as SecureConfirmWorkerResponse;
        if (response.id === message.id) {
          clearTimeout(timeout);
          this.worker!.removeEventListener('message', handleMessage);
          resolve(response);
        }
      };

      this.worker.addEventListener('message', handleMessage);
      this.worker.postMessage(message);
    });
  }

  /**
   * Generate unique message ID
   */
  private generateMessageId(): string {
    return `sc_${Date.now()}_${++this.messageId}`;
  }

  /**
   * Test Web Worker communication
   */
  private async testWebWorkerCommunication(): Promise<void> {
    try {
      const timeoutMs = 2000;
      const pingResponse = await this.sendMessage({
        type: 'PING',
        id: this.generateMessageId(),
        payload: {}
      }, timeoutMs);
      if (!pingResponse.success) {
        throw new Error(`SecureConfirm worker PING failed: ${pingResponse.error}`);
      }
      return;
    } catch (error: any) {
      console.warn('[SecureConfirmWorker] testWebWorkerCommunication failed:', error.message);
    }
  }
}
