import { UnifiedIndexedDBManager } from '../../../IndexedDBManager';
import { IndexedDBManager } from '../../../IndexedDBManager';
import { type NearClient } from '../../../near/NearClient';
import {
  type WorkerResponseForRequest,
  type WorkerRequestTypeMap,
} from '../../../types/signer-worker';
import { SecureConfirmWorkerManager } from '../../secureConfirm/manager';
import { TouchIdPrompt } from "../../webauthn/prompt/touchIdPrompt";
import type { MultichainSignerRuntimeDeps } from '../../chains/types';
import type { NearSignerWorkerRequestArgs } from './backends/types';
import { UserPreferencesManager } from '../../api/userPreferences';
import { NonceManager } from '../../../near/nonceManager';
import type { ThemeName } from '../../../types/tatchi';
import { NearSignerWorkerBackend } from './backends/nearWorkerBackend';
import { NearSigningKeyOpsService } from './nearKeyOpsService';

export interface SigningWorkerManagerContext extends MultichainSignerRuntimeDeps {
  userPreferencesManager: UserPreferencesManager;
  getTheme?: () => ThemeName;
  rpIdOverride?: string;
  nearExplorerUrl?: string;
}

/**
 * WebAuthnWorkers handles PRF, workers, and COSE operations
 *
 * Note: This stack is WebAuthn-only; challenges are either server-minted
 * (e.g. login) or derived from intent/session digests (e.g. threshold sessions).
 */
export class SigningWorkerManager {

  private indexedDB: UnifiedIndexedDBManager;
  private touchIdPrompt: TouchIdPrompt;
  private secureConfirmWorkerManager: SecureConfirmWorkerManager;
  private nearClient: NearClient;
  private userPreferencesManager: UserPreferencesManager;
  private nonceManager: NonceManager;
  private relayerUrl: string;
  private nearExplorerUrl?: string;
  private getTheme?: () => ThemeName;
  private nearWorkerBackend: NearSignerWorkerBackend;
  readonly nearKeyOps: NearSigningKeyOpsService;

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
    this.nearWorkerBackend = new NearSignerWorkerBackend();
    this.nearKeyOps = new NearSigningKeyOpsService(() => this.getContext());
  }

  setWorkerBaseOrigin(origin: string | undefined): void {
    this.nearWorkerBackend.setWorkerBaseOrigin(origin);
  }

  getContext(): SigningWorkerManagerContext {
    return {
      sendMessage: this.sendMessage.bind(this),
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
    };
  }

  createSecureWorker(): Worker {
    return this.nearWorkerBackend.createSecureWorker();
  }

  /**
   * Pre-warm worker pool by creating and initializing workers in advance
   * This reduces latency for the first transaction by having workers ready
   */
  async preWarmWorkerPool(): Promise<void> {
    await this.nearWorkerBackend.preWarmWorkerPool();
  }

  private async sendMessage<T extends keyof WorkerRequestTypeMap>({
    sessionId,
    message,
    onEvent,
    timeoutMs,
  }: NearSignerWorkerRequestArgs<T>): Promise<WorkerResponseForRequest<T>> {
    const request = {
      sessionId,
      message,
      ...(onEvent ? { onEvent } : {}),
      ...(typeof timeoutMs === 'number' ? { timeoutMs } : {}),
    };
    return await this.nearWorkerBackend.sendMessage(request);
  }

}
