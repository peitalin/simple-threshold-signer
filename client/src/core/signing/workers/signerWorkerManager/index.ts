import { UnifiedIndexedDBManager } from '../../../IndexedDBManager';
import { IndexedDBManager } from '../../../IndexedDBManager';
import { type NearClient } from '../../../near/NearClient';
import { SecureConfirmWorkerManager } from '../../secureConfirm/manager';
import { TouchIdPrompt } from '../../webauthn/prompt/touchIdPrompt';
import type { SigningRuntimeDeps } from '../../chainAdaptors/types';
import type {
  MultichainOperationType,
  MultichainWorkerOperationRequest,
  MultichainWorkerOperationResult,
  NearWorkerOperationRequest,
  NearWorkerOperationResult,
  NearWorkerOperationType,
} from './backends/types';
import { UserPreferencesManager } from '../../api/userPreferences';
import { NonceManager } from '../../../near/nonceManager';
import type { ThemeName } from '../../../types/tatchi';
import { NearSignerWorkerBackend } from './backends/nearWorkerBackend';
import { requestMultichainWorkerOperation } from './gateway';
import { NearSigningKeyOpsService } from './nearKeyOpsService';
import type { MultichainWorkerKind } from '../../../runtimeAssetPaths/multichainWorkers';

export interface SignerWorkerManagerContext extends SigningRuntimeDeps {
  userPreferencesManager: UserPreferencesManager;
  getTheme?: () => ThemeName;
  rpIdOverride?: string;
  nearExplorerUrl?: string;
}

type NearWorkerOperationArgs<T extends NearWorkerOperationType = NearWorkerOperationType> = {
  kind: 'nearSigner';
  request: NearWorkerOperationRequest<T>;
};

type MultichainWorkerOperationArgs<
  K extends MultichainWorkerKind = MultichainWorkerKind,
  T extends MultichainOperationType<K> = MultichainOperationType<K>,
> = {
  kind: K;
  request: MultichainWorkerOperationRequest<K, T>;
};

type AnyWorkerOperationArgs =
  | NearWorkerOperationArgs
  | {
      [K in MultichainWorkerKind]: MultichainWorkerOperationArgs<K, MultichainOperationType<K>>;
    }[MultichainWorkerKind];

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
    this.touchIdPrompt = new TouchIdPrompt(
      rpIdOverride,
      enableSafariGetWebauthnRegistrationFallback,
    );
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

  getContext(): SignerWorkerManagerContext {
    return {
      requestWorkerOperation: this.requestWorkerOperation.bind(this),
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

  requestWorkerOperation<T extends NearWorkerOperationType>(args: {
    kind: 'nearSigner';
    request: NearWorkerOperationRequest<T>;
  }): Promise<NearWorkerOperationResult<T>>;
  requestWorkerOperation<
    K extends MultichainWorkerKind,
    T extends MultichainOperationType<K>,
  >(args: {
    kind: K;
    request: MultichainWorkerOperationRequest<K, T>;
  }): Promise<MultichainWorkerOperationResult<K, T>>;
  async requestWorkerOperation(
    args: AnyWorkerOperationArgs,
  ): Promise<
    | NearWorkerOperationResult<NearWorkerOperationType>
    | MultichainWorkerOperationResult<
        MultichainWorkerKind,
        MultichainOperationType<MultichainWorkerKind>
      >
  > {
    if (args.kind === 'nearSigner') {
      return await this.nearWorkerBackend.requestOperation(args.request);
    }

    if (args.kind === 'ethSigner') {
      return await requestMultichainWorkerOperation({
        kind: 'ethSigner',
        request: args.request,
      });
    }

    return await requestMultichainWorkerOperation({
      kind: 'tempoSigner',
      request: args.request,
    });
  }
}
