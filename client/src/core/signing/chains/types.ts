import type { UnifiedIndexedDBManager } from '../../IndexedDBManager';
import type { NearClient } from '../../near/NearClient';
import type { NonceManager } from '../../near/nonceManager';
import type { WorkerRequestTypeMap, WorkerResponseForRequest } from '../../types/signer-worker';
import type { SecureConfirmWorkerManager } from '../secureConfirm/manager';
import type { TouchIdPrompt } from '../webauthn/prompt/touchIdPrompt';
import type { UserPreferencesManager } from '../api/userPreferences';
import type { ThemeName } from '../../types/tatchi';
import type { NearSignerWorkerRequestArgs } from '../workers/signingWorkerManager/backends';

/**
 * Runtime dependencies required by chain adapters/handlers.
 * Keeps chain signing logic decoupled from SigningWorkerManager internals.
 */
export interface MultichainSignerRuntimeDeps {
  touchIdPrompt: TouchIdPrompt;
  nearClient: NearClient;
  indexedDB: UnifiedIndexedDBManager;
  userPreferencesManager: UserPreferencesManager;
  nonceManager: NonceManager;
  getTheme?: () => ThemeName;
  rpIdOverride?: string;
  nearExplorerUrl?: string;
  relayerUrl: string;
  secureConfirmWorkerManager?: SecureConfirmWorkerManager;
  sendMessage: <T extends keyof WorkerRequestTypeMap>(args: NearSignerWorkerRequestArgs<T>) => Promise<WorkerResponseForRequest<T>>;
}
