import type { UnifiedIndexedDBManager } from '../../IndexedDBManager';
import type { NearClient } from '../../near/NearClient';
import type { NonceManager } from '../../near/nonceManager';
import type { onProgressEvents } from '../../types/sdkSentEvents';
import type { WorkerRequestTypeMap, WorkerResponseForRequest } from '../../types/signer-worker';
import type { SecureConfirmWorkerManager } from '../secureConfirm/manager';
import type { TouchIdPrompt } from '../webauthn/prompt/touchIdPrompt';
import type { UserPreferencesManager } from '../api/userPreferences';
import type { ThemeName } from '../../types/tatchi';

type WithOptionalSessionId<T> = T extends { sessionId: string }
  ? Omit<T, 'sessionId'> & { sessionId?: string }
  : T;

/**
 * Runtime dependencies required by chain adapters/handlers.
 * Keeps chain signing logic decoupled from SignerWorkerManager internals.
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
  sendMessage: <T extends keyof WorkerRequestTypeMap>(args: {
    message: {
      type: T;
      payload: WithOptionalSessionId<WorkerRequestTypeMap[T]['request']>;
    };
    onEvent?: (update: onProgressEvents) => void;
    timeoutMs?: number;
    sessionId?: string;
  }) => Promise<WorkerResponseForRequest<T>>;
}
