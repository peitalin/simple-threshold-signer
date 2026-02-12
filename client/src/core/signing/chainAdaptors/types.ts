import type { UnifiedIndexedDBManager } from '../../IndexedDBManager';
import type { NearClient } from '../../near/NearClient';
import type { NonceManager } from '../../near/nonceManager';
import type { SecureConfirmWorkerManager } from '../secureConfirm/manager';
import type { TouchIdPrompt } from '../webauthn/prompt/touchIdPrompt';
import type { UserPreferencesManager } from '../api/userPreferences';
import type { ThemeName } from '../../types/tatchi';
import type {
  SignerWorkerKind,
  SignerWorkerOperationRequest,
  SignerWorkerOperationResult,
  SignerWorkerOperationType,
} from '../workers/signerWorkerManager/backends/types';

/**
 * Runtime dependencies required by chain adapters/handlers.
 * Keeps chain signing logic decoupled from SignerWorkerManager internals.
 */
export interface SigningRuntimeDeps {
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
  requestWorkerOperation: <
    K extends SignerWorkerKind,
    T extends SignerWorkerOperationType<K>,
  >(args: {
    kind: K;
    request: SignerWorkerOperationRequest<K, T>;
  }) => Promise<SignerWorkerOperationResult<K, T>>;
}
