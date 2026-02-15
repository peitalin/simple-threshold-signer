import { __isWalletIframeHostMode } from '../../WalletIframe/host-mode';
import { onEmbeddedBaseChange, resolveWorkerBaseOrigin } from '../../runtimeAssetPaths';
import type { TatchiConfigs } from '../../types/tatchi';
import type { UserPreferencesManager } from './userPreferences';

export type RuntimeBootstrapDeps = {
  tatchiPasskeyConfigs: TatchiConfigs;
  userPreferencesManager: Pick<UserPreferencesManager, 'initFromIndexedDB'>;
  getWorkerBaseOrigin: () => string;
  setWorkerBaseOrigin: (origin: string) => void;
};

function resolveInitialWorkerBaseOrigin(): string {
  return resolveWorkerBaseOrigin() || (typeof window !== 'undefined' ? window.location.origin : '');
}

export function initializeRuntimeBootstrap(deps: RuntimeBootstrapDeps): void {
  deps.setWorkerBaseOrigin(resolveInitialWorkerBaseOrigin());

  // Keep base origin updated if the wallet sets a new embedded base.
  if (typeof window !== 'undefined') {
    onEmbeddedBaseChange((url) => {
      const origin = new URL(url, window.location.origin).origin;
      if (origin && origin !== deps.getWorkerBaseOrigin()) {
        deps.setWorkerBaseOrigin(origin);
      }
    });
  }

  // Best-effort: load persisted preferences unless we are in app-origin iframe mode,
  // where the wallet origin owns persistence and the app should avoid IndexedDB.
  const shouldAvoidAppOriginIndexedDB =
    !!deps.tatchiPasskeyConfigs.iframeWallet?.walletOrigin && !__isWalletIframeHostMode();
  if (!shouldAvoidAppOriginIndexedDB) {
    void deps.userPreferencesManager.initFromIndexedDB().catch(() => undefined);
  }
}
