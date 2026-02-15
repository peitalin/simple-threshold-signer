import { IndexedDBManager } from '../../IndexedDBManager';
import type { NearClient } from '../../near/NearClient';
import { NonceManager } from '../../near/nonceManager';
import NonceManagerInstance from '../../near/nonceManager';
import type { ThemeName, TatchiConfigs } from '../../types/tatchi';
import { SecureConfirmWorkerManager } from '../secureConfirm/manager';
import { TouchIdPrompt } from '../webauthn/prompt/touchIdPrompt';
import { SignerWorkerManager } from '../workers/signerWorkerManager';
import { UserPreferencesManager } from './userPreferences';
import UserPreferencesInstance from './userPreferences';

export type ManagerAssembly = {
  touchIdPrompt: TouchIdPrompt;
  userPreferencesManager: UserPreferencesManager;
  nonceManager: NonceManager;
  secureConfirmWorkerManager: SecureConfirmWorkerManager;
  signerWorkerManager: SignerWorkerManager;
};

export function createManagerAssembly(args: {
  tatchiPasskeyConfigs: TatchiConfigs;
  nearClient: NearClient;
  getTheme: () => ThemeName;
}): ManagerAssembly {
  const touchIdPrompt = new TouchIdPrompt(args.tatchiPasskeyConfigs.iframeWallet?.rpIdOverride, true);
  const userPreferencesManager = UserPreferencesInstance;
  userPreferencesManager.configureDefaultSignerMode?.(args.tatchiPasskeyConfigs.signerMode);
  const nonceManager = NonceManagerInstance;

  const secureConfirmWorkerManager = new SecureConfirmWorkerManager(
    {},
    {
      touchIdPrompt: touchIdPrompt,
      nearClient: args.nearClient,
      indexedDB: IndexedDBManager,
      userPreferencesManager: userPreferencesManager,
      nonceManager: nonceManager,
      rpIdOverride: touchIdPrompt.getRpId(),
      nearExplorerUrl: args.tatchiPasskeyConfigs.nearExplorerUrl,
      getTheme: args.getTheme,
    },
  );

  const signerWorkerManager = new SignerWorkerManager(
    secureConfirmWorkerManager,
    args.nearClient,
    userPreferencesManager,
    nonceManager,
    args.tatchiPasskeyConfigs.relayer.url,
    args.tatchiPasskeyConfigs.iframeWallet?.rpIdOverride,
    true,
    args.tatchiPasskeyConfigs.nearExplorerUrl,
    args.getTheme,
  );

  return {
    touchIdPrompt,
    userPreferencesManager,
    nonceManager,
    secureConfirmWorkerManager,
    signerWorkerManager,
  };
}
