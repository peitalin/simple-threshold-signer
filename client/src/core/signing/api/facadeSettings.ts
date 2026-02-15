import type { NonceManager } from '../../near/nonceManager';
import type { ThemeName } from '../../types/tatchi';
import type { TouchIdPrompt } from '../webauthn/prompt/touchIdPrompt';
import type { UserPreferencesManager } from './userPreferences';

export type FacadeSettingsDeps = {
  touchIdPrompt: Pick<TouchIdPrompt, 'getRpId'>;
  nonceManager: NonceManager;
  userPreferencesManager: UserPreferencesManager;
  activeSigningSessionIds: Map<string, string>;
};

export function getRpId(deps: FacadeSettingsDeps): string {
  return deps.touchIdPrompt.getRpId();
}

export function getNonceManager(deps: FacadeSettingsDeps): NonceManager {
  return deps.nonceManager;
}

export function setTheme(currentTheme: ThemeName, next: ThemeName): ThemeName {
  if (next !== 'light' && next !== 'dark') {
    return currentTheme;
  }
  return next;
}

export function getTheme(theme: ThemeName): ThemeName {
  return theme;
}

export function getUserPreferences(deps: FacadeSettingsDeps): UserPreferencesManager {
  return deps.userPreferencesManager;
}

export function destroyFacade(deps: FacadeSettingsDeps): void {
  deps.userPreferencesManager.destroy();
  deps.nonceManager.clear();
  deps.activeSigningSessionIds.clear();
}
