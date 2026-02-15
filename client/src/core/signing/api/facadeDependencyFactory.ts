import type { AccountId } from '../../types/accountIds';
import type { SigningSessionStatus } from '../../types/tatchi';
import type { FacadeConvenienceDeps } from './facadeConvenience';
import type { FacadeSettingsDeps } from './facadeSettings';

export type CreateFacadeSettingsDepsArgs = {
  touchIdPrompt: FacadeSettingsDeps['touchIdPrompt'];
  nonceManager: FacadeSettingsDeps['nonceManager'];
  userPreferencesManager: FacadeSettingsDeps['userPreferencesManager'];
  activeSigningSessionIds: FacadeSettingsDeps['activeSigningSessionIds'];
};

export function createFacadeSettingsDeps(args: CreateFacadeSettingsDepsArgs): FacadeSettingsDeps {
  return {
    touchIdPrompt: args.touchIdPrompt,
    nonceManager: args.nonceManager,
    userPreferencesManager: args.userPreferencesManager,
    activeSigningSessionIds: args.activeSigningSessionIds,
  };
}

export type CreateFacadeConvenienceDepsArgs = {
  signTempo: FacadeConvenienceDeps['signTempo'];
  prewarmSignerWorkers: FacadeConvenienceDeps['prewarmSignerWorkers'];
  warmCriticalResources: FacadeConvenienceDeps['warmCriticalResources'];
  getWarmSigningSessionStatus: (
    nearAccountId: AccountId | string,
  ) => Promise<SigningSessionStatus | null>;
};

export function createFacadeConvenienceDeps(
  args: CreateFacadeConvenienceDepsArgs,
): FacadeConvenienceDeps {
  return {
    signTempo: args.signTempo,
    prewarmSignerWorkers: args.prewarmSignerWorkers,
    warmCriticalResources: args.warmCriticalResources,
    getWarmSigningSessionStatus: args.getWarmSigningSessionStatus,
  };
}
