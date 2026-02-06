import { useCallback, useMemo } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import {
  LoginPhase,
  LoginStatus,
} from '@/core/types/sdkSentEvents';
import type {
  AccountInputState,
  LoginState,
  RegistrationResult,
  TatchiContextType,
} from '../types';
import type { ThemeName } from '@/core/types/tatchi';
import { useSDKFlowRuntime } from './useSDKFlowRuntime';
import { useTatchiWithSdkFlow } from './useTatchiWithSdkFlow';

export function useTatchiContextValue(args: {
  tatchi: TatchiContextType['tatchi'];
  loginState: LoginState;
  setLoginState: Dispatch<SetStateAction<LoginState>>;
  walletIframeConnected: boolean;
  refreshLoginState: TatchiContextType['refreshLoginState'];
  accountInputState: AccountInputState;
  setInputUsername: TatchiContextType['setInputUsername'];
  refreshAccountData: TatchiContextType['refreshAccountData'];
  hostSetTheme?: (theme: ThemeName) => void;
}): TatchiContextType {
  const {
    tatchi,
    loginState,
    setLoginState,
    walletIframeConnected,
    refreshLoginState,
    accountInputState,
    setInputUsername,
    refreshAccountData,
    hostSetTheme,
  } = args;

  const { sdkFlow, beginSdkFlow, appendSdkEventMessage, endSdkFlow } = useSDKFlowRuntime();
  const tatchiWithSdkFlow = useTatchiWithSdkFlow({
    tatchi,
    beginSdkFlow,
    appendSdkEventMessage,
    endSdkFlow,
    hostSetTheme,
  });

  const logout: TatchiContextType['logout'] = useCallback(() => {
    try {
      void tatchi.logoutAndClearSession().catch((error) => {
        console.warn('Logout warning:', error);
      });
    } catch (error) {
      console.warn('Logout warning:', error);
    }

    setLoginState(prevState => ({
      ...prevState,
      isLoggedIn: false,
      nearAccountId: null,
      nearPublicKey: null,
    }));
  }, [setLoginState, tatchi]);

  const startDevice2LinkingFlow: TatchiContextType['startDevice2LinkingFlow'] = useCallback(
    async (args) => {
      return await tatchiWithSdkFlow.startDevice2LinkingFlow((args ?? {}) as any);
    },
    [tatchiWithSdkFlow],
  );

  const stopDevice2LinkingFlow: TatchiContextType['stopDevice2LinkingFlow'] = useCallback(async () => {
    await tatchi.stopDevice2LinkingFlow();
  }, [tatchi]);

  const loginAndCreateSession: TatchiContextType['loginAndCreateSession'] = useCallback(async (nearAccountId, options) => {
    return tatchiWithSdkFlow.loginAndCreateSession(nearAccountId, {
      ...options,
      onEvent: async (event) => {
        if (event.phase === LoginPhase.STEP_4_LOGIN_COMPLETE && event.status === LoginStatus.SUCCESS) {
          const { login } = await tatchi.getLoginSession(nearAccountId);
          const isLoggedIn = login.isLoggedIn;
          setLoginState(prevState => ({
            ...prevState,
            isLoggedIn,
            nearAccountId: event.nearAccountId || null,
            nearPublicKey: event.clientNearPublicKey || null,
          }));
        }
        return options?.onEvent?.(event);
      },
      onError: (error) => {
        logout();
        return options?.onError?.(error);
      }
    });
  }, [logout, setLoginState, tatchi, tatchiWithSdkFlow]);

  const registerPasskey: TatchiContextType['registerPasskey'] = useCallback(async (nearAccountId, options) => {
    const result: RegistrationResult = await tatchiWithSdkFlow.registerPasskey(nearAccountId, {
      ...options,
      onError: (error) => {
        logout();
        return options?.onError?.(error);
      }
    });

    if (result?.success) {
      await refreshLoginState(nearAccountId);
    }
    return result;
  }, [logout, refreshLoginState, tatchiWithSdkFlow]);

  const executeAction: TatchiContextType['executeAction'] = useCallback((args) => {
    return tatchi.executeAction({ ...args, options: { ...(args.options || {}) } });
  }, [tatchi]);

  const signNEP413Message: TatchiContextType['signNEP413Message'] = useCallback((args) => {
    return tatchi.signNEP413Message({ ...args, options: { ...(args.options || {}) } });
  }, [tatchi]);

  const signDelegateAction: TatchiContextType['signDelegateAction'] = useCallback((args) => {
    return tatchi.signDelegateAction({ ...args, options: { ...(args.options || {}) } });
  }, [tatchi]);

  const getLoginSession: TatchiContextType['getLoginSession'] = useCallback((nearAccountId?: string) => {
    return tatchi.getLoginSession(nearAccountId);
  }, [tatchi]);

  const setConfirmBehavior: TatchiContextType['setConfirmBehavior'] = useCallback((behavior) => {
    tatchi.setConfirmBehavior(behavior);
  }, [tatchi]);

  const setConfirmationConfig: TatchiContextType['setConfirmationConfig'] = useCallback((config) => {
    tatchi.setConfirmationConfig(config);
  }, [tatchi]);

  const getConfirmationConfig: TatchiContextType['getConfirmationConfig'] = useCallback(() => {
    return tatchi.getConfirmationConfig();
  }, [tatchi]);

  const viewAccessKeyList: TatchiContextType['viewAccessKeyList'] = useCallback((accountId: string) => {
    return tatchi.viewAccessKeyList(accountId);
  }, [tatchi]);

  return useMemo(() => ({
    tatchi: tatchiWithSdkFlow,
    sdkFlow,
    registerPasskey,
    loginAndCreateSession,
    logout,
    startDevice2LinkingFlow,
    stopDevice2LinkingFlow,
    executeAction,
    signNEP413Message,
    signDelegateAction,
    getLoginSession,
    refreshLoginState,
    loginState,
    walletIframeConnected,
    accountInputState,
    setInputUsername,
    refreshAccountData,
    setConfirmBehavior,
    setConfirmationConfig,
    getConfirmationConfig,
    viewAccessKeyList,
    themeCapabilities: {
      canSetHostTheme: typeof hostSetTheme === 'function',
    },
  }), [
    tatchiWithSdkFlow,
    sdkFlow,
    registerPasskey,
    loginAndCreateSession,
    logout,
    startDevice2LinkingFlow,
    stopDevice2LinkingFlow,
    executeAction,
    signNEP413Message,
    signDelegateAction,
    getLoginSession,
    refreshLoginState,
    loginState,
    walletIframeConnected,
    accountInputState,
    setInputUsername,
    refreshAccountData,
    setConfirmBehavior,
    setConfirmationConfig,
    getConfirmationConfig,
    viewAccessKeyList,
    hostSetTheme,
  ]);
}
