import { useState, useEffect, useCallback } from 'react';
import type { TatchiPasskey } from '@/core/TatchiPasskey';
import { toAccountId } from '@/core/types/accountIds';
import { awaitWalletIframeReady } from '../utils/walletIframe';

async function discoverRelayerAccountIdFromHealthz(relayUrl: string): Promise<string | null> {
  const base = String(relayUrl || '').trim().replace(/\/$/, '');
  if (!base) return null;

  const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
  const timer = controller ? setTimeout(() => controller.abort(), 1500) : null;

  try {
    const res = await fetch(`${base}/healthz`, {
      method: 'GET',
      ...(controller ? { signal: controller.signal } : {}),
    });
    if (!res.ok) return null;
    const json = await res.json().catch(() => ({}));
    const relayerAccountId =
      (typeof json?.relayerAccountId === 'string' ? json.relayerAccountId : '') ||
      (typeof json?.relayer_account_id === 'string' ? json.relayer_account_id : '');
    const normalized = String(relayerAccountId || '').trim().replace(/^\./, '').toLowerCase();
    return normalized || null;
  } catch {
    return null;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export interface AccountInputState {
  inputUsername: string;
  lastLoggedInUsername: string;
  lastLoggedInDomain: string;
  targetAccountId: string;
  displayPostfix: string;
  isUsingExistingAccount: boolean;
  accountExists: boolean;
  indexDBAccounts: string[];
}

export interface UseAccountInputOptions {
  tatchi: TatchiPasskey;
  /**
   * Account domain/postfix used to derive full accountIds from a username input
   * (e.g. `w3a-relayer.testnet` for `alice.w3a-relayer.testnet`).
   */
  accountDomain?: string;
  /**
   * @deprecated Use `accountDomain` instead.
   * Kept for backwards-compat with earlier versions of this hook.
   */
  contractId?: string;
  currentNearAccountId?: string | null;
  isLoggedIn: boolean;
}

export interface UseAccountInputReturn extends AccountInputState {
  setInputUsername: (username: string) => void;
  refreshAccountData: () => Promise<void>;
}

export function useAccountInput({
  tatchi,
  accountDomain,
  contractId,
  currentNearAccountId,
  isLoggedIn
}: UseAccountInputOptions): UseAccountInputReturn {
  const [discoveredRelayerAccount, setDiscoveredRelayerAccount] = useState<string>('');

  // Best-effort: when the host app didn't explicitly configure `relayerAccount`, try to
  // discover it from the relay's `/healthz` response so atomic registration uses the
  // correct accountId postfix.
  useEffect(() => {
    const hasExplicitDomain = typeof accountDomain === 'string' && accountDomain.trim().length > 0;
    if (hasExplicitDomain) return;

    const cfgRelayer = String(tatchi.configs.relayerAccount || '').trim().replace(/^\./, '').toLowerCase();
    const cfgContract = String(tatchi.configs.contractId || '').trim().replace(/^\./, '').toLowerCase();
    // If relayerAccount differs from contractId, assume it was configured explicitly or via env and do not override.
    if (cfgRelayer && cfgContract && cfgRelayer !== cfgContract) return;

    const relayUrl = String(tatchi.configs.relayer?.url || '').trim();
    if (!relayUrl) return;

    let cancelled = false;
    void (async () => {
      const discovered = await discoverRelayerAccountIdFromHealthz(relayUrl);
      if (cancelled || !discovered) return;
      setDiscoveredRelayerAccount(discovered);
    })();
    return () => {
      cancelled = true;
    };
  }, [accountDomain, tatchi]);

  const normalizedDomain = (accountDomain || discoveredRelayerAccount || contractId || tatchi.configs.relayerAccount || tatchi.configs.contractId || '')
    .trim()
    .replace(/^\./, '')
    .toLowerCase();

  const [state, setState] = useState<AccountInputState>({
    inputUsername: '',
    lastLoggedInUsername: '',
    lastLoggedInDomain: '',
    targetAccountId: '',
    displayPostfix: '',
    isUsingExistingAccount: false,
    accountExists: false,
    indexDBAccounts: []
  });

  // Await wallet iframe readiness when needed
  const awaitWalletIframeIfNeeded = useCallback(async () => {
    await awaitWalletIframeReady(tatchi);
  }, [tatchi]);

  // Load recent accounts and determine account info
  const refreshAccountData = useCallback(async () => {
    try {
      await awaitWalletIframeIfNeeded();
      const { accountIds, lastUsedAccount } = await tatchi.getRecentLogins();

      let lastUsername = '';
      let lastDomain = '';

      if (lastUsedAccount) {
        const parts = lastUsedAccount.nearAccountId.split('.');
        lastUsername = parts[0];
        lastDomain = `.${parts.slice(1).join('.')}`;
      }

      setState(prevState => ({
        ...prevState,
        indexDBAccounts: accountIds,
        lastLoggedInUsername: lastUsername,
        lastLoggedInDomain: lastDomain
      }));

    } catch (error) {
      console.warn('Error loading account data:', error);
    }
  }, [awaitWalletIframeIfNeeded, tatchi]);

  // Check if account has passkey credentials
  const checkAccountExists = useCallback(async (accountId: string) => {
    if (!accountId) {
      setState(prevState => ({ ...prevState, accountExists: false }));
      return;
    }

    try {
      await awaitWalletIframeIfNeeded();
      const hasCredential = await tatchi.hasPasskeyCredential(toAccountId(accountId));
      setState(prevState => ({ ...prevState, accountExists: hasCredential }));
    } catch (error) {
      console.warn('Error checking credentials:', error);
      setState(prevState => ({ ...prevState, accountExists: false }));
    }
  }, [awaitWalletIframeIfNeeded, tatchi]);

  // Update derived state when inputs change
  const updateDerivedState = useCallback((username: string, accounts: string[]) => {
    // Normalize username to lowercase to avoid iOS autocapitalize causing invalid NEAR IDs
    const raw = (username || '').trim();
    const uname = raw.toLowerCase();

    if (!raw) {
      setState(prevState => ({
        ...prevState,
        targetAccountId: '',
        displayPostfix: '',
        isUsingExistingAccount: false,
        accountExists: false
      }));
      return;
    }

    // If user types a full accountId (or selects one via custom UI), prefer it when present in storage.
    const accountByExactInput = accounts.find((accountId) => accountId.toLowerCase() === uname);

    // If the user typed a full accountId, don't append any postfix.
    const typedFullAccountId = uname.includes('.');
    const derivedTarget = typedFullAccountId ? uname : (normalizedDomain ? `${uname}.${normalizedDomain}` : uname);
    const derivedStoredMatch = accounts.find((accountId) => accountId.toLowerCase() === derivedTarget);

    // Only treat as an "existing account" when we have an exact accountId match. This prevents
    // accidentally selecting `alice.<old-domain>` when the configured domain is `.<new-domain>`.
    const existingAccount = accountByExactInput || derivedStoredMatch;

    let targetAccountId: string;
    let displayPostfix: string;
    let isUsingExistingAccount: boolean;

    if (existingAccount) {
      // Use existing account's full ID
      targetAccountId = existingAccount;
      const parts = existingAccount.split('.');
      // If the user typed the full accountId, don't show an extra postfix overlay.
      displayPostfix = accountByExactInput ? '' : `.${parts.slice(1).join('.')}`;
      isUsingExistingAccount = true;
    } else {
      targetAccountId = derivedTarget;
      displayPostfix = (!typedFullAccountId && normalizedDomain) ? `.${normalizedDomain}` : '';
      isUsingExistingAccount = false;
    }

    setState(prevState => ({
      ...prevState,
      targetAccountId,
      displayPostfix,
      isUsingExistingAccount
    }));

    // Check if account has credentials
    void checkAccountExists(targetAccountId);
  }, [checkAccountExists, normalizedDomain]);

  // Handle username input changes
  const setInputUsername = useCallback((username: string) => {
    const uname = (username || '').toLowerCase();
    setState(prevState => ({ ...prevState, inputUsername: uname }));
    updateDerivedState(uname, state.indexDBAccounts);
  }, [state.indexDBAccounts, updateDerivedState]);

  // onInitialMount: Load last logged in user and prefill
  useEffect(() => {
    const initializeAccountInput = async () => {
      await refreshAccountData();

      if (isLoggedIn && currentNearAccountId) {
        // User is logged in, show their username
        const username = currentNearAccountId.split('.')[0];
        setState(prevState => ({ ...prevState, inputUsername: username }));
      } else {
        // No logged-in user, try to get last used account
        await awaitWalletIframeIfNeeded();
        const { lastUsedAccount } = await tatchi.getRecentLogins();
        if (lastUsedAccount) {
          const username = lastUsedAccount.nearAccountId.split('.')[0];
          setState(prevState => ({ ...prevState, inputUsername: username }));
        }
      }
    };

    initializeAccountInput();
  }, [awaitWalletIframeIfNeeded, currentNearAccountId, isLoggedIn, refreshAccountData, tatchi]);

  // onLogout: Reset to last used account
  useEffect(() => {
    const handleLogoutReset = async () => {
      // Only reset if user just logged out (isLoggedIn is false but we had a nearAccountId before)
      if (!isLoggedIn && !currentNearAccountId) {
        try {
          await awaitWalletIframeIfNeeded();
          const { lastUsedAccount } = await tatchi.getRecentLogins();
          if (lastUsedAccount) {
            const username = lastUsedAccount.nearAccountId.split('.')[0];
            setState(prevState => ({ ...prevState, inputUsername: username }));
          }
        } catch (error) {
          console.warn('Error resetting username after logout:', error);
        }
      }
    };

    handleLogoutReset();
  }, [awaitWalletIframeIfNeeded, currentNearAccountId, isLoggedIn, tatchi]);

  // Update derived state when dependencies change
  useEffect(() => {
    updateDerivedState(state.inputUsername, state.indexDBAccounts);
  }, [state.inputUsername, state.indexDBAccounts, updateDerivedState]);

  return {
    ...state,
    setInputUsername,
    refreshAccountData
  };
}
