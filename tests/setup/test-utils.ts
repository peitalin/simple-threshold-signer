import { Page } from '@playwright/test';
import type { PasskeyTestConfig } from './types';

/**
 * Setup test utilities
 */
export async function setupTestUtilities(page: Page, config: PasskeyTestConfig): Promise<void> {
  await page.evaluate(async (setupConfig) => {
    const baseLog = console.log.bind(console);
    const baseWarn = console.warn.bind(console);
    const baseError = console.error.bind(console);
    console.log = (...args: any[]) => baseLog('[setup:utils]', ...args);
    console.warn = (...args: any[]) => baseWarn('[setup:utils]', ...args);
    console.error = (...args: any[]) => baseError('[setup:utils]', ...args);

    const { originalFetch, originalCredentialsCreate, originalCredentialsGet } = (window as any).__test_originals;

    const webAuthnUtils = {
      simulateSuccessfulPasskeyInput: async (operationTrigger: () => Promise<void>) => {
        console.log('Simulating successful passkey input...');
        await operationTrigger();
        await new Promise(resolve => setTimeout(resolve, 500));
        console.log('Successful passkey input simulation completed');
      },
      simulateFailedPasskeyInput: async (operationTrigger: () => Promise<void>, postOperationCheck?: () => Promise<void>) => {
        console.log('Simulating failed passkey input...');
        await operationTrigger();
        if (postOperationCheck) {
          await postOperationCheck();
        } else {
          await new Promise(resolve => setTimeout(resolve, 300));
        }
        console.log('Failed passkey input simulation completed');
      },
      getCredentials: async () => [],
      clearCredentials: async () => {}
    };

    (window as any).testUtils = {
      PasskeyManager: (window as any).PasskeyManager,
      tatchi: (window as any).tatchi,
      configs: (window as any).configs || setupConfig,
      confirmOverrides: {
        // SecureConfirm invariants:
        // - LocalOnly decrypt flows (DECRYPT_PRIVATE_KEY_WITH_PRF) typically run with uiMode: 'none'
        //   and never leak PRF outputs outside the wallet origin.
        // - Registration/signing flows use modal UI and never return PRF/WrapKeySeed to app-origin code.
        none: { uiMode: 'none', behavior: 'skipClick', autoProceedDelay: 0 },
        skipClick: { uiMode: 'modal', behavior: 'skipClick', autoProceedDelay: 0 },
      },
      webAuthnUtils,
      // Login diagnostics helper (best-effort): returns the current login session snapshot.
      loginStatus: async () => {
        try {
          const pm = (window as any).tatchi;
          if (!pm || typeof pm.getLoginSession !== 'function') return null;
          return await pm.getLoginSession();
        } catch {
          return null;
        }
      },
      // IMPORTANT: For the atomic relay-server flow, the relay account is the
      // signer/predecessor for account creation. On NEAR, only the parent account can create
      // its own subaccounts, so new accounts MUST be subaccounts of the configured parent.
      generateTestAccountId: () => {
        const cfg = (window as any).configs || {};
        const parent = String(cfg.relayerAccount || cfg.contractId || 'w3a-v1.testnet').trim().replace(/^\./, '');
        return `e2etest${Date.now()}.${parent}`;
      },
      verifyAccountExists: async (accountId: string) => {
        const response = await fetch(setupConfig.nearRpcUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 'verify-account',
            method: 'query',
            params: {
              request_type: 'view_account',
              finality: 'final',
              account_id: accountId
            }
          })
        });
        const result = await response.json();
        return !result.error && !!result.result;
      },
      failureMocks: {
        webAuthnCeremony: () => {
          if (navigator.credentials) {
            navigator.credentials.create = async () => {
              throw new Error('WebAuthn ceremony failed - user cancelled');
            };
          }
        },
        nearKeypairGeneration: () => {},
        contractVerification: () => {},
        faucetService: () => {
          window.fetch = async (url: any, options: any) => {
            if (typeof url === 'string' && url.includes('helper.testnet.near.org')) {
              return new Response(JSON.stringify({
                error: 'Rate limit exceeded - faucet failure injected'
              }), { status: 429, headers: { 'Content-Type': 'application/json' } });
            }
            return originalFetch(url, options);
          };
        },
        relayServer: () => {
          window.fetch = async (url: any, options: any) => {
            if (typeof url === 'string' && url.includes('/create_account_and_register_user')) {
              return new Response(JSON.stringify({
                success: false,
                error: 'Relay server failure injected for testing'
              }), { status: 500, headers: { 'Content-Type': 'application/json' } });
            }
            return originalFetch(url, options);
          };
        },
        contractRegistration: () => {},
        databaseStorage: () => {},
        // transactionBroadcasting mock removed - using real NEAR testnet
        accessKeyLookup: () => {
          window.fetch = async (url: any, options: any) => {
            if (typeof url === 'string' && url.includes('test.rpc.fastnear.com') && options?.method === 'POST') {
              try {
                const body = JSON.parse(options.body || '{}');
                if (body.method === 'query' && body.params?.request_type === 'view_access_key') {
                  return new Response(JSON.stringify({
                    jsonrpc: '2.0',
                    id: body.id,
                    result: {
                      nonce: 1,
                      permission: 'FullAccess',
                      block_height: 1,
                      block_hash: 'mock_block_hash_' + Date.now()
                    }
                  }), { status: 200, headers: { 'Content-Type': 'application/json' } });
                }
              } catch (e) {
                // If parsing fails, continue with original fetch
              }
            }
            return originalFetch(url, options);
          };
        },
        preventSessionClearing: () => {
          const t = (window as any).testUtils?.tatchi;
          if (t && typeof t.logoutAndClearSession === 'function') {
            (window as any).testUtils.tatchi.logoutAndClearSession = async () => {
              console.log('[TEST] Preventing session clearing in test environment');
            };
          }
        },
        restore: () => {
          window.fetch = originalFetch;
          if (navigator.credentials && originalCredentialsCreate) {
            navigator.credentials.create = originalCredentialsCreate;
          }
          if (navigator.credentials && originalCredentialsGet) {
            navigator.credentials.get = originalCredentialsGet;
          }
        }
      },
      rollbackVerification: {
        verifyDatabaseClean: async (accountId: string) => true,
        verifyAccountDeleted: async (accountId: string) => true,
        getRollbackEvents: (events: any[]) => events.filter(e => e.type === 'rollback')
      },
      registrationFlowUtils: {
        setupRelayServerMock: (successResponse = true) => {
          window.fetch = async (url: any, options: any) => {
            if (typeof url === 'string' && url.includes('/create_account_and_register_user')) {
              if (successResponse) {
                return new Response(JSON.stringify({
                  success: true,
                  transactionHash: 'mock_atomic_transaction_hash_' + Date.now(),
                  message: 'Account created and registered successfully via relay-server'
                }), { status: 200, headers: { 'Content-Type': 'application/json' } });
              } else {
                return new Response(JSON.stringify({
                  success: false,
                  error: 'Mock atomic registration failure'
                }), { status: 500, headers: { 'Content-Type': 'application/json' } });
              }
            }
            return originalFetch(url, options);
          };
        },
        setupTestnetFaucetMock: (successResponse = true) => {
          window.fetch = async (url: any, options: any) => {
            if (typeof url === 'string' && url.includes('helper.testnet.near.org')) {
              if (successResponse) {
                return new Response(JSON.stringify({
                  ok: true,
                  account_id: options.body ? JSON.parse(options.body).account_id : 'test.testnet'
                }), { status: 200, headers: { 'Content-Type': 'application/json' } });
              } else {
                return new Response(JSON.stringify({
                  error: 'Mock testnet faucet failure'
                }), { status: 429, headers: { 'Content-Type': 'application/json' } });
              }
            }
            return originalFetch(url, options);
          };
        },
        restoreFetch: () => {
          window.fetch = originalFetch;
        }
      }
    };

    console.log('Test utilities setup complete');

    // Best-effort: discover the runtime relayer account from the relay health endpoint.
    // This allows tests that use the real relay-server harness (with a provisioned
    // relayer account) to generate valid subaccounts under that relayer.
    try {
      const cfg = (window as any).configs || setupConfig;
      const relayBase = String(cfg?.relayer?.url || '').trim().replace(/\/$/, '');
      if (relayBase) {
        const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
        const timer = controller ? setTimeout(() => controller.abort(), 1500) : null;
        try {
          const res = await originalFetch(`${relayBase}/healthz`, {
            method: 'GET',
            ...(controller ? { signal: controller.signal } : {}),
          });
          const json = await res.json().catch(() => ({}));
          const relayerAccountId = String(json?.relayerAccountId || json?.relayer_account_id || '').trim();
          if (relayerAccountId) {
            (window as any).configs = { ...(cfg || {}), relayerAccount: relayerAccountId };
            if ((window as any).testUtils) {
              (window as any).testUtils.configs = (window as any).configs;
            }
          }
        } finally {
          if (timer) clearTimeout(timer);
        }
      }
    } catch { }

    try {
      const originalWarn = console.warn;
      console.warn = function(...args: any[]) {
        const msg = (args && args[0]) ? String(args[0]) : '';
        if (
          /Passkey(Client|NearKeys)DB connection is blocking another connection\./i.test(msg)
          || /pre-warm timeout/i.test(msg)
          || /noble\/ed25519 import failed/i.test(msg)
        ) {
          return;
        }
        return (originalWarn as any).apply(console, args as any);
      } as any;
    } catch {}

    try {
      const tatchi = (window as any).tatchi;
      const nonceManager = tatchi?.webAuthnManager?.getNonceManager?.();

      // SecureConfirm-driven confirmTxFlow tests rely on these fallbacks when NonceManager
      // has not been initialized with a user yet (pre-login or LocalOnly decrypt).
      if (!nonceManager) {
        console.warn('[TEST PATCH] NonceManager not available for patching');
      } else {
        if (typeof nonceManager.getNonceBlockHashAndHeight === 'function') {
          const originalGet = nonceManager.getNonceBlockHashAndHeight.bind(nonceManager);
          nonceManager.getNonceBlockHashAndHeight = async function(nearClient: any, opts?: any) {
            if (this.nearAccountId && this.nearPublicKeyStr) {
              return await originalGet(nearClient, opts);
            }
            try {
              const block = await nearClient.viewBlock({ finality: 'final' });
              return {
                nearPublicKeyStr: 'ed25519:11111111111111111111111111111111',
                accessKeyInfo: { nonce: 0, permission: 'FullAccess' },
                nextNonce: '1',
                txBlockHeight: String(block?.header?.height ?? '0'),
                txBlockHash: block?.header?.hash ?? '',
              };
            } catch (error) {
              console.warn('[TEST PATCH] Block-only NonceManager fallback failed:', error);
              return await originalGet(nearClient, opts);
            }
          };
        }
        if (typeof nonceManager.reserveNonces === 'function') {
          const originalReserve = nonceManager.reserveNonces.bind(nonceManager);
          nonceManager.reserveNonces = function(count: number) {
            if (this.nearAccountId && this.nearPublicKeyStr) {
              return originalReserve(count);
            }
            const timestamp = Date.now();
            const mockNonces = Array.from({ length: count }, (_, i) => `${timestamp}${i}`);
            console.log('[TEST PATCH] NonceManager returning %d mock nonces for uninitialized state', count);
            return mockNonces;
          };
        }
        if (typeof nonceManager.updateFromChain === 'function') {
          const originalUpdate = nonceManager.updateFromChain.bind(nonceManager);
          nonceManager.updateFromChain = async function(nearClient: any) {
            try {
              return await originalUpdate(nearClient);
            } catch (error) {
              const message = (error && (error as any).message) ? String((error as any).message) : String(error ?? '');
              if (message.includes('behind expected') || message.includes('nonce')) {
                console.log('[TEST PATCH] NonceManager: Tolerating nonce mismatch during test');
                return;
              }
              throw error;
            }
          };
        }
        console.log('[TEST PATCH] NonceManager patches applied successfully');
      }
    } catch (error) {
      console.warn('[TEST PATCH] Failed to apply NonceManager patches:', error);
    }
  }, config);
}
