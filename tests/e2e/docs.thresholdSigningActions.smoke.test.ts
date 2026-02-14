import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  demoPage: '/src/components/DemoPage.tsx',
} as const;

test.describe('docs frontend signing actions smoke', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('logged-in demo exposes NEAR, Tempo, and EVM signing actions and invokes each', async ({
    page,
  }) => {
    await page.evaluate(async ({ paths }) => {
      const React =
        ((await import('/node_modules/.vite/deps/react.js').catch(() => null)) as any) ||
        (await import('react'));
      const ReactRuntime = (React as any).default || React;
      const ReactDOMClient =
        ((await import('/node_modules/.vite/deps/react-dom_client.js').catch(() => null)) as any) ||
        (await import('react-dom/client'));
      const ReactDOMClientRuntime = (ReactDOMClient as any).default || ReactDOMClient;
      const ReactDOM =
        ((await import('/node_modules/.vite/deps/react-dom.js').catch(() => null)) as any) ||
        (await import('react-dom'));
      const ReactDOMRuntime = (ReactDOM as any).default || ReactDOM;
      const demoMod = await import(paths.demoPage);
      const DemoPage = (demoMod as any).DemoPage || (demoMod as any).default;
      if (!DemoPage) {
        throw new Error('Failed to load DemoPage module export');
      }

      const counters = {
        nearSigns: 0,
        tempoSigns: 0,
        evmSigns: 0,
      };
      (window as any).__docsSigningSmokeCounters = counters;

      const keyRef = {
        type: 'threshold-ecdsa-secp256k1',
        userId: 'alice.testnet',
        relayerUrl: 'https://relay.example',
        relayerKeyId: 'mock-relayer-key-id',
        clientVerifyingShareB64u: 'mock-client-share',
      };

      function useTatchiHook() {
        return {
          loginState: {
            isLoggedIn: true,
            nearAccountId: 'alice.testnet',
          },
          tatchi: {
            getLoginSession: async () => ({
              signingSession: {
                sessionId: 'session-1',
                status: 'active',
                remainingUses: 3,
                expiresAtMs: Date.now() + 60_000,
                createdAtMs: Date.now(),
              },
            }),
            loginAndCreateSession: async () => ({ success: true }),
            signTransactionsWithActions: async () => {
              counters.nearSigns += 1;
              return [
                {
                  signedTransaction: {
                    borsh_bytes: [1, 2, 3, 4],
                  },
                },
              ];
            },
            signTempoWithThresholdEcdsa: async ({
              request,
            }: {
              request: { kind: 'tempoTransaction' | 'eip1559' };
            }) => {
              if (request.kind === 'tempoTransaction') {
                counters.tempoSigns += 1;
                return {
                  kind: 'tempoTransaction',
                  senderHashHex: `0x${'ab'.repeat(32)}`,
                  rawTxHex: `0x${'12'.repeat(32)}`,
                };
              }

              counters.evmSigns += 1;
              return {
                kind: 'eip1559',
                txHashHex: `0x${'cd'.repeat(32)}`,
                rawTxHex: `0x${'34'.repeat(32)}`,
              };
            },
            executeAction: async () => ({ success: true }),
            signDelegateAction: async () => ({
              hash: 'mock-hash',
              signedDelegate: {},
            }),
            sendDelegateActionViaRelayer: async () => ({
              ok: true,
              relayerTxHash: 'mock-relayer-tx',
            }),
            configs: { relayer: { url: 'https://relay.example' } },
          },
        };
      }

      function useSetGreetingHook() {
        return {
          onchainGreeting: 'hello',
          isLoading: false,
          fetchGreeting: async () => undefined,
          error: null,
        };
      }

      const mount = document.createElement('div');
      mount.id = 'demo-page-test-mount';
      document.body.appendChild(mount);

      const root = ReactDOMClientRuntime.createRoot(mount);
      ReactDOMRuntime.flushSync(() => {
        root.render(
          ReactRuntime.createElement(DemoPage, {
            __testOverrides: {
              useTatchiHook,
              useSetGreetingHook,
              readCachedThresholdKeyRef: () => keyRef as any,
              resolveThresholdKeyRef: async () => keyRef as any,
              provisionTempoAndEvmThresholdSigners: async () => ({
                evm: { thresholdEcdsaKeyRef: keyRef as any },
                tempo: { thresholdEcdsaKeyRef: keyRef as any },
              }),
            },
          }),
        );
      });
    }, { paths: IMPORT_PATHS });

    const scope = page.locator('#demo-page-test-mount');
    const nearButton = scope.getByRole('button', { name: 'Sign NEAR Threshold Transaction' });
    const tempoButton = scope.getByRole('button', { name: 'Sign Tempo Threshold Transaction' });
    const evmButton = scope.getByRole('button', { name: 'Sign EVM Threshold EIP-1559 Transaction' });

    await expect(nearButton).toBeVisible();
    await expect(tempoButton).toBeVisible();
    await expect(evmButton).toBeVisible();

    await nearButton.evaluate((el: HTMLElement) => el.click());
    await tempoButton.evaluate((el: HTMLElement) => el.click());
    await evmButton.evaluate((el: HTMLElement) => el.click());

    await page.waitForFunction(() => {
      const counters = (window as any).__docsSigningSmokeCounters;
      return (
        counters &&
        counters.nearSigns === 1 &&
        counters.tempoSigns === 1 &&
        counters.evmSigns === 1
      );
    });

    const counters = await page.evaluate(() => (window as any).__docsSigningSmokeCounters);
    expect(counters).toEqual({
      nearSigns: 1,
      tempoSigns: 1,
      evmSigns: 1,
    });
  });
});
