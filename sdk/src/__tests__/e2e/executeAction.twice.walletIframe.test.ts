import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, handleInfrastructureErrors } from '../setup';
import { autoConfirmWalletIframeUntil } from '../setup/flows';
import { DEFAULT_TEST_CONFIG } from '../setup/config';
import { installCreateAccountAndRegisterUserMock, installFastNearRpcMock } from './thresholdEd25519.testUtils';

test.describe('Lite signer – executeAction twice (wallet iframe)', () => {
  test('second transaction progresses past signing', async ({ page }) => {
    await setupBasicPasskeyTest(page);
    await page.waitForTimeout(300);

    const keysOnChain = new Set<string>();
    const nonceByPublicKey = new Map<string, number>();
    let localNearPublicKey = '';

    await installCreateAccountAndRegisterUserMock(page, {
      relayerBaseUrl: DEFAULT_TEST_CONFIG.relayer?.url ?? 'https://relay-server.localhost',
      onNewPublicKey: (pk) => {
        localNearPublicKey = pk;
        keysOnChain.add(pk);
        nonceByPublicKey.set(pk, 0);
      },
    });

    await installFastNearRpcMock(page, {
      keysOnChain,
      nonceByPublicKey,
      onSendTx: () => {
        if (localNearPublicKey) {
          nonceByPublicKey.set(localNearPublicKey, (nonceByPublicKey.get(localNearPublicKey) ?? 0) + 1);
        }
      },
      strictAccessKeyLookup: true,
    });

    const resultPromise = page.evaluate(async ({ walletOrigin, relayerUrl, receiverId }) => {
      try {
        const { TatchiPasskey } = await import('/sdk/esm/core/TatchiPasskey/index.js');
        const { ActionType } = await import('/sdk/esm/core/types/actions.js');

        const suffix =
          (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function')
            ? crypto.randomUUID()
            : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
        const accountId = `e2e2x${suffix}.w3a-v1.testnet`;

        const tatchi = new TatchiPasskey({
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          contractId: 'w3a-v1.testnet',
          relayer: { url: relayerUrl },
          // Ensure the wallet iframe path is exercised (bug repro target).
          iframeWallet: {
            walletOrigin,
            servicePath: '/wallet-service',
            sdkBasePath: '/sdk',
            rpIdOverride: 'example.localhost',
          },
        });

        const cfg = { uiMode: 'modal', behavior: 'requireClick', autoProceedDelay: 0 } as const;
        const reg = await tatchi.registerPasskeyInternal(accountId, { signerMode: { mode: 'local-signer' } }, cfg as any);
        if (!reg?.success) {
          return { ok: false as const, error: reg?.error || 'registration failed' };
        }

        const login = await tatchi.loginAndCreateSession(accountId);
        if (!login?.success) {
          return { ok: false as const, error: login?.error || 'login failed' };
        }

        const events: Array<{ call: number; phase: string; message: string; step: number; status: string }> = [];

        const runOnce = async (call: number) => {
          const result = await tatchi.executeAction({
            nearAccountId: accountId,
            receiverId,
            actionArgs: {
              type: ActionType.FunctionCall,
              methodName: 'set_greeting',
              args: { greeting: `hello-${call}-${Date.now()}` },
              gas: '30000000000000',
              deposit: '0',
            },
            options: {
              waitUntil: 'EXECUTED_OPTIMISTIC' as any,
              onEvent: (ev: any) => {
                events.push({
                  call,
                  phase: String(ev?.phase || ''),
                  message: String(ev?.message || ''),
                  step: Number(ev?.step || 0),
                  status: String(ev?.status || ''),
                });
              },
            },
          });
          return result;
        };

        const r1 = await runOnce(1);
        const r2 = await runOnce(2);

        const phasesFor = (call: number) => events.filter((e) => e.call === call).map((e) => e.phase);

        return {
          ok: true as const,
          accountId,
          result1: r1,
          result2: r2,
          phases1: phasesFor(1),
          phases2: phasesFor(2),
          lastMessage2: (events.filter((e) => e.call === 2).slice(-1)[0]?.message) || null,
        };
      } catch (e: any) {
        return { ok: false as const, error: e?.message || String(e) };
      }
    }, {
      walletOrigin: 'https://wallet.example.localhost',
      relayerUrl: DEFAULT_TEST_CONFIG.relayer?.url ?? 'https://relay-server.localhost',
      receiverId: receiverIdFromConfig(),
    });

    const result = await autoConfirmWalletIframeUntil(page, resultPromise, { timeoutMs: 75_000, intervalMs: 250 });
    if (!result.ok) {
      if (handleInfrastructureErrors(result as any)) return;
      expect(result.ok, (result as any)?.error || 'executeAction twice failed').toBe(true);
      return;
    }

    expect(result.result1?.success, JSON.stringify(result.result1 || null)).toBe(true);
    expect(result.result2?.success, JSON.stringify(result.result2 || null)).toBe(true);

    expect(result.phases1).toContain('broadcasting');
    expect(result.phases1).toContain('action-complete');

    // Regression target: second call must not stall after signing.
    expect(result.phases2).toContain('broadcasting');
    expect(result.phases2).toContain('action-complete');
  });
});

function receiverIdFromConfig(): string {
  return DEFAULT_TEST_CONFIG.testReceiverAccountId || 'w3a-v1.testnet';
}
