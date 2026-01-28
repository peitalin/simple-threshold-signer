import { test, expect } from '@playwright/test';
import { handleInfrastructureErrors } from '../setup';

const IMPORT_PATHS = {
  nonceManager: '/sdk/esm/core/nonceManager.js',
  nearAdapter: '/sdk/esm/core/WebAuthnManager/SecureConfirmWorkerManager/confirmTxFlow/adapters/near.js',
} as const;

test.describe('confirmTxFlow near adapter – concurrency', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('fetchNearContext returns an isolated transactionContext per call', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      try {
        // @ts-ignore runtime import
        const nonceManager = (await import(paths.nonceManager)).default;
        // @ts-ignore runtime import
        const nearAdapter = await import(paths.nearAdapter);

        nonceManager.clear();
        nonceManager.initializeUser('test-account', 'ed25519:test-public-key');

        // Seed a fresh cached context so fetchNearContext doesn't need RPC calls.
        (nonceManager as any).transactionContext = {
          nearPublicKeyStr: 'ed25519:test-public-key',
          accessKeyInfo: { nonce: 10 },
          nextNonce: '11',
          txBlockHeight: '1000',
          txBlockHash: '11111111111111111111111111111111',
        };
        (nonceManager as any).lastNonceUpdate = Date.now();
        (nonceManager as any).lastBlockHeightUpdate = Date.now();

        const ctx = { nonceManager, nearClient: {} } as any;

        // Run two reservations "concurrently" to mimic rapid-fire signing requests.
        const [r1, r2] = await Promise.all([
          nearAdapter.fetchNearContext(ctx, { nearAccountId: 'test-account', txCount: 1, reserveNonces: true }),
          nearAdapter.fetchNearContext(ctx, { nearAccountId: 'test-account', txCount: 1, reserveNonces: true }),
        ]);

        return {
          ok: true as const,
          sameObject: r1.transactionContext === r2.transactionContext,
          nonce1: r1.transactionContext?.nextNonce ?? null,
          nonce2: r2.transactionContext?.nextNonce ?? null,
          reserved: Array.from((nonceManager as any).reservedNonces || []),
        };
      } catch (e: any) {
        return { ok: false as const, error: e?.message || String(e) };
      }
    }, { paths: IMPORT_PATHS });

    if (!result.ok) {
      if (handleInfrastructureErrors(result as any)) return;
      expect(result.ok, (result as any).error || 'near adapter test failed').toBe(true);
      return;
    }

    expect(result.sameObject).toBe(false);
    expect(result.nonce1).not.toBeNull();
    expect(result.nonce2).not.toBeNull();
    expect(result.nonce1).not.toBe(result.nonce2);
  });
});

