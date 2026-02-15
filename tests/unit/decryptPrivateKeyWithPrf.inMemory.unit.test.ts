import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

test.describe('decryptPrivateKeyWithPrf in-memory payload fallback', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('decrypts from explicit encrypted payload without requiring profile mapping lookup', async ({
    page,
  }) => {
    const result = await page.evaluate(async () => {
      const nearKeyOps = await import(
        '/sdk/esm/core/signing/workers/signerWorkerManager/nearKeyOps/decryptPrivateKeyWithPrf.js'
      );
      const signerTypes = await import('/sdk/esm/core/types/signer-worker.js');

      let localKeyReadCount = 0;
      let workerRequestPayload: any = null;

      const ctx: any = {
        indexedDB: {
          clientDB: {
            resolveNearAccountContext: async () => null,
          },
          getNearLocalKeyMaterialV2First: async () => {
            localKeyReadCount += 1;
            return null;
          },
        },
        requestWorkerOperation: async ({ request }: any) => {
          workerRequestPayload = request?.payload;
          return {
            type: signerTypes.WorkerResponseType.DecryptPrivateKeyWithPrfSuccess,
            payload: {
              privateKey: 'ed25519:dummy-private-key',
              nearAccountId: 'alice.testnet',
            },
          };
        },
      };

      const out = await nearKeyOps.decryptPrivateKeyWithPrf({
        ctx,
        nearAccountId: 'alice.testnet',
        authenticators: [],
        sessionId: 's-in-memory',
        prfFirstB64u: 'prf-first',
        wrapKeySalt: 'wrap-salt',
        encryptedPrivateKeyData: 'encrypted-sk',
        encryptedPrivateKeyChacha20NonceB64u: 'nonce',
      });

      return {
        nearAccountId: out.nearAccountId,
        privateKey: out.decryptedPrivateKey,
        localKeyReadCount,
        workerRequestPayload,
      };
    });

    expect(result.nearAccountId).toBe('alice.testnet');
    expect(result.privateKey).toBe('ed25519:dummy-private-key');
    expect(result.localKeyReadCount).toBe(0);
    expect(result.workerRequestPayload.encryptedPrivateKeyData).toBe('encrypted-sk');
    expect(result.workerRequestPayload.encryptedPrivateKeyChacha20NonceB64u).toBe('nonce');
    expect(result.workerRequestPayload.wrapKeySalt).toBe('wrap-salt');
  });
});
