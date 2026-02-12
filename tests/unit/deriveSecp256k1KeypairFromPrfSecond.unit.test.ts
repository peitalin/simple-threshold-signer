import { test, expect } from '@playwright/test';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes } from '@/core/signing/chainAdaptors/evm/bytes';

const IMPORT_PATHS = {
  ethSignerWasm:
    '/sdk/esm/core/signing/chainAdaptors/evm/ethSignerWasm.js',
  signerGateway:
    '/sdk/esm/core/signing/workers/signerWorkerManager/gateway.js',
} as const;

test.describe('deriveSecp256k1KeypairFromPrfSecondWasm', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('is deterministic and returns valid secp256k1 material', async ({ page }) => {
    const prfSecondB64u = Buffer.alloc(32, 7).toString('base64url');

    const result = await page.evaluate(async ({ paths, prfSecondB64u }) => {
      const { deriveSecp256k1KeypairFromPrfSecondWasm } = await import(paths.ethSignerWasm);
      const { requestMultichainWorkerOperation } = await import(paths.signerGateway);
      const workerCtx = {
        requestWorkerOperation: async ({ kind, request }: { kind: string; request: unknown }) =>
          await requestMultichainWorkerOperation({ kind: kind as any, request: request as any }),
      };

      const first = await deriveSecp256k1KeypairFromPrfSecondWasm({
        prfSecondB64u,
        nearAccountId: 'alice.testnet',
        workerCtx: workerCtx as any,
      });
      const second = await deriveSecp256k1KeypairFromPrfSecondWasm({
        prfSecondB64u,
        nearAccountId: 'alice.testnet',
        workerCtx: workerCtx as any,
      });
      const otherAccount = await deriveSecp256k1KeypairFromPrfSecondWasm({
        prfSecondB64u,
        nearAccountId: 'bob.testnet',
        workerCtx: workerCtx as any,
      });

      return { first, second, otherAccount };
    }, { paths: IMPORT_PATHS, prfSecondB64u });

    const { first, second, otherAccount } = result;

    expect(first).toEqual(second);
    expect(first.privateKeyHex).not.toBe(otherAccount.privateKeyHex);

    expect(first.privateKeyHex).toMatch(/^0x[0-9a-f]{64}$/);
    expect(first.publicKeyHex).toMatch(/^0x[0-9a-f]{66}$/);
    expect(first.ethereumAddress).toMatch(/^0x[0-9a-f]{40}$/);

    const expectedPub = bytesToHex(secp256k1.getPublicKey(hexToBytes(first.privateKeyHex), true));
    expect(first.publicKeyHex).toBe(expectedPub);
  });
});
