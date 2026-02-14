import { test, expect } from '@playwright/test';

test.describe('signer worker contract version guards', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/', { waitUntil: 'domcontentloaded' });
  });

  test('resolves undefined request version to the current contract version', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const mod = await import('/sdk/esm/core/signing/workers/signerWorkerManager/backends/types.js');
      return mod.resolveSignerWorkerContractVersion(undefined);
    });

    expect(result).toBe(1);
  });

  test('rejects unsupported version before dispatching a multichain request', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const { getMultichainSignerWorkerTransport } = await import(
        '/sdk/esm/core/signing/workers/signerWorkerManager/backends/multichainWorkerBackend.js'
      );
      const unsupportedVersion = 999;

      try {
        const transport = getMultichainSignerWorkerTransport('tempoSigner');
        await transport.requestOperation({
          version: unsupportedVersion,
          type: 'computeTempoSenderHash',
          payload: { tx: {} },
        } as any);
        return { ok: true as const };
      } catch (error: any) {
        return { ok: false as const, message: error?.message || String(error) };
      }
    });

    expect(result.ok).toBe(false);
    expect((result as any).message).toContain('unsupported contract version');
  });
});
