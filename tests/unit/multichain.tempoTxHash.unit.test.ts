import { test, expect } from '@playwright/test';

const IMPORT_PATHS = {
  tempoSignerWasm: '/sdk/esm/core/signing/multichain/tempo/tempoSignerWasm.js',
} as const;

test.describe('TempoTransaction sender hash', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('omits feeToken when fee payer is present (placeholder mode)', async ({ page }) => {
    const res = await page.evaluate(async ({ paths }) => {
      const { computeTempoSenderHashWasm } = await import(paths.tempoSignerWasm);
      const hex = (bytes: Uint8Array) =>
        `0x${Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')}`;

      const mkTx = (feeToken: string) => ({
        chainId: 42431n,
        maxPriorityFeePerGas: 1n,
        maxFeePerGas: 2n,
        gasLimit: 21_000n,
        calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x' }],
        accessList: [],
        nonceKey: 0n,
        nonce: 1n,
        validBefore: null,
        validAfter: null,
        feeToken,
        feePayerSignature: { kind: 'placeholder' as const },
        aaAuthorizationList: [],
      });

      const h1 = await computeTempoSenderHashWasm(mkTx('0x' + 'aa'.repeat(20)));
      const h2 = await computeTempoSenderHashWasm(mkTx('0x' + 'bb'.repeat(20)));

      return { h1: hex(h1), h2: hex(h2) };
    }, { paths: IMPORT_PATHS });

    expect(res.h1).toBe(res.h2);
  });

  test('includes feeToken when no fee payer is present', async ({ page }) => {
    const res = await page.evaluate(async ({ paths }) => {
      const { computeTempoSenderHashWasm } = await import(paths.tempoSignerWasm);
      const hex = (bytes: Uint8Array) =>
        `0x${Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')}`;

      const mkTx = (feeToken: string) => ({
        chainId: 42431n,
        maxPriorityFeePerGas: 1n,
        maxFeePerGas: 2n,
        gasLimit: 21_000n,
        calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x' }],
        accessList: [],
        nonceKey: 0n,
        nonce: 1n,
        validBefore: null,
        validAfter: null,
        feeToken,
        feePayerSignature: { kind: 'none' as const },
        aaAuthorizationList: [],
      });

      const h1 = await computeTempoSenderHashWasm(mkTx('0x' + 'aa'.repeat(20)));
      const h2 = await computeTempoSenderHashWasm(mkTx('0x' + 'bb'.repeat(20)));

      return { h1: hex(h1), h2: hex(h2) };
    }, { paths: IMPORT_PATHS });

    expect(res.h1).not.toBe(res.h2);
  });
});
