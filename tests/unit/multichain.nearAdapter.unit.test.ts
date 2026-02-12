import { test, expect } from '@playwright/test';

const IMPORT_PATHS = {
  nearAdapter:
    '/sdk/esm/core/signing/chainAdaptors/near/nearAdapter.js',
  actions: '/sdk/esm/core/types/actions.js',
} as const;

test.describe('NearAdapter', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('normalizes transactions into txSigningRequests', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { NearAdapter } = await import(paths.nearAdapter);
        const { ActionType } = await import(paths.actions);

        const adapter = new NearAdapter();
        const intent = await adapter.buildIntent({
          chain: 'near',
          kind: 'transactionsWithActions',
          nearAccountId: 'alice.near',
          transactions: [
            {
              receiverId: '  bob.near  ',
              actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
            },
          ],
        });

        return {
          chain: intent.chain,
          signRequests: intent.signRequests.length,
          uiModel: intent.uiModel,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.chain).toBe('near');
    expect(result.signRequests).toBe(0);
    expect(result.uiModel.kind).toBe('transactionsWithActions');
    expect(result.uiModel.nearAccountId).toBe('alice.near');
    expect(result.uiModel.transactionCount).toBe(1);
    expect(result.uiModel.totalActionCount).toBe(1);
    expect(result.uiModel.txSigningRequests).toEqual([
      {
        nearAccountId: 'alice.near',
        receiverId: 'bob.near',
        actions: [{ action_type: 'Transfer', deposit: '1' }],
      },
    ]);
  });

  test('rejects empty actions', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        try {
          const { NearAdapter } = await import(paths.nearAdapter);
          const adapter = new NearAdapter();
          await adapter.buildIntent({
            chain: 'near',
            kind: 'transactionsWithActions',
            nearAccountId: 'alice.near',
            transactions: [{ receiverId: 'bob.near', actions: [] }],
          });
          return { ok: true };
        } catch (error: any) {
          return { ok: false, message: error?.message || String(error) };
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.ok).toBe(false);
    expect(result.message).toContain('actions must be non-empty');
  });
});
