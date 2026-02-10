import { test, expect } from '@playwright/test';

const IMPORT_PATHS = {
  nearWalletOrigin:
    '/sdk/esm/core/WebAuthnManager/SignerWorkerManager/MultichainAdapter/near/walletOrigin.js',
  actions: '/sdk/esm/core/types/actions.js',
} as const;

test.describe('near wallet-origin orchestration', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('normalizes request before delegating to signer worker manager', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { signNearWithSecureConfirm } = await import(paths.nearWalletOrigin);
        const { ActionType } = await import(paths.actions);

        const calls: any[] = [];
        const signerWorkerManager = {
          signTransactionsWithActions: async (payload: any) => {
            calls.push(payload);
            return [] as any[];
          },
        };

        await signNearWithSecureConfirm({
          signerWorkerManager,
          request: {
            chain: 'near',
            kind: 'transactionsWithActions',
            nearAccountId: 'alice.near',
            transactions: [
              {
                receiverId: '  bob.near ',
                actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
              },
            ],
          },
          rpcCall: {
            nearAccountId: 'alice.near',
            nearRpcUrl: 'https://rpc.testnet.near.org',
            contractId: 'w3a-v1.testnet',
          },
          signerMode: { mode: 'local-signer' },
          sessionId: 'session-1',
        });

        return calls[0];
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.rpcCall.nearAccountId).toBe('alice.near');
    expect(result.transactions).toEqual([
      {
        receiverId: 'bob.near',
        actions: [{ action_type: 'Transfer', deposit: '1' }],
      },
    ]);
  });
});
