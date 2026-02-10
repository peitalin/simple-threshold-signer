import { test, expect } from '@playwright/test';
import { readFileSync } from 'fs';
import bs58 from 'bs58';
import { ed25519 } from '@noble/curves/ed25519.js';
import { setupBasicPasskeyTest, handleInfrastructureErrors } from '../setup';
import { autoConfirmWalletIframeUntil } from '../setup/flows';
import { DEFAULT_TEST_CONFIG } from '../setup/config';
import { installCreateAccountAndRegisterUserMock, installFastNearRpcMock } from './thresholdEd25519.testUtils';
import { initSync as initWasmSignerSync, threshold_ed25519_compute_near_tx_signing_digests } from '../../wasm/near_signer/pkg/wasm_signer_worker.js';

test.describe('Lite signer – NEAR multichain seam normalization (wallet iframe)', () => {
  test('normalizes receiverId before signer-worker signing', async ({ page }) => {
    await setupBasicPasskeyTest(page);
    await page.waitForTimeout(300);

    const keysOnChain = new Set<string>();
    const nonceByPublicKey = new Map<string, number>();
    const accountsOnChain = new Set<string>();
    const relayerUrl = DEFAULT_TEST_CONFIG.relayer?.url ?? 'https://relay-server.localhost';
    const expectedReceiverId = receiverIdFromConfig();
    accountsOnChain.add(expectedReceiverId);

    await installCreateAccountAndRegisterUserMock(page, {
      relayerBaseUrl: relayerUrl,
      accountsOnChain,
      onNewPublicKey: (pk) => {
        keysOnChain.add(pk);
        nonceByPublicKey.set(pk, 0);
      },
      onNewAccountId: (accountId) => {
        accountsOnChain.add(accountId);
      },
    });

    await installFastNearRpcMock(page, {
      keysOnChain,
      nonceByPublicKey,
      accountsOnChain,
      strictAccessKeyLookup: true,
    });

    const resultPromise = page.evaluate(async ({ walletOrigin, relayerUrl, receiverId }) => {
      try {
        const { TatchiPasskey } = await import('/sdk/esm/core/TatchiPasskey/index.js');
        const { ActionType, toActionArgsWasm } = await import('/sdk/esm/core/types/actions.js');

        const suffix =
          (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function')
            ? crypto.randomUUID()
            : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
        const accountId = `e2enearnorm${suffix}.w3a-v1.testnet`;

        const tatchi = new TatchiPasskey({
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          contractId: 'w3a-v1.testnet',
          relayer: { url: relayerUrl },
          iframeWallet: {
            walletOrigin,
            servicePath: '/wallet-service',
            sdkBasePath: '/sdk',
            rpIdOverride: 'example.localhost',
          },
        });

        const confirmationConfig = { uiMode: 'none', behavior: 'skipClick', autoProceedDelay: 0 } as const;
        const registration = await tatchi.registerPasskeyInternal(
          accountId,
          { signerMode: { mode: 'local-signer' } },
          confirmationConfig as any,
        );
        if (!registration?.success) {
          return { ok: false as const, error: registration?.error || 'registration failed' };
        }

        const login = await tatchi.loginAndCreateSession(accountId);
        if (!login?.success) {
          return { ok: false as const, error: login?.error || 'login failed' };
        }

        const rawReceiverId = `  ${receiverId}  `;
        const transferAction = { type: ActionType.Transfer, amount: '1' };
        const signed = await tatchi.signTransactionsWithActions({
          nearAccountId: accountId,
          transactions: [{ receiverId: rawReceiverId, actions: [transferAction] }],
          options: {
            signerMode: { mode: 'local-signer' },
            deviceNumber: 1,
            confirmationConfig: confirmationConfig as any,
          },
        });

        if (!Array.isArray(signed) || signed.length !== 1) {
          return {
            ok: false as const,
            error: `expected 1 signed tx, got ${Array.isArray(signed) ? signed.length : 'non-array'}`,
          };
        }

        const signedTx: any = signed[0]?.signedTransaction;
        const signatureData = signedTx?.signature?.signatureData;
        const tx = signedTx?.transaction;
        if (!tx || !signatureData) {
          return { ok: false as const, error: 'invalid signed transaction shape' };
        }

        return {
          ok: true as const,
          account: {
            id: accountId,
            publicKey: String(registration.clientNearPublicKey || ''),
          },
          rawReceiverId,
          normalizedReceiverId: rawReceiverId.trim(),
          wasmActions: [toActionArgsWasm(transferAction)],
          signed: {
            signerId: String(tx?.signerId || ''),
            receiverId: String(tx?.receiverId || ''),
            nonce: typeof tx?.nonce === 'bigint' ? tx.nonce.toString() : String(tx?.nonce || ''),
            blockHash: Array.from((tx?.blockHash ?? []) as ArrayLike<number>),
            signature: Array.from(signatureData as ArrayLike<number>),
          },
        };
      } catch (error: any) {
        return { ok: false as const, error: error?.message || String(error) };
      }
    }, {
      walletOrigin: 'https://wallet.example.localhost',
      relayerUrl,
      receiverId: expectedReceiverId,
    });

    const result = await autoConfirmWalletIframeUntil(page, resultPromise, { timeoutMs: 75_000, intervalMs: 250 });
    if (!result.ok) {
      if (handleInfrastructureErrors(result as any)) return;
      expect(result.ok, (result as any)?.error || 'NEAR seam normalization flow failed').toBe(true);
      return;
    }

    const wasmBytes = readFileSync(new URL('../../wasm/near_signer/pkg/wasm_signer_worker_bg.wasm', import.meta.url));
    initWasmSignerSync({ module: wasmBytes });

    const toPkBytes = (pk: string): Uint8Array => {
      const raw = pk.includes(':') ? pk.split(':')[1] : pk;
      return bs58.decode(raw);
    };

    const verifySignatureForReceiver = (receiverId: string): boolean => {
      try {
        const signingPayload = {
          txSigningRequests: [{
            nearAccountId: result.account.id,
            receiverId,
            actions: result.wasmActions,
          }],
          transactionContext: {
            nearPublicKeyStr: result.account.publicKey,
            nextNonce: result.signed.nonce,
            txBlockHash: bs58.encode(Uint8Array.from(result.signed.blockHash)),
          },
        };
        const digestsUnknown: unknown = threshold_ed25519_compute_near_tx_signing_digests(signingPayload);
        if (!Array.isArray(digestsUnknown) || !digestsUnknown.length) return false;
        const digest0 = digestsUnknown[0];
        if (!(digest0 instanceof Uint8Array) || digest0.length !== 32) return false;
        return ed25519.verify(Uint8Array.from(result.signed.signature), digest0, toPkBytes(result.account.publicKey));
      } catch {
        return false;
      }
    };

    expect(result.rawReceiverId).not.toBe(result.normalizedReceiverId);
    expect(result.signed.signerId).toBe(result.account.id);
    expect(result.signed.receiverId).toBe(result.normalizedReceiverId);
    expect(result.signed.receiverId).toBe(expectedReceiverId);
    expect(verifySignatureForReceiver(result.normalizedReceiverId)).toBe(true);
  });
});

function receiverIdFromConfig(): string {
  return DEFAULT_TEST_CONFIG.testReceiverAccountId || 'w3a-v1.testnet';
}
