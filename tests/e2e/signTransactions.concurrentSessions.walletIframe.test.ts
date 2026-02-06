import { test, expect } from '@playwright/test';
import { readFileSync } from 'fs';
import bs58 from 'bs58';
import { ed25519 } from '@noble/curves/ed25519.js';
import { setupBasicPasskeyTest, handleInfrastructureErrors } from '../setup';
import { autoConfirmWalletIframeUntil } from '../setup/flows';
import { DEFAULT_TEST_CONFIG } from '../setup/config';
import { installCreateAccountAndRegisterUserMock, installFastNearRpcMock } from './thresholdEd25519.testUtils';
import { initSync as initWasmSignerSync, threshold_ed25519_compute_near_tx_signing_digests } from '../../wasm/near_signer/pkg/wasm_signer_worker.js';

// Regression: concurrent signing requests must stay pinned to their requested device/account
// so PRF/session material and signer context never cross-talk between in-flight operations.
test.describe('Lite signer – concurrent sessions (wallet iframe)', () => {
  test('signing requests do not cross-talk', async ({ page }) => {
    await setupBasicPasskeyTest(page);
    await page.waitForTimeout(300);

    const keysOnChain = new Set<string>();
    const nonceByPublicKey = new Map<string, number>();
    const accountsOnChain = new Set<string>();

    const relayerUrl = DEFAULT_TEST_CONFIG.relayer?.url ?? 'https://relay-server.localhost';

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
        const account1 = `e2econ1${suffix}.w3a-v1.testnet`;
        const account2 = `e2econ2${suffix}.w3a-v1.testnet`;

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

        const confirmConfig = { uiMode: 'none', behavior: 'skipClick', autoProceedDelay: 0 } as const;

        const reg1 = await tatchi.registerPasskeyInternal(
          account1,
          { signerMode: { mode: 'local-signer' } },
          confirmConfig as any
        );
        if (!reg1?.success) {
          return { ok: false as const, error: reg1?.error || 'registration (1) failed' };
        }

        const reg2 = await tatchi.registerPasskeyInternal(
          account2,
          { signerMode: { mode: 'local-signer' } },
          confirmConfig as any
        );
        if (!reg2?.success) {
          return { ok: false as const, error: reg2?.error || 'registration (2) failed' };
        }

        const login1 = await tatchi.loginAndCreateSession(account1);
        if (!login1?.success) {
          return { ok: false as const, error: login1?.error || 'login (1) failed' };
        }

        const login2 = await tatchi.loginAndCreateSession(account2);
        if (!login2?.success) {
          return { ok: false as const, error: login2?.error || 'login (2) failed' };
        }

        const receiver = receiverId || 'w3a-v1.testnet';
        const alternateReceiver = receiver === 'w3a-v1.testnet' ? 'alt.w3a-v1.testnet' : 'w3a-v1.testnet';
        const action = { type: ActionType.Transfer, amount: '1' };
        const wasmActions = [toActionArgsWasm(action)];
        const toNumberArray = (value: unknown): number[] => Array.from(value as ArrayLike<number>);

        const signOnce = async (accountId: string, receiverId: string) => {
          const signed = await tatchi.signTransactionsWithActions({
            nearAccountId: accountId,
            transactions: [{ receiverId, actions: [action] }],
            options: {
              signerMode: { mode: 'local-signer' },
              deviceNumber: 1,
              confirmationConfig: confirmConfig as any,
            },
          });

          if (!Array.isArray(signed) || signed.length !== 1) {
            throw new Error(
              `expected 1 signed tx for ${accountId}, got ${Array.isArray(signed) ? signed.length : 'non-array'}`
            );
          }

          const signedTx: any = signed[0]?.signedTransaction;
          const signatureData = signedTx?.signature?.signatureData;
          const borshBytes = signedTx?.borsh_bytes ?? signedTx?.borshBytes;
          if (!signedTx || !signatureData || !borshBytes) {
            throw new Error(`invalid signed transaction shape for ${receiverId}`);
          }

          return {
            signerId: String(signedTx?.transaction?.signerId || ''),
            receiverId: String(signedTx?.transaction?.receiverId || ''),
            signature: toNumberArray(signatureData),
            borshBytes: toNumberArray(borshBytes),
            nonce: typeof signedTx?.transaction?.nonce === 'bigint'
              ? signedTx.transaction.nonce.toString()
              : String(signedTx?.transaction?.nonce || ''),
            blockHash: toNumberArray(signedTx?.transaction?.blockHash ?? []),
          };
        };

        const [signed1, signed2] = await Promise.all([
          signOnce(account1, receiver),
          signOnce(account2, alternateReceiver),
        ]);

        return {
          ok: true as const,
          account1: { id: account1, publicKey: String(reg1.clientNearPublicKey || '') },
          account2: { id: account2, publicKey: String(reg2.clientNearPublicKey || '') },
          receiver,
          alternateReceiver,
          wasmActions,
          signed1,
          signed2,
        };
      } catch (e: any) {
        return { ok: false as const, error: e?.message || String(e) };
      }
    }, {
      walletOrigin: 'https://wallet.example.localhost',
      relayerUrl,
      receiverId: receiverIdFromConfig(),
    });

    const result = await autoConfirmWalletIframeUntil(page, resultPromise, { timeoutMs: 75_000, intervalMs: 250 });
    if (!result.ok) {
      if (handleInfrastructureErrors(result as any)) return;
      expect(result.ok, (result as any)?.error || 'concurrent signing failed').toBe(true);
      return;
    }

    const wasmBytes = readFileSync(new URL('../../wasm/near_signer/pkg/wasm_signer_worker_bg.wasm', import.meta.url));
    initWasmSignerSync({ module: wasmBytes });

    const toPkBytes = (pk: string): Uint8Array => {
      const raw = pk.includes(':') ? pk.split(':')[1] : pk;
      return bs58.decode(raw);
    };

    const computeDigest = (signed: {
      receiverId: string;
      nonce: string;
      blockHash: number[];
    }, account: { id: string; publicKey: string }): Uint8Array => {
      const signingPayload = {
        txSigningRequests: [{
          nearAccountId: account.id,
          receiverId: signed.receiverId,
          actions: result.wasmActions,
        }],
        transactionContext: {
          nearPublicKeyStr: account.publicKey,
          nextNonce: signed.nonce,
          txBlockHash: bs58.encode(Uint8Array.from(signed.blockHash)),
        },
      };

      const digestsUnknown: unknown = threshold_ed25519_compute_near_tx_signing_digests(signingPayload);
      if (!Array.isArray(digestsUnknown) || !digestsUnknown.length) {
        throw new Error('Expected a non-empty signing digests array');
      }
      const digest0 = digestsUnknown[0];
      if (!(digest0 instanceof Uint8Array) || digest0.length !== 32) {
        throw new Error('Expected digest[0] to be a 32-byte Uint8Array');
      }
      return digest0;
    };

    const verifySignature = (signed: {
      signature: number[];
      receiverId: string;
      nonce: string;
      blockHash: number[];
    }, account: { id: string; publicKey: string }): boolean => {
      const sigBytes = Uint8Array.from(signed.signature);
      const digest = computeDigest(signed, account);
      return ed25519.verify(sigBytes, digest, toPkBytes(account.publicKey));
    };

    expect(result.account1.publicKey).toBeTruthy();
    expect(result.account2.publicKey).toBeTruthy();
    expect(result.signed1.signerId).toBe(result.account1.id);
    expect(result.signed2.signerId).toBe(result.account2.id);
    expect(result.signed1.receiverId).toBe(result.receiver);
    expect(result.signed2.receiverId).toBe(result.alternateReceiver);
    expect(result.signed1.borshBytes).not.toEqual(result.signed2.borshBytes);

    expect(verifySignature(result.signed1, result.account1)).toBe(true);
    expect(verifySignature(result.signed1, result.account2)).toBe(false);
    expect(verifySignature(result.signed2, result.account2)).toBe(true);
    expect(verifySignature(result.signed2, result.account1)).toBe(false);
  });
});

function receiverIdFromConfig(): string {
  return DEFAULT_TEST_CONFIG.testReceiverAccountId || 'w3a-v1.testnet';
}
