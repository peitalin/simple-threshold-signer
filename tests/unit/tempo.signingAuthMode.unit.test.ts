import { expect, test } from '@playwright/test';

const IMPORT_PATHS = {
  signTempoWithSecureConfirm:
    '/sdk/esm/core/signing/chainAdaptors/tempo/handlers/signTempoWithSecureConfirm.js',
} as const;

test.describe('tempo signing auth-mode resolution', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('throws early when threshold warm session cache is unavailable', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { signTempoWithSecureConfirm } = await import(paths.signTempoWithSecureConfirm);
      let confirmCalls = 0;

      const workerCtx = {
        requestWorkerOperation: async ({ request }: { request: any }) => {
          const type = String(request?.type || '');
          if (type === 'computeEip1559TxHash') return new Uint8Array(32).buffer;
          if (type === 'encodeEip1559SignedTxFromSignature65')
            return new Uint8Array([0x02, 0xaa]).buffer;
          throw new Error(`Unexpected worker operation: ${type}`);
        },
      };

      try {
        await signTempoWithSecureConfirm({
          ctx: { indexedDB: {} } as any,
          workerCtx: workerCtx as any,
          secureConfirmWorkerManager: {
            peekPrfFirstForThresholdSession: async () => ({
              ok: false,
              code: 'expired',
              message: 'expired',
            }),
            confirmAndPrepareSigningSession: async () => {
              confirmCalls += 1;
              return {
                sessionId: 'intent',
                intentDigest: '0x' + '11'.repeat(32),
              };
            },
          } as any,
          nearAccountId: 'alice.testnet',
          request: {
            chain: 'tempo',
            kind: 'eip1559',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId: 11155111n,
              nonce: 7n,
              maxPriorityFeePerGas: 1_500_000_000n,
              maxFeePerGas: 3_000_000_000n,
              gasLimit: 21_000n,
              to: '0x' + '22'.repeat(20),
              value: 12_345n,
              data: '0x',
              accessList: [],
            },
          } as any,
          engines: {
            secp256k1: {
              algorithm: 'secp256k1',
              sign: async () => {
                const sig = new Uint8Array(65);
                sig[64] = 0;
                return sig;
              },
            },
          } as any,
          keyRefsByAlgorithm: {
            secp256k1: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relayer.example',
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              thresholdSessionId: 'session-1',
            },
          } as any,
        });
        return { ok: true, confirmCalls };
      } catch (error: any) {
        return {
          ok: false,
          confirmCalls,
          message: String(error?.message || error),
        };
      }
    }, { paths: IMPORT_PATHS });

    expect(result.ok).toBe(false);
    expect(result.confirmCalls).toBe(0);
    expect(String(result.message || '')).toContain('threshold session expired');
  });

  test('uses warmSession mode when threshold warm cache is available', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { signTempoWithSecureConfirm } = await import(paths.signTempoWithSecureConfirm);
      let capturedAuthMode: string | null = null;

      const workerCtx = {
        requestWorkerOperation: async ({ request }: { request: any }) => {
          const type = String(request?.type || '');
          if (type === 'computeEip1559TxHash') return new Uint8Array(32).buffer;
          if (type === 'encodeEip1559SignedTxFromSignature65')
            return new Uint8Array([0x02, 0xaa]).buffer;
          throw new Error(`Unexpected worker operation: ${type}`);
        },
      };

      const signed = await signTempoWithSecureConfirm({
        ctx: { indexedDB: {} } as any,
        workerCtx: workerCtx as any,
        secureConfirmWorkerManager: {
          peekPrfFirstForThresholdSession: async () => ({
            ok: true,
            remainingUses: 2,
            expiresAtMs: Date.now() + 10_000,
          }),
          confirmAndPrepareSigningSession: async (params: any) => {
            capturedAuthMode = String(params?.signingAuthMode || '');
            return {
              sessionId: 'intent',
              intentDigest: String(params?.intentDigest || ''),
            };
          },
        } as any,
        nearAccountId: 'alice.testnet',
        request: {
          chain: 'tempo',
          kind: 'eip1559',
          senderSignatureAlgorithm: 'secp256k1',
          tx: {
            chainId: 11155111n,
            nonce: 7n,
            maxPriorityFeePerGas: 1_500_000_000n,
            maxFeePerGas: 3_000_000_000n,
            gasLimit: 21_000n,
            to: '0x' + '22'.repeat(20),
            value: 12_345n,
            data: '0x',
            accessList: [],
          },
        } as any,
        engines: {
          secp256k1: {
            algorithm: 'secp256k1',
            sign: async () => {
              const sig = new Uint8Array(65);
              sig[64] = 0;
              return sig;
            },
          },
        } as any,
        keyRefsByAlgorithm: {
          secp256k1: {
            type: 'threshold-ecdsa-secp256k1',
            userId: 'alice.testnet',
            relayerUrl: 'https://relayer.example',
            relayerKeyId: 'rk-1',
            clientVerifyingShareB64u: 'AQ',
            thresholdSessionId: 'session-1',
          },
        } as any,
      });

      return {
        capturedAuthMode,
        kind: signed.kind,
        chain: signed.chain,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.capturedAuthMode).toBe('warmSession');
    expect(result.chain).toBe('tempo');
    expect(result.kind).toBe('eip1559');
  });
});
