import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

const IMPORT_PATHS = {
  executeSigningIntent: '/sdk/esm/core/signing/orchestration/executeSigningIntent.js',
  nearAdapter: '/sdk/esm/core/signing/chainAdaptors/near/nearAdapter.js',
  tempoAdapter: '/sdk/esm/core/signing/chainAdaptors/tempo/tempoAdapter.js',
  actions: '/sdk/esm/core/types/actions.js',
} as const;

test.describe('unified signing pipeline', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('NEAR/EVM/Tempo intent flows traverse the same sign runner steps', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { executeSigningIntent } = await import(paths.executeSigningIntent);
      const { NearAdapter } = await import(paths.nearAdapter);
      const { TempoAdapter } = await import(paths.tempoAdapter);
      const { ActionType } = await import(paths.actions);

      const pipeline = {
        near: [] as string[],
        evm: [] as string[],
        tempo: [] as string[],
      };
      const workerOps: string[] = [];

      const workerCtx = {
        requestWorkerOperation: async ({ kind, request }: { kind: string; request: any }) => {
          const op = `${kind}:${String(request?.type || '')}`;
          workerOps.push(op);

          switch (String(request?.type || '')) {
            case 'computeEip1559TxHash':
            case 'computeTempoSenderHash':
              return new Uint8Array(32).buffer;
            case 'encodeEip1559SignedTx':
              return new Uint8Array([0x02, 0xaa, 0xbb]).buffer;
            case 'encodeTempoSignedTx':
              return new Uint8Array([0x76, 0xaa, 0xbb]).buffer;
            default:
              throw new Error(`Unexpected worker operation: ${op}`);
          }
        },
      };

      const makeResolve = (label: 'near' | 'evm' | 'tempo', keyRef: any) => async (signReq: any) => {
        pipeline[label].push('resolve');
        return { signReq, keyRef };
      };
      const runIntent = async (args: {
        adapter: any;
        request: any;
        engines: Record<string, any>;
        resolveSignInput: (signReq: any) => Promise<{ signReq: any; keyRef: any }>;
      }) => {
        const intent = await args.adapter.buildIntent(args.request);
        return await executeSigningIntent({
          intent,
          engines: args.engines,
          resolveSignInput: args.resolveSignInput,
        });
      };

      const nearEngine: any = {
        algorithm: 'ed25519',
        sign: async (signReq: any) => {
          pipeline.near.push('engine');
          return { kind: signReq.kind, result: { path: 'near' } };
        },
      };

      const makeSecpEngine = (label: 'evm' | 'tempo') => ({
        algorithm: 'secp256k1',
        sign: async () => {
          pipeline[label].push('engine');
          const sig = new Uint8Array(65);
          sig[64] = 0;
          return sig;
        },
      });

      const nearResult = await runIntent({
        adapter: new NearAdapter(),
        request: {
          chain: 'near',
          kind: 'transactionsWithActions',
          payload: {
            rpcCall: {
              nearAccountId: 'alice.testnet',
              nearRpcUrl: 'https://rpc.testnet.near.org',
              contractId: 'web3-authn-v4.testnet',
            },
            transactions: [
              {
                receiverId: 'bob.testnet',
                actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
              },
            ],
            signerMode: 'threshold-signer',
          },
        },
        engines: { ed25519: nearEngine },
        resolveSignInput: makeResolve('near', { type: 'near-ed25519-runtime' }),
      });

      const evmResult = await runIntent({
        adapter: new TempoAdapter(workerCtx as any),
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
        },
        engines: { secp256k1: makeSecpEngine('evm') as any },
        resolveSignInput: makeResolve('evm', {
          type: 'local-secp256k1',
          privateKey: new Uint8Array(32),
        }),
      });

      const tempoResult = await runIntent({
        adapter: new TempoAdapter(workerCtx as any),
        request: {
          chain: 'tempo',
          kind: 'tempoTransaction',
          senderSignatureAlgorithm: 'secp256k1',
          tx: {
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
            feePayerSignature: { kind: 'none' as const },
            aaAuthorizationList: [],
          },
        },
        engines: { secp256k1: makeSecpEngine('tempo') as any },
        resolveSignInput: makeResolve('tempo', {
          type: 'local-secp256k1',
          privateKey: new Uint8Array(32),
        }),
      });

      return {
        pipeline,
        workerOps,
        nearResult,
        evmResult,
        tempoResult,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.pipeline.near).toEqual(['resolve', 'engine']);
    expect(result.pipeline.evm).toEqual(['resolve', 'engine']);
    expect(result.pipeline.tempo).toEqual(['resolve', 'engine']);

    expect(result.workerOps).toEqual([
      'ethSigner:computeEip1559TxHash',
      'ethSigner:encodeEip1559SignedTx',
      'tempoSigner:computeTempoSenderHash',
      'tempoSigner:encodeTempoSignedTx',
    ]);

    expect(result.nearResult?.path).toBe('near');
    expect(result.evmResult?.kind).toBe('eip1559');
    expect(result.tempoResult?.kind).toBe('tempoTransaction');
  });

  test('chain entrypoints stay wired to the unified intent runner', () => {
    const webAuthnManagerSource = fs.readFileSync(
      path.resolve(process.cwd(), '../client/src/core/signing/api/WebAuthnManager.ts'),
      'utf8',
    );
    const tempoHandlerSource = fs.readFileSync(
      path.resolve(
        process.cwd(),
        '../client/src/core/signing/chainAdaptors/tempo/handlers/signTempoWithSecureConfirm.ts',
      ),
      'utf8',
    );

    expect(webAuthnManagerSource).toContain("import('../orchestration/signWithIntent')");
    expect(tempoHandlerSource).toContain('executeSigningIntent({');
  });

  test('activation helpers stay internal-only and bootstrap-only', () => {
    const rootIndexSource = fs.readFileSync(
      path.resolve(process.cwd(), '../client/src/index.ts'),
      'utf8',
    );
    const webAuthnManagerSource = fs.readFileSync(
      path.resolve(process.cwd(), '../client/src/core/signing/api/WebAuthnManager.ts'),
      'utf8',
    );

    expect(rootIndexSource).not.toContain('orchestration/activation');
    expect(rootIndexSource).not.toContain('activateThresholdKeyForChain');
    expect(rootIndexSource).not.toContain('activateNearThresholdKeyNoPrompt');

    // Activation helper is used for bootstrap/enrollment only, not as a public API entrypoint.
    expect(webAuthnManagerSource).toContain('bootstrapThresholdEcdsaSessionLite');
    expect(webAuthnManagerSource).toContain("chain: 'near'");
    expect(webAuthnManagerSource).toContain('activateThresholdKeyForChain({');
  });
});
