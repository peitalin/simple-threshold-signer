import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

const IMPORT_PATHS = {
  nearAdapter:
    '/sdk/esm/core/signing/chainAdaptors/near/nearAdapter.js',
  tempoAdapter:
    '/sdk/esm/core/signing/chainAdaptors/tempo/tempoAdapter.js',
  signerGateway:
    '/sdk/esm/core/signing/workers/signerWorkerManager/gateway.js',
  actions: '/sdk/esm/core/types/actions.js',
} as const;

test.describe('modularity lazy signer loading', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('signing wiring stays dynamic-import based', async () => {
    const signerWorkerBridgeSource = fs.readFileSync(
      path.resolve(process.cwd(), '../client/src/core/signing/api/signerWorkerBridge.ts'),
      'utf8',
    );
    const tempoSigningSource = fs.readFileSync(
      path.resolve(process.cwd(), '../client/src/core/signing/api/tempoSigning.ts'),
      'utf8',
    );

    expect(signerWorkerBridgeSource).toContain("import('../orchestration/signWithIntent')");
    expect(signerWorkerBridgeSource).toContain("import('../engines/ed25519')");
    expect(tempoSigningSource).toContain(
      "import('../chainAdaptors/tempo/handlers/signTempoWithSecureConfirm')",
    );
    expect(tempoSigningSource).toContain("import('../engines/secp256k1')");
    expect(tempoSigningSource).toContain("import('../engines/webauthnP256')");

    expect(signerWorkerBridgeSource).not.toContain(
      "await import('../chainAdaptors/near/walletOrigin')",
    );
    expect(tempoSigningSource).not.toContain("from '../chainAdaptors/tempo/handlers/signTempoWithSecureConfirm'");
    expect(signerWorkerBridgeSource).not.toContain("from '../engines/ed25519'");
    expect(tempoSigningSource).not.toContain("from '../engines/secp256k1'");
    expect(tempoSigningSource).not.toContain("from '../engines/webauthnP256'");
  });

  test('near adapter path does not instantiate multichain wasm workers', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const workerCreations: Array<{ url: string; name: string | null }> = [];

      class ThrowingWorker {
        constructor(url: string | URL, opts?: WorkerOptions) {
          workerCreations.push({
            url: String(url),
            name: typeof opts?.name === 'string' ? opts.name : null,
          });
          throw new Error('Worker creation is not expected in near adapter intent-build flow');
        }
      }

      const originalWorker = window.Worker;
      try {
        (window as any).Worker = ThrowingWorker as any;
        const { NearAdapter } = await import(paths.nearAdapter);
        const { ActionType } = await import(paths.actions);
        const adapter = new NearAdapter();

        await adapter.buildIntent({
          chain: 'near',
          kind: 'transactionsWithActions',
          payload: {
            rpcCall: {
              nearAccountId: 'alice.near',
              nearRpcUrl: 'https://rpc.testnet.near.org',
              contractId: 'web3authn.testnet',
            },
            transactions: [
              {
                receiverId: 'bob.near',
                actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
              },
            ],
            signerMode: 'threshold-signer',
          },
        });

        return { workerCreations };
      } finally {
        (window as any).Worker = originalWorker;
      }
    }, { paths: IMPORT_PATHS });

    expect(result.workerCreations).toEqual([]);
  });

  test('tempo adapter creates workers only when corresponding signer path is used', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const workerCreations: Array<{ url: string; name: string | null }> = [];

      type MessageListener = (event: MessageEvent) => void;

      class FakeWorker {
        private messageListeners = new Set<MessageListener>();
        onmessage: ((event: MessageEvent) => void) | null = null;
        onerror: ((event: ErrorEvent) => void) | null = null;

        constructor(url: string | URL, opts?: WorkerOptions) {
          workerCreations.push({
            url: String(url),
            name: typeof opts?.name === 'string' ? opts.name : null,
          });
          queueMicrotask(() => {
            this.emitMessage({ type: 'WORKER_READY', ready: true });
          });
        }

        addEventListener(type: string, listener: EventListenerOrEventListenerObject): void {
          if (type !== 'message') return;
          if (typeof listener === 'function') {
            this.messageListeners.add(listener as MessageListener);
          }
        }

        removeEventListener(type: string, listener: EventListenerOrEventListenerObject): void {
          if (type !== 'message') return;
          if (typeof listener === 'function') {
            this.messageListeners.delete(listener as MessageListener);
          }
        }

        postMessage(message: any): void {
          const type = String(message?.type || '');
          const id = String(message?.id || '');
          if (!id) return;

          let result: ArrayBuffer;
          if (type === 'computeEip1559TxHash' || type === 'computeTempoSenderHash') {
            result = new Uint8Array(32).buffer;
          } else {
            result = new Uint8Array(1).buffer;
          }

          queueMicrotask(() => {
            this.emitMessage({ id, ok: true, result });
          });
        }

        terminate(): void {}

        private emitMessage(data: any): void {
          const event = { data } as MessageEvent;
          for (const listener of this.messageListeners) listener(event);
          this.onmessage?.(event);
        }
      }

      const originalWorker = window.Worker;
      try {
        (window as any).Worker = FakeWorker as any;
        const { TempoAdapter } = await import(paths.tempoAdapter);
        const { requestMultichainWorkerOperation } = await import(paths.signerGateway);
        const workerCtx = {
          requestWorkerOperation: async ({ kind, request }: { kind: string; request: unknown }) =>
            await requestMultichainWorkerOperation({ kind: kind as any, request: request as any }),
        };

        const adapter = new TempoAdapter(workerCtx as any);

        const eip1559Request = {
          chain: 'tempo' as const,
          kind: 'eip1559' as const,
          senderSignatureAlgorithm: 'secp256k1' as const,
          tx: {
            chainId: 11155111n,
            nonce: 1n,
            maxPriorityFeePerGas: 1n,
            maxFeePerGas: 2n,
            gasLimit: 21_000n,
            to: `0x${'11'.repeat(20)}`,
            value: 0n,
            data: '0x',
            accessList: [],
          },
        };

        await adapter.buildIntent(eip1559Request);
        await adapter.buildIntent(eip1559Request);

        const afterEip = [...workerCreations];

        const tempoRequest = {
          chain: 'tempo' as const,
          kind: 'tempoTransaction' as const,
          senderSignatureAlgorithm: 'secp256k1' as const,
          tx: {
            chainId: 11155111n,
            maxPriorityFeePerGas: 1n,
            maxFeePerGas: 2n,
            gasLimit: 21_000n,
            calls: [{ to: `0x${'22'.repeat(20)}`, value: 0n, input: '0x' }],
            accessList: [],
            nonceKey: 1n,
            nonce: 1n,
            validBefore: null,
            validAfter: null,
            feeToken: null,
            feePayerSignature: { kind: 'none' as const },
          },
        };

        await adapter.buildIntent(tempoRequest);

        const names = workerCreations.map((entry) => entry.name || '');
        const ethWorkers = names.filter((name) => name === 'ethSigner-worker').length;
        const tempoWorkers = names.filter((name) => name === 'tempoSigner-worker').length;

        return {
          afterEipCount: afterEip.length,
          ethWorkers,
          tempoWorkers,
        };
      } finally {
        (window as any).Worker = originalWorker;
      }
    }, { paths: IMPORT_PATHS });

    expect(result.afterEipCount).toBe(1);
    expect(result.ethWorkers).toBe(1);
    expect(result.tempoWorkers).toBe(1);
  });
});
