import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

const IMPORT_PATHS = {
  nearWalletOrigin:
    '/sdk/esm/core/signing/chains/near/walletOrigin.js',
  tempoAdapter:
    '/sdk/esm/core/signing/chains/tempo/tempoAdapter.js',
  actions: '/sdk/esm/core/types/actions.js',
} as const;

test.describe('modularity lazy signer loading', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('WebAuthnManager signing wiring stays dynamic-import based', async () => {
    const sourcePath = path.resolve(
      process.cwd(),
      '../client/src/core/signing/api/WebAuthnManager.ts',
    );
    const source = fs.readFileSync(sourcePath, 'utf8');

    expect(source).toContain(
      "await import('../chains/near/walletOrigin')",
    );
    expect(source).toContain(
      "import('../chains/orchestrator')",
    );
    expect(source).toContain("import('../engines/secp256k1')");
    expect(source).toContain("import('../engines/webauthnP256')");

    expect(source).not.toContain(
      "from '../chains/near/walletOrigin'",
    );
    expect(source).not.toContain("from '../chains/orchestrator'");
    expect(source).not.toContain("from '../engines/secp256k1'");
    expect(source).not.toContain("from '../engines/webauthnP256'");
  });

  test('near wallet-origin path does not instantiate multichain wasm workers', async ({
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
          throw new Error('Worker creation is not expected in near wallet-origin normalization flow');
        }
      }

      const originalWorker = window.Worker;
      try {
        (window as any).Worker = ThrowingWorker as any;
        const { signNearWithSecureConfirm } = await import(paths.nearWalletOrigin);
        const { ActionType } = await import(paths.actions);

        const signerWorkerManager = {
          signTransactionsWithActions: async () => [] as any[],
        };

        await signNearWithSecureConfirm({
          signerWorkerManager,
          request: {
            chain: 'near',
            kind: 'transactionsWithActions',
            nearAccountId: 'alice.near',
            transactions: [
              {
                receiverId: 'bob.near',
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
          sessionId: 'session-near-only',
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

        const adapter = new TempoAdapter();

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
