import { errorMessage } from '../../../../../../../shared/src/utils/errors';
import type { MultichainWorkerKind } from '../../../../runtimeAssetPaths/multichainWorkers';
import { resolveMultichainWorkerUrl } from '../../../../runtimeAssetPaths/multichainWorkers';
import { WorkerControlMessage } from '../../../../workers/workerControlMessages';
import type {
  MultichainOperationType,
  MultichainWorkerBackendContract,
  MultichainWorkerOperationRequest,
  MultichainWorkerOperationResult,
} from './types';

type RpcOk<T = unknown> = { id: string; ok: true; result: T };
type RpcErr = { id: string; ok: false; error: string };
type RpcResp<T = unknown> = RpcOk<T> | RpcErr;

function makeId(prefix: string): string {
  const c = globalThis.crypto;
  if (c?.randomUUID && typeof c.randomUUID === 'function') return c.randomUUID();
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export class MultichainSignerWorkerBackend<
  K extends MultichainWorkerKind = MultichainWorkerKind,
> implements MultichainWorkerBackendContract<K> {
  private readonly kind: K;
  private worker: Worker | null = null;
  private readonly pending = new Map<
    string,
    {
      resolve: (value: unknown) => void;
      reject: (e: Error) => void;
    }
  >();

  constructor(kind: K) {
    this.kind = kind;
  }

  private getOrCreateWorker(): Worker {
    if (this.worker) return this.worker;

    const workerUrlStr = resolveMultichainWorkerUrl(this.kind);
    const worker = new Worker(workerUrlStr, { type: 'module', name: `${this.kind}-worker` });

    worker.addEventListener('message', (event: MessageEvent) => {
      if (event.data?.type === WorkerControlMessage.WORKER_READY || event.data?.ready) return;
      const msg = event.data as RpcResp;
      const entry = msg?.id ? this.pending.get(msg.id) : undefined;
      if (!entry) return;
      this.pending.delete(msg.id);
      if (msg.ok) {
        entry.resolve(msg.result);
      } else {
        entry.reject(new Error(msg.error || `[${this.kind}] worker error`));
      }
    });

    worker.addEventListener('error', (event: ErrorEvent) => {
      const err = new Error(
        `[${this.kind}] worker runtime error: ${event.message || 'unknown error'}`,
      );
      for (const [, pending] of this.pending) pending.reject(err);
      this.pending.clear();
    });

    this.worker = worker;
    return worker;
  }

  async requestOperation<T extends MultichainOperationType<K>>(
    args: MultichainWorkerOperationRequest<K, T>,
  ): Promise<MultichainWorkerOperationResult<K, T>> {
    const worker = this.getOrCreateWorker();
    const id = makeId(this.kind);

    return await new Promise<MultichainWorkerOperationResult<K, T>>((resolve, reject) => {
      this.pending.set(id, {
        resolve: (value) => resolve(value as MultichainWorkerOperationResult<K, T>),
        reject,
      });
      try {
        worker.postMessage({ id, type: args.type, payload: args.payload }, args.transfer || []);
      } catch (e) {
        this.pending.delete(id);
        reject(new Error(`[${this.kind}] failed to postMessage: ${errorMessage(e)}`));
      }
    });
  }
}

const multichainSignerWorkerBackends = new Map<
  MultichainWorkerKind,
  MultichainSignerWorkerBackend<MultichainWorkerKind>
>();

export function getMultichainSignerWorkerBackend<K extends MultichainWorkerKind>(
  kind: K,
): MultichainSignerWorkerBackend<K> {
  const existing = multichainSignerWorkerBackends.get(kind) as
    | MultichainSignerWorkerBackend<K>
    | undefined;
  if (existing) return existing;
  const backend = new MultichainSignerWorkerBackend(kind);
  multichainSignerWorkerBackends.set(
    kind,
    backend as MultichainSignerWorkerBackend<MultichainWorkerKind>,
  );
  return backend;
}
