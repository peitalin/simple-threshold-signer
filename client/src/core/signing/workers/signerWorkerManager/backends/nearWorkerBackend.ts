import { SIGNER_WORKER_MANAGER_CONFIG } from '../../../../../config';
import { resolveWorkerUrl } from '../../../../runtimeAssetPaths';
import { WorkerControlMessage } from '../../../../workers/workerControlMessages';
import {
  type WorkerResponseForRequest,
  isWorkerError,
  isWorkerProgress,
  isWorkerSuccess,
  type WorkerErrorResponse,
  type WorkerProgressResponse,
} from '../../../../types/signer-worker';
import { withSessionId } from '../internal/session';
import { isObject } from '../../../../../../../shared/src/utils/validation';
import { toError } from '../../../../../../../shared/src/utils/errors';
import type {
  NearSignerWorkerTransportContract,
  NearWorkerOperationRequest,
  NearWorkerOperationResult,
  NearWorkerOperationType,
} from './types';
import { resolveSignerWorkerContractVersion } from './types';

export class NearSignerWorkerTransport implements NearSignerWorkerTransportContract {
  private workerBaseOrigin: string | undefined;
  private workerPool: Worker[] = [];
  private readonly maxWorkerPoolSize = 3;

  setWorkerBaseOrigin(origin: string | undefined): void {
    this.workerBaseOrigin = origin;
  }

  createSecureWorker(): Worker {
    const workerUrlStr = resolveWorkerUrl(
      SIGNER_WORKER_MANAGER_CONFIG.WORKER.URL,
      { worker: 'signer', baseOrigin: this.workerBaseOrigin },
    );
    try {
      const worker = new Worker(workerUrlStr, {
        type: SIGNER_WORKER_MANAGER_CONFIG.WORKER.TYPE,
        name: SIGNER_WORKER_MANAGER_CONFIG.WORKER.NAME,
      });
      // Minimal error handler in tests; avoid noisy logs.
      worker.onerror = () => {};
      return worker;
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      throw new Error(`Failed to create secure worker: ${msg}`);
    }
  }

  private getWorkerFromPool(): Worker {
    if (this.workerPool.length > 0) {
      return this.workerPool.pop()!;
    }
    return this.createSecureWorker();
  }

  private terminateAndReplaceWorker(worker: Worker): void {
    worker.terminate();
    this.createReplacementWorker();
  }

  private async createReplacementWorker(): Promise<void> {
    try {
      const worker = this.createSecureWorker();
      const healthPromise = new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('Health check timeout')), 5000);

        const onMessage = (event: MessageEvent) => {
          if (event.data?.type === WorkerControlMessage.WORKER_READY || event.data?.ready) {
            worker.removeEventListener('message', onMessage);
            clearTimeout(timeout);
            resolve();
          }
        };

        worker.addEventListener('message', onMessage);
        worker.onerror = () => {
          worker.removeEventListener('message', onMessage);
          clearTimeout(timeout);
          reject(new Error('Worker error during health check'));
        };
      });

      await healthPromise;

      if (this.workerPool.length < this.maxWorkerPoolSize) {
        this.workerPool.push(worker);
      } else {
        worker.terminate();
      }
    } catch (error: unknown) {
      console.warn('NearSignerWorkerTransport: Failed to create replacement worker:', error);
    }
  }

  async preWarmWorkerPool(): Promise<void> {
    const promises: Promise<void>[] = [];

    for (let i = 0; i < this.maxWorkerPoolSize; i++) {
      promises.push(
        new Promise<void>((resolve, reject) => {
          try {
            const worker = this.createSecureWorker();
            const onReady = (event: MessageEvent) => {
              if (event.data?.type === WorkerControlMessage.WORKER_READY || event.data?.ready) {
                worker.removeEventListener('message', onReady);
                this.terminateAndReplaceWorker(worker);
                resolve();
              }
            };

            worker.addEventListener('message', onReady);
            worker.onerror = (error) => {
              worker.removeEventListener('message', onReady);
              console.error(`NearSignerWorkerTransport: Worker ${i + 1} pre-warm failed:`, error);
              reject(error);
            };

            setTimeout(() => {
              worker.removeEventListener('message', onReady);
              reject(new Error('Pre-warm timeout'));
            }, 5000);
          } catch (error: unknown) {
            console.error(`NearSignerWorkerTransport: Failed to create worker ${i + 1}:`, error);
            reject(toError(error));
          }
        }),
      );
    }

    try {
      await Promise.allSettled(promises);
    } catch (error: unknown) {
      console.warn('NearSignerWorkerTransport: Some workers failed to pre-warm:', error);
    }
  }

  async requestOperation<T extends NearWorkerOperationType>({
    version,
    sessionId,
    type,
    payload,
    onEvent,
    timeoutMs = SIGNER_WORKER_MANAGER_CONFIG.TIMEOUTS.DEFAULT,
  }: NearWorkerOperationRequest<T>): Promise<NearWorkerOperationResult<T>> {
    resolveSignerWorkerContractVersion(version);
    const payloadSessionId = (payload as any)?.sessionId as string | undefined;
    if (sessionId && payloadSessionId && payloadSessionId !== sessionId) {
      throw new Error(
        `requestOperation: payload.sessionId (${payloadSessionId}) does not match provided sessionId (${sessionId})`,
      );
    }

    const effectiveSessionId = sessionId || payloadSessionId;
    const finalPayload = effectiveSessionId
      ? withSessionId(effectiveSessionId, payload)
      : payload;

    const worker = this.getWorkerFromPool();

    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        try {
          this.terminateAndReplaceWorker(worker);
        } catch {}
        try {
          const seconds = Math.round(timeoutMs / 1000);
          window.postMessage({ type: 'MODAL_TIMEOUT', payload: `Timed out after ${seconds}s, try again` }, '*');
        } catch {}
        reject(new Error(`Worker operation timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      worker.onmessage = async (event) => {
        try {
          if (event?.data?.type === WorkerControlMessage.WORKER_READY || event?.data?.ready) {
            return;
          }
          const response = event.data as WorkerResponseForRequest<T>;

          if (isWorkerProgress(response)) {
            const progressResponse = response as WorkerProgressResponse;
            onEvent?.(progressResponse.payload);
            return;
          }

          if (isWorkerError(response)) {
            clearTimeout(timeoutId);
            this.terminateAndReplaceWorker(worker);
            const errorResponse = response as WorkerErrorResponse;
            console.error('Worker error response:', errorResponse);
            reject(new Error(errorResponse.payload.error));
            return;
          }

          if (isWorkerSuccess(response)) {
            clearTimeout(timeoutId);
            this.terminateAndReplaceWorker(worker);
            resolve(response as WorkerResponseForRequest<T>);
            return;
          }

          console.error('Unexpected worker response format:', { response });
          if (isObject(response) && 'message' in response && 'stack' in response) {
            clearTimeout(timeoutId);
            this.terminateAndReplaceWorker(worker);
            const message = String((response as { message?: unknown }).message ?? 'Unknown error');
            reject(new Error(`Worker sent generic error: ${message}`));
            return;
          }

          clearTimeout(timeoutId);
          this.terminateAndReplaceWorker(worker);
          reject(new Error(`Unknown worker response format: ${JSON.stringify(response)}`));
        } catch (error: unknown) {
          clearTimeout(timeoutId);
          this.terminateAndReplaceWorker(worker);
          const err = toError(error);
          reject(new Error(`Worker message processing error: ${err.message}`));
        }
      };

      worker.onerror = (event) => {
        clearTimeout(timeoutId);
        this.terminateAndReplaceWorker(worker);
        const errorMessage = event.error?.message || event.message || 'Unknown worker error';
        console.error('Worker error details (progress):', {
          message: errorMessage,
          filename: event.filename,
          lineno: event.lineno,
          colno: event.colno,
          error: event.error,
        });
        reject(new Error(`Worker error: ${errorMessage}`));
      };

      worker.postMessage({
        type,
        payload: finalPayload,
      });
    });
  }
}
