import type {
  SecureConfirmWorkerMessage,
  SecureConfirmWorkerResponse,
} from '../../../types/secure-confirm-worker';
import type { SecureConfirmWorkerManagerContext } from '..';

export interface SecureConfirmWorkerManagerHandlerContext {
  ensureWorkerReady: (requireHealthCheck?: boolean) => Promise<void>;
  sendMessage: <TPayload = unknown>(
    message: SecureConfirmWorkerMessage<TPayload>,
    customTimeout?: number
  ) => Promise<SecureConfirmWorkerResponse>;
  generateMessageId: () => string;

  getContext: () => SecureConfirmWorkerManagerContext;

  postToWorker: (message: unknown, transfer?: Transferable[]) => void;
}
