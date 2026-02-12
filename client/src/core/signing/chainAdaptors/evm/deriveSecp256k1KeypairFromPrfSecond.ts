import type { WorkerOperationContext } from '../../workers/operations/executeSignerWorkerOperation';
import { deriveSecp256k1KeypairFromPrfSecondWasm } from './ethSignerWasm';

/**
 * @deprecated Use `deriveSecp256k1KeypairFromPrfSecondWasm`.
 * This shim keeps the historical path but executes derivation inside the eth-signer worker.
 */
export async function deriveSecp256k1KeypairFromPrfSecondB64u(args: {
  prfSecondB64u: string;
  nearAccountId: string;
  workerCtx: WorkerOperationContext;
}): Promise<{ privateKeyHex: string; publicKeyHex: string; ethereumAddress: string }> {
  return await deriveSecp256k1KeypairFromPrfSecondWasm(args);
}
