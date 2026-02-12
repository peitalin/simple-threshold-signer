import type { MultichainWorkerKind } from '../../../runtimeAssetPaths/multichainWorkers';
import { getMultichainSignerWorkerBackend } from './backends/multichainWorkerBackend';
import type {
  MultichainOperationType,
  MultichainWorkerOperationRequest,
  MultichainWorkerOperationResult,
} from './backends/types';

export async function requestMultichainWorkerOperation<
  K extends MultichainWorkerKind,
  T extends MultichainOperationType<K>,
>(args: {
  kind: K;
  request: MultichainWorkerOperationRequest<K, T>;
}): Promise<MultichainWorkerOperationResult<K, T>> {
  const backend = getMultichainSignerWorkerBackend(args.kind);
  return await backend.requestOperation(args.request);
}
