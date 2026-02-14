import type { MultichainWorkerKind } from '../../../runtimeAssetPaths/multichainWorkers';
import { getMultichainSignerWorkerTransport } from './backends/multichainWorkerBackend';
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
  const transport = getMultichainSignerWorkerTransport(args.kind);
  return await transport.requestOperation(args.request);
}
