import type { MultichainWorkerKind } from '../../../runtimeAssetPaths/multichainWorkers';
import {
  getMultichainSignerWorkerBackend,
  type MultichainOperationType,
  type MultichainWorkerOperationRequest,
  type MultichainWorkerOperationResult,
} from '../../workers/signingWorkerManager/backends';

export async function executeMultichainWorkerOperation<
  K extends MultichainWorkerKind,
  T extends MultichainOperationType<K>,
>(args: {
  kind: K;
  request: MultichainWorkerOperationRequest<K, T>;
}): Promise<MultichainWorkerOperationResult<K, T>> {
  const backend = getMultichainSignerWorkerBackend(args.kind);
  return await backend.requestOperation(args.request);
}
