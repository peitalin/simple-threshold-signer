import type { MultichainWorkerKind } from '../../../runtimeAssetPaths/multichainWorkers';
import type {
  MultichainOperationType,
  MultichainWorkerOperationRequest,
  MultichainWorkerOperationResult,
  NearWorkerOperationRequest,
  NearWorkerOperationResult,
  NearWorkerOperationType,
} from '../../workers/signerWorkerManager/backends/types';
import type { SigningRuntimeDeps } from '../types';

export type WorkerOperationContext = Pick<SigningRuntimeDeps, 'requestWorkerOperation'>;

type NearOperationArgs<T extends NearWorkerOperationType> = {
  kind: 'nearSigner';
  request: NearWorkerOperationRequest<T>;
  ctx: WorkerOperationContext;
};

type MultichainOperationArgs<
  K extends MultichainWorkerKind,
  T extends MultichainOperationType<K>,
> = {
  kind: K;
  request: MultichainWorkerOperationRequest<K, T>;
  ctx: WorkerOperationContext;
};

export function executeSignerWorkerOperation<T extends NearWorkerOperationType>(
  args: NearOperationArgs<T>,
): Promise<NearWorkerOperationResult<T>>;
export function executeSignerWorkerOperation<
  K extends MultichainWorkerKind,
  T extends MultichainOperationType<K>,
>(
  args: MultichainOperationArgs<K, T>,
): Promise<MultichainWorkerOperationResult<K, T>>;
export async function executeSignerWorkerOperation<
  K extends MultichainWorkerKind,
  T extends MultichainOperationType<K>,
>(
  args: NearOperationArgs<NearWorkerOperationType> | MultichainOperationArgs<K, T>,
): Promise<NearWorkerOperationResult<NearWorkerOperationType> | MultichainWorkerOperationResult<K, T>> {
  if (args.kind === 'nearSigner') {
    if (!args.ctx) {
      throw new Error('[executeSignerWorkerOperation] ctx is required for nearSigner operations');
    }
    return await args.ctx.requestWorkerOperation({
      kind: 'nearSigner',
      request: args.request as NearWorkerOperationRequest<NearWorkerOperationType>,
    });
  }

  if (!args.ctx) {
    throw new Error(`[executeSignerWorkerOperation] ctx is required for ${args.kind} operations`);
  }
  const requestWorkerOperation = args.ctx.requestWorkerOperation as <
    K2 extends MultichainWorkerKind,
    T2 extends MultichainOperationType<K2>,
  >(args: {
    kind: K2;
    request: MultichainWorkerOperationRequest<K2, T2>;
  }) => Promise<MultichainWorkerOperationResult<K2, T2>>;
  return await requestWorkerOperation({
    kind: args.kind,
    request: args.request as MultichainWorkerOperationRequest<K, T>,
  });
}
