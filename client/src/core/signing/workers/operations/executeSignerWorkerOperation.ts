import type { MultichainWorkerKind } from '../../../runtimeAssetPaths/multichainWorkers';
import type {
  MultichainOperationType,
  MultichainWorkerOperationRequest,
  MultichainWorkerOperationResult,
  NearWorkerOperationRequest,
  NearWorkerOperationResult,
  NearWorkerOperationType,
  SignerWorkerKind,
  SignerWorkerOperationRequest,
  SignerWorkerOperationResult,
  SignerWorkerOperationType,
} from '../signerWorkerManager/backends/types';

export type WorkerOperationContext = {
  requestWorkerOperation: <
    K extends SignerWorkerKind,
    T extends SignerWorkerOperationType<K>,
  >(args: {
    kind: K;
    request: SignerWorkerOperationRequest<K, T>;
  }) => Promise<SignerWorkerOperationResult<K, T>>;
};

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

type AnyNearOperationArgs = NearOperationArgs<NearWorkerOperationType>;
type AnyMultichainOperationArgs = {
  [K in MultichainWorkerKind]: MultichainOperationArgs<K, MultichainOperationType<K>>;
}[MultichainWorkerKind];

export function executeSignerWorkerOperation<T extends NearWorkerOperationType>(
  args: NearOperationArgs<T>,
): Promise<NearWorkerOperationResult<T>>;
export function executeSignerWorkerOperation<
  K extends MultichainWorkerKind,
  T extends MultichainOperationType<K>,
>(args: MultichainOperationArgs<K, T>): Promise<MultichainWorkerOperationResult<K, T>>;
export async function executeSignerWorkerOperation(
  args: AnyNearOperationArgs | AnyMultichainOperationArgs,
): Promise<
  | NearWorkerOperationResult<NearWorkerOperationType>
  | MultichainWorkerOperationResult<
      MultichainWorkerKind,
      MultichainOperationType<MultichainWorkerKind>
    >
> {
  if (args.kind === 'nearSigner') {
    if (!args.ctx) {
      throw new Error('[executeSignerWorkerOperation] ctx is required for nearSigner operations');
    }
    return await args.ctx.requestWorkerOperation({
      kind: 'nearSigner',
      request: args.request,
    });
  }

  if (!args.ctx) {
    throw new Error(`[executeSignerWorkerOperation] ctx is required for ${args.kind} operations`);
  }
  return await args.ctx.requestWorkerOperation({
    kind: args.kind,
    request: args.request,
  });
}
