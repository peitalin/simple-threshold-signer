import type { SigningRuntimeDeps } from '../../../chainAdaptors/types';
import {
  WorkerRequestType,
  WorkerResponseType,
  type WasmDeriveThresholdEd25519ClientVerifyingShareResult,
} from '../../../../types/signer-worker';

export async function deriveThresholdEd25519ClientVerifyingShare(args: {
  ctx: SigningRuntimeDeps;
  sessionId: string;
  nearAccountId: string;
  prfFirstB64u: string;
  wrapKeySalt: string;
}): Promise<{
  success: boolean;
  nearAccountId: string;
  clientVerifyingShareB64u: string;
  error?: string;
}> {
  const { ctx } = args;
  const sessionId = args.sessionId;
  const nearAccountId = args.nearAccountId;

  try {
    if (!sessionId) throw new Error('Missing sessionId');
    if (!nearAccountId) throw new Error('Missing nearAccountId');
    if (!args.prfFirstB64u || !args.wrapKeySalt) {
      throw new Error('Missing PRF.first or wrapKeySalt for share derivation');
    }

    const response = await ctx.requestWorkerOperation({
      kind: 'nearSigner',
      request: {
        sessionId,
        type: WorkerRequestType.DeriveThresholdEd25519ClientVerifyingShare,
        payload: {
          nearAccountId,
          prfFirstB64u: args.prfFirstB64u,
          wrapKeySalt: args.wrapKeySalt,
        },
      },
    });

    if (response.type !== WorkerResponseType.DeriveThresholdEd25519ClientVerifyingShareSuccess) {
      throw new Error('DeriveThresholdEd25519ClientVerifyingShare failed');
    }

    const wasmResult = response.payload as WasmDeriveThresholdEd25519ClientVerifyingShareResult;
    const clientVerifyingShareB64u = wasmResult?.clientVerifyingShareB64u;

    if (!clientVerifyingShareB64u) throw new Error('Missing clientVerifyingShareB64u in worker response');

    return {
      success: true,
      nearAccountId,
      clientVerifyingShareB64u,
    };
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return {
      success: false,
      nearAccountId,
      clientVerifyingShareB64u: '',
      error: message
    };
  }
}
