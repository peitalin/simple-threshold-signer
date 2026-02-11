import type { SecureConfirmWorkerManagerContext } from '../../';
import { TransactionContext } from '../../../../types';
import type { BlockReference, AccessKeyView } from '@near-js/types';
import { errorMessage } from '../../../../../../../shared/src/utils/errors';

export async function fetchNearContext(
  ctx: SecureConfirmWorkerManagerContext,
  opts: { nearAccountId: string; txCount: number; reserveNonces: boolean },
): Promise<{
  transactionContext: TransactionContext | null;
  error?: string;
  details?: string;
  reservedNonces?: string[];
}> {
  try {
    // Prefer NonceManager when initialized (signing flows).
    // Use cached transaction context if fresh; avoid forcing a refresh here.
    const cached = await ctx.nonceManager.getNonceBlockHashAndHeight(ctx.nearClient);
    // IMPORTANT: `NonceManager` returns its cached `transactionContext` object by reference.
    // Never mutate it in-place here, otherwise concurrent signing requests can race and overwrite
    // `nextNonce` for each other, leading to duplicate nonces (InvalidNonce) under load.
    const transactionContext: TransactionContext = { ...cached };

    const txCount = opts.txCount || 1;
    let reservedNonces: string[] | undefined;
    if (opts.reserveNonces) {
      try {
        reservedNonces = ctx.nonceManager.reserveNonces(txCount);
        // Provide the first reserved nonce to the worker context; worker handles per-tx assignment
        transactionContext.nextNonce = reservedNonces[0];
      } catch (error) {
        // Continue with existing nextNonce; worker may auto-increment where appropriate
      }
    }

    return { transactionContext, reservedNonces };
  } catch (error) {
    // Registration or pre-login flows may not have NonceManager initialized.
    // Fallback: fetch latest block info directly; nonces are not required for registration/link flows.
    try {
      const block = await ctx.nearClient.viewBlock({ finality: 'final' } as BlockReference);
      const txBlockHeight = String(block?.header?.height ?? '');
      const txBlockHash = String(block?.header?.hash ?? '');
      const fallback: TransactionContext = {
        nearPublicKeyStr: '', // not needed for registration/link flows here
        accessKeyInfo: ({
          nonce: 0,
          permission: 'FullAccess',
          block_height: 0,
          block_hash: ''
        } as unknown) as AccessKeyView, // minimal shape; not used in registration/link flows
        nextNonce: '0',
        txBlockHeight,
        txBlockHash,
      } as TransactionContext;
      return { transactionContext: fallback };
    } catch (e) {
      return {
        transactionContext: null,
        error: 'NEAR_RPC_FAILED',
        details: errorMessage(e) || errorMessage(error),
      };
    }
  }
}

export function releaseReservedNonces(ctx: SecureConfirmWorkerManagerContext, nonces?: string[]) {
  nonces?.forEach((n) => ctx.nonceManager.releaseNonce(n));
}
