import { validateActionArgsWasm, type TransactionInputWasm } from '../../../types/actions';
import type { TransactionPayload } from '../../../types/signer-worker';
import type { ChainAdapter, SigningIntent } from '../../orchestration/types';

export type NearSigningRequest = {
  chain: 'near';
  kind: 'transactionsWithActions';
  nearAccountId: string;
  transactions: TransactionInputWasm[];
};

export type NearIntentUiModel = {
  kind: 'transactionsWithActions';
  nearAccountId: string;
  transactionCount: number;
  totalActionCount: number;
  txSigningRequests: TransactionPayload[];
};

function normalizeNearTransactionInput(args: {
  nearAccountId: string;
  tx: TransactionInputWasm;
  txIndex: number;
}): TransactionPayload {
  const receiverId = String(args.tx?.receiverId || '').trim();
  if (!receiverId) {
    throw new Error(`[NearAdapter] transactions[${args.txIndex}].receiverId is required`);
  }

  const actions = Array.isArray(args.tx?.actions) ? args.tx.actions : [];
  if (actions.length === 0) {
    throw new Error(`[NearAdapter] transactions[${args.txIndex}].actions must be non-empty`);
  }

  for (let i = 0; i < actions.length; i++) {
    validateActionArgsWasm(actions[i]);
  }

  return {
    nearAccountId: args.nearAccountId,
    receiverId,
    actions,
  };
}

export class NearAdapter implements ChainAdapter<NearSigningRequest, NearIntentUiModel, never> {
  readonly chain = 'near' as const;

  async buildIntent(request: NearSigningRequest): Promise<SigningIntent<NearIntentUiModel, never>> {
    if (request.chain !== 'near') {
      throw new Error('[NearAdapter] invalid chain');
    }
    if (request.kind !== 'transactionsWithActions') {
      throw new Error('[NearAdapter] unsupported request kind');
    }

    const nearAccountId = String(request.nearAccountId || '').trim();
    if (!nearAccountId) {
      throw new Error('[NearAdapter] nearAccountId is required');
    }

    const transactions = Array.isArray(request.transactions) ? request.transactions : [];
    if (transactions.length === 0) {
      throw new Error('[NearAdapter] transactions must be non-empty');
    }

    const txSigningRequests = transactions.map((tx, txIndex) =>
      normalizeNearTransactionInput({ nearAccountId, tx, txIndex }),
    );

    const totalActionCount = txSigningRequests.reduce((sum, tx) => sum + tx.actions.length, 0);
    const uiModel: NearIntentUiModel = {
      kind: 'transactionsWithActions',
      nearAccountId,
      transactionCount: txSigningRequests.length,
      totalActionCount,
      txSigningRequests,
    };

    return {
      chain: 'near',
      uiModel,
      signRequests: [],
      finalize: async () => {
        throw new Error('[NearAdapter] finalize is not used for NEAR signer-worker flows');
      },
    };
  }
}
