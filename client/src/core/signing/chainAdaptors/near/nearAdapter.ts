import { validateActionArgsWasm, type TransactionInputWasm } from '../../../types/actions';
import type { TransactionPayload } from '../../../types/signer-worker';
import type { ChainAdapter, SigningIntent } from '../../orchestration/types';
import type { signDelegateAction } from './handlers/signDelegateAction';
import type { signNep413Message } from './handlers/signNep413Message';
import type { signTransactionsWithActions } from './handlers/signTransactionsWithActions';

export type NearSigningRequest =
  | {
      chain: 'near';
      kind: 'transactionsWithActions';
      payload: Parameters<typeof signTransactionsWithActions>[0];
    }
  | {
      chain: 'near';
      kind: 'delegateAction';
      payload: Parameters<typeof signDelegateAction>[0];
    }
  | {
      chain: 'near';
      kind: 'nep413';
      payload: Parameters<typeof signNep413Message>[0];
    };

export type NearEd25519SignRequest =
  | {
      kind: 'near-transactions-with-actions';
      algorithm: 'ed25519';
      payload: Parameters<typeof signTransactionsWithActions>[0];
    }
  | {
      kind: 'near-delegate-action';
      algorithm: 'ed25519';
      payload: Parameters<typeof signDelegateAction>[0];
    }
  | {
      kind: 'near-nep413-message';
      algorithm: 'ed25519';
      payload: Parameters<typeof signNep413Message>[0];
    };

export type NearEd25519SignOutput =
  | {
      kind: 'near-transactions-with-actions';
      result: Awaited<ReturnType<typeof signTransactionsWithActions>>;
    }
  | {
      kind: 'near-delegate-action';
      result: Awaited<ReturnType<typeof signDelegateAction>>;
    }
  | {
      kind: 'near-nep413-message';
      result: Awaited<ReturnType<typeof signNep413Message>>;
    };

export type NearSignedResult = NearEd25519SignOutput['result'];

export type NearIntentResultByKind = {
  transactionsWithActions: Awaited<ReturnType<typeof signTransactionsWithActions>>;
  delegateAction: Awaited<ReturnType<typeof signDelegateAction>>;
  nep413: Awaited<ReturnType<typeof signNep413Message>>;
};

export type NearIntentResult<T extends NearSigningRequest> = T extends { kind: infer K }
  ? K extends keyof NearIntentResultByKind
    ? NearIntentResultByKind[K]
    : never
  : never;

export type NearIntentUiModel =
  | {
      kind: 'transactionsWithActions';
      nearAccountId: string;
      transactionCount: number;
      totalActionCount: number;
      txSigningRequests: TransactionPayload[];
    }
  | {
      kind: 'delegateAction';
      nearAccountId: string;
      receiverId: string;
      actionCount: number;
    }
  | {
      kind: 'nep413';
      nearAccountId: string;
      recipient: string;
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

export class NearAdapter
implements ChainAdapter<NearSigningRequest, NearIntentUiModel, NearSignedResult, NearEd25519SignRequest, NearEd25519SignOutput> {
  readonly chain = 'near' as const;

  async buildIntent(
    request: NearSigningRequest,
  ): Promise<SigningIntent<NearIntentUiModel, NearSignedResult, NearEd25519SignRequest, NearEd25519SignOutput>> {
    if (request.chain !== 'near') {
      throw new Error('[NearAdapter] invalid chain');
    }
    if (request.kind === 'transactionsWithActions') {
      const nearAccountId = String(request.payload?.rpcCall?.nearAccountId || '').trim();
      if (!nearAccountId) {
        throw new Error('[NearAdapter] nearAccountId is required');
      }
      const transactions = Array.isArray(request.payload.transactions) ? request.payload.transactions : [];
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
        signRequests: [{
          kind: 'near-transactions-with-actions',
          algorithm: 'ed25519',
          payload: request.payload,
        }],
        finalize: async (signed) => expectNearOutput(signed, 'near-transactions-with-actions'),
      };
    }

    if (request.kind === 'delegateAction') {
      const nearAccountId = String(
        request.payload.rpcCall?.nearAccountId || request.payload.delegate?.senderId || '',
      ).trim();
      if (!nearAccountId) {
        throw new Error('[NearAdapter] nearAccountId is required');
      }
      const receiverId = String(request.payload.delegate?.receiverId || '').trim();
      if (!receiverId) {
        throw new Error('[NearAdapter] delegate.receiverId is required');
      }
      const actions = Array.isArray(request.payload.delegate?.actions)
        ? request.payload.delegate.actions
        : [];
      if (actions.length === 0) {
        throw new Error('[NearAdapter] delegate.actions must be non-empty');
      }
      for (let i = 0; i < actions.length; i++) {
        validateActionArgsWasm(actions[i] as any);
      }

      return {
        chain: 'near',
        uiModel: {
          kind: 'delegateAction',
          nearAccountId,
          receiverId,
          actionCount: actions.length,
        },
        signRequests: [{
          kind: 'near-delegate-action',
          algorithm: 'ed25519',
          payload: request.payload,
        }],
        finalize: async (signed) => expectNearOutput(signed, 'near-delegate-action'),
      };
    }

    if (request.kind === 'nep413') {
      const nearAccountId = String(request.payload.payload?.accountId || '').trim();
      if (!nearAccountId) {
        throw new Error('[NearAdapter] accountId is required for NEP-413');
      }
      const recipient = String(request.payload.payload?.recipient || '').trim();
      if (!recipient) {
        throw new Error('[NearAdapter] recipient is required for NEP-413');
      }
      const message = String(request.payload.payload?.message || '').trim();
      if (!message) {
        throw new Error('[NearAdapter] message is required for NEP-413');
      }

      return {
        chain: 'near',
        uiModel: {
          kind: 'nep413',
          nearAccountId,
          recipient,
        },
        signRequests: [{
          kind: 'near-nep413-message',
          algorithm: 'ed25519',
          payload: request.payload,
        }],
        finalize: async (signed) => expectNearOutput(signed, 'near-nep413-message'),
      };
    }

    const _exhaustive: never = request;
    return _exhaustive;
  }
}

function expectNearOutput(
  signed: NearEd25519SignOutput[],
  expectedKind: NearEd25519SignOutput['kind'],
): NearSignedResult {
  if (signed.length !== 1) {
    throw new Error(`[NearAdapter] expected one engine output, got ${signed.length}`);
  }
  const first = signed[0];
  if (first.kind !== expectedKind) {
    throw new Error(`[NearAdapter] unexpected engine output kind: ${first.kind}`);
  }
  return first.result;
}
