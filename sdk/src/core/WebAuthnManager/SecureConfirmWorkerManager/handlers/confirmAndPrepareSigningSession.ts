import type { TransactionInputWasm } from '../../../types/actions';
import { ActionType } from '../../../types/actions';
import type { RpcCallPayload, ConfirmationConfig } from '../../../types/signer-worker';
import type { TransactionContext } from '../../../types/rpc';
import { computeUiIntentDigestFromTxs, orderActionForDigest } from '../../../digests/intentDigest';
import {
  SecureConfirmationType,
  type SecureConfirmRequest,
  type SignTransactionPayload,
  type SigningAuthMode,
  type TransactionSummary,
  type SerializableCredential,
} from '../confirmTxFlow/types';
import type { SignNep413Payload } from '../confirmTxFlow/types';
import type { SecureConfirmWorkerManagerContext } from '..';
import type { SecureConfirmWorkerManagerHandlerContext } from './types';
import { runSecureConfirm } from '../secureConfirmBridge';

export interface ConfirmAndPrepareSigningSessionBaseParams {
  ctx: SecureConfirmWorkerManagerContext;
  sessionId: string;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  /**
   * Optional override for signing auth mode.
   * When omitted, the SecureConfirm worker may auto-select `warmSession` when a warm session is available.
   *
   * Threshold signing typically selects `warmSession` only when a valid relay session token exists
   * and PRF.first is cached in the SecureConfirm worker; otherwise it uses `webauthn`.
   */
  signingAuthMode?: SigningAuthMode;
  /**
   * Optional base64url-encoded 32-byte digest to bind a relayer session policy into the WebAuthn challenge.
   * When provided, it is forwarded to SecureConfirm for challenge construction and intent binding.
   */
  sessionPolicyDigest32?: string;
}

export interface ConfirmAndPrepareSigningSessionTransactionParams extends ConfirmAndPrepareSigningSessionBaseParams {
  kind: 'transaction';
  txSigningRequests: TransactionInputWasm[];
  rpcCall: RpcCallPayload;
  title?: string;
  body?: string;
}

export interface ConfirmAndPrepareSigningSessionDelegateParams extends ConfirmAndPrepareSigningSessionBaseParams {
  kind: 'delegate';
  nearAccountId: string;
  title?: string;
  body?: string;
  delegate: {
    senderId: string;
    receiverId: string;
    actions: TransactionInputWasm['actions'];
    nonce: string | number | bigint;
    maxBlockHeight: string | number | bigint;
  };
  rpcCall: RpcCallPayload;
}

export interface ConfirmAndPrepareSigningSessionNep413Params extends ConfirmAndPrepareSigningSessionBaseParams {
  kind: 'nep413';
  nearAccountId: string;
  message: string;
  recipient: string;
  title?: string;
  body?: string;
  contractId?: string;
  nearRpcUrl?: string;
}

export type ConfirmAndPrepareSigningSessionParams =
  | ConfirmAndPrepareSigningSessionTransactionParams
  | ConfirmAndPrepareSigningSessionDelegateParams
  | ConfirmAndPrepareSigningSessionNep413Params;

export interface ConfirmAndPrepareSigningSessionResult {
  sessionId: string;
  transactionContext: TransactionContext;
  intentDigest: string;
  credential?: SerializableCredential;
}

/**
 * Kick off the SecureConfirm signing flow (WebAuthn-only).
 *
 * This creates a `SecureConfirmRequest` (tx / delegate / NEP-413) and runs confirmTxFlow on the
 * main thread to:
 * - render UI (wallet origin),
 * - collect a WebAuthn credential when needed,
 * - return `transactionContext` (reserved nonces, block hash/height) for the signer worker.
 */
export async function confirmAndPrepareSigningSession(
  _handlerCtx: SecureConfirmWorkerManagerHandlerContext,
  params: ConfirmAndPrepareSigningSessionParams
): Promise<ConfirmAndPrepareSigningSessionResult> {
  const { sessionId } = params;

  let intentDigest: string;
  let request: SecureConfirmRequest<SignTransactionPayload | SignNep413Payload, TransactionSummary>;

  switch (params.kind) {
    case 'transaction': {
      const txSigningRequests = params.txSigningRequests;
      intentDigest = await computeUiIntentDigestFromTxs(
        txSigningRequests.map(tx => ({
          receiverId: tx.receiverId,
          actions: tx.actions.map(orderActionForDigest),
        })) as TransactionInputWasm[]
      );

      const summary: TransactionSummary = {
        intentDigest,
        receiverId: txSigningRequests[0]?.receiverId,
        totalAmount: computeTotalAmountYocto(txSigningRequests),
        type: 'transaction',
        ...(params.title != null ? { title: params.title } : {}),
        ...(params.body != null ? { body: params.body } : {}),
      };

      request = {
        requestId: sessionId,
        type: SecureConfirmationType.SIGN_TRANSACTION,
        summary,
        payload: {
          txSigningRequests,
          intentDigest,
          rpcCall: params.rpcCall,
          ...(params.sessionPolicyDigest32 ? { sessionPolicyDigest32: params.sessionPolicyDigest32 } : {}),
          ...(params.signingAuthMode ? { signingAuthMode: params.signingAuthMode } : {}),
        },
        confirmationConfig: params.confirmationConfigOverride,
        intentDigest,
      };
      break;
    }
    case 'delegate': {
      const txSigningRequests: TransactionInputWasm[] = [{
        receiverId: params.delegate.receiverId,
        actions: params.delegate.actions,
      }];

      intentDigest = await computeUiIntentDigestFromTxs(
        txSigningRequests.map(tx => ({
          receiverId: tx.receiverId,
          actions: tx.actions.map(orderActionForDigest),
        }))
      );

      const summary: TransactionSummary = {
        intentDigest,
        receiverId: txSigningRequests[0]?.receiverId,
        totalAmount: computeTotalAmountYocto(txSigningRequests),
        type: 'delegateAction',
        ...(params.title != null ? { title: params.title } : {}),
        ...(params.body != null ? { body: params.body } : {}),
        delegate: {
          senderId: params.delegate.senderId,
          receiverId: params.delegate.receiverId,
          nonce: String(params.delegate.nonce),
          maxBlockHeight: String(params.delegate.maxBlockHeight),
        },
      };

      request = {
        requestId: sessionId,
        type: SecureConfirmationType.SIGN_TRANSACTION,
        summary,
        payload: {
          txSigningRequests,
          intentDigest,
          rpcCall: params.rpcCall,
          ...(params.sessionPolicyDigest32 ? { sessionPolicyDigest32: params.sessionPolicyDigest32 } : {}),
          ...(params.signingAuthMode ? { signingAuthMode: params.signingAuthMode } : {}),
        },
        confirmationConfig: params.confirmationConfigOverride,
        intentDigest,
      };
      break;
    }
    case 'nep413': {
      intentDigest = `${params.nearAccountId}:${params.recipient}:${params.message}`;
      const summary: TransactionSummary = {
        intentDigest,
        method: 'NEP-413',
        receiverId: params.recipient,
        ...(params.title != null ? { title: params.title } : {}),
        ...(params.body != null ? { body: params.body } : {}),
      };

      request = {
        requestId: sessionId,
        type: SecureConfirmationType.SIGN_NEP413_MESSAGE,
        summary,
        payload: {
          nearAccountId: params.nearAccountId,
          message: params.message,
          recipient: params.recipient,
          ...(params.sessionPolicyDigest32 ? { sessionPolicyDigest32: params.sessionPolicyDigest32 } : {}),
          ...(params.contractId ? { contractId: params.contractId } : {}),
          ...(params.nearRpcUrl ? { nearRpcUrl: params.nearRpcUrl } : {}),
          ...(params.signingAuthMode ? { signingAuthMode: params.signingAuthMode } : {}),
        },
        confirmationConfig: params.confirmationConfigOverride,
        intentDigest,
      };
      break;
    }
    default: {
      // Exhaustiveness guard
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const _exhaustive: never = params;
      throw new Error('Unsupported signing session kind');
    }
  }

  const decision = await runSecureConfirm(params.ctx, request);

  if (!decision?.confirmed) {
    throw new Error(decision?.error || 'User rejected signing request');
  }
  if (!decision.transactionContext) {
    throw new Error('Missing transactionContext from confirmation flow');
  }

  return {
    sessionId,
    transactionContext: decision.transactionContext,
    intentDigest: decision.intentDigest || intentDigest,
    credential: decision.credential,
  };
}

function computeTotalAmountYocto(txSigningRequests: TransactionInputWasm[]): string | undefined {
  try {
    let total = BigInt(0);
    for (const tx of txSigningRequests) {
      for (const action of tx.actions) {
        switch (action.action_type) {
          case ActionType.Transfer:
            total += BigInt(action.deposit || '0');
            break;
          case ActionType.FunctionCall:
            total += BigInt(action.deposit || '0');
            break;
          case ActionType.Stake:
            total += BigInt(action.stake || '0');
            break;
          default:
            break;
        }
      }
    }
    return total > BigInt(0) ? total.toString() : undefined;
  } catch {
    return undefined;
  }
}
