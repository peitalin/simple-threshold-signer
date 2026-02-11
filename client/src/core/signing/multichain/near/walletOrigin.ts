import type { TransactionInputWasm } from '../../../types/actions';
import type { onProgressEvents } from '../../../types/sdkSentEvents';
import type {
  ConfirmationConfig,
  RpcCallPayload,
  SignerMode,
  TransactionPayload,
} from '../../../types/signer-worker';
import type { SignTransactionResult } from '../../../types/tatchi';
import { NearAdapter, type NearSigningRequest } from './nearAdapter';

type NearSignerWorkerFacade = {
  signTransactionsWithActions: (args: {
    transactions: TransactionInputWasm[];
    rpcCall: RpcCallPayload;
    signerMode: SignerMode;
    onEvent?: (update: onProgressEvents) => void;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    title?: string;
    body?: string;
    signingSessionTtlMs?: number;
    signingSessionRemainingUses?: number;
    sessionId: string;
    deviceNumber?: number;
  }) => Promise<SignTransactionResult[]>;
};

export async function signNearWithSecureConfirm(args: {
  signerWorkerManager: NearSignerWorkerFacade;
  request: NearSigningRequest;
  rpcCall: RpcCallPayload;
  signerMode: SignerMode;
  onEvent?: (update: onProgressEvents) => void;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  title?: string;
  body?: string;
  signingSessionTtlMs?: number;
  signingSessionRemainingUses?: number;
  sessionId: string;
  deviceNumber?: number;
}): Promise<SignTransactionResult[]> {
  const nearIntent = await new NearAdapter().buildIntent(args.request);
  const normalizedTransactions: TransactionInputWasm[] = nearIntent.uiModel.txSigningRequests.map(
    (tx: TransactionPayload) => ({
      receiverId: tx.receiverId,
      actions: tx.actions,
    }),
  );

  return await args.signerWorkerManager.signTransactionsWithActions({
    transactions: normalizedTransactions,
    rpcCall: {
      ...args.rpcCall,
      nearAccountId: nearIntent.uiModel.nearAccountId,
    },
    signerMode: args.signerMode,
    onEvent: args.onEvent,
    confirmationConfigOverride: args.confirmationConfigOverride,
    title: args.title,
    body: args.body,
    signingSessionTtlMs: args.signingSessionTtlMs,
    signingSessionRemainingUses: args.signingSessionRemainingUses,
    sessionId: args.sessionId,
    deviceNumber: args.deviceNumber,
  });
}
