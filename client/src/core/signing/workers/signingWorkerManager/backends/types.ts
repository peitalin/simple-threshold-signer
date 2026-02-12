import type { onProgressEvents } from '../../../../types/sdkSentEvents';
import type { WorkerRequestTypeMap, WorkerResponseForRequest } from '../../../../types/signer-worker';
import type { MultichainWorkerKind } from '../../../../runtimeAssetPaths/multichainWorkers';

export type ThresholdEcdsaPresignStage = 'triples' | 'triples_done' | 'presign' | 'done';
export type ThresholdEcdsaPresignEvent = 'none' | 'triples_done' | 'presign_done';

export type ThresholdEcdsaPresignProgressResult = {
  stage: ThresholdEcdsaPresignStage;
  event: ThresholdEcdsaPresignEvent;
  outgoingMessages: ArrayBuffer[];
  presignature97?: ArrayBuffer;
};

export interface EthSignerWorkerOperationMap {
  computeEip1559TxHash: {
    payload: { tx: unknown };
    result: ArrayBuffer;
  };
  encodeEip1559SignedTx: {
    payload: { tx: unknown; yParity: number; r: ArrayBuffer; s: ArrayBuffer };
    result: ArrayBuffer;
  };
  signSecp256k1Recoverable: {
    payload: { digest32: ArrayBuffer; privateKey32: ArrayBuffer };
    result: ArrayBuffer;
  };
  deriveThresholdSecp256k1ClientShare: {
    payload: { prfFirst32: ArrayBuffer; userId: string; derivationPath?: number };
    result: { clientSigningShare32: ArrayBuffer; clientVerifyingShare33: ArrayBuffer };
  };
  thresholdEcdsaPresignSessionInit: {
    payload: {
      sessionId: string;
      participantIds: number[];
      clientParticipantId: number;
      threshold: number;
      clientThresholdSigningShare32: ArrayBuffer;
      groupPublicKey33: ArrayBuffer;
    };
    result: ThresholdEcdsaPresignProgressResult;
  };
  thresholdEcdsaPresignSessionStep: {
    payload: {
      sessionId: string;
      relayerParticipantId: number;
      stage: 'triples' | 'presign';
      incomingMessages?: ArrayBuffer[];
    };
    result: ThresholdEcdsaPresignProgressResult;
  };
  thresholdEcdsaPresignSessionAbort: {
    payload: { sessionId: string };
    result: { ok: boolean };
  };
  thresholdEcdsaComputeSignatureShare: {
    payload: {
      participantIds: number[];
      clientParticipantId: number;
      groupPublicKey33: ArrayBuffer;
      presignBigR33: ArrayBuffer;
      presignKShare32: ArrayBuffer;
      presignSigmaShare32: ArrayBuffer;
      digest32: ArrayBuffer;
      entropy32: ArrayBuffer;
    };
    result: ArrayBuffer;
  };
}

export interface TempoSignerWorkerOperationMap {
  computeTempoSenderHash: {
    payload: { tx: unknown };
    result: ArrayBuffer;
  };
  encodeTempoSignedTx: {
    payload: { tx: unknown; senderSignature: ArrayBuffer };
    result: ArrayBuffer;
  };
}

export interface MultichainSignerWorkerOperationMapByKind {
  ethSigner: EthSignerWorkerOperationMap;
  tempoSigner: TempoSignerWorkerOperationMap;
}

export type MultichainOperationType<K extends MultichainWorkerKind> =
  keyof MultichainSignerWorkerOperationMapByKind[K];

type MultichainWorkerOperationEntry<
  K extends MultichainWorkerKind,
  T extends MultichainOperationType<K>,
> = MultichainSignerWorkerOperationMapByKind[K][T] extends {
  payload: infer P;
  result: infer R;
}
  ? { payload: P; result: R }
  : never;

export type MultichainWorkerOperationRequest<
  K extends MultichainWorkerKind,
  T extends MultichainOperationType<K>,
> = {
  type: T;
  payload: MultichainWorkerOperationEntry<K, T>['payload'];
  transfer?: Transferable[];
};

export type MultichainWorkerOperationResult<
  K extends MultichainWorkerKind,
  T extends MultichainOperationType<K>,
> = MultichainWorkerOperationEntry<K, T>['result'];

export interface MultichainWorkerBackendContract<K extends MultichainWorkerKind = MultichainWorkerKind> {
  requestOperation<T extends MultichainOperationType<K>>(
    args: MultichainWorkerOperationRequest<K, T>,
  ): Promise<MultichainWorkerOperationResult<K, T>>;
}

export type WithOptionalSessionId<T> = T extends { sessionId: string }
  ? Omit<T, 'sessionId'> & { sessionId?: string }
  : T;

export type NearSignerWorkerRequestArgs<T extends keyof WorkerRequestTypeMap> = {
  sessionId?: string;
  message: {
    type: T;
    payload: WithOptionalSessionId<WorkerRequestTypeMap[T]['request']>;
  };
  onEvent?: (update: onProgressEvents) => void;
  timeoutMs?: number;
};

export interface NearSignerWorkerBackendContract {
  sendMessage<T extends keyof WorkerRequestTypeMap>(args: NearSignerWorkerRequestArgs<T>): Promise<WorkerResponseForRequest<T>>;
}
