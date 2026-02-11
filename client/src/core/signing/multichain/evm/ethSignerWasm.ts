import type { Eip1559UnsignedTx } from './types';
import { WasmSignerWorkerRpc } from '../workerRpc';
import { base64UrlDecode, base64UrlEncode } from '../../../../../../shared/src/utils/encoders';

type Eip1559TxWasmJson = {
  chainId: string;
  nonce: string;
  maxPriorityFeePerGas: string;
  maxFeePerGas: string;
  gasLimit: string;
  to?: string | null;
  value: string;
  data?: string;
  accessList?: { address: string; storageKeys: string[] }[];
};

function toDec(v: bigint): string {
  if (v < 0n) throw new Error('[ethSignerWasm] negative bigint not supported');
  return v.toString(10);
}

function toWasmTx(tx: Eip1559UnsignedTx): Eip1559TxWasmJson {
  return {
    chainId: toDec(tx.chainId),
    nonce: toDec(tx.nonce),
    maxPriorityFeePerGas: toDec(tx.maxPriorityFeePerGas),
    maxFeePerGas: toDec(tx.maxFeePerGas),
    gasLimit: toDec(tx.gasLimit),
    to: tx.to ?? null,
    value: toDec(tx.value),
    data: tx.data ?? '0x',
    accessList: (tx.accessList ?? []).map((item) => ({
      address: item.address,
      storageKeys: item.storageKeys,
    })),
  };
}

const rpc = new WasmSignerWorkerRpc('ethSigner');

type ThresholdSecp256k1ClientShareWasmRaw = {
  clientSigningShare32: ArrayBuffer;
  clientVerifyingShare33: ArrayBuffer;
};

export async function computeEip1559TxHashWasm(tx: Eip1559UnsignedTx): Promise<Uint8Array> {
  const ab = await rpc.request<ArrayBuffer>({ type: 'computeEip1559TxHash', payload: { tx: toWasmTx(tx) } });
  return new Uint8Array(ab);
}

export async function encodeEip1559SignedTxWasm(args: {
  tx: Eip1559UnsignedTx;
  yParity: 0 | 1;
  r: Uint8Array; // 32
  s: Uint8Array; // 32
}): Promise<Uint8Array> {
  const rBuf = args.r.slice().buffer;
  const sBuf = args.s.slice().buffer;
  const ab = await rpc.request<ArrayBuffer>({
    type: 'encodeEip1559SignedTx',
    payload: { tx: toWasmTx(args.tx), yParity: args.yParity, r: rBuf, s: sBuf },
    transfer: [rBuf, sBuf],
  });
  return new Uint8Array(ab);
}

export async function signSecp256k1RecoverableWasm(args: {
  digest32: Uint8Array;
  privateKey32: Uint8Array;
}): Promise<Uint8Array> {
  const digestBuf = args.digest32.slice().buffer;
  const pkBuf = args.privateKey32.slice().buffer;
  const ab = await rpc.request<ArrayBuffer>({
    type: 'signSecp256k1Recoverable',
    payload: { digest32: digestBuf, privateKey32: pkBuf },
    transfer: [digestBuf, pkBuf],
  });
  return new Uint8Array(ab);
}

export async function deriveThresholdSecp256k1ClientShareWasm(args: {
  prfFirstB64u: string;
  userId: string;
  derivationPath?: number;
}): Promise<{
  clientSigningShare32: Uint8Array;
  clientVerifyingShareB64u: string;
  clientVerifyingShareBytes: Uint8Array;
}> {
  const prfFirstB64u = String(args.prfFirstB64u || '').trim();
  if (!prfFirstB64u) throw new Error('Missing prfFirstB64u');
  const userId = String(args.userId || '').trim();
  if (!userId) throw new Error('Missing userId');
  const derivationPath = Number.isFinite(args.derivationPath)
    ? Math.max(0, Math.floor(Number(args.derivationPath)))
    : 0;

  const prfFirst32 = base64UrlDecode(prfFirstB64u);
  if (prfFirst32.length !== 32) {
    throw new Error(`Invalid PRF.first: expected 32 bytes, got ${prfFirst32.length}`);
  }
  const prfFirst32Copy = prfFirst32.slice();

  const raw = await rpc.request<ThresholdSecp256k1ClientShareWasmRaw>({
    type: 'deriveThresholdSecp256k1ClientShare',
    payload: {
      prfFirst32: prfFirst32Copy.buffer,
      userId,
      derivationPath,
    },
    transfer: [prfFirst32Copy.buffer],
  });

  const clientSigningShare32 = new Uint8Array(raw.clientSigningShare32);
  if (clientSigningShare32.length !== 32) {
    throw new Error(`deriveThresholdSecp256k1ClientShare expected 32-byte signing share (got ${clientSigningShare32.length})`);
  }
  const clientVerifyingShareBytes = new Uint8Array(raw.clientVerifyingShare33);
  if (clientVerifyingShareBytes.length !== 33) {
    throw new Error(`deriveThresholdSecp256k1ClientShare expected 33-byte verifying share (got ${clientVerifyingShareBytes.length})`);
  }

  return {
    clientSigningShare32,
    clientVerifyingShareB64u: base64UrlEncode(clientVerifyingShareBytes),
    clientVerifyingShareBytes,
  };
}

export type ThresholdEcdsaPresignProgressWasm = {
  stage: 'triples' | 'triples_done' | 'presign' | 'done';
  event: 'none' | 'triples_done' | 'presign_done';
  outgoingMessages: Uint8Array[];
  presignature97?: Uint8Array;
};

type ThresholdEcdsaPresignProgressWasmRaw = {
  stage?: unknown;
  event?: unknown;
  outgoingMessages?: unknown[];
  presignature97?: unknown;
};

function asPresignProgress(raw: ThresholdEcdsaPresignProgressWasmRaw): ThresholdEcdsaPresignProgressWasm {
  const stage = raw.stage === 'triples'
    || raw.stage === 'triples_done'
    || raw.stage === 'presign'
    || raw.stage === 'done'
    ? raw.stage
    : 'triples';

  const event = raw.event === 'triples_done' || raw.event === 'presign_done'
    ? raw.event
    : 'none';

  const outgoingMessages = Array.isArray(raw.outgoingMessages)
    ? raw.outgoingMessages.map((entry) => new Uint8Array(entry as ArrayBuffer))
    : [];

  const presignature97 = raw.presignature97
    ? new Uint8Array(raw.presignature97 as ArrayBuffer)
    : undefined;

  return { stage, event, outgoingMessages, ...(presignature97 ? { presignature97 } : {}) };
}

export async function thresholdEcdsaPresignSessionInitWasm(args: {
  sessionId: string;
  participantIds: number[];
  clientParticipantId: number;
  threshold: number;
  clientThresholdSigningShare32: Uint8Array;
  groupPublicKey33: Uint8Array;
}): Promise<ThresholdEcdsaPresignProgressWasm> {
  const clientThresholdSigningShare32 = args.clientThresholdSigningShare32.slice();
  const groupPublicKey33 = args.groupPublicKey33.slice();

  const raw = await rpc.request<ThresholdEcdsaPresignProgressWasmRaw>({
    type: 'thresholdEcdsaPresignSessionInit',
    payload: {
      sessionId: args.sessionId,
      participantIds: [...args.participantIds],
      clientParticipantId: args.clientParticipantId,
      threshold: args.threshold,
      clientThresholdSigningShare32: clientThresholdSigningShare32.buffer,
      groupPublicKey33: groupPublicKey33.buffer,
    },
    transfer: [clientThresholdSigningShare32.buffer, groupPublicKey33.buffer],
  });

  return asPresignProgress(raw);
}

export async function thresholdEcdsaPresignSessionStepWasm(args: {
  sessionId: string;
  relayerParticipantId: number;
  stage: 'triples' | 'presign';
  incomingMessages?: Uint8Array[];
}): Promise<ThresholdEcdsaPresignProgressWasm> {
  const incomingMessages = (args.incomingMessages || []).map((entry) => entry.slice());
  const transfer = incomingMessages.map((entry) => entry.buffer);

  const raw = await rpc.request<ThresholdEcdsaPresignProgressWasmRaw>({
    type: 'thresholdEcdsaPresignSessionStep',
    payload: {
      sessionId: args.sessionId,
      relayerParticipantId: args.relayerParticipantId,
      stage: args.stage,
      incomingMessages: incomingMessages.map((entry) => entry.buffer),
    },
    transfer,
  });

  return asPresignProgress(raw);
}

export async function thresholdEcdsaPresignSessionAbortWasm(args: { sessionId: string }): Promise<void> {
  await rpc.request<{ ok: boolean }>({
    type: 'thresholdEcdsaPresignSessionAbort',
    payload: { sessionId: args.sessionId },
  });
}

export async function thresholdEcdsaComputeSignatureShareWasm(args: {
  participantIds: number[];
  clientParticipantId: number;
  groupPublicKey33: Uint8Array;
  presignBigR33: Uint8Array;
  presignKShare32: Uint8Array;
  presignSigmaShare32: Uint8Array;
  digest32: Uint8Array;
  entropy32: Uint8Array;
}): Promise<Uint8Array> {
  const groupPublicKey33 = args.groupPublicKey33.slice();
  const presignBigR33 = args.presignBigR33.slice();
  const presignKShare32 = args.presignKShare32.slice();
  const presignSigmaShare32 = args.presignSigmaShare32.slice();
  const digest32 = args.digest32.slice();
  const entropy32 = args.entropy32.slice();

  const ab = await rpc.request<ArrayBuffer>({
    type: 'thresholdEcdsaComputeSignatureShare',
    payload: {
      participantIds: [...args.participantIds],
      clientParticipantId: args.clientParticipantId,
      groupPublicKey33: groupPublicKey33.buffer,
      presignBigR33: presignBigR33.buffer,
      presignKShare32: presignKShare32.buffer,
      presignSigmaShare32: presignSigmaShare32.buffer,
      digest32: digest32.buffer,
      entropy32: entropy32.buffer,
    },
    transfer: [
      groupPublicKey33.buffer,
      presignBigR33.buffer,
      presignKShare32.buffer,
      presignSigmaShare32.buffer,
      digest32.buffer,
      entropy32.buffer,
    ],
  });
  return new Uint8Array(ab);
}
