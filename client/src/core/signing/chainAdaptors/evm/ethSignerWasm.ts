import type { Eip1559UnsignedTx } from './types';
import { bytesToHex } from './bytes';
import {
  executeSignerWorkerOperation,
  type WorkerOperationContext,
} from '../../workers/operations/executeSignerWorkerOperation';
import { base64UrlDecode, base64UrlEncode } from '../../../../../../shared/src/utils/base64';

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

const ETH_SIGNER_WORKER_KIND = 'ethSigner' as const;

export async function computeEip1559TxHashWasm(
  tx: Eip1559UnsignedTx,
  workerCtx: WorkerOperationContext,
): Promise<Uint8Array> {
  const ab = await executeSignerWorkerOperation({
    ctx: workerCtx,
    kind: ETH_SIGNER_WORKER_KIND,
    request: { type: 'computeEip1559TxHash', payload: { tx: toWasmTx(tx) } },
  });
  return new Uint8Array(ab);
}

export async function encodeEip1559SignedTxWasm(args: {
  tx: Eip1559UnsignedTx;
  yParity: 0 | 1;
  r: Uint8Array; // 32
  s: Uint8Array; // 32
  workerCtx: WorkerOperationContext;
}): Promise<Uint8Array> {
  const rBuf = args.r.slice().buffer;
  const sBuf = args.s.slice().buffer;
  const ab = await executeSignerWorkerOperation({
    ctx: args.workerCtx,
    kind: ETH_SIGNER_WORKER_KIND,
    request: {
      type: 'encodeEip1559SignedTx',
      payload: { tx: toWasmTx(args.tx), yParity: args.yParity, r: rBuf, s: sBuf },
      transfer: [rBuf, sBuf],
    },
  });
  return new Uint8Array(ab);
}

export async function signSecp256k1RecoverableWasm(args: {
  digest32: Uint8Array;
  privateKey32: Uint8Array;
  workerCtx: WorkerOperationContext;
}): Promise<Uint8Array> {
  const digestBuf = args.digest32.slice().buffer;
  const pkBuf = args.privateKey32.slice().buffer;
  const ab = await executeSignerWorkerOperation({
    ctx: args.workerCtx,
    kind: ETH_SIGNER_WORKER_KIND,
    request: {
      type: 'signSecp256k1Recoverable',
      payload: { digest32: digestBuf, privateKey32: pkBuf },
      transfer: [digestBuf, pkBuf],
    },
  });
  return new Uint8Array(ab);
}

export async function deriveThresholdSecp256k1ClientShareWasm(args: {
  prfFirstB64u: string;
  userId: string;
  derivationPath?: number;
  workerCtx: WorkerOperationContext;
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

  const raw = await executeSignerWorkerOperation({
    ctx: args.workerCtx,
    kind: ETH_SIGNER_WORKER_KIND,
    request: {
      type: 'deriveThresholdSecp256k1ClientShare',
      payload: {
        prfFirst32: prfFirst32Copy.buffer,
        userId,
        derivationPath,
      },
      transfer: [prfFirst32Copy.buffer],
    },
  });

  const clientSigningShare32 = new Uint8Array(raw.clientSigningShare32);
  if (clientSigningShare32.length !== 32) {
    throw new Error(
      `deriveThresholdSecp256k1ClientShare expected 32-byte signing share (got ${clientSigningShare32.length})`,
    );
  }
  const clientVerifyingShareBytes = new Uint8Array(raw.clientVerifyingShare33);
  if (clientVerifyingShareBytes.length !== 33) {
    throw new Error(
      `deriveThresholdSecp256k1ClientShare expected 33-byte verifying share (got ${clientVerifyingShareBytes.length})`,
    );
  }

  return {
    clientSigningShare32,
    clientVerifyingShareB64u: base64UrlEncode(clientVerifyingShareBytes),
    clientVerifyingShareBytes,
  };
}

export async function deriveSecp256k1KeypairFromPrfSecondWasm(args: {
  prfSecondB64u: string;
  nearAccountId: string;
  workerCtx: WorkerOperationContext;
}): Promise<{ privateKeyHex: string; publicKeyHex: string; ethereumAddress: string }> {
  const prfSecondB64u = String(args.prfSecondB64u || '').trim();
  if (!prfSecondB64u) throw new Error('Missing prfSecondB64u');
  const nearAccountId = String(args.nearAccountId || '').trim();
  if (!nearAccountId) throw new Error('Missing nearAccountId');

  const prfSecond = base64UrlDecode(prfSecondB64u);
  if (prfSecond.length === 0) {
    throw new Error('Invalid PRF.second: empty after base64url decode');
  }
  const prfSecondCopy = prfSecond.slice();

  const raw = await executeSignerWorkerOperation({
    ctx: args.workerCtx,
    kind: ETH_SIGNER_WORKER_KIND,
    request: {
      type: 'deriveSecp256k1KeypairFromPrfSecond',
      payload: {
        prfSecond: prfSecondCopy.buffer,
        nearAccountId,
      },
      transfer: [prfSecondCopy.buffer],
    },
  });

  const privateKey32 = new Uint8Array(raw.privateKey32);
  const publicKey33 = new Uint8Array(raw.publicKey33);
  const ethereumAddress20 = new Uint8Array(raw.ethereumAddress20);

  if (privateKey32.length !== 32) {
    throw new Error(
      `deriveSecp256k1KeypairFromPrfSecond expected 32-byte private key (got ${privateKey32.length})`,
    );
  }
  if (publicKey33.length !== 33) {
    throw new Error(
      `deriveSecp256k1KeypairFromPrfSecond expected 33-byte public key (got ${publicKey33.length})`,
    );
  }
  if (ethereumAddress20.length !== 20) {
    throw new Error(
      `deriveSecp256k1KeypairFromPrfSecond expected 20-byte ethereum address (got ${ethereumAddress20.length})`,
    );
  }

  return {
    privateKeyHex: bytesToHex(privateKey32),
    publicKeyHex: bytesToHex(publicKey33),
    ethereumAddress: bytesToHex(ethereumAddress20),
  };
}

export async function mapAdditiveShareToThresholdSignaturesShare2pWasm(args: {
  additiveShare32: Uint8Array;
  participantId: number;
  workerCtx: WorkerOperationContext;
}): Promise<Uint8Array> {
  if (!(args.additiveShare32 instanceof Uint8Array) || args.additiveShare32.length !== 32) {
    throw new Error('additiveShare32 must be 32 bytes');
  }
  const additiveShare32 = args.additiveShare32.slice();
  const participantId = Math.floor(Number(args.participantId));
  if (!Number.isFinite(participantId) || participantId <= 0) {
    throw new Error(`Invalid participantId: ${args.participantId}`);
  }

  const ab = await executeSignerWorkerOperation({
    ctx: args.workerCtx,
    kind: ETH_SIGNER_WORKER_KIND,
    request: {
      type: 'mapAdditiveShareToThresholdSignaturesShare2p',
      payload: {
        additiveShare32: additiveShare32.buffer,
        participantId,
      },
      transfer: [additiveShare32.buffer],
    },
  });
  const mapped = new Uint8Array(ab);
  if (mapped.length !== 32) {
    throw new Error(
      `mapAdditiveShareToThresholdSignaturesShare2p expected 32-byte output (got ${mapped.length})`,
    );
  }
  return mapped;
}

export async function validateSecp256k1PublicKey33Wasm(args: {
  publicKey33: Uint8Array;
  workerCtx: WorkerOperationContext;
}): Promise<Uint8Array> {
  if (!(args.publicKey33 instanceof Uint8Array) || args.publicKey33.length !== 33) {
    throw new Error('publicKey33 must be 33 bytes');
  }
  const publicKey33 = args.publicKey33.slice();
  const ab = await executeSignerWorkerOperation({
    ctx: args.workerCtx,
    kind: ETH_SIGNER_WORKER_KIND,
    request: {
      type: 'validateSecp256k1PublicKey33',
      payload: { publicKey33: publicKey33.buffer },
      transfer: [publicKey33.buffer],
    },
  });
  const validated = new Uint8Array(ab);
  if (validated.length !== 33) {
    throw new Error(
      `validateSecp256k1PublicKey33 expected 33-byte output (got ${validated.length})`,
    );
  }
  return validated;
}

export async function addSecp256k1PublicKeys33Wasm(args: {
  left33: Uint8Array;
  right33: Uint8Array;
  workerCtx: WorkerOperationContext;
}): Promise<Uint8Array> {
  if (!(args.left33 instanceof Uint8Array) || args.left33.length !== 33) {
    throw new Error('left33 must be 33 bytes');
  }
  if (!(args.right33 instanceof Uint8Array) || args.right33.length !== 33) {
    throw new Error('right33 must be 33 bytes');
  }
  const left33 = args.left33.slice();
  const right33 = args.right33.slice();
  const ab = await executeSignerWorkerOperation({
    ctx: args.workerCtx,
    kind: ETH_SIGNER_WORKER_KIND,
    request: {
      type: 'addSecp256k1PublicKeys33',
      payload: {
        left33: left33.buffer,
        right33: right33.buffer,
      },
      transfer: [left33.buffer, right33.buffer],
    },
  });
  const groupPublicKey33 = new Uint8Array(ab);
  if (groupPublicKey33.length !== 33) {
    throw new Error(
      `addSecp256k1PublicKeys33 expected 33-byte output (got ${groupPublicKey33.length})`,
    );
  }
  return groupPublicKey33;
}

export async function buildWebauthnP256SignatureWasm(args: {
  challenge32: Uint8Array;
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
  signatureDer: Uint8Array;
  pubKeyX32: Uint8Array;
  pubKeyY32: Uint8Array;
  workerCtx: WorkerOperationContext;
}): Promise<Uint8Array> {
  if (!(args.challenge32 instanceof Uint8Array) || args.challenge32.length !== 32) {
    throw new Error('challenge32 must be 32 bytes');
  }
  if (!(args.pubKeyX32 instanceof Uint8Array) || args.pubKeyX32.length !== 32) {
    throw new Error('pubKeyX32 must be 32 bytes');
  }
  if (!(args.pubKeyY32 instanceof Uint8Array) || args.pubKeyY32.length !== 32) {
    throw new Error('pubKeyY32 must be 32 bytes');
  }
  if (!(args.authenticatorData instanceof Uint8Array) || !args.authenticatorData.length) {
    throw new Error('authenticatorData must be non-empty');
  }
  if (!(args.clientDataJSON instanceof Uint8Array) || !args.clientDataJSON.length) {
    throw new Error('clientDataJSON must be non-empty');
  }
  if (!(args.signatureDer instanceof Uint8Array) || !args.signatureDer.length) {
    throw new Error('signatureDer must be non-empty');
  }

  const challenge32 = args.challenge32.slice();
  const authenticatorData = args.authenticatorData.slice();
  const clientDataJSON = args.clientDataJSON.slice();
  const signatureDer = args.signatureDer.slice();
  const pubKeyX32 = args.pubKeyX32.slice();
  const pubKeyY32 = args.pubKeyY32.slice();

  const ab = await executeSignerWorkerOperation({
    ctx: args.workerCtx,
    kind: ETH_SIGNER_WORKER_KIND,
    request: {
      type: 'buildWebauthnP256Signature',
      payload: {
        challenge32: challenge32.buffer,
        authenticatorData: authenticatorData.buffer,
        clientDataJSON: clientDataJSON.buffer,
        signatureDer: signatureDer.buffer,
        pubKeyX32: pubKeyX32.buffer,
        pubKeyY32: pubKeyY32.buffer,
      },
      transfer: [
        challenge32.buffer,
        authenticatorData.buffer,
        clientDataJSON.buffer,
        signatureDer.buffer,
        pubKeyX32.buffer,
        pubKeyY32.buffer,
      ],
    },
  });
  return new Uint8Array(ab);
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

function asPresignProgress(
  raw: ThresholdEcdsaPresignProgressWasmRaw,
): ThresholdEcdsaPresignProgressWasm {
  const stage =
    raw.stage === 'triples' ||
    raw.stage === 'triples_done' ||
    raw.stage === 'presign' ||
    raw.stage === 'done'
      ? raw.stage
      : 'triples';

  const event = raw.event === 'triples_done' || raw.event === 'presign_done' ? raw.event : 'none';

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
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEcdsaPresignProgressWasm> {
  const clientThresholdSigningShare32 = args.clientThresholdSigningShare32.slice();
  const groupPublicKey33 = args.groupPublicKey33.slice();

  const raw = await executeSignerWorkerOperation({
    ctx: args.workerCtx,
    kind: ETH_SIGNER_WORKER_KIND,
    request: {
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
    },
  });

  return asPresignProgress(raw);
}

export async function thresholdEcdsaPresignSessionStepWasm(args: {
  sessionId: string;
  relayerParticipantId: number;
  stage: 'triples' | 'presign';
  incomingMessages?: Uint8Array[];
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEcdsaPresignProgressWasm> {
  const incomingMessages = (args.incomingMessages || []).map((entry) => entry.slice());
  const transfer = incomingMessages.map((entry) => entry.buffer);

  const raw = await executeSignerWorkerOperation({
    ctx: args.workerCtx,
    kind: ETH_SIGNER_WORKER_KIND,
    request: {
      type: 'thresholdEcdsaPresignSessionStep',
      payload: {
        sessionId: args.sessionId,
        relayerParticipantId: args.relayerParticipantId,
        stage: args.stage,
        incomingMessages: incomingMessages.map((entry) => entry.buffer),
      },
      transfer,
    },
  });

  return asPresignProgress(raw);
}

export async function thresholdEcdsaPresignSessionAbortWasm(args: {
  sessionId: string;
  workerCtx: WorkerOperationContext;
}): Promise<void> {
  await executeSignerWorkerOperation({
    ctx: args.workerCtx,
    kind: ETH_SIGNER_WORKER_KIND,
    request: {
      type: 'thresholdEcdsaPresignSessionAbort',
      payload: { sessionId: args.sessionId },
    },
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
  workerCtx: WorkerOperationContext;
}): Promise<Uint8Array> {
  const groupPublicKey33 = args.groupPublicKey33.slice();
  const presignBigR33 = args.presignBigR33.slice();
  const presignKShare32 = args.presignKShare32.slice();
  const presignSigmaShare32 = args.presignSigmaShare32.slice();
  const digest32 = args.digest32.slice();
  const entropy32 = args.entropy32.slice();

  const ab = await executeSignerWorkerOperation({
    ctx: args.workerCtx,
    kind: ETH_SIGNER_WORKER_KIND,
    request: {
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
    },
  });
  return new Uint8Array(ab);
}
