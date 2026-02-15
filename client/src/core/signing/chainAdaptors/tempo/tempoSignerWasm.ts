import type { TempoUnsignedTx } from './types';
import {
  executeSignerWorkerOperation,
  type WorkerOperationContext,
} from '../../workers/operations/executeSignerWorkerOperation';

type TempoRlpValueWasm = number[] | TempoRlpValueWasm[];

type TempoTxWasmJson = {
  chainId: string;
  maxPriorityFeePerGas: string;
  maxFeePerGas: string;
  gasLimit: string;
  calls: { to: string; value: string; input?: string }[];
  accessList?: { address: string; storageKeys: string[] }[];
  nonceKey: string;
  nonce: string;
  validBefore?: string | null;
  validAfter?: string | null;
  feeToken?: string | null;
  feePayerSignature?:
    | { kind: 'none' }
    | { kind: 'placeholder' }
    | { kind: 'signed'; v: 0 | 1; r: string; s: string };
  aaAuthorizationList?: TempoRlpValueWasm;
  keyAuthorization?: TempoRlpValueWasm;
};

function toDec(v: bigint): string {
  if (v < 0n) throw new Error('[tempoSignerWasm] negative bigint not supported');
  return v.toString(10);
}

function toDecOpt(v: bigint | null | undefined): string | null | undefined {
  if (v === null) return null;
  if (v === undefined) return undefined;
  return toDec(v);
}

function toWasmTempoRlpValue(
  value: TempoUnsignedTx['aaAuthorizationList'] | TempoUnsignedTx['keyAuthorization'],
): TempoRlpValueWasm | undefined {
  if (value === undefined) return undefined;
  if (value instanceof Uint8Array) return Array.from(value);
  return value.map((entry) => toWasmTempoRlpValue(entry) as TempoRlpValueWasm);
}

function toWasmTx(tx: TempoUnsignedTx): TempoTxWasmJson {
  return {
    chainId: toDec(tx.chainId),
    maxPriorityFeePerGas: toDec(tx.maxPriorityFeePerGas),
    maxFeePerGas: toDec(tx.maxFeePerGas),
    gasLimit: toDec(tx.gasLimit),
    calls: tx.calls.map((c) => ({ to: c.to, value: toDec(c.value), input: c.input ?? '0x' })),
    accessList: (tx.accessList ?? []).map((item) => ({
      address: item.address,
      storageKeys: item.storageKeys,
    })),
    nonceKey: toDec(tx.nonceKey),
    nonce: toDec(tx.nonce),
    validBefore: toDecOpt(tx.validBefore),
    validAfter: toDecOpt(tx.validAfter),
    feeToken: tx.feeToken ?? null,
    feePayerSignature: tx.feePayerSignature ?? { kind: 'none' },
    aaAuthorizationList: toWasmTempoRlpValue(tx.aaAuthorizationList),
    keyAuthorization: toWasmTempoRlpValue(tx.keyAuthorization),
  };
}

const TEMPO_SIGNER_WORKER_KIND = 'tempoSigner' as const;

export async function computeTempoSenderHashWasm(
  tx: TempoUnsignedTx,
  workerCtx: WorkerOperationContext,
): Promise<Uint8Array> {
  const ab = await executeSignerWorkerOperation({
    ctx: workerCtx,
    kind: TEMPO_SIGNER_WORKER_KIND,
    request: { type: 'computeTempoSenderHash', payload: { tx: toWasmTx(tx) } },
  });
  return new Uint8Array(ab);
}

export async function encodeTempoSignedTxWasm(args: {
  tx: TempoUnsignedTx;
  senderSignature: Uint8Array; // TempoSignature bytes
  workerCtx: WorkerOperationContext;
}): Promise<Uint8Array> {
  const sigBuf = args.senderSignature.slice().buffer;
  const ab = await executeSignerWorkerOperation({
    ctx: args.workerCtx,
    kind: TEMPO_SIGNER_WORKER_KIND,
    request: {
      type: 'encodeTempoSignedTx',
      payload: { tx: toWasmTx(args.tx), senderSignature: sigBuf },
      transfer: [sigBuf],
    },
  });
  return new Uint8Array(ab);
}
