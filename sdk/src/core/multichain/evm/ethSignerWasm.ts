import type { Eip1559UnsignedTx } from './types';
import { WasmSignerWorkerRpc } from '../wasmWorkers/workerRpc';

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

export async function computeEip1559TxHashWasm(tx: Eip1559UnsignedTx): Promise<Uint8Array> {
  const ab = await rpc.request({ type: 'computeEip1559TxHash', payload: { tx: toWasmTx(tx) } });
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
  const ab = await rpc.request({
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
  const ab = await rpc.request({
    type: 'signSecp256k1Recoverable',
    payload: { digest32: digestBuf, privateKey32: pkBuf },
    transfer: [digestBuf, pkBuf],
  });
  return new Uint8Array(ab);
}

