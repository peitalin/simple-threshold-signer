import { concatBytes, hexToBytes } from './bytes';
import { keccak256 } from './keccak';
import { rlpEncode, type RlpValue } from './rlp';
import type { Eip1559UnsignedTx } from './types';

const TYPE_EIP1559 = 0x02;

function encodeAccessList(accessList: Eip1559UnsignedTx['accessList']): RlpValue {
  const items = accessList ?? [];
  return items.map((item) => {
    const address = hexToBytes(item.address);
    const storageKeys = item.storageKeys.map(hexToBytes);
    return [address, storageKeys];
  });
}

export function encodeEip1559SigningPayload(tx: Eip1559UnsignedTx): Uint8Array {
  const toBytes = tx.to ? hexToBytes(tx.to) : new Uint8Array();
  const dataBytes = tx.data ? hexToBytes(tx.data) : new Uint8Array();
  const accessList = encodeAccessList(tx.accessList);

  const fields: RlpValue = [
    // chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList
    // Values are encoded as minimal big-endian bytes in RLP (0 => empty string 0x80).
    // Addresses/data are raw bytes.
    bigintToRlpBytes(tx.chainId),
    bigintToRlpBytes(tx.nonce),
    bigintToRlpBytes(tx.maxPriorityFeePerGas),
    bigintToRlpBytes(tx.maxFeePerGas),
    bigintToRlpBytes(tx.gasLimit),
    toBytes,
    bigintToRlpBytes(tx.value),
    dataBytes,
    accessList,
  ];

  return concatBytes([Uint8Array.from([TYPE_EIP1559]), rlpEncode(fields)]);
}

export function computeEip1559TxHash(tx: Eip1559UnsignedTx): Uint8Array {
  return keccak256(encodeEip1559SigningPayload(tx));
}

export function encodeEip1559SignedTx(args: {
  tx: Eip1559UnsignedTx;
  yParity: 0 | 1;
  r: Uint8Array; // 32
  s: Uint8Array; // 32
}): Uint8Array {
  if (args.r.length !== 32 || args.s.length !== 32)
    throw new Error('EIP-1559 signature r/s must be 32 bytes each');

  const toBytes = args.tx.to ? hexToBytes(args.tx.to) : new Uint8Array();
  const dataBytes = args.tx.data ? hexToBytes(args.tx.data) : new Uint8Array();
  const accessList = encodeAccessList(args.tx.accessList);

  const fields: RlpValue = [
    bigintToRlpBytes(args.tx.chainId),
    bigintToRlpBytes(args.tx.nonce),
    bigintToRlpBytes(args.tx.maxPriorityFeePerGas),
    bigintToRlpBytes(args.tx.maxFeePerGas),
    bigintToRlpBytes(args.tx.gasLimit),
    toBytes,
    bigintToRlpBytes(args.tx.value),
    dataBytes,
    accessList,
    bigintToRlpBytes(BigInt(args.yParity)),
    stripLeadingZeros(args.r),
    stripLeadingZeros(args.s),
  ];

  return concatBytes([Uint8Array.from([TYPE_EIP1559]), rlpEncode(fields)]);
}

function bigintToRlpBytes(v: bigint): Uint8Array {
  // RLP uses minimal bytes. 0 is encoded as empty string (0x80), which is represented here as empty bytes.
  if (v < 0n) throw new Error('EIP-1559 bigint fields must be non-negative');
  if (v === 0n) return new Uint8Array();
  const bytes: number[] = [];
  let x = v;
  while (x > 0n) {
    bytes.push(Number(x & 0xffn));
    x >>= 8n;
  }
  bytes.reverse();
  return Uint8Array.from(bytes);
}

function stripLeadingZeros(bytes: Uint8Array): Uint8Array {
  let i = 0;
  while (i < bytes.length && bytes[i] === 0) i++;
  return bytes.slice(i);
}
