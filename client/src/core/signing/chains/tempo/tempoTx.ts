import type { RlpValue } from '../evm/rlp';
import { rlpEncode } from '../evm/rlp';
import { hexToBytes, concatBytes } from '../evm/bytes';
import { keccak256 } from '../evm/keccak';
import type {
  TempoFeePayerSignature,
  TempoUnsignedTx,
} from './types';

const TYPE_TEMPO_TX = 0x76;
const FEE_PAYER_MAGIC_BYTE = 0x78;

function u256Bytes(v: bigint): Uint8Array {
  if (v < 0n) throw new Error('tempoTx: negative bigint not supported');
  if (v === 0n) return new Uint8Array();
  const out: number[] = [];
  let x = v;
  while (x > 0n) {
    out.push(Number(x & 0xffn));
    x >>= 8n;
  }
  out.reverse();
  return Uint8Array.from(out);
}

function encodeOptU64(v: bigint | null | undefined): Uint8Array {
  // Optional fields encode as EMPTY_STRING_CODE (0x80) when None, i.e., empty bytes input for RLP.
  if (v === null || v === undefined) return new Uint8Array();
  return u256Bytes(v);
}

function encodeFeeToken(addr: string | null | undefined): Uint8Array {
  if (!addr) return new Uint8Array();
  const bytes = hexToBytes(addr);
  if (bytes.length !== 20) throw new Error('tempoTx: feeToken must be a 20-byte address');
  return bytes;
}

function encodeCall(call: { to: string; value: bigint; input?: string }): RlpValue {
  const toBytes = hexToBytes(call.to);
  if (toBytes.length !== 20) throw new Error('tempoTx: call.to must be a 20-byte address');
  const inputBytes = call.input ? hexToBytes(call.input) : new Uint8Array();
  return [toBytes, u256Bytes(call.value), inputBytes];
}

function encodeAccessList(accessList: TempoUnsignedTx['accessList']): RlpValue {
  const items = accessList ?? [];
  return items.map((item) => {
    const address = hexToBytes(item.address);
    if (address.length !== 20) throw new Error('tempoTx: accessList address must be 20 bytes');
    const storageKeys = item.storageKeys.map((k) => {
      const bytes = hexToBytes(k);
      if (bytes.length !== 32) throw new Error('tempoTx: accessList storage key must be 32 bytes');
      return bytes;
    });
    return [address, storageKeys];
  });
}

function feePayerFieldValue(sig: TempoFeePayerSignature | undefined): RlpValue {
  const mode = sig?.kind ?? 'none';
  if (mode === 'none') return new Uint8Array(); // RLP encodes as 0x80
  if (mode === 'placeholder') return Uint8Array.from([0x00]); // encoded as a single byte 0x00

  if (!sig || sig.kind !== 'signed') {
    throw new Error('tempoTx: invalid fee payer signature state');
  }

  // signed: RLP list [v, r, s]
  const r = hexToBytes(sig.r);
  const s = hexToBytes(sig.s);
  if (r.length !== 32 || s.length !== 32) throw new Error('tempoTx: fee payer r/s must be 32 bytes each');
  return [u256Bytes(BigInt(sig.v)), stripLeadingZeros(r), stripLeadingZeros(s)];
}

function stripLeadingZeros(bytes: Uint8Array): Uint8Array {
  let i = 0;
  while (i < bytes.length && bytes[i] === 0) i++;
  return bytes.slice(i);
}

function baseFields(tx: TempoUnsignedTx): RlpValue[] {
  if (!tx.calls?.length) throw new Error('tempoTx: calls must be non-empty');
  const calls = tx.calls.map(encodeCall);

  return [
    u256Bytes(tx.chainId),
    u256Bytes(tx.maxPriorityFeePerGas),
    u256Bytes(tx.maxFeePerGas),
    u256Bytes(tx.gasLimit),
    calls,
    encodeAccessList(tx.accessList),
    u256Bytes(tx.nonceKey),
    u256Bytes(tx.nonce),
    encodeOptU64(tx.validBefore),
    encodeOptU64(tx.validAfter),
  ];
}

export function computeTempoSenderHash(tx: TempoUnsignedTx): Uint8Array {
  const hasFeePayer = (tx.feePayerSignature?.kind ?? 'none') !== 'none';
  const feeTokenForSender = hasFeePayer ? new Uint8Array() : encodeFeeToken(tx.feeToken);
  const feePayerFieldForSender = hasFeePayer ? Uint8Array.from([0x00]) : new Uint8Array();

  const fields: RlpValue = [
    ...baseFields(tx),
    feeTokenForSender,
    feePayerFieldForSender,
  ];

  return keccak256(concatBytes([Uint8Array.from([TYPE_TEMPO_TX]), rlpEncode(fields)]));
}

export function computeTempoFeePayerHash(args: { tx: TempoUnsignedTx; senderAddress: string }): Uint8Array {
  const sender = hexToBytes(args.senderAddress);
  if (sender.length !== 20) throw new Error('tempoTx: senderAddress must be 20 bytes');

  const fields: RlpValue = [
    ...baseFields(args.tx),
    encodeFeeToken(args.tx.feeToken),
    sender,
    args.tx.keyAuthorization ?? new Uint8Array(), // if absent, encode as 0x80 in the fee payer hash
  ];

  return keccak256(concatBytes([Uint8Array.from([FEE_PAYER_MAGIC_BYTE]), rlpEncode(fields)]));
}

export function encodeTempoSignedTx(args: {
  tx: TempoUnsignedTx;
  senderSignature: Uint8Array; // TempoSignature bytes
}): Uint8Array {
  const feeToken = encodeFeeToken(args.tx.feeToken);
  const feePayerSigField = feePayerFieldValue(args.tx.feePayerSignature);

  const aaAuthList = args.tx.aaAuthorizationList ?? ([] as RlpValue);
  if (!Array.isArray(aaAuthList)) {
    throw new Error('tempoTx: aaAuthorizationList must be an RLP list (use [] for empty)');
  }

  const fields: RlpValue[] = [
    ...baseFields(args.tx),
    feeToken,
    feePayerSigField,
    aaAuthList,
  ];

  if (args.tx.keyAuthorization !== undefined) {
    fields.push(args.tx.keyAuthorization);
  }
  fields.push(args.senderSignature);

  return concatBytes([Uint8Array.from([TYPE_TEMPO_TX]), rlpEncode(fields)]);
}
