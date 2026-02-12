import { bigintToBytesBE, concatBytes } from './bytes';

export type RlpValue = Uint8Array | RlpValue[];

function encodeLength(len: number): Uint8Array {
  if (len === 0) return new Uint8Array();
  const bytes: number[] = [];
  let x = len;
  while (x > 0) {
    bytes.push(x & 0xff);
    x = x >> 8;
  }
  bytes.reverse();
  return Uint8Array.from(bytes);
}

function encodeBytes(input: Uint8Array): Uint8Array {
  const len = input.length;
  if (len === 1 && input[0] < 0x80) return input;
  if (len <= 55) {
    return concatBytes([Uint8Array.from([0x80 + len]), input]);
  }
  const lenBytes = encodeLength(len);
  return concatBytes([Uint8Array.from([0xb7 + lenBytes.length]), lenBytes, input]);
}

function encodeList(items: Uint8Array[]): Uint8Array {
  const payload = concatBytes(items);
  const len = payload.length;
  if (len <= 55) {
    return concatBytes([Uint8Array.from([0xc0 + len]), payload]);
  }
  const lenBytes = encodeLength(len);
  return concatBytes([Uint8Array.from([0xf7 + lenBytes.length]), lenBytes, payload]);
}

export function rlpEncode(value: RlpValue): Uint8Array {
  if (Array.isArray(value)) {
    const encodedItems = value.map(rlpEncode);
    return encodeList(encodedItems);
  }
  return encodeBytes(value);
}

export function rlpEncodeU256(v: bigint): Uint8Array {
  return rlpEncode(bigintToBytesBE(v));
}
