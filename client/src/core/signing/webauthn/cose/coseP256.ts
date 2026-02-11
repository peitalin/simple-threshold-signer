type CborDecoded =
  | { kind: 'int'; value: number }
  | { kind: 'bytes'; value: Uint8Array }
  | { kind: 'map'; value: Map<number, CborDecoded> };

function readUInt(bytes: Uint8Array, offset: number, additional: number): { value: number; next: number } {
  if (additional < 24) return { value: additional, next: offset };
  if (additional === 24) {
    if (offset + 1 > bytes.length) throw new Error('CBOR truncated uint8');
    return { value: bytes[offset], next: offset + 1 };
  }
  if (additional === 25) {
    if (offset + 2 > bytes.length) throw new Error('CBOR truncated uint16');
    return { value: (bytes[offset] << 8) | bytes[offset + 1], next: offset + 2 };
  }
  if (additional === 26) {
    if (offset + 4 > bytes.length) throw new Error('CBOR truncated uint32');
    return {
      value:
        (bytes[offset] * 2 ** 24) +
        (bytes[offset + 1] << 16) +
        (bytes[offset + 2] << 8) +
        bytes[offset + 3],
      next: offset + 4,
    };
  }
  throw new Error('CBOR unsupported uint length');
}

function decodeItem(bytes: Uint8Array, offset: number): { item: CborDecoded; next: number } {
  if (offset >= bytes.length) throw new Error('CBOR truncated');
  const head = bytes[offset++];
  const major = head >> 5;
  const additional = head & 0x1f;

  if (major === 0 || major === 1) {
    const u = readUInt(bytes, offset, additional);
    offset = u.next;
    const value = major === 0 ? u.value : (-1 - u.value);
    return { item: { kind: 'int', value }, next: offset };
  }

  if (major === 2) {
    const len = readUInt(bytes, offset, additional);
    offset = len.next;
    const end = offset + len.value;
    if (end > bytes.length) throw new Error('CBOR truncated bytes');
    const value = bytes.slice(offset, end);
    return { item: { kind: 'bytes', value }, next: end };
  }

  if (major === 5) {
    const len = readUInt(bytes, offset, additional);
    offset = len.next;
    const map = new Map<number, CborDecoded>();
    for (let i = 0; i < len.value; i++) {
      const k = decodeItem(bytes, offset);
      offset = k.next;
      if (k.item.kind !== 'int') throw new Error('CBOR COSE key: map keys must be integers');
      const v = decodeItem(bytes, offset);
      offset = v.next;
      map.set(k.item.value, v.item);
    }
    return { item: { kind: 'map', value: map }, next: offset };
  }

  throw new Error('CBOR unsupported major type');
}

export function coseP256PublicKeyToXY(cosePublicKey: Uint8Array): { x: Uint8Array; y: Uint8Array } {
  const decoded = decodeItem(cosePublicKey, 0);
  if (decoded.next !== cosePublicKey.length) throw new Error('CBOR COSE key: trailing bytes');
  if (decoded.item.kind !== 'map') throw new Error('CBOR COSE key: expected map');

  const xItem = decoded.item.value.get(-2);
  const yItem = decoded.item.value.get(-3);
  if (!xItem || xItem.kind !== 'bytes') throw new Error('CBOR COSE key: missing -2 (x)');
  if (!yItem || yItem.kind !== 'bytes') throw new Error('CBOR COSE key: missing -3 (y)');
  if (xItem.value.length !== 32 || yItem.value.length !== 32) throw new Error('CBOR COSE key: x/y must be 32 bytes');
  return { x: xItem.value, y: yItem.value };
}

