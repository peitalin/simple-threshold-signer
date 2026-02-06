import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/utils.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { base64UrlDecode, base64UrlEncode } from '../../../../shared/src/utils/encoders';
import { SECP256K1_ORDER } from '../../../../shared/src/threshold/secp256k1';

const HKDF_SALT_V1 = new TextEncoder().encode('tatchi/lite/threshold-secp256k1-ecdsa/client-share:v1');

function u32be(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n >>> 0, false);
  return out;
}

/**
 * Deterministically derive a secp256k1 "client share" from PRF.first (base64url).
 *
 * This mirrors the threshold-ed25519 pattern:
 * - PRF.first is treated as a 32-byte WrapKeySeed
 * - HKDF-SHA256 with a scheme-specific domain (salt)
 * - `info = userId || 0x00 || u32be(derivationPath)`
 *
 * The derived 64-byte OKM is reduced into a non-zero scalar mod secp256k1 order.
 */
export function deriveThresholdSecp256k1ClientShare(args: {
  prfFirstB64u: string;
  userId: string;
  derivationPath?: number;
}): {
  clientSigningShare32: Uint8Array;
  clientVerifyingShareB64u: string;
  clientVerifyingShareBytes: Uint8Array;
} {
  const prfFirstB64u = String(args.prfFirstB64u || '').trim();
  if (!prfFirstB64u) throw new Error('Missing prfFirstB64u');
  const userId = String(args.userId || '').trim();
  if (!userId) throw new Error('Missing userId');
  const derivationPath = Number.isFinite(args.derivationPath) ? Math.max(0, Math.floor(args.derivationPath!)) : 0;

  const seed = base64UrlDecode(prfFirstB64u);
  if (seed.length !== 32) {
    throw new Error(`Invalid PRF.first: expected 32 bytes, got ${seed.length}`);
  }

  const userIdBytes = new TextEncoder().encode(userId);
  const info = new Uint8Array(userIdBytes.length + 1 + 4);
  info.set(userIdBytes, 0);
  info[userIdBytes.length] = 0;
  info.set(u32be(derivationPath), userIdBytes.length + 1);

  const okm64 = hkdf(sha256, seed, HKDF_SALT_V1, info, 64);
  const reduced = (bytesToNumberBE(okm64) % (SECP256K1_ORDER - 1n)) + 1n;
  const clientSigningShare32 = numberToBytesBE(reduced, 32);

  const clientVerifyingShareBytes = secp256k1.getPublicKey(clientSigningShare32, true);
  const clientVerifyingShareB64u = base64UrlEncode(clientVerifyingShareBytes);

  return { clientSigningShare32, clientVerifyingShareB64u, clientVerifyingShareBytes };
}
