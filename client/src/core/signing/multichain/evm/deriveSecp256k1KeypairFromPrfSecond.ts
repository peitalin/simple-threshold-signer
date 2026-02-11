import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/utils.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { base64UrlDecode } from '../../../../../../shared/src/utils/encoders';
import { SECP256K1_ORDER } from '../../../../../../shared/src/threshold/secp256k1';
import { bytesToHex } from './bytes';
import { keccak256 } from './keccak';

const HKDF_INFO = new TextEncoder().encode('secp256k1-signing-key-dual-prf-v1');

/**
 * Deterministically derive a secp256k1 keypair + EVM address from PRF.second.
 */
export function deriveSecp256k1KeypairFromPrfSecondB64u(args: {
  prfSecondB64u: string;
  nearAccountId: string;
}): { privateKeyHex: string; publicKeyHex: string; ethereumAddress: string } {
  const accountId = String(args.nearAccountId || '').trim();
  if (!accountId) throw new Error('Missing nearAccountId for secp256k1 key derivation');

  const prfSecondB64u = String(args.prfSecondB64u || '').trim();
  if (!prfSecondB64u) throw new Error('Missing prfSecondB64u for secp256k1 key derivation');

  const ikm = base64UrlDecode(prfSecondB64u);
  if (ikm.length === 0) throw new Error('Invalid PRF.second: empty after base64url decode');

  const salt = new TextEncoder().encode(`evm-key-derivation:${accountId}`);
  const okm64 = hkdf(sha256, ikm, salt, HKDF_INFO, 64);
  const privateKeyBigint = (bytesToNumberBE(okm64) % (SECP256K1_ORDER - 1n)) + 1n;
  const privateKey = numberToBytesBE(privateKeyBigint, 32);

  const publicKeyCompressed = secp256k1.getPublicKey(privateKey, true);
  const publicKeyUncompressed = secp256k1.getPublicKey(privateKey, false);
  const addressBytes = keccak256(publicKeyUncompressed.slice(1)).slice(-20);

  return {
    privateKeyHex: bytesToHex(privateKey),
    publicKeyHex: bytesToHex(publicKeyCompressed),
    ethereumAddress: bytesToHex(addressBytes),
  };
}
