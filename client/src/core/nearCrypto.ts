import * as ed25519 from '@noble/ed25519';
import bs58 from 'bs58';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { ensureEd25519Prefix } from '../../../shared/src/utils/validation';
import { base64UrlDecode } from '../../../shared/src/utils/encoders';
export { ensureEd25519Prefix };

export const NEAR_ED25519_KEY_PREFIX = 'ed25519:' as const;

/**
 * Remove the NEAR Ed25519 prefix (`ed25519:`) if present.
 * Useful for comparing keys where one side may omit the prefix.
 */
export function stripEd25519Prefix(value: string): string {
  const raw = String(value || '').trim();
  return raw.replace(/^ed25519:/i, '');
}

/**
 * Creates a NEAR-compatible Ed25519 keypair formatted as strings:
 * - publicKey:  'ed25519:' + base58(pub)
 * - privateKey: 'ed25519:' + base58(seed(32) | pub(32))
 */
export async function createNearKeypair(): Promise<{ publicKey: string; privateKey: string }> {
  const seed = ed25519.utils.randomPrivateKey(); // 32 bytes
  const pub = await ed25519.getPublicKeyAsync(seed); // 32 bytes

  const secret = new Uint8Array(64);
  secret.set(seed, 0);
  secret.set(pub, 32);

  const publicKey = ensureEd25519Prefix(bs58.encode(pub));
  const privateKey = ensureEd25519Prefix(bs58.encode(secret));
  return { publicKey, privateKey };
}

/** Parse NEAR public key string ('ed25519:...') into 32-byte Uint8Array */
export function parseNearPublicKey(str: string): Uint8Array {
  const b58 = stripEd25519Prefix(str);
  const bytes = bs58.decode(b58);
  if (bytes.length !== 32) {
    throw new Error(`Invalid NEAR public key length: ${bytes.length}`);
  }
  return new Uint8Array(bytes);
}

/** Convert raw 32-byte public key to NEAR string ('ed25519:...') */
export function toPublicKeyString(pub: Uint8Array): string {
  if (!(pub?.length === 32)) {
    throw new Error('Public key must be 32 bytes');
  }
  return ensureEd25519Prefix(bs58.encode(pub));
}

/** Convert raw seed(32) + pub(32) to NEAR secret string ('ed25519:...') */
export function toSecretKeyString(seed: Uint8Array, pub: Uint8Array): string {
  if (!(seed?.length === 32)) {
    throw new Error('Seed must be 32 bytes');
  }
  if (!(pub?.length === 32)) {
    throw new Error('Public key must be 32 bytes');
  }
  const secret = new Uint8Array(64);
  secret.set(seed, 0);
  secret.set(pub, 32);
  return ensureEd25519Prefix(bs58.encode(secret));
}

/**
 * Deterministically derive a NEAR Ed25519 keypair from a PRF.second output (base64url string).
 *
 * NOTE: This matches the current signer-worker (Rust) derivation:
 * - HKDF-SHA256(ikm=prfSecond, salt="near-key-derivation:<accountId>", info="ed25519-signing-key-dual-prf-v1", len=32)
 * - seed -> Ed25519 keypair
 */
export async function deriveNearKeypairFromPrfSecondB64u(args: {
  prfSecondB64u: string;
  nearAccountId: string;
}): Promise<{ publicKey: string; privateKey: string }> {
  const accountId = String(args.nearAccountId || '').trim();
  if (!accountId) throw new Error('Missing nearAccountId for PRF.second key derivation');

  const prfSecondB64u = String(args.prfSecondB64u || '').trim();
  if (!prfSecondB64u) throw new Error('Missing prfSecondB64u for PRF.second key derivation');

  const ikm = base64UrlDecode(prfSecondB64u);
  if (ikm.length === 0) throw new Error('Invalid PRF.second: empty after base64url decode');

  const saltStr = `near-key-derivation:${accountId}`;
  const infoStr = 'ed25519-signing-key-dual-prf-v1';
  const salt = new TextEncoder().encode(saltStr);
  const info = new TextEncoder().encode(infoStr);

  const seed = hkdf(sha256, ikm, salt, info, 32);
  if (seed.length !== 32) throw new Error(`HKDF derived seed must be 32 bytes, got ${seed.length}`);

  const pub = await ed25519.getPublicKeyAsync(seed);
  const publicKey = ensureEd25519Prefix(bs58.encode(pub));
  const privateKey = toSecretKeyString(seed, pub);
  return { publicKey, privateKey };
}
