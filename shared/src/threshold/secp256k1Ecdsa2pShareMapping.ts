import { SECP256K1_ORDER } from './secp256k1';

function bytesToBigIntBE(bytes: Uint8Array): bigint {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) + BigInt(b);
  return n;
}

function bigIntTo32BytesBE(n: bigint): Uint8Array {
  if (n < 0n) throw new Error('expected non-negative bigint');
  const out = new Uint8Array(32);
  let x = n;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function modInv(a: bigint, m: bigint): bigint {
  // Extended Euclidean Algorithm.
  let t = 0n;
  let newT = 1n;
  let r = m;
  let newR = mod(a, m);

  while (newR !== 0n) {
    const q = r / newR;
    [t, newT] = [newT, t - q * newT];
    [r, newR] = [newR, r - q * newR];
  }

  if (r !== 1n) {
    throw new Error('modular inverse does not exist');
  }
  return mod(t, m);
}

export const THRESHOLD_SECP256K1_ECDSA_2P_PARTICIPANTS_V1 = Object.freeze({
  clientId: 1,
  relayerId: 2,
  participantIds: [1, 2] as const,
});

/**
 * Map our deterministic additive 2P shares into the Shamir-style share encoding expected by
 * `near/threshold-signatures`, for the fixed signer set `{client=1, relayer=2}`.
 *
 * Rationale:
 * - `threshold-signatures` "linearizes" shares using Lagrange coefficients `λ_i` at 0, computed
 *   from participant ids.
 * - For ids `{1,2}`, `threshold-signatures` uses x-coordinates `{2,3}` (it maps `id -> id+1`).
 * - The corresponding Lagrange coefficients at 0 are `λ_client = 3` and `λ_relayer = -2`.
 * - We feed `share_i = additive_i * inv(λ_i)` so that linearization recovers the original additive
 *   shares and the combined secret remains `x_client + x_relayer (mod n)`.
 */
export function mapAdditiveShareToThresholdSignaturesShare2p(args: {
  additiveShare32: Uint8Array;
  participantId: number;
}): Uint8Array {
  if (args.additiveShare32.length !== 32) throw new Error('additiveShare32 must be 32 bytes');
  const participantId = Number(args.participantId);
  const lambda = (() => {
    if (participantId === THRESHOLD_SECP256K1_ECDSA_2P_PARTICIPANTS_V1.clientId) return 3n;
    if (participantId === THRESHOLD_SECP256K1_ECDSA_2P_PARTICIPANTS_V1.relayerId) return -2n;
    throw new Error(`unsupported participantId for 2P mapping: ${participantId}`);
  })();

  const x = bytesToBigIntBE(args.additiveShare32);
  if (x <= 0n || x >= SECP256K1_ORDER) throw new Error('additive share must be in (0, n)');

  const invLambda = modInv(lambda, SECP256K1_ORDER);
  const mapped = mod(x * invLambda, SECP256K1_ORDER);
  if (mapped === 0n) throw new Error('mapped share is zero (unexpected)');
  return bigIntTo32BytesBE(mapped);
}

