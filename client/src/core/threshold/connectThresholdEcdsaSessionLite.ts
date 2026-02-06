import type { UnifiedIndexedDBManager } from '../IndexedDBManager';
import type { TouchIdPrompt } from '../WebAuthnManager/touchIdPrompt';
import type { SignerWorkerManager } from '../WebAuthnManager/SignerWorkerManager';
import { collectAuthenticationCredentialForChallengeB64u } from '../WebAuthnManager/collectAuthenticationCredentialForChallengeB64u';
import { buildThresholdEcdsaSessionPolicy } from './thresholdSessionPolicy';
import { deriveThresholdSecp256k1ClientShare } from './deriveThresholdSecp256k1ClientShare';
import {
  makeThresholdEcdsaAuthSessionCacheKey,
  mintThresholdEcdsaAuthSessionLite,
  putCachedThresholdEcdsaAuthSession,
} from './thresholdEcdsaAuthSession';
import type { ThresholdEcdsaSessionKind } from './thresholdEcdsaAuthSession';

function getPrfFirstB64uFromCredential(credential: unknown): string | null {
  try {
    const b64u = (credential as any)?.clientExtensionResults?.prf?.results?.first;
    if (typeof b64u !== 'string') return null;
    const trimmed = b64u.trim();
    return trimmed ? trimmed : null;
  } catch {
    return null;
  }
}

/**
 * Wallet-origin helper:
 * - build a threshold session policy (and digest)
 * - collect a WebAuthn assertion with challenge = `sessionPolicyDigest32`
 * - derive `clientVerifyingShareB64u` from PRF.first (client-side HKDF, secp256k1)
 * - mint a relay threshold session token via `POST /threshold-ecdsa/session` (lite)
 *
 * Notes:
 * - This function is intentionally standard-WebAuthn (no contract verifier).
 * - The WebAuthn credential sent to the relay is PRF-redacted in `mintThresholdEcdsaAuthSessionLite`.
 */
export async function connectThresholdEcdsaSessionLite(args: {
  indexedDB: UnifiedIndexedDBManager;
  touchIdPrompt: TouchIdPrompt;
  signerWorkerManager: SignerWorkerManager;
  relayerUrl: string;
  relayerKeyId: string;
  userId: string;
  participantIds?: number[];
  sessionKind?: ThresholdEcdsaSessionKind;
  sessionId?: string;
  ttlMs?: number;
  remainingUses?: number;
}): Promise<{
  ok: boolean;
  sessionId?: string;
  expiresAtMs?: number;
  remainingUses?: number;
  jwt?: string;
  clientVerifyingShareB64u?: string;
  code?: string;
  message?: string;
}> {
  const sessionKind: ThresholdEcdsaSessionKind = args.sessionKind || 'jwt';
  const rpId = args.touchIdPrompt.getRpId();
  if (!rpId) {
    return { ok: false, code: 'invalid_args', message: 'Missing rpId for WebAuthn' };
  }

  const userId = String(args.userId || '').trim();
  if (!userId) {
    return { ok: false, code: 'invalid_args', message: 'Missing userId' };
  }

  const { policy, policyJson, sessionPolicyDigest32 } = await buildThresholdEcdsaSessionPolicy({
    userId,
    rpId,
    relayerKeyId: args.relayerKeyId,
    participantIds: args.participantIds,
    sessionId: args.sessionId,
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
  });

  // 1) Collect WebAuthn assertion for challenge=sessionPolicyDigest32 and include PRF outputs.
  const credential = await collectAuthenticationCredentialForChallengeB64u({
    indexedDB: args.indexedDB,
    touchIdPrompt: args.touchIdPrompt,
    nearAccountId: userId,
    challengeB64u: sessionPolicyDigest32,
  });

  const prfFirstB64u = getPrfFirstB64uFromCredential(credential);
  if (!prfFirstB64u) {
    return { ok: false, code: 'unsupported', message: 'Missing PRF.first output from credential (requires a PRF-enabled passkey)' };
  }

  // 2) Derive client verifying share locally (never send PRF output).
  let clientVerifyingShareB64u: string;
  try {
    clientVerifyingShareB64u = deriveThresholdSecp256k1ClientShare({
      prfFirstB64u,
      userId,
    }).clientVerifyingShareB64u;
  } catch (e: unknown) {
    const msg = String((e && typeof e === 'object' && 'message' in e) ? (e as { message?: unknown }).message : e || 'Failed to derive client verifying share');
    return { ok: false, code: 'internal', message: msg };
  }

  // 3) Mint threshold auth session token/cookie with standard WebAuthn verification.
  const minted = await mintThresholdEcdsaAuthSessionLite({
    relayerUrl: args.relayerUrl,
    sessionKind,
    relayerKeyId: args.relayerKeyId,
    clientVerifyingShareB64u,
    sessionPolicy: policy,
    webauthnAuthentication: credential,
  });
  if (!minted.ok) {
    return minted;
  }

  // Cache PRF.first in-memory for the session TTL/uses window so subsequent signing can
  // dispense the client share seed without prompting again (wallet-origin only).
  const sessionId = policy.sessionId;
  const expiresAtMs = minted.expiresAtMs ?? (Date.now() + policy.ttlMs);
  const remainingUses = minted.remainingUses ?? policy.remainingUses;
  const secureConfirmWorkerManager = args.signerWorkerManager.getContext().secureConfirmWorkerManager;
  if (secureConfirmWorkerManager) {
    await secureConfirmWorkerManager.putPrfFirstForThresholdSession({
      sessionId,
      prfFirstB64u,
      expiresAtMs,
      remainingUses,
    }).catch(() => {});
  }

  // 4) Cache for on-demand `/threshold-ecdsa/authorize` usage.
  const cacheKey = makeThresholdEcdsaAuthSessionCacheKey({
    userId,
    rpId,
    relayerUrl: args.relayerUrl,
    relayerKeyId: args.relayerKeyId,
    participantIds: args.participantIds,
  });
  putCachedThresholdEcdsaAuthSession(cacheKey, {
    sessionKind,
    policy,
    policyJson,
    sessionPolicyDigest32,
    jwt: minted.jwt,
    expiresAtMs,
  });

  return {
    ok: true,
    sessionId: minted.sessionId,
    expiresAtMs,
    remainingUses,
    jwt: minted.jwt,
    clientVerifyingShareB64u,
  };
}

