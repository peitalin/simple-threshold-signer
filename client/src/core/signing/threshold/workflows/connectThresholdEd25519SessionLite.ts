import { base64UrlEncode } from '../../../../../../shared/src/utils/encoders';
import { toAccountId } from '../../../types/accountIds';
import {
  collectAuthenticationCredentialForChallengeB64u,
  getPrfFirstB64uFromCredential,
  getThresholdPrfFirstCachePortFromSignerWorker,
  type ThresholdIndexedDbPort,
  type ThresholdPrfFirstCachePort,
  type ThresholdSignerWorkerPort,
  type ThresholdWebAuthnPromptPort,
} from '../ports/webauthn';
import { buildThresholdSessionPolicy } from '../session/thresholdSessionPolicy';
import {
  makeThresholdEd25519AuthSessionCacheKey,
  mintThresholdEd25519AuthSessionLite,
  putCachedThresholdEd25519AuthSession,
} from '../session/thresholdEd25519AuthSession';
import type { ThresholdEd25519SessionKind } from '../session/thresholdEd25519AuthSession';

const DUMMY_WRAP_KEY_SALT_B64U = base64UrlEncode(new Uint8Array(32));

/**
 * Wallet-origin helper:
 * - build a threshold session policy (and digest)
 * - collect a WebAuthn assertion with challenge = `sessionPolicyDigest32`
 * - extract `PRF.first` (base64url) and derive `clientVerifyingShareB64u` via the signer worker
 * - mint a relay threshold session token via `POST /threshold-ed25519/session` (lite)
 *
 * Notes:
 * - This function is intentionally standard-WebAuthn (no contract verifier).
 * - The WebAuthn credential sent to the relay is PRF-redacted in `mintThresholdEd25519AuthSessionLite`.
 */
export async function connectThresholdEd25519SessionLite(args: {
  indexedDB: ThresholdIndexedDbPort;
  touchIdPrompt: ThresholdWebAuthnPromptPort;
  signerWorkerManager: ThresholdSignerWorkerPort;
  prfFirstCache?: ThresholdPrfFirstCachePort;
  relayerUrl: string;
  relayerKeyId: string;
  nearAccountId: string;
  participantIds?: number[];
  sessionKind?: ThresholdEd25519SessionKind;
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
  const sessionKind: ThresholdEd25519SessionKind = args.sessionKind || 'jwt';
  const rpId = args.touchIdPrompt.getRpId();
  if (!rpId) {
    return { ok: false, code: 'invalid_args', message: 'Missing rpId for WebAuthn' };
  }

  const { policy, policyJson, sessionPolicyDigest32 } = await buildThresholdSessionPolicy({
    nearAccountId: args.nearAccountId,
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
    nearAccountId: args.nearAccountId,
    challengeB64u: sessionPolicyDigest32,
  });

  const prfFirstB64u = getPrfFirstB64uFromCredential(credential);
  if (!prfFirstB64u) {
    return { ok: false, code: 'unsupported', message: 'Missing PRF.first output from credential (requires a PRF-enabled passkey)' };
  }

  // 2) Derive client verifying share using the signer worker (share stays inside the worker).
  const sessionId = policy.sessionId;
  const derive = await args.signerWorkerManager.deriveThresholdEd25519ClientVerifyingShare({
    sessionId,
    nearAccountId: toAccountId(args.nearAccountId),
    prfFirstB64u,
    wrapKeySalt: DUMMY_WRAP_KEY_SALT_B64U,
  });
  if (!derive.success) {
    return { ok: false, code: 'internal', message: derive.error || 'Failed to derive client verifying share' };
  }
  const clientVerifyingShareB64u = derive.clientVerifyingShareB64u;

  // 3) Mint threshold auth session token/cookie with standard WebAuthn verification.
  const minted = await mintThresholdEd25519AuthSessionLite({
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
  const expiresAtMs = minted.expiresAtMs ?? (Date.now() + policy.ttlMs);
  const remainingUses = minted.remainingUses ?? policy.remainingUses;
  const prfFirstCache =
    args.prfFirstCache || getThresholdPrfFirstCachePortFromSignerWorker(args.signerWorkerManager);
  if (prfFirstCache) {
    await prfFirstCache.putPrfFirstForThresholdSession({
      sessionId,
      prfFirstB64u,
      expiresAtMs,
      remainingUses,
    }).catch(() => {});
  }

  // 4) Cache for on-demand `/threshold-ed25519/authorize` usage.
  const cacheKey = makeThresholdEd25519AuthSessionCacheKey({
    nearAccountId: args.nearAccountId,
    rpId,
    relayerUrl: args.relayerUrl,
    relayerKeyId: args.relayerKeyId,
    participantIds: args.participantIds,
  });
  putCachedThresholdEd25519AuthSession(cacheKey, {
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
