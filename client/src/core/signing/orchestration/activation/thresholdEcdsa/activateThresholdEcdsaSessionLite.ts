import { toAccountId } from '../../../../types/accountIds';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../types';
import { connectThresholdEcdsaSessionLite } from '../../../threshold/workflows/connectThresholdEcdsaSessionLite';
import { keygenThresholdEcdsaLite } from '../../../threshold/workflows/keygenThresholdEcdsaLite';
import type {
  ActivateThresholdEcdsaSessionLiteDeps,
  ActivateThresholdEcdsaSessionLiteRequest,
  ThresholdEcdsaKeygenLiteSuccess,
  ThresholdEcdsaSessionBootstrapResult,
  ThresholdEcdsaSessionLiteSuccess,
} from './types';

export async function activateThresholdEcdsaSessionLite(
  deps: ActivateThresholdEcdsaSessionLiteDeps,
  args: ActivateThresholdEcdsaSessionLiteRequest,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const nearAccountId = toAccountId(args.nearAccountId);

  const keygen = await keygenThresholdEcdsaLite({
    indexedDB: deps.indexedDB,
    touchIdPrompt: deps.touchIdPrompt,
    relayerUrl: args.relayerUrl,
    userId: nearAccountId,
    workerCtx: deps.workerCtx,
  });
  if (!keygen.ok) {
    throw new Error(keygen.message || keygen.code || 'threshold-ecdsa keygen failed');
  }

  const relayerKeyId = String(keygen.relayerKeyId || '').trim();
  if (!relayerKeyId) {
    throw new Error('threshold-ecdsa keygen returned empty relayerKeyId');
  }

  const clientVerifyingShareB64u = String(keygen.clientVerifyingShareB64u || '').trim();
  if (!clientVerifyingShareB64u) {
    throw new Error('threshold-ecdsa keygen returned empty clientVerifyingShareB64u');
  }

  const session = await connectThresholdEcdsaSessionLite({
    indexedDB: deps.indexedDB,
    touchIdPrompt: deps.touchIdPrompt,
    prfFirstCache: deps.prfFirstCache,
    relayerUrl: args.relayerUrl,
    relayerKeyId,
    userId: nearAccountId,
    participantIds: args.participantIds || keygen.participantIds,
    sessionKind: args.sessionKind,
    sessionId: deps.getOrCreateActiveSigningSessionId(nearAccountId),
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
    workerCtx: deps.workerCtx,
  });
  if (!session.ok) {
    throw new Error(session.message || session.code || 'threshold-ecdsa session connect failed');
  }

  const thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef = {
    type: 'threshold-ecdsa-secp256k1',
    userId: nearAccountId,
    relayerUrl: args.relayerUrl,
    relayerKeyId,
    clientVerifyingShareB64u,
    ...(Array.isArray(args.participantIds)
      ? { participantIds: args.participantIds }
      : Array.isArray(keygen.participantIds)
        ? { participantIds: keygen.participantIds }
        : {}),
    ...(typeof keygen.groupPublicKeyB64u === 'string' && keygen.groupPublicKeyB64u.trim()
      ? { groupPublicKeyB64u: keygen.groupPublicKeyB64u.trim() }
      : {}),
    ...(typeof keygen.relayerVerifyingShareB64u === 'string' && keygen.relayerVerifyingShareB64u.trim()
      ? { relayerVerifyingShareB64u: keygen.relayerVerifyingShareB64u.trim() }
      : {}),
    thresholdSessionKind: args.sessionKind || 'jwt',
    ...(typeof session.sessionId === 'string' && session.sessionId.trim()
      ? { thresholdSessionId: session.sessionId.trim() }
      : {}),
    ...(typeof session.jwt === 'string' && session.jwt.trim()
      ? { thresholdSessionJwt: session.jwt.trim() }
      : {}),
  };

  return {
    thresholdEcdsaKeyRef,
    keygen: keygen as ThresholdEcdsaKeygenLiteSuccess,
    session: session as ThresholdEcdsaSessionLiteSuccess,
  };
}
