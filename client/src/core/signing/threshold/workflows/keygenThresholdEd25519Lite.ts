import { base64UrlEncode } from '../../../../../../shared/src/utils/encoders';
import { computeThresholdEd25519KeygenIntentDigest } from '../../../../utils/intentDigest';
import { thresholdEd25519Keygen } from '../../../near/rpcCalls';
import { toAccountId } from '../../../types/accountIds';
import {
  collectAuthenticationCredentialForChallengeB64u,
  getPrfFirstB64uFromCredential,
  type ThresholdEd25519ClientShareDeriverPort,
  type ThresholdIndexedDbPort,
  type ThresholdWebAuthnPromptPort,
} from '../ports/webauthn';

const DUMMY_WRAP_KEY_SALT_B64U = base64UrlEncode(new Uint8Array(32));

function generateKeygenSessionId(): string {
  const id = (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function')
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `tkeygen-${id}`;
}

/**
 * Threshold-ed25519 keygen helper (standard WebAuthn).
 *
 * - Collects a WebAuthn assertion (challenge = keygen policy digest)
 * - Uses PRF.first to derive `clientVerifyingShareB64u` in the signer worker
 * - Calls `POST /threshold-ed25519/keygen` (lite) to obtain relayer key material + group public key
 *
 * Notes:
 * - PRF outputs are never sent to the relay.
 * - The derived client share stays inside the signer worker; only public material is returned.
 */
export async function keygenThresholdEd25519Lite(args: {
  indexedDB: ThresholdIndexedDbPort;
  touchIdPrompt: ThresholdWebAuthnPromptPort;
  signerWorkerManager: ThresholdEd25519ClientShareDeriverPort;
  relayerUrl: string;
  nearAccountId: string;
}): Promise<{
  ok: boolean;
  keygenSessionId?: string;
  rpId?: string;
  clientVerifyingShareB64u?: string;
  publicKey?: string;
  relayerKeyId?: string;
  relayerVerifyingShareB64u?: string;
  clientParticipantId?: number;
  relayerParticipantId?: number;
  participantIds?: number[];
  code?: string;
  message?: string;
}> {
  const rpId = args.touchIdPrompt.getRpId();
  if (!rpId) return { ok: false, code: 'invalid_args', message: 'Missing rpId for WebAuthn' };

  const keygenSessionId = generateKeygenSessionId();
  const challengeB64u = await computeThresholdEd25519KeygenIntentDigest({
    nearAccountId: args.nearAccountId,
    rpId,
    keygenSessionId,
  });

  // 1) Collect WebAuthn assertion with PRF outputs enabled.
  const credential = await collectAuthenticationCredentialForChallengeB64u({
    indexedDB: args.indexedDB,
    touchIdPrompt: args.touchIdPrompt,
    nearAccountId: args.nearAccountId,
    challengeB64u,
  });

  const prfFirstB64u = getPrfFirstB64uFromCredential(credential);
  if (!prfFirstB64u) {
    return { ok: false, code: 'unsupported', message: 'Missing PRF.first output from credential (requires a PRF-enabled passkey)' };
  }

  // 2) Derive the client verifying share inside the signer worker.
  try {
    const derived = await args.signerWorkerManager.deriveThresholdEd25519ClientVerifyingShare({
      sessionId: keygenSessionId,
      nearAccountId: toAccountId(args.nearAccountId),
      prfFirstB64u,
      wrapKeySalt: DUMMY_WRAP_KEY_SALT_B64U,
    });
    if (!derived.success) {
      return { ok: false, code: 'internal', message: derived.error || 'Failed to derive client verifying share' };
    }

    // 3) Keygen with the relay.
    const keygen = await thresholdEd25519Keygen(args.relayerUrl, {
      nearAccountId: args.nearAccountId,
      rpId,
      keygenSessionId,
      clientVerifyingShareB64u: derived.clientVerifyingShareB64u,
      webauthnAuthentication: credential,
    });
    if (!keygen.ok) {
      return {
        ok: false,
        code: keygen.code || 'keygen_failed',
        message: keygen.error || keygen.message || 'Threshold keygen failed',
      };
    }

    return {
      ok: true,
      keygenSessionId,
      rpId,
      clientVerifyingShareB64u: derived.clientVerifyingShareB64u,
      publicKey: keygen.publicKey,
      relayerKeyId: keygen.relayerKeyId,
      relayerVerifyingShareB64u: keygen.relayerVerifyingShareB64u,
      clientParticipantId: keygen.clientParticipantId,
      relayerParticipantId: keygen.relayerParticipantId,
      participantIds: keygen.participantIds,
      ...(keygen.code ? { code: keygen.code } : {}),
      ...(keygen.message ? { message: keygen.message } : {}),
    };
  } catch (e: unknown) {
    const msg = (e && typeof e === 'object' && 'message' in e) ? String((e as any).message || 'keygen failed') : String(e || 'keygen failed');
    return { ok: false, code: 'internal', message: msg };
  }
}
