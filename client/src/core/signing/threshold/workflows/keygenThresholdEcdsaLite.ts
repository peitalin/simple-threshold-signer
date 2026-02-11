import { computeThresholdEcdsaKeygenIntentDigest } from '../../../../utils/intentDigest';
import { thresholdEcdsaKeygen } from '../../../near/rpcCalls';
import { deriveThresholdSecp256k1ClientShareWasm } from '../../chains/evm/ethSignerWasm';
import {
  collectAuthenticationCredentialForChallengeB64u,
  getPrfFirstB64uFromCredential,
  type ThresholdIndexedDbPort,
  type ThresholdWebAuthnPromptPort,
} from '../ports/webauthn';

function generateKeygenSessionId(): string {
  const id = (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function')
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `tecdsa-keygen-${id}`;
}

/**
 * Threshold-ecdsa (secp256k1) keygen helper (standard WebAuthn).
 *
 * - Collects a WebAuthn assertion (challenge = keygen policy digest)
 * - Uses PRF.first to derive `clientVerifyingShareB64u` deterministically (HKDF in eth-signer WASM worker)
 * - Calls `POST /threshold-ecdsa/keygen` to obtain relayer key material + group public key
 *
 * Notes:
 * - PRF outputs are never sent to the relay.
 */
export async function keygenThresholdEcdsaLite(args: {
  indexedDB: ThresholdIndexedDbPort;
  touchIdPrompt: ThresholdWebAuthnPromptPort;
  relayerUrl: string;
  userId: string;
}): Promise<{
  ok: boolean;
  keygenSessionId?: string;
  rpId?: string;
  clientVerifyingShareB64u?: string;
  groupPublicKeyB64u?: string;
  ethereumAddress?: string;
  relayerKeyId?: string;
  relayerVerifyingShareB64u?: string;
  participantIds?: number[];
  code?: string;
  message?: string;
}> {
  const rpId = args.touchIdPrompt.getRpId();
  if (!rpId) return { ok: false, code: 'invalid_args', message: 'Missing rpId for WebAuthn' };

  const userId = String(args.userId || '').trim();
  if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };

  const keygenSessionId = generateKeygenSessionId();
  const challengeB64u = await computeThresholdEcdsaKeygenIntentDigest({
    userId,
    rpId,
    keygenSessionId,
  });

  // 1) Collect WebAuthn assertion with PRF outputs enabled.
  const credential = await collectAuthenticationCredentialForChallengeB64u({
    indexedDB: args.indexedDB,
    touchIdPrompt: args.touchIdPrompt,
    nearAccountId: userId,
    challengeB64u,
  });

  const prfFirstB64u = getPrfFirstB64uFromCredential(credential);
  if (!prfFirstB64u) {
    return { ok: false, code: 'unsupported', message: 'Missing PRF.first output from credential (requires a PRF-enabled passkey)' };
  }

  try {
    // 2) Derive the client verifying share deterministically (never send PRF output).
    const derived = await deriveThresholdSecp256k1ClientShareWasm({
      prfFirstB64u,
      userId,
    });

    // 3) Keygen with the relay.
    const keygen = await thresholdEcdsaKeygen(args.relayerUrl, {
      userId,
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
      groupPublicKeyB64u: keygen.groupPublicKeyB64u,
      ethereumAddress: keygen.ethereumAddress,
      relayerKeyId: keygen.relayerKeyId,
      relayerVerifyingShareB64u: keygen.relayerVerifyingShareB64u,
      participantIds: keygen.participantIds,
      ...(keygen.code ? { code: keygen.code } : {}),
      ...(keygen.message ? { message: keygen.message } : {}),
    };
  } catch (e: unknown) {
    const msg = (e && typeof e === 'object' && 'message' in e) ? String((e as any).message || 'keygen failed') : String(e || 'keygen failed');
    return { ok: false, code: 'internal', message: msg };
  }
}
