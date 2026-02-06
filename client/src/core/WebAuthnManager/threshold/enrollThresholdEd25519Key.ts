import { toAccountId, type AccountId } from '../../types/accountIds';
import { thresholdEd25519Keygen } from '../../rpcCalls';
import { ensureEd25519Prefix } from '../../../../../shared/src/utils/validation';
import type { TouchIdPrompt } from '../touchIdPrompt';
import type { WebAuthnAuthenticationCredential } from '../../types/webauthn';

type DeriveThresholdClientShareResult = {
  success: boolean;
  clientVerifyingShareB64u: string;
  error?: string;
};

export type EnrollThresholdEd25519KeyHandlerContext = {
  signerWorkerManager: {
    deriveThresholdEd25519ClientVerifyingShare: (args: {
      sessionId: string;
      nearAccountId: AccountId;
      prfFirstB64u: string;
      wrapKeySalt: string;
    }) => Promise<DeriveThresholdClientShareResult>;
  };
  touchIdPrompt: Pick<TouchIdPrompt, 'getRpId'>;
  relayerUrl: string;
};

/**
 * Threshold keygen helper (2-of-2):
 * - derive deterministic client verifying share from WrapKeySeed (via signer worker session)
 * - run `/threshold-ed25519/keygen` to fetch relayer share + group public key
 */
export async function enrollThresholdEd25519KeyHandler(
  ctx: EnrollThresholdEd25519KeyHandlerContext,
  args: {
    sessionId: string;
    nearAccountId: AccountId | string;
    webauthnAuthentication: WebAuthnAuthenticationCredential;
    prfFirstB64u: string;
    wrapKeySalt: string;
    keygenSessionId?: string;
  }
): Promise<{
  success: boolean;
  publicKey: string;
  clientParticipantId?: number;
  relayerParticipantId?: number;
  participantIds?: number[];
  clientVerifyingShareB64u: string;
  relayerKeyId: string;
  relayerVerifyingShareB64u: string;
  error?: string;
}> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const sessionId = String(args.sessionId || '').trim();
  const relayerUrl = String(ctx.relayerUrl || '').trim();

  try {
    if (!sessionId) throw new Error('Missing sessionId');
    if (!relayerUrl) throw new Error('Missing relayer url (configs.relayer.url)');
    if (!args.webauthnAuthentication) throw new Error('Missing webauthnAuthentication for threshold keygen');
    if (!args.prfFirstB64u) throw new Error('Missing PRF.first output for threshold keygen');
    if (!args.wrapKeySalt) throw new Error('Missing wrapKeySalt for threshold keygen');

    const derived = await ctx.signerWorkerManager.deriveThresholdEd25519ClientVerifyingShare({
      sessionId,
      nearAccountId,
      prfFirstB64u: args.prfFirstB64u,
      wrapKeySalt: args.wrapKeySalt,
    });
    if (!derived.success) {
      throw new Error(derived.error || 'Failed to derive threshold client verifying share');
    }

    const rpId = ctx.touchIdPrompt.getRpId();
    if (!rpId) throw new Error('Missing rpId for WebAuthn keygen challenge');

    const keygenSessionId = String((args.keygenSessionId || sessionId) ?? '').trim();
    if (!keygenSessionId) throw new Error('Missing keygenSessionId for threshold keygen');

    const keygen = await thresholdEd25519Keygen(relayerUrl, {
      clientVerifyingShareB64u: derived.clientVerifyingShareB64u,
      nearAccountId,
      rpId,
      keygenSessionId,
      webauthnAuthentication: args.webauthnAuthentication,
    });
    if (!keygen.ok) {
      throw new Error(keygen.error || keygen.message || keygen.code || 'Threshold keygen failed');
    }

    const publicKeyRaw = keygen.publicKey;
    const relayerKeyId = keygen.relayerKeyId;
    const relayerVerifyingShareB64u = keygen.relayerVerifyingShareB64u;
    if (!publicKeyRaw) throw new Error('Threshold keygen returned empty publicKey');
    if (!relayerKeyId) throw new Error('Threshold keygen returned empty relayerKeyId');
    if (!relayerVerifyingShareB64u) throw new Error('Threshold keygen returned empty relayerVerifyingShareB64u');

    const publicKey = ensureEd25519Prefix(publicKeyRaw);
    if (!publicKey) throw new Error('Threshold keygen returned empty publicKey');

    const clientParticipantId = typeof keygen.clientParticipantId === 'number' ? keygen.clientParticipantId : undefined;
    const relayerParticipantId = typeof keygen.relayerParticipantId === 'number' ? keygen.relayerParticipantId : undefined;

    return {
      success: true,
      publicKey,
      clientParticipantId,
      relayerParticipantId,
      participantIds: Array.isArray(keygen.participantIds) ? keygen.participantIds : undefined,
      clientVerifyingShareB64u: derived.clientVerifyingShareB64u,
      relayerKeyId,
      relayerVerifyingShareB64u,
    };
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return { success: false, publicKey: '', clientVerifyingShareB64u: '', relayerKeyId: '', relayerVerifyingShareB64u: '', error: message };
  }
}
