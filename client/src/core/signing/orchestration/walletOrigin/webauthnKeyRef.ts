import type { UnifiedIndexedDBManager } from '../../../IndexedDBManager';
import { toAccountId } from '../../../types/accountIds';
import { base64UrlDecode } from '../../../../../../shared/src/utils/base64';
import type { KeyRef } from '../types';
import { coseP256PublicKeyToXY } from '../../webauthn/cose/coseP256';

export async function resolveWebAuthnP256KeyRefForNearAccount(args: {
  indexedDB: UnifiedIndexedDBManager;
  nearAccountId: string;
  rpId?: string;
}): Promise<KeyRef & { type: 'webauthnP256' }> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const context = await args.indexedDB.clientDB.resolveNearAccountContext(nearAccountId);
  if (!context?.profileId) {
    throw new Error(`[multichain] no profile/account mapping found for account ${nearAccountId}`);
  }

  const authenticators = await args.indexedDB.clientDB.listProfileAuthenticators(context.profileId);
  if (!authenticators.length) {
    throw new Error(`[multichain] no passkeys found for account ${nearAccountId}`);
  }

  const { authenticatorsForPrompt } =
    await args.indexedDB.clientDB.selectProfileAuthenticatorsForPrompt({
      profileId: context.profileId,
      authenticators,
      accountLabel: nearAccountId,
    });
  const auth = authenticatorsForPrompt[0];
  if (!auth) {
    throw new Error(`[multichain] missing authenticator for account ${nearAccountId}`);
  }

  const { x, y } = coseP256PublicKeyToXY(auth.credentialPublicKey);
  const credentialId = base64UrlDecode(auth.credentialId);
  if (credentialId.length === 0) {
    throw new Error('[multichain] invalid credentialId for authenticator');
  }

  return {
    type: 'webauthnP256',
    credentialId,
    pubKeyX: x,
    pubKeyY: y,
    rpId: args.rpId,
  };
}
