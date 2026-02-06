import type { UnifiedIndexedDBManager } from '../../IndexedDBManager';
import { toAccountId } from '../../types/accountIds';
import { base64UrlDecode } from '../../../../../shared/src/utils/base64';
import type { KeyRef } from '../types';
import { coseP256PublicKeyToXY } from '../webauthn/coseP256';

export async function resolveWebAuthnP256KeyRefForNearAccount(args: {
  indexedDB: UnifiedIndexedDBManager;
  nearAccountId: string;
  rpId?: string;
}): Promise<KeyRef & { type: 'webauthn-p256' }> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const authenticators = await args.indexedDB.clientDB.getAuthenticatorsByUser(nearAccountId);
  if (!authenticators.length) {
    throw new Error(`[multichain] no passkeys found for account ${nearAccountId}`);
  }

  let authenticatorsForPrompt = authenticators;
  ({ authenticatorsForPrompt } = await args.indexedDB.clientDB.ensureCurrentPasskey(nearAccountId, authenticators));
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
    type: 'webauthn-p256',
    credentialId,
    pubKeyX: x,
    pubKeyY: y,
    rpId: args.rpId,
  };
}

