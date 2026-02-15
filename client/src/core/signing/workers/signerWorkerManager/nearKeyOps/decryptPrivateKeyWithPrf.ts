
import { ClientAuthenticatorData } from '../../../../IndexedDBManager';
import {
  WorkerRequestType,
  isDecryptPrivateKeyWithPrfSuccess,
} from '../../../../types/signer-worker';
import { AccountId, toAccountId } from "../../../../types/accountIds";

import { SignerWorkerManagerContext } from '..';
import { getLastLoggedInDeviceNumber } from '../getDeviceNumber';
import { isObject } from '../../../../../../../shared/src/utils/validation';
import { withSessionId } from '../internal/session';

export async function decryptPrivateKeyWithPrf({
  ctx,
  nearAccountId,
  authenticators,
  sessionId,
  prfFirstB64u,
  wrapKeySalt,
  encryptedPrivateKeyData,
  encryptedPrivateKeyChacha20NonceB64u,
  deviceNumber,
}: {
  ctx: SignerWorkerManagerContext,
  nearAccountId: AccountId,
  authenticators: ClientAuthenticatorData[],
  sessionId: string,
  prfFirstB64u?: string;
  wrapKeySalt?: string;
  encryptedPrivateKeyData?: string;
  encryptedPrivateKeyChacha20NonceB64u?: string;
  deviceNumber?: number;
}): Promise<{ decryptedPrivateKey: string; nearAccountId: AccountId }> {
  try {
    console.info('WebAuthnManager: Starting private key decryption with dual PRF (local operation)');
    const explicitEncryptedSk = String(encryptedPrivateKeyData || '').trim();
    const explicitNonce = String(encryptedPrivateKeyChacha20NonceB64u || '').trim();
    if ((explicitEncryptedSk && !explicitNonce) || (!explicitEncryptedSk && explicitNonce)) {
      throw new Error(
        'Both encryptedPrivateKeyData and encryptedPrivateKeyChacha20NonceB64u must be provided together',
      );
    }

    let encryptedSk = explicitEncryptedSk;
    let chacha20NonceB64u = explicitNonce;
    let resolvedWrapKeySalt = String(wrapKeySalt || '').trim();

    if (!encryptedSk || !chacha20NonceB64u) {
      // Retrieve encrypted key data from IndexedDB in main thread only when explicit
      // encrypted payload was not provided by caller.
      const resolvedDeviceNumber = Number.isSafeInteger(deviceNumber) && Number(deviceNumber) >= 1
        ? Number(deviceNumber)
        : await getLastLoggedInDeviceNumber(nearAccountId, ctx.indexedDB.clientDB);
      const keyMaterial = await ctx.indexedDB.getNearLocalKeyMaterialV2First(
        nearAccountId,
        resolvedDeviceNumber,
      );
      if (!keyMaterial) {
        throw new Error(`No key material found for account: ${nearAccountId}`);
      }
      encryptedSk = String(keyMaterial.encryptedSk || '').trim();
      chacha20NonceB64u = String(keyMaterial.chacha20NonceB64u || '').trim();
      if (!resolvedWrapKeySalt) {
        resolvedWrapKeySalt = String(keyMaterial.wrapKeySalt || '').trim();
      }
    }

    if (!encryptedSk || !chacha20NonceB64u) {
      throw new Error('Missing encrypted private key payload for private key decryption');
    }

    const prfFirst = String(prfFirstB64u || '').trim();
    const wrapKeySaltB64u = resolvedWrapKeySalt;
    if (!prfFirst) {
      throw new Error('Missing PRF.first output for private key decryption');
    }
    if (!wrapKeySaltB64u) {
      throw new Error('Missing wrapKeySalt for private key decryption');
    }

    const response = await ctx.requestWorkerOperation({
      kind: 'nearSigner',
      request: {
        sessionId,
        type: WorkerRequestType.DecryptPrivateKeyWithPrf,
        payload: withSessionId(sessionId, {
          nearAccountId: nearAccountId,
          encryptedPrivateKeyData: encryptedSk,
          encryptedPrivateKeyChacha20NonceB64u: chacha20NonceB64u,
          prfFirstB64u: prfFirst,
          wrapKeySalt: wrapKeySaltB64u,
        }),
      },
    });

    if (!isDecryptPrivateKeyWithPrfSuccess(response)) {
      console.error('WebAuthnManager: Dual PRF private key decryption failed:', response);
      const payloadError = isObject(response?.payload) && (response as any)?.payload?.error;
      throw new Error(payloadError || 'Private key decryption failed');
    }
    return {
      decryptedPrivateKey: response.payload.privateKey,
      nearAccountId: toAccountId(response.payload.nearAccountId)
    };
  } catch (error: unknown) {
    console.error('WebAuthnManager: Dual PRF private key decryption error:', error);
    throw error;
  }
}
