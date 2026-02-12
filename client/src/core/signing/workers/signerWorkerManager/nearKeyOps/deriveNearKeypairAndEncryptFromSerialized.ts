
import type { AuthenticatorOptions } from '../../../../types/authenticatorOptions';
import {
  WorkerRequestType,
  isDeriveNearKeypairAndEncryptSuccess,
} from '../../../../types/signer-worker';
import { AccountId, toAccountId } from "../../../../types/accountIds";
import { getLastLoggedInDeviceNumber } from '../getDeviceNumber';
import { SignerWorkerManagerContext } from '..';
import type { WebAuthnRegistrationCredential } from '../../../../types/webauthn';
import { toEnumUserVerificationPolicy } from '../../../../types/authenticatorOptions';
import { withSessionId } from '../internal/session';
import { base64UrlEncode } from '../../../../../../../shared/src/utils/encoders';

/**
 * Derive NEAR keypair and encrypt it from a serialized WebAuthn registration credential
 * (shape compatible with SerializedRegistrationCredential from WASM) by extracting PRF outputs from it.
 */
export async function deriveNearKeypairAndEncryptFromSerialized({
  ctx,
  credential,
  nearAccountId,
  options,
  sessionId,
}: {
  ctx: SignerWorkerManagerContext,
  credential: WebAuthnRegistrationCredential;
  nearAccountId: AccountId,
  options?: {
    authenticatorOptions?: AuthenticatorOptions;
    deviceNumber?: number;
    persistToDb?: boolean;
  };
  sessionId: string;
}): Promise<{
  success: boolean;
  nearAccountId: AccountId;
  publicKey: string;
  /**
   * Base64url-encoded AEAD nonce (ChaCha20-Poly1305) for the encrypted private key.
   */
  chacha20NonceB64u?: string;
  wrapKeySalt?: string;
  encryptedSk?: string;
  error?: string;
}> {
  try {
    if (!sessionId) throw new Error('Missing sessionId for registration request');

    const prfResults = (credential as any)?.clientExtensionResults?.prf?.results as
      | { first?: string; second?: string }
      | undefined;
    const prfFirstB64u = typeof prfResults?.first === 'string' ? prfResults.first.trim() : '';
    const prfSecondB64u = typeof prfResults?.second === 'string' ? prfResults.second.trim() : '';
    if (!prfFirstB64u || !prfSecondB64u) {
      throw new Error('Dual PRF outputs required for registration (PRF.first + PRF.second)');
    }

    const wrapKeySalt = (() => {
      const bytes = new Uint8Array(32);
      crypto.getRandomValues(bytes);
      return base64UrlEncode(bytes);
    })();

    const response = await ctx.requestWorkerOperation({
      kind: 'nearSigner',
      request: {
        sessionId,
        type: WorkerRequestType.DeriveNearKeypairAndEncrypt,
        payload: withSessionId(sessionId, {
          nearAccountId: nearAccountId,
          credential,
          authenticatorOptions: options?.authenticatorOptions ? {
            userVerification: toEnumUserVerificationPolicy(options.authenticatorOptions.userVerification),
            originPolicy: options.authenticatorOptions.originPolicy,
          } : undefined,
          prfFirstB64u,
          wrapKeySalt,
          prfSecondB64u,
        }),
      },
    });

    if (!isDeriveNearKeypairAndEncryptSuccess(response)) {
      throw new Error('Dual PRF registration (from serialized) failed');
    }

    const wasmResult = response.payload;
    const wrapKeySaltPersisted = wasmResult.wrapKeySalt;
    if (!wrapKeySaltPersisted) {
      throw new Error('Missing wrapKeySalt in deriveNearKeypairAndEncrypt result');
    }
    const chacha20NonceB64u = wasmResult.chacha20NonceB64u;
    if (!chacha20NonceB64u) {
      throw new Error('Missing chacha20NonceB64u in deriveNearKeypairAndEncrypt result');
    }
    const encryptedSk = String(wasmResult.encryptedData || '').trim();
    if (!encryptedSk) {
      throw new Error('Missing encryptedData in deriveNearKeypairAndEncrypt result');
    }
    const shouldPersistToDb = options?.persistToDb !== false;
    if (shouldPersistToDb) {
      // Prefer explicitly provided deviceNumber, else derive from IndexedDB state
      const deviceNumber = (typeof options?.deviceNumber === 'number')
        ? options!.deviceNumber!
        : await getLastLoggedInDeviceNumber(nearAccountId, ctx.indexedDB.clientDB);
      await ctx.indexedDB.storeNearLocalKeyMaterialV2({
        nearAccountId,
        deviceNumber,
        publicKey: wasmResult.publicKey,
        encryptedSk,
        chacha20NonceB64u,
        wrapKeySalt: wrapKeySaltPersisted,
        timestamp: Date.now(),
      });
    }

    return {
      success: true,
      nearAccountId: toAccountId(wasmResult.nearAccountId),
      publicKey: wasmResult.publicKey,
      chacha20NonceB64u,
      wrapKeySalt: wrapKeySaltPersisted,
      encryptedSk,
    };
  } catch (error: unknown) {
    console.error('WebAuthnManager: deriveNearKeypairAndEncryptFromSerialized error:', error);
    const message = String((error as { message?: unknown })?.message || error || '');
    return {
      success: false,
      nearAccountId,
      publicKey: '',
      error: message
    };
  }
}
