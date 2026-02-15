import { toAccountId, type AccountId } from '../../types/accountIds';
import type { AuthenticatorOptions } from '../../types/authenticatorOptions';
import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '../../types';
import { getPrfResultsFromCredential } from '../webauthn/credentials/credentialExtensions';
import type { NearSigningKeyOpsService } from '../workers/signerWorkerManager/nearKeyOpsService';

function requirePrfB64uFromCredential(
  credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential,
  output: 'first' | 'second',
): string {
  const value = getPrfResultsFromCredential(credential)[output];
  if (!value) {
    throw new Error(`Missing PRF.${output} output from credential (requires a PRF-enabled passkey)`);
  }
  return value;
}

function isWebAuthnRegistrationCredential(
  credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential,
): credential is WebAuthnRegistrationCredential {
  return typeof (credential as WebAuthnRegistrationCredential)?.response?.attestationObject === 'string';
}

export type NearKeyDerivationDeps = {
  createSessionId: (prefix: string) => string;
  signingKeyOps: Pick<
    NearSigningKeyOpsService,
    'deriveNearKeypairAndEncryptFromSerialized' | 'decryptPrivateKeyWithPrf' | 'recoverKeypairFromPasskey'
  >;
};

export async function deriveNearKeypairAndEncryptFromSerialized(
  deps: NearKeyDerivationDeps,
  args: {
    credential: WebAuthnRegistrationCredential;
    nearAccountId: string;
    options?: {
      authenticatorOptions?: AuthenticatorOptions;
      deviceNumber?: number;
      persistToDb?: boolean;
    };
  },
): Promise<{
  success: boolean;
  nearAccountId: string;
  publicKey: string;
  chacha20NonceB64u?: string;
  wrapKeySalt?: string;
  encryptedSk?: string;
  error?: string;
}> {
  const sessionId = deps.createSessionId('reg');
  return await deps.signingKeyOps.deriveNearKeypairAndEncryptFromSerialized({
    credential: args.credential,
    nearAccountId: toAccountId(args.nearAccountId),
    options: args.options,
    sessionId,
  });
}

export async function deriveNearKeypairFromCredentialViaWorker(
  deps: NearKeyDerivationDeps,
  args: {
    credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
    nearAccountId: AccountId;
  },
): Promise<{ publicKey: string; privateKey: string }> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const prfFirstB64u = requirePrfB64uFromCredential(args.credential, 'first');
  const decryptSessionId = deps.createSessionId('derive-near-prf2-decrypt');

  if (isWebAuthnRegistrationCredential(args.credential)) {
    const derived = await deriveNearKeypairAndEncryptFromSerialized(deps, {
      credential: args.credential,
      nearAccountId,
      options: { persistToDb: false },
    });
    if (!derived.success || !derived.publicKey || !derived.wrapKeySalt) {
      throw new Error(derived.error || 'Failed to derive NEAR keypair from registration credential');
    }
    const encryptedSk = String(derived.encryptedSk || '').trim();
    const chacha20NonceB64u = String(derived.chacha20NonceB64u || '').trim();
    if (!encryptedSk || !chacha20NonceB64u) {
      throw new Error('Missing encrypted local key payload after NEAR key derivation');
    }

    const decrypted = await deps.signingKeyOps.decryptPrivateKeyWithPrf({
      nearAccountId,
      authenticators: [],
      sessionId: decryptSessionId,
      prfFirstB64u,
      wrapKeySalt: derived.wrapKeySalt,
      encryptedPrivateKeyData: encryptedSk,
      encryptedPrivateKeyChacha20NonceB64u: chacha20NonceB64u,
    });
    return {
      publicKey: derived.publicKey,
      privateKey: decrypted.decryptedPrivateKey,
    };
  }

  const recovered = await deps.signingKeyOps.recoverKeypairFromPasskey({
    credential: args.credential,
    accountIdHint: String(nearAccountId),
    sessionId: deps.createSessionId('derive-near-prf2-recover'),
  });
  const decrypted = await deps.signingKeyOps.decryptPrivateKeyWithPrf({
    nearAccountId,
    authenticators: [],
    sessionId: decryptSessionId,
    prfFirstB64u,
    wrapKeySalt: recovered.wrapKeySalt,
  });
  return {
    publicKey: recovered.publicKey,
    privateKey: decrypted.decryptedPrivateKey,
  };
}
