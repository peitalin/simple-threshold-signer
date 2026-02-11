import { toAccountId, type AccountId } from '../../../types/accountIds';
import type { ClientAuthenticatorData } from '../../../IndexedDBManager';
import type { WebAuthnAuthenticationCredential } from '../../../types/webauthn';

export type WebAuthnAllowCredential = {
  id: string;
  type: string;
  transports: AuthenticatorTransport[];
};

export type WebAuthnAuthenticatorRecord = Pick<ClientAuthenticatorData, 'credentialId' | 'transports'>;

export type WebAuthnIndexedDbClientPort<TAuth extends WebAuthnAuthenticatorRecord = ClientAuthenticatorData> = {
  getAuthenticatorsByUser: (nearAccountId: AccountId) => Promise<TAuth[]>;
  ensureCurrentPasskey: (
    nearAccountId: AccountId,
    authenticators: TAuth[],
    selectedCredentialId?: string,
  ) => Promise<{
    authenticatorsForPrompt?: TAuth[];
    wrongPasskeyError?: string;
  }>;
};

export type WebAuthnIndexedDbPort<TAuth extends WebAuthnAuthenticatorRecord = ClientAuthenticatorData> = {
  clientDB: WebAuthnIndexedDbClientPort<TAuth>;
};

export type WebAuthnPromptPort = {
  getRpId: () => string;
  getAuthenticationCredentialsSerializedForChallengeB64u: (args: {
    nearAccountId: AccountId;
    challengeB64u: string;
    allowCredentials?: WebAuthnAllowCredential[];
    includeSecondPrfOutput?: boolean;
  }) => Promise<WebAuthnAuthenticationCredential>;
};

export function authenticatorsToAllowCredentials<TAuth extends WebAuthnAuthenticatorRecord>(
  authenticators: TAuth[],
): WebAuthnAllowCredential[] {
  return authenticators.map((auth) => ({
    id: String(auth.credentialId || ''),
    type: 'public-key',
    transports: Array.isArray(auth.transports) ? (auth.transports as AuthenticatorTransport[]) : [],
  }));
}

export async function collectAuthenticationCredentialForChallengeB64u<
  TAuth extends WebAuthnAuthenticatorRecord = ClientAuthenticatorData,
>(args: {
  indexedDB: WebAuthnIndexedDbPort<TAuth>;
  touchIdPrompt: Pick<WebAuthnPromptPort, 'getAuthenticationCredentialsSerializedForChallengeB64u'>;
  nearAccountId: AccountId | string;
  challengeB64u: string;
  onBeforePrompt?: (info: {
    authenticators: TAuth[];
    authenticatorsForPrompt: TAuth[];
    challengeB64u: string;
  }) => void;
  includeSecondPrfOutput?: boolean;
}): Promise<WebAuthnAuthenticationCredential> {
  const nearAccountId = toAccountId(args.nearAccountId);

  const authenticators = await args.indexedDB.clientDB.getAuthenticatorsByUser(nearAccountId);
  let authenticatorsForPrompt = authenticators;
  if (authenticators.length > 0) {
    const ensured = await args.indexedDB.clientDB.ensureCurrentPasskey(nearAccountId, authenticators);
    if (Array.isArray(ensured?.authenticatorsForPrompt)) {
      authenticatorsForPrompt = ensured.authenticatorsForPrompt;
    }
  }

  args.onBeforePrompt?.({ authenticators, authenticatorsForPrompt, challengeB64u: args.challengeB64u });

  const allowCredentials = authenticatorsToAllowCredentials(authenticatorsForPrompt);
  const serialized = await args.touchIdPrompt.getAuthenticationCredentialsSerializedForChallengeB64u({
    nearAccountId,
    challengeB64u: args.challengeB64u,
    allowCredentials,
    includeSecondPrfOutput: args.includeSecondPrfOutput,
  });

  if (authenticators.length > 0) {
    const ensured = await args.indexedDB.clientDB.ensureCurrentPasskey(
      nearAccountId,
      authenticators,
      serialized.rawId,
    );
    if (ensured?.wrongPasskeyError) {
      throw new Error(String(ensured.wrongPasskeyError));
    }
  }

  return serialized;
}
