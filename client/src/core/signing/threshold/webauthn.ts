import type { AccountId } from '../../types/accountIds';
import type { ClientAuthenticatorData } from '../../IndexedDBManager';
import type { WebAuthnAuthenticationCredential } from '../../types/webauthn';
import {
  collectAuthenticationCredentialForChallengeB64u as collectAuthenticationCredentialForChallengeB64uShared,
  type WebAuthnAllowCredential,
  type WebAuthnAuthenticatorRecord,
  type WebAuthnIndexedDbClientPort,
  type WebAuthnIndexedDbPort,
  type WebAuthnPromptPort,
} from '../webauthn/credentials/collectAuthenticationCredentialForChallengeB64u';
import {
  getPrfFirstB64uFromCredential,
  redactCredentialExtensionOutputs,
} from '../webauthn/credentials/credentialExtensions';

export { getPrfFirstB64uFromCredential, redactCredentialExtensionOutputs };

export type ThresholdAllowCredential = WebAuthnAllowCredential;
export type ThresholdAuthenticatorRecord = ClientAuthenticatorData & WebAuthnAuthenticatorRecord;
export type ThresholdIndexedDbClientPort = WebAuthnIndexedDbClientPort<ThresholdAuthenticatorRecord>;
export type ThresholdIndexedDbPort = WebAuthnIndexedDbPort<ThresholdAuthenticatorRecord>;
export type ThresholdWebAuthnPromptPort = WebAuthnPromptPort;

export type ThresholdEd25519ClientShareDeriverPort = {
  deriveThresholdEd25519ClientVerifyingShare: (args: {
    sessionId: string;
    nearAccountId: AccountId;
    prfFirstB64u: string;
    wrapKeySalt: string;
  }) => Promise<{
    success: boolean;
    nearAccountId?: string;
    clientVerifyingShareB64u: string;
    error?: string;
  }>;
};

export type ThresholdPrfFirstCachePort = {
  putPrfFirstForThresholdSession: (args: {
    sessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
  }) => Promise<void>;
};
export type ThresholdSigningKeyOpsPort = ThresholdEd25519ClientShareDeriverPort;

export async function collectAuthenticationCredentialForChallengeB64u(args: {
  indexedDB: ThresholdIndexedDbPort;
  touchIdPrompt: Pick<ThresholdWebAuthnPromptPort, 'getAuthenticationCredentialsSerializedForChallengeB64u'>;
  nearAccountId: AccountId | string;
  challengeB64u: string;
  includeSecondPrfOutput?: boolean;
}): Promise<WebAuthnAuthenticationCredential> {
  return await collectAuthenticationCredentialForChallengeB64uShared({
    indexedDB: args.indexedDB,
    touchIdPrompt: args.touchIdPrompt,
    nearAccountId: args.nearAccountId,
    challengeB64u: args.challengeB64u,
    includeSecondPrfOutput: args.includeSecondPrfOutput,
  });
}
