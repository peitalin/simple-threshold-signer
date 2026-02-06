import type { ClientAuthenticatorData, UnifiedIndexedDBManager } from '../IndexedDBManager';
import type { AccountId } from '../types/accountIds';
import { toAccountId } from '../types/accountIds';
import { authenticatorsToAllowCredentials } from './touchIdPrompt';
import type { TouchIdPrompt } from './touchIdPrompt';
import type { WebAuthnAuthenticationCredential } from '../types/webauthn';

export async function collectAuthenticationCredentialForChallengeB64u(args: {
  indexedDB: UnifiedIndexedDBManager;
  touchIdPrompt: Pick<TouchIdPrompt, 'getAuthenticationCredentialsSerializedForChallengeB64u'>;
  nearAccountId: AccountId | string;
  /**
   * Base64url-encoded 32-byte challenge. For threshold sessions this should be
   * `sessionPolicyDigest32`.
   */
  challengeB64u: string;
  onBeforePrompt?: (info: {
    authenticators: ClientAuthenticatorData[];
    authenticatorsForPrompt: ClientAuthenticatorData[];
    challengeB64u: string;
  }) => void;
  /**
   * When true, include PRF.second in the serialized credential.
   * Use only for explicit recovery/export flows (higher-friction paths).
   */
  includeSecondPrfOutput?: boolean;
}): Promise<WebAuthnAuthenticationCredential> {
  const nearAccountId = toAccountId(args.nearAccountId);

  const authenticators = await args.indexedDB.clientDB.getAuthenticatorsByUser(nearAccountId);
  let authenticatorsForPrompt: ClientAuthenticatorData[] = authenticators;
  if (authenticators.length > 0) {
    ({ authenticatorsForPrompt } = await args.indexedDB.clientDB.ensureCurrentPasskey(
      toAccountId(nearAccountId),
      authenticators,
    ));
  }

  args.onBeforePrompt?.({ authenticators, authenticatorsForPrompt, challengeB64u: args.challengeB64u });

  const allowCredentials = authenticatorsToAllowCredentials(authenticatorsForPrompt);
  const serialized = await args.touchIdPrompt.getAuthenticationCredentialsSerializedForChallengeB64u({
    nearAccountId,
    challengeB64u: args.challengeB64u,
    allowCredentials,
    includeSecondPrfOutput: args.includeSecondPrfOutput,
  });

  // Verify that the chosen credential matches the "current" passkey device, when applicable.
  if (authenticators.length > 0) {
    const { wrongPasskeyError } = await args.indexedDB.clientDB.ensureCurrentPasskey(
      toAccountId(nearAccountId),
      authenticators,
      serialized.rawId,
    );
    if (wrongPasskeyError) {
      throw new Error(wrongPasskeyError);
    }
  }

  return serialized;
}

