import type { SecureConfirmWorkerManagerContext } from '../../';
import type { SerializableCredential } from '../types';
import type { ProfileAuthenticatorRecord } from '../../../../IndexedDBManager';
import { collectAuthenticationCredentialForChallengeB64u } from '../../../webauthn/credentials/collectAuthenticationCredentialForChallengeB64u';

export async function collectAuthenticationCredentialWithPRF({
  ctx,
  nearAccountId,
  challengeB64u,
  onBeforePrompt,
  includeSecondPrfOutput = false,
}: {
  ctx: SecureConfirmWorkerManagerContext;
  nearAccountId: string;
  challengeB64u: string;
  onBeforePrompt?: (info: {
    authenticators: ProfileAuthenticatorRecord[];
    authenticatorsForPrompt: ProfileAuthenticatorRecord[];
    challengeB64u: string;
  }) => void;
  /**
   * When true, include PRF.second in the serialized credential.
   * Use only for explicit recovery/export flows (higher-friction paths).
   */
  includeSecondPrfOutput?: boolean;
}): Promise<SerializableCredential> {
  return collectAuthenticationCredentialForChallengeB64u({
    indexedDB: ctx.indexedDB,
    touchIdPrompt: ctx.touchIdPrompt,
    nearAccountId,
    challengeB64u,
    includeSecondPrfOutput,
    onBeforePrompt,
  });
}
