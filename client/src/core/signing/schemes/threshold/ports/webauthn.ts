import { toAccountId, type AccountId } from '../../../../types/accountIds';
import type { ClientAuthenticatorData } from '../../../../IndexedDBManager';
import type { WebAuthnAuthenticationCredential } from '../../../../types/webauthn';

export type ThresholdAllowCredential = {
  id: string;
  type: string;
  transports: AuthenticatorTransport[];
};

export type ThresholdAuthenticatorRecord = ClientAuthenticatorData;

export type ThresholdIndexedDbClientPort = {
  getAuthenticatorsByUser: (nearAccountId: AccountId) => Promise<ThresholdAuthenticatorRecord[]>;
  ensureCurrentPasskey: (
    nearAccountId: AccountId,
    authenticators: ThresholdAuthenticatorRecord[],
    selectedCredentialId?: string,
  ) => Promise<{
    authenticatorsForPrompt?: ThresholdAuthenticatorRecord[];
    wrongPasskeyError?: string;
  }>;
};

export type ThresholdIndexedDbPort = {
  clientDB: ThresholdIndexedDbClientPort;
};

export type ThresholdWebAuthnPromptPort = {
  getRpId: () => string;
  getAuthenticationCredentialsSerializedForChallengeB64u: (args: {
    nearAccountId: AccountId;
    challengeB64u: string;
    allowCredentials?: ThresholdAllowCredential[];
    includeSecondPrfOutput?: boolean;
  }) => Promise<WebAuthnAuthenticationCredential>;
};

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

export type ThresholdSignerWorkerPort = ThresholdEd25519ClientShareDeriverPort & {
  getContext?: () => {
    secureConfirmWorkerManager?: Partial<ThresholdPrfFirstCachePort> | null;
  };
};

function authenticatorsToAllowCredentials(
  authenticators: ThresholdAuthenticatorRecord[],
): ThresholdAllowCredential[] {
  return authenticators.map((auth) => ({
    id: String(auth.credentialId || ''),
    type: 'public-key',
    transports: Array.isArray(auth.transports)
      ? (auth.transports as AuthenticatorTransport[])
      : [],
  }));
}

export async function collectAuthenticationCredentialForChallengeB64u(args: {
  indexedDB: ThresholdIndexedDbPort;
  touchIdPrompt: Pick<ThresholdWebAuthnPromptPort, 'getAuthenticationCredentialsSerializedForChallengeB64u'>;
  nearAccountId: AccountId | string;
  challengeB64u: string;
  includeSecondPrfOutput?: boolean;
}): Promise<WebAuthnAuthenticationCredential> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const authenticators = await args.indexedDB.clientDB.getAuthenticatorsByUser(nearAccountId);

  let authenticatorsForPrompt: ThresholdAuthenticatorRecord[] = authenticators;
  if (authenticators.length > 0) {
    const ensured = await args.indexedDB.clientDB.ensureCurrentPasskey(nearAccountId, authenticators);
    if (Array.isArray(ensured?.authenticatorsForPrompt)) {
      authenticatorsForPrompt = ensured.authenticatorsForPrompt;
    }
  }

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

export function getPrfFirstB64uFromCredential(credential: unknown): string | null {
  try {
    const b64u = (credential as any)?.clientExtensionResults?.prf?.results?.first;
    if (typeof b64u !== 'string') return null;
    const trimmed = b64u.trim();
    return trimmed ? trimmed : null;
  } catch {
    return null;
  }
}

type CredentialWithExtensionOutputs = {
  response?: unknown;
  clientExtensionResults?: unknown;
};

export function redactCredentialExtensionOutputs<C extends CredentialWithExtensionOutputs>(
  credential: C,
): C {
  const response = credential.response;
  const responseWithoutExtensions =
    response && typeof response === 'object'
      ? (() => {
          const cloned = { ...(response as Record<string, unknown>) };
          if ('clientExtensionResults' in cloned) cloned.clientExtensionResults = null;
          return cloned;
        })()
      : response;

  return {
    ...credential,
    response: responseWithoutExtensions,
    clientExtensionResults: null,
  } as C;
}

export function getThresholdPrfFirstCachePortFromSignerWorker(
  signerWorkerManager?: ThresholdSignerWorkerPort | null,
): ThresholdPrfFirstCachePort | null {
  const ctx = signerWorkerManager?.getContext?.();
  const cache = ctx?.secureConfirmWorkerManager;
  if (!cache || typeof cache.putPrfFirstForThresholdSession !== 'function') {
    return null;
  }
  return {
    putPrfFirstForThresholdSession: cache.putPrfFirstForThresholdSession.bind(cache),
  };
}
