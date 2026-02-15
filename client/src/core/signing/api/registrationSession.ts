import type { AccountId } from '../../types/accountIds';
import type { ConfirmationConfig } from '../../types/signer-worker';
import type { WebAuthnAuthenticationCredential } from '../../types';
import type { RegistrationCredentialConfirmationPayload } from '../workers/signerWorkerManager/internal/validation';
import type { SecureConfirmWorkerManager } from '../secureConfirm/manager';
import type { TouchIdPrompt } from '../webauthn/prompt/touchIdPrompt';
import type { WebAuthnAllowCredential } from '../webauthn/credentials';

export type RegistrationSessionDeps = {
  contractId: string;
  nearRpcUrl: string;
  secureConfirmWorkerManager: Pick<
    SecureConfirmWorkerManager,
    'requestRegistrationCredentialConfirmation'
  >;
  touchIdPrompt: Pick<TouchIdPrompt, 'getAuthenticationCredentialsSerializedForChallengeB64u'>;
};

export async function requestRegistrationCredentialConfirmation(
  deps: RegistrationSessionDeps,
  params: {
    nearAccountId: string;
    deviceNumber: number;
    confirmerText?: { title?: string; body?: string };
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
  },
): Promise<RegistrationCredentialConfirmationPayload> {
  return await deps.secureConfirmWorkerManager.requestRegistrationCredentialConfirmation({
    nearAccountId: params.nearAccountId,
    deviceNumber: params.deviceNumber,
    confirmerText: params.confirmerText,
    confirmationConfigOverride: params.confirmationConfigOverride,
    contractId: deps.contractId,
    nearRpcUrl: deps.nearRpcUrl,
  });
}

export async function getAuthenticationCredentialsSerialized(
  deps: RegistrationSessionDeps,
  params: {
    nearAccountId: AccountId;
    challengeB64u: string;
    allowCredentials: WebAuthnAllowCredential[];
    includeSecondPrfOutput?: boolean;
  },
): Promise<WebAuthnAuthenticationCredential> {
  return await deps.touchIdPrompt.getAuthenticationCredentialsSerializedForChallengeB64u({
    nearAccountId: params.nearAccountId,
    challengeB64u: params.challengeB64u,
    allowCredentials: params.allowCredentials,
    includeSecondPrfOutput: params.includeSecondPrfOutput ?? false,
  });
}

function toAllowCredentials(credentialIds: string[]): WebAuthnAllowCredential[] {
  return credentialIds.map((id) => ({
    id: id,
    type: 'public-key',
    transports: ['internal', 'hybrid', 'usb', 'ble'],
  }));
}

export async function getAuthenticationCredentialsSerializedDualPrf(
  deps: RegistrationSessionDeps,
  params: {
    nearAccountId: AccountId;
    challengeB64u: string;
    credentialIds: string[];
  },
): Promise<WebAuthnAuthenticationCredential> {
  return await deps.touchIdPrompt.getAuthenticationCredentialsSerializedForChallengeB64u({
    nearAccountId: params.nearAccountId,
    challengeB64u: params.challengeB64u,
    allowCredentials: toAllowCredentials(params.credentialIds),
    includeSecondPrfOutput: true,
  });
}
