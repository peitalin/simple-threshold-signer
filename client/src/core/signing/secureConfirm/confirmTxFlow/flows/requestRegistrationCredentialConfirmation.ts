import type { ConfirmationConfig } from '../../../../types/signer-worker';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '../../../../config/defaultConfigs';
import type { SecureConfirmWorkerManagerContext } from '../../';
import { runSecureConfirm } from '../../secureConfirmBridge';
import {
  SecureConfirmationType,
  type RegistrationSummary,
  type SecureConfirmRequest,
} from '../types';
import {
  parseAndValidateRegistrationCredentialConfirmationPayload,
  type RegistrationCredentialConfirmationPayload,
} from '../../../threshold/keys';

export async function requestRegistrationCredentialConfirmation({
  ctx,
  nearAccountId,
  deviceNumber,
  confirmerText,
  contractId,
  nearRpcUrl,
  confirmationConfig,
}: {
  ctx: SecureConfirmWorkerManagerContext,
  nearAccountId: string,
  deviceNumber: number,
  confirmerText?: { title?: string; body?: string };
  contractId: string,
  nearRpcUrl: string,
  confirmationConfig?: Partial<ConfirmationConfig>,
}): Promise<RegistrationCredentialConfirmationPayload> {

  // Ensure required fields are present; JSON.stringify drops undefined causing Rust parse failure
  const resolvedContractId = contractId || PASSKEY_MANAGER_DEFAULT_CONFIGS.contractId;
  // Use the first URL if defaults include a failover list
  const resolvedNearRpcUrl = nearRpcUrl
    || (PASSKEY_MANAGER_DEFAULT_CONFIGS.nearRpcUrl.split(',')[0] || PASSKEY_MANAGER_DEFAULT_CONFIGS.nearRpcUrl);

  const requestId = (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function')
    ? crypto.randomUUID()
    : `register-${Date.now()}-${Math.random().toString(16).slice(2)}`;

  const title = confirmerText?.title;
  const body = confirmerText?.body;
  const request: SecureConfirmRequest<{
    nearAccountId: string;
    deviceNumber: number;
    rpcCall: { contractId: string; nearRpcUrl: string; nearAccountId: string };
  }, RegistrationSummary> = {
    requestId,
    type: SecureConfirmationType.REGISTER_ACCOUNT,
    summary: {
      nearAccountId,
      deviceNumber,
      contractId: resolvedContractId,
      ...(title != null ? { title } : {}),
      ...(body != null ? { body } : {}),
    },
    payload: {
      nearAccountId,
      deviceNumber,
      rpcCall: {
        contractId: resolvedContractId,
        nearRpcUrl: resolvedNearRpcUrl,
        nearAccountId,
      },
    },
    confirmationConfig,
    intentDigest: `register:${nearAccountId}:${deviceNumber}`,
  };

  const decision = await runSecureConfirm(ctx, request);

  return parseAndValidateRegistrationCredentialConfirmationPayload({
    confirmed: decision.confirmed,
    requestId,
    intentDigest: decision.intentDigest || '',
    credential: decision.credential,
    transactionContext: decision.transactionContext,
    error: decision.error,
  });
}
