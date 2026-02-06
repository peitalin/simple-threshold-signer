import { RegistrationSSEEvent, RegistrationPhase, RegistrationStatus } from '../../types/sdkSentEvents';
import { PasskeyManagerContext } from '..';
import { removePrfOutputGuard, serializeRegistrationCredential, normalizeRegistrationCredential } from '../../WebAuthnManager/credentialsHelpers';
import type { WebAuthnRegistrationCredential } from '../../types/webauthn';
import type { AuthenticatorOptions } from '../../types/authenticatorOptions';
import type { CreateAccountAndRegisterResult } from '@server/core/types';
import { isObject } from '../../../../../shared/src/utils/validation';
import { errorMessage } from '../../../../../shared/src/utils/errors';

function isSerializedRegistrationCredential(
  credential: WebAuthnRegistrationCredential | PublicKeyCredential,
): credential is WebAuthnRegistrationCredential {
  if (!isObject(credential)) return false;
  const resp = (credential as { response?: unknown }).response;
  if (!isObject(resp)) return false;
  return typeof (resp as { attestationObject?: unknown }).attestationObject === 'string';
}

function improveAtomicRegistrationError(args: {
  raw: string;
  nearAccountId: string;
  relayUrl: string;
}): string {
  const raw = String(args.raw || '').trim();
  const nearAccountId = String(args.nearAccountId || '').trim();
  const relayUrl = String(args.relayUrl || '').trim();

  // Server validation: account creation can only create subaccounts under a specific namespace.
  // Depending on the deployment, that namespace can be the WebAuthn contract account (contractId)
  // or the relayer signer account (relayerAccountId).
  const mContract = /new_account_id must be a subaccount of contractId\s*\(([^)]+)\)/i.exec(raw);
  const mWebAuthn = /new_account_id must be a subaccount of webAuthnContractId\s*\(([^)]+)\)/i.exec(raw);
  const mRelayer = /new_account_id must be a subaccount of relayerAccountId\s*\(([^)]+)\)/i.exec(raw);

  const expectedContract = (mContract?.[1] || mWebAuthn?.[1]) ? String(mContract?.[1] || mWebAuthn?.[1]).trim() : '';
  const expectedRelayer = mRelayer?.[1] ? String(mRelayer[1]).trim() : '';

  if (expectedContract) {
    const providedSuffix = (() => {
      const parts = nearAccountId.split('.');
      if (parts.length < 2) return '';
      return parts.slice(1).join('.');
    })();
    const hint =
      `Registration accountId must be a subaccount of the contract account.\n` +
      `Relay expects: <username>.${expectedContract}\n` +
      (nearAccountId ? `You provided: ${nearAccountId}\n` : '') +
      `Fix (pick one):\n` +
      `- Client: set \`contractId: '${expectedContract}'\` (must match relay WEBAUTHN_CONTRACT_ID)` +
      (relayUrl ? ` for relayer \`${relayUrl}\`` : '') +
      `.\n` +
      (providedSuffix && providedSuffix !== expectedContract
        ? `- Relay: if \`.${providedSuffix}\` is the intended postfix, set WEBAUTHN_CONTRACT_ID=${providedSuffix} then restart the relay.\n`
        : '') +
      `Tip: check \`${relayUrl || '<relayer-url>'}/healthz\` → \`webAuthnContractId\`.`;
    return hint;
  }

  if (expectedRelayer) {
    const hint =
      `Registration accountId must be a subaccount of the relay signer account.\n` +
      `Expected: <username>.${expectedRelayer}\n` +
      (nearAccountId ? `Got: ${nearAccountId}\n` : '') +
      `Fix: set client config \`relayerAccount: '${expectedRelayer}'\` (must match relay RELAYER_ACCOUNT_ID)` +
      (relayUrl ? ` for relayer \`${relayUrl}\`` : '') +
      `.`;
    return hint;
  }

  return raw || 'Atomic registration failed';
}

/**
 * HTTP Request body for the relay server's /create_account_and_register_user endpoint
 */
export interface CreateAccountAndRegisterUserRequest {
  new_account_id: string;
  /**
   * Optional account access key to add during creation.
   *
   * - Local-signer flows provide a locally derived key.
   * - Threshold-signer flows typically provide a locally derived "backup" key (Option B) so the client
   *   can add the threshold key after validating it. Older clients may omit this (Option A).
   */
  new_public_key?: string;
  device_number: number;
  threshold_ed25519?: {
    client_verifying_share_b64u: string;
  };
  rp_id: string;
  webauthn_registration: WebAuthnRegistrationCredential;
  authenticator_options?: AuthenticatorOptions;
}

/**
 * Create account and register user using relay-server atomic endpoint
 * Makes a single call to the relay-server's /create_account_and_register_user endpoint
 */
export async function createAccountAndRegisterWithRelayServer(
  context: PasskeyManagerContext,
  nearAccountId: string,
  publicKey: string | undefined,
  credential: WebAuthnRegistrationCredential | PublicKeyCredential,
  rpId: string,
  authenticatorOptions?: AuthenticatorOptions,
  onEvent?: (event: RegistrationSSEEvent) => void,
  opts?: {
    thresholdEd25519?: {
      clientVerifyingShareB64u: string;
    };
  },
): Promise<{
  success: boolean;
  transactionId?: string;
  thresholdEd25519?: {
    publicKey: string;
    relayerKeyId: string;
    relayerVerifyingShareB64u?: string;
    clientParticipantId?: number;
    relayerParticipantId?: number;
    participantIds?: number[];
  };
  error?: string;
}> {
  const { configs } = context;

  if (!configs.relayer.url) {
    throw new Error('Relay server URL is required for atomic registration');
  }

  try {
    onEvent?.({
      step: 4,
      phase: RegistrationPhase.STEP_4_ACCESS_KEY_ADDITION,
      status: RegistrationStatus.PROGRESS,
      message: 'Creating account and adding access key...',
    });

    // Serialize the WebAuthn credential properly for the contract.
    // Accept both live PublicKeyCredential and already-serialized credentials from secureConfirm.
    const isSerialized = isSerializedRegistrationCredential(credential);

    // Ensure proper serialization + normalization regardless of source
    const serialized: WebAuthnRegistrationCredential = isSerialized
      ? normalizeRegistrationCredential(credential)
      : serializeRegistrationCredential(credential);

    // Strip PRF outputs before sending to relay/contract
    const serializedCredential = removePrfOutputGuard<WebAuthnRegistrationCredential>(serialized);
    // Normalize transports to an array (avoid null)
    if (!Array.isArray(serializedCredential?.response?.transports)) {
      serializedCredential.response.transports = [];
    }

    const requestData: CreateAccountAndRegisterUserRequest = {
      new_account_id: nearAccountId,
      device_number: 1, // First device gets device number 1 (1-indexed)
      ...(opts?.thresholdEd25519?.clientVerifyingShareB64u
        ? {
          threshold_ed25519: {
            client_verifying_share_b64u: opts.thresholdEd25519.clientVerifyingShareB64u,
          },
        }
        : {}),
      rp_id: String(rpId || '').trim(),
      webauthn_registration: serializedCredential,
      authenticator_options: authenticatorOptions || context.configs.authenticatorOptions,
    };
    const pk = String(publicKey || '').trim();
    if (pk) {
      requestData.new_public_key = pk;
    }

    onEvent?.({
      step: 5,
      phase: RegistrationPhase.STEP_5_CONTRACT_REGISTRATION,
      status: RegistrationStatus.PROGRESS,
      message: 'Registering user with relay...',
    });

    // Call the atomic endpoint
    const response = await fetch(`${configs.relayer.url}/create_account_and_register_user`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(requestData)
    });

    // Handle both successful and failed responses
    const result: CreateAccountAndRegisterResult = await response.json();

    if (!response.ok) {
      // Extract specific error message from relay server response
      const msg = result.error || result.message || `HTTP ${response.status}: ${response.statusText}`;
      throw new Error(improveAtomicRegistrationError({
        raw: msg,
        nearAccountId,
        relayUrl: configs.relayer.url,
      }));
    }

    if (!result.success) {
      throw new Error(result.error || 'Atomic registration failed');
    }

    onEvent?.({
      step: 5,
      phase: RegistrationPhase.STEP_5_CONTRACT_REGISTRATION,
      status: RegistrationStatus.SUCCESS,
      message: 'User registered successfully',
    });

    return {
      success: true,
      transactionId: result.transactionHash,
      thresholdEd25519: result.thresholdEd25519
        ? {
          publicKey: result.thresholdEd25519.publicKey,
          relayerKeyId: result.thresholdEd25519.relayerKeyId,
          relayerVerifyingShareB64u: result.thresholdEd25519.relayerVerifyingShareB64u,
          clientParticipantId: result.thresholdEd25519.clientParticipantId,
          relayerParticipantId: result.thresholdEd25519.relayerParticipantId,
          participantIds: result.thresholdEd25519.participantIds,
        }
        : undefined,
    };

  } catch (error: unknown) {
    console.error('Atomic registration failed:', error);

    onEvent?.({
      step: 0,
      phase: RegistrationPhase.REGISTRATION_ERROR,
      status: RegistrationStatus.ERROR,
      message: 'Registration failed',
      error: errorMessage(error),
    });

    return {
      success: false,
      error: errorMessage(error),
    };
  }
}
