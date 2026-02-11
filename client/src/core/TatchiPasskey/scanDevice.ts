import type { PasskeyManagerContext } from './index';
import { validateNearAccountId } from '../../../../shared/src/utils/validation';
import { getLoginSession } from './login';
import type {
  DeviceLinkingQRData,
  LinkDeviceResult,
  ScanAndLinkDeviceOptionsDevice1,
} from '../types/linkDevice';
import { DeviceLinkingPhase, DeviceLinkingStatus } from '../types/sdkSentEvents';
import { DeviceLinkingError, DeviceLinkingErrorCode } from '../types/linkDevice';
import { DEVICE_LINKING_CONFIG } from '../../config.js';
import { executeDeviceLinkingContractCalls } from '../near/rpcCalls';
import { ensureEd25519Prefix } from '../near/nearCrypto';

/**
 * Device1 (original device): Link device using pre-scanned QR data
 */
export async function linkDeviceWithScannedQRData(
  context: PasskeyManagerContext,
  qrData: DeviceLinkingQRData,
  options: ScanAndLinkDeviceOptionsDevice1
): Promise<LinkDeviceResult> {
  const { onEvent, onError } = options || {};

  try {
    onEvent?.({
      step: 2,
      phase: DeviceLinkingPhase.STEP_2_SCANNING,
      status: DeviceLinkingStatus.PROGRESS,
      message: 'Validating QR data...'
    });

    // Validate QR data
    validateDeviceLinkingQRData(qrData);

    // 3. Get Device1's current account (the account that will receive the new key)
    const { login: device1LoginState } = await getLoginSession(context);

    if (!device1LoginState.isLoggedIn || !device1LoginState.nearAccountId) {
      throw new Error('Device1 must be logged in to authorize device linking');
    }

    const device1AccountId = device1LoginState.nearAccountId;

    // 4. Execute batched transaction: AddKey + Contract notification
    const fundingAmount = options.fundingAmount;

    // Parse the device public key for AddKey action
    const device2PublicKey = ensureEd25519Prefix(String(qrData?.device2PublicKey || '').trim());
    if (!device2PublicKey || !/^ed25519:/i.test(device2PublicKey)) {
      throw new Error('Invalid device public key format');
    }

    onEvent?.({
      step: 3,
      phase: DeviceLinkingPhase.STEP_3_AUTHORIZATION,
      status: DeviceLinkingStatus.PROGRESS,
      message: `Performing TouchID authentication for device linking...`
    });

    onEvent?.({
      step: 6,
      phase: DeviceLinkingPhase.STEP_6_REGISTRATION,
      status: DeviceLinkingStatus.PROGRESS,
      message: 'TouchID successful! Signing AddKey transaction...'
    });

    // Execute device linking transactions using the centralized RPC function
    const {
      addKeyTxResult,
    } = await executeDeviceLinkingContractCalls({
      context,
      device1AccountId,
      device2PublicKey,
      onEvent,
      confirmationConfigOverride: options?.confirmationConfig,
      confirmerText: options?.confirmerText,
    });

    // Best-effort: claim the link-device session on the relay so Device2 can discover
    // the accountId without on-chain polling.
    const sessionId = String((qrData as any)?.sessionId || '').trim();
    const relayerUrl = String(context?.configs?.relayer?.url || '').trim();
    const addKeyTxHash = (addKeyTxResult as any)?.transaction?.hash as string | undefined;
    if (sessionId && relayerUrl) {
      try {
        const resp = await fetch(`${relayerUrl.replace(/\/$/, '')}/link-device/session/claim`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            session_id: sessionId,
            account_id: String(device1AccountId),
            device2_public_key: device2PublicKey,
            ...(addKeyTxHash ? { add_key_tx_hash: addKeyTxHash } : {}),
          }),
        });
        const json: any = await resp.json().catch(() => ({}));
        if (!resp.ok || json?.ok !== true) {
          console.warn('[link-device] relay claim failed:', json?.message || `HTTP ${resp.status}`);
        }
      } catch (err) {
        console.warn('[link-device] relay claim error:', err);
      }
    }

    const result = {
      success: true,
      device2PublicKey,
      transactionId: addKeyTxResult?.transaction?.hash || 'unknown',
      fundingAmount,
      linkedToAccount: device1AccountId, // Include which account the key was added to
    };

    onEvent?.({
      step: 6,
      phase: DeviceLinkingPhase.STEP_6_REGISTRATION,
      status: DeviceLinkingStatus.SUCCESS,
      message: `Device2's key added to ${device1AccountId} successfully!`
    });

    return result;

  } catch (error: any) {
    console.error('LinkDeviceFlow: linkDeviceWithQRData caught error:', error);

    const errorMessage = `Failed to scan and link device: ${error.message}`;
    onError?.(new Error(errorMessage));

    throw new DeviceLinkingError(
      errorMessage,
      DeviceLinkingErrorCode.AUTHORIZATION_TIMEOUT,
      'authorization'
    );
  }
}

export function validateDeviceLinkingQRData(qrData: DeviceLinkingQRData): void {
  if (qrData.sessionId) {
    const sid = String(qrData.sessionId || '').trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/.test(sid)) {
      throw new DeviceLinkingError(
        'Invalid sessionId',
        DeviceLinkingErrorCode.INVALID_QR_DATA,
        'authorization'
      );
    }
  }

  const publicKey = String(qrData?.device2PublicKey || '').trim();
  if (!publicKey) {
    throw new DeviceLinkingError(
      'Missing device public key',
      DeviceLinkingErrorCode.INVALID_QR_DATA,
      'authorization'
    );
  }
  const normalized = ensureEd25519Prefix(publicKey);
  if (!/^ed25519:/i.test(normalized)) {
    throw new DeviceLinkingError(
      'Invalid device public key format',
      DeviceLinkingErrorCode.INVALID_QR_DATA,
      'authorization'
    );
  }

  if (!qrData.timestamp) {
    throw new DeviceLinkingError(
      'Missing timestamp',
      DeviceLinkingErrorCode.INVALID_QR_DATA,
      'authorization'
    );
  }

  // Check timestamp is not too old (max 15 minutes)
  const maxAge = DEVICE_LINKING_CONFIG.TIMEOUTS.QR_CODE_MAX_AGE_MS;
  if (Date.now() - qrData.timestamp > maxAge) {
    throw new DeviceLinkingError(
      'QR code expired',
      DeviceLinkingErrorCode.SESSION_EXPIRED,
      'authorization'
    );
  }

  // Account ID is optional - Device2 discovers it from contract logs
  if (qrData.accountId) {
    validateNearAccountId(qrData.accountId);
  }
}
