import type { SecureConfirmWorkerManagerContext } from '../../';
import type { ConfirmationConfig } from '../../../../types/signer-worker';
import {
  TransactionSummary,
  RegistrationSecureConfirmRequest,
} from '../types';
import type { SecureConfirmSecurityContext, TransactionContext } from '../../../../types';
import type { WebAuthnRegistrationCredential } from '../../../../types/webauthn';
import { sha256Base64UrlUtf8 } from '../../../../../utils/intentDigest';
import {
  getNearAccountId,
  getIntentDigest,
  isUserCancelledSecureConfirm,
  ERROR_MESSAGES,
  getRegisterAccountPayload,
} from './index';
import { isSerializedRegistrationCredential, serializeRegistrationCredentialWithPRF } from '../../../credentialsHelpers';
import { toError } from '../../../../../../../shared/src/utils/errors';
import { createConfirmSession } from '../adapters/session';
import { createConfirmTxFlowAdapters } from '../adapters/createAdapters';
import type { ThemeName } from '../../../../types/tatchi';

export async function handleRegistrationFlow(
  ctx: SecureConfirmWorkerManagerContext,
  request: RegistrationSecureConfirmRequest,
  worker: Worker,
  opts: { confirmationConfig: ConfirmationConfig; transactionSummary: TransactionSummary; theme: ThemeName },
): Promise<void> {

  const { confirmationConfig, transactionSummary, theme } = opts;
  const adapters = createConfirmTxFlowAdapters(ctx);
  const session = createConfirmSession({
    adapters,
    worker,
    request,
    confirmationConfig,
    transactionSummary,
    theme,
  });
  const nearAccountId = getNearAccountId(request);

  try {
    // 1) NEAR context
    const nearRpc = await adapters.near.fetchNearContext({ nearAccountId, txCount: 1, reserveNonces: true });
    if (nearRpc.error && !nearRpc.transactionContext) {
      return session.confirmAndCloseModal({
        requestId: request.requestId,
        intentDigest: getIntentDigest(request),
        confirmed: false,
        error: `${ERROR_MESSAGES.nearRpcFailed}: ${nearRpc.details}`,
      });
    }
    const transactionContext = nearRpc.transactionContext as TransactionContext;
    session.setReservedNonces(nearRpc.reservedNonces);

    const computeBoundIntentDigestB64u = async (): Promise<string> => {
      const uiIntentDigest = getIntentDigest(request);
      if (!uiIntentDigest) {
        throw new Error('Missing intentDigest for registration flow');
      }
      return sha256Base64UrlUtf8(uiIntentDigest);
    };

    // 2) WebAuthn registration challenge (32 bytes, base64url)
    const rpId = adapters.security.getRpId();
    if (!rpId) throw new Error('Missing rpId for registration challenge');

    let challengeB64u = await computeBoundIntentDigestB64u();
    const securityContext: SecureConfirmSecurityContext = {
      rpId,
      blockHeight: transactionContext.txBlockHeight,
      blockHash: transactionContext.txBlockHash,
    };

    // 3) UI confirm
    const { confirmed, error: uiError } = await session.promptUser({ securityContext });
    if (!confirmed) {
      return session.confirmAndCloseModal({
        requestId: request.requestId,
        intentDigest: getIntentDigest(request),
        confirmed: false,
        error: uiError,
      });
    }

    // 4) Collect registration credentials (with duplicate retry)
    let credential: PublicKeyCredential | undefined;
    let deviceNumber = request.payload?.deviceNumber ?? 1;

    const tryCreate = async (dn?: number): Promise<PublicKeyCredential> => {
      return await adapters.webauthn.createRegistrationCredential({
        nearAccountId,
        challengeB64u,
        deviceNumber: dn,
      });
    };

    try {
      credential = await tryCreate(deviceNumber);
    } catch (e: unknown) {

      const err = toError(e);
      const name = String(err?.name || '');
      const msg = String(err?.message || '');
      const isDuplicate = name === 'InvalidStateError' || /excluded|already\s*registered/i.test(msg);

      if (isDuplicate) {
        const nextDeviceNumber = (deviceNumber !== undefined && Number.isFinite(deviceNumber)) ? (deviceNumber + 1) : 2;
        // Keep request payload and intentDigest in sync with the deviceNumber retry.
        deviceNumber = nextDeviceNumber;
        getRegisterAccountPayload(request).deviceNumber = nextDeviceNumber;
        request.intentDigest = request.type === 'registerAccount'
          ? `register:${nearAccountId}:${nextDeviceNumber}`
          : `device2-register:${nearAccountId}:${nextDeviceNumber}`;

        challengeB64u = await computeBoundIntentDigestB64u();

        credential = await tryCreate(nextDeviceNumber);
      } else {
        console.error('[RegistrationFlow] credentials.create failed (non-duplicate)', { name, msg });
        throw err;
      }
    }

    // We require registration credentials to include dual PRF outputs (first + second)
    // so wallet-origin code can pass PRF outputs directly to signer workers when deriving keys.
    const serialized: WebAuthnRegistrationCredential = isSerializedRegistrationCredential(credential)
      ? (credential as unknown as WebAuthnRegistrationCredential)
      : serializeRegistrationCredentialWithPRF({
          credential: credential! as PublicKeyCredential,
          firstPrfOutput: true,
          secondPrfOutput: true,
      });

    // 5) Respond + close
    session.confirmAndCloseModal({
      requestId: request.requestId,
      intentDigest: getIntentDigest(request),
      confirmed: true,
      credential: serialized,
      transactionContext,
    });
  } catch (err: unknown) {

    const cancelled = isUserCancelledSecureConfirm(err);
    const msg = String((toError(err))?.message || err || '');
    if (cancelled) {
      window.parent?.postMessage({ type: 'WALLET_UI_CLOSED' }, '*');
    }

    const isPrfBrowserUnsupported =
      /WebAuthn PRF output is missing from navigator\.credentials\.create\(\)/i.test(msg)
      || /does not fully support the WebAuthn PRF extension during registration/i.test(msg)
      || /roaming hardware authenticators .* not supported in this flow/i.test(msg);

    return session.confirmAndCloseModal({
      requestId: request.requestId,
      intentDigest: getIntentDigest(request),
      confirmed: false,
      error: cancelled
        ? ERROR_MESSAGES.cancelled
        : (isPrfBrowserUnsupported ? msg : (msg || ERROR_MESSAGES.collectCredentialsFailed)),
    });
  }
}
