import type { SecureConfirmWorkerManagerContext } from '../../';
import type { ConfirmationConfig } from '../../../../types/signer-worker';
import {
  SecureConfirmationType,
  TransactionSummary,
  SigningSecureConfirmRequest,
  SigningAuthMode,
} from '../types';
import type { SecureConfirmSecurityContext, TransactionContext } from '../../../../types';
import {
  getNearAccountId,
  getIntentDigest,
  getTxCount,
  isUserCancelledSecureConfirm,
  ERROR_MESSAGES,
  getSignTransactionPayload,
} from './index';
import { toError } from '../../../../../../../shared/src/utils/errors';
import { createConfirmSession } from '../adapters/session';
import { createConfirmTxFlowAdapters } from '../adapters/createAdapters';
import { computeUiIntentDigestFromNep413 } from '../../../../digests/intentDigest';
import type { ThemeName } from '../../../../types/tatchi';
import { collectAuthenticationCredentialForChallengeB64u } from '../../../collectAuthenticationCredentialForChallengeB64u';

function getSigningAuthMode(request: SigningSecureConfirmRequest): SigningAuthMode {
  if (request.type === SecureConfirmationType.SIGN_TRANSACTION) {
    return getSignTransactionPayload(request).signingAuthMode ?? 'webauthn';
  }
  if (request.type === SecureConfirmationType.SIGN_NEP413_MESSAGE) {
    return request.payload.signingAuthMode ?? 'webauthn';
  }
  return 'webauthn';
}

export async function handleTransactionSigningFlow(
  ctx: SecureConfirmWorkerManagerContext,
  request: SigningSecureConfirmRequest,
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
    const signingAuthMode = getSigningAuthMode(request);
    const usesNeeded = getTxCount(request);
    const intentDigestB64u = request.type === SecureConfirmationType.SIGN_TRANSACTION
      ? getIntentDigest(request)
      : request.type === SecureConfirmationType.SIGN_NEP413_MESSAGE
        ? await computeUiIntentDigestFromNep413({
          nearAccountId,
          recipient: request.payload.recipient,
          message: request.payload.message,
        })
        : undefined;
    const sessionPolicyDigest32 = request.payload.sessionPolicyDigest32;

    // 1) NEAR context + nonce reservation
    const nearRpc = await adapters.near.fetchNearContext({ nearAccountId, txCount: usesNeeded, reserveNonces: true });
    if (!nearRpc.transactionContext) {
      // eslint-disable-next-line no-console
      console.error('[SigningFlow] fetchNearContext failed', { error: nearRpc.error, details: nearRpc.details });
      return session.confirmAndCloseModal({
        requestId: request.requestId,
        intentDigest: getIntentDigest(request),
        confirmed: false,
        error: nearRpc.details ? `${ERROR_MESSAGES.nearRpcFailed}: ${nearRpc.details}` : ERROR_MESSAGES.nearRpcFailed,
      });
    }
    session.setReservedNonces(nearRpc.reservedNonces);
    let transactionContext: TransactionContext = nearRpc.transactionContext;

    // 2) Security context shown in the confirmer (rpId + block height).
    // For warmSession signing we still want to show this context even though
    // we won't collect a WebAuthn credential.
    const rpId = adapters.security.getRpId();
    let securityContext: Partial<SecureConfirmSecurityContext> | undefined = rpId
      ? {
          rpId,
          blockHeight: transactionContext.txBlockHeight,
          blockHash: transactionContext.txBlockHash,
        }
      : undefined;

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

    // 4) Warm session: skip WebAuthn (seed/token handled by caller).
    if (signingAuthMode === 'warmSession') {
      session.confirmAndCloseModal({
        requestId: request.requestId,
        intentDigest: getIntentDigest(request),
        confirmed: true,
        transactionContext,
      });
      return;
    }

    // 5) Collect authentication credential.
    const challengeB64u = String(sessionPolicyDigest32 || intentDigestB64u || '').trim();
    if (!challengeB64u) {
      throw new Error('Missing WebAuthn challenge digest for signing flow');
    }
    const serializedCredential = await collectAuthenticationCredentialForChallengeB64u({
      indexedDB: ctx.indexedDB,
      touchIdPrompt: ctx.touchIdPrompt,
      nearAccountId,
      challengeB64u,
    });

    // 6) Respond; keep nonces reserved for worker to use
    session.confirmAndCloseModal({
      requestId: request.requestId,
      intentDigest: getIntentDigest(request),
      confirmed: true,
      credential: serializedCredential,
      transactionContext,
    });
  } catch (err: unknown) {
    // Treat TouchID/FaceID cancellation and related errors as a negative decision
    const cancelled = isUserCancelledSecureConfirm(err);
    const msg = String((toError(err))?.message || err || '');
    if (cancelled) {
      window.parent?.postMessage({ type: 'WALLET_UI_CLOSED' }, '*');
    }
    const isWrongPasskeyError = /multiple passkeys \(devicenumbers\) for account/i.test(msg);
    return session.confirmAndCloseModal({
      requestId: request.requestId,
      intentDigest: getIntentDigest(request),
      confirmed: false,
      error: cancelled
        ? ERROR_MESSAGES.cancelled
        : (isWrongPasskeyError ? msg : (msg || ERROR_MESSAGES.collectCredentialsFailed)),
    });
  }
}
