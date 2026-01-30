import type { SecureConfirmWorkerManagerContext } from '../../';
import type { ConfirmationConfig } from '../../../../types/signer-worker';
import {
  SecureConfirmationType,
  TransactionSummary,
  type IntentDigestSecureConfirmRequest,
  type SigningAuthMode,
} from '../types';
import type { SecureConfirmSecurityContext } from '../../../../types';
import {
  getNearAccountId,
  getIntentDigest,
  isUserCancelledSecureConfirm,
  ERROR_MESSAGES,
} from './index';
import { toError } from '../../../../../utils/errors';
import { createConfirmSession } from '../adapters/session';
import { createConfirmTxFlowAdapters } from '../adapters/createAdapters';
import type { ThemeName } from '../../../../types/tatchi';
import { collectAuthenticationCredentialForChallengeB64u } from '../../../collectAuthenticationCredentialForChallengeB64u';

function getSigningAuthMode(request: IntentDigestSecureConfirmRequest): SigningAuthMode {
  return request.payload.signingAuthMode ?? 'webauthn';
}

export async function handleIntentDigestSigningFlow(
  ctx: SecureConfirmWorkerManagerContext,
  request: IntentDigestSecureConfirmRequest,
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
    const rpId = adapters.security.getRpId();
    const securityContext: Partial<SecureConfirmSecurityContext> | undefined = rpId ? { rpId } : undefined;

    const { confirmed, error: uiError } = await session.promptUser({ securityContext });
    if (!confirmed) {
      return session.confirmAndCloseModal({
        requestId: request.requestId,
        intentDigest: getIntentDigest(request),
        confirmed: false,
        error: uiError,
      });
    }

    if (signingAuthMode === 'warmSession') {
      return session.confirmAndCloseModal({
        requestId: request.requestId,
        intentDigest: getIntentDigest(request),
        confirmed: true,
      });
    }

    const challengeB64u = String(request.payload.challengeB64u || '').trim();
    if (!challengeB64u) {
      throw new Error('Missing WebAuthn challenge digest for intent signing flow');
    }

    const serializedCredential = await collectAuthenticationCredentialForChallengeB64u({
      indexedDB: ctx.indexedDB,
      touchIdPrompt: ctx.touchIdPrompt,
      nearAccountId,
      challengeB64u,
    });

    return session.confirmAndCloseModal({
      requestId: request.requestId,
      intentDigest: getIntentDigest(request),
      confirmed: true,
      credential: serializedCredential,
    });
  } catch (err: unknown) {
    const cancelled = isUserCancelledSecureConfirm(err);
    const msg = String((toError(err))?.message || err || '');
    if (cancelled) {
      window.parent?.postMessage({ type: 'WALLET_UI_CLOSED' }, '*');
    }
    return session.confirmAndCloseModal({
      requestId: request.requestId,
      intentDigest: getIntentDigest(request),
      confirmed: false,
      error: cancelled ? ERROR_MESSAGES.cancelled : (msg || ERROR_MESSAGES.collectCredentialsFailed),
    });
  }
}

