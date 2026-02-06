import type { SecureConfirmWorkerManagerContext } from '../../';
import type { ConfirmTxFlowAdapters } from './interfaces';
import { fetchNearContext, releaseReservedNonces } from './near';
import { collectAuthenticationCredentialWithPRF } from './webauthn';
import { closeModalSafely, renderConfirmUI } from './ui';

export function createConfirmTxFlowAdapters(ctx: SecureConfirmWorkerManagerContext): ConfirmTxFlowAdapters {
  return {
    near: {
      fetchNearContext: (opts) => fetchNearContext(ctx, opts),
      releaseReservedNonces: (nonces) => releaseReservedNonces(ctx, nonces),
    },
    security: {
      getRpId: () => ctx.touchIdPrompt.getRpId(),
    },
    webauthn: {
      collectAuthenticationCredentialWithPRF: (args) => collectAuthenticationCredentialWithPRF({ ctx, ...args }),
      createRegistrationCredential: (args) => ctx.touchIdPrompt.generateRegistrationCredentialsInternal(args),
    },
    ui: {
      renderConfirmUI: (args) => renderConfirmUI({ ctx, ...args }),
      closeModalSafely,
    },
  };
}
