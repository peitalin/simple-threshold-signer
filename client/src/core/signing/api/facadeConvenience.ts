import type { AccountId } from '../../types/accountIds';
import type { ConfirmationConfig } from '../../types/signer-worker';
import type { SigningSessionStatus } from '../../types/tatchi';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../orchestration/types';
import type {
  TempoSecp256k1SigningRequest,
  TempoSigningRequest,
} from '../chainAdaptors/tempo/types';
import type { TempoSignedResult } from '../chainAdaptors/tempo/tempoAdapter';

export type FacadeSignTempoInput = {
  nearAccountId: string;
  request: TempoSigningRequest;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  thresholdEcdsaKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
};

export type FacadeConvenienceDeps = {
  signTempo: (args: FacadeSignTempoInput) => Promise<TempoSignedResult>;
  prewarmSignerWorkers: () => void;
  warmCriticalResources: (nearAccountId?: string) => Promise<void>;
  getWarmSigningSessionStatus: (
    nearAccountId: AccountId | string,
  ) => Promise<SigningSessionStatus | null>;
};

export async function signTempoWithThresholdEcdsa(
  deps: FacadeConvenienceDeps,
  args: {
    nearAccountId: string;
    request: TempoSecp256k1SigningRequest;
    thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
  },
): Promise<TempoSignedResult> {
  if (args.request.senderSignatureAlgorithm !== 'secp256k1') {
    throw new Error(
      '[WebAuthnManager] signTempoWithThresholdEcdsa requires senderSignatureAlgorithm=secp256k1',
    );
  }

  return await deps.signTempo({
    nearAccountId: args.nearAccountId,
    request: args.request,
    thresholdEcdsaKeyRef: args.thresholdEcdsaKeyRef,
    confirmationConfigOverride: args.confirmationConfigOverride,
  });
}

export function prewarmSignerWorkersSurface(deps: FacadeConvenienceDeps): void {
  deps.prewarmSignerWorkers();
}

export async function warmCriticalResourcesSurface(
  deps: FacadeConvenienceDeps,
  nearAccountId?: string,
): Promise<void> {
  await deps.warmCriticalResources(nearAccountId);
}

export async function getWarmSigningSessionStatusSurface(
  deps: FacadeConvenienceDeps,
  nearAccountId: AccountId | string,
): Promise<SigningSessionStatus | null> {
  return await deps.getWarmSigningSessionStatus(nearAccountId);
}
