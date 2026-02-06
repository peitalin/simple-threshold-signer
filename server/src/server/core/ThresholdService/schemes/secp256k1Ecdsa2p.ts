import type {
  ThresholdEcdsaAuthorizeResponse,
  ThresholdEcdsaAuthorizeWithSessionRequest,
  ThresholdEcdsaKeygenRequest,
  ThresholdEcdsaKeygenResponse,
  ThresholdEcdsaPresignInitRequest,
  ThresholdEcdsaPresignInitResponse,
  ThresholdEcdsaPresignStepRequest,
  ThresholdEcdsaPresignStepResponse,
  ThresholdEcdsaSessionRequest,
  ThresholdEcdsaSessionResponse,
} from '../../types';
import { THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID } from './schemeIds';
import type { ThresholdSecp256k1Ecdsa2pSchemeModule } from './types';
import type { ThresholdEcdsaSessionClaims } from '../validation';

export type ThresholdSecp256k1Ecdsa2pSchemeModuleDeps = {
  healthz?: () => Promise<{ ok: boolean; code?: string; message?: string }>;
  keygen(request: ThresholdEcdsaKeygenRequest): Promise<ThresholdEcdsaKeygenResponse>;
  session(request: ThresholdEcdsaSessionRequest): Promise<ThresholdEcdsaSessionResponse>;
  authorize(input: { claims: ThresholdEcdsaSessionClaims; request: ThresholdEcdsaAuthorizeWithSessionRequest }): Promise<ThresholdEcdsaAuthorizeResponse>;
  presign: {
    init(input: { claims: ThresholdEcdsaSessionClaims; request: ThresholdEcdsaPresignInitRequest }): Promise<ThresholdEcdsaPresignInitResponse>;
    step(input: { claims: ThresholdEcdsaSessionClaims; request: ThresholdEcdsaPresignStepRequest }): Promise<ThresholdEcdsaPresignStepResponse>;
  };
  protocol: ThresholdSecp256k1Ecdsa2pSchemeModule['protocol'];
};

export function createThresholdSecp256k1Ecdsa2pSchemeModule(
  deps: ThresholdSecp256k1Ecdsa2pSchemeModuleDeps
): ThresholdSecp256k1Ecdsa2pSchemeModule {
  return {
    schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
    async healthz() {
      return deps.healthz ? await deps.healthz() : { ok: true };
    },
    keygen: deps.keygen,
    session: deps.session,
    authorize: deps.authorize,
    presign: deps.presign,
    protocol: deps.protocol,
  };
}
