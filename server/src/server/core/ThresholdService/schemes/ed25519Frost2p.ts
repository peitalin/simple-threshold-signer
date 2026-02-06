import type {
  ThresholdEd25519AuthorizeResponse,
  ThresholdEd25519AuthorizeWithSessionRequest,
  ThresholdEd25519KeygenRequest,
  ThresholdEd25519KeygenResponse,
  ThresholdEd25519SessionRequest,
  ThresholdEd25519SessionResponse,
} from '../../types';
import type { ThresholdEd25519SessionClaims } from '../validation';
import { THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID } from './schemeIds';
import type {
  ThresholdEd25519Frost2pSchemeModule,
  ThresholdEd25519RegistrationKeygenRequest,
  ThresholdEd25519RegistrationKeygenResult,
} from './types';

export type ThresholdEd25519Frost2pSchemeModuleDeps = {
  healthz?: () => Promise<{ ok: boolean; code?: string; message?: string }>;
  keygen(request: ThresholdEd25519KeygenRequest): Promise<ThresholdEd25519KeygenResponse>;
  registrationKeygenFromClientVerifyingShare(
    request: ThresholdEd25519RegistrationKeygenRequest
  ): Promise<ThresholdEd25519RegistrationKeygenResult>;
  session(request: ThresholdEd25519SessionRequest): Promise<ThresholdEd25519SessionResponse>;
  authorize(input: {
    claims: ThresholdEd25519SessionClaims;
    request: ThresholdEd25519AuthorizeWithSessionRequest;
  }): Promise<ThresholdEd25519AuthorizeResponse>;
  protocol: ThresholdEd25519Frost2pSchemeModule['protocol'];
};

export function createThresholdEd25519Frost2pSchemeModule(
  deps: ThresholdEd25519Frost2pSchemeModuleDeps
): ThresholdEd25519Frost2pSchemeModule {
  return {
    schemeId: THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID,
    healthz: deps.healthz || (async () => ({ ok: true })),
    keygen: deps.keygen,
    registration: {
      keygenFromClientVerifyingShare: deps.registrationKeygenFromClientVerifyingShare,
    },
    session: deps.session,
    authorize: deps.authorize,
    protocol: deps.protocol,
  };
}
