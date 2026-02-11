import type {
  ThresholdEd25519AuthorizeResponse,
  ThresholdEd25519AuthorizeWithSessionRequest,
  ThresholdEd25519CosignFinalizeRequest,
  ThresholdEd25519CosignFinalizeResponse,
  ThresholdEd25519CosignInitRequest,
  ThresholdEd25519CosignInitResponse,
  ThresholdEcdsaKeygenRequest,
  ThresholdEcdsaKeygenResponse,
  ThresholdEcdsaAuthorizeResponse,
  ThresholdEcdsaAuthorizeWithSessionRequest,
  ThresholdEcdsaCosignFinalizeRequest,
  ThresholdEcdsaCosignFinalizeResponse,
  ThresholdEcdsaCosignInitRequest,
  ThresholdEcdsaCosignInitResponse,
  ThresholdEcdsaSessionRequest,
  ThresholdEcdsaSessionResponse,
  ThresholdEcdsaPresignInitRequest,
  ThresholdEcdsaPresignInitResponse,
  ThresholdEcdsaPresignStepRequest,
  ThresholdEcdsaPresignStepResponse,
  ThresholdEcdsaSignFinalizeRequest,
  ThresholdEcdsaSignFinalizeResponse,
  ThresholdEcdsaSignInitRequest,
  ThresholdEcdsaSignInitResponse,
  ThresholdEd25519KeygenRequest,
  ThresholdEd25519KeygenResponse,
  ThresholdEd25519SessionRequest,
  ThresholdEd25519SessionResponse,
  ThresholdEd25519SignFinalizeRequest,
  ThresholdEd25519SignFinalizeResponse,
  ThresholdEd25519SignInitRequest,
  ThresholdEd25519SignInitResponse,
} from '../../types';
import type { ThresholdEd25519SessionClaims, ThresholdEcdsaSessionClaims } from '../validation';
import type { ThresholdSchemeId } from './schemeIds';

export interface ThresholdProtocolDriver<
  SignInitReq,
  SignInitRes,
  SignFinalizeReq,
  SignFinalizeRes,
  CosignInitReq = never,
  CosignInitRes = never,
  CosignFinalizeReq = never,
  CosignFinalizeRes = never
> {
  signInit(request: SignInitReq): Promise<SignInitRes>;
  signFinalize(request: SignFinalizeReq): Promise<SignFinalizeRes>;
  internalCosignInit?: (request: CosignInitReq) => Promise<CosignInitRes>;
  internalCosignFinalize?: (request: CosignFinalizeReq) => Promise<CosignFinalizeRes>;
}

export interface ThresholdSchemeModule<
  SchemeId extends ThresholdSchemeId,
  KeygenReq,
  KeygenRes,
  SessionReq,
  SessionRes,
  AuthorizeClaims,
  AuthorizeReq,
  AuthorizeRes,
  SignInitReq,
  SignInitRes,
  SignFinalizeReq,
  SignFinalizeRes,
  CosignInitReq = never,
  CosignInitRes = never,
  CosignFinalizeReq = never,
  CosignFinalizeRes = never
> {
  schemeId: SchemeId;
  protocol: ThresholdProtocolDriver<
    SignInitReq,
    SignInitRes,
    SignFinalizeReq,
    SignFinalizeRes,
    CosignInitReq,
    CosignInitRes,
    CosignFinalizeReq,
    CosignFinalizeRes
  >;

  healthz(): Promise<{ ok: boolean; code?: string; message?: string }>;

  keygen(request: KeygenReq): Promise<KeygenRes>;
  session(request: SessionReq): Promise<SessionRes>;
  authorize(input: { claims: AuthorizeClaims; request: AuthorizeReq }): Promise<AuthorizeRes>;
}

export type ThresholdEd25519RegistrationKeygenRequest = {
  nearAccountId: string;
  rpId: string;
  clientVerifyingShareB64u: string;
};

export type ThresholdEd25519RegistrationKeygenResult =
  | {
      ok: true;
      clientParticipantId: number;
      relayerParticipantId: number;
      participantIds: number[];
      relayerKeyId: string;
      publicKey: string;
      relayerVerifyingShareB64u: string;
    }
  | { ok: false; code: string; message: string };

export type ThresholdEd25519Frost2pSchemeModule = ThresholdSchemeModule<
  'threshold-ed25519-frost-2p-v1',
  ThresholdEd25519KeygenRequest,
  ThresholdEd25519KeygenResponse,
  ThresholdEd25519SessionRequest,
  ThresholdEd25519SessionResponse,
  ThresholdEd25519SessionClaims,
  ThresholdEd25519AuthorizeWithSessionRequest,
  ThresholdEd25519AuthorizeResponse,
  ThresholdEd25519SignInitRequest,
  ThresholdEd25519SignInitResponse,
  ThresholdEd25519SignFinalizeRequest,
  ThresholdEd25519SignFinalizeResponse,
  ThresholdEd25519CosignInitRequest,
  ThresholdEd25519CosignInitResponse,
  ThresholdEd25519CosignFinalizeRequest,
  ThresholdEd25519CosignFinalizeResponse
> & {
  registration: {
    keygenFromClientVerifyingShare(request: ThresholdEd25519RegistrationKeygenRequest): Promise<ThresholdEd25519RegistrationKeygenResult>;
  };
};

export type ThresholdSecp256k1Ecdsa2pSchemeModule = ThresholdSchemeModule<
  'threshold-secp256k1-ecdsa-2p-v1',
  ThresholdEcdsaKeygenRequest,
  ThresholdEcdsaKeygenResponse,
  ThresholdEcdsaSessionRequest,
  ThresholdEcdsaSessionResponse,
  ThresholdEcdsaSessionClaims,
  ThresholdEcdsaAuthorizeWithSessionRequest,
  ThresholdEcdsaAuthorizeResponse,
  ThresholdEcdsaSignInitRequest,
  ThresholdEcdsaSignInitResponse,
  ThresholdEcdsaSignFinalizeRequest,
  ThresholdEcdsaSignFinalizeResponse,
  ThresholdEcdsaCosignInitRequest,
  ThresholdEcdsaCosignInitResponse,
  ThresholdEcdsaCosignFinalizeRequest,
  ThresholdEcdsaCosignFinalizeResponse
> & {
  presign: {
    init(input: { claims: ThresholdEcdsaSessionClaims; request: ThresholdEcdsaPresignInitRequest }): Promise<ThresholdEcdsaPresignInitResponse>;
    step(input: { claims: ThresholdEcdsaSessionClaims; request: ThresholdEcdsaPresignStepRequest }): Promise<ThresholdEcdsaPresignStepResponse>;
  };
};

export type ThresholdAnySchemeModule =
  | ThresholdEd25519Frost2pSchemeModule
  | ThresholdSecp256k1Ecdsa2pSchemeModule;
