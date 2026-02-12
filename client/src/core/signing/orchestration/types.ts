import type { WebAuthnAuthenticationCredential } from '../../types/webauthn';

export type ChainNamespace = 'near' | 'tempo';

export type SignatureAlgorithm = 'ed25519' | 'secp256k1' | 'webauthnP256';

export type SignatureBytes = Uint8Array;

export type KeyRef =
  | { type: 'local-secp256k1'; privateKey: Uint8Array }
  | {
      type: 'threshold-ecdsa-secp256k1';
      userId: string;
      relayerUrl: string;
      relayerKeyId: string;
      clientVerifyingShareB64u: string;
      participantIds?: number[];
      groupPublicKeyB64u?: string;
      relayerVerifyingShareB64u?: string;
      thresholdSessionKind?: 'jwt' | 'cookie';
      thresholdSessionJwt?: string;
      thresholdSessionId?: string;
      mpcSessionId?: string;
    }
  | {
      type: 'webauthnP256';
      credentialId: Uint8Array;
      pubKeyX: Uint8Array;
      pubKeyY: Uint8Array;
      rpId?: string;
    };

export type ThresholdEcdsaSecp256k1KeyRef = Extract<KeyRef, { type: 'threshold-ecdsa-secp256k1' }>;

export type SignRequest =
  | {
      kind: 'digest';
      algorithm: Exclude<SignatureAlgorithm, 'webauthnP256'>;
      digest32: Uint8Array;
      label?: string;
    }
  | {
      kind: 'webauthn';
      algorithm: 'webauthnP256';
      challenge32: Uint8Array;
      rpId?: string;
      label?: string;
      /**
       * Optional serialized WebAuthn credential collected by SecureConfirm.
       * When present, engines must not call `navigator.credentials.get`.
       */
      credential?: WebAuthnAuthenticationCredential;
    };

export interface SigningIntent<
  UiModel = unknown,
  Result = unknown,
  Request = SignRequest,
  Signed = SignatureBytes,
> {
  chain: ChainNamespace;
  uiModel: UiModel;
  signRequests: Request[];
  finalize: (signatures: Signed[]) => Promise<Result>;
}

export interface ChainAdapter<
  Request = unknown,
  UiModel = unknown,
  Result = unknown,
  SignRequestType = SignRequest,
  Signed = SignatureBytes,
> {
  readonly chain: ChainNamespace;
  buildIntent: (
    request: Request,
  ) => Promise<SigningIntent<UiModel, Result, SignRequestType, Signed>>;
}

export interface SigningEngine<Request = SignRequest, Key = KeyRef, Signed = SignatureBytes> {
  readonly algorithm: SignatureAlgorithm;
  sign: (req: Request, keyRef: Key) => Promise<Signed>;
}

export type SigningEngineMap<
  Request extends { algorithm: string } = SignRequest,
  Key = KeyRef,
  Signed = SignatureBytes,
> = Partial<Record<Request['algorithm'] & string, SigningEngine<Request, Key, Signed>>>;
