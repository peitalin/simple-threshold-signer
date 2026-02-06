import type { WebAuthnAuthenticationCredential } from '../types/webauthn';

export type ChainNamespace = 'near' | 'tempo';

export type SignatureAlgorithm = 'ed25519' | 'secp256k1' | 'webauthn-p256';

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
      thresholdSessionKind?: 'jwt' | 'cookie';
      thresholdSessionJwt?: string;
      mpcSessionId?: string;
    }
  | { type: 'webauthn-p256'; credentialId: Uint8Array; pubKeyX: Uint8Array; pubKeyY: Uint8Array; rpId?: string };

export type SignRequest =
  | {
      kind: 'digest';
      algorithm: Exclude<SignatureAlgorithm, 'webauthn-p256'>;
      digest32: Uint8Array;
      label?: string;
    }
  | {
      kind: 'webauthn';
      algorithm: 'webauthn-p256';
      challenge32: Uint8Array;
      rpId?: string;
      label?: string;
      /**
       * Optional serialized WebAuthn credential collected by SecureConfirm.
       * When present, engines must not call `navigator.credentials.get`.
       */
      credential?: WebAuthnAuthenticationCredential;
    };

export interface SigningIntent<UiModel = unknown, Result = unknown> {
  chain: ChainNamespace;
  uiModel: UiModel;
  signRequests: SignRequest[];
  finalize: (signatures: SignatureBytes[]) => Promise<Result>;
}

export interface ChainAdapter<Request = unknown, UiModel = unknown, Result = unknown> {
  readonly chain: ChainNamespace;
  buildIntent: (request: Request) => Promise<SigningIntent<UiModel, Result>>;
}

export interface SignerEngine {
  readonly algorithm: SignatureAlgorithm;
  sign: (req: SignRequest, keyRef: KeyRef) => Promise<SignatureBytes>;
}
