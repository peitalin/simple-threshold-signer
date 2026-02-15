import { type ThresholdEd25519ParticipantV1 } from '../../../../shared/src/threshold/participants';

export type ClientShareDerivation = 'prf_first_v1';

export type PasskeyNearKeyMaterialKind =
  | 'local_near_sk_v3'
  | 'threshold_ed25519_2p_v1';

export interface BasePasskeyNearKeyMaterial {
  nearAccountId: string;
  deviceNumber: number; // 1-indexed device number
  kind: PasskeyNearKeyMaterialKind;
  /** NEAR ed25519 public key (e.g. `ed25519:...`) */
  publicKey: string;
  /**
   * HKDF salt used alongside WrapKeySeed for KEK derivation.
   *
   * This is required for `local_near_sk_v3` (encrypted key storage) but is not
   * required for threshold-only key material.
   */
  wrapKeySalt?: string;
  timestamp: number;
}

export interface LocalNearSkV3Material extends BasePasskeyNearKeyMaterial {
  kind: 'local_near_sk_v3';
  wrapKeySalt: string;
  encryptedSk: string;
  /**
   * Usage policy for local key material.
   * - `runtime-signing`: may be used by local-signer runtime signing paths.
   * - `export-only`: backup/export material only; runtime signing must reject it.
   */
  usage?: 'runtime-signing' | 'export-only';
  /**
   * Base64url-encoded AEAD nonce (ChaCha20-Poly1305) for `encryptedSk`.
   */
  chacha20NonceB64u: string;
}

export interface ThresholdEd25519_2p_V1Material extends BasePasskeyNearKeyMaterial {
  kind: 'threshold_ed25519_2p_v1';
  relayerKeyId: string;
  clientShareDerivation: ClientShareDerivation;
  /**
   * Versioned participant list for future n-party support.
   * In 2P, participants are `{id:1, role:'client'}` and `{id:2, role:'relayer', ...}`.
   */
  participants: ThresholdEd25519ParticipantV1[];
}

export type PasskeyNearKeyMaterial =
  | LocalNearSkV3Material
  | ThresholdEd25519_2p_V1Material;

export type PasskeyChainKeyAlgorithm =
  | 'ed25519'
  | 'secp256k1'
  | 'webauthn-p256'
  | string;

export type PasskeyChainKeyKind =
  | 'local_sk_encrypted_v1'
  | 'threshold_share_v1'
  | string;

export interface PasskeyChainKeyPayloadEnvelopeAAD {
  profileId: string;
  deviceNumber: number;
  chainId: string;
  keyKind: string;
  schemaVersion: number;
  signerId?: string;
  accountAddress?: string;
}

export interface PasskeyChainKeyPayloadEnvelope {
  encVersion: number;
  alg: string;
  nonce: string;
  ciphertext: string;
  tag?: string;
  aad: PasskeyChainKeyPayloadEnvelopeAAD;
}

export interface PasskeyChainKeyMaterialV2 {
  profileId: string;
  deviceNumber: number;
  chainId: string;
  keyKind: PasskeyChainKeyKind;
  algorithm: PasskeyChainKeyAlgorithm;
  publicKey: string;
  signerId?: string;
  wrapKeySalt?: string;
  payload?: Record<string, unknown>;
  payloadEnvelope?: PasskeyChainKeyPayloadEnvelope;
  timestamp: number;
  schemaVersion: number;
}
