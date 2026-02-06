export const THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID = 'threshold-ed25519-frost-2p-v1' as const;
export const THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID = 'threshold-secp256k1-ecdsa-2p-v1' as const;

export type ThresholdSchemeId =
  | typeof THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID
  | typeof THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID;
