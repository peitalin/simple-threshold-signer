
export { TatchiPasskey } from './core/TatchiPasskey';
export { WebAuthnManager } from './core/signing/api/WebAuthnManager';
export {
  type NearClient,
  MinimalNearClient,
  encodeSignedTransactionBase64
} from './core/near/NearClient';
export { createWebAuthnLoginOptions, verifyWebAuthnLogin } from './core/near/rpcCalls';

export * from './config';
export { base64UrlEncode, base64UrlDecode } from '@shared/utils/encoders';
export { PASSKEY_MANAGER_DEFAULT_CONFIGS } from './core/config/defaultConfigs';
export { buildConfigsFromEnv } from './core/config/defaultConfigs';

export type {
  TatchiConfigs,
  TatchiConfigsInput,
  // Registration
  RegistrationResult,
  // Login
  LoginResult,
  LoginAndCreateSessionResult,
  LoginSession,
  SigningSessionStatus,
  // Actions
  ActionResult,
} from './core/types/tatchi';

export type {
  RegistrationSSEEvent,
  LoginSSEvent,
  // Device Linking
  DeviceLinkingSSEEvent,
  // Hooks Options
  LoginHooksOptions,
  RegistrationHooksOptions,
  ActionHooksOptions,
  SignNEP413HooksOptions,
  AfterCall,
  EventCallback,
} from './core/types/sdkSentEvents';

export { DEFAULT_WAIT_STATUS } from './core/types/rpc';

// === Device Linking Types ===
export {
  DeviceLinkingPhase,
  DeviceLinkingStatus,
} from './core/types/sdkSentEvents';
export type {
  DeviceLinkingQRData,
  DeviceLinkingSession,
  LinkDeviceResult,
  DeviceLinkingError,
  DeviceLinkingErrorCode
} from './core/types/linkDevice';

// === AccountID Types ===
export type { AccountId } from './core/types/accountIds';
export { toAccountId } from './core/types/accountIds';

export type {
  SignNEP413MessageParams,
  SignNEP413MessageResult
} from './core/TatchiPasskey/signNEP413';

// === Action Types ===
export { ActionType } from './core/types/actions';
export type {
  ActionArgs,
  FunctionCallAction,
  TransferAction,
  CreateAccountAction,
  DeployContractAction,
  StakeAction,
  AddKeyAction,
  DeleteKeyAction,
  DeleteAccountAction
} from './core/types/actions';

// === ERROR TYPES ===
export type { PasskeyErrorDetails } from './core/types/errors';

// === CONFIRMATION TYPES ===
export type {
  ConfirmationConfig,
  ConfirmationUIMode,
  ConfirmationBehavior,
} from './core/types/signer-worker';

// Experimental: signing adapter/engine scaffold (post-lite).
export * from './core/signing/orchestration/types';
export * from './core/signing/engines/ed25519';
export * from './core/signing/engines/secp256k1';
export * from './core/signing/engines/webauthnP256';
export * from './core/signing/orchestration/walletOrigin/thresholdEcdsaCoordinator';
export * from './core/signing/orchestration/walletOrigin/webauthnKeyRef';
export * from './core/signing/webauthn/cose/coseP256';
export * from './core/signing/chains/near/nearAdapter';
export * from './core/signing/chains/tempo/types';
export * from './core/signing/chains/tempo/tempoAdapter';
export { signTempoWithSecureConfirm } from './core/signing/chains/tempo/handlers/signTempoWithSecureConfirm';

// Threshold/lite APIs consolidated into the root SDK entrypoint.
export { keygenThresholdEd25519Lite } from './core/signing/threshold/workflows/keygenThresholdEd25519Lite';
export { keygenThresholdEcdsaLite } from './core/signing/threshold/workflows/keygenThresholdEcdsaLite';
export { connectThresholdEd25519SessionLite } from './core/signing/threshold/workflows/connectThresholdEd25519SessionLite';
export { connectThresholdEcdsaSessionLite } from './core/signing/threshold/workflows/connectThresholdEcdsaSessionLite';
export { authorizeThresholdEcdsaWithSession } from './core/signing/threshold/workflows/thresholdEcdsaAuthorize';
export {
  thresholdEcdsaPresignInit,
  thresholdEcdsaPresignStep,
  thresholdEcdsaSignInit,
  thresholdEcdsaSignFinalize,
} from './core/signing/threshold/workflows/thresholdEcdsaSigning';
export {
  THRESHOLD_SESSION_POLICY_VERSION,
  buildThresholdSessionPolicy,
  buildThresholdEcdsaSessionPolicy,
  computeThresholdSessionPolicyDigest32,
  computeThresholdEcdsaSessionPolicyDigest32,
  type ThresholdEd25519SessionPolicy,
  type ThresholdEcdsaSessionPolicy,
} from './core/signing/threshold/session/thresholdSessionPolicy';
export { PRF_FIRST_SALT_V1, PRF_SECOND_SALT_V1 } from './core/signing/threshold/prfSalts';
export { computeThresholdEd25519KeygenIntentDigest } from './utils/intentDigest';
export { computeThresholdEcdsaKeygenIntentDigest } from './utils/intentDigest';
