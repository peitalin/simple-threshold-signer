/**
 * SecureConfirm worker types
 *
 * The legacy VRF WASM worker has been removed from the threshold-only lite stack.
 * The SecureConfirm worker now hosts:
 * - the SecureConfirm bridge (`awaitSecureConfirmationV2`) used by confirmTxFlow, and
 * - a small PRF.first cache + WrapKeySeed MessagePort wiring for threshold signing.
 */

export interface SecureConfirmWorkerManagerConfig {
  workerUrl?: string;
  workerTimeout?: number;
  debug?: boolean;
}

export type SecureConfirmWorkerMessageType =
  | 'PING'
  | 'THRESHOLD_PRF_FIRST_CACHE_PUT'
  | 'THRESHOLD_PRF_FIRST_CACHE_PEEK'
  | 'THRESHOLD_PRF_FIRST_CACHE_DISPENSE'
  | 'THRESHOLD_PRF_FIRST_CACHE_CLEAR'
  | 'THRESHOLD_PRF_FIRST_SEND_TO_SIGNER'
  | 'THRESHOLD_PRF_FIRST_DISPENSE_TO_SIGNER'
  | 'THRESHOLD_CLEAR_WRAP_KEY_SEED_PORT';

export interface SecureConfirmWorkerMessage<TPayload = unknown> {
  type: SecureConfirmWorkerMessageType;
  id?: string;
  payload?: TPayload;
}

export interface SecureConfirmWorkerResponse<TData = unknown> {
  id?: string;
  success: boolean;
  data?: TData;
  error?: string;
}

