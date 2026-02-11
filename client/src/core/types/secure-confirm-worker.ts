/**
 * SecureConfirm worker types
 *
 * The SecureConfirm worker now hosts:
 * - the SecureConfirm bridge (`awaitSecureConfirmationV2`) used by confirmTxFlow, and
 * - a small PRF.first cache for threshold warm sessions.
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
  | 'THRESHOLD_PRF_FIRST_CACHE_CLEAR';

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
