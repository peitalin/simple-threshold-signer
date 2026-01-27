/**
 * SecureConfirm UI context
 *
 * This is display-only metadata shown in the wallet-origin confirmer UI.
 * It should not contain secrets (PRF outputs, keys, etc).
 */
export interface SecureConfirmSecurityContext {
  rpId?: string;
  blockHeight?: string;
  blockHash?: string;
}

