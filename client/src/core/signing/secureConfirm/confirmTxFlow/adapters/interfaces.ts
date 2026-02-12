import type { ConfirmationConfig } from '../../../../types/signer-worker';
import type { TransactionContext, SecureConfirmSecurityContext } from '../../../../types';
import type { ConfirmUIHandle } from '../../ui/confirm-ui';
import type { ProfileAuthenticatorRecord } from '../../../../IndexedDBManager';
import type { KnownSecureConfirmRequest, SerializableCredential, TransactionSummary } from '../types';
import type { ThemeName } from '../../../../types/tatchi';

export type NearContextResult = {
  transactionContext: TransactionContext | null;
  error?: string;
  details?: string;
  reservedNonces?: string[];
};

export interface NearContextProvider {
  fetchNearContext(opts: { nearAccountId: string; txCount: number; reserveNonces: boolean }): Promise<NearContextResult>;
  releaseReservedNonces(nonces?: string[]): void;
}

export interface SecurityContextProvider {
  getRpId(): string;
}

export interface WebAuthnCollector {
  collectAuthenticationCredentialWithPRF(args: {
    nearAccountId: string;
    challengeB64u: string;
    onBeforePrompt?: (info: {
      authenticators: ProfileAuthenticatorRecord[];
      authenticatorsForPrompt: ProfileAuthenticatorRecord[];
      challengeB64u: string;
    }) => void;
    includeSecondPrfOutput?: boolean;
  }): Promise<SerializableCredential>;

  createRegistrationCredential(args: {
    nearAccountId: string;
    challengeB64u: string;
    deviceNumber?: number;
  }): Promise<PublicKeyCredential>;
}

export interface ConfirmUiRenderer {
  renderConfirmUI(args: {
    request: KnownSecureConfirmRequest;
    confirmationConfig: ConfirmationConfig;
    transactionSummary: TransactionSummary;
    securityContext?: Partial<SecureConfirmSecurityContext>;
    theme: ThemeName;
  }): Promise<{ confirmed: boolean; confirmHandle?: ConfirmUIHandle; error?: string }>;

  closeModalSafely(confirmed: boolean, handle?: ConfirmUIHandle): void;
}

export interface ConfirmTxFlowAdapters {
  near: NearContextProvider;
  security: SecurityContextProvider;
  webauthn: WebAuthnCollector;
  ui: ConfirmUiRenderer;
}
