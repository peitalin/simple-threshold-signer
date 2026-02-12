import { ClientAuthenticatorData, UnifiedIndexedDBManager } from '../../../IndexedDBManager';
import { IndexedDBManager } from '../../../IndexedDBManager';
import { SignedTransaction, type NearClient } from '../../../near/NearClient';
import {
  type WorkerResponseForRequest,
  type WorkerRequestTypeMap,
} from '../../../types/signer-worker';
import { SecureConfirmWorkerManager } from '../../secureConfirm/manager';
import type { ActionArgsWasm } from '../../../types/actions';
import type { AuthenticatorOptions } from '../../../types/authenticatorOptions';
import { AccountId } from "../../../types/accountIds";
import { TouchIdPrompt } from "../../webauthn/prompt/touchIdPrompt";
import type { MultichainSignerRuntimeDeps } from '../../chains/types';
import type { NearSignerWorkerRequestArgs } from './backends/types';

import {
  decryptPrivateKeyWithPrf,
} from './keyOps/decryptPrivateKeyWithPrf';
import {
  recoverKeypairFromPasskey,
} from './keyOps/recoverKeypairFromPasskey';
import {
  extractCosePublicKey,
} from './keyOps/extractCosePublicKey';
import {
  signTransactionWithKeyPair,
} from './keyOps/signTransactionWithKeyPair';
import {
  deriveNearKeypairAndEncryptFromSerialized,
} from './keyOps/deriveNearKeypairAndEncryptFromSerialized';
import {
  exportNearKeypairUi,
} from './keyOps/exportNearKeypairUi';
import {
  deriveThresholdEd25519ClientVerifyingShare,
} from './keyOps/deriveThresholdEd25519ClientVerifyingShare';
import { UserPreferencesManager } from '../../api/userPreferences';
import { NonceManager } from '../../../near/nonceManager';
import type { ThemeName } from '../../../types/tatchi';
import { WebAuthnAuthenticationCredential, WebAuthnRegistrationCredential } from '../../../types';
import { NearSignerWorkerBackend } from './backends/nearWorkerBackend';

export interface SigningWorkerManagerContext extends MultichainSignerRuntimeDeps {
  userPreferencesManager: UserPreferencesManager;
  getTheme?: () => ThemeName;
  rpIdOverride?: string;
  nearExplorerUrl?: string;
}

/**
 * WebAuthnWorkers handles PRF, workers, and COSE operations
 *
 * Note: This stack is WebAuthn-only; challenges are either server-minted
 * (e.g. login) or derived from intent/session digests (e.g. threshold sessions).
 */
export class SigningWorkerManager {

  private indexedDB: UnifiedIndexedDBManager;
  private touchIdPrompt: TouchIdPrompt;
  private secureConfirmWorkerManager: SecureConfirmWorkerManager;
  private nearClient: NearClient;
  private userPreferencesManager: UserPreferencesManager;
  private nonceManager: NonceManager;
  private relayerUrl: string;
  private nearExplorerUrl?: string;
  private getTheme?: () => ThemeName;
  private nearWorkerBackend: NearSignerWorkerBackend;

  constructor(
    secureConfirmWorkerManager: SecureConfirmWorkerManager,
    nearClient: NearClient,
    userPreferencesManager: UserPreferencesManager,
    nonceManager: NonceManager,
    relayerUrl: string,
    rpIdOverride?: string,
    enableSafariGetWebauthnRegistrationFallback: boolean = true,
    nearExplorerUrl?: string,
    getTheme?: () => ThemeName,
  ) {
    this.indexedDB = IndexedDBManager;
    this.touchIdPrompt = new TouchIdPrompt(rpIdOverride, enableSafariGetWebauthnRegistrationFallback);
    this.secureConfirmWorkerManager = secureConfirmWorkerManager;
    this.nearClient = nearClient;
    this.userPreferencesManager = userPreferencesManager;
    this.nonceManager = nonceManager;
    this.relayerUrl = relayerUrl;
    this.nearExplorerUrl = nearExplorerUrl;
    this.getTheme = getTheme;
    this.nearWorkerBackend = new NearSignerWorkerBackend();
  }

  setWorkerBaseOrigin(origin: string | undefined): void {
    this.nearWorkerBackend.setWorkerBaseOrigin(origin);
  }

  getContext(): SigningWorkerManagerContext {
    return {
      sendMessage: this.sendMessage.bind(this),
      indexedDB: this.indexedDB,
      touchIdPrompt: this.touchIdPrompt,
      secureConfirmWorkerManager: this.secureConfirmWorkerManager,
      nearClient: this.nearClient,
      userPreferencesManager: this.userPreferencesManager,
      nonceManager: this.nonceManager,
      getTheme: this.getTheme,
      rpIdOverride: this.touchIdPrompt.getRpId(),
      nearExplorerUrl: this.nearExplorerUrl,
      relayerUrl: this.relayerUrl,
    };
  }

  createSecureWorker(): Worker {
    return this.nearWorkerBackend.createSecureWorker();
  }

  /**
   * Pre-warm worker pool by creating and initializing workers in advance
   * This reduces latency for the first transaction by having workers ready
   */
  async preWarmWorkerPool(): Promise<void> {
    await this.nearWorkerBackend.preWarmWorkerPool();
  }

  private async sendMessage<T extends keyof WorkerRequestTypeMap>({
    sessionId,
    message,
    onEvent,
    timeoutMs,
  }: NearSignerWorkerRequestArgs<T>): Promise<WorkerResponseForRequest<T>> {
    const request = {
      sessionId,
      message,
      ...(onEvent ? { onEvent } : {}),
      ...(typeof timeoutMs === 'number' ? { timeoutMs } : {}),
    };
    return await this.nearWorkerBackend.sendMessage(request);
  }

  /**
   * Derive NEAR keypair from a serialized WebAuthn registration credential
   */
  async deriveNearKeypairAndEncryptFromSerialized(args: {
    credential: WebAuthnRegistrationCredential;
    nearAccountId: AccountId;
    options?: {
      authenticatorOptions?: AuthenticatorOptions;
      deviceNumber?: number;
    };
    sessionId: string;
  }): Promise<{
    success: boolean;
    nearAccountId: AccountId;
    publicKey: string;
    /**
     * Base64url-encoded AEAD nonce (ChaCha20-Poly1305) for the encrypted private key.
     */
    chacha20NonceB64u?: string;
    wrapKeySalt?: string;
  }> {
    return deriveNearKeypairAndEncryptFromSerialized({ ctx: this.getContext(), ...args });
  }

  async deriveThresholdEd25519ClientVerifyingShare(args: {
    sessionId: string;
    nearAccountId: AccountId;
    prfFirstB64u: string;
    wrapKeySalt: string;
  }): Promise<{
    success: boolean;
    nearAccountId: string;
    clientVerifyingShareB64u: string;
    error?: string;
  }> {
    return deriveThresholdEd25519ClientVerifyingShare({
      ctx: this.getContext(),
      sessionId: args.sessionId,
      nearAccountId: String(args.nearAccountId),
      prfFirstB64u: args.prfFirstB64u,
      wrapKeySalt: args.wrapKeySalt,
    });
  }

  /**
   * Secure private key decryption with dual PRF
   */
  async decryptPrivateKeyWithPrf(args: {
    nearAccountId: AccountId,
    authenticators: ClientAuthenticatorData[],
    sessionId: string,
    prfFirstB64u?: string;
    wrapKeySalt?: string;
  }): Promise<{
    decryptedPrivateKey: string;
    nearAccountId: AccountId
  }> {
    return decryptPrivateKeyWithPrf({ ctx: this.getContext(), ...args });
  }

  /**
   * Recover keypair from authentication credential for account recovery
   * Uses dual PRF-based Ed25519 key derivation with account-specific HKDF and AES encryption
   */
  async recoverKeypairFromPasskey(args: {
    credential: WebAuthnAuthenticationCredential;
    accountIdHint?: string;
    sessionId: string,
  }): Promise<{
    publicKey: string;
    encryptedPrivateKey: string;
    /** Base64url-encoded AEAD nonce (ChaCha20-Poly1305) for encrypted key */
    chacha20NonceB64u: string;
    accountIdHint?: string;
    wrapKeySalt: string;
  }> {
    return recoverKeypairFromPasskey({ ctx: this.getContext(), ...args });
  }

  /**
   * Extract COSE public key from WebAuthn attestation object
   * Simple operation that doesn't require TouchID or progress updates
   */
  async extractCosePublicKey(attestationObjectBase64url: string): Promise<Uint8Array> {
    return extractCosePublicKey({ ctx: this.getContext(), attestationObjectBase64url });
  }

  /**
   * Sign transaction with raw private key (for key replacement in Option D device linking)
   * No TouchID/PRF required - uses provided private key directly
   */
  async signTransactionWithKeyPair(args: {
    nearPrivateKey: string;
    signerAccountId: string;
    receiverId: string;
    nonce: string;
    blockHash: string;
    actions: ActionArgsWasm[];
  }): Promise<{
    signedTransaction: SignedTransaction;
    logs?: string[];
  }> {
    return signTransactionWithKeyPair({ ctx: this.getContext(), ...args });
  }

  /**
   * Two-phase export (worker-driven):
   *  - Phase 1: collect PRF (uiMode: 'none')
   *  - Decrypt inside worker
   *  - Phase 2: show export UI with decrypted key (kept open until user closes)
   */
  async exportNearKeypairUi(args: {
    nearAccountId: AccountId,
    variant?: 'drawer'|'modal',
    theme?: 'dark'|'light',
    sessionId: string,
    prfFirstB64u: string;
    wrapKeySalt: string;
  }): Promise<void> {
    return exportNearKeypairUi({ ctx: this.getContext(), ...args });
  }

}
