import type { ClientAuthenticatorData } from '../../../IndexedDBManager';
import type { SignedTransaction } from '../../../near/NearClient';
import type { ActionArgsWasm } from '../../../types/actions';
import type { AuthenticatorOptions } from '../../../types/authenticatorOptions';
import type { AccountId } from '../../../types/accountIds';
import type { WebAuthnAuthenticationCredential, WebAuthnRegistrationCredential } from '../../../types';
import {
  decryptPrivateKeyWithPrf,
} from './nearKeyOps/decryptPrivateKeyWithPrf';
import {
  recoverKeypairFromPasskey,
} from './nearKeyOps/recoverKeypairFromPasskey';
import {
  extractCosePublicKey,
} from './nearKeyOps/extractCosePublicKey';
import {
  signTransactionWithKeyPair,
} from './nearKeyOps/signTransactionWithKeyPair';
import {
  deriveNearKeypairAndEncryptFromSerialized,
} from './nearKeyOps/deriveNearKeypairAndEncryptFromSerialized';
import {
  exportNearKeypairUi,
} from './nearKeyOps/exportNearKeypairUi';
import {
  deriveThresholdEd25519ClientVerifyingShare,
} from './nearKeyOps/deriveThresholdEd25519ClientVerifyingShare';
import type { SignerWorkerManagerContext } from './index';

export class NearSigningKeyOpsService {
  private readonly getContext: () => SignerWorkerManagerContext;

  constructor(getContext: () => SignerWorkerManagerContext) {
    this.getContext = getContext;
  }

  async deriveNearKeypairAndEncryptFromSerialized(args: {
    credential: WebAuthnRegistrationCredential;
    nearAccountId: AccountId;
    options?: {
      authenticatorOptions?: AuthenticatorOptions;
      deviceNumber?: number;
      persistToDb?: boolean;
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
    encryptedSk?: string;
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

  async decryptPrivateKeyWithPrf(args: {
    nearAccountId: AccountId;
    authenticators: ClientAuthenticatorData[];
    sessionId: string;
    prfFirstB64u?: string;
    wrapKeySalt?: string;
    encryptedPrivateKeyData?: string;
    encryptedPrivateKeyChacha20NonceB64u?: string;
    deviceNumber?: number;
  }): Promise<{
    decryptedPrivateKey: string;
    nearAccountId: AccountId;
  }> {
    return decryptPrivateKeyWithPrf({ ctx: this.getContext(), ...args });
  }

  async recoverKeypairFromPasskey(args: {
    credential: WebAuthnAuthenticationCredential;
    accountIdHint?: string;
    sessionId: string;
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

  async extractCosePublicKey(attestationObjectBase64url: string): Promise<Uint8Array> {
    return extractCosePublicKey({ ctx: this.getContext(), attestationObjectBase64url });
  }

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

  async exportNearKeypairUi(args: {
    nearAccountId: AccountId;
    variant?: 'drawer' | 'modal';
    theme?: 'dark' | 'light';
    sessionId: string;
    prfFirstB64u: string;
    wrapKeySalt: string;
  }): Promise<void> {
    return exportNearKeypairUi({ ctx: this.getContext(), ...args });
  }
}
