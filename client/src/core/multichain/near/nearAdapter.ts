import type { ChainAdapter, SigningIntent } from '../types';

export type NearSigningRequest = {
  chain: 'near';
  kind: 'transactionsWithActions';
  // Intentionally loose for now; we will align with existing `signTransactionsWithActions` inputs
  // when wiring the adapter into the wallet-origin signer worker.
  payload: unknown;
};

export class NearAdapter implements ChainAdapter<NearSigningRequest, unknown, never> {
  readonly chain = 'near' as const;

  async buildIntent(_request: NearSigningRequest): Promise<SigningIntent<unknown, never>> {
    // NEAR signing today is driven by the wallet-origin signer worker and SecureConfirm:
    // - `core/WebAuthnManager/SignerWorkerManager/handlers/signTransactionsWithActions.ts`
    // - `core/WebAuthnManager/SecureConfirmWorkerManager/confirmTxFlow/*`
    //
    // When we migrate to the multichain layer, this adapter should:
    // - translate NEAR tx payloads into a reviewable UI model
    // - fetch/compute per-tx nonce + block context pre-sign (or via a "lazy digest" abstraction)
    // - produce SignRequests for the signer engine (threshold/local ed25519)
    // - finalize into `SignedTransaction` artifacts.
    throw new Error('[NearAdapter] not implemented');
  }
}
