import type { SignedTransaction } from '../../near/NearClient';
import type { ActionArgsWasm } from '../../types/actions';
import type {
  NearIntentResult,
  NearSigningRequest,
} from '../chainAdaptors/near/nearAdapter';
import type { NearSigningKeyOpsService } from '../workers/signerWorkerManager/nearKeyOpsService';

export type SignerWorkerBridgeDeps = {
  signingKeyOps: Pick<NearSigningKeyOpsService, 'extractCosePublicKey' | 'signTransactionWithKeyPair'>;
};

export async function signNearWithIntent<TRequest extends NearSigningRequest>(
  request: TRequest,
): Promise<NearIntentResult<TRequest>> {
  const [{ signWithIntent }, { NearAdapter }, { NearEd25519Engine, NEAR_ED25519_KEY_REF }] =
    await Promise.all([
      import('../orchestration/signWithIntent'),
      import('../chainAdaptors/near/nearAdapter'),
      import('../engines/ed25519'),
    ]);

  return await signWithIntent({
    adapter: new NearAdapter(),
    request,
    engines: { ed25519: new NearEd25519Engine() } as any,
    resolveSignInput: async (signReq) => ({ signReq, keyRef: NEAR_ED25519_KEY_REF }),
  }) as NearIntentResult<TRequest>;
}

export async function extractCosePublicKey(
  deps: SignerWorkerBridgeDeps,
  attestationObjectBase64url: string,
): Promise<Uint8Array> {
  return await deps.signingKeyOps.extractCosePublicKey(attestationObjectBase64url);
}

export async function signTransactionWithKeyPair(
  deps: SignerWorkerBridgeDeps,
  args: {
    nearPrivateKey: string;
    signerAccountId: string;
    receiverId: string;
    nonce: string;
    blockHash: string;
    actions: ActionArgsWasm[];
  },
): Promise<{
  signedTransaction: SignedTransaction;
  logs?: string[];
}> {
  return await deps.signingKeyOps.signTransactionWithKeyPair({
    nearPrivateKey: args.nearPrivateKey,
    signerAccountId: args.signerAccountId,
    receiverId: args.receiverId,
    nonce: args.nonce,
    blockHash: args.blockHash,
    actions: args.actions,
  });
}
