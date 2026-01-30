import type { KeyRef, SignRequest, SignerEngine, SignatureBytes } from '../types';
import { signSecp256k1RecoverableWasm } from '../evm/ethSignerWasm';

export class LocalSecp256k1Engine implements SignerEngine {
  readonly algorithm = 'secp256k1' as const;

  async sign(req: SignRequest, keyRef: KeyRef): Promise<SignatureBytes> {
    if (req.kind !== 'digest' || req.algorithm !== 'secp256k1') {
      throw new Error('[LocalSecp256k1Engine] unsupported sign request');
    }
    if (req.digest32.length !== 32) {
      throw new Error('[LocalSecp256k1Engine] digest32 must be 32 bytes');
    }
    if (keyRef.type !== 'local-secp256k1') {
      throw new Error('[LocalSecp256k1Engine] keyRef must be local-secp256k1');
    }
    if (keyRef.privateKey.length !== 32) {
      throw new Error('[LocalSecp256k1Engine] privateKey must be 32 bytes');
    }

    return await signSecp256k1RecoverableWasm({
      digest32: req.digest32,
      privateKey32: keyRef.privateKey,
    });
  }
}
