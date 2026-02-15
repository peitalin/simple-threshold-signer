import type { ChainAdapter, SigningIntent, SignatureBytes } from '../../orchestration/types';
import { bytesToHex } from '../evm/bytes';
import {
  computeEip1559TxHashWasm,
  encodeEip1559SignedTxFromSignature65Wasm,
} from '../evm/ethSignerWasm';
import type { Eip1559UnsignedTx } from '../evm/types';
import type { WorkerOperationContext } from '../../workers/operations/executeSignerWorkerOperation';
import type { TempoSigningRequest, TempoUnsignedTx } from './types';
import { computeTempoSenderHashWasm, encodeTempoSignedTxWasm } from './tempoSignerWasm';

export type TempoSignedResult =
  | {
      chain: 'tempo';
      kind: 'tempoTransaction';
      senderHashHex: string;
      rawTxHex: string;
    }
  | {
      chain: 'tempo';
      kind: 'eip1559';
      txHashHex: string;
      rawTxHex: string;
    };

export type TempoIntentUiModel =
  | {
      kind: 'tempoTransaction';
      tx: TempoUnsignedTx;
    }
  | {
      kind: 'eip1559';
      tx: Eip1559UnsignedTx;
    };

export class TempoAdapter implements ChainAdapter<
  TempoSigningRequest,
  TempoIntentUiModel,
  TempoSignedResult
> {
  readonly chain = 'tempo' as const;
  private readonly workerCtx: WorkerOperationContext;

  constructor(workerCtx: WorkerOperationContext) {
    this.workerCtx = workerCtx;
  }

  async buildIntent(
    request: TempoSigningRequest,
  ): Promise<SigningIntent<TempoIntentUiModel, TempoSignedResult>> {
    if (request.chain !== 'tempo') {
      throw new Error('[TempoAdapter] invalid chain');
    }

    if (request.kind === 'eip1559') {
      const txHash = await computeEip1559TxHashWasm(request.tx, this.workerCtx);
      const txHashHex = bytesToHex(txHash);

      return {
        chain: 'tempo',
        uiModel: { kind: 'eip1559', tx: request.tx },
        signRequests: [
          {
            kind: 'digest',
            algorithm: 'secp256k1',
            digest32: txHash,
            label: 'tempo:eip1559:sender',
          },
        ],
        finalize: async (sigs: SignatureBytes[]) => {
          const raw = await encodeEip1559SignedTxFromSignature65Wasm({
            tx: request.tx,
            signature65: sigs[0]!,
            workerCtx: this.workerCtx,
          });
          return { chain: 'tempo', kind: 'eip1559', txHashHex, rawTxHex: bytesToHex(raw) };
        },
      };
    }

    if (request.kind === 'tempoTransaction') {
      const senderHash = await computeTempoSenderHashWasm(request.tx, this.workerCtx);
      const senderHashHex = bytesToHex(senderHash);

      return {
        chain: 'tempo',
        uiModel: { kind: 'tempoTransaction', tx: request.tx },
        signRequests: [
          request.senderSignatureAlgorithm === 'webauthnP256'
            ? {
                kind: 'webauthn',
                algorithm: 'webauthnP256',
                challenge32: senderHash,
                label: 'tempo:0x76:sender',
              }
            : {
                kind: 'digest',
                algorithm: 'secp256k1',
                digest32: senderHash,
                label: 'tempo:0x76:sender',
              },
        ],
        finalize: async (sigs: SignatureBytes[]) => {
          const raw = await encodeTempoSignedTxWasm({
            tx: request.tx,
            senderSignature: sigs[0]!,
            workerCtx: this.workerCtx,
          });
          return {
            chain: 'tempo',
            kind: 'tempoTransaction',
            senderHashHex,
            rawTxHex: bytesToHex(raw),
          };
        },
      };
    }

    const _exhaustive: never = request;
    return _exhaustive;
  }
}
