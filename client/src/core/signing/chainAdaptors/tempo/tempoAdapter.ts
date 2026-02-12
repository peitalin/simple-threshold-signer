import type { ChainAdapter, SigningIntent, SignatureBytes } from '../../orchestration/types';
import { bytesToHex } from '../evm/bytes';
import { computeEip1559TxHashWasm, encodeEip1559SignedTxWasm } from '../evm/ethSignerWasm';
import type { WorkerOperationContext } from '../handlers/executeSignerWorkerOperation';
import type { TempoSigningRequest } from './types';
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

function parseRecoveredSecp256k1Signature(sig65: Uint8Array): { r: Uint8Array; s: Uint8Array; recovery: number } {
  if (sig65.length !== 65) throw new Error('secp256k1 recovered signature must be 65 bytes');
  return { r: sig65.slice(0, 32), s: sig65.slice(32, 64), recovery: sig65[64] };
}

function assertTempoWebAuthnSignature(sig: Uint8Array): void {
  // Tempo WebAuthn signature encoding:
  // 0x02 || webauthn_data || r || s || pub_key_x || pub_key_y
  // Minimum length: 1 + 0 + 128 = 129 bytes; maximum: 2049 bytes (2KB + typeId).
  if (sig.length < 129 || sig.length > 2049) throw new Error('[TempoAdapter] invalid WebAuthn signature length');
  if (sig[0] !== 0x02) throw new Error('[TempoAdapter] invalid WebAuthn signature typeId (expected 0x02)');
}

export class TempoAdapter implements ChainAdapter<TempoSigningRequest, unknown, TempoSignedResult> {
  readonly chain = 'tempo' as const;
  private readonly workerCtx: WorkerOperationContext;

  constructor(workerCtx: WorkerOperationContext) {
    this.workerCtx = workerCtx;
  }

  async buildIntent(request: TempoSigningRequest): Promise<SigningIntent<unknown, TempoSignedResult>> {
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
          if (sigs.length !== 1) throw new Error('[TempoAdapter] expected one signature');
          const { r, s, recovery } = parseRecoveredSecp256k1Signature(sigs[0]);
          const yParity = (recovery & 1) as 0 | 1;

          const raw = await encodeEip1559SignedTxWasm({
            tx: request.tx,
            yParity,
            r,
            s,
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
          if (sigs.length !== 1) throw new Error('[TempoAdapter] expected one signature');
          const senderSignature = sigs[0];
          if (request.senderSignatureAlgorithm === 'secp256k1') {
            // Tempo secp256k1 signatures are 65 bytes (no type prefix).
            if (senderSignature.length !== 65) {
              throw new Error('[TempoAdapter] secp256k1 Tempo signatures must be 65 bytes');
            }
          } else {
            assertTempoWebAuthnSignature(senderSignature);
          }

          // For MVP: enforce empty AA list and no key authorization until we explicitly support these fields.
          if (request.tx.aaAuthorizationList && (request.tx.aaAuthorizationList as any[])?.length > 0) {
            throw new Error('[TempoAdapter] aaAuthorizationList not supported in MVP (must be empty)');
          }
          if (request.tx.keyAuthorization !== undefined) {
            throw new Error('[TempoAdapter] keyAuthorization not supported in MVP');
          }

          const raw = await encodeTempoSignedTxWasm({
            tx: request.tx,
            senderSignature,
            workerCtx: this.workerCtx,
          });
          return { chain: 'tempo', kind: 'tempoTransaction', senderHashHex, rawTxHex: bytesToHex(raw) };
        },
      };
    }

    const _exhaustive: never = request;
    return _exhaustive;
  }
}
