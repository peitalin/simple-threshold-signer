import init, {
  compute_eip1559_tx_hash,
  encode_eip1559_signed_tx,
  init_eth_signer,
  sign_secp256k1_recoverable,
} from '../../../wasm/eth_signer/pkg/eth_signer.js';
import { initializeWasm, resolveWasmUrl } from './sdkPaths/wasm-loader';
import { errorMessage } from '../../../shared/src/utils/errors';
import { WorkerControlMessage } from './workerControlMessages';

type EthSignerWorkerRequest =
  | { id: string; type: 'computeEip1559TxHash'; payload: { tx: any } }
  | { id: string; type: 'encodeEip1559SignedTx'; payload: { tx: any; yParity: number; r: any; s: any } }
  | { id: string; type: 'signSecp256k1Recoverable'; payload: { digest32: any; privateKey32: any } };

function toU8(v: any): Uint8Array {
  if (v instanceof Uint8Array) return v;
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  throw new Error('expected bytes');
}

const wasmUrl = resolveWasmUrl('eth_signer.wasm', 'Eth Signer');
let wasmInitPromise: Promise<void> | null = null;

async function ensureWasm(): Promise<void> {
  if (wasmInitPromise) return wasmInitPromise;
  wasmInitPromise = (async () => {
    await initializeWasm({
      workerName: 'Eth Signer',
      wasmUrl,
      initFunction: init as any,
      validateFunction: () => init_eth_signer(),
    });
  })();
  return wasmInitPromise;
}

setTimeout(() => {
  (self as any).postMessage({ type: WorkerControlMessage.WORKER_READY, ready: true });
}, 0);

self.addEventListener('message', async (event: MessageEvent) => {
  const msg = event.data as EthSignerWorkerRequest;
  if (!msg?.id || !msg?.type) return;

  try {
    await ensureWasm();
    switch (msg.type) {
      case 'computeEip1559TxHash': {
        const out = compute_eip1559_tx_hash(msg.payload.tx) as Uint8Array;
        const ab = out.slice().buffer;
        (self as any).postMessage({ id: msg.id, ok: true, result: ab }, [ab]);
        return;
      }
      case 'encodeEip1559SignedTx': {
        const out = encode_eip1559_signed_tx(
          msg.payload.tx,
          msg.payload.yParity,
          toU8(msg.payload.r),
          toU8(msg.payload.s),
        ) as Uint8Array;
        const ab = out.slice().buffer;
        (self as any).postMessage({ id: msg.id, ok: true, result: ab }, [ab]);
        return;
      }
      case 'signSecp256k1Recoverable': {
        const out = sign_secp256k1_recoverable(
          toU8(msg.payload.digest32),
          toU8(msg.payload.privateKey32),
        ) as Uint8Array;
        const ab = out.slice().buffer;
        (self as any).postMessage({ id: msg.id, ok: true, result: ab }, [ab]);
        return;
      }
    }
  } catch (e) {
    (self as any).postMessage({ id: msg.id, ok: false, error: errorMessage(e) });
  }
});
