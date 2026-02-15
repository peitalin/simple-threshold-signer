import init, {
  compute_tempo_sender_hash,
  encode_tempo_signed_tx,
  init_tempo_signer,
} from '../../../../wasm/tempo_signer/pkg/tempo_signer.js';
import { initializeWasm, resolveWasmUrl } from '../runtimeAssetPaths/wasm-loader';
import { errorMessage } from '../../../../shared/src/utils/errors';
import { WorkerControlMessage } from './workerControlMessages';
import { resolveSignerWorkerContractVersion } from '../signing/workers/signerWorkerManager/backends/types';

type TempoSignerWorkerRequest =
  | { id: string; version?: number; type: 'computeTempoSenderHash'; payload: { tx: any } }
  | {
      id: string;
      version?: number;
      type: 'encodeTempoSignedTx';
      payload: { tx: any; senderSignature: any };
    };

type WorkerErrorPayload = {
  message: string;
  code?: string;
  coreCode?: string;
};

function asWorkerErrorPayload(err: unknown): WorkerErrorPayload {
  if (err && typeof err === 'object') {
    const message = typeof (err as { message?: unknown }).message === 'string'
      ? String((err as { message?: string }).message).trim()
      : '';
    const code = typeof (err as { code?: unknown }).code === 'string'
      ? String((err as { code?: string }).code).trim()
      : '';
    const coreCode = typeof (err as { coreCode?: unknown }).coreCode === 'string'
      ? String((err as { coreCode?: string }).coreCode).trim()
      : '';
    return {
      message: message || errorMessage(err),
      ...(code ? { code } : {}),
      ...(coreCode ? { coreCode } : {}),
    };
  }
  return { message: errorMessage(err) };
}

function toU8(v: any): Uint8Array {
  if (v instanceof Uint8Array) return v;
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  throw new Error('expected bytes');
}

const wasmUrl = resolveWasmUrl('tempo_signer.wasm', 'Tempo Signer');
let wasmInitPromise: Promise<void> | null = null;

async function ensureWasm(): Promise<void> {
  if (wasmInitPromise) return wasmInitPromise;
  wasmInitPromise = (async () => {
    await initializeWasm({
      workerName: 'Tempo Signer',
      wasmUrl,
      initFunction: init as any,
      validateFunction: () => init_tempo_signer(),
    });
  })();
  return wasmInitPromise;
}

setTimeout(() => {
  (self as any).postMessage({ type: WorkerControlMessage.WORKER_READY, ready: true });
}, 0);

self.addEventListener('message', async (event: MessageEvent) => {
  const msg = event.data as TempoSignerWorkerRequest;
  if (!msg?.id || !msg?.type) return;

  try {
    resolveSignerWorkerContractVersion((msg as { version?: number }).version);
    await ensureWasm();
    switch (msg.type) {
      case 'computeTempoSenderHash': {
        const out = compute_tempo_sender_hash(msg.payload.tx) as Uint8Array;
        const ab = out.slice().buffer;
        (self as any).postMessage({ id: msg.id, ok: true, result: ab }, [ab]);
        return;
      }
      case 'encodeTempoSignedTx': {
        const out = encode_tempo_signed_tx(msg.payload.tx, toU8(msg.payload.senderSignature)) as Uint8Array;
        const ab = out.slice().buffer;
        (self as any).postMessage({ id: msg.id, ok: true, result: ab }, [ab]);
        return;
      }
    }
  } catch (e) {
    const err = asWorkerErrorPayload(e);
    (self as any).postMessage({
      id: msg.id,
      ok: false,
      error: err.message,
      ...(err.code ? { code: err.code } : {}),
      ...(err.coreCode ? { coreCode: err.coreCode } : {}),
    });
  }
});
