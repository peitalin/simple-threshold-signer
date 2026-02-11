import init, {
  compute_eip1559_tx_hash,
  derive_threshold_secp256k1_client_share,
  encode_eip1559_signed_tx,
  init_eth_signer,
  sign_secp256k1_recoverable,
  ThresholdEcdsaPresignSession,
  threshold_ecdsa_compute_signature_share,
} from '../../../../wasm/eth_signer/pkg/eth_signer.js';
import { initializeWasm, resolveWasmUrl } from '../runtimeAssetPaths/wasm-loader';
import { errorMessage } from '../../../../shared/src/utils/errors';
import { WorkerControlMessage } from './workerControlMessages';

type EthSignerWorkerRequest =
  | { id: string; type: 'computeEip1559TxHash'; payload: { tx: any } }
  | { id: string; type: 'encodeEip1559SignedTx'; payload: { tx: any; yParity: number; r: any; s: any } }
  | { id: string; type: 'signSecp256k1Recoverable'; payload: { digest32: any; privateKey32: any } }
  | {
      id: string;
      type: 'deriveThresholdSecp256k1ClientShare';
      payload: {
        prfFirst32: any;
        userId: string;
        derivationPath?: number;
      };
    }
  | {
      id: string;
      type: 'thresholdEcdsaPresignSessionInit';
      payload: {
        sessionId: string;
        participantIds: number[];
        clientParticipantId: number;
        threshold: number;
        clientThresholdSigningShare32: any;
        groupPublicKey33: any;
      };
    }
  | {
      id: string;
      type: 'thresholdEcdsaPresignSessionStep';
      payload: {
        sessionId: string;
        relayerParticipantId: number;
        stage: 'triples' | 'presign';
        incomingMessages?: any[];
      };
    }
  | {
      id: string;
      type: 'thresholdEcdsaPresignSessionAbort';
      payload: { sessionId: string };
    }
  | {
      id: string;
      type: 'thresholdEcdsaComputeSignatureShare';
      payload: {
        participantIds: number[];
        clientParticipantId: number;
        groupPublicKey33: any;
        presignBigR33: any;
        presignKShare32: any;
        presignSigmaShare32: any;
        digest32: any;
        entropy32: any;
      };
    };

function toU8(v: any): Uint8Array {
  if (v instanceof Uint8Array) return v;
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  throw new Error('expected bytes');
}

type PresignProgressResult = {
  stage: 'triples' | 'triples_done' | 'presign' | 'done';
  event: 'none' | 'triples_done' | 'presign_done';
  outgoingMessages: ArrayBuffer[];
  presignature97?: ArrayBuffer;
};

const thresholdEcdsaPresignSessions = new Map<string, ThresholdEcdsaPresignSession>();

function normalizePresignStage(stageRaw: unknown): 'triples' | 'triples_done' | 'presign' | 'done' {
  if (stageRaw === 'triples') return 'triples';
  if (stageRaw === 'triples_done') return 'triples_done';
  if (stageRaw === 'presign') return 'presign';
  if (stageRaw === 'done') return 'done';
  return 'triples';
}

function normalizePresignEvent(eventRaw: unknown): 'none' | 'triples_done' | 'presign_done' {
  if (eventRaw === 'triples_done') return 'triples_done';
  if (eventRaw === 'presign_done') return 'presign_done';
  return 'none';
}

function parsePresignPollResult(raw: unknown): {
  stage: 'triples' | 'triples_done' | 'presign' | 'done';
  event: 'none' | 'triples_done' | 'presign_done';
  outgoing: Uint8Array[];
} {
  const obj = (raw || {}) as { stage?: unknown; event?: unknown; outgoing?: unknown };
  const outgoingRaw = obj.outgoing;
  const outgoing = Array.isArray(outgoingRaw)
    ? outgoingRaw.map((entry) => toU8(entry))
    : [];
  return {
    stage: normalizePresignStage(obj.stage),
    event: normalizePresignEvent(obj.event),
    outgoing,
  };
}

function freePresignSession(sessionId: string): void {
  const existing = thresholdEcdsaPresignSessions.get(sessionId);
  if (!existing) return;
  thresholdEcdsaPresignSessions.delete(sessionId);
  try {
    existing.free();
  } catch { }
}

function pollPresignSession(sessionId: string, session: ThresholdEcdsaPresignSession): PresignProgressResult {
  const parsed = parsePresignPollResult(session.poll());
  const outgoingMessages = parsed.outgoing.map((msg) => msg.slice().buffer);
  if (parsed.event !== 'presign_done') {
    return {
      stage: parsed.stage,
      event: parsed.event,
      outgoingMessages,
    };
  }

  const presignature97 = session.take_presignature_97();
  freePresignSession(sessionId);
  return {
    stage: 'done',
    event: 'presign_done',
    outgoingMessages,
    presignature97: presignature97.slice().buffer,
  };
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
      case 'deriveThresholdSecp256k1ClientShare': {
        const prfFirst32 = toU8(msg.payload.prfFirst32);
        const userId = String(msg.payload.userId || '').trim();
        const derivationPath = Number.isFinite(msg.payload.derivationPath)
          ? Math.max(0, Math.floor(Number(msg.payload.derivationPath)))
          : 0;
        const out = derive_threshold_secp256k1_client_share(
          prfFirst32,
          userId,
          derivationPath,
        ) as Uint8Array;
        if (out.length !== 65) {
          throw new Error(`derive_threshold_secp256k1_client_share must return 65 bytes (got ${out.length})`);
        }
        const signingShare32 = out.slice(0, 32).buffer;
        const verifyingShare33 = out.slice(32, 65).buffer;
        (self as any).postMessage(
          {
            id: msg.id,
            ok: true,
            result: {
              clientSigningShare32: signingShare32,
              clientVerifyingShare33: verifyingShare33,
            },
          },
          [signingShare32, verifyingShare33],
        );
        return;
      }
      case 'thresholdEcdsaPresignSessionInit': {
        const sessionId = String(msg.payload.sessionId || '').trim();
        if (!sessionId) throw new Error('Missing sessionId');
        freePresignSession(sessionId);

        const participantIds = Array.isArray(msg.payload.participantIds)
          ? msg.payload.participantIds.map((v) => Number(v))
          : [];
        const clientParticipantId = Number(msg.payload.clientParticipantId);
        const threshold = Number(msg.payload.threshold);
        const clientThresholdSigningShare32 = toU8(msg.payload.clientThresholdSigningShare32);
        const groupPublicKey33 = toU8(msg.payload.groupPublicKey33);

        const session = new ThresholdEcdsaPresignSession(
          new Uint32Array(participantIds),
          clientParticipantId,
          threshold,
          clientThresholdSigningShare32,
          groupPublicKey33,
        );
        thresholdEcdsaPresignSessions.set(sessionId, session);

        const progress = pollPresignSession(sessionId, session);
        const transferables = [...progress.outgoingMessages];
        if (progress.presignature97) transferables.push(progress.presignature97);
        (self as any).postMessage({ id: msg.id, ok: true, result: progress }, transferables);
        return;
      }
      case 'thresholdEcdsaPresignSessionStep': {
        const sessionId = String(msg.payload.sessionId || '').trim();
        if (!sessionId) throw new Error('Missing sessionId');
        const session = thresholdEcdsaPresignSessions.get(sessionId);
        if (!session) throw new Error('Unknown threshold ECDSA presign session');

        const stage = msg.payload.stage;
        if (stage !== 'triples' && stage !== 'presign') {
          throw new Error('Invalid stage (expected "triples" or "presign")');
        }
        const relayerParticipantId = Number(msg.payload.relayerParticipantId);
        if (!Number.isFinite(relayerParticipantId) || relayerParticipantId <= 0) {
          throw new Error('Invalid relayerParticipantId');
        }

        const currentStage = session.stage();
        if (stage === 'presign') {
          if (currentStage === 'triples_done') {
            session.start_presign();
          } else if (currentStage === 'triples') {
            throw new Error('Client presign session is not ready for "presign" stage');
          }
        }

        const incomingMessages = Array.isArray(msg.payload.incomingMessages)
          ? msg.payload.incomingMessages.map((entry) => toU8(entry))
          : [];
        for (const incoming of incomingMessages) {
          session.message(relayerParticipantId, incoming);
        }

        const progress = pollPresignSession(sessionId, session);
        const transferables = [...progress.outgoingMessages];
        if (progress.presignature97) transferables.push(progress.presignature97);
        (self as any).postMessage({ id: msg.id, ok: true, result: progress }, transferables);
        return;
      }
      case 'thresholdEcdsaPresignSessionAbort': {
        const sessionId = String(msg.payload.sessionId || '').trim();
        if (!sessionId) throw new Error('Missing sessionId');
        freePresignSession(sessionId);
        (self as any).postMessage({ id: msg.id, ok: true, result: { ok: true } });
        return;
      }
      case 'thresholdEcdsaComputeSignatureShare': {
        const out = threshold_ecdsa_compute_signature_share(
          new Uint32Array((Array.isArray(msg.payload.participantIds) ? msg.payload.participantIds : []).map((v) => Number(v))),
          Number(msg.payload.clientParticipantId),
          toU8(msg.payload.groupPublicKey33),
          toU8(msg.payload.presignBigR33),
          toU8(msg.payload.presignKShare32),
          toU8(msg.payload.presignSigmaShare32),
          toU8(msg.payload.digest32),
          toU8(msg.payload.entropy32),
        ) as Uint8Array;
        const ab = out.slice().buffer;
        (self as any).postMessage({ id: msg.id, ok: true, result: ab }, [ab]);
        return;
      }
    }
  } catch (e) {
    if (msg?.type === 'thresholdEcdsaPresignSessionInit' || msg?.type === 'thresholdEcdsaPresignSessionStep') {
      const sessionId = String((msg as { payload?: { sessionId?: unknown } })?.payload?.sessionId || '').trim();
      if (sessionId) freePresignSession(sessionId);
    }
    (self as any).postMessage({ id: msg.id, ok: false, error: errorMessage(e) });
  }
});
