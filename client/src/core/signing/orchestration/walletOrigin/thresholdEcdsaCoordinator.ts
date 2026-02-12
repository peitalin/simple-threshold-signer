import { base64UrlDecode, base64UrlEncode } from '../../../../../../shared/src/utils/encoders';
import { normalizeThresholdEd25519ParticipantIds } from '../../../../../../shared/src/threshold/participants';
import {
  addSecp256k1PublicKeys33Wasm,
  mapAdditiveShareToThresholdSignaturesShare2pWasm,
  thresholdEcdsaComputeSignatureShareWasm,
  thresholdEcdsaPresignSessionAbortWasm,
  thresholdEcdsaPresignSessionInitWasm,
  thresholdEcdsaPresignSessionStepWasm,
  validateSecp256k1PublicKey33Wasm,
} from '../../chainAdaptors/evm/ethSignerWasm';
import type { WorkerOperationContext } from '../../workers/operations/executeSignerWorkerOperation';
import {
  thresholdEcdsaPresignInit,
  thresholdEcdsaPresignStep,
  thresholdEcdsaSignFinalize,
  thresholdEcdsaSignInit,
} from '../../threshold/workflows/thresholdEcdsaSigning';

type ThresholdEcdsaSessionKind = 'jwt' | 'cookie';

type ThresholdEcdsaClientPresignatureShare = {
  presignatureId: string;
  bigRB64u: string;
  kShareB64u: string;
  sigmaShareB64u: string;
  createdAtMs: number;
};

type ThresholdEcdsaCoordinatorError = {
  ok: false;
  code: string;
  message: string;
};

type ThresholdEcdsaCoordinatorOk = {
  ok: true;
  signature65: Uint8Array;
  signature65B64u: string;
  rB64u: string;
  sB64u: string;
  recId: number;
};

export type ThresholdEcdsaCoordinatorResult = ThresholdEcdsaCoordinatorOk | ThresholdEcdsaCoordinatorError;

const THRESHOLD_SECP256K1_ECDSA_2P_PARTICIPANTS_V1 = Object.freeze({
  clientId: 1,
  relayerId: 2,
  participantIds: [1, 2] as const,
});

const MAX_HANDSHAKE_STEPS = 64;
const clientPresignaturePool = new Map<string, ThresholdEcdsaClientPresignatureShare[]>();

function createClientPresignSessionId(): string {
  const c = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  if (typeof c?.randomUUID === 'function') return `c-presign-${c.randomUUID()}`;
  return `c-presign-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function normalizeParticipantIds(participantIds: number[] | undefined): number[] {
  return normalizeThresholdEd25519ParticipantIds(participantIds)
    || [...THRESHOLD_SECP256K1_ECDSA_2P_PARTICIPANTS_V1.participantIds];
}

function makePresignaturePoolKey(args: {
  relayerUrl: string;
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  participantIds: number[];
}): string {
  const relayerUrl = String(args.relayerUrl || '').trim().replace(/\/+$/g, '');
  const relayerKeyId = String(args.relayerKeyId || '').trim();
  const clientVerifyingShareB64u = String(args.clientVerifyingShareB64u || '').trim();
  const participantIds = normalizeParticipantIds(args.participantIds);
  return [
    relayerUrl,
    relayerKeyId,
    clientVerifyingShareB64u,
    participantIds.join(','),
  ].join('|');
}

function popClientPresignature(poolKey: string): ThresholdEcdsaClientPresignatureShare | null {
  const list = clientPresignaturePool.get(poolKey);
  if (!list || list.length === 0) return null;
  const item = list.shift() || null;
  if (!list.length) {
    clientPresignaturePool.delete(poolKey);
  } else {
    clientPresignaturePool.set(poolKey, list);
  }
  return item;
}

function pushClientPresignature(poolKey: string, item: ThresholdEcdsaClientPresignatureShare): void {
  const list = clientPresignaturePool.get(poolKey) || [];
  list.push(item);
  clientPresignaturePool.set(poolKey, list);
}

export function clearAllThresholdEcdsaClientPresignatures(): void {
  clientPresignaturePool.clear();
}

function toB64uMessages(messages: Uint8Array[]): string[] {
  return messages.map((entry) => base64UrlEncode(entry));
}

function fromB64uMessages(messagesB64u: string[] | undefined): Uint8Array[] {
  if (!Array.isArray(messagesB64u)) return [];
  return messagesB64u
    .map((entry) => String(entry || '').trim())
    .filter((entry) => Boolean(entry))
    .map((entry) => base64UrlDecode(entry));
}

async function resolveGroupPublicKey33(args: {
  clientVerifyingShareB64u: string;
  groupPublicKeyB64u?: string;
  relayerVerifyingShareB64u?: string;
  workerCtx: WorkerOperationContext;
}): Promise<Uint8Array> {
  const groupPublicKeyB64u = String(args.groupPublicKeyB64u || '').trim();
  if (groupPublicKeyB64u) {
    const bytes = base64UrlDecode(groupPublicKeyB64u);
    if (bytes.length !== 33) throw new Error('groupPublicKeyB64u must decode to 33 bytes');
    return await validateSecp256k1PublicKey33Wasm({
      publicKey33: bytes,
      workerCtx: args.workerCtx,
    });
  }

  const clientVerifyingShareB64u = String(args.clientVerifyingShareB64u || '').trim();
  const relayerVerifyingShareB64u = String(args.relayerVerifyingShareB64u || '').trim();
  if (!clientVerifyingShareB64u || !relayerVerifyingShareB64u) {
    throw new Error('Missing groupPublicKeyB64u (or relayerVerifyingShareB64u fallback) for threshold-ecdsa signing');
  }

  const clientBytes = base64UrlDecode(clientVerifyingShareB64u);
  const relayerBytes = base64UrlDecode(relayerVerifyingShareB64u);
  if (clientBytes.length !== 33) throw new Error('clientVerifyingShareB64u must decode to 33 bytes');
  if (relayerBytes.length !== 33) throw new Error('relayerVerifyingShareB64u must decode to 33 bytes');
  const validatedClientPublicKey33 = await validateSecp256k1PublicKey33Wasm({
    publicKey33: clientBytes,
    workerCtx: args.workerCtx,
  });
  const validatedRelayerPublicKey33 = await validateSecp256k1PublicKey33Wasm({
    publicKey33: relayerBytes,
    workerCtx: args.workerCtx,
  });
  return await addSecp256k1PublicKeys33Wasm({
    left33: validatedClientPublicKey33,
    right33: validatedRelayerPublicKey33,
    workerCtx: args.workerCtx,
  });
}

async function runPresignHandshake(args: {
  relayerUrl: string;
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  participantIds: number[];
  clientParticipantId: number;
  relayerParticipantId: number;
  clientSigningShare32: Uint8Array;
  groupPublicKey33: Uint8Array;
  sessionKind: ThresholdEcdsaSessionKind;
  thresholdSessionJwt?: string;
  workerCtx: WorkerOperationContext;
}): Promise<{ ok: true; presignature: ThresholdEcdsaClientPresignatureShare } | ThresholdEcdsaCoordinatorError> {
  const init = await thresholdEcdsaPresignInit({
    relayerUrl: args.relayerUrl,
    relayerKeyId: args.relayerKeyId,
    clientVerifyingShareB64u: args.clientVerifyingShareB64u,
    count: 1,
    sessionKind: args.sessionKind,
    thresholdSessionJwt: args.thresholdSessionJwt,
  });
  if (!init.ok) {
    return {
      ok: false,
      code: init.code || 'presign_init_failed',
      message: init.message || 'threshold-ecdsa presign/init failed',
    };
  }

  const presignSessionId = String(init.presignSessionId || '').trim();
  if (!presignSessionId) {
    return { ok: false, code: 'internal', message: 'threshold-ecdsa presign/init returned empty presignSessionId' };
  }

  const localSessionId = createClientPresignSessionId();
  const clientThresholdSigningShare32 = await mapAdditiveShareToThresholdSignaturesShare2pWasm({
    additiveShare32: args.clientSigningShare32,
    participantId: args.clientParticipantId,
    workerCtx: args.workerCtx,
  });

  let localDonePresignature97: Uint8Array | null = null;
  let serverPresignatureId: string | null = null;
  let serverBigRB64u: string | null = null;
  let serverDone = false;
  let stageForServer: 'triples' | 'presign' = 'triples';
  let pendingClientOutgoing = [] as Uint8Array[];
  let pendingServerOutgoing = fromB64uMessages(init.outgoingMessagesB64u);
  let shouldAbortLocalSession = true;

  try {
    const localInit = await thresholdEcdsaPresignSessionInitWasm({
      sessionId: localSessionId,
      participantIds: args.participantIds,
      clientParticipantId: args.clientParticipantId,
      threshold: 2,
      clientThresholdSigningShare32,
      groupPublicKey33: args.groupPublicKey33,
      workerCtx: args.workerCtx,
    });
    pendingClientOutgoing = [...localInit.outgoingMessages];
    if (localInit.stage === 'triples_done' || localInit.stage === 'presign' || localInit.stage === 'done') {
      stageForServer = 'presign';
    }
    if (localInit.presignature97) {
      localDonePresignature97 = localInit.presignature97;
      shouldAbortLocalSession = false;
    }

    for (let i = 0; i < MAX_HANDSHAKE_STEPS; i++) {
      if (pendingServerOutgoing.length > 0 && !localDonePresignature97) {
        const localStepped = await thresholdEcdsaPresignSessionStepWasm({
          sessionId: localSessionId,
          relayerParticipantId: args.relayerParticipantId,
          stage: stageForServer,
          incomingMessages: pendingServerOutgoing,
          workerCtx: args.workerCtx,
        });
        pendingServerOutgoing = [];
        pendingClientOutgoing.push(...localStepped.outgoingMessages);
        if (localStepped.stage === 'triples_done' || localStepped.stage === 'presign' || localStepped.stage === 'done') {
          stageForServer = 'presign';
        }
        if (localStepped.presignature97) {
          localDonePresignature97 = localStepped.presignature97;
          shouldAbortLocalSession = false;
        }
      }

      if (!serverDone) {
        const stepped = await thresholdEcdsaPresignStep({
          relayerUrl: args.relayerUrl,
          presignSessionId,
          stage: stageForServer,
          outgoingMessagesB64u: toB64uMessages(pendingClientOutgoing),
          sessionKind: args.sessionKind,
          thresholdSessionJwt: args.thresholdSessionJwt,
        });
        pendingClientOutgoing = [];
        if (!stepped.ok) {
          return {
            ok: false,
            code: stepped.code || 'presign_step_failed',
            message: stepped.message || 'threshold-ecdsa presign/step failed',
          };
        }
        pendingServerOutgoing = fromB64uMessages(stepped.outgoingMessagesB64u);
        if (stepped.stage === 'presign' || stepped.stage === 'done') {
          stageForServer = 'presign';
        }
        if (stepped.event === 'presign_done') {
          serverPresignatureId = String(stepped.presignatureId || '').trim() || null;
          serverBigRB64u = String(stepped.bigRB64u || '').trim() || null;
          serverDone = true;
        }
      }

      if (localDonePresignature97 && serverPresignatureId && serverBigRB64u) {
        break;
      }

      if (!pendingServerOutgoing.length && !pendingClientOutgoing.length && !localDonePresignature97) {
        const localStepped = await thresholdEcdsaPresignSessionStepWasm({
          sessionId: localSessionId,
          relayerParticipantId: args.relayerParticipantId,
          stage: stageForServer,
          incomingMessages: [],
          workerCtx: args.workerCtx,
        });
        pendingClientOutgoing.push(...localStepped.outgoingMessages);
        if (localStepped.presignature97) {
          localDonePresignature97 = localStepped.presignature97;
          shouldAbortLocalSession = false;
        }
      }
    }

    if (!localDonePresignature97) {
      return { ok: false, code: 'presign_timeout', message: 'Client presign session did not reach done state' };
    }
    if (!serverPresignatureId || !serverBigRB64u) {
      return { ok: false, code: 'presign_timeout', message: 'Server presign session did not reach done state' };
    }
    if (localDonePresignature97.length !== 97) {
      return {
        ok: false,
        code: 'internal',
        message: `Invalid local presignature bytes (expected 97, got ${localDonePresignature97.length})`,
      };
    }

    const bigR33 = localDonePresignature97.slice(0, 33);
    const kShare32 = localDonePresignature97.slice(33, 65);
    const sigmaShare32 = localDonePresignature97.slice(65, 97);
    const localBigRB64u = base64UrlEncode(bigR33);
    if (localBigRB64u !== serverBigRB64u) {
      return {
        ok: false,
        code: 'presign_mismatch',
        message: 'Client/server presignature mismatch (bigR mismatch)',
      };
    }

    return {
      ok: true,
      presignature: {
        presignatureId: serverPresignatureId,
        bigRB64u: localBigRB64u,
        kShareB64u: base64UrlEncode(kShare32),
        sigmaShareB64u: base64UrlEncode(sigmaShare32),
        createdAtMs: Date.now(),
      },
    };
  } catch (e: unknown) {
    const msg = String((e && typeof e === 'object' && 'message' in e) ? (e as { message?: unknown }).message : e || 'threshold-ecdsa presign handshake failed');
    return { ok: false, code: 'presign_failed', message: msg };
  } finally {
    if (shouldAbortLocalSession) {
      await thresholdEcdsaPresignSessionAbortWasm({
        sessionId: localSessionId,
        workerCtx: args.workerCtx,
      }).catch(() => {});
    }
  }
}

export async function signThresholdEcdsaDigestWithPool(args: {
  relayerUrl: string;
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  mpcSessionId: string;
  signingDigest32: Uint8Array;
  clientSigningShare32: Uint8Array;
  participantIds?: number[];
  clientParticipantId?: number;
  relayerParticipantId?: number;
  groupPublicKeyB64u?: string;
  relayerVerifyingShareB64u?: string;
  sessionKind?: ThresholdEcdsaSessionKind;
  thresholdSessionJwt?: string;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEcdsaCoordinatorResult> {
  try {
    const relayerUrl = String(args.relayerUrl || '').trim().replace(/\/+$/g, '');
    if (!relayerUrl) return { ok: false, code: 'invalid_args', message: 'Missing relayerUrl for threshold-ecdsa signing' };
    const relayerKeyId = String(args.relayerKeyId || '').trim();
    if (!relayerKeyId) return { ok: false, code: 'invalid_args', message: 'Missing relayerKeyId for threshold-ecdsa signing' };
    const mpcSessionId = String(args.mpcSessionId || '').trim();
    if (!mpcSessionId) return { ok: false, code: 'invalid_args', message: 'Missing mpcSessionId for threshold-ecdsa signing' };
    const clientVerifyingShareB64u = String(args.clientVerifyingShareB64u || '').trim();
    if (!clientVerifyingShareB64u) {
      return { ok: false, code: 'invalid_args', message: 'Missing clientVerifyingShareB64u for threshold-ecdsa signing' };
    }
    if (!(args.signingDigest32 instanceof Uint8Array) || args.signingDigest32.length !== 32) {
      return { ok: false, code: 'invalid_args', message: 'signingDigest32 must be 32 bytes for threshold-ecdsa signing' };
    }
    if (!(args.clientSigningShare32 instanceof Uint8Array) || args.clientSigningShare32.length !== 32) {
      return { ok: false, code: 'invalid_args', message: 'clientSigningShare32 must be 32 bytes for threshold-ecdsa signing' };
    }

    const participantIds = normalizeParticipantIds(args.participantIds);
    const clientParticipantId = Number.isFinite(args.clientParticipantId)
      ? Math.floor(Number(args.clientParticipantId))
      : THRESHOLD_SECP256K1_ECDSA_2P_PARTICIPANTS_V1.clientId;
    const relayerParticipantId = Number.isFinite(args.relayerParticipantId)
      ? Math.floor(Number(args.relayerParticipantId))
      : THRESHOLD_SECP256K1_ECDSA_2P_PARTICIPANTS_V1.relayerId;
    const sessionKind: ThresholdEcdsaSessionKind = args.sessionKind || 'jwt';

    const groupPublicKey33 = await resolveGroupPublicKey33({
      clientVerifyingShareB64u,
      groupPublicKeyB64u: args.groupPublicKeyB64u,
      relayerVerifyingShareB64u: args.relayerVerifyingShareB64u,
      workerCtx: args.workerCtx,
    });

    const poolKey = makePresignaturePoolKey({
      relayerUrl,
      relayerKeyId,
      clientVerifyingShareB64u,
      participantIds,
    });

    let presignature = popClientPresignature(poolKey);
    if (!presignature) {
      const generated = await runPresignHandshake({
        relayerUrl,
        relayerKeyId,
        clientVerifyingShareB64u,
        participantIds,
        clientParticipantId,
        relayerParticipantId,
        clientSigningShare32: args.clientSigningShare32,
        groupPublicKey33,
        sessionKind,
        thresholdSessionJwt: args.thresholdSessionJwt,
        workerCtx: args.workerCtx,
      });
      if (!generated.ok) return generated;
      presignature = generated.presignature;
    }

    let signInit = await thresholdEcdsaSignInit({
      relayerUrl,
      mpcSessionId,
      relayerKeyId,
      signingDigest32: args.signingDigest32,
      presignatureId: presignature.presignatureId,
    });
    if (!signInit.ok && signInit.code === 'pool_empty') {
      const generated = await runPresignHandshake({
        relayerUrl,
        relayerKeyId,
        clientVerifyingShareB64u,
        participantIds,
        clientParticipantId,
        relayerParticipantId,
        clientSigningShare32: args.clientSigningShare32,
        groupPublicKey33,
        sessionKind,
        thresholdSessionJwt: args.thresholdSessionJwt,
        workerCtx: args.workerCtx,
      });
      if (!generated.ok) return generated;
      presignature = generated.presignature;
      signInit = await thresholdEcdsaSignInit({
        relayerUrl,
        mpcSessionId,
        relayerKeyId,
        signingDigest32: args.signingDigest32,
        presignatureId: presignature.presignatureId,
      });
    }
    if (!signInit.ok) {
      return {
        ok: false,
        code: signInit.code || 'sign_init_failed',
        message: signInit.message || 'threshold-ecdsa sign/init failed',
      };
    }

    const signingSessionId = String(signInit.signingSessionId || '').trim();
    const relayerRound1 = signInit.relayerRound1 || {};
    const entropyB64u = String(relayerRound1.entropyB64u || '').trim();
    if (!signingSessionId || !entropyB64u) {
      return { ok: false, code: 'internal', message: 'threshold-ecdsa sign/init returned incomplete round-1 payload' };
    }
    const relayerBigRB64u = String(relayerRound1.bigRB64u || '').trim();
    if (relayerBigRB64u && relayerBigRB64u !== presignature.bigRB64u) {
      return {
        ok: false,
        code: 'presign_mismatch',
        message: 'Relayer selected a different presignature than the client pool item (bigR mismatch)',
      };
    }

    const bigR33 = base64UrlDecode(presignature.bigRB64u);
    const kShare32 = base64UrlDecode(presignature.kShareB64u);
    const sigmaShare32 = base64UrlDecode(presignature.sigmaShareB64u);
    const entropy32 = base64UrlDecode(entropyB64u);
    if (bigR33.length !== 33) return { ok: false, code: 'internal', message: 'presign bigR must decode to 33 bytes' };
    if (kShare32.length !== 32) return { ok: false, code: 'internal', message: 'presign kShare must decode to 32 bytes' };
    if (sigmaShare32.length !== 32) return { ok: false, code: 'internal', message: 'presign sigmaShare must decode to 32 bytes' };
    if (entropy32.length !== 32) return { ok: false, code: 'internal', message: 'relayer entropy must decode to 32 bytes' };

    const clientSignatureShare32 = await thresholdEcdsaComputeSignatureShareWasm({
      participantIds,
      clientParticipantId,
      groupPublicKey33,
      presignBigR33: bigR33,
      presignKShare32: kShare32,
      presignSigmaShare32: sigmaShare32,
      digest32: args.signingDigest32,
      entropy32,
      workerCtx: args.workerCtx,
    });
    if (clientSignatureShare32.length !== 32) {
      return {
        ok: false,
        code: 'internal',
        message: `Invalid client signature share length (expected 32, got ${clientSignatureShare32.length})`,
      };
    }

    const finalized = await thresholdEcdsaSignFinalize({
      relayerUrl,
      signingSessionId,
      clientSignatureShare32,
    });
    if (!finalized.ok) {
      return {
        ok: false,
        code: finalized.code || 'sign_finalize_failed',
        message: finalized.message || 'threshold-ecdsa sign/finalize failed',
      };
    }

    const signature65B64u = String(finalized.relayerRound2?.signature65B64u || '').trim();
    if (!signature65B64u) {
      return { ok: false, code: 'internal', message: 'threshold-ecdsa sign/finalize returned empty signature65B64u' };
    }
    const signature65 = base64UrlDecode(signature65B64u);
    if (signature65.length !== 65) {
      return {
        ok: false,
        code: 'internal',
        message: `threshold-ecdsa sign/finalize returned invalid signature length (expected 65, got ${signature65.length})`,
      };
    }

    return {
      ok: true,
      signature65,
      signature65B64u,
      rB64u: String(finalized.relayerRound2?.rB64u || '').trim(),
      sB64u: String(finalized.relayerRound2?.sB64u || '').trim(),
      recId: Number(finalized.relayerRound2?.recId ?? signature65[64]),
    };
  } catch (e: unknown) {
    const msg = String((e && typeof e === 'object' && 'message' in e) ? (e as { message?: unknown }).message : e || 'threshold-ecdsa coordinator failed');
    return { ok: false, code: 'internal', message: msg };
  }
}

export async function refillThresholdEcdsaClientPresignaturePool(args: {
  relayerUrl: string;
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  participantIds?: number[];
  clientParticipantId?: number;
  relayerParticipantId?: number;
  clientSigningShare32: Uint8Array;
  groupPublicKeyB64u?: string;
  relayerVerifyingShareB64u?: string;
  sessionKind?: ThresholdEcdsaSessionKind;
  thresholdSessionJwt?: string;
  workerCtx: WorkerOperationContext;
}): Promise<{ ok: true; presignatureId: string } | ThresholdEcdsaCoordinatorError> {
  try {
    const participantIds = normalizeParticipantIds(args.participantIds);
    const clientParticipantId = Number.isFinite(args.clientParticipantId)
      ? Math.floor(Number(args.clientParticipantId))
      : THRESHOLD_SECP256K1_ECDSA_2P_PARTICIPANTS_V1.clientId;
    const relayerParticipantId = Number.isFinite(args.relayerParticipantId)
      ? Math.floor(Number(args.relayerParticipantId))
      : THRESHOLD_SECP256K1_ECDSA_2P_PARTICIPANTS_V1.relayerId;
    const sessionKind: ThresholdEcdsaSessionKind = args.sessionKind || 'jwt';
    const groupPublicKey33 = await resolveGroupPublicKey33({
      clientVerifyingShareB64u: args.clientVerifyingShareB64u,
      groupPublicKeyB64u: args.groupPublicKeyB64u,
      relayerVerifyingShareB64u: args.relayerVerifyingShareB64u,
      workerCtx: args.workerCtx,
    });

    const generated = await runPresignHandshake({
      relayerUrl: args.relayerUrl,
      relayerKeyId: args.relayerKeyId,
      clientVerifyingShareB64u: args.clientVerifyingShareB64u,
      participantIds,
      clientParticipantId,
      relayerParticipantId,
      clientSigningShare32: args.clientSigningShare32,
      groupPublicKey33,
      sessionKind,
      thresholdSessionJwt: args.thresholdSessionJwt,
      workerCtx: args.workerCtx,
    });
    if (!generated.ok) return generated;

    const poolKey = makePresignaturePoolKey({
      relayerUrl: args.relayerUrl,
      relayerKeyId: args.relayerKeyId,
      clientVerifyingShareB64u: args.clientVerifyingShareB64u,
      participantIds,
    });
    pushClientPresignature(poolKey, generated.presignature);
    return { ok: true, presignatureId: generated.presignature.presignatureId };
  } catch (e: unknown) {
    const msg = String((e && typeof e === 'object' && 'message' in e) ? (e as { message?: unknown }).message : e || 'threshold-ecdsa presign refill failed');
    return { ok: false, code: 'internal', message: msg };
  }
}
