import type { NormalizedLogger } from '../logger';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  ThresholdEcdsaPresignInitRequest,
  ThresholdEcdsaPresignInitResponse,
  ThresholdEcdsaPresignStepRequest,
  ThresholdEcdsaPresignStepResponse,
  ThresholdEcdsaSignFinalizeRequest,
  ThresholdEcdsaSignFinalizeResponse,
  ThresholdEcdsaSignInitRequest,
  ThresholdEcdsaSignInitResponse,
} from '../types';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import type { ThresholdNodeRole } from './config';
import type { ThresholdEd25519SessionStore } from './stores/SessionStore';
import type {
  ThresholdEcdsaPresignSessionRecord,
  ThresholdEcdsaPresignSessionStore,
  ThresholdEcdsaPresignaturePool,
  ThresholdEcdsaSigningSessionRecord,
  ThresholdEcdsaSigningSessionStore,
} from './stores/EcdsaSigningStore';
import type { ThresholdEcdsaSessionClaims } from './validation';
import { THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID } from './schemes/schemeIds';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/utils.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { SECP256K1_ORDER } from '@shared/threshold/secp256k1';
import { mapAdditiveShareToThresholdSignaturesShare2p } from '@shared/threshold/secp256k1Ecdsa2pShareMapping';
import initEthSignerWasm, {
  init_eth_signer,
  ThresholdEcdsaPresignSession,
  threshold_ecdsa_finalize_signature,
} from '../../../../wasm/eth_signer/pkg/eth_signer.js';
import type { InitInput } from '../../../../wasm/eth_signer/pkg/eth_signer.js';

type ParseOk<T> = { ok: true; value: T };
type ParseErr = { ok: false; code: string; message: string };
type ParseResult<T> = ParseOk<T> | ParseErr;

const ETH_SIGNER_WASM_MAIN_PATH = '../../../../wasm/eth_signer/pkg/eth_signer_bg.wasm';
const ETH_SIGNER_WASM_FALLBACK_PATH = '../../../workers/eth_signer.wasm';
let ethSignerWasmInitPromise: Promise<void> | null = null;

function isNodeEnvironment(): boolean {
  // Detect true Node.js, not Cloudflare Workers with nodejs_compat polyfills.
  const processObj = (globalThis as unknown as { process?: { versions?: { node?: string } } }).process;
  const isNode = Boolean(processObj?.versions?.node);
  const webSocketPair = (globalThis as unknown as { WebSocketPair?: unknown }).WebSocketPair;
  const nav = (globalThis as unknown as { navigator?: { userAgent?: unknown } }).navigator;
  const isCloudflareWorker = typeof webSocketPair !== 'undefined'
    || (typeof nav?.userAgent === 'string' && nav.userAgent.includes('Cloudflare-Workers'));
  return isNode && !isCloudflareWorker;
}

function getEthSignerWasmUrls(): URL[] {
  const baseUrl = import.meta.url;
  const paths = [ETH_SIGNER_WASM_MAIN_PATH, ETH_SIGNER_WASM_FALLBACK_PATH];
  const resolved: URL[] = [];
  for (const path of paths) {
    try {
      if (!baseUrl) throw new Error('import.meta.url is undefined');
      resolved.push(new URL(path, baseUrl));
    } catch {
      // ignore
    }
  }
  return resolved;
}

async function ensureEthSignerWasm(): Promise<void> {
  if (ethSignerWasmInitPromise) return ethSignerWasmInitPromise;
  ethSignerWasmInitPromise = (async () => {
    // Prefer filesystem loading in Node (avoids `fetch(file://...)`).
    const urls = getEthSignerWasmUrls();
    if (isNodeEnvironment()) {
      const { fileURLToPath } = await import('node:url');
      const { readFile } = await import('node:fs/promises');
      for (const url of urls) {
        try {
          const filePath = fileURLToPath(url);
          const bytes = await readFile(filePath);
          const ab = new ArrayBuffer(bytes.byteLength);
          new Uint8Array(ab).set(bytes);
          const module = await WebAssembly.compile(ab);
          await initEthSignerWasm({ module_or_path: module as unknown as InitInput });
          init_eth_signer();
          return;
        } catch { } // try next candidate
      }
      throw new Error('[threshold-ecdsa] Failed to initialize eth_signer WASM from filesystem candidates');
    }

    // Fallback for non-Node runtimes.
    let lastErr: unknown = null;
    for (const url of urls) {
      try {
        await initEthSignerWasm({ module_or_path: url as unknown as InitInput });
        init_eth_signer();
        return;
      } catch (e) {
        lastErr = e;
      }
    }
    throw lastErr instanceof Error ? lastErr : new Error(String(lastErr || 'Failed to initialize eth_signer WASM'));
  })();
  return ethSignerWasmInitPromise;
}

function parseThresholdEcdsaSignInitRequest(request: ThresholdEcdsaSignInitRequest): ParseResult<{
  mpcSessionId: string;
  relayerKeyId: string;
  signingDigestB64u: string;
}> {
  const mpcSessionId = toOptionalTrimmedString(request.mpcSessionId);
  if (!mpcSessionId) return { ok: false, code: 'invalid_body', message: 'mpcSessionId is required' };

  const relayerKeyId = toOptionalTrimmedString(request.relayerKeyId);
  if (!relayerKeyId) return { ok: false, code: 'invalid_body', message: 'relayerKeyId is required' };

  const signingDigestB64u = toOptionalTrimmedString(request.signingDigestB64u);
  if (!signingDigestB64u) return { ok: false, code: 'invalid_body', message: 'signingDigestB64u is required' };

  return { ok: true, value: { mpcSessionId, relayerKeyId, signingDigestB64u } };
}

function parseThresholdEcdsaSignFinalizeRequest(request: ThresholdEcdsaSignFinalizeRequest): ParseResult<{
  signingSessionId: string;
  clientSignatureShareB64u: string;
}> {
  const signingSessionId = toOptionalTrimmedString(request.signingSessionId);
  if (!signingSessionId) return { ok: false, code: 'invalid_body', message: 'signingSessionId is required' };

  const clientRound2 = (request as unknown as { clientRound2?: unknown }).clientRound2;
  const clientSignatureShareB64u = toOptionalTrimmedString(
    (clientRound2 as { clientSignatureShareB64u?: unknown } | undefined)?.clientSignatureShareB64u
  );
  if (!clientSignatureShareB64u) {
    return { ok: false, code: 'invalid_body', message: 'clientRound2.clientSignatureShareB64u is required' };
  }

  return { ok: true, value: { signingSessionId, clientSignatureShareB64u } };
}

function parseThresholdEcdsaPresignInitRequest(request: ThresholdEcdsaPresignInitRequest): ParseResult<{
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  count: number;
}> {
  const relayerKeyId = toOptionalTrimmedString(request.relayerKeyId);
  if (!relayerKeyId) return { ok: false, code: 'invalid_body', message: 'relayerKeyId is required' };
  const clientVerifyingShareB64u = toOptionalTrimmedString(request.clientVerifyingShareB64u);
  if (!clientVerifyingShareB64u) return { ok: false, code: 'invalid_body', message: 'clientVerifyingShareB64u is required' };
  const countRaw = (request as { count?: unknown }).count;
  const count = Math.max(1, Math.floor(Number(countRaw ?? 1)));
  if (count !== 1) {
    return { ok: false, code: 'unsupported', message: 'v1 presign endpoint supports only count=1' };
  }
  return { ok: true, value: { relayerKeyId, clientVerifyingShareB64u, count } };
}

function parseThresholdEcdsaPresignStepRequest(request: ThresholdEcdsaPresignStepRequest): ParseResult<{
  presignSessionId: string;
  stage: 'triples' | 'presign';
  outgoingMessagesB64u: string[];
}> {
  const presignSessionId = toOptionalTrimmedString(request.presignSessionId);
  if (!presignSessionId) return { ok: false, code: 'invalid_body', message: 'presignSessionId is required' };
  const stageRaw = toOptionalTrimmedString((request as { stage?: unknown }).stage);
  if (stageRaw !== 'triples' && stageRaw !== 'presign') {
    return { ok: false, code: 'invalid_body', message: 'stage must be "triples" or "presign"' };
  }
  const msgsRaw = (request as { outgoingMessagesB64u?: unknown }).outgoingMessagesB64u;
  const outgoingMessagesB64u = Array.isArray(msgsRaw)
    ? msgsRaw.map((v) => toOptionalTrimmedString(v)).filter((v): v is string => Boolean(v))
    : [];
  return { ok: true, value: { presignSessionId, stage: stageRaw, outgoingMessagesB64u } };
}

function computePresignatureIdFromBigRBytes(bigR33: Uint8Array): string {
  const digest = sha256(bigR33);
  return `presig-${base64UrlEncode(digest)}`;
}

function deriveRelayerSecp256k1SigningShare32(input: { masterSecretB64u: string; relayerKeyId: string }): Uint8Array {
  const masterSecretBytes = base64UrlDecode(input.masterSecretB64u);
  const relayerShareSaltV1 = new TextEncoder().encode('tatchi/lite/threshold-secp256k1-ecdsa/relayer-share:v1');
  const relayerShareInfo = new TextEncoder().encode(input.relayerKeyId);
  const okm64 = hkdf(sha256, masterSecretBytes, relayerShareSaltV1, relayerShareInfo, 64);
  const reduced = (bytesToNumberBE(okm64) % (SECP256K1_ORDER - 1n)) + 1n;
  return numberToBytesBE(reduced, 32);
}

function sameParticipantIds(a: number[], b: number[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

type PresignReplayStep = {
  stage: 'triples' | 'presign';
  incomingMessagesB64u: string[];
};

type SerializedPresignSessionState = {
  kind: 'replay_v1';
  sessionSeedB64u: string;
  relayerThresholdShareB64u: string;
  groupPublicKeyB64u: string;
  appliedSteps: PresignReplayStep[];
};

type WasmPresignPoll = {
  stage: 'triples' | 'triples_done' | 'presign' | 'done';
  event: 'none' | 'triples_done' | 'presign_done';
  outgoingMessagesB64u: string[];
};

function serializePresignSessionState(state: SerializedPresignSessionState): string {
  return base64UrlEncode(new TextEncoder().encode(JSON.stringify(state)));
}

function parsePresignReplayStep(raw: unknown): PresignReplayStep | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const rec = raw as Record<string, unknown>;
  const stageRaw = toOptionalTrimmedString(rec.stage);
  if (stageRaw !== 'triples' && stageRaw !== 'presign') return null;
  const incomingRaw = rec.incomingMessagesB64u;
  if (!Array.isArray(incomingRaw)) return null;
  const incomingMessagesB64u: string[] = [];
  for (const msg of incomingRaw) {
    const v = toOptionalTrimmedString(msg);
    if (!v) return null;
    incomingMessagesB64u.push(v);
  }
  return { stage: stageRaw, incomingMessagesB64u };
}

function parseSerializedPresignSessionState(stateB64u: string): SerializedPresignSessionState | null {
  let decoded: Uint8Array;
  try {
    decoded = base64UrlDecode(stateB64u);
  } catch {
    return null;
  }
  let raw: unknown;
  try {
    raw = JSON.parse(new TextDecoder().decode(decoded));
  } catch {
    return null;
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const rec = raw as Record<string, unknown>;
  const kind = toOptionalTrimmedString(rec.kind);
  if (kind !== 'replay_v1') return null;
  const sessionSeedB64u = toOptionalTrimmedString(rec.sessionSeedB64u);
  const relayerThresholdShareB64u = toOptionalTrimmedString(rec.relayerThresholdShareB64u);
  const groupPublicKeyB64u = toOptionalTrimmedString(rec.groupPublicKeyB64u);
  if (!sessionSeedB64u || !relayerThresholdShareB64u || !groupPublicKeyB64u) return null;
  const appliedRaw = rec.appliedSteps;
  const appliedSteps: PresignReplayStep[] = [];
  if (Array.isArray(appliedRaw)) {
    for (const entry of appliedRaw) {
      const parsed = parsePresignReplayStep(entry);
      if (!parsed) return null;
      appliedSteps.push(parsed);
    }
  } else if (appliedRaw !== undefined) {
    return null;
  }
  return { kind, sessionSeedB64u, relayerThresholdShareB64u, groupPublicKeyB64u, appliedSteps };
}

function decodeSessionSeed32(seedB64u: string): Uint8Array | null {
  try {
    const decoded = base64UrlDecode(seedB64u);
    return decoded.length === 32 ? decoded : null;
  } catch {
    return null;
  }
}

function deterministicRandomBlock(seed32: Uint8Array, counter: bigint): Uint8Array {
  const blockInput = new Uint8Array(40);
  blockInput.set(seed32, 0);
  const dv = new DataView(blockInput.buffer);
  dv.setUint32(32, Number((counter >> 32n) & 0xffffffffn), false);
  dv.setUint32(36, Number(counter & 0xffffffffn), false);
  return sha256(blockInput);
}

function withDeterministicCryptoRandom<T>(seed32: Uint8Array, fn: () => T): T {
  const cryptoObj = (globalThis as unknown as {
    crypto?: { getRandomValues?: (array: ArrayBufferView) => ArrayBufferView };
  }).crypto;
  if (!cryptoObj || typeof cryptoObj.getRandomValues !== 'function') return fn();
  const original = cryptoObj.getRandomValues.bind(cryptoObj);
  let counter = 0n;
  const deterministicGetRandomValues = (array: ArrayBufferView): ArrayBufferView => {
    const out = new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
    let offset = 0;
    while (offset < out.length) {
      const block = deterministicRandomBlock(seed32, counter);
      counter += 1n;
      const len = Math.min(block.length, out.length - offset);
      out.set(block.slice(0, len), offset);
      offset += len;
    }
    return array;
  };
  try {
    cryptoObj.getRandomValues = deterministicGetRandomValues;
    return fn();
  } finally {
    cryptoObj.getRandomValues = original;
  }
}

function normalizeWasmPresignStage(rawStage: string): 'triples' | 'triples_done' | 'presign' | 'done' {
  if (rawStage === 'triples_done') return 'triples_done';
  if (rawStage === 'presign') return 'presign';
  if (rawStage === 'done') return 'done';
  return 'triples';
}

function pollWasmPresignSession(session: ThresholdEcdsaPresignSession): WasmPresignPoll {
  const polled = session.poll() as { stage?: string; outgoing?: Uint8Array[]; event?: string };
  const outgoingMessages = Array.isArray(polled?.outgoing) ? polled.outgoing : [];
  return {
    stage: normalizeWasmPresignStage(String(polled?.stage || session.stage() || 'triples')),
    event: (polled?.event === 'triples_done' || polled?.event === 'presign_done') ? polled.event : 'none',
    outgoingMessagesB64u: outgoingMessages.map((msg) => base64UrlEncode(msg)),
  };
}

function decodePresignIncomingMessages(outgoingMessagesB64u: string[]): ParseResult<Uint8Array[]> {
  const decoded: Uint8Array[] = [];
  for (const msgB64u of outgoingMessagesB64u) {
    try {
      decoded.push(base64UrlDecode(msgB64u));
    } catch {
      return { ok: false, code: 'invalid_body', message: 'outgoingMessagesB64u contains invalid base64url' };
    }
  }
  return { ok: true, value: decoded };
}

function takePresignatureFromSession(session: ThresholdEcdsaPresignSession): ParseResult<{
  presignatureId: string;
  bigRB64u: string;
  kShareB64u: string;
  sigmaShareB64u: string;
}> {
  const presig97 = session.take_presignature_97();
  if (presig97.length !== 97) {
    return { ok: false, code: 'internal', message: `Invalid presignature bytes (expected 97, got ${presig97.length})` };
  }
  const bigR33 = presig97.slice(0, 33);
  const kShare32 = presig97.slice(33, 65);
  const sigmaShare32 = presig97.slice(65, 97);
  return {
    ok: true,
    value: {
      presignatureId: computePresignatureIdFromBigRBytes(bigR33),
      bigRB64u: base64UrlEncode(bigR33),
      kShareB64u: base64UrlEncode(kShare32),
      sigmaShareB64u: base64UrlEncode(sigmaShare32),
    },
  };
}

type ReplayedPresignSession = {
  session: ThresholdEcdsaPresignSession;
  stage: 'triples' | 'triples_done' | 'presign' | 'done';
};

function reconstructPresignSessionFromState(input: {
  record: ThresholdEcdsaPresignSessionRecord;
  state: SerializedPresignSessionState;
}): ReplayedPresignSession | null {
  let relayerThresholdShare32: Uint8Array;
  let groupPublicKey33: Uint8Array;
  try {
    relayerThresholdShare32 = base64UrlDecode(input.state.relayerThresholdShareB64u);
    groupPublicKey33 = base64UrlDecode(input.state.groupPublicKeyB64u);
  } catch {
    return null;
  }
  if (relayerThresholdShare32.length !== 32 || groupPublicKey33.length !== 33) return null;

  const session = new ThresholdEcdsaPresignSession(
    new Uint32Array(input.record.participantIds),
    input.record.relayerParticipantId,
    2,
    relayerThresholdShare32,
    groupPublicKey33,
  );

  // Presign init calls `poll()` once and returns those outgoing messages.
  // Replay that initial poll so reconstructed state matches a post-init session.
  pollWasmPresignSession(session);

  for (const step of input.state.appliedSteps) {
    const currentStage = normalizeWasmPresignStage(session.stage());
    if (step.stage === 'triples') {
      if (currentStage !== 'triples') return null;
    } else if (step.stage === 'presign') {
      if (currentStage === 'triples_done') {
        try {
          session.start_presign();
        } catch {
          return null;
        }
      } else if (currentStage === 'triples') {
        return null;
      } else if (currentStage === 'done') {
        return null;
      }
    }

    for (const msgB64u of step.incomingMessagesB64u) {
      let decoded: Uint8Array;
      try {
        decoded = base64UrlDecode(msgB64u);
      } catch {
        return null;
      }
      try {
        session.message(input.record.clientParticipantId, decoded);
      } catch {
        return null;
      }
    }

    pollWasmPresignSession(session);
  }

  return {
    session,
    stage: normalizeWasmPresignStage(session.stage()),
  };
}

export class ThresholdEcdsaSigningHandlers {
  private readonly logger: NormalizedLogger;
  private readonly nodeRole: ThresholdNodeRole;
  private readonly participantIds2p: number[];
  private readonly clientParticipantId: number;
  private readonly relayerParticipantId: number;
  private readonly secp256k1MasterSecretB64u: string | null;
  private readonly sessionStore: ThresholdEd25519SessionStore;
  private readonly signingSessionStore: ThresholdEcdsaSigningSessionStore;
  private readonly presignSessionStore: ThresholdEcdsaPresignSessionStore;
  private readonly presignaturePool: ThresholdEcdsaPresignaturePool;
  private readonly ensureReady: () => Promise<void>;
  private readonly createSigningSessionId: () => string;
  private readonly createPresignSessionId: () => string;

  constructor(input: {
    logger: NormalizedLogger;
    nodeRole: ThresholdNodeRole;
    participantIds2p: number[];
    clientParticipantId: number;
    relayerParticipantId: number;
    secp256k1MasterSecretB64u: string | null;
    sessionStore: ThresholdEd25519SessionStore;
    signingSessionStore: ThresholdEcdsaSigningSessionStore;
    presignSessionStore: ThresholdEcdsaPresignSessionStore;
    presignaturePool: ThresholdEcdsaPresignaturePool;
    ensureReady: () => Promise<void>;
    createSigningSessionId: () => string;
    createPresignSessionId: () => string;
  }) {
    this.logger = input.logger;
    this.nodeRole = input.nodeRole;
    this.participantIds2p = input.participantIds2p;
    this.clientParticipantId = input.clientParticipantId;
    this.relayerParticipantId = input.relayerParticipantId;
    this.secp256k1MasterSecretB64u = input.secp256k1MasterSecretB64u;
    this.sessionStore = input.sessionStore;
    this.signingSessionStore = input.signingSessionStore;
    this.presignSessionStore = input.presignSessionStore;
    this.presignaturePool = input.presignaturePool;
    this.ensureReady = input.ensureReady;
    this.createSigningSessionId = input.createSigningSessionId;
    this.createPresignSessionId = input.createPresignSessionId;
  }

  async thresholdEcdsaPresignInit(input: {
    claims: ThresholdEcdsaSessionClaims;
    request: ThresholdEcdsaPresignInitRequest;
  }): Promise<ThresholdEcdsaPresignInitResponse> {
    if (this.nodeRole !== 'coordinator') {
      return {
        ok: false,
        code: 'not_found',
        message: 'threshold-ecdsa presign endpoints are not enabled on this server (set THRESHOLD_NODE_ROLE=coordinator)',
      };
    }

    await this.ensureReady();
    await ensureEthSignerWasm();

    const parsedRequest = parseThresholdEcdsaPresignInitRequest(input.request);
    if (!parsedRequest.ok) return parsedRequest;
    const { relayerKeyId, clientVerifyingShareB64u } = parsedRequest.value;

    const claims = input.claims;
    const userId = toOptionalTrimmedString(claims?.sub);
    if (!userId) return { ok: false, code: 'unauthorized', message: 'Missing userId in threshold session token' };
    const tokenRelayerKeyId = toOptionalTrimmedString(claims?.relayerKeyId);
    const tokenRpId = toOptionalTrimmedString(claims?.rpId);
    if (!tokenRelayerKeyId || !tokenRpId) {
      return { ok: false, code: 'unauthorized', message: 'Invalid threshold session token claims' };
    }
    if (relayerKeyId !== tokenRelayerKeyId) {
      return { ok: false, code: 'unauthorized', message: 'relayerKeyId does not match threshold session scope' };
    }
    if (Date.now() > claims.thresholdExpiresAtMs) {
      return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
    }

    if (!this.secp256k1MasterSecretB64u) {
      return { ok: false, code: 'not_configured', message: 'threshold-ecdsa requires THRESHOLD_SECP256K1_MASTER_SECRET_B64U' };
    }
    if (this.clientParticipantId !== 1 || this.relayerParticipantId !== 2) {
      return { ok: false, code: 'unsupported', message: 'v1 presign endpoint requires participantIds={client=1,relayer=2}' };
    }

    const expectedRelayerKeyIdDigest32 = await sha256BytesUtf8(alphabetizeStringify({
      version: 'threshold_secp256k1_key_id_v1',
      schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
      userId,
      rpId: tokenRpId,
      clientVerifyingShareB64u,
    }));
    const expectedRelayerKeyId = `secp-${base64UrlEncode(expectedRelayerKeyIdDigest32)}`;
    if (relayerKeyId !== expectedRelayerKeyId) {
      return { ok: false, code: 'unauthorized', message: 'relayerKeyId does not match clientVerifyingShareB64u binding' };
    }

    let clientVerifyingShareBytes: Uint8Array;
    try {
      clientVerifyingShareBytes = base64UrlDecode(clientVerifyingShareB64u);
    } catch {
      return { ok: false, code: 'invalid_body', message: 'clientVerifyingShareB64u must be valid base64url' };
    }
    if (clientVerifyingShareBytes.length !== 33) {
      return { ok: false, code: 'invalid_body', message: 'clientVerifyingShareB64u must decode to 33 bytes (compressed secp256k1 pubkey)' };
    }
    let clientPoint: ReturnType<typeof secp256k1.Point.fromBytes>;
    try {
      clientPoint = secp256k1.Point.fromBytes(clientVerifyingShareBytes);
      clientPoint.assertValidity();
    } catch {
      return { ok: false, code: 'invalid_body', message: 'clientVerifyingShareB64u is not a valid secp256k1 public key' };
    }

    const relayerSigningShare32 = deriveRelayerSecp256k1SigningShare32({
      masterSecretB64u: this.secp256k1MasterSecretB64u,
      relayerKeyId,
    });
    const relayerVerifyingShareBytes = secp256k1.getPublicKey(relayerSigningShare32, true);
    const relayerPoint = secp256k1.Point.fromBytes(relayerVerifyingShareBytes);
    const groupPoint = clientPoint.add(relayerPoint);
    const groupPublicKeyBytes = groupPoint.toBytes(true);

    const relayerThresholdShare32 = mapAdditiveShareToThresholdSignaturesShare2p({
      additiveShare32: relayerSigningShare32,
      participantId: this.relayerParticipantId,
    });

    const participantIds = normalizeThresholdEd25519ParticipantIds(claims.participantIds)
      || [...this.participantIds2p];

    const nowMs = Date.now();
    const ttlMs = Math.max(0, Math.min(5 * 60_000, claims.thresholdExpiresAtMs - nowMs));
    if (ttlMs <= 0) {
      return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
    }
    const expiresAtMs = nowMs + ttlMs;
    if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
      return { ok: false, code: 'unsupported', message: 'crypto.getRandomValues is unavailable in this runtime' };
    }

    for (let attempt = 0; attempt < 4; attempt += 1) {
      const presignSessionId = this.createPresignSessionId();
      const sessionSeed32 = crypto.getRandomValues(new Uint8Array(32));
      const polled = withDeterministicCryptoRandom(sessionSeed32, () => {
        const wasmSession = new ThresholdEcdsaPresignSession(
          new Uint32Array(participantIds),
          this.relayerParticipantId,
          2,
          relayerThresholdShare32,
          groupPublicKeyBytes,
        );
        return pollWasmPresignSession(wasmSession);
      });

      const storedState: SerializedPresignSessionState = {
        kind: 'replay_v1',
        sessionSeedB64u: base64UrlEncode(sessionSeed32),
        relayerThresholdShareB64u: base64UrlEncode(relayerThresholdShare32),
        groupPublicKeyB64u: base64UrlEncode(groupPublicKeyBytes),
        appliedSteps: [],
      };

      const createdAtMs = Date.now();
      const record: ThresholdEcdsaPresignSessionRecord = {
        expiresAtMs,
        userId,
        rpId: tokenRpId,
        relayerKeyId,
        participantIds,
        clientParticipantId: this.clientParticipantId,
        relayerParticipantId: this.relayerParticipantId,
        stage: polled.stage,
        version: 1,
        wasmSessionStateB64u: serializePresignSessionState(storedState),
        createdAtMs,
        updatedAtMs: createdAtMs,
      };

      const created = await this.presignSessionStore.createSession(
        presignSessionId,
        record,
        Math.max(1, expiresAtMs - Date.now()),
      );
      if (!created.ok) continue;

      return {
        ok: true,
        presignSessionId,
        stage: polled.stage,
        outgoingMessagesB64u: polled.outgoingMessagesB64u,
      };
    }

    return { ok: false, code: 'internal', message: 'Failed to allocate presignSessionId; retry' };
  }

  async thresholdEcdsaPresignStep(input: {
    claims: ThresholdEcdsaSessionClaims;
    request: ThresholdEcdsaPresignStepRequest;
  }): Promise<ThresholdEcdsaPresignStepResponse> {
    if (this.nodeRole !== 'coordinator') {
      return {
        ok: false,
        code: 'not_found',
        message: 'threshold-ecdsa presign endpoints are not enabled on this server (set THRESHOLD_NODE_ROLE=coordinator)',
      };
    }

    await this.ensureReady();
    await ensureEthSignerWasm();

    const parsedRequest = parseThresholdEcdsaPresignStepRequest(input.request);
    if (!parsedRequest.ok) return parsedRequest;
    const { presignSessionId, stage: requestedStage, outgoingMessagesB64u } = parsedRequest.value;

    const record = await this.presignSessionStore.getSession(presignSessionId);
    if (!record) {
      return { ok: false, code: 'unauthorized', message: 'presignSessionId expired or invalid' };
    }
    if (Date.now() > record.expiresAtMs) {
      await this.presignSessionStore.deleteSession(presignSessionId);
      return { ok: false, code: 'unauthorized', message: 'presignSessionId expired' };
    }

    const claims = input.claims;
    const tokenUserId = toOptionalTrimmedString(claims?.sub);
    const tokenRpId = toOptionalTrimmedString(claims?.rpId);
    const tokenParticipantIds = normalizeThresholdEd25519ParticipantIds(claims?.participantIds);
    if (!tokenUserId || !tokenRpId || !tokenParticipantIds) {
      await this.presignSessionStore.deleteSession(presignSessionId);
      return { ok: false, code: 'unauthorized', message: 'Invalid threshold session token claims' };
    }
    if (
      tokenUserId !== record.userId
      || tokenRpId !== record.rpId
      || !sameParticipantIds(tokenParticipantIds, record.participantIds)
    ) {
      await this.presignSessionStore.deleteSession(presignSessionId);
      return { ok: false, code: 'unauthorized', message: 'presignSessionId does not match threshold session scope' };
    }
    if (toOptionalTrimmedString(claims?.relayerKeyId) !== record.relayerKeyId) {
      await this.presignSessionStore.deleteSession(presignSessionId);
      return { ok: false, code: 'unauthorized', message: 'presignSessionId does not match threshold session scope' };
    }
    if (Date.now() > claims.thresholdExpiresAtMs) {
      await this.presignSessionStore.deleteSession(presignSessionId);
      return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
    }

    const state = parseSerializedPresignSessionState(record.wasmSessionStateB64u);
    if (!state) {
      await this.presignSessionStore.deleteSession(presignSessionId);
      return { ok: false, code: 'internal', message: 'Corrupt presign session state' };
    }
    const sessionSeed32 = decodeSessionSeed32(state.sessionSeedB64u);
    if (!sessionSeed32) {
      await this.presignSessionStore.deleteSession(presignSessionId);
      return { ok: false, code: 'internal', message: 'Corrupt presign session seed' };
    }

    type PreparedPresignStepValue =
      | {
        mode: 'terminal';
        presignDone: {
          presignatureId: string;
          bigRB64u: string;
          kShareB64u: string;
          sigmaShareB64u: string;
        };
      }
      | {
        mode: 'immediate';
        response: ThresholdEcdsaPresignStepResponse;
      }
      | {
        mode: 'advance';
        polled: WasmPresignPoll;
        nextRecord: ThresholdEcdsaPresignSessionRecord;
        presignDone: {
          presignatureId: string;
          bigRB64u: string;
          kShareB64u: string;
          sigmaShareB64u: string;
        } | null;
      };

    const prepared: ParseResult<PreparedPresignStepValue> = withDeterministicCryptoRandom(
      sessionSeed32,
      (): ParseResult<PreparedPresignStepValue> => {
        const replayed = reconstructPresignSessionFromState({ record, state });
        if (!replayed) {
          return { ok: false, code: 'internal', message: 'Failed to restore presign session state' } as ParseErr;
        }

        const wasmSession = replayed.session;
        const currentStage = replayed.stage;
        if (currentStage !== record.stage) {
          return { ok: false, code: 'internal', message: 'presign session stage mismatch' } as ParseErr;
        }

        if (currentStage === 'done') {
          const terminal = takePresignatureFromSession(wasmSession);
          if (!terminal.ok) return terminal;
          return {
            ok: true,
            value: {
              mode: 'terminal' as const,
              presignDone: terminal.value,
            },
          };
        }

        if (currentStage === 'triples_done' && requestedStage === 'triples') {
          return {
            ok: true,
            value: {
              mode: 'immediate' as const,
              response: { ok: true, stage: 'triples_done' as const, event: 'triples_done' as const, outgoingMessagesB64u: [] },
            },
          };
        }
        if (requestedStage === 'presign' && currentStage === 'triples_done') {
          wasmSession.start_presign();
        } else if (requestedStage === 'presign' && currentStage === 'triples') {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'server is not ready for presign (triples still running)',
          } as ParseErr;
        } else if (requestedStage === 'triples' && currentStage !== 'triples') {
          return { ok: false, code: 'invalid_body', message: 'stage regression is not allowed' } as ParseErr;
        }

        const decodedIncoming = decodePresignIncomingMessages(outgoingMessagesB64u);
        if (!decodedIncoming.ok) return decodedIncoming;

        for (const decoded of decodedIncoming.value) {
          try {
            wasmSession.message(record.clientParticipantId, decoded);
          } catch (e: unknown) {
            return {
              ok: false,
              code: 'invalid_body',
              message: `Protocol rejected message: ${String(e || 'error')}`,
            } as ParseErr;
          }
        }

        const polled = pollWasmPresignSession(wasmSession);
        const nextExpiresAtMs = Math.min(record.expiresAtMs, claims.thresholdExpiresAtMs);
        const nextState: SerializedPresignSessionState = {
          ...state,
          appliedSteps: [...state.appliedSteps, { stage: requestedStage, incomingMessagesB64u: outgoingMessagesB64u }],
        };
        const nextRecord: ThresholdEcdsaPresignSessionRecord = {
          ...record,
          stage: polled.stage,
          version: record.version + 1,
          wasmSessionStateB64u: serializePresignSessionState(nextState),
          expiresAtMs: nextExpiresAtMs,
          updatedAtMs: Date.now(),
        };

        let presignDone: {
          presignatureId: string;
          bigRB64u: string;
          kShareB64u: string;
          sigmaShareB64u: string;
        } | null = null;
        if (polled.event === 'presign_done') {
          const done = takePresignatureFromSession(wasmSession);
          if (!done.ok) return done;
          presignDone = done.value;
        }

        return {
          ok: true,
          value: {
            mode: 'advance' as const,
            polled,
            nextRecord,
            presignDone,
          },
        };
      },
    );
    if (!prepared.ok) {
      if (prepared.code === 'internal') {
        await this.presignSessionStore.deleteSession(presignSessionId);
      }
      return prepared;
    }
    if (prepared.value.mode === 'immediate') {
      return prepared.value.response;
    }
    if (prepared.value.mode === 'terminal') {
      await this.presignaturePool.put({
        relayerKeyId: record.relayerKeyId,
        presignatureId: prepared.value.presignDone.presignatureId,
        bigRB64u: prepared.value.presignDone.bigRB64u,
        kShareB64u: prepared.value.presignDone.kShareB64u,
        sigmaShareB64u: prepared.value.presignDone.sigmaShareB64u,
        createdAtMs: Date.now(),
      });
      await this.presignSessionStore.deleteSession(presignSessionId);
      return {
        ok: true,
        stage: 'done',
        event: 'presign_done',
        outgoingMessagesB64u: [],
        presignatureId: prepared.value.presignDone.presignatureId,
        bigRB64u: prepared.value.presignDone.bigRB64u,
      };
    }

    const { polled, nextRecord, presignDone } = prepared.value;
    const ttlMs = nextRecord.expiresAtMs - Date.now();
    if (ttlMs <= 0) {
      await this.presignSessionStore.deleteSession(presignSessionId);
      return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
    }

    const cas = await this.presignSessionStore.advanceSessionCas({
      id: presignSessionId,
      expectedVersion: record.version,
      nextRecord,
      ttlMs,
    });
    if (!cas.ok) {
      if (cas.code === 'expired') return { ok: false, code: 'unauthorized', message: 'presignSessionId expired' };
      if (cas.code === 'not_found') return { ok: false, code: 'unauthorized', message: 'presignSessionId expired or invalid' };
      return { ok: false, code: 'stale_session_state', message: 'Presign session updated concurrently; retry step' };
    }

    if (polled.event === 'presign_done') {
      if (!presignDone) {
        return { ok: false, code: 'internal', message: 'presign_done missing presignature material' };
      }
      await this.presignaturePool.put({
        relayerKeyId: record.relayerKeyId,
        presignatureId: presignDone.presignatureId,
        bigRB64u: presignDone.bigRB64u,
        kShareB64u: presignDone.kShareB64u,
        sigmaShareB64u: presignDone.sigmaShareB64u,
        createdAtMs: Date.now(),
      });
      await this.presignSessionStore.deleteSession(presignSessionId);
      return {
        ok: true,
        stage: 'done',
        event: 'presign_done',
        outgoingMessagesB64u: polled.outgoingMessagesB64u,
        presignatureId: presignDone.presignatureId,
        bigRB64u: presignDone.bigRB64u,
      };
    }

    return {
      ok: true,
      stage: polled.stage,
      event: polled.event === 'triples_done' ? 'triples_done' : 'none',
      outgoingMessagesB64u: polled.outgoingMessagesB64u,
    };
  }

  async thresholdEcdsaSignInit(request: ThresholdEcdsaSignInitRequest): Promise<ThresholdEcdsaSignInitResponse> {
    const route = '/threshold-ecdsa/sign/init';

    if (this.nodeRole !== 'coordinator') {
      return {
        ok: false,
        code: 'not_found',
        message: 'threshold-ecdsa signing endpoints are not enabled on this server (set THRESHOLD_NODE_ROLE=coordinator)',
      };
    }

    await this.ensureReady();
    const parsedRequest = parseThresholdEcdsaSignInitRequest(request);
    if (!parsedRequest.ok) return parsedRequest;
    const { mpcSessionId, relayerKeyId, signingDigestB64u } = parsedRequest.value;

    this.logger.info('[threshold-ecdsa] request', {
      route,
      mpcSessionId,
      relayerKeyId,
      signingDigestB64u_len: signingDigestB64u.length,
    });

    const sess = await this.sessionStore.takeMpcSession(mpcSessionId);
    if (!sess) {
      return { ok: false, code: 'unauthorized', message: 'mpcSessionId expired or invalid' };
    }
    if (Date.now() > sess.expiresAtMs) {
      return { ok: false, code: 'unauthorized', message: 'mpcSessionId expired' };
    }

    const participantIds = normalizeThresholdEd25519ParticipantIds(sess.participantIds) || [...this.participantIds2p];

    if (relayerKeyId !== sess.relayerKeyId) {
      return { ok: false, code: 'unauthorized', message: 'relayerKeyId does not match mpcSessionId scope' };
    }
    if (signingDigestB64u !== sess.signingDigestB64u) {
      return { ok: false, code: 'unauthorized', message: 'signingDigestB64u does not match mpcSessionId scope' };
    }

    const presignature = await this.presignaturePool.reserve(relayerKeyId);
    if (!presignature) {
      return { ok: false, code: 'pool_empty', message: 'presignature pool is empty; refill required' };
    }

    if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
      await this.presignaturePool.discard(relayerKeyId, presignature.presignatureId);
      return { ok: false, code: 'unsupported', message: 'crypto.getRandomValues is unavailable in this runtime' };
    }

    const ttlMs = Math.max(0, Math.min(60_000, sess.expiresAtMs - Date.now()));
    if (ttlMs <= 0) {
      await this.presignaturePool.discard(relayerKeyId, presignature.presignatureId);
      return { ok: false, code: 'unauthorized', message: 'mpcSessionId expired' };
    }

    const signingSessionId = this.createSigningSessionId();
    const entropyB64u = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));

    const record: ThresholdEcdsaSigningSessionRecord = {
      expiresAtMs: sess.expiresAtMs,
      mpcSessionId,
      relayerKeyId,
      signingDigestB64u: sess.signingDigestB64u,
      userId: sess.userId,
      rpId: sess.rpId,
      clientVerifyingShareB64u: sess.clientVerifyingShareB64u,
      participantIds,
      presignatureId: presignature.presignatureId,
      entropyB64u,
      ...(presignature.bigRB64u ? { bigRB64u: presignature.bigRB64u } : {}),
    };

    await this.signingSessionStore.putSigningSession(signingSessionId, record, ttlMs);

    return {
      ok: true,
      signingSessionId,
      relayerRound1: {
        presignatureId: presignature.presignatureId,
        entropyB64u,
        ...(presignature.bigRB64u ? { bigRB64u: presignature.bigRB64u } : {}),
      },
    };
  }

  async thresholdEcdsaSignFinalize(request: ThresholdEcdsaSignFinalizeRequest): Promise<ThresholdEcdsaSignFinalizeResponse> {
    const route = '/threshold-ecdsa/sign/finalize';

    if (this.nodeRole !== 'coordinator') {
      return {
        ok: false,
        code: 'not_found',
        message: 'threshold-ecdsa signing endpoints are not enabled on this server (set THRESHOLD_NODE_ROLE=coordinator)',
      };
    }

    await this.ensureReady();
    await ensureEthSignerWasm();
    const parsedRequest = parseThresholdEcdsaSignFinalizeRequest(request);
    if (!parsedRequest.ok) return parsedRequest;
    const { signingSessionId, clientSignatureShareB64u } = parsedRequest.value;

    this.logger.info('[threshold-ecdsa] request', {
      route,
      signingSessionId,
      clientSignatureShareB64u_len: clientSignatureShareB64u.length,
    });

    const sess = await this.signingSessionStore.takeSigningSession(signingSessionId);
    if (!sess) {
      return { ok: false, code: 'unauthorized', message: 'signingSessionId expired or invalid' };
    }
    if (Date.now() > sess.expiresAtMs) {
      await this.presignaturePool.discard(sess.relayerKeyId, sess.presignatureId);
      return { ok: false, code: 'unauthorized', message: 'signingSessionId expired' };
    }

    if (!this.secp256k1MasterSecretB64u) {
      await this.presignaturePool.discard(sess.relayerKeyId, sess.presignatureId);
      return { ok: false, code: 'not_configured', message: 'threshold-ecdsa requires THRESHOLD_SECP256K1_MASTER_SECRET_B64U' };
    }
    if (this.clientParticipantId !== 1 || this.relayerParticipantId !== 2) {
      await this.presignaturePool.discard(sess.relayerKeyId, sess.presignatureId);
      return { ok: false, code: 'unsupported', message: 'v1 signer requires participantIds={client=1,relayer=2}' };
    }

    let clientSignatureShare32: Uint8Array;
    try {
      clientSignatureShare32 = base64UrlDecode(clientSignatureShareB64u);
      if (clientSignatureShare32.length !== 32) {
        await this.presignaturePool.discard(sess.relayerKeyId, sess.presignatureId);
        return { ok: false, code: 'invalid_body', message: `clientSignatureShareB64u must be 32 bytes, got ${clientSignatureShare32.length}` };
      }
    } catch (e: unknown) {
      await this.presignaturePool.discard(sess.relayerKeyId, sess.presignatureId);
      return { ok: false, code: 'invalid_body', message: `Invalid clientSignatureShareB64u: ${String(e || 'decode failed')}` };
    }

    const presignature = await this.presignaturePool.consume(sess.relayerKeyId, sess.presignatureId);
    if (!presignature) {
      return { ok: false, code: 'internal', message: 'Reserved presignature is missing or expired (cannot finalize signature)' };
    }

    let digest32: Uint8Array;
    let entropy32: Uint8Array;
    let presignBigR33: Uint8Array;
    let relayerKShare32: Uint8Array;
    let relayerSigmaShare32: Uint8Array;
    let clientVerifyingShare33: Uint8Array;
    try {
      digest32 = base64UrlDecode(sess.signingDigestB64u);
      entropy32 = base64UrlDecode(sess.entropyB64u);
      presignBigR33 = base64UrlDecode(presignature.bigRB64u);
      relayerKShare32 = base64UrlDecode(presignature.kShareB64u);
      relayerSigmaShare32 = base64UrlDecode(presignature.sigmaShareB64u);
      clientVerifyingShare33 = base64UrlDecode(sess.clientVerifyingShareB64u);
    } catch (e: unknown) {
      return { ok: false, code: 'internal', message: `Failed to decode signing inputs: ${String(e || 'decode failed')}` };
    }

    if (digest32.length !== 32) return { ok: false, code: 'internal', message: `signingDigestB64u must decode to 32 bytes, got ${digest32.length}` };
    if (entropy32.length !== 32) return { ok: false, code: 'internal', message: `entropyB64u must decode to 32 bytes, got ${entropy32.length}` };
    if (presignBigR33.length !== 33) return { ok: false, code: 'internal', message: `presignature.bigRB64u must decode to 33 bytes, got ${presignBigR33.length}` };
    if (relayerKShare32.length !== 32) return { ok: false, code: 'internal', message: `presignature.kShareB64u must decode to 32 bytes, got ${relayerKShare32.length}` };
    if (relayerSigmaShare32.length !== 32) return { ok: false, code: 'internal', message: `presignature.sigmaShareB64u must decode to 32 bytes, got ${relayerSigmaShare32.length}` };
    if (clientVerifyingShare33.length !== 33) return { ok: false, code: 'internal', message: `clientVerifyingShareB64u must decode to 33 bytes, got ${clientVerifyingShare33.length}` };

    let groupPublicKey33: Uint8Array;
    try {
      const clientPoint = secp256k1.Point.fromBytes(clientVerifyingShare33);
      clientPoint.assertValidity();
      const relayerSigningShare32 = deriveRelayerSecp256k1SigningShare32({
        masterSecretB64u: this.secp256k1MasterSecretB64u,
        relayerKeyId: sess.relayerKeyId,
      });
      const relayerVerifyingShare33 = secp256k1.getPublicKey(relayerSigningShare32, true);
      const relayerPoint = secp256k1.Point.fromBytes(relayerVerifyingShare33);
      groupPublicKey33 = clientPoint.add(relayerPoint).toBytes(true);
    } catch (e: unknown) {
      return { ok: false, code: 'internal', message: `Failed to derive group public key: ${String(e || 'error')}` };
    }

    const participantIds = normalizeThresholdEd25519ParticipantIds(sess.participantIds) || [...this.participantIds2p];

    try {
      const sig65 = threshold_ecdsa_finalize_signature(
        new Uint32Array(participantIds),
        this.relayerParticipantId,
        groupPublicKey33,
        presignBigR33,
        relayerKShare32,
        relayerSigmaShare32,
        digest32,
        entropy32,
        clientSignatureShare32,
      );
      if (sig65.length !== 65) {
        return { ok: false, code: 'internal', message: `Invalid signature output (expected 65 bytes, got ${sig65.length})` };
      }
      const r32 = sig65.slice(0, 32);
      const s32 = sig65.slice(32, 64);
      const recId = sig65[64]!;
      if (!Number.isFinite(recId) || recId < 0 || recId > 3) {
        return { ok: false, code: 'internal', message: `Invalid recovery id (expected 0..3, got ${recId})` };
      }

      return {
        ok: true,
        relayerRound2: {
          signature65B64u: base64UrlEncode(sig65),
          rB64u: base64UrlEncode(r32),
          sB64u: base64UrlEncode(s32),
          recId,
        },
      };
    } catch (e: unknown) {
      const msg = String((e && typeof e === 'object' && 'message' in e) ? (e as { message?: unknown }).message : e || 'finalize failed');
      return { ok: false, code: 'invalid_body', message: msg };
    }
  }
}
