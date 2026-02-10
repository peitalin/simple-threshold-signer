import { test, expect } from '@playwright/test';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/utils.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { alphabetizeStringify, sha256BytesUtf8 } from '../../shared/src/utils/digests';
import { base64UrlDecode, base64UrlEncode } from '../../shared/src/utils/encoders';
import { mapAdditiveShareToThresholdSignaturesShare2p } from '../../shared/src/threshold/secp256k1Ecdsa2pShareMapping';
import { SECP256K1_ORDER } from '../../shared/src/threshold/secp256k1';
import { THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID } from '../../server/src/server/core/ThresholdService/schemes/schemeIds';
import { ThresholdEcdsaSigningHandlers } from '../../server/src/server/core/ThresholdService/ecdsaSigningHandlers';
import {
  InMemoryThresholdEcdsaPresignSessionStore,
  InMemoryThresholdEcdsaPresignaturePool,
  InMemoryThresholdEcdsaSigningSessionStore,
} from '../../server/src/server/core/ThresholdService/stores/EcdsaSigningStore';
import {
  ThresholdEcdsaPresignSession,
} from '../../wasm/eth_signer/pkg/eth_signer.js';

const TEST_MASTER_SECRET_B64U = Buffer.from(new Uint8Array(32).fill(9)).toString('base64url');

function deriveRelayerSecp256k1SigningShare32(input: { masterSecretB64u: string; relayerKeyId: string }): Uint8Array {
  const masterSecretBytes = base64UrlDecode(input.masterSecretB64u);
  const relayerShareSaltV1 = new TextEncoder().encode('tatchi/lite/threshold-secp256k1-ecdsa/relayer-share:v1');
  const relayerShareInfo = new TextEncoder().encode(input.relayerKeyId);
  const okm64 = hkdf(sha256, masterSecretBytes, relayerShareSaltV1, relayerShareInfo, 64);
  const reduced = (bytesToNumberBE(okm64) % (SECP256K1_ORDER - 1n)) + 1n;
  return numberToBytesBE(reduced, 32);
}

function pollSession(session: ThresholdEcdsaPresignSession): {
  stage: 'triples' | 'triples_done' | 'presign' | 'done';
  event: 'none' | 'triples_done' | 'presign_done';
  outgoingMessages: Uint8Array[];
} {
  const raw = session.poll() as { stage?: unknown; event?: unknown; outgoing?: unknown };
  const stage = raw?.stage === 'triples_done'
    ? 'triples_done'
    : raw?.stage === 'presign'
      ? 'presign'
      : raw?.stage === 'done'
        ? 'done'
        : 'triples';
  const event = raw?.event === 'triples_done'
    ? 'triples_done'
    : raw?.event === 'presign_done'
      ? 'presign_done'
      : 'none';
  const outgoingMessages = Array.isArray(raw?.outgoing)
    ? raw.outgoing.map((entry) => {
      if (entry instanceof Uint8Array) return entry;
      if (entry instanceof ArrayBuffer) return new Uint8Array(entry);
      if (ArrayBuffer.isView(entry as any)) {
        const view = entry as ArrayBufferView;
        return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
      }
      throw new Error('Unexpected presign outgoing message type');
    })
    : [];
  return { stage, event, outgoingMessages };
}

test.describe('threshold-ecdsa presign distributed session store', () => {
  test('progresses one presign session across two coordinator instances', async () => {
    const userId = 'distributed-user';
    const rpId = 'example.localhost';
    const participantIds = [1, 2];
    const clientParticipantId = 1;
    const relayerParticipantId = 2;
    const thresholdExpiresAtMs = Date.now() + 120_000;

    const clientSigningShare32 = secp256k1.utils.randomSecretKey();
    const clientVerifyingShare33 = secp256k1.getPublicKey(clientSigningShare32, true);
    const clientVerifyingShareB64u = base64UrlEncode(clientVerifyingShare33);

    const relayerKeyIdDigest32 = await sha256BytesUtf8(alphabetizeStringify({
      version: 'threshold_secp256k1_key_id_v1',
      schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
      userId,
      rpId,
      clientVerifyingShareB64u,
    }));
    const relayerKeyId = `secp-${base64UrlEncode(relayerKeyIdDigest32)}`;

    const relayerSigningShare32 = deriveRelayerSecp256k1SigningShare32({
      masterSecretB64u: TEST_MASTER_SECRET_B64U,
      relayerKeyId,
    });
    const relayerVerifyingShare33 = secp256k1.getPublicKey(relayerSigningShare32, true);
    const groupPublicKey33 = secp256k1.Point.fromBytes(clientVerifyingShare33)
      .add(secp256k1.Point.fromBytes(relayerVerifyingShare33))
      .toBytes(true);

    const sharedPresignSessionStore = new InMemoryThresholdEcdsaPresignSessionStore();
    const sharedPresignaturePool = new InMemoryThresholdEcdsaPresignaturePool();
    const sharedSigningSessionStore = new InMemoryThresholdEcdsaSigningSessionStore();

    const fakeSessionStore = {
      putMpcSession: async () => {},
      takeMpcSession: async () => null,
      putSigningSession: async () => {},
      takeSigningSession: async () => null,
      putCoordinatorSigningSession: async () => {},
      takeCoordinatorSigningSession: async () => null,
    } as const;

    let presignIdCounter = 0;
    const makeHandler = () => new ThresholdEcdsaSigningHandlers({
      logger: console as any,
      nodeRole: 'coordinator',
      participantIds2p: participantIds,
      clientParticipantId,
      relayerParticipantId,
      secp256k1MasterSecretB64u: TEST_MASTER_SECRET_B64U,
      sessionStore: fakeSessionStore as any,
      signingSessionStore: sharedSigningSessionStore,
      presignSessionStore: sharedPresignSessionStore,
      presignaturePool: sharedPresignaturePool,
      ensureReady: async () => {},
      createSigningSessionId: () => `sign-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      createPresignSessionId: () => `presign-${++presignIdCounter}`,
    });

    const handlerA = makeHandler();
    const handlerB = makeHandler();

    const claims = {
      sub: userId,
      rpId,
      relayerKeyId,
      participantIds,
      thresholdExpiresAtMs,
    };

    const init = await handlerA.thresholdEcdsaPresignInit({
      claims: claims as any,
      request: { relayerKeyId, clientVerifyingShareB64u, count: 1 },
    });
    expect(init.ok, JSON.stringify(init)).toBe(true);
    const presignSessionId = String(init.presignSessionId || '');
    expect(presignSessionId).toBeTruthy();

    const localClientThresholdShare32 = mapAdditiveShareToThresholdSignaturesShare2p({
      additiveShare32: clientSigningShare32,
      participantId: clientParticipantId,
    });
    const localSession = new ThresholdEcdsaPresignSession(
      new Uint32Array(participantIds),
      clientParticipantId,
      2,
      localClientThresholdShare32,
      groupPublicKey33,
    );

    let stageForServer: 'triples' | 'presign' = 'triples';
    let pendingClientOutgoing = pollSession(localSession).outgoingMessages;
    let pendingServerOutgoing = (init.outgoingMessagesB64u || []).map((msg) => base64UrlDecode(msg));
    let localPresignature97: Uint8Array | null = null;
    let serverPresignatureId = '';
    let serverBigRB64u = '';
    let serverDone = false;

    const MAX_STEPS = 64;
    for (let i = 0; i < MAX_STEPS; i += 1) {
      if (pendingServerOutgoing.length > 0 && !localPresignature97) {
        if (stageForServer === 'presign' && localSession.stage() === 'triples_done') {
          localSession.start_presign();
        }
        for (const msg of pendingServerOutgoing) {
          localSession.message(relayerParticipantId, msg);
        }
        pendingServerOutgoing = [];
        const polled = pollSession(localSession);
        pendingClientOutgoing.push(...polled.outgoingMessages);
        if (polled.stage === 'triples_done' || polled.stage === 'presign' || polled.stage === 'done') {
          stageForServer = 'presign';
        }
        if (polled.event === 'presign_done') {
          localPresignature97 = localSession.take_presignature_97();
        }
      }

      if (!serverDone) {
        const activeHandler = i % 2 === 0 ? handlerB : handlerA;
        const step = await activeHandler.thresholdEcdsaPresignStep({
          claims: claims as any,
          request: {
            presignSessionId,
            stage: stageForServer,
            outgoingMessagesB64u: pendingClientOutgoing.map((msg) => base64UrlEncode(msg)),
          },
        });
        expect(step.ok, JSON.stringify(step)).toBe(true);
        pendingClientOutgoing = [];
        pendingServerOutgoing = (step.outgoingMessagesB64u || []).map((msg) => base64UrlDecode(msg));
        if (step.event === 'triples_done' || step.stage === 'presign') {
          stageForServer = 'presign';
        }
        if (step.event === 'presign_done') {
          serverDone = true;
          serverPresignatureId = String(step.presignatureId || '');
          serverBigRB64u = String(step.bigRB64u || '');
        }
      }

      if (serverDone && localPresignature97) break;
    }

    expect(serverDone).toBe(true);
    expect(localPresignature97).not.toBeNull();
    const localBigR33 = localPresignature97!.slice(0, 33);
    const expectedPresignatureId = `presig-${base64UrlEncode(sha256(localBigR33))}`;
    expect(serverPresignatureId).toBe(expectedPresignatureId);
    expect(serverBigRB64u).toBe(base64UrlEncode(localBigR33));

    const reserved = await sharedPresignaturePool.reserve(relayerKeyId);
    expect(reserved?.presignatureId).toBe(serverPresignatureId);
    expect(reserved?.bigRB64u).toBe(serverBigRB64u);
  });
});
