import { test, expect } from '@playwright/test';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { createRelayRouter } from '@server/router/express-adaptor';
import { AuthService } from '@server/core/AuthService';
import { createThresholdSigningService } from '@server/core/ThresholdService';
import { makeSessionAdapter, fetchJson, startExpressRouter } from './helpers';
import {
  ThresholdEcdsaPresignSession,
  threshold_ecdsa_compute_signature_share,
} from '../../wasm/eth_signer/pkg/eth_signer.js';
import { mapAdditiveShareToThresholdSignaturesShare2p } from '../../shared/src/threshold/secp256k1Ecdsa2pShareMapping';

const TEST_MASTER_SECRET_B64U = Buffer.from(new Uint8Array(32).fill(9)).toString('base64url');

function makeAuthServiceForThreshold(): {
  service: AuthService;
  threshold: ReturnType<typeof createThresholdSigningService>;
} {
  const service = new AuthService({
    relayerAccountId: 'relayer.testnet',
    relayerPrivateKey: 'ed25519:dummy',
    webAuthnContractId: 'w3a-v1.testnet',
    nearRpcUrl: 'https://rpc.testnet.near.org',
    networkId: 'testnet',
    accountInitialBalance: '1',
    createAccountAndRegisterGas: '1',
    logger: null,
  });

  (service as unknown as {
    verifyWebAuthnAuthenticationLite: (req: unknown) => Promise<{ success: boolean; verified: boolean }>;
  }).verifyWebAuthnAuthenticationLite = async (_req: unknown) => ({ success: true, verified: true });

  const threshold = createThresholdSigningService({
    authService: service,
    thresholdEd25519KeyStore: {
      kind: 'in-memory',
      THRESHOLD_NODE_ROLE: 'coordinator',
      THRESHOLD_SECP256K1_MASTER_SECRET_B64U: TEST_MASTER_SECRET_B64U,
    },
    logger: null,
  });

  return { service, threshold };
}

function makeJwtSessionAdapter(): ReturnType<typeof makeSessionAdapter> {
  const tokens = new Map<string, Record<string, unknown>>();
  return makeSessionAdapter({
    signJwt: async (sub: string, extra?: Record<string, unknown>) => {
      const token = `testjwt-${Date.now()}-${Math.random().toString(16).slice(2)}`;
      tokens.set(token, { sub, ...(extra || {}) });
      return token;
    },
    parse: async (headers: Record<string, string | string[] | undefined>) => {
      const authHeaderRaw = headers.authorization ?? headers.Authorization;
      const authHeader = Array.isArray(authHeaderRaw) ? authHeaderRaw[0] : authHeaderRaw;
      const token = typeof authHeader === 'string'
        ? authHeader.replace(/^Bearer\s+/i, '').trim()
        : '';
      const claims = token ? tokens.get(token) : undefined;
      return claims ? { ok: true as const, claims } : { ok: false as const };
    },
  });
}

function fakeWebAuthnAuthentication(): Record<string, unknown> {
  return {
    id: 'test',
    rawId: 'test',
    type: 'public-key',
    authenticatorAttachment: null,
    response: {
      clientDataJSON: 'test',
      authenticatorData: 'test',
      signature: 'test',
      userHandle: null,
    },
    clientExtensionResults: null,
  };
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

test.describe('threshold-ecdsa harness signature verification', () => {
  test('signs a known digest and verifies the signature against the group key', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    const session = makeJwtSessionAdapter();
    const router = createRelayRouter(service, { threshold, session });
    const srv = await startExpressRouter(router);

    try {
      const userId = 'bob.testnet';
      const rpId = 'example.localhost';
      const participantIds = [1, 2];
      const clientParticipantId = 1;
      const relayerParticipantId = 2;
      const digest32 = Uint8Array.from(Array.from({ length: 32 }, (_, i) => i + 1));
      const clientSigningShare32 = secp256k1.utils.randomSecretKey();
      const clientVerifyingShareB64u = base64UrlEncode(secp256k1.getPublicKey(clientSigningShare32, true));

      const keygen = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/keygen`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId,
          rpId,
          keygenSessionId: `keygen-${Date.now()}`,
          clientVerifyingShareB64u,
          webauthn_authentication: fakeWebAuthnAuthentication(),
        }),
      });
      expect(keygen.status, keygen.text).toBe(200);
      expect(keygen.json?.ok, keygen.text).toBe(true);

      const relayerKeyId = String(keygen.json?.relayerKeyId || '');
      const groupPublicKeyB64u = String(keygen.json?.groupPublicKeyB64u || '');
      expect(relayerKeyId).toBeTruthy();
      expect(groupPublicKeyB64u).toBeTruthy();

      const sessionId = `sess-${Date.now()}`;
      const minted = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          relayerKeyId,
          clientVerifyingShareB64u,
          sessionKind: 'jwt',
          sessionPolicy: {
            version: 'threshold_session_v1',
            userId,
            rpId,
            relayerKeyId,
            sessionId,
            ttlMs: 60_000,
            remainingUses: 3,
            participantIds,
          },
          webauthn_authentication: fakeWebAuthnAuthentication(),
        }),
      });
      expect(minted.status, minted.text).toBe(200);
      expect(minted.json?.ok, minted.text).toBe(true);

      const jwt = String(minted.json?.jwt || '');
      expect(jwt).toBeTruthy();

      const authorized = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/authorize`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${jwt}`,
        },
        body: JSON.stringify({
          relayerKeyId,
          clientVerifyingShareB64u,
          purpose: 'test:known_digest',
          signing_digest_32: Array.from(digest32),
        }),
      });
      expect(authorized.status, authorized.text).toBe(200);
      expect(authorized.json?.ok, authorized.text).toBe(true);
      const mpcSessionId = String(authorized.json?.mpcSessionId || '');
      expect(mpcSessionId).toBeTruthy();

      const presignInit = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/presign/init`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${jwt}`,
        },
        body: JSON.stringify({
          relayerKeyId,
          clientVerifyingShareB64u,
          count: 1,
        }),
      });
      expect(presignInit.status, presignInit.text).toBe(200);
      expect(presignInit.json?.ok, presignInit.text).toBe(true);

      const presignSessionId = String(presignInit.json?.presignSessionId || '');
      expect(presignSessionId).toBeTruthy();

      const groupPublicKey33 = base64UrlDecode(groupPublicKeyB64u);
      const clientThresholdSigningShare32 = mapAdditiveShareToThresholdSignaturesShare2p({
        additiveShare32: clientSigningShare32,
        participantId: clientParticipantId,
      });
      const localPresignSession = new ThresholdEcdsaPresignSession(
        new Uint32Array(participantIds),
        clientParticipantId,
        2,
        clientThresholdSigningShare32,
        groupPublicKey33,
      );

      let stageForServer: 'triples' | 'presign' = 'triples';
      let pendingClientOutgoing = pollSession(localPresignSession).outgoingMessages;
      let pendingServerOutgoing = (
        Array.isArray(presignInit.json?.outgoingMessagesB64u) ? presignInit.json!.outgoingMessagesB64u : []
      ).map((entry) => base64UrlDecode(String(entry || '')));
      let localPresignature97: Uint8Array | null = null;
      let serverPresignatureId = '';
      let serverBigRB64u = '';
      let serverDone = false;

      const MAX_HANDSHAKE_STEPS = 64;
      for (let i = 0; i < MAX_HANDSHAKE_STEPS; i += 1) {
        if (pendingServerOutgoing.length > 0 && !localPresignature97) {
          if (stageForServer === 'presign' && localPresignSession.stage() === 'triples_done') {
            localPresignSession.start_presign();
          }
          for (const msg of pendingServerOutgoing) {
            localPresignSession.message(relayerParticipantId, msg);
          }
          pendingServerOutgoing = [];
          const polled = pollSession(localPresignSession);
          pendingClientOutgoing.push(...polled.outgoingMessages);
          if (polled.stage === 'triples_done' || polled.stage === 'presign' || polled.stage === 'done') {
            stageForServer = 'presign';
          }
          if (polled.event === 'presign_done') {
            localPresignature97 = localPresignSession.take_presignature_97();
          }
        }

        if (!serverDone) {
          const presignStep = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/presign/step`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${jwt}`,
            },
            body: JSON.stringify({
              presignSessionId,
              stage: stageForServer,
              outgoingMessagesB64u: pendingClientOutgoing.map((entry) => base64UrlEncode(entry)),
            }),
          });
          expect(presignStep.status, presignStep.text).toBe(200);
          expect(presignStep.json?.ok, presignStep.text).toBe(true);
          pendingClientOutgoing = [];

          pendingServerOutgoing = (
            Array.isArray(presignStep.json?.outgoingMessagesB64u) ? presignStep.json!.outgoingMessagesB64u : []
          ).map((entry) => base64UrlDecode(String(entry || '')));
          const stepStage = String(presignStep.json?.stage || '');
          if (stepStage === 'presign' || stepStage === 'done') {
            stageForServer = 'presign';
          }
          if (String(presignStep.json?.event || '') === 'presign_done') {
            serverPresignatureId = String(presignStep.json?.presignatureId || '');
            serverBigRB64u = String(presignStep.json?.bigRB64u || '');
            serverDone = true;
          }
        }

        if (localPresignature97 && serverPresignatureId && serverBigRB64u) {
          break;
        }

        if (!pendingServerOutgoing.length && !pendingClientOutgoing.length && !localPresignature97) {
          if (stageForServer === 'presign' && localPresignSession.stage() === 'triples_done') {
            localPresignSession.start_presign();
          }
          const polled = pollSession(localPresignSession);
          pendingClientOutgoing.push(...polled.outgoingMessages);
          if (polled.stage === 'triples_done' || polled.stage === 'presign' || polled.stage === 'done') {
            stageForServer = 'presign';
          }
          if (polled.event === 'presign_done') {
            localPresignature97 = localPresignSession.take_presignature_97();
          }
        }
      }

      expect(localPresignature97).toBeTruthy();
      expect(serverPresignatureId).toBeTruthy();
      expect(serverBigRB64u).toBeTruthy();

      const bigR33 = localPresignature97!.slice(0, 33);
      const kShare32 = localPresignature97!.slice(33, 65);
      const sigmaShare32 = localPresignature97!.slice(65, 97);
      expect(base64UrlEncode(bigR33)).toBe(serverBigRB64u);

      const signInit = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/sign/init`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mpcSessionId,
          relayerKeyId,
          signingDigestB64u: base64UrlEncode(digest32),
          clientRound1: { presignatureId: serverPresignatureId },
        }),
      });
      expect(signInit.status, signInit.text).toBe(200);
      expect(signInit.json?.ok, signInit.text).toBe(true);

      const signingSessionId = String(signInit.json?.signingSessionId || '');
      const entropyB64u = String((signInit.json?.relayerRound1 as Record<string, unknown> | undefined)?.entropyB64u || '');
      const bigREchoB64u = String((signInit.json?.relayerRound1 as Record<string, unknown> | undefined)?.bigRB64u || '');
      expect(signingSessionId).toBeTruthy();
      expect(entropyB64u).toBeTruthy();
      if (bigREchoB64u) expect(bigREchoB64u).toBe(serverBigRB64u);

      const clientSignatureShare32 = threshold_ecdsa_compute_signature_share(
        new Uint32Array(participantIds),
        clientParticipantId,
        groupPublicKey33,
        bigR33,
        kShare32,
        sigmaShare32,
        digest32,
        base64UrlDecode(entropyB64u),
      );
      expect(clientSignatureShare32.length).toBe(32);

      const finalized = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/sign/finalize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          signingSessionId,
          clientRound2: { clientSignatureShareB64u: base64UrlEncode(clientSignatureShare32) },
        }),
      });
      expect(finalized.status, finalized.text).toBe(200);
      expect(finalized.json?.ok, finalized.text).toBe(true);

      const signature65B64u = String((finalized.json?.relayerRound2 as Record<string, unknown> | undefined)?.signature65B64u || '');
      expect(signature65B64u).toBeTruthy();

      const signature65 = base64UrlDecode(signature65B64u);
      expect(signature65.length).toBe(65);
      const signature64 = signature65.slice(0, 64);
      const recId = signature65[64]!;

      const verified = secp256k1.verify(signature64, digest32, groupPublicKey33, { lowS: true });
      expect(verified).toBe(true);

      const recovered = secp256k1.Signature
        .fromCompact(signature64)
        .addRecoveryBit(recId & 1)
        .recoverPublicKey(digest32)
        .toBytes(true);
      expect(base64UrlEncode(recovered)).toBe(groupPublicKeyB64u);
    } finally {
      await srv.close();
    }
  });
});
