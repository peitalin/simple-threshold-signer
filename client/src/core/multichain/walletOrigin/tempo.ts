import type { ConfirmationConfig } from '../../types/signer-worker';
import type { SecureConfirmWorkerManagerContext } from '../../WebAuthnManager/SecureConfirmWorkerManager';
import { runSecureConfirm } from '../../WebAuthnManager/SecureConfirmWorkerManager/secureConfirmBridge';
import { SecureConfirmationType, type SecureConfirmRequest } from '../../WebAuthnManager/SecureConfirmWorkerManager/confirmTxFlow/types';
import type { KeyRef, SignerEngine } from '../types';
import { base64UrlEncode } from '../../../../../shared/src/utils/base64';
import { bytesToHex } from '../evm/bytes';
import { TempoAdapter, type TempoSignedResult } from '../tempo/tempoAdapter';
import type { TempoSigningRequest } from '../tempo/types';
import { resolveWebAuthnP256KeyRefForNearAccount } from './webauthnKeyRef';
import { authorizeThresholdEcdsaWithSession } from '../../threshold/thresholdEcdsaAuthorize';
import { getCachedThresholdEcdsaAuthSessionJwt, makeThresholdEcdsaAuthSessionCacheKey } from '../../threshold/thresholdEcdsaAuthSession';

function makeRequestId(prefix: string): string {
  const c = (globalThis as any).crypto;
  if (c?.randomUUID && typeof c.randomUUID === 'function') return c.randomUUID();
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function inferDigest32FromSignRequest(req: { kind: string; digest32?: Uint8Array; challenge32?: Uint8Array }): Uint8Array {
  const bytes = req.kind === 'digest' ? req.digest32 : req.challenge32;
  if (!bytes || bytes.length !== 32) throw new Error('[multichain] expected 32-byte digest/challenge');
  return bytes;
}

export async function signTempoWithSecureConfirm(args: {
  ctx: SecureConfirmWorkerManagerContext;
  nearAccountId: string;
  request: TempoSigningRequest;
  engines: Record<string, SignerEngine>;
  keyRefsByAlgorithm?: Partial<Record<string, KeyRef>>;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
}): Promise<TempoSignedResult> {
  const adapter = new TempoAdapter();
  const intent = await adapter.buildIntent(args.request);

  const webauthnReqs = intent.signRequests.filter((r) => r.kind === 'webauthn');
  if (webauthnReqs.length > 1) {
    throw new Error('[multichain] multiple WebAuthn sign requests are not supported yet');
  }

  const firstDigest = inferDigest32FromSignRequest(intent.signRequests[0] as any);
  const challengeB64u = base64UrlEncode(firstDigest);
  const intentDigestHex = bytesToHex(firstDigest);
  const needsWebAuthn = webauthnReqs.length === 1;

  const requestId = makeRequestId('intent');
  const decision = await runSecureConfirm(args.ctx, {
    requestId,
    type: SecureConfirmationType.SIGN_INTENT_DIGEST,
    summary: {
      title: intent.chain === 'tempo'
        ? (args.request.kind === 'tempoTransaction' ? 'Sign TempoTransaction (0x76)' : 'Sign EIP-1559 (0x02)')
        : `Sign ${intent.chain} intent`,
      body: args.request.kind === 'tempoTransaction'
        ? 'Review and approve signing the Tempo sender hash.'
        : 'Review and approve signing the transaction hash.',
      intentDigest: intentDigestHex,
    },
    payload: {
      nearAccountId: args.nearAccountId,
      challengeB64u,
      signingAuthMode: needsWebAuthn ? 'webauthn' : 'warmSession',
    },
    intentDigest: intentDigestHex,
    confirmationConfig: args.confirmationConfigOverride,
  } satisfies SecureConfirmRequest);

  if (!decision?.confirmed) {
    throw new Error(decision?.error || '[multichain] user rejected signing request');
  }

  const signatures: Uint8Array[] = [];
  for (const signReq of intent.signRequests) {
    const engine = args.engines[signReq.algorithm];
    if (!engine) throw new Error(`[multichain] missing engine for algorithm: ${signReq.algorithm}`);

    const keyRef = (() => {
      if (signReq.algorithm === 'webauthn-p256') return undefined;
      return args.keyRefsByAlgorithm?.[signReq.algorithm];
    })();

    if (signReq.kind === 'webauthn') {
      if (!decision.credential) {
        throw new Error('[multichain] missing WebAuthn credential from SecureConfirm');
      }
      const webauthnKeyRef = await resolveWebAuthnP256KeyRefForNearAccount({
        indexedDB: args.ctx.indexedDB,
        nearAccountId: args.nearAccountId,
        rpId: signReq.rpId,
      });
      signatures.push(await engine.sign({ ...signReq, credential: decision.credential as any }, webauthnKeyRef));
      continue;
    }

    if (!keyRef) {
      throw new Error(`[multichain] missing keyRef for algorithm: ${signReq.algorithm}`);
    }

    if (signReq.kind === 'digest' && signReq.algorithm === 'secp256k1' && keyRef.type === 'threshold-ecdsa-secp256k1') {
      const rpId = args.ctx.touchIdPrompt.getRpId();
      if (!rpId) {
        throw new Error('[multichain] Missing rpId for threshold-ecdsa authorize');
      }

      const sessionKind: 'jwt' | 'cookie' = keyRef.thresholdSessionKind || 'jwt';
      const thresholdSessionJwt = sessionKind === 'jwt'
        ? (
            keyRef.thresholdSessionJwt ||
            getCachedThresholdEcdsaAuthSessionJwt(makeThresholdEcdsaAuthSessionCacheKey({
              userId: keyRef.userId,
              rpId,
              relayerUrl: keyRef.relayerUrl,
              relayerKeyId: keyRef.relayerKeyId,
              participantIds: keyRef.participantIds,
            }))
          )
        : undefined;

      if (sessionKind === 'jwt' && !thresholdSessionJwt) {
        throw new Error('[multichain] No cached threshold-ecdsa session token; call connectThresholdEcdsaSessionLite first');
      }

      const purpose = String(signReq.label || 'tempo:secp256k1');
      const authorized = await authorizeThresholdEcdsaWithSession({
        relayerUrl: keyRef.relayerUrl,
        relayerKeyId: keyRef.relayerKeyId,
        clientVerifyingShareB64u: keyRef.clientVerifyingShareB64u,
        purpose,
        signingDigest32: signReq.digest32,
        sessionKind,
        ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
      });
      if (!authorized.ok || !authorized.mpcSessionId) {
        throw new Error(authorized.message || authorized.code || '[multichain] threshold-ecdsa authorize failed');
      }
      keyRef.mpcSessionId = authorized.mpcSessionId;
    }
    signatures.push(await engine.sign(signReq, keyRef));
  }

  return await intent.finalize(signatures);
}
