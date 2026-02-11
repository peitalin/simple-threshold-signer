import type { ConfirmationConfig } from '../../../../types/signer-worker';
import type { SecureConfirmWorkerManagerContext } from '../../../secureConfirm/manager';
import { runSecureConfirm } from '../../../secureConfirm/flow/bridge';
import {
  SecureConfirmationType,
  type SecureConfirmRequest,
} from '../../../secureConfirm/flow/types';
import type { KeyRef, SignRequest, SigningEngine } from '../../../orchestration/types';
import { base64UrlEncode } from '../../../../../../../shared/src/utils/base64';
import { bytesToHex } from '../../evm/bytes';
import { TempoAdapter, type TempoSignedResult } from '../tempoAdapter';
import type { TempoSigningRequest } from '../types';
import { resolveWebAuthnP256KeyRefForNearAccount } from '../../../orchestration/walletOrigin/webauthnKeyRef';
import { executeSigningIntent } from '../../../orchestration/executeSigningIntent';

function makeRequestId(prefix: string): string {
  const c = (globalThis as any).crypto;
  if (c?.randomUUID && typeof c.randomUUID === 'function') return c.randomUUID();
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function inferDigest32FromSignRequest(req: { kind: string; digest32?: Uint8Array; challenge32?: Uint8Array }): Uint8Array {
  const bytes = req.kind === 'digest' ? req.digest32 : req.challenge32;
  if (!bytes || bytes.length !== 32) throw new Error('[chains] expected 32-byte digest/challenge');
  return bytes;
}

export async function signTempoWithSecureConfirm(args: {
  ctx: SecureConfirmWorkerManagerContext;
  nearAccountId: string;
  request: TempoSigningRequest;
  engines: Record<string, SigningEngine>;
  keyRefsByAlgorithm?: Partial<Record<string, KeyRef>>;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  dispenseThresholdEcdsaPrfFirstForSession?: (args: {
    sessionId: string;
    uses?: number;
  }) => Promise<
    | { ok: true; prfFirstB64u: string; remainingUses: number; expiresAtMs: number }
    | { ok: false; code: string; message: string }
  >;
}): Promise<TempoSignedResult> {
  const adapter = new TempoAdapter();
  const intent = await adapter.buildIntent(args.request);

  const webauthnReqs = intent.signRequests.filter((r) => r.kind === 'webauthn');
  if (webauthnReqs.length > 1) {
    throw new Error('[chains] multiple WebAuthn sign requests are not supported yet');
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
    throw new Error(decision?.error || '[chains] user rejected signing request');
  }

  return await executeSigningIntent({
    intent,
    engines: args.engines,
    resolveSignInput: async (signReq: SignRequest) => {
      if (signReq.kind === 'webauthn') {
        if (!decision.credential) {
          throw new Error('[chains] missing WebAuthn credential from SecureConfirm');
        }
        const webauthnKeyRef = await resolveWebAuthnP256KeyRefForNearAccount({
          indexedDB: args.ctx.indexedDB,
          nearAccountId: args.nearAccountId,
          rpId: signReq.rpId,
        });
        return {
          signReq: { ...signReq, credential: decision.credential as any },
          keyRef: webauthnKeyRef,
        };
      }

      const keyRef = args.keyRefsByAlgorithm?.[signReq.algorithm];
      if (!keyRef) {
        throw new Error(`[chains] missing keyRef for algorithm: ${signReq.algorithm}`);
      }
      return { signReq, keyRef };
    },
  });
}
