import type { ConfirmationConfig } from '../../../../types/signer-worker';
import type {
  SecureConfirmWorkerManager,
  SecureConfirmWorkerManagerContext,
} from '../../../secureConfirm/manager';
import type { KeyRef, SignRequest, SigningEngine } from '../../../orchestration/types';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../../orchestration/types';
import { base64UrlEncode } from '../../../../../../../shared/src/utils/base64';
import { bytesToHex } from '../../evm/bytes';
import type { WorkerOperationContext } from '../../../workers/operations/executeSignerWorkerOperation';
import { TempoAdapter, type TempoSignedResult } from '../tempoAdapter';
import type { TempoSigningRequest } from '../types';
import { resolveWebAuthnP256KeyRefForNearAccount } from '../../../orchestration/walletOrigin/webauthnKeyRef';
import { executeSigningIntent } from '../../../orchestration/executeSigningIntent';
import type { SigningAuthMode } from '../../../secureConfirm/confirmTxFlow/types';
import { normalizeAuthenticationCredential } from '../../../webauthn/credentials/helpers';

function makeRequestId(prefix: string): string {
  const c = globalThis.crypto;
  if (c?.randomUUID && typeof c.randomUUID === 'function') return c.randomUUID();
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function inferDigest32FromSignRequest(req: SignRequest): Uint8Array {
  return req.kind === 'digest' ? req.digest32 : req.challenge32;
}

function asThresholdEcdsaKeyRef(value: KeyRef | undefined): ThresholdEcdsaSecp256k1KeyRef | null {
  if (!value || typeof value !== 'object') return null;
  return value.type === 'threshold-ecdsa-secp256k1'
    ? (value as ThresholdEcdsaSecp256k1KeyRef)
    : null;
}

async function resolveSigningAuthMode(args: {
  needsWebAuthn: boolean;
  thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef | null;
  secureConfirmWorkerManager: Pick<SecureConfirmWorkerManager, 'peekPrfFirstForThresholdSession'>;
}): Promise<SigningAuthMode> {
  if (args.needsWebAuthn) return 'webauthn';

  const thresholdSessionId = String(args.thresholdEcdsaKeyRef?.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return 'warmSession';

  const peek = await args.secureConfirmWorkerManager.peekPrfFirstForThresholdSession({
    sessionId: thresholdSessionId,
  });
  if (!peek.ok || peek.remainingUses < 1) {
    throw new Error(
      '[chains] threshold session expired; reconnect via connectThresholdEcdsaSessionLite',
    );
  }
  return 'warmSession';
}

export async function signTempoWithSecureConfirm(args: {
  ctx: SecureConfirmWorkerManagerContext;
  secureConfirmWorkerManager: Pick<
    SecureConfirmWorkerManager,
    'confirmAndPrepareSigningSession' | 'peekPrfFirstForThresholdSession'
  >;
  nearAccountId: string;
  request: TempoSigningRequest;
  engines: Record<string, SigningEngine>;
  keyRefsByAlgorithm?: Partial<Record<SignRequest['algorithm'], KeyRef>>;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  workerCtx: WorkerOperationContext;
}): Promise<TempoSignedResult> {
  const adapter = new TempoAdapter(args.workerCtx);
  const intent = await adapter.buildIntent(args.request);

  const webauthnReqs = intent.signRequests.filter((r) => r.kind === 'webauthn');
  if (webauthnReqs.length > 1) {
    throw new Error('[chains] multiple WebAuthn sign requests are not supported yet');
  }

  const firstSignRequest = intent.signRequests[0];
  if (!firstSignRequest) {
    throw new Error('[chains] signing intent has no sign requests');
  }
  const firstDigest = inferDigest32FromSignRequest(firstSignRequest);
  const challengeB64u = base64UrlEncode(firstDigest);
  const intentDigestHex = bytesToHex(firstDigest);
  const needsWebAuthn = webauthnReqs.length === 1;
  const thresholdEcdsaKeyRef = asThresholdEcdsaKeyRef(args.keyRefsByAlgorithm?.secp256k1);
  const signingAuthMode = await resolveSigningAuthMode({
    needsWebAuthn,
    thresholdEcdsaKeyRef,
    secureConfirmWorkerManager: args.secureConfirmWorkerManager,
  });

  const sessionId = makeRequestId('intent');
  const confirmation = await args.secureConfirmWorkerManager.confirmAndPrepareSigningSession({
    ctx: args.ctx,
    sessionId,
    kind: 'intentDigest',
    nearAccountId: args.nearAccountId,
    challengeB64u,
    intentDigest: intentDigestHex,
    title:
      intent.chain === 'tempo'
        ? args.request.kind === 'tempoTransaction'
          ? 'Sign TempoTransaction (0x76)'
          : 'Sign EIP-1559 (0x02)'
        : `Sign ${intent.chain} intent`,
    body:
      args.request.kind === 'tempoTransaction'
        ? 'Review and approve signing the Tempo sender hash.'
        : 'Review and approve signing the transaction hash.',
    signingAuthMode,
    confirmationConfigOverride: args.confirmationConfigOverride,
  });

  return await executeSigningIntent({
    intent,
    engines: args.engines,
    resolveSignInput: async (signReq: SignRequest) => {
      if (signReq.kind === 'webauthn') {
        if (!confirmation.credential) {
          throw new Error('[chains] missing WebAuthn credential from SecureConfirm');
        }
        const credential = normalizeAuthenticationCredential(confirmation.credential);
        const webauthnKeyRef = await resolveWebAuthnP256KeyRefForNearAccount({
          indexedDB: args.ctx.indexedDB,
          nearAccountId: args.nearAccountId,
          rpId: signReq.rpId,
        });
        return {
          signReq: { ...signReq, credential },
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
