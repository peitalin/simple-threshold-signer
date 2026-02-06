import type { Request, Response, Router as ExpressRouter } from 'express';
import type { ExpressRelayContext } from '../createRelayRouter';
import type {
  ThresholdEd25519CosignFinalizeRequest,
  ThresholdEd25519CosignInitRequest,
  ThresholdEd25519KeygenRequest,
  ThresholdEd25519SignFinalizeRequest,
  ThresholdEd25519SignInitRequest,
  ThresholdEd25519SessionRequest,
} from '../../../core/types';
import { thresholdEd25519StatusCode } from '../../../threshold/statusCodes';
import { parseSessionKind, resolveThresholdScheme } from '../../relay';
import {
  validateThresholdEd25519AuthorizeInputs,
} from '../../commonRouterUtils';
import { THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID } from '../../../core/ThresholdService/schemes/schemeIds';

function errMessage(e: unknown): string {
  if (e && typeof e === 'object' && 'message' in e) return String((e as { message?: unknown }).message || 'Internal error');
  return String(e || 'Internal error');
}

async function handle<T extends { ok: boolean; code?: string; message?: string }>(
  ctx: ExpressRelayContext,
  req: Request,
  res: Response,
  route: string,
  requestMeta: Record<string, unknown>,
  fn: () => Promise<T>
): Promise<void> {
  try {
    ctx.logger.info('[threshold-ed25519] request', {
      route,
      method: req.method,
      ...(requestMeta || {}),
    });
    const result = await fn();
    const status = thresholdEd25519StatusCode(result);
    ctx.logger.info('[threshold-ed25519] response', {
      route,
      status,
      ok: result.ok,
      ...(result.code ? { code: result.code } : {}),
      ...(!result.ok && result.message ? { message: result.message } : {}),
    });
    res.status(status).json(result);
  } catch (e: unknown) {
    ctx.logger.error('[threshold-ed25519] error', {
      route,
      message: errMessage(e),
      ...(requestMeta || {}),
    });
    res.status(500).json({ ok: false, code: 'internal', message: errMessage(e) });
  }
}

export function registerThresholdEd25519Routes(router: ExpressRouter, ctx: ExpressRelayContext): void {
  ctx.logger.info('[threshold-ed25519] routes', {
    enabled: Boolean(ctx.opts.threshold),
  });

  // Threshold Ed25519 (2-party) routes (scaffolding).
  // These routes establish the relayer as a co-signer and will eventually run a 2-round FROST flow.
  router.get('/threshold-ed25519/healthz', async (req: Request, res: Response) => {
    await handle(ctx, req, res, '/threshold-ed25519/healthz', {}, async () => {
      const resolved = resolveThresholdScheme(ctx.opts.threshold, THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID, {
        notFoundMessage: 'threshold-ed25519 scheme is not enabled on this server',
      });
      if (!resolved.ok) {
        return { ...resolved, configured: false };
      }
      return { ok: true, configured: true };
    });
  });

  router.post('/threshold-ed25519/keygen', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEd25519KeygenRequest;
    await handle(ctx, req, res, '/threshold-ed25519/keygen', {
      nearAccountId: typeof body.nearAccountId === 'string' ? body.nearAccountId : undefined,
      clientVerifyingShareB64u_len: typeof body.clientVerifyingShareB64u === 'string' ? body.clientVerifyingShareB64u.length : undefined,
      rpId: (body as unknown as { rpId?: unknown }).rpId,
      keygenSessionId: (body as unknown as { keygenSessionId?: unknown }).keygenSessionId,
    }, async () => {
      const resolved = resolveThresholdScheme(ctx.opts.threshold, THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID, {
        notFoundMessage: 'threshold-ed25519 scheme is not enabled on this server',
      });
      if (!resolved.ok) return resolved;
      return resolved.scheme.keygen(body);
    });
  });

  router.post('/threshold-ed25519/session', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEd25519SessionRequest;
    await handle(ctx, req, res, '/threshold-ed25519/session', {
      relayerKeyId: typeof body.relayerKeyId === 'string' ? body.relayerKeyId : undefined,
      clientVerifyingShareB64u_len: typeof body.clientVerifyingShareB64u === 'string' ? body.clientVerifyingShareB64u.length : undefined,
      sessionPolicy: body.sessionPolicy ? { version: body.sessionPolicy.version } : undefined,
    }, async () => {
      const resolved = resolveThresholdScheme(ctx.opts.threshold, THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID, {
        notFoundMessage: 'threshold-ed25519 scheme is not enabled on this server',
      });
      if (!resolved.ok) return resolved;

      const session = ctx.opts.session;
      if (!session) {
        return { ok: false, code: 'sessions_disabled', message: 'Sessions are not configured on this server' };
      }

      const result = await resolved.scheme.session(body);
      if (!result.ok) return result;

      const sessionId = String(result.sessionId || '').trim();
      if (!sessionId) {
        return { ok: false, code: 'internal', message: 'threshold session missing sessionId' };
      }

	      const userId = String((body as any).sessionPolicy?.nearAccountId || '').trim();
	      if (!userId) {
	        return { ok: false, code: 'internal', message: 'threshold session missing sessionPolicy.nearAccountId' };
	      }
	      const rpId = String((body as any).sessionPolicy?.rpId || '').trim();
	      if (!rpId) {
	        return { ok: false, code: 'internal', message: 'threshold session missing sessionPolicy.rpId' };
	      }
	      const relayerKeyId = String((body as any).relayerKeyId || '').trim();
	      if (!relayerKeyId) {
	        return { ok: false, code: 'internal', message: 'threshold session missing relayerKeyId' };
	      }
	      const thresholdExpiresAtMs = Number(result.expiresAtMs);
	      if (!Number.isFinite(thresholdExpiresAtMs) || thresholdExpiresAtMs <= 0) {
	        return { ok: false, code: 'internal', message: 'threshold session missing expiresAtMs' };
	      }
	      const participantIds = Array.isArray(result.participantIds) ? result.participantIds : null;
	      if (!participantIds || participantIds.length < 2) {
	        return { ok: false, code: 'internal', message: 'threshold session missing participantIds' };
	      }
	      const nowSec = Math.floor(Date.now() / 1000);
	      const expSec = Math.floor(thresholdExpiresAtMs / 1000);
	      const token = await session.signJwt(userId, {
	        kind: 'threshold_ed25519_session_v1',
	        sessionId,
	        relayerKeyId,
	        rpId,
	        participantIds,
	        thresholdExpiresAtMs,
	        iat: nowSec,
	        exp: expSec,
	      });

      const sessionKind = parseSessionKind(body);
      if (sessionKind === 'cookie') {
        res.set('Set-Cookie', session.buildSetCookie(token));
        const { jwt: _omit, ...rest } = result;
        return { ...rest, ok: true };
      }

      return { ...result, jwt: token };
    });
  });

  router.post('/threshold-ed25519/authorize', async (req: Request, res: Response) => {
    const bodyUnknown = (req.body || {}) as unknown;
    const body = (bodyUnknown || {}) as Record<string, unknown>;
    await handle(ctx, req, res, '/threshold-ed25519/authorize', {
      relayerKeyId: typeof body.relayerKeyId === 'string' ? body.relayerKeyId : undefined,
      clientVerifyingShareB64u_len: typeof body.clientVerifyingShareB64u === 'string' ? body.clientVerifyingShareB64u.length : undefined,
      purpose: typeof body.purpose === 'string' ? body.purpose : undefined,
      signing_digest_32_len: Array.isArray(body.signing_digest_32) ? body.signing_digest_32.length : undefined,
    }, async () => {
      const threshold = ctx.opts.threshold;
      if (!threshold) {
        return { ok: false, code: 'threshold_disabled', message: 'Threshold signing is not configured on this server' };
      }

      const validated = await validateThresholdEd25519AuthorizeInputs({
        body: bodyUnknown,
        headers: req.headers || {},
        session: ctx.opts.session,
      });
      if (!validated.ok) return validated;

      const resolved = resolveThresholdScheme(ctx.opts.threshold, THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID, {
        notFoundMessage: 'threshold-ed25519 scheme is not enabled on this server',
      });
      if (!resolved.ok) return resolved;

      return resolved.scheme.authorize({ claims: validated.claims, request: validated.request });
		    });
		  });

  router.post('/threshold-ed25519/sign/init', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEd25519SignInitRequest;
    await handle(ctx, req, res, '/threshold-ed25519/sign/init', {
      mpcSessionId: typeof body.mpcSessionId === 'string' ? body.mpcSessionId : undefined,
      relayerKeyId: typeof body.relayerKeyId === 'string' ? body.relayerKeyId : undefined,
      nearAccountId: typeof body.nearAccountId === 'string' ? body.nearAccountId : undefined,
      signingDigestB64u_len: typeof body.signingDigestB64u === 'string' ? body.signingDigestB64u.length : undefined,
    }, async () => {
      const resolved = resolveThresholdScheme(ctx.opts.threshold, THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID, {
        notFoundMessage: 'threshold-ed25519 scheme is not enabled on this server',
      });
      if (!resolved.ok) return resolved;
      return resolved.scheme.protocol.signInit(body);
    });
  });

  router.post('/threshold-ed25519/sign/finalize', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEd25519SignFinalizeRequest;
    await handle(ctx, req, res, '/threshold-ed25519/sign/finalize', {
      signingSessionId: typeof body.signingSessionId === 'string' ? body.signingSessionId : undefined,
      clientSignatureShareB64u_len: typeof body.clientSignatureShareB64u === 'string' ? body.clientSignatureShareB64u.length : undefined,
    }, async () => {
      const resolved = resolveThresholdScheme(ctx.opts.threshold, THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID, {
        notFoundMessage: 'threshold-ed25519 scheme is not enabled on this server',
      });
      if (!resolved.ok) return resolved;
      return resolved.scheme.protocol.signFinalize(body);
    });
  });

  // Internal coordinator → cosigner route (feature-gated by shared secret).
  router.post('/threshold-ed25519/internal/cosign/init', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEd25519CosignInitRequest;
    await handle(ctx, req, res, '/threshold-ed25519/internal/cosign/init', {
      coordinatorGrant_len: typeof body.coordinatorGrant === 'string' ? body.coordinatorGrant.length : undefined,
      signingSessionId: typeof body.signingSessionId === 'string' ? body.signingSessionId : undefined,
      cosignerShareB64u_len: typeof body.cosignerShareB64u === 'string' ? body.cosignerShareB64u.length : undefined,
    }, async () => {
      const resolved = resolveThresholdScheme(ctx.opts.threshold, THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID, {
        notFoundMessage: 'threshold-ed25519 scheme is not enabled on this server',
      });
      if (!resolved.ok) return resolved;

      const cosignInit = resolved.scheme.protocol.internalCosignInit;
      if (!cosignInit) {
        return { ok: false, code: 'not_found', message: 'threshold-ed25519 cosigner endpoints are not enabled on this server' };
      }
      return cosignInit(body);
    });
  });

  router.post('/threshold-ed25519/internal/cosign/finalize', async (req: Request, res: Response) => {
    const body = (req.body || {}) as ThresholdEd25519CosignFinalizeRequest;
    await handle(ctx, req, res, '/threshold-ed25519/internal/cosign/finalize', {
      coordinatorGrant_len: typeof body.coordinatorGrant === 'string' ? body.coordinatorGrant.length : undefined,
      signingSessionId: typeof body.signingSessionId === 'string' ? body.signingSessionId : undefined,
      cosignerIds_len: Array.isArray(body.cosignerIds) ? body.cosignerIds.length : undefined,
    }, async () => {
      const resolved = resolveThresholdScheme(ctx.opts.threshold, THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID, {
        notFoundMessage: 'threshold-ed25519 scheme is not enabled on this server',
      });
      if (!resolved.ok) return resolved;

      const cosignFinalize = resolved.scheme.protocol.internalCosignFinalize;
      if (!cosignFinalize) {
        return { ok: false, code: 'not_found', message: 'threshold-ed25519 cosigner endpoints are not enabled on this server' };
      }
      return cosignFinalize(body);
    });
  });
}
