import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { json, readJson } from '../http';
import { thresholdEd25519StatusCode } from '../../../threshold/statusCodes';
import type {
  ThresholdEd25519AuthorizeResponse,
  ThresholdEd25519CosignFinalizeRequest,
  ThresholdEd25519CosignInitRequest,
  ThresholdEd25519KeygenRequest,
  ThresholdEd25519SignFinalizeRequest,
  ThresholdEd25519SignInitRequest,
  ThresholdEd25519SessionRequest,
} from '../../../core/types';
import { parseSessionKind, resolveThresholdScheme } from '../../relay';
import {
  validateThresholdEd25519AuthorizeInputs,
} from '../../commonRouterUtils';
import {
  normalizeThresholdEd25519ParticipantIds,
  THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
} from '@shared/threshold/participants';
import { THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID } from '../../../core/ThresholdService/schemes/schemeIds';

export async function handleThresholdEd25519(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (ctx.method === 'GET' && ctx.pathname === '/threshold-ed25519/healthz') {
    const resolved = resolveThresholdScheme(ctx.opts.threshold, THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID, {
      notFoundMessage: 'threshold-ed25519 scheme is not enabled on this server',
    });
    if (!resolved.ok) {
      const body = { ...resolved, configured: false };
      return json(body, { status: thresholdEd25519StatusCode(body) });
    }
    return json({ ok: true, configured: true }, { status: 200 });
  }

  if (ctx.method !== 'POST') return null;

  const pathname = ctx.pathname;
  if (
    pathname !== '/threshold-ed25519/keygen'
    && pathname !== '/threshold-ed25519/session'
    && pathname !== '/threshold-ed25519/authorize'
    && pathname !== '/threshold-ed25519/sign/init'
    && pathname !== '/threshold-ed25519/sign/finalize'
    && pathname !== '/threshold-ed25519/internal/cosign/init'
    && pathname !== '/threshold-ed25519/internal/cosign/finalize'
  ) {
    return null;
  }

  const body = await readJson(ctx.request);
  const resolved = resolveThresholdScheme(ctx.opts.threshold, THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID, {
    notFoundMessage: 'threshold-ed25519 scheme is not enabled on this server',
  });
  if (!resolved.ok) {
    return json(resolved, { status: thresholdEd25519StatusCode(resolved) });
  }
  const ed25519 = resolved.scheme;

  switch (pathname) {
    case '/threshold-ed25519/keygen': {
      const b = (body || {}) as ThresholdEd25519KeygenRequest;
      ctx.logger.info('[threshold-ed25519] request', {
        route: pathname,
        method: ctx.method,
        nearAccountId: typeof b.nearAccountId === 'string' ? b.nearAccountId : undefined,
        clientVerifyingShareB64u_len: typeof b.clientVerifyingShareB64u === 'string' ? b.clientVerifyingShareB64u.length : undefined,
      });
      const result = await ed25519.keygen(b);
      ctx.logger.info('[threshold-ed25519] response', {
        route: pathname,
        status: thresholdEd25519StatusCode(result),
        ok: result.ok,
        ...(result.code ? { code: result.code } : {}),
      });
      return json(result, { status: thresholdEd25519StatusCode(result) });
    }
    case '/threshold-ed25519/session': {
      const session = ctx.opts.session;
      if (!session) {
        ctx.logger.warn('[threshold-ed25519] request', { route: pathname, method: ctx.method, sessions: false });
        return json({ ok: false, code: 'sessions_disabled', message: 'Sessions are not configured on this server' }, { status: 501 });
      }

      const b = (body || {}) as ThresholdEd25519SessionRequest;
      ctx.logger.info('[threshold-ed25519] request', {
        route: pathname,
        method: ctx.method,
        relayerKeyId: typeof b.relayerKeyId === 'string' ? b.relayerKeyId : undefined,
        clientVerifyingShareB64u_len: typeof b.clientVerifyingShareB64u === 'string' ? b.clientVerifyingShareB64u.length : undefined,
        sessionPolicy: b.sessionPolicy ? { version: b.sessionPolicy.version } : undefined,
      });

      const result = await ed25519.session(b);
      const status = thresholdEd25519StatusCode(result);
      ctx.logger.info('[threshold-ed25519] response', { route: pathname, status, ok: result.ok, ...(result.code ? { code: result.code } : {}) });
      if (!result.ok) return json(result, { status });

      const sessionId = String(result.sessionId || '').trim();
      if (!sessionId) {
        return json({ ok: false, code: 'internal', message: 'threshold session missing sessionId' }, { status: 500 });
      }
      const userId = String(b.sessionPolicy?.nearAccountId || '').trim();
      const rpId = String(b.sessionPolicy?.rpId || '').trim();
      const relayerKeyId = String(b.relayerKeyId || '').trim();
      const thresholdExpiresAtMs = (() => {
        const ms = typeof (result as any).expiresAtMs === 'number'
          ? (result as any).expiresAtMs
          : (result.expiresAt ? Date.parse(result.expiresAt) : NaN);
        return Number.isFinite(ms) && ms > 0 ? ms : undefined;
      })();
      if (!userId) {
        return json({ ok: false, code: 'internal', message: 'threshold session missing sessionPolicy.nearAccountId' }, { status: 500 });
      }
      if (!rpId) {
        return json({ ok: false, code: 'internal', message: 'threshold session missing sessionPolicy.rpId' }, { status: 500 });
      }
      if (!relayerKeyId) {
        return json({ ok: false, code: 'internal', message: 'threshold session missing relayerKeyId' }, { status: 500 });
      }
      if (thresholdExpiresAtMs === undefined) {
        return json({ ok: false, code: 'internal', message: 'threshold session missing expiresAtMs' }, { status: 500 });
      }
      const exp = thresholdExpiresAtMs ? Math.floor(thresholdExpiresAtMs / 1000) : undefined;
      const iat = Math.floor(Date.now() / 1000);
      const participantIds =
        normalizeThresholdEd25519ParticipantIds(b.sessionPolicy?.participantIds)
        || [...THRESHOLD_ED25519_2P_PARTICIPANT_IDS];
      const token = await session.signJwt(userId, {
        kind: 'threshold_ed25519_session_v1',
        sessionId,
        relayerKeyId,
        rpId,
        ...(thresholdExpiresAtMs !== undefined ? { thresholdExpiresAtMs } : {}),
        ...(exp !== undefined ? { exp } : {}),
        iat,
        participantIds,
      });
      const sessionKind = parseSessionKind(b);

      const res = json(sessionKind === 'cookie' ? { ...result, jwt: undefined } : { ...result, jwt: token }, { status: 200 });
      if (sessionKind === 'cookie') {
        res.headers.set('Set-Cookie', session.buildSetCookie(token));
      }
      return res;
    }
    case '/threshold-ed25519/authorize': {
      const b = (body || {}) as Record<string, unknown>;
      ctx.logger.info('[threshold-ed25519] request', {
        route: pathname,
        method: ctx.method,
        relayerKeyId: typeof b.relayerKeyId === 'string' ? b.relayerKeyId : undefined,
        clientVerifyingShareB64u_len: typeof b.clientVerifyingShareB64u === 'string' ? b.clientVerifyingShareB64u.length : undefined,
        purpose: typeof b.purpose === 'string' ? b.purpose : undefined,
        signing_digest_32_len: Array.isArray(b.signing_digest_32) ? b.signing_digest_32.length : undefined,
      });

      const respond = (result: ThresholdEd25519AuthorizeResponse): Response => {
        ctx.logger.info('[threshold-ed25519] response', {
          route: pathname,
          status: thresholdEd25519StatusCode(result),
          ok: result.ok,
          ...(result.code ? { code: result.code } : {}),
        });
        return json(result, { status: thresholdEd25519StatusCode(result) });
      };

      const validated = await validateThresholdEd25519AuthorizeInputs({
        body,
        headers: Object.fromEntries(ctx.request.headers.entries()),
        session: ctx.opts.session,
      });
      if (!validated.ok) return respond(validated);

      const result = await ed25519.authorize({ claims: validated.claims, request: validated.request });
      return respond(result);

    }
    case '/threshold-ed25519/sign/init': {
      const b = (body || {}) as ThresholdEd25519SignInitRequest;
      ctx.logger.info('[threshold-ed25519] request', {
        route: pathname,
        method: ctx.method,
        mpcSessionId: typeof b.mpcSessionId === 'string' ? b.mpcSessionId : undefined,
        relayerKeyId: typeof b.relayerKeyId === 'string' ? b.relayerKeyId : undefined,
        nearAccountId: typeof b.nearAccountId === 'string' ? b.nearAccountId : undefined,
        signingDigestB64u_len: typeof b.signingDigestB64u === 'string' ? b.signingDigestB64u.length : undefined,
      });
      const result = await ed25519.protocol.signInit(b);
      ctx.logger.info('[threshold-ed25519] response', {
        route: pathname,
        status: thresholdEd25519StatusCode(result),
        ok: result.ok,
        ...(result.code ? { code: result.code } : {}),
      });
      return json(result, { status: thresholdEd25519StatusCode(result) });
    }
    case '/threshold-ed25519/sign/finalize': {
      const b = (body || {}) as ThresholdEd25519SignFinalizeRequest;
      ctx.logger.info('[threshold-ed25519] request', {
        route: pathname,
        method: ctx.method,
        signingSessionId: typeof b.signingSessionId === 'string' ? b.signingSessionId : undefined,
        clientSignatureShareB64u_len: typeof b.clientSignatureShareB64u === 'string' ? b.clientSignatureShareB64u.length : undefined,
      });
      const result = await ed25519.protocol.signFinalize(b);
      ctx.logger.info('[threshold-ed25519] response', {
        route: pathname,
        status: thresholdEd25519StatusCode(result),
        ok: result.ok,
        ...(result.code ? { code: result.code } : {}),
      });
      return json(result, { status: thresholdEd25519StatusCode(result) });
    }
    case '/threshold-ed25519/internal/cosign/init': {
      const cosignInit = ed25519.protocol.internalCosignInit;
      if (!cosignInit) {
        const result = { ok: false, code: 'not_found', message: 'threshold-ed25519 cosigner endpoints are not enabled on this server' };
        return json(result, { status: thresholdEd25519StatusCode(result) });
      }
      const b = (body || {}) as ThresholdEd25519CosignInitRequest;
      ctx.logger.info('[threshold-ed25519] request', {
        route: pathname,
        method: ctx.method,
        coordinatorGrant_len: typeof b.coordinatorGrant === 'string' ? b.coordinatorGrant.length : undefined,
        signingSessionId: typeof b.signingSessionId === 'string' ? b.signingSessionId : undefined,
        cosignerShareB64u_len: typeof b.cosignerShareB64u === 'string' ? b.cosignerShareB64u.length : undefined,
      });
      const result = await cosignInit(b);
      ctx.logger.info('[threshold-ed25519] response', {
        route: pathname,
        status: thresholdEd25519StatusCode(result),
        ok: result.ok,
        ...(result.code ? { code: result.code } : {}),
      });
      return json(result, { status: thresholdEd25519StatusCode(result) });
    }
    case '/threshold-ed25519/internal/cosign/finalize': {
      const cosignFinalize = ed25519.protocol.internalCosignFinalize;
      if (!cosignFinalize) {
        const result = { ok: false, code: 'not_found', message: 'threshold-ed25519 cosigner endpoints are not enabled on this server' };
        return json(result, { status: thresholdEd25519StatusCode(result) });
      }
      const b = (body || {}) as ThresholdEd25519CosignFinalizeRequest;
      ctx.logger.info('[threshold-ed25519] request', {
        route: pathname,
        method: ctx.method,
        coordinatorGrant_len: typeof b.coordinatorGrant === 'string' ? b.coordinatorGrant.length : undefined,
        signingSessionId: typeof b.signingSessionId === 'string' ? b.signingSessionId : undefined,
        cosignerIds_len: Array.isArray(b.cosignerIds) ? b.cosignerIds.length : undefined,
      });
      const result = await cosignFinalize(b);
      ctx.logger.info('[threshold-ed25519] response', {
        route: pathname,
        status: thresholdEd25519StatusCode(result),
        ok: result.ok,
        ...(result.code ? { code: result.code } : {}),
      });
      return json(result, { status: thresholdEd25519StatusCode(result) });
    }
    default:
      return null;
  }
}
