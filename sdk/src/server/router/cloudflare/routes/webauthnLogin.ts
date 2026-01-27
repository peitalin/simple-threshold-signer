import { parseSessionKind } from '../../relay';
import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { isObject, json, readJson } from '../http';

export async function handleWebAuthnLogin(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (ctx.method !== 'POST') return null;

  if (ctx.pathname === '/login/options') {
    const body = await readJson(ctx.request);
    if (!isObject(body)) {
      return json({ ok: false, code: 'invalid_body', message: 'Expected JSON object body' }, { status: 400 });
    }
    const result = await ctx.service.createWebAuthnLoginOptions(body as any);
    return json(result, { status: result.ok ? 200 : (result.code === 'internal' ? 500 : 400) });
  }

  if (ctx.pathname === '/login/verify') {
    const body = await readJson(ctx.request);
    if (!isObject(body)) {
      return json({ ok: false, code: 'invalid_body', message: 'Expected JSON object body' }, { status: 400 });
    }
    const challengeId = String((body as any).challengeId ?? (body as any).challenge_id ?? '').trim();
    if (!challengeId) {
      return json({ ok: false, code: 'invalid_body', message: 'challengeId is required' }, { status: 400 });
    }
    if (!isObject((body as any).webauthn_authentication)) {
      return json({ ok: false, code: 'invalid_body', message: 'webauthn_authentication is required' }, { status: 400 });
    }

    const origin = String(ctx.request.headers.get('origin') || '').trim() || undefined;
    const result = await ctx.service.verifyWebAuthnLogin({
      challengeId,
      webauthn_authentication: (body as any).webauthn_authentication,
      expected_origin: origin,
    });
    if (!result.ok || !result.verified) {
      return json(result, { status: result.code === 'internal' ? 500 : 400 });
    }

    const res = json({ ok: true, verified: true }, { status: 200 });
    const session = ctx.opts.session;
    if (session && result.userId && result.rpId) {
      try {
        const sessionKind = parseSessionKind(body);
        const token = await session.signJwt(result.userId, { rpId: result.rpId });
        ctx.logger.info(`[relay] creating ${sessionKind === 'cookie' ? 'HttpOnly session' : 'JWT'} for`, result.userId);
        if (sessionKind === 'cookie') {
          res.headers.set('Set-Cookie', session.buildSetCookie(token));
        } else {
          const payload = await res.clone().json();
          return new Response(JSON.stringify({ ...payload, jwt: token }), { status: 200, headers: res.headers });
        }
      } catch { }
    }

    return res;
  }

  return null;
}

