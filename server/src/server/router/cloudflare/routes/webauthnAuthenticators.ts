import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { json } from '../http';

export async function handleWebAuthnAuthenticators(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (ctx.method !== 'GET') return null;
  if (ctx.pathname !== '/webauthn/authenticators') return null;

  try {
    const session = ctx.opts.session;
    if (!session) {
      return json({ ok: false, code: 'sessions_disabled', message: 'Sessions are not configured' }, { status: 501 });
    }

    const headersObj: Record<string, string | string[] | undefined> = {};
    try {
      ctx.request.headers.forEach((v, k) => { headersObj[k] = v; });
    } catch {}

    const parsed = await session.parse(headersObj as any);
    if (!parsed.ok) {
      return json({ ok: false, code: 'unauthorized', message: 'No valid session' }, { status: 401 });
    }

    const claims: any = (parsed as any).claims || {};
    const kindRaw = (claims as any).kind;
    const kind = typeof kindRaw === 'string' ? kindRaw.trim() : '';
    if (kind !== 'app_session_v1') {
      return json({ ok: false, code: 'unauthorized', message: 'No valid app session' }, { status: 401 });
    }
    const userId = String(claims.sub || '').trim();
    const appSessionVersion = typeof claims.appSessionVersion === 'string' ? claims.appSessionVersion.trim() : '';
    if (!userId || !appSessionVersion) {
      return json({ ok: false, code: 'unauthorized', message: 'Invalid app session' }, { status: 401 });
    }
    const validated = await ctx.service.validateAppSessionVersion({ userId, appSessionVersion });
    if (!validated.ok) {
      return json({ ok: false, code: validated.code, message: validated.message }, { status: validated.code === 'internal' ? 500 : 401 });
    }

    const rpIdFromQuery = String(ctx.url.searchParams.get('rpId') || ctx.url.searchParams.get('rp_id') || '').trim();
    const rpId = rpIdFromQuery || String(claims.rpId || '').trim();

    const result = await ctx.service.listWebAuthnAuthenticatorsForUser({ userId, ...(rpId ? { rpId } : {}) });
    if (!result.ok) {
      const status = result.code === 'not_supported' ? 501 : (result.code === 'invalid_args' ? 400 : 500);
      return json(result, { status });
    }

    return json(result, { status: 200 });
  } catch (e: any) {
    return json({ ok: false, code: 'internal', message: e?.message || 'Internal error' }, { status: 500 });
  }
}
