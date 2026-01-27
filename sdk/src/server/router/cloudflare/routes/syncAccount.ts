import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { isObject, json, readJson } from '../http';

export async function handleSyncAccount(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (ctx.method !== 'POST') return null;

  if (ctx.pathname === '/sync-account/options') {
    const body = await readJson(ctx.request);
    if (!isObject(body)) {
      return json({ ok: false, code: 'invalid_body', message: 'Expected JSON object body' }, { status: 400 });
    }
    const result = await ctx.service.createWebAuthnSyncAccountOptions(body as any);
    return json(result, { status: result.ok ? 200 : (result.code === 'internal' ? 500 : 400) });
  }

  if (ctx.pathname === '/sync-account/verify') {
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
    const result = await ctx.service.verifyWebAuthnSyncAccount({
      challengeId,
      webauthn_authentication: (body as any).webauthn_authentication,
      expected_origin: origin,
    });
    return json(result, { status: result.ok && result.verified ? 200 : (result.code === 'internal' ? 500 : 400) });
  }

  return null;
}

