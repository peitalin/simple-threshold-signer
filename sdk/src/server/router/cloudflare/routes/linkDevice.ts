import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { isObject, json, readJson } from '../http';

export async function handleLinkDevice(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (ctx.method === 'GET' && ctx.pathname.startsWith('/link-device/session/')) {
    const sessionId = ctx.pathname.slice('/link-device/session/'.length);
    const result = await ctx.service.getLinkDeviceSession({ sessionId });
    const status = result.ok ? 200 : (result.code === 'not_found' ? 404 : (result.code === 'internal' ? 500 : 400));
    return json(result, { status });
  }

  if (ctx.method === 'POST' && ctx.pathname === '/link-device/session/claim') {
    const body = await readJson(ctx.request);
    if (!isObject(body)) {
      return json({ ok: false, code: 'invalid_body', message: 'Expected JSON object body' }, { status: 400 });
    }
    const result = await ctx.service.claimLinkDeviceSession(body as any);
    const status = result.ok ? 200 : (result.code === 'not_found' ? 404 : (result.code === 'internal' ? 500 : 400));
    return json(result, { status });
  }

  if (ctx.method !== 'POST' || ctx.pathname !== '/link-device/prepare') return null;

  const body = await readJson(ctx.request);
  if (!isObject(body)) {
    return json({ ok: false, code: 'invalid_body', message: 'Expected JSON object body' }, { status: 400 });
  }

  const origin = String(ctx.request.headers.get('origin') || '').trim() || undefined;
  const result = await ctx.service.prepareLinkDevice({
    ...(body as any),
    ...(origin ? { expected_origin: origin } : {}),
  });
  return json(result, { status: result.ok ? 200 : (result.code === 'internal' ? 500 : 400) });
}
