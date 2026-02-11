import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { isObject, json, readJson } from '../http';

export async function handleEmailRecoveryPrepare(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/email-recovery/prepare') return null;

  const body = await readJson(ctx.request);
  if (!isObject(body)) {
    return json({ ok: false, code: 'invalid_body', message: 'Expected JSON object body' }, { status: 400 });
  }

  const origin = String(ctx.request.headers.get('origin') || '').trim() || undefined;
  const result = await ctx.service.prepareEmailRecovery({
    ...(body as any),
    ...(origin ? { expected_origin: origin } : {}),
  });
  return json(result, { status: result.ok ? 200 : (result.code === 'internal' ? 500 : 400) });
}

