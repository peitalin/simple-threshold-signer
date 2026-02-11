import type { CreateAccountAndRegisterRequest, CreateAccountAndRegisterResult } from '../../../core/types';
import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { isObject, json, readJson } from '../http';

export async function handleCreateAccountAndRegisterUser(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/create_account_and_register_user') return null;

  const body = await readJson(ctx.request);
  if (!isObject(body)) {
    return json({ code: 'invalid_body', message: 'JSON body required' }, { status: 400 });
  }

  const new_account_id = typeof body.new_account_id === 'string' ? body.new_account_id : '';
  const new_public_key = typeof body.new_public_key === 'string' ? String(body.new_public_key || '').trim() : '';
  const device_number = typeof (body as Record<string, unknown>).device_number === 'number'
    ? (body as Record<string, unknown>).device_number
    : Number((body as Record<string, unknown>).device_number);
  const threshold_ed25519 = isObject((body as Record<string, unknown>).threshold_ed25519)
    ? (body as Record<string, unknown>).threshold_ed25519
    : undefined;
  const rp_id = typeof (body as Record<string, unknown>).rp_id === 'string'
    ? String((body as Record<string, unknown>).rp_id || '').trim()
    : '';
  const webauthn_registration = isObject(body.webauthn_registration) ? body.webauthn_registration : null;
  const authenticator_options = isObject((body as Record<string, unknown>).authenticator_options)
    ? (body as Record<string, unknown>).authenticator_options
    : undefined;

  if (!new_account_id) {
    return json({ code: 'invalid_body', message: 'Missing or invalid new_account_id' }, { status: 400 });
  }
  if (!rp_id) {
    return json({ code: 'invalid_body', message: 'Missing or invalid rp_id' }, { status: 400 });
  }
  if (!webauthn_registration) {
    return json({ code: 'invalid_body', message: 'Missing or invalid webauthn_registration' }, { status: 400 });
  }

  const input = {
    new_account_id,
    ...(new_public_key ? { new_public_key } : {}),
    device_number,
    ...(threshold_ed25519 ? { threshold_ed25519 } : {}),
    rp_id,
    webauthn_registration,
    expected_origin: ctx.request.headers.get('origin') || ctx.request.headers.get('Origin') || undefined,
    authenticator_options,
  } as unknown as CreateAccountAndRegisterRequest;

  const result = await ctx.service.createAccountAndRegisterUser(input);
  const response: CreateAccountAndRegisterResult = result;
  return json(response, { status: response.success ? 200 : 400 });
}
