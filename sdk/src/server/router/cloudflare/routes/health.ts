import { buildCorsOrigins } from '../../../core/SessionService';
import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { json } from '../http';

export async function handleHealth(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (!ctx.opts.healthz || ctx.method !== 'GET' || ctx.pathname !== '/healthz') return null;

  // Surface simple CORS info for diagnostics (normalized)
  const allowed = buildCorsOrigins(...(ctx.opts.corsOrigins || []));
  const corsAllowed = allowed === '*' ? '*' : allowed;
  const thresholdConfigured = Boolean(ctx.opts.threshold);

  const proverBaseUrl = ctx.service.emailRecovery?.getZkEmailProverBaseUrl?.() ?? null;
  const zkEmailConfigured = Boolean(proverBaseUrl);

  return json({
    ok: true,
    relayerAccountId: ctx.service.getRelayerAccountId?.() ?? null,
    webAuthnContractId: ctx.service.getWebAuthnContractId?.() ?? null,
    zkEmail: { configured: zkEmailConfigured, proverBaseUrl },
    thresholdEd25519: { configured: thresholdConfigured },
    cors: { allowedOrigins: corsAllowed },
  }, { status: 200 });
}

export async function handleReady(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (!ctx.opts.readyz || ctx.method !== 'GET' || ctx.pathname !== '/readyz') return null;

  const allowed = buildCorsOrigins(...(ctx.opts.corsOrigins || []));
  const corsAllowed = allowed === '*' ? '*' : allowed;

  const thresholdConfigured = Boolean(ctx.opts.threshold);

  const zk = ctx.service.emailRecovery
    ? await ctx.service.emailRecovery.checkZkEmailProverHealth()
    : { configured: false, baseUrl: null, healthy: null as boolean | null };

  const ok =
    (zk.configured ? zk.healthy === true : true);

  return json({
    ok,
    thresholdEd25519: { configured: thresholdConfigured },
    zkEmail: zk,
    cors: { allowedOrigins: corsAllowed },
  }, { status: ok ? 200 : 503 });
}
