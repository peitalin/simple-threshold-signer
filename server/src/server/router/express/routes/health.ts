import type { Request, Response, Router as ExpressRouter } from 'express';
import type { ExpressRelayContext } from '../createRelayRouter';

export function registerHealthRoutes(router: ExpressRouter, ctx: ExpressRelayContext): void {
  if (ctx.opts.healthz) {
    router.get('/healthz', async (_req: Request, res: Response) => {
      const thresholdConfigured = Boolean(ctx.opts.threshold);

      const proverBaseUrl = ctx.service.emailRecovery?.getZkEmailProverBaseUrl?.() ?? null;
      const zkEmailConfigured = Boolean(proverBaseUrl);

      res.status(200).json({
        ok: true,
        relayerAccountId: ctx.service.getRelayerAccountId?.() ?? null,
        webAuthnContractId: ctx.service.getWebAuthnContractId?.() ?? null,
        zkEmail: { configured: zkEmailConfigured, proverBaseUrl },
        thresholdEd25519: { configured: thresholdConfigured },
      });
    });
  }

  if (ctx.opts.readyz) {
    router.get('/readyz', async (_req: Request, res: Response) => {
      const thresholdConfigured = Boolean(ctx.opts.threshold);

      const zk = ctx.service.emailRecovery
        ? await ctx.service.emailRecovery.checkZkEmailProverHealth()
        : { configured: false, baseUrl: null, healthy: null as boolean | null };

      const ok =
        (zk.configured ? zk.healthy === true : true);

      res.status(ok ? 200 : 503).json({
        ok,
        thresholdEd25519: { configured: thresholdConfigured },
        zkEmail: zk,
      });
    });
  }
}
