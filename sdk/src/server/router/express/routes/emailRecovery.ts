import type { Router as ExpressRouter } from 'express';
import type { ExpressRelayContext } from '../createRelayRouter';

export function registerEmailRecoveryRoutes(router: ExpressRouter, ctx: ExpressRelayContext): void {
  router.post('/email-recovery/prepare', async (req: any, res: any) => {
    try {
      if (!req?.body) {
        res.status(400).json({ ok: false, code: 'invalid_body', message: 'Request body is required' });
        return;
      }
      const origin = String(req.headers?.origin || req.headers?.Origin || '').trim() || undefined;
      const result = await ctx.service.prepareEmailRecovery({
        ...(req.body || {}),
        ...(origin ? { expected_origin: origin } : {}),
      });
      if (!result.ok) {
        res.status(result.code === 'internal' ? 500 : 400).json(result);
        return;
      }
      res.status(200).json(result);
    } catch (e: any) {
      res.status(500).json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });
}

