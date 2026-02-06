import type { Router as ExpressRouter } from 'express';
import type { ExpressRelayContext } from '../createRelayRouter';

export function registerWebAuthnAuthenticatorRoutes(router: ExpressRouter, ctx: ExpressRelayContext): void {
  router.get('/webauthn/authenticators', async (req: any, res: any) => {
    try {
      const session = ctx.opts.session;
      if (!session) {
        res.status(501).json({ ok: false, code: 'sessions_disabled', message: 'Sessions are not configured' });
        return;
      }

      const parsed = await session.parse(req.headers || {});
      if (!parsed.ok) {
        res.status(401).json({ ok: false, code: 'unauthorized', message: 'No valid session' });
        return;
      }

      const claims: any = (parsed as any).claims || {};
      const kindRaw = (claims as any).kind;
      const kind = typeof kindRaw === 'string' ? kindRaw.trim() : '';
      if (kind !== 'app_session_v1') {
        res.status(401).json({ ok: false, code: 'unauthorized', message: 'No valid app session' });
        return;
      }
      const userId = String(claims.sub || '').trim();
      const appSessionVersion = typeof claims.appSessionVersion === 'string' ? claims.appSessionVersion.trim() : '';
      if (!userId || !appSessionVersion) {
        res.status(401).json({ ok: false, code: 'unauthorized', message: 'Invalid app session' });
        return;
      }
      const validated = await ctx.service.validateAppSessionVersion({ userId, appSessionVersion });
      if (!validated.ok) {
        res.status(validated.code === 'internal' ? 500 : 401).json({ ok: false, code: validated.code, message: validated.message });
        return;
      }

      const rpIdFromQuery = String((req.query?.rpId ?? req.query?.rp_id ?? '') || '').trim();
      const rpId = rpIdFromQuery || String(claims.rpId || '').trim();

      const result = await ctx.service.listWebAuthnAuthenticatorsForUser({ userId, ...(rpId ? { rpId } : {}) });
      if (!result.ok) {
        const status = result.code === 'not_supported' ? 501 : (result.code === 'invalid_args' ? 400 : 500);
        res.status(status).json(result);
        return;
      }

      res.status(200).json(result);
    } catch (e: any) {
      res.status(500).json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });
}
