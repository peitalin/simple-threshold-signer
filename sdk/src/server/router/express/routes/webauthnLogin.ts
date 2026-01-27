import type { Router as ExpressRouter } from 'express';
import { parseSessionKind } from '../../relay';
import type { ExpressRelayContext } from '../createRelayRouter';

export function registerWebAuthnLoginRoutes(router: ExpressRouter, ctx: ExpressRelayContext): void {
  router.post('/login/options', async (req: any, res: any) => {
    try {
      if (!req?.body) {
        res.status(400).json({ ok: false, code: 'invalid_body', message: 'Request body is required' });
        return;
      }
      const result = await ctx.service.createWebAuthnLoginOptions(req.body);
      if (!result.ok) {
        res.status(result.code === 'internal' ? 500 : 400).json(result);
        return;
      }
      res.status(200).json(result);
    } catch (e: any) {
      res.status(500).json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  router.post('/login/verify', async (req: any, res: any) => {
    try {
      if (!req?.body) {
        res.status(400).json({ ok: false, code: 'invalid_body', message: 'Request body is required' });
        return;
      }

      const body = req.body;
      const challengeId = String(body.challengeId ?? body.challenge_id ?? '').trim();
      if (!challengeId) {
        res.status(400).json({ ok: false, code: 'invalid_body', message: 'challengeId is required' });
        return;
      }
      if (!body.webauthn_authentication || typeof body.webauthn_authentication !== 'object') {
        res.status(400).json({ ok: false, code: 'invalid_body', message: 'webauthn_authentication is required' });
        return;
      }

      const origin = String(req.headers?.origin || req.headers?.Origin || '').trim() || undefined;
      const result = await ctx.service.verifyWebAuthnLogin({
        challengeId,
        webauthn_authentication: body.webauthn_authentication,
        expected_origin: origin,
      });

      if (!result.ok || !result.verified) {
        res.status(result.code === 'internal' ? 500 : 400).json(result);
        return;
      }

      const session = ctx.opts.session;
      if (session && result.userId && result.rpId) {
        try {
          const sessionKind = parseSessionKind(body);
          const token = await session.signJwt(result.userId, { rpId: result.rpId });
          ctx.logger.info(`[relay] creating ${sessionKind === 'cookie' ? 'HttpOnly session' : 'JWT'} for`, result.userId);
          if (sessionKind === 'cookie') {
            res.set('Set-Cookie', session.buildSetCookie(token));
            res.status(200).json({ ok: true, verified: true });
            return;
          }
          res.status(200).json({ ok: true, verified: true, jwt: token });
          return;
        } catch { }
      }

      res.status(200).json({ ok: true, verified: true });
    } catch (e: any) {
      res.status(500).json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });
}

